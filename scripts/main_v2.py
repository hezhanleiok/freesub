#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
免费节点自动测活订阅池 v2 — 全协议 · 高精度 · 低误杀
====================================================

架构（三阶段流水线）:
  1. 抓取订阅源 → 解析全部协议 URI 为统一节点对象
     (vless/vmess/trojan/ss/hysteria2/tuic/anytls + reality + 全部传输层)
  2. 真实测活（sing-box v1.14 内核，逐节点 SOCKS 入站 + 节点出站）:
     - 阶段A 端口预检: TCP/QUIC 直连握手, 快速丢弃死端口 (削减 90% 无效工作)
     - 阶段B 真实探测: 多 URL 探测 (gstatic 204 / cloudflare trace) 
       + 经代理取真实出口 IP (api.ip.sb/geoip → 一次拿 country+asn+isp)
       + Cloudflare 限时下载测速 → 断流节点识别 (吞吐量不足)
       + cloudflare trace tls=VERIFIED → MITM/劫持节点识别
  3. 分类与导出:
     - 国家: 出口 IP ip-api.com 批量(45req/min 免费) → MaxMind GeoLite2 兜底
     - 属性: hosting=true/CDN网段/IDC ASN → 机房 | mobile=true → 移动
            | 运营商白名单+rDNS → 家宽
     - 去重: 出口IP+端口 唯一化, 家宽区严格防同IP刷屏
"""

import os
import re
import io
import sys
import json
import time
import uuid
import base64
import shutil
import socket
import zipfile
import tarfile
import platform
import threading
import subprocess
import ipaddress
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    import yaml
    import maxminddb
except ImportError as e:
    print(f"[!] 缺少依赖: {e} — 请先 pip install -r requirements.txt")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════
# 配置
# ══════════════════════════════════════════════════════════════════

SOURCE_URLS = [
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-TW.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",
    "https://raw.githubusercontent.com/10ium/HiN-VPN/main/subscription/base64/mix",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/protocols/hysteria",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/security/tls",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://www.ermao.net/sub/v2ray/ermao.net",
    "https://raw.githubusercontent.com/ishalumi/proxy-node-collector/main/output/nodes_base64.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt",
    "https://shadowmere.akiel.dev/api/b64sub/",
]

OUTPUT_DIR = "output"
COUNTRY_DIR = os.path.join(OUTPUT_DIR, "by-country")
RESIDENTIAL_COUNTRY_DIR = os.path.join(OUTPUT_DIR, "residential-by-country")

SINGBOX_VERSION = "v1.14.0"
WORKDIR = os.path.dirname(os.path.abspath(__file__))          # scripts/
BASEDIR = os.path.dirname(WORKDIR)                              # repo root
RUNTIME_DIR = os.path.join(BASEDIR, "runtime")                  # kernels & db
SINGBOX_BIN = os.path.join(RUNTIME_DIR, "sing-box")

# --- 测活阈值 (毫秒/秒) ---
# ★ 分层超时: 首击宽 (12s 容慢节点), 重试窄 (4s 快速放弃死节点)
#   依据 CI 实测: 25 分钟里 ~60% 时间烧在死节点 3×12s 满额重试上
PROBE_TIMEOUT          = 12      # 活性首击超时 (秒) — 容纳慢启动节点
PROBE_RETRY_TIMEOUT    = 4       # 活性重试超时 (秒) — 死节点快速放弃
PORT_KNOCK_TIMEOUT     = 2.5     # 端口预检超时
IP_ECHO_TIMEOUT        = 6.0     # 出口 IP 检测超时

# ★ 测速判定 (v3 修正):
#   旧版 5s 窗口把 SOCKS/TCP/TLS 握手 + TTFB 全算进吞吐, 且未剔除 TCP 慢启动期,
#   导致"真实 100KB/s 的节点被测成 60KB/s" → 系统性误杀 (尤其 CF CDN 中转节点)。
#   现在: 计时从首字节开始, 丢弃前 1.5s 慢启动, 用稳态窗口算速率, 阈值降到 35KB/s。
SPEED_TEST_BYTES       = 1_500_000   # 1.5MB (9s@35KB/s=315KB, 1.5MB 足够算准稳态)
SPEED_TEST_BUDGET      = 9.0         # 测速总预算 (秒, 从首字节起算)
SPEED_WARMUP           = 1.5         # 慢启动丢弃窗口 (秒)
SPEED_MIN_BYTES_PER_S  = 35_000      # 稳态吞吐 < 35KB/s 才判定断流 (仅在"实测到速度"时生效)
SPEED_MIN_SAMPLE_BYTES = 200_000     # 有效样本下限: 不足则视为未测到 (防 64KB/0.3s 算出假高值)
IP_ECHO_URLS = [                    # 经代理获取出口 IP (多路冗余)
    "https://api.ip.sb/geoip",                         # JSON: country_code/asn/isp
    "https://ipinfo.io/json",                          # JSON: country/org
    "http://ip-api.com/json/?fields=status,query,countryCode,isp,org,as",  # HTTP free
]
LIVENESS_URLS = [                    # 活性探测 URL (多厂商混合, 避免单一依赖 Google)
    "https://www.gstatic.com/generate_204",              # Google 204
    "https://cp.cloudflare.com/generate_204",            # Cloudflare 204
    "https://captive.apple.com/hotspot-detect.html",     # Apple 200 "Success"
]
SPEED_TEST_URLS = [               # 测速端点多路 (实测部分节点商屏蔽 speed.cloudflare.com)
    "https://speed.cloudflare.com/__down?bytes=" + str(SPEED_TEST_BYTES),
    "https://cachefly.cachefly.net/10mb.test",
]
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"      # warp=on 检测套壳节点


def _env_int(name: str, default: int, max_value: int = 128) -> int:
    """读环境变量整数 (非法/<=0 回退默认值; 超过 max_value 截断, 防手抖填 480)"""
    try:
        v = int(os.environ.get(name, "").strip())
        return min(v, max_value) if v > 0 else default
    except Exception:
        return default


# 同时 sing-box 实测节点数。
#   为什么可调: 并发不是越高越好。GitHub Actions 标准 runner 只有 2~4 vCPU,
#   48 并发 = 每核 12~24 个 sing-box 进程, TLS 握手阶段会互相抢 CPU,
#   握手被拉长 → 超时 → 误判 no_liveness (正是"能用变不能用"的一种来源)。
#   另外 Azure 出站有 SNAT 端口上限, 高并发 + 端口快速 TIME_WAIT 会造成连接失败。
#   因此默认取 48 (吞吐优先), 但可通过 PROBE_CONCURRENCY 环境变量下调:
#   若"未通过原因分布"里 no_liveness 占比异常高、且 probe_secs p90 接近超时值,
#   说明并发压过了 CPU, 调到 32 / 24 再跑一轮对比真活数即可定论。
MAX_WORKERS_TEST    = _env_int("PROBE_CONCURRENCY", 48)
MAX_WORKERS_FETCH   = 8
MAX_WORKERS_CLASSIFY = 32

# ip-api.com 免费批量: 15 req/min, 每 req ≤100 IP (仅 HTTP)
IP_API_BATCH_URL = "http://ip-api.com/batch?fields=status,countryCode,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
IP_API_BATCH_SIZE = 100
IP_API_BATCH_RPS_INTERVAL = 4.2     # 60/15s ≈ 每 4.2s 一批

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

# ══════════════════════════════════════════════════════════════════
# 出口 IP 情报 (本地离线兜底)
# ══════════════════════════════════════════════════════════════════

# Cloudflare 官方 Anycast 全网段 (命中即 CDN 任播, 绝非家宽)
CLOUDFLARE_IP_NETWORKS = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
    "141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20",
    "197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
    "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22",
)]

# Google / Fastly / Akamai 等常见 CDN 与云入口段 (命中即标 CDN/机房)
CDN_IP_NETWORKS_EXTRA = [ipaddress.ip_network(n) for n in (
    # Google
    "8.8.4.0/24","8.8.8.0/24","8.34.208.0/20","8.35.192.0/20","34.64.0.0/10","35.184.0.0/13",
    "35.192.0.0/14","35.196.0.0/15","35.200.0.0/13","35.216.0.0/15","35.220.0.0/14",
    "64.15.112.0/20","64.233.160.0/19","66.102.0.0/20","66.249.64.0/19","72.14.192.0/18",
    "74.125.0.0/16","108.177.0.0/17","142.250.0.0/15","172.217.0.0/16","173.194.0.0/16",
    "209.85.128.0/17","216.58.192.0/19","216.239.32.0/19",
    # Fastly
    "23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.222.0/23",
    "104.156.80.0/20","140.248.64.0/18","146.75.0.0/16","151.101.0.0/16",
    "157.52.64.0/18","167.82.0.0/17","199.232.0.0/16","204.129.196.0/22",
    # Akamai (核心段)
    "23.32.0.0/13","23.64.0.0/14","23.192.0.0/11","23.197.0.0/16",
    "95.100.0.0/15","104.64.0.0/10","184.24.0.0/13","184.84.0.0/14",
    # Cloudflare Spectrum / 托管入口
    "104.16.0.0/12",
)]

# 已知云/机房 ASN (离线兜底用; 在线 ip-api hosting=true 为主判据)
DATACENTER_ASNS = {
    13335,  # Cloudflare
    16509, 14618,  # AWS
    15169, 396982,  # Google
    8075, 8068,  # Microsoft
    24940,  # Hetzner
    16276,  # OVH
    14061,  # DigitalOcean
    31898, 63949,  # Oracle
    45102,  # Alibaba
    132203,  # Tencent
    20473,  # Choopa/Vultr 早期
    60068,  # Datacamp (CDN77)
    55081,  # Hostinger
    197540,  # Hostinger EU
    51167,  # Contabo
    8560,  # 1&1 / IONOS
    42708,  # IONOS
    201814, 49981,  # Hosthatch/Hostkey 类
    212238, 46652,  # Serverius/OVH 类
    141995, 200019, 136907, 39351, 9009,  # M247/Hosthatch 等
    174, 3356, 1299, 2914, 6939,  # 骨干 (Cogent/Lumen/Arelion/NTT/Hurricane)
    199524, 206096, 49505,  # Selectel/WorldStream
    62240, 49304, 34665, 209242, 219337, 44477,
    200651, 202685, 210644, 205628, 51852, 204544, 397373, 140224,  # 小型 IDC
    54866,  # Parsebian/HydraTransit 类
    45899,  # VNPT 云? 标记为 IDC
    # ★ 实测漏网: 收购家宽段/伪装 DSL rDNS 的云边网络 (ip-api proxy=true 案例补充)
    62610,  # Zenlayer (AS62610, rDNS 带 dsl.speakeasy.net 但 proxy=true)
    60205,  # 62610 关联段
    8342,  # Deltacomputers/Evrasia 类
    9009, 47692, 62041, 56630, 57502,  # Serverius/ProXmedia/Clouvider 类
}

# ══════════════════════════════════════════════════════════════════
# 跨运行记忆
#
# 【保留但不再参与出库】曾经用来支撑"救援池"(Azure 连不上但历史活过 + 入口画像
#   可直连 → 当作对国内家宽可用)。实测反馈: 这批节点在国内客户端里全是 -1,
#   必须挂前置才有一部分能用 —— 说明"入口 IP 像 CF/亚洲 IDC"并不等于"国内能连",
#   该假设不成立, 救援池与国内直连专区已整体下线。
#   state.json 仍继续写入, 保留各节点的历史存活轨迹备查。
# ══════════════════════════════════════════════════════════════════
STATE_FILE = os.path.join(OUTPUT_DIR, "state.json")
STATE_MAX_CONSEC_DEAD = 3


# 民用宽带 ASN 白名单 (离线兜底; 关键国家主流运营商)
RESIDENTIAL_ASNS = {
    # 台湾
    3462,    # Chunghwa Telecom (中华电信)
    9924, 17709, 4780, 18049,  # 亚太电信/远传/台湾大哥大/凯擘
    9269, 3491,  # 台湾硕网/和宇宽频
    # 香港
    4760, 476, 4515, 9229, 9266, 10103,  # PCCW/HKT/CUHK/HGC/HKBN/HKTBB
    9059, 38861,  # Hong Kong Broadband
    # 日本
    4713, 2516, 17676, 4721, 2497, 9605, 17511, 9318, 2518, 20193,
    # Softbank/NTT Communications/KDDI/IIJ/Sony/Plala/@nifty/JCN
    4766, 3786, 17816, 9357,
    # 韩国
    4713, 9318, 17816, 9357, 4766,  # KT/LG/SK  
    # 美国
    701, 7018, 7922, 20115, 22773, 10796, 20057, 11427, 10507, 6128,
    33363, 21928, 10777, 33660, 33661, 33662, 36466, 53417, 55136,
    20057, 19024, 12271, 11404, 6983, 33554, 7155, 30162, 10790,
    # Comcast (7922/33487/22263...) / Charter (20115/10796/20057) / Cox / AT&T / Verizon
    702, 703, 704, 705, 706, 709, 710, 711, 712, 713, 714, 715,  # legacy Verizon
    2828, 20001, 3549,  # CenturyLink/Level3 (部分为家宽)
    6167, 6162, 7018,  # AT&T
    5056,  # Cox East
    10796,  # Charter
    11351,  # TWC
    6128,  # Atlantis
    # 英国
    2856, 5607, 20650, 13285, 12576, 12725, 19541, 33950, 5413,
    # BT/TalkTalk/Orange/Virgin/Plusnet/Sky/Eclipse
    # 德国
    3320, 3209, 6805, 8888, 9145, 13237, 15366, 20879, 16097, 15594,
    # DT/Vodafone/EWE/netcup/Telefónica
    # 法国
    3215, 12322, 15557, 5410, 21590, 22869, 8228, 8220, 12670,
    # Orange/Free/SFR/Bouygues/LDN/9.tel
    # 荷兰 / 比利时
    33915, 20857, 5418, 6777, 15535, 6830, 8683,
    # KPN/Ziggo/Tele2/Solcon/Proximus/Telenet
    # 加拿大
    577, 6539, 812, 7992, 22995, 23498, 30645, 11260, 5645, 13331,
    # Bell/Rogers/Corus/Cogeco/Videotron/Telus
    # 澳大利亚 / 新西兰
    1221, 4764, 4761, 4747, 4802, 4804, 38293, 9443, 23871, 4771,
    # Telstra/Optus/iinet/AAPT/Exetel/SparkNZ
    # 新加坡 / 马来西亚
    9506, 9224, 10091, 4657, 32308, 55553, 177545, 9534, 17971, 24210,
    # Singtel/StarHub/M1/MyRepublic/TM/Maxis/Time
    # 巴西 / 拉美
    28573, 26599, 28598, 22085, 27699, 11014, 16832, 16397, 26615,
    # Claro/Vivo/Algar/Brisanet
    # 土耳其 / 俄罗斯 / 哈萨克
    9121, 34984, 15924, 31103, 47853, 25513, 12714, 8359, 12389,
    # Türk Telekom/Vodafone TR/MTS/Rostelecom/Kazakhtelecom
    # 意大利 / 西班牙
    3269, 30722, 12874, 12392, 12474, 3352, 12479, 12430,
    # Telecom Italia/Fastweb/Vodafone IT/Telefónica ES
    # 印度 / 越南 / 泰国 / 菲律宾 / 印尼
    55836, 9829, 9498, 17813, 45899, 7552, 9675, 7568, 45773, 45543,
    7590, 17457, 7552, 131293, 9336, 23969, 17816, 24099, 38251,
    # 印尼 Telkomsel/Indosat/Smartfren; 越南 Viettel/FPT; 泰国 AIS/True
}

# rDNS / ISP 名称关键词 (大小写不敏感; 离线兜底)
IDC_NAME_PATTERNS = [
    "hosting", "hoster", "datacenter", "data center", "cloud", "server",
    "vps", "dedicated", "colo", "colocation", "compute", "storage",
    "amazon", "aws", "google cloud", "microsoft", "azure", "oracle",
    "digitalocean", "linode", "vultr", "choopa", "hetzner", "ovh",
    "contabo", "m247", "leaseweb", "online s.a.s", "scaleway",
    "alibaba", "tencent", "huawei cloud", "ucloud", "jdcloud", "ksyun",
    "fastly", "cloudflare", "akamai", "cdn", "anycast", "edge network",
    "hostkey", "selectel", "aeza", "justhost", "idnica", "hostinger",
    "ionos", "1&1", "godaddy", "namecheap", "sucuri", "ispxk",
    "zenlayer", "zencom", "g-core", "gcore", "netcup", "hetzner",
]

RESIDENTIAL_NAME_PATTERNS = [
    # 通用家宽特征
    "broadband", "pppoe", "pppoa", "dsl", "cable", "fiber", "ftth",
    "fibre", "dynamic", "dial", "dialup", "residential", "home",
    "consumer", "cust", "customer", "subscriber", "pool", "dynamic-ip",
    # 台湾
    "chunghwa", "hinet", "taiwanmobile", "twn", "aptg", "kbro",
    "tfn", "sparq", "seednet", "data communication business group",
    # 香港
    "hkbn", "hong kong broadband", "pccw", "hkt", "hgc", "smartone",
    "netvigator", "citic telecom", "i-cable", "hk cable",
    # 日本
    "softbank", "ocn", "plala", "so-net", "iiJmio home", "eonet",
    "kddi", "jcom", "au broadband", "biglobe", "nifty",
    # 韩国
    "korea telecom", "kt corp", "sk broadband", "lgu+", "lg uplus",
    # 美国
    "comcast", "charter communications", "spectrum", "cox communications",
    "at&t", "at and t", "bellsouth", "sbc internet", "qwest", "centurylink",
    "verizon fios", "verizon online", "frontier communications", "windstream",
    "altice", "optimum online", "rcn", "wave broadband", "consolidated",
    "hughes", "viasat", "starlink", "mediaserv",
    # 欧洲
    "deutsche telekom", "telekom deutschland", "vodafone d2", "kabel deutschland",
    "british telecom", "bt broadband", "virgin media", "sky uk", "talktalk",
    "orange sa", "free SAS".lower(), "sfr", "bouygues", "bbox", "numericable",
    "kpn", "ziggo", "t-mobile netherlands", "proximus", "telenet",
    "telefonica", "movistar", "vodafone espana", "jazztel", "orange es",
    "telecom italia", "fastweb home", "iliad italia", "windtre",
    "swisscom", "a1 telekom", "magyar telekom", "o2 czech",
    "telia sweden", "telenor", "tele2 sweden", "bredband2",
    "rostelecom home", "mgts", "ertelecom", "dom.ru", "mtu-moscow",
    # 亚太其他
    "singtel", "starhub", "m1 limited", "myrepublic", "viewqwest",
    "maxis", "unifi", "time dotcom", "tm net", "celcom",
    "ais", "true internet", "3bb", "dtac tri", "ntc net",
    "viettel", "vnpt", "fpt telecom", "cmc telecom", "vinaphone",
    "pldt", "globe telecom", "converge ict", "sky broadband ph",
    "telkomsel", "indosat", "xl axiata", "biznet networks", "first media",
    # 拉美 / 土耳其 / 其他
    "claro", "vivo", "tim brasil", "oi internet", "net servicos",
    "turk telekom", "superonline", "ttk", "kablonet", "vodafone net",
    " kazakhtelecom", "beeline kz", "izatelecom",
    "bigpond", "iinet", "optus", "tpg internet", "aussie broadband",
    "spark nz", "vodafone nz", "2degrees", "orcon", "slingshot",
]

# 协议 → 全称 (命名用)
PROTOCOL_LABELS = {
    "vless": "VLESS", "vmess": "VMESS", "trojan": "Trojan",
    "ss": "Shadowsocks", "hysteria2": "Hysteria2", "tuic": "TUIC",
    "anytls": "AnyTLS",
}

COUNTRY_NAMES = {
    "HK": "中国香港 (Hong Kong)", "TW": "中国台湾 (Taiwan)", "JP": "日本 (Japan)",
    "SG": "新加坡 (Singapore)", "US": "美国 (United States)", "KR": "韩国 (South Korea)",
    "DE": "德国 (Germany)", "GB": "英国 (United Kingdom)", "CA": "加拿大 (Canada)",
    "FR": "法国 (France)", "NL": "荷兰 (Netherlands)", "RU": "俄罗斯 (Russia)",
    "IN": "印度 (India)", "AU": "澳大利亚 (Australia)", "IT": "意大利 (Italy)",
    "ES": "西班牙 (Spain)", "TR": "土耳其 (Turkey)", "AE": "阿联酋 (UAE)",
    "BR": "巴西 (Brazil)", "MY": "马来西亚 (Malaysia)", "TH": "泰国 (Thailand)",
    "VN": "越南 (Vietnam)", "PH": "菲律宾 (Philippines)", "ID": "印尼 (Indonesia)",
    "MX": "墨西哥 (Mexico)", "AR": "阿根廷 (Argentina)", "CL": "智利 (Chile)",
    "CO": "哥伦比亚 (Colombia)", "PE": "秘鲁 (Peru)", "ZA": "南非 (South Africa)",
    "EG": "埃及 (Egypt)", "KE": "肯尼亚 (Kenya)", "NG": "尼日利亚 (Nigeria)",
    "UA": "乌克兰 (Ukraine)", "PL": "波兰 (Poland)", "SE": "瑞典 (Sweden)",
    "NO": "挪威 (Norway)", "FI": "芬兰 (Finland)", "DK": "丹麦 (Denmark)",
    "CH": "瑞士 (Switzerland)", "AT": "奥地利 (Austria)", "BE": "比利时 (Belgium)",
    "IE": "爱尔兰 (Ireland)", "PT": "葡萄牙 (Portugal)", "GR": "希腊 (Greece)",
    "CZ": "捷克 (Czech)", "RO": "罗马尼亚 (Romania)", "HU": "匈牙利 (Hungary)",
    "IL": "以色列 (Israel)", "SA": "沙特 (Saudi Arabia)", "QA": "卡塔尔 (Qatar)",
    "KZ": "哈萨克斯坦 (Kazakhstan)", "UZ": "乌兹别克斯坦 (Uzbekistan)",
    "PK": "巴基斯坦 (Pakistan)", "BD": "孟加拉 (Bangladesh)", "LK": "斯里兰卡 (Sri Lanka)",
    "NP": "尼泊尔 (Nepal)", "MM": "缅甸 (Myanmar)", "KH": "柬埔寨 (Cambodia)",
    "LA": "老挝 (Laos)", "NZ": "新西兰 (New Zealand)", "EE": "爱沙尼亚 (Estonia)",
    "LV": "拉脱维亚 (Latvia)", "LT": "立陶宛 (Lithuania)", "BG": "保加利亚 (Bulgaria)",
    "RS": "塞尔维亚 (Serbia)", "HR": "克罗地亚 (Croatia)", "SK": "斯洛伐克 (Slovakia)",
    "SI": "斯洛文尼亚 (Slovenia)", "IS": "冰岛 (Iceland)", "LU": "卢森堡 (Luxembourg)",
    "MT": "马耳他 (Malta)", "CY": "塞浦路斯 (Cyprus)", "GE": "格鲁吉亚 (Georgia)",
    "AM": "亚美尼亚 (Armenia)", "AZ": "阿塞拜疆 (Azerbaijan)", "MD": "摩尔多瓦 (Moldova)",
    "BY": "白俄罗斯 (Belarus)", "SC": "塞舌尔 (Seychelles)", "OTHER": "其他地区 (Other)",
}


# ══════════════════════════════════════════════════════════════════
# 工具函数
# ══════════════════════════════════════════════════════════════════

def get_country_flag(country_code: str) -> str:
    if not country_code:
        return "🌐"
    cc = country_code.upper()
    if cc in ("OTHER", "ZZ", "XX", "T1", "A1", "A2"):
        return "🌐"
    if len(cc) == 2 and cc.isalpha() and cc.isascii():
        return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
    return "🌐"


def b64_decode(data: str) -> str:
    """容错 base64 解码 (支持 URL-safe / 缺失 padding)"""
    data = data.strip()
    try:
        pad = -len(data) % 4
        if data and data[-1] not in "=":
            data += "=" * pad
        raw = base64.urlsafe_b64decode(data)
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        pass
    try:
        raw = base64.b64decode(data + "=" * (-len(data) % 4))
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


# ══════════════════════════════════════════════════════════════════
# HTTP 会话 (两分离设计):
#
# 【设计定位: 测活视角 = GitHub Actions 美国微软云 (海外直连节点)】
#   节点从海外可达即入库; 大陆用户经前置代理(链式)访问 —— 与 CI 同视角。
#   因此: 本地开发机 (大陆网络) 只用于调试, 抓订阅源需借系统代理过墙;
#   生产环境 (Actions) 无代理直连, 天然正确。
#
#   - DIRECT_SESSION (trust_env=True): 抓订阅源/下载数据库/IP情报/Scamalytics。
#       本地: 经系统代理 (v2rayN) 过墙; Actions: 直连 — 两种环境都正确。
#   - PROBE_SESSION (trust_env=False): 经 sing-box SOCKS 探测节点。
#       强制隔离环境代理, 保证测的是"运行机→节点"真实链路。
#       (本地调试时受 GFW 影响的失败 ≠ 节点死亡, Actions 上会得到真实结果;
#        宁可本地多杀, 不可 CI 误杀 — 生产判定以 Actions 为准)
# ══════════════════════════════════════════════════════════════════

DIRECT_SESSION = requests.Session()
DIRECT_SESSION.trust_env = True    # 跟随系统/环境代理 (本地大陆网络抓 GitHub 需要; Actions 无代理直连不受影响)
DIRECT_SESSION.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})

PROBE_SESSION = requests.Session()
PROBE_SESSION.trust_env = False    # 强制隔离: 节点探测链路绝不经本机代理, 防污染测试结果
PROBE_SESSION.headers.update({"User-Agent": USER_AGENT})


def http_get(url: str, timeout: int = 15, headers: dict = None) -> requests.Response:
    h = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        h.update(headers)
    return DIRECT_SESSION.get(url, timeout=timeout, headers=h)


def ensure_directories():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(COUNTRY_DIR, exist_ok=True)
    os.makedirs(RESIDENTIAL_COUNTRY_DIR, exist_ok=True)
    os.makedirs(RUNTIME_DIR, exist_ok=True)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip())
        return True
    except ValueError:
        return False


def parse_host_port(hostinfo: str):
    """解析 '[v6]:port' 或 'v4:port' 或 'host:port'"""
    hostinfo = hostinfo.strip()
    if hostinfo.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", hostinfo)
        if m:
            return m.group(1), int(m.group(2)) if m.group(2) else 0
        return hostinfo, 0
    if hostinfo.count(":") == 1:
        host, _, port = hostinfo.rpartition(":")
        if host and port.isdigit():
            return host, int(port)
    if hostinfo.count(":") > 1 and is_ip_literal(hostinfo):
        return hostinfo, 0  # 裸 IPv6 无端口
    parts = hostinfo.rsplit(":", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1])
    return hostinfo, 0


# ══════════════════════════════════════════════════════════════════
# 环境准备 (sing-box / GeoLite)
# ══════════════════════════════════════════════════════════════════

def download_file(url: str, dest: str, timeout: int = 300, retries: int = 3):
    """下载文件到本地; 分块流式 + 原子替换 + 重试 + 镜像切换
    (GitHub 直连失败自动尝试 jsdelivr 镜像 — 本地大陆网络/CI 偶发限流都更稳)"""
    if os.path.exists(dest) and os.path.getsize(dest) > 1024:
        return
    # 镜像: github.com/OWNER/REPO/... → cdn.jsdelivr.net/gh/OWNER/REPO@...
    mirrors = [url]
    m = re.match(r"^https://(?:github\.com|raw\.githubusercontent\.com)/([^/]+)/([^/]+)/(?:raw|releases/download)/(.+)$", url)
    if m and "releases/download" not in url:
        owner, repo, path = m.groups()
        mirrors.append(f"https://cdn.jsdelivr.net/gh/{owner}/{repo.replace('.git','')}@{path}")
    print(f"[*] 下载: {url}")
    tmp = dest + ".part"
    last_err = None
    for mirror in mirrors:
        for attempt in range(retries):
            try:
                with DIRECT_SESSION.get(mirror, timeout=timeout, stream=True,
                                        headers={"Accept": "*/*"}) as r:
                    r.raise_for_status()
                    with open(tmp, "wb") as f:
                        for chunk in r.iter_content(chunk_size=1 << 20):
                            if chunk:
                                f.write(chunk)
                if os.path.getsize(tmp) < 1024:
                    raise RuntimeError(f"下载不完整: {os.path.getsize(tmp)} bytes")
                os.replace(tmp, dest)
                return
            except Exception as e:
                last_err = e
                if attempt < retries - 1:
                    wait = 3 * (attempt + 1)
                    print(f"[!] 下载失败 (第{attempt+1}次): {str(e)[:70]} — {wait}s 后重试")
                    time.sleep(wait)
        if len(mirrors) > 1 and mirror != mirrors[-1]:
            print(f"[!] 切换镜像: {mirrors[1]}")
    # 清理失败的半截文件
    try:
        if os.path.exists(tmp):
            os.remove(tmp)
    except OSError:
        pass
    raise RuntimeError(f"下载最终失败 ({mirrors[0]}): {last_err}")


def setup_environment():
    print("[*] 准备 sing-box 内核与 GeoLite2 离线数据库 ...")
    os.makedirs(RUNTIME_DIR, exist_ok=True)

    # --- sing-box ---
    exe = SINGBOX_BIN + (".exe" if os.name == "nt" else "")
    if not os.path.exists(exe) or os.path.getsize(exe) < 1024:
        system = "windows" if os.name == "nt" else "linux"
        ext = "zip" if system == "windows" else "tar.gz"
        url = (f"https://github.com/SagerNet/sing-box/releases/download/"
               f"{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION.lstrip('v')}-{system}-amd64.{ext}")
        archive = os.path.join(RUNTIME_DIR, f"sing-box.{ext}")
        download_file(url, archive)
        if system == "windows":
            with zipfile.ZipFile(archive) as z:
                for name in z.namelist():
                    if name.endswith("sing-box.exe"):
                        with z.open(name) as src, open(exe, "wb") as dst:
                            shutil.copyfileobj(src, dst)
        else:
            with tarfile.open(archive) as t:
                for m in t.getmembers():
                    if m.name.endswith("sing-box"):
                        f = t.extractfile(m)
                        with open(exe, "wb") as dst:
                            shutil.copyfileobj(f, dst)
        os.chmod(exe, 0o755)
        try:
            os.remove(archive)
        except OSError:
            pass
    # 校验内核可运行
    try:
        ver = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=20)
        first = (ver.stdout or "").splitlines()[0] if ver.stdout else "?"
        print(f"[+] sing-box 内核就绪: {first.strip()}")
    except Exception as e:
        print(f"[!] sing-box 内核无法运行: {e}")
        raise

    # --- GeoLite2 数据库 ---
    country_db = os.path.join(RUNTIME_DIR, "Country.mmdb")
    asn_db = os.path.join(RUNTIME_DIR, "ASN.mmdb")
    download_file("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb", country_db)
    download_file("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb", asn_db)
    print(f"[+] GeoLite 数据库就绪: Country={os.path.getsize(country_db)//1024}KB, ASN={os.path.getsize(asn_db)//1024}KB")


# ═══════════════════════════════════════════N═══════════════════════
# 节点 URI 解析 (全协议 → sing-box outbound JSON)
# ═══════════════════════════════════════════N═══════════════════════

def _query_dict(query: str) -> dict:
    return {k: v[0] for k, v in urllib.parse.parse_qs(query, keep_blank_values=True).items()}


def _parse_tls_params(params: dict, host: str) -> dict:
    """从 URI query 提取 TLS/Reality 设置 → sing-box 格式"""
    security = params.get("security", "").lower()
    tls = {}
    if security == "reality":
        pbk = params.get("pbk", "")
        if not pbk:
            return None
        tls = {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "utls": {"enabled": True, "fingerprint": params.get("fp", "chrome")},
            "reality": {"enabled": True, "public_key": pbk, "short_id": params.get("sid", "")},
        }
    elif security in ("tls", "xtls"):
        tls = {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true"),
            "alpn": params.get("alpn", "").split(",") if params.get("alpn") else None,
        }
        if params.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": params["fp"]}
        if tls.get("alpn") is None:
            del tls["alpn"]
    return tls or None


def _parse_transport(params: dict) -> dict:
    """从 URI query 提取传输层 → sing-box transport 格式"""
    network = params.get("type", "tcp").lower()
    if network in ("tcp", "none", "raw"):
        return None
    if network == "ws":
        t = {"type": "ws"}
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        if params.get("host"):
            t["headers"] = {"Host": params["host"]}
        # 0-RTT early data (v2ray ws 0-RTT: path 含 ?ed=2560 时由 max-early-data 指定)
        if params.get("ed"):
            t["max_early_data"] = 2560
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return t
    if network in ("grpc", "gun"):
        t = {"type": "grpc"}
        if params.get("serviceName"):
            t["service_name"] = urllib.parse.unquote(params["serviceName"])
        return t
    if network in ("h2", "http"):   # v2ray 生态两种写法都有: type=h2 / type=http (导出用 http, 兼容两者)
        t = {"type": "http"}
        host = params.get("host", "")
        if host:
            t["host"] = [h for h in host.split(",") if h]
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        return t
    if network == "httpupgrade":
        t = {"type": "httpupgrade"}
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        if params.get("host"):
            t["host"] = params["host"]
        return t
    return None


def parse_vless(uri: str):
    """vless://uuid@host:port?params#name"""
    m = re.match(r"^vless://([^@#]+)@(\[[^\]]+\]|[^:@/]+):(\d+)(?:[/?]([^#]*))?(?:#(.*))?$", uri)
    if not m:
        return None
    user, host, port, query, _name = m.groups()
    params = _query_dict(query or "")
    tls = _parse_tls_params(params, host)
    if params.get("security", "").lower() == "reality" and tls is None:
        return None  # reality 缺 pbk 无法测
    outbound = {
        "type": "vless",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "uuid": user,
    }
    flow = params.get("flow", "")
    if flow and ("vision" in flow or "xtls" in flow):
        outbound["flow"] = flow
    if tls:
        outbound["tls"] = tls
    transport = _parse_transport(params)
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_vmess(uri: str):
    """vmess://base64({v,ps,add,port,id,aid,net,tls,sni,path,host,type})"""
    data = json.loads(b64_decode(uri[8:]))
    if not data:
        return None
    server = str(data.get("add", "")).strip()
    port = int(data.get("port", 0) or 0)
    if not server or port <= 0:
        return None
    outbound = {
        "type": "vmess",
        "tag": "node",
        "server": server,
        "server_port": port,
        "uuid": str(data.get("id", "")).strip(),
        "security": "auto",
    }
    aid = int(data.get("aid", 0) or 0)
    if aid > 0:
        outbound["alter_id"] = aid
    net = str(data.get("net", "tcp")).lower()
    if data.get("tls") in ("tls", "1", 1, True):
        outbound["tls"] = {
            "enabled": True,
            "server_name": str(data.get("sni") or data.get("host") or server).strip(),
            "insecure": str(data.get("verify_cert", "false")).lower() in ("true", "1"),
        }
    transport = None
    if net in ("ws",):
        transport = {"type": "ws"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["headers"] = {"Host": str(data["host"])}
    elif net in ("grpc", "gun"):
        transport = {"type": "grpc"}
        if data.get("path"):
            transport["service_name"] = str(data["path"])
    elif net == "h2":
        transport = {"type": "http"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["host"] = [str(data["host"])]
    elif net == "httpupgrade":
        transport = {"type": "httpupgrade"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["host"] = str(data["host"])
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_trojan(uri: str):
    """trojan://password@host:port?params#name"""
    m = re.match(r"^trojan://([^@#]+)@(\[[^\]]+\]|[^:@/]+):(\d+)(?:[/?]([^#]*))?(?:#(.*))?$", uri)
    if not m:
        return None
    password, host, port, query, _ = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "trojan",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(password),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    if params.get("fp"):
        outbound["tls"]["utls"] = {"enabled": True, "fingerprint": params["fp"]}
    transport = _parse_transport(params)
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_ss(uri: str):
    """ss://base64(method:password)@host:port#name  或  ss://method:password@... (SIP002)"""
    body = uri[5:].split("#", 1)[0]
    name = urllib.parse.unquote(uri.split("#", 1)[1]) if "#" in uri else ""
    # SIP002: method:password@host:port
    if "@" in body:
        userinfo, _, hostinfo = body.rpartition("@")
        host, port = parse_host_port(hostinfo.split("/")[0].split("?")[0])
        method, password = "", ""
        if ":" in userinfo:
            method, _, password = userinfo.partition(":")
        else:
            dec = b64_decode(userinfo)
            if ":" in dec:
                method, _, password = dec.partition(":")
        method = urllib.parse.unquote(method)
        password = urllib.parse.unquote(password)
        if not (host and port > 0 and method and password):
            return None
        return _ss_outbound(host, port, method, password)
    # legacy: base64(method:password@host:port)
    dec = b64_decode(body)
    if "@" in dec:
        userinfo, _, hostinfo = dec.rpartition("@")
        host, port = parse_host_port(hostinfo.strip())
        method, _, password = userinfo.partition(":")
        if host and port > 0 and method:
            return _ss_outbound(host, port, urllib.parse.unquote(method), urllib.parse.unquote(password))
    return None


def _ss_outbound(host, port, method, password):
    return {
        "type": "shadowsocks",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "method": method.strip().lower(),
        "password": password,
    }


def parse_hysteria2(uri: str):
    """hy2:// / hysteria2:// auth@host:port?sni=..&obfs=salamander&obfs-password=..&insecure=1
    注: auth 可能含 : / 等特殊字符 (如 https:// 前缀的密码) — 以最后一个 @ 为锚点分割"""
    prefix = "hysteria2://" if uri.startswith("hysteria2://") else "hy2://"
    body = uri[len(prefix):].split("#", 1)[0]
    # 以最后一个 @ 分割 (密码内可能含 @); host 部分不含 @
    at = body.rfind("@")
    if at <= 0:
        return None
    auth, rest = body[:at], body[at+1:]
    m = re.match(r"^(\[[^\]]+\]|[^:/?#]+):(\d+)(?:[/?]([^#]*))?$", rest)
    if not m:
        return None
    host, port, query = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "hysteria2",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(auth),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true") or params.get("insecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    if params.get("obfs", "") and params["obfs"] not in ("none", ""):
        outbound["obfs"] = {"type": params["obfs"], "password": params.get("obfs-password", "")}
    mport = params.get("mport") or params.get("ports")
    if mport:
        # 实测验证: server_ports 只接受 "start:end" 区间; 裸单端口 "443" 会 FATAL
        # 单端口保留在 server_port, 区间放 server_ports (两者可共存, 实测 check 通过)
        singles, ranges = [], []
        for part in str(mport).split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, _, b = part.partition("-")
                if a.strip().isdigit() and b.strip().isdigit():
                    if a.strip() == b.strip():
                        singles.append(a.strip())
                    else:
                        ranges.append(f"{a.strip()}:{b.strip()}")
            elif part.isdigit():
                singles.append(part)
        if ranges or singles:
            # 全部转为 "start:end" 区间格式 (实测: 裸单端口 FATAL)
            outbound["server_ports"] = ranges + [f"{s}:{s}" for s in singles]
            outbound.pop("server_port", None)  # 端口跳跃节点无固定单端口
    return outbound


def _parse_port_range(spec: str):
    """'2087-2097,443' → sing-box server_ports 格式 ['2087:2097', '443:443'] (实测: 裸单端口 FATAL, 必须区间)"""
    result = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            if a.strip().isdigit() and b.strip().isdigit():
                result.append(f"{a.strip()}:{b.strip()}")
        elif part.isdigit():
            result.append(f"{part}:{part}")
    return result


def parse_tuic(uri: str):
    """tuic://uuid:password@host:port?congestion_control=bbr&alpn=h3&sni=..&udp_relay_mode=native#name"""
    m = re.match(r"^tuic://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)(?:[/?]([^#]*))?$", uri.split("#")[0])
    if not m:
        return None
    userinfo, host, port, query = m.groups()
    if ":" not in userinfo:
        return None
    uuid_, _, password = userinfo.partition(":")
    params = _query_dict(query or "")
    outbound = {
        "type": "tuic",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "uuid": urllib.parse.unquote(uuid_),
        "password": urllib.parse.unquote(password),
        "congestion_control": params.get("congestion_control", "bbr"),
        "udp_relay_mode": params.get("udp_relay_mode", "native"),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", host),
            "insecure": params.get("allow_insecure", "0") in ("1", "true"),
            "alpn": [a for a in params.get("alpn", "h3").split(",") if a],
        },
    }
    return outbound


def parse_anytls(uri: str):
    """anytls://password@host:port?sni=..&insecure=1#name"""
    m = re.match(r"^anytls://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)(?:[/?]([^#]*))?$", uri.split("#")[0])
    if not m:
        return None
    password, host, port, query = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "anytls",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(password),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", host),
            "insecure": params.get("insecure", "0") in ("1", "true") or params.get("allowInsecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    return outbound


def parse_ssh(uri: str):
    """ssh://user:pass@host:port#name (少见于免费池, 顺手支持)"""
    m = re.match(r"^ssh://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)?", uri.split("#")[0])
    if not m:
        return None
    userinfo, host, port = m.groups()
    outbound = {
        "type": "ssh",
        "tag": "node",
        "server": host,
        "server_port": int(port or 22),
        "user": urllib.parse.unquote(userinfo.split(":")[0]),
    }
    if ":" in userinfo:
        outbound["user"] = urllib.parse.unquote(userinfo.split(":")[0])
        outbound["password"] = urllib.parse.unquote(userinfo.split(":", 1)[1])
    return outbound


PARSERS = {
    "vless://": parse_vless,
    "vmess://": parse_vmess,
    "trojan://": parse_trojan,
    "ss://": parse_ss,
    "hy2://": parse_hysteria2,
    "hysteria2://": parse_hysteria2,
    "tuic://": parse_tuic,
    "anytls://": parse_anytls,
    "ssh://": parse_ssh,
}

# 排除明显加密残缺/占位节点
BLACKLIST_NAME_HINTS = re.compile(r"(剩余流量|流量重置|expire|expired|官网|套餐|telegram\.me|t\.me/|获取订阅)", re.I)


def parse_node_uri(uri: str):
    """解析节点 URI → (outbound, server, port, protocol) ; 失败返回 None"""
    for prefix, parser in PARSERS.items():
        if uri.startswith(prefix):
            try:
                out = parser(uri)
            except Exception:
                return None
            if not out:
                return None
            proto = out["type"]
            port = out.get("server_port")
            if port is None:  # 端口跳跃节点: 无固定端口, 取区间首个起点用于预检
                ports = out.get("server_ports") or []
                first = ports[0].split(":")[0] if ports else "0"
                port = int(first)
            if port <= 0:
                return None
            return out, out["server"], int(port), proto
    return None


def extract_nodes_from_text(text: str) -> set:
    results = set()
    if not text:
        return results
    probe = text.strip()
    # 最多三层 base64 解包 (订阅常见整体 base64)
    for _ in range(3):
        if any(p in probe for p in ("vmess://", "vless://", "ss://", "trojan://",
                                     "hy2://", "hysteria2://", "tuic://", "anytls://")):
            break
        decoded = b64_decode(probe)
        if not decoded or decoded == probe:
            break
        probe = decoded
    # 直接文本也可能混杂 base64 行
    lines_blob = probe
    pattern = (r'((?:vmess|vless|trojan|ss|hy2|hysteria2|tuic|anytls|ssh)://'
               r'[^\s"\'<>\\]+)')
    for m in re.findall(pattern, lines_blob):
        clean = m.strip().rstrip(".,;'\"")
        if len(clean) > 12:
            results.add(clean)
    return results


# 被 WAF / 风控拦截的状态码: 同一个出口 IP 重试毫无意义, 直接交给"回源补抓"
FETCH_BLOCK_STATUS = {401, 403, 407, 429, 451}


def _classify_fetch_error(status_code: int) -> str:
    """HTTP 状态码 → 失败类型

    blocked: 鉴权/风控/地域封锁 — 同 IP 重试无意义, 直接回源
    server : 5xx — 源站自身故障或过载, 值得重试一次, 仍失败再回源
    network: 其他 4xx — 多为路径错误, 回源也救不了, 但仍归入回源集合 (成本可忽略)
    """
    if status_code in FETCH_BLOCK_STATUS:
        return "blocked"
    if 500 <= status_code < 600:
        return "server"
    return "network"


# 失败类型的信息量排序: 越靠前越"值得回源", 多次尝试时保留信息量最高的那个
FETCH_KIND_PRIO = {"blocked": 0, "server": 1, "empty": 2, "network": 3}


def _merge_kind(old: str, new: str) -> str:
    """两次尝试的失败类型合并: 取信息量更高的 (blocked > server > empty > network)

    例: 第 1 次 200-但-0节点 (empty)、第 2 次连接超时 (network) —— 保留 empty,
    因为"源站回了内容但是空的"比"这次没连上"更能说明问题。
    """
    return new if FETCH_KIND_PRIO.get(new, 9) < FETCH_KIND_PRIO.get(old, 9) else old


def fetch_raw_nodes() -> tuple:
    """抓取全部订阅源

    返回 (nodes, failed)
      nodes  : list[str]  节点 URI 全集
      failed : list[(url, kind, err)]  kind ∈ {blocked, server, empty, network}

    ★ 为什么要区分 kind:
      源站 (如 shadowmere.xyz) 普遍在 Cloudflare 上按出口 ASN 拦截数据中心 IP。
      GitHub Actions 出口是 Azure → 直接 403。此时在同一 IP 上重试 3 次纯属浪费,
      正确做法是记下来, 等测活阶段拿到存活节点后**用节点自身作出口回源补抓**。
    """
    nodes = set()
    failed = []
    print("[*] 抓取全部订阅源 ...")

    def _fetch(url):
        last_err, kind = "unknown", "network"
        # 重试 2 次 (网络抖动/间歇性重置; 退避 3s) —— 仅对网络/5xx 类失败有意义
        for attempt in range(3):
            try:
                r = http_get(url, timeout=30)
                if r.status_code == 200:
                    got = extract_nodes_from_text(r.text)
                    if got:
                        return url, got, None, ""
                    # 200 但解析不出节点: 可能是空订阅/维护页, 重试一次仍不行就记为 empty
                    last_err, kind = "HTTP 200 但解析 0 节点", _merge_kind(kind, "empty")
                else:
                    last_err = f"HTTP {r.status_code}"
                    new_kind = _classify_fetch_error(r.status_code)
                    kind = _merge_kind(kind, new_kind)
                    if new_kind == "blocked":
                        break   # WAF 拦截: 换 IP 才有意义, 同 IP 重试无用
            except Exception as e:
                last_err, kind = str(e)[:70], _merge_kind(kind, "network")
            if attempt < 2:
                time.sleep(3)
        return url, set(), last_err, kind

    with ThreadPoolExecutor(MAX_WORKERS_FETCH) as ex:
        futs = [ex.submit(_fetch, u) for u in SOURCE_URLS]
        for f in as_completed(futs):
            url, got, err, kind = f.result()
            if err:
                failed.append((url, kind, err))
                tag = "被拦" if kind == "blocked" else "失败"
                print(f"[!] 拉取{tag} {url} → {err}")
            else:
                print(f"[+] {url} → {len(got)} 节点")
            nodes.update(got)
    print(f"[*] 初始抓取总量: {len(nodes)}")
    if failed:
        blocked_n = sum(1 for _, k, _ in failed if k == "blocked")
        print(f"[*] 抓取失败 {len(failed)} 个源站 (其中被 WAF 拦截 {blocked_n} 个, 将尝试用存活节点回源补抓)")
    return list(nodes), failed


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 A: 端口预检 (削减死节点, 避免后面浪费 sing-box 全流程)
# ═══════════════════════════════════════════N═══════════════════════

# DoH 域名解析 (Cloudflare): 防 DNS 污染 (本地大陆网络); Actions 上顺带跳过其国内 DNS 限制
_DNS_CACHE = {}

def resolve_host(host: str) -> str:
    """DoH 解析 (带本地缓存); 失败退回系统 DNS"""
    if not host or is_ip_literal(host):
        return host or ""
    if host in _DNS_CACHE:
        return _DNS_CACHE[host]
    # 1) DoH (Cloudflare 1.1.1.1, 走 DIRECT_SESSION 可过墙)
    try:
        r = DIRECT_SESSION.get(
            f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(host)}&type=A",
            headers={"Accept": "application/dns-json"}, timeout=5)
        if r.status_code == 200:
            answers = r.json().get("Answer") or []
            for a in answers:
                if a.get("type") == 1 and a.get("data"):
                    _DNS_CACHE[host] = a["data"]
                    return a["data"]
    except Exception:
        pass
    # 2) 系统 DNS 兜底
    try:
        ip = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        _DNS_CACHE[host] = ip
        return ip
    except Exception:
        # ★ 负缓存: 死域名不缓存会导致每个节点都重试 DoH(5s)+getaddrinfo,
        #   几千个节点里几百个死域名就能把分类阶段拖成几十分钟。
        _DNS_CACHE[host] = ""
        return ""


def knock_port(server: str, port: int, protocol_type: str) -> bool:
    """TCP 直连预检 (DoH 解析防本地 DNS 污染); QUIC 类直接放行阶段B
    注: 预检失败不淘汰 (本地大陆视角的假死 ≠ 节点死亡), 只影响排序;
        生死由阶段B sing-box 全流程测活裁决 (Actions 海外视角)"""
    if protocol_type in ("hysteria2", "tuic"):
        # QUIC 无法轻量预检 UDP 端口连通性, 且本地 UDP 常被 QoS → 放行交阶段B
        return True
    try:
        ip = resolve_host(server)
        if not ip:
            return False
        with socket.create_connection((ip, port), timeout=PORT_KNOCK_TIMEOUT):
            return True
    except Exception:
        return False


def prefilter_candidates(candidates: list) -> list:
    """端口预检: 通过者优先, 未通过者降级保留 (防止本地网络/GFW 视角误杀;
    真正生死由阶段B sing-box 全流程测活裁决 — Actions 海外视角)"""
    print(f"[*] 端口预检 (TCP {PORT_KNOCK_TIMEOUT}s): {len(candidates)} 候选 ...")
    passed, deferred = [], []

    def _knock(item):
        raw, outbound, server, port, proto = item
        return knock_port(server, port, proto)

    with ThreadPoolExecutor(max_workers=64) as ex:
        # ex.map 保序返回; 通过者优先, 未通过降级保留 (不淘汰, 防本地视角误杀)
        for item, ok in zip(candidates, ex.map(_knock, candidates)):
            (passed if ok else deferred).append(item)
    print(f"[+] 预检通过: {len(passed)} | 预检未过(保留低优先级待全测): {len(deferred)}")
    # 预检未过的仍进入全流程 (只是排在后面) — 交给 sing-box 真实裁决
    return passed + deferred


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 B: sing-box 真实测活
# ═══════════════════════════════════════════N═══════════════════════

_PORT_LOCK = threading.Lock()
_PORT_CURSOR = [21000 + (os.getpid() % 4000)]


def _alloc_socks_port() -> int:
    """顺序分配 SOCKS 入站端口 (锁保护)

    ★ 修复旧版竞态: 旧实现 bind(0) 拿到端口后立刻 close, 再让 sing-box 去 bind —
      48 线程并发时, 这个端口可能被别的线程抢先占用, 导致节点随机启动失败被误判死亡。
      现在改为单调递增 + 加锁探测, 循环 200 次内基本不会碰撞。
    """
    with _PORT_LOCK:
        for _ in range(200):
            p = _PORT_CURSOR[0]
            _PORT_CURSOR[0] = p + 1 if p < 60000 else 21000
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    # 兜底: 交还系统分配
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_test_config(outbound: dict, socks_port: int, chain_relay: dict = None,
                      allow_front: bool = True) -> dict:
    node = dict(outbound)
    node["tag"] = "node"

    outbounds = [node, {"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}]

    # ══ 链式前置 (家宽链式复测用) ═════════════════════════════════════
    # chain_relay: 已验证存活的 sing-box outbound dict — node 经它转发 (detour 双跳)
    # 模拟用户 v2rayN "链式/前置代理" 场景: 前置 → 家宽节点 → 目标
    if chain_relay:
        relay = dict(chain_relay)
        relay["tag"] = "chain-relay"
        # relay 自身剥 detour (避免与 node 的 detour 循环)
        relay.pop("detour", None)
        outbounds.append(relay)
        node["detour"] = "chain-relay"

    # ══ 前置代理 (链式) ═════════════════════════════════════════════
    # 模拟 GitHub Actions 海外视角:
    #   - 本地大陆开发机: 经前置代理(默认 v2rayN 127.0.0.1:10808)出海 → 等效 CI 视角
    #     (大陆直连目标节点会被 GFW 拦截, 造成本地假死 ≠ 节点死亡)
    #   - GitHub Actions: FRONT_PROXY 为空 → 直连 (Azure US 本就是海外视角)
    # 用法: 环境变量 FRONT_PROXY=socks5://127.0.0.1:10808
    # ★ allow_front=False 用于"回源补抓": 那里必须让流量真的从节点出去,
    #   若再叠一层本机前置代理, 出口又变回本机 IP, 整个回源机制就静默失效了。
    front = os.environ.get("FRONT_PROXY", "").strip() if allow_front else ""
    if front and not chain_relay:
        # 解析 socks5://host:port → socks outbound
        m = re.match(r"^(socks5h?|http)://([^:]+):(\d+)$", front)
        if m:
            scheme, fhost, fport = m.groups()
            ftype = "socks" if scheme.startswith("socks5") else "http"
            front_out = {
                "type": ftype, "tag": "front-proxy",
                "server": fhost, "server_port": int(fport),
            }
            if ftype == "socks":
                front_out["version"] = "5"
            outbounds.append(front_out)
            # 节点出站流量经前置代理 (detour 链式)
            node["detour"] = "front-proxy"
            print_once("_FRONT_ENABLED", f"[*] 前置代理已启用: {front} (模拟 CI 海外视角)")

    config = {
        "log": {"level": "warn"},   # 实测: silent 不是合法级别 (trace/debug/info/warn/error/fatal/panic)
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": socks_port,
            "sniff": False,
        }],
        "outbounds": outbounds,
        "route": {"rules": [], "final": "node"},
    }
    return config


_PRINTED_ONCE = set()


def print_once(key: str, msg: str):
    if key not in _PRINTED_ONCE:
        _PRINTED_ONCE.add(key)
        print(msg)


def _make_result(item, status, fail_stage="", fail_detail=""):
    """构造统一结果对象 (★ 三态化: 失败节点也返回对象, 不再 return None)

    为什么要保留失败节点而不直接丢弃:
      失败原因要能统计 (fail_stage 直方图), 否则永远看不清漏斗卡在哪一步。
      但**不连通就不出库** —— 曾经试过把"Azure 连不上但入口像 CF/亚洲 IDC"的节点
      当救援池放出, 实测国内客户端全 -1, 必须挂前置才有一部分能用, 该假设已废弃。
    """
    raw, outbound, server, port, proto = item
    return {
        "raw": raw,
        "server": server,
        "port": port,
        "proto": proto,
        "cred": cred_fingerprint(outbound, proto),
        "status": status,
        "fail_stage": fail_stage,
        "fail_detail": (fail_detail or "")[:120],
        "alive": status == "alive",
        "latency_ms": 99999,
        "exit_ip": None,
        "exit_country_online": None,
        "exit_asn_online": None,
        "exit_asn_org_online": "",
        "exit_isp_online": "",
        "mitm_risk": False,
        "is_warp": False,
        "speed_bps": 0,
        "speed_unmeasured": True,   # 未连通 = 未测速
        "is_stalled": False,
        "quality_flags": [],
    }


def test_single_node(item, keep_alive_check=True):
    """返回 dict (★ 永不返回 None); status ∈ {alive, unreachable}
    含: 活性/延迟/出口IP/国家/ASN/ISP/速度/MITM/质量标记/失败阶段"""
    raw, outbound, server, port, proto = item
    socks_port = _alloc_socks_port()
    task_id = uuid.uuid4().hex[:10]
    cfg_path = os.path.join(RUNTIME_DIR, f"sb_{task_id}.json")

    # ★ 链式前置 (chain relay): 注入已验证存活节点作前置 (chain_retest 用, 模拟 v2rayN 链式)
    chain_out = None
    chain_json = os.environ.get("CHAIN_RELAY_OUT", "").strip()
    if chain_json:
        try:
            chain_out = json.loads(chain_json)
        except Exception:
            chain_out = None
    config = build_test_config(outbound, socks_port, chain_relay=chain_out)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config, f)

    exe = SINGBOX_BIN + (".exe" if os.name == "nt" else "")

    # --- 0) sing-box check 预校验: 快速识别 schema 错误 (记录原因, 不再静默丢弃) ---
    try:
        chk = subprocess.run([exe, "check", "-c", cfg_path],
                             capture_output=True, text=True, timeout=15,
                             creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
        if chk.returncode != 0:
            detail = (chk.stderr or chk.stdout or "").strip().splitlines()
            try:
                os.remove(cfg_path)   # 早返回不经过 finally, 手动清理临时配置
            except OSError:
                pass
            return _make_result(item, "unreachable", "config_invalid",
                                detail[-1] if detail else f"exit={chk.returncode}")
    except Exception:
        pass  # check 本身失败不阻止后续 run 尝试

    proc = None
    try:
        proc = subprocess.Popen(
            [exe, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
        )
        # 等 SOCKS 端口就绪 (主动探测而非盲 sleep — 修复旧版误杀)
        deadline = time.time() + 6
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                break  # 进程崩溃 (配置错误/端口冲突)
            try:
                with socket.create_connection(("127.0.0.1", socks_port), timeout=0.4):
                    ready = True
                    break
            except Exception:
                time.sleep(0.15)
        if not ready:
            return _make_result(item, "unreachable", "socks_not_ready",
                                "sing-box 进程未能监听本地入站")

        proxies = {"http": f"socks5h://127.0.0.1:{socks_port}",
                   "https": f"socks5h://127.0.0.1:{socks_port}"}

        # --- 1) 活性探测: 分层超时 (首击宽 12s 容慢节点; 重试窄 4s 快速放弃死节点) ---
        #     多厂商端点 (Google / Cloudflare / Apple), 避免单一厂商被限速或劫持时全灭
        alive_hits, latency_ms = 0, 99999
        last_err = ""
        t0 = time.time()
        t_live0 = t0          # 活性阶段单独计时 (并发是否压垮 CPU, 只看这一段)
        for i, url in enumerate(LIVENESS_URLS):
            timeout = PROBE_TIMEOUT if i == 0 else PROBE_RETRY_TIMEOUT
            try:
                r = PROBE_SESSION.get(url, proxies=proxies, timeout=timeout, allow_redirects=False)
                if r.status_code in (204, 200):
                    alive_hits += 1
                    latency_ms = min(latency_ms, (time.time() - t0) * 1000)
                    break  # 任一成功即可
                last_err = f"HTTP {r.status_code}"
            except Exception as e:
                last_err = type(e).__name__
                continue
        liveness_secs = round(time.time() - t_live0, 2)
        if alive_hits == 0:
            res = _make_result(item, "unreachable", "no_liveness", last_err)
            res["liveness_secs"] = liveness_secs
            return res

        # --- 2) 真实出口 IP (多路冗余) ---
        exit_ip, exit_country, exit_asn, exit_asn_org, exit_isp = None, None, None, None, None
        for url in IP_ECHO_URLS:
            try:
                r = PROBE_SESSION.get(url, proxies=proxies, timeout=IP_ECHO_TIMEOUT)
                if r.status_code != 200:
                    continue
                j = r.json()
                ip = (j.get("ip") or j.get("query") or j.get("your_ip") or "").strip()
                if not ip:
                    continue
                exit_ip = ip
                if url.startswith("https://api.ip.sb"):
                    exit_country = j.get("country_code")
                    exit_asn = j.get("asn")
                    exit_asn_org = (j.get("asn_organization") or j.get("organization") or "")
                    exit_isp = (j.get("isp") or j.get("organization") or "")
                elif url.startswith("https://ipinfo.io"):
                    exit_country = exit_country or (j.get("country") or "").upper()
                    org = j.get("org") or ""
                    if org and not exit_asn:
                        mm = re.match(r"^AS(\d+)\s+(.*)", org)
                        if mm:
                            exit_asn, exit_asn_org = int(mm.group(1)), mm.group(2)
                    exit_isp = exit_isp or org
                elif "ip-api.com" in url:
                    exit_country = exit_country or (j.get("countryCode") or "").upper()
                    exit_asn = exit_asn or j.get("as")
                    exit_asn_org = exit_asn_org or j.get("asname") or j.get("org") or ""
                    exit_isp = exit_isp or j.get("isp") or j.get("org") or ""
                break
            except Exception:
                continue

        quality_flags = []

        # --- 3) MITM 劫持检测 ---
        # ★ 修正旧版误判: 旧实现把"非 204/200 且带内容"全判为 MITM 并直接删除,
        #   但 Google 对机房/被滥用 IP 经常直接回 403 或 sorry 页 —— 那是 IP 信誉问题,
        #   不是中间人。真正的 MITM 唯一可靠信号是 TLS 证书链校验失败 (SSLError)。
        #   其他异常状态码只记质量标记, 不参与生死判定。
        mitm_risk = False
        try:
            r = PROBE_SESSION.get("https://www.gstatic.com/generate_204", proxies=proxies,
                                  timeout=PROBE_RETRY_TIMEOUT, verify=True)
            if r.status_code not in (200, 204):
                quality_flags.append(f"gstatic_{r.status_code}")
        except requests.exceptions.SSLError:
            mitm_risk = True   # 证书链验证失败 = TLS 拦截 / 自签劫持
        except Exception:
            pass  # 网络层失败不算 MITM (活性探测已通过)

        # 3b) cloudflare trace: warp=on = 套壳 WARP 节点 (非真实出口, 只打标记不淘汰)
        is_warp = False
        try:
            r = PROBE_SESSION.get(TRACE_URL, proxies=proxies, timeout=PROBE_RETRY_TIMEOUT, verify=True)
            if r.status_code == 200 and re.search(r"^warp=on", r.text, re.M):
                is_warp = True
                quality_flags.append("warp")
        except Exception:
            pass

        # --- 4) 吞吐测量 (★ 修正三处系统性低估) ---
        #   (a) 计时从**首字节**开始, 不再把 SOCKS/TCP/TLS 握手 + TTFB 算进吞吐
        #   (b) 丢弃前 1.5s 慢启动期, 用稳态窗口算速率
        #   (c) 全部端点都拿不到数据 → 标记 speed_unmeasured, **不再判定断流**
        #       (旧版 0 字节 = 断流 = 删除, 把"连不上测速站"误判成"节点坏了")
        speed_bps = 0
        speed_measured = False
        for speed_url in SPEED_TEST_URLS:
            downloaded = 0
            t_first = t_warm = t_last = None
            bytes_warm = 0
            try:
                with PROBE_SESSION.get(speed_url, proxies=proxies,
                                       timeout=(5, SPEED_TEST_BUDGET), stream=True) as r:
                    if r.status_code != 200:
                        continue
                    for chunk in r.iter_content(chunk_size=65536):
                        now = time.time()
                        if chunk:
                            if t_first is None:
                                t_first = now
                                t_warm = now + SPEED_WARMUP
                            downloaded += len(chunk)
                            if now >= t_warm:
                                bytes_warm += len(chunk)
                                t_last = now
                        if t_first is not None and now - t_first > SPEED_TEST_BUDGET:
                            break
                        if t_last is not None and now - t_last > 3.0:
                            break   # 空闲 > 3s 无数据 = 断流签名, 立即中止
                if downloaded <= 0 or t_first is None:
                    continue
                if downloaded < SPEED_MIN_SAMPLE_BYTES:
                    # 样本太小 (服务端提前 EOF / 只发了个头): 不足以判吞吐。
                    # 若拿 64KB / 0.3s 硬算会得到 200KB/s 的假高值 → 漏判断流; 当作未测到。
                    continue
                if bytes_warm > 0 and t_last is not None:
                    speed_bps = int(bytes_warm / max(t_last - t_warm, 0.5))
                else:
                    # 全部数据都在慢启动窗口内到达 (极快节点) → 用总时长兜底
                    speed_bps = int(downloaded / max((t_last or time.time()) - t_first, 0.3))
                speed_measured = True
                break   # 首个成功端点的结果即有效
            except Exception:
                continue

        is_stalled = speed_measured and speed_bps < SPEED_MIN_BYTES_PER_S

        return {
            "raw": raw,
            "server": server,
            "port": port,
            "proto": proto,
            "cred": cred_fingerprint(outbound, proto),
            "status": "alive",
            "fail_stage": "",
            "fail_detail": "",
            "alive": True,
            "latency_ms": int(latency_ms),
            "liveness_secs": liveness_secs,
            "exit_ip": exit_ip,
            "exit_country_online": exit_country,
            "exit_asn_online": exit_asn,
            "exit_asn_org_online": (exit_asn_org or "")[:120],
            "exit_isp_online": (exit_isp or "")[:120],
            "mitm_risk": mitm_risk,
            "is_warp": is_warp,
            "speed_bps": speed_bps,
            "speed_unmeasured": not speed_measured,
            "is_stalled": is_stalled,
            "quality_flags": quality_flags,
        }
    except Exception as e:
        return _make_result(item, "unreachable", "exception", f"{type(e).__name__}: {e}")
    finally:
        if proc and proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
        try:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)
        except OSError:
            pass


def run_liveness_test(candidates: list) -> list:
    print(f"[*] sing-box 全协议真实测活: {len(candidates)} 节点 (并发 {MAX_WORKERS_TEST}) ...")
    results = []
    done_count = [0]

    def _work(item):
        t0 = time.time()
        r = test_single_node(item)
        if r is not None:
            r["probe_secs"] = round(time.time() - t0, 2)
        return r

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_TEST) as ex:
        futs = {ex.submit(_work, it): it for it in candidates}
        for fut in as_completed(futs):
            done_count[0] += 1
            r = fut.result()
            if r:   # ★ 三态化后 test_single_node 永不返回 None, 这里只防极端异常
                results.append(r)
            if done_count[0] % 40 == 0:
                alive_n = sum(1 for x in results if x.get("alive"))
                print(f"[*] 测活进度: {done_count[0]}/{len(candidates)}, 通过 {alive_n}")

    alive = [r for r in results if r.get("alive") and not r.get("is_stalled")]
    mitm = sum(1 for r in results if r.get("mitm_risk"))
    stalled = sum(1 for r in results if r.get("is_stalled"))
    unmeasured = sum(1 for r in results if r.get("speed_unmeasured"))
    print(f"[+] 测活完成: 真活 {len(alive)} | 断流 {stalled} | 未测到速度(保留) {unmeasured} | MITM {mitm}")

    # ★ 并发压测埋点: 只统计"活性阶段"耗时 (不含 sing-box check / 出口IP / 测速)。
    #   判据: 若存活节点的 p90 明显变大 (正常应 < 2s), 或大量节点卡满首击超时,
    #   说明 48 并发已把 CPU/SNAT 压满, no_liveness 里混着"被自己挤死"的节点
    #   → 下调 PROBE_CONCURRENCY (32/24) 再跑一轮, 对比真活数即可定论。
    def _pct(arr, p):
        return arr[min(int(len(arr) * p), len(arr) - 1)]

    live_secs = sorted(r["liveness_secs"] for r in results
                       if r.get("alive") and "liveness_secs" in r)
    dead_secs = sorted(r["liveness_secs"] for r in results
                       if not r.get("alive") and "liveness_secs" in r)
    if live_secs:
        print(f"[*] 活性耗时(存活节点): p50={_pct(live_secs, 0.5):.2f}s "
              f"p90={_pct(live_secs, 0.9):.2f}s max={live_secs[-1]:.2f}s | 并发 {MAX_WORKERS_TEST}")
    if dead_secs:
        hit = sum(1 for s in dead_secs if s >= PROBE_TIMEOUT - 0.3)
        print(f"[*] 活性耗时(未通节点): 卡满首击超时(≥{PROBE_TIMEOUT}s) {hit}/{len(dead_secs)} "
              f"| 若该比例异常高, 说明并发把 CPU/SNAT 压满了")
    total_secs = sorted(r["probe_secs"] for r in results if "probe_secs" in r)
    if total_secs:
        print(f"[*] 单节点全流程耗时: p50={_pct(total_secs, 0.5):.1f}s "
              f"p90={_pct(total_secs, 0.9):.1f}s")

    # ★ 淘汰原因直方图 (埋点): 看清漏斗, 后续所有规则调整都以此为依据
    stage_hist = {}
    for r in results:
        if not r.get("alive"):
            st = r.get("fail_stage") or "unknown"
            stage_hist[st] = stage_hist.get(st, 0) + 1
    if stage_hist:
        print("[*] 未通过原因分布: " + " | ".join(
            f"{k}={v}" for k, v in sorted(stage_hist.items(), key=lambda x: -x[1])))
    return results  # 保留全部信息 (含失败节点), 分类阶段再决定去留


# ════════════════════════════════════════════════════════════════════
# 阶段 B1.5: 回源补抓 (用已测活节点作出口, 绕过源站对数据中心 IP 的拦截)
# ════════════════════════════════════════════════════════════════════

# 回源出口优先国家 (离大陆近、到源站 RTT 低, 且多为家宽/小机房段, 不易被 WAF 规则命中)
REFETCH_PREFER_COUNTRIES = {"HK", "TW", "SG", "JP", "KR", "MO"}
REFETCH_MAX_EGRESS = 4          # 最多换几个出口节点 (每个节点启动 ~1s, 不宜多)
REFETCH_CONNECT_TIMEOUT = 5     # 连接超时 (秒) — 节点连不上要快速放弃
REFETCH_READ_TIMEOUT = 15       # 读超时 (秒) — 源站回包, 不是下载大文件, 15s 足够
REFETCH_TOTAL_BUDGET = 180      # 回源阶段总耗时上限 (秒) — 防止源站全挂时无限拖时间


def expand_dedup(test_results: list, dedup_map: dict) -> tuple:
    """把代表节点的测活结果回填给同 (server, port, proto, 凭据) 的重复 URI

    返回 (expanded, backfilled)
    """
    result_by_key = {}
    for r in test_results:
        p = parse_node_uri(r["raw"])
        if not p:
            continue
        fp = cred_fingerprint(p[0], r["proto"])
        result_by_key[((r["server"] or "").lower(), r["port"], r["proto"], fp)] = r
    expanded = list(test_results)
    backfilled = 0
    for key, uris in dedup_map.items():
        if len(uris) <= 1:
            continue
        r = result_by_key.get(key)
        if not r or not r.get("alive"):
            continue
        for extra_uri in uris[1:]:
            clone = dict(r)
            clone["raw"] = extra_uri
            expanded.append(clone)
            backfilled += 1
    return expanded, backfilled


def _pick_refetch_egress(alive_items: list, n: int) -> list:
    """挑回源出口节点: 亚洲低延迟优先, 排除 WARP 套壳 / 断流节点

    ★ 必须先去重: main() 里 expand_dedup 会把同一节点的测活结果克隆给它的重复 URI,
      克隆体与原节点的 (exit_ip, latency_ms) 完全相同。若不去重, 按延迟排序后
      前 4 名可能全是同一个节点的克隆 → 实际只有 1 个出口, 回源失败就整体失败。
      这里用 (server, port, proto, 凭据) 还原"真实节点"身份。
    """
    cands, seen = [], set()
    for r in alive_items:
        if not r.get("exit_ip") or r.get("is_warp") or r.get("is_stalled"):
            continue
        ident = ((r.get("server") or "").lower(), r.get("port"), r.get("proto"), r.get("cred") or "")
        if ident in seen:
            continue
        seen.add(ident)
        cc = (r.get("exit_country_online") or "").upper()
        tier = 0 if cc in REFETCH_PREFER_COUNTRIES else 1
        lat = r.get("latency_ms")
        cands.append((tier, lat if isinstance(lat, int) else 99999, r))
    cands.sort(key=lambda x: (x[0], x[1]))
    return [c[2] for c in cands[:n]]


def _fetch_via_socks(url: str, socks_port: int):
    """经本地 SOCKS 入站抓取 (独立 Session, 绝不跟随本机/环境代理)"""
    s = requests.Session()
    s.trust_env = False   # 关键: 否则环境里的 http_proxy 会覆盖, 又回到原出口
    origin = urllib.parse.urlsplit(url)
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Referer": f"{origin.scheme}://{origin.netloc}/",
    })
    proxies = {"http": f"socks5h://127.0.0.1:{socks_port}",
               "https": f"socks5h://127.0.0.1:{socks_port}"}
    try:
        return s.get(url, proxies=proxies,
                     timeout=(REFETCH_CONNECT_TIMEOUT, REFETCH_READ_TIMEOUT))
    finally:
        s.close()


def _refetch_targets(failed: list) -> list:
    """从抓取失败列表里挑出值得回源的 URL, 按 kind 优先级排序 (被拦的优先救)"""
    prio = {"blocked": 0, "server": 1, "empty": 2, "network": 3}
    items = sorted(((prio.get(k, 9), u) for u, k, _ in failed), key=lambda x: x[0])
    seen, out = set(), []
    for _, u in items:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def refetch_via_alive_nodes(failed: list, alive_items: list) -> dict:
    """用已测活节点作出口, 补抓被源站 WAF 拦截的订阅

    背景 (实测):
      shadowmere.xyz / shadowmere.akiel.dev 在 Cloudflare 上按出口 ASN 拦截数据中心 IP。
      GitHub Actions 出口是 Azure → 恒 403。换备用域名无用 (同一 CF zone, 同一套规则);
      套一层 Cloudflare Worker 也无用 (Worker 回源同样是数据中心 IP, 实测返回 522/403)。

      唯一不依赖外部基建的办法: 池子里已经有上千个测活节点, 拿其中一个作出口去拉。
      这些节点出口多为港台日新家宽/小机房, 不在源站的拦截名单里。

    failed      : [(url, kind, err)]
    alive_items : 测活结果中 status=alive 的项 (需带 raw / exit_ip / latency_ms)
    返回 {url: set(uri)}  —— 仅含成功且解析出节点的
    """
    urls = _refetch_targets(failed)
    if not urls:
        return {}
    # 纯网络抖动 (全部是 exception/timeout) 不启用回源:
    # 为一次偶发超时白起 4 个 sing-box 进程不划算。只要有一个非 network 类失败
    # (被拦/5xx/空内容) 才值得走回源, 顺带把 network 类也一起重试。
    if not any(k != "network" for _, k, _ in failed):
        print("[*] 抓取失败均为网络抖动, 不启用回源补抓")
        return {}
    egress = _pick_refetch_egress(alive_items, REFETCH_MAX_EGRESS)
    if not egress:
        print("[!] 回源补抓: 无可用的存活节点作出口, 跳过 (本次将缺少这些源站的节点)")
        return {}

    print(f"[*] 回源补抓: {len(urls)} 个源站抓取失败, 尝试 {len(egress)} 个存活节点作出口 ...")
    exe = SINGBOX_BIN + (".exe" if os.name == "nt" else "")
    recovered = {}
    pending = list(urls)
    t_refetch = time.time()
    tried_egress = 0

    def _out_of_budget() -> bool:
        return time.time() - t_refetch > REFETCH_TOTAL_BUDGET

    for node in egress:
        if not pending:
            break
        if _out_of_budget():
            print(f"[!] 回源补抓超出 {REFETCH_TOTAL_BUDGET}s 预算, 停止 (剩余 {len(pending)} 个源站未解决)")
            break
        parsed = parse_node_uri(node["raw"])
        if not parsed:
            continue
        tried_egress += 1
        outbound = parsed[0]
        socks_port = _alloc_socks_port()
        cfg_path = os.path.join(RUNTIME_DIR, f"rf_{uuid.uuid4().hex[:10]}.json")
        proc = None
        try:
            with open(cfg_path, "w", encoding="utf-8") as f:
                # allow_front=False: 回源必须真的从节点出去, 不能叠本机前置代理
                json.dump(build_test_config(outbound, socks_port, allow_front=False), f)
            proc = subprocess.Popen(
                [exe, "run", "-c", cfg_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
            )
            deadline = time.time() + 8
            ready = False
            while time.time() < deadline:
                if proc.poll() is not None:
                    break
                try:
                    with socket.create_connection(("127.0.0.1", socks_port), timeout=0.4):
                        ready = True
                        break
                except Exception:
                    time.sleep(0.15)
            if not ready:
                print(f"  [-] 出口 {node.get('exit_country_online')}/{node.get('exit_ip')} 未能启动, 换下一个")
                continue

            cc = node.get("exit_country_online") or "??"
            for url in list(pending):
                if _out_of_budget():
                    print(f"  [!] 超出 {REFETCH_TOTAL_BUDGET}s 预算, 中止本出口剩余源站")
                    break
                try:
                    r = _fetch_via_socks(url, socks_port)
                    if r.status_code != 200:
                        print(f"  [!] 出口 {cc} 仍被拒 {url} → HTTP {r.status_code}")
                        continue
                    got = extract_nodes_from_text(r.text)
                    if not got:
                        print(f"  [!] 出口 {cc} 返回 200 但解析 0 节点 {url}")
                        continue
                    recovered[url] = got
                    pending.remove(url)
                    print(f"  [+] 回源成功 (出口 {cc}/{node.get('exit_ip')}) {url} → {len(got)} 节点")
                except Exception as e:
                    print(f"  [!] 出口 {cc} 回源异常 {url} → {type(e).__name__}: {str(e)[:60]}")
        except Exception as e:
            print(f"  [!] 回源出口准备失败 → {type(e).__name__}: {str(e)[:60]}")
        finally:
            if proc and proc.poll() is None:
                proc.kill()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    pass
            try:
                if os.path.exists(cfg_path):
                    os.remove(cfg_path)
            except OSError:
                pass

    if pending:
        print(f"[!] 回源补抓仍有 {len(pending)} 个源站未解决 (已试 {tried_egress} 个出口, "
              f"耗时 {time.time() - t_refetch:.0f}s)")
    elif recovered:
        print(f"[+] 回源补抓完成: {len(recovered)} 个源站恢复, 耗时 {time.time() - t_refetch:.0f}s")
    return recovered


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 B2: 家宽链式复测 (chain relay retest)
# ════════════════════════════════════════════════════════════════════

def chain_retest(test_results: list) -> list:
    """家宽链式复测: 模拟用户 v2rayN 链式 (前置 → 家宽节点 → 目标)

    实测背景: 用户反馈家宽节点在 v2rayN 链式代理下仅 ~50% 可用。
    根因: 单跳测活通过 ≠ 双跳可用 (部分节点不允许"已被代理的流量"再入,
    或 UDP/QUIC 节点无法过 socks 链)。解决: CI 里用最快存活节点当前置,
    对家宽候选做双跳复测 — 双跳通过的才进家宽专区。

    流程: 先跑一遍轻量分类拿到家宽候选 → 取最快存活节点做 relay →
    家宽候选逐个双跳复测 → 双跳也活的保留, 双跳死的降级普通区。
    返回: 更新 net_type 后的 test_results (原对象原地修改)。
    """
    # 1) 轻量分类拿家宽候选 (复用 classify_and_export 的候选判定, 但不导出)
    #    家宽候选 = ip-api/mmdb 六信号判 residential/mobile 的节点
    ip_api_info = {}
    all_exit_ips = list({r["exit_ip"] for r in test_results if r.get("exit_ip")})
    if all_exit_ips:
        try:
            ip_api_info = ip_api_batch_lookup(all_exit_ips)
        except Exception as e:
            print(f"[!] 链式复测: ip-api 批量失败 ({e}), 跳过链式复测")
            return test_results

    res_candidates = {}
    for r in test_results:
        if not (r.get("alive") and not r.get("is_stalled")):
            continue
        rec = ip_api_info.get(r.get("exit_ip"), {})
        t, c = classify_network_type(r["exit_ip"], r.get("exit_country_online"),
                                     r.get("exit_asn_online"),
                                     r.get("exit_asn_org_online"), rec or None)
        if t in ("residential", "mobile") and c >= 60:
            res_candidates[(r["server"].lower(), r["port"], r["proto"])] = r

    if not res_candidates:
        print("[*] 链式复测: 无家宽候选, 跳过")
        return test_results
    print(f"[*] 链式复测: {len(res_candidates)} 个家宽候选")

    # 2) 选 relay: 全体存活节点里延迟最低、非家宽候选自己 (避免自己套自己)
    alive_sorted = sorted(
        [r for r in test_results if r.get("alive") and not r.get("is_stalled")],
        key=lambda x: x.get("latency_ms", 99999))
    relay_result = None
    for r in alive_sorted:
        if (r["server"].lower(), r["port"], r["proto"]) not in res_candidates:
            relay_result = r
            break
    if not relay_result:
        print("[!] 链式复测: 无可用 relay 节点, 跳过")
        return test_results
    relay_out = relay_result.get("outbound")
    if not relay_out:
        # 重新解析 relay 的 raw 拿 outbound
        p = parse_node_uri(relay_result["raw"])
        if p:
            relay_out = p[0]
    if not relay_out:
        print("[!] 链式复测: relay outbound 构建失败, 跳过")
        return test_results
    # relay 必须剥离 detour (前置链复用时防循环)
    relay_out = dict(relay_out)
    relay_out.pop("detour", None)
    print(f"[*] 链式 relay: {relay_result['proto']} {relay_result['server']}:{relay_result['port']} "
          f"(延迟 {relay_result['latency_ms']}ms)")

    # 3) 家宽候选逐个双跳复测 (注入 CHAIN_RELAY_OUT, test_single_node 自动加 detour)
    os.environ["CHAIN_RELAY_OUT"] = json.dumps(relay_out)
    chain_alive, chain_dead = [], []
    try:
        for key, r in res_candidates.items():
            item = (r["raw"], r.get("outbound") or (parse_node_uri(r["raw"]) or [None])[0],
                    r["server"], r["port"], r["proto"])
            if not item[1]:
                chain_dead.append(r)
                continue
            recheck = test_single_node(item)
            if recheck and recheck.get("alive") and not recheck.get("is_stalled"):
                chain_alive.append(r)
            else:
                chain_dead.append(r)
    finally:
        os.environ.pop("CHAIN_RELAY_OUT", None)

    # 4) 双跳失败的 → 降级普通区 (不从订阅删除, 用户直连场景仍可能可用)
    for r in chain_dead:
        r["_chain_failed"] = True

    print(f"[+] 链式复测完成: 双跳可用 {len(chain_alive)} | 双跳失败降级 {len(chain_dead)}")
    return test_results


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 C: 出口 IP 批量情报 (ip-api.com 免费 batch) + 离线兜底
# ═══════════════════════════════════════════N═══════════════════════

def ip_api_batch_lookup(ip_list: list) -> dict:
    """ip-api.com batch (免费 HTTP, ≤100/req, 15 req/min → 1500 IP/min)"""
    info = {}
    session = requests.Session()
    session.trust_env = True  # 直连即可; ip-api.com 免费层全球可达 (CI 无代理/本地走系统代理均可)
    total_batches = (len(ip_list) + IP_API_BATCH_SIZE - 1) // IP_API_BATCH_SIZE
    for bi, i in enumerate(range(0, len(ip_list), IP_API_BATCH_SIZE), 1):
        chunk = ip_list[i:i + IP_API_BATCH_SIZE]
        payload = [{"query": ip} for ip in chunk]
        for attempt in range(3):
            try:
                r = session.post(IP_API_BATCH_URL, json=payload, timeout=20)
                if r.status_code == 200:
                    for rec in r.json():
                        q = rec.get("query")
                        if q:
                            info[q] = rec
                    break
                elif r.status_code == 429:
                    time.sleep(4 + attempt * 3)
                else:
                    time.sleep(2)
            except Exception:
                time.sleep(2)
        if total_batches >= 3 and (bi % 5 == 0 or bi == total_batches):
            print(f"[*] ip-api 进度: 批 {bi}/{total_batches} ({len(info)} IP 已查)")
        time.sleep(IP_API_BATCH_RPS_INTERVAL)
    return info


def offline_ip_lookup(ip: str, country_reader, asn_reader) -> tuple:
    """GeoLite2 离线查询 → (country, asn, org)"""
    country, asn, org = None, None, None
    try:
        c = country_reader.get(ip)
        if c and c.get("country", {}).get("iso_code"):
            country = c["country"]["iso_code"]
    except Exception:
        pass
    try:
        a = asn_reader.get(ip)
        if a:
            asn = a.get("autonomous_system_number")
            org = a.get("autonomous_system_organization", "")
    except Exception:
        pass
    return country, asn, org


def get_rdns(ip: str) -> str:
    """反向 DNS 查询 (★ 线程安全)

    旧实现用 socket.setdefaulttimeout(2.0) 改的是**进程级全局状态**,
    在 32 线程的分类池里会污染其他线程的 socket 超时 (包括探测用的),
    造成随机超时/随机失败。现在改为子线程 + join 控制超时, 不碰全局状态。
    """
    box = []

    def _work():
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            box.append(host.lower())
        except Exception:
            pass

    t = threading.Thread(target=_work, daemon=True)
    t.start()
    t.join(2.0)
    return box[0] if box else ""


def classify_network_type(ip: str, country: str, asn, org: str, ip_api_rec: dict = None) -> tuple:
    """
    返回 (net_type, confidence):
      net_type ∈ {datacenter, residential, mobile, cdn, unknown}
    优先级: ip-api.com hosting/mobile 字段 > CDN 网段 > ASN 白/黑名单 > 名称关键词
    """
    ip_str = str(ip)
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown", 0

    # 1) CDN / Anycast 网段 (硬判据)
    for net in CLOUDFLARE_IP_NETWORKS:
        if ip_obj in net:
            return "cdn", 100
    for net in CDN_IP_NETWORKS_EXTRA:
        if ip_obj in net:
            return "cdn", 95

    asn_int = None
    if isinstance(asn, int):
        asn_int = asn
    elif isinstance(asn, str) and asn:
        m = re.match(r"AS(\d+)", asn)
        if m:
            asn_int = int(m.group(1))

    org_lower = (org or "").lower()
    hosting_flag = False
    mobile_flag = False
    proxy_flag = False

    # 2) ip-api.com 在线字段 (最高可信)
    if ip_api_rec:
        hosting_flag = bool(ip_api_rec.get("hosting"))
        mobile_flag = bool(ip_api_rec.get("mobile"))
        proxy_flag = bool(ip_api_rec.get("proxy"))
        rec_asn = ip_api_rec.get("as") or ""
        m = re.match(r"AS(\d+)", str(rec_asn))
        if m and asn_int is None:
            asn_int = int(m.group(1))
        org_lower = (ip_api_rec.get("asname") or ip_api_rec.get("org") or org_lower).lower()

    if hosting_flag:
        return "datacenter", 90
    # ★ proxy/VPN/Tor 出口标志 (ip-api) — 硬否决家宽/民用
    # 实测 AS62610 Zenlayer (收购 speakeasy DSL legacy 段): hosting=false 但 proxy=true
    # 此类"机房收购家宽段"是假家宽主要形态, rDNS 带 dsl/pppoe 也不能信
    if proxy_flag:
        return "datacenter", 88
    if mobile_flag:
        return "mobile", 85

    # 3) ASN 白/黑名单
    if asn_int:
        if asn_int in DATACENTER_ASNS:
            return "datacenter", 80
        if asn_int in RESIDENTIAL_ASNS:
            return "residential", 82

    # 4) ISP 名称关键词
    if org_lower:
        for kw in IDC_NAME_PATTERNS:
            if kw in org_lower:
                return "datacenter", 70
        for kw in RESIDENTIAL_NAME_PATTERNS:
            if kw in org_lower:
                return "residential", 70

    # 5) rDNS 兜底
    rdns = get_rdns(ip_str)
    if rdns:
        for kw in IDC_NAME_PATTERNS:
            if kw in rdns:
                return "datacenter", 60
        for kw in RESIDENTIAL_NAME_PATTERNS:
            if kw in rdns:
                return "residential", 60

    return "unknown", 30


# ═══════════════════════════════════════════N═══════════════════════
# 节点 → 各客户端配置转换
# ═══════════════════════════════════════════N═══════════════════════

def outbound_to_clash(node: dict, name: str) -> dict:
    """sing-box outbound → Clash (Meta/mihomo) proxy dict"""
    t = node.get("type")
    server = node.get("server")
    port = node.get("server_port")
    
    # 安全处理：防止 hy2 端口跳跃节点缺少 server_port 导致崩溃
    if not server:
        return None
    if port is None:
        if node.get("server_ports"):
            # 取第一个端口区间的起始端口
            port = int(str(node["server_ports"][0]).split(":")[0])
        else:
            return None
            
    proxy = {"name": name, "server": server, "port": port, "udp": True}

    if t == "vless":
        proxy["type"] = "vless"
        proxy["uuid"] = node["uuid"]
        if node.get("flow"):
            proxy["flow"] = node["flow"]
        tls = node.get("tls") or {}
        if tls.get("reality"):
            proxy["tls"] = True
            proxy["reality-opts"] = {"public-key": tls["reality"]["public_key"]}
            if tls["reality"].get("short_id"):
                proxy["reality-opts"]["short-id"] = tls["reality"]["short_id"]
            proxy["servername"] = tls.get("server_name") or server
            if tls.get("utls"):
                proxy["client-fingerprint"] = tls["utls"].get("fingerprint", "chrome")
        elif tls.get("enabled"):
            proxy["tls"] = True
            proxy["servername"] = tls.get("server_name") or server
            proxy["skip-cert-verify"] = bool(tls.get("insecure"))
            if tls.get("utls"):
                proxy["client-fingerprint"] = tls["utls"].get("fingerprint", "chrome")
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
                if transport.get("headers"):
                    proxy["ws-opts"]["headers"] = transport["headers"]
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
            elif transport["type"] == "http":
                proxy["network"] = "h2"
                proxy["h2-opts"] = {"host": transport.get("host", []),
                                    "path": transport.get("path", "/")}
            elif transport["type"] == "httpupgrade":
                proxy["network"] = "httpupgrade"
                proxy["httpupgrade-opts"] = {"path": transport.get("path", "/"),
                                              "headers": {"Host": transport.get("host", "")}}
    elif t == "vmess":
        proxy["type"] = "vmess"
        proxy["uuid"] = node["uuid"]
        proxy["alterId"] = node.get("alter_id", 0)
        proxy["cipher"] = "auto"
        tls = node.get("tls") or {}
        if tls.get("enabled"):
            proxy["tls"] = True
            proxy["servername"] = tls.get("server_name") or server
            proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
                if transport.get("headers"):
                    proxy["ws-opts"]["headers"] = transport["headers"]
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
            elif transport["type"] == "http":
                proxy["network"] = "h2"
                proxy["h2-opts"] = {"host": transport.get("host", []),
                                    "path": transport.get("path", "/")}
    elif t == "trojan":
        proxy["type"] = "trojan"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
    elif t == "shadowsocks":
        proxy["type"] = "ss"
        proxy["cipher"] = node["method"]
        proxy["password"] = node["password"]
    elif t == "hysteria2":
        proxy["type"] = "hysteria2"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        if node.get("obfs"):
            proxy["obfs"] = node["obfs"].get("type")
            proxy["obfs-password"] = node["obfs"].get("password", "")
        if node.get("server_ports"):
            proxy["ports"] = ",".join(p.replace(":", "-") for p in node["server_ports"])
    elif t == "tuic":
        proxy["type"] = "tuic"
        proxy["uuid"] = node["uuid"]
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        proxy["congestion-controller"] = node.get("congestion_control", "bbr")
        proxy["udp-relay-mode"] = node.get("udp_relay_mode", "native")
        if tls.get("alpn"):
            proxy["alpn"] = tls["alpn"]
    elif t == "anytls":
        proxy["type"] = "anytls"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
    else:
        return None
    return proxy


def outbound_to_v2ray_link(node: dict, name: str) -> str:
    """sing-box outbound → v2rayN 兼容 URI"""
    t = node.get("type")
    # 端口跳跃节点 (hy2 mport): 无 server_port 时取 server_ports 首区间起始端口
    if "server_port" in node:
        port = node["server_port"]
    elif node.get("server_ports"):
        port = int(str(node["server_ports"][0]).split(":")[0])
    else:
        return ""
    server = node["server"]
    tls = node.get("tls") or {}
    transport = node.get("transport") or {}

    if t == "vmess":
        ttype = transport.get("type", "tcp")
        data = {
            "v": "2", "ps": name, "add": server, "port": str(port),
            "id": node["uuid"], "aid": str(node.get("alter_id", 0)),
            "scy": "auto", "net": ttype,
            "type": "none",
            "host": "", "path": "",
            "tls": "tls" if tls.get("enabled") else "",
            "sni": tls.get("server_name", ""),
        }
        if ttype == "ws":
            if transport.get("path"):
                data["path"] = transport["path"]
            if (transport.get("headers") or {}).get("Host"):
                data["host"] = transport["headers"]["Host"]
            if transport.get("max_early_data"):
                data["path"] = (data["path"] or "") + f"?ed={transport['max_early_data']}"
        elif ttype == "grpc":
            if transport.get("service_name"):
                data["path"] = transport["service_name"]
        elif ttype == "http":
            if transport.get("path"):
                data["path"] = transport["path"]
            if transport.get("host"):
                data["host"] = ",".join(transport["host"])
        elif ttype == "httpupgrade":
            if transport.get("path"):
                data["path"] = transport["path"]
            if transport.get("host"):
                data["host"] = transport["host"]
        return "vmess://" + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()
    if t == "vless":
        q = {}
        ttype = transport.get("type")
        if ttype:
            q["type"] = ttype
            if ttype == "ws":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if (transport.get("headers") or {}).get("Host"):
                    q["host"] = transport["headers"]["Host"]
                if transport.get("max_early_data"):
                    q["ed"] = str(transport["max_early_data"])
            elif ttype == "grpc":
                if transport.get("service_name"):
                    q["serviceName"] = transport["service_name"]
            elif ttype == "http":
                if transport.get("host"):
                    q["host"] = ",".join(transport["host"])
                if transport.get("path"):
                    q["path"] = transport["path"]
            elif ttype == "httpupgrade":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if transport.get("host"):
                    q["host"] = transport["host"]
        if tls.get("reality"):
            q["security"] = "reality"
            q["pbk"] = tls["reality"]["public_key"]
            q["sid"] = tls["reality"].get("short_id", "")
            q["fp"] = (tls.get("utls") or {}).get("fingerprint", "chrome")
            if tls.get("server_name"):
                q["sni"] = tls["server_name"]
        elif tls.get("enabled"):
            q["security"] = "tls"
            if tls.get("server_name"):
                q["sni"] = tls["server_name"]
            if tls.get("alpn"):
                q["alpn"] = ",".join(tls["alpn"])
            if tls.get("utls"):
                q["fp"] = tls["utls"].get("fingerprint", "chrome")
            if tls.get("insecure"):
                q["allowInsecure"] = "1"
        if node.get("flow"):
            q["flow"] = node["flow"]
        query = urllib.parse.urlencode(q)
        return f"vless://{node['uuid']}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "trojan":
        q = {"security": "tls"}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("alpn"):
            q["alpn"] = ",".join(tls["alpn"])
        if (tls.get("utls") or {}).get("fingerprint"):
            q["fp"] = tls["utls"]["fingerprint"]
        if tls.get("insecure"):
            q["allowInsecure"] = "1"
        ttype = transport.get("type")
        if ttype:
            q["type"] = ttype
            if ttype == "ws":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if (transport.get("headers") or {}).get("Host"):
                    q["host"] = transport["headers"]["Host"]
                if transport.get("max_early_data"):
                    q["ed"] = str(transport["max_early_data"])
            elif ttype == "grpc":
                if transport.get("service_name"):
                    q["serviceName"] = transport["service_name"]
            elif ttype == "httpupgrade":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if transport.get("host"):
                    q["host"] = transport["host"]
        query = urllib.parse.urlencode(q)
        return f"trojan://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "shadowsocks":
        # SIP002: userinfo = urlsafe-base64(method:password), ★ 必须保留 padding ("=")
        # 实测: rstrip("=") 砍 padding 后 v2rayN 解析失败 (无 padding 的畸形 base64)
        # urlsafe 字母表 (A-Za-z0-9-_) + "=" 均为 URI 合法字符, 不需再 quote (quote 反而破坏 "=")
        userinfo = base64.urlsafe_b64encode(
            f"{node['method']}:{node['password']}".encode()).decode()
        return f"ss://{userinfo}@{server}:{port}#{urllib.parse.quote(name)}"
    if t == "hysteria2":
        q = {}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["insecure"] = "1"
        if node.get("obfs"):
            q["obfs"] = node["obfs"].get("type", "salamander")
            q["obfs-password"] = node["obfs"].get("password", "")
        if node.get("server_ports"):
            q["mport"] = ",".join(p.replace(":", "-") for p in node["server_ports"])
        query = urllib.parse.urlencode(q)
        return f"hysteria2://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "tuic":
        q = {
            "congestion_control": node.get("congestion_control", "bbr"),
            "udp_relay_mode": node.get("udp_relay_mode", "native"),
            "alpn": ",".join((tls.get("alpn") or ["h3"])),
        }
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["allow_insecure"] = "1"
        query = urllib.parse.urlencode(q)
        return f"tuic://{urllib.parse.quote(node['uuid'])}:{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "anytls":
        q = {}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["insecure"] = "1"
        query = urllib.parse.urlencode(q)
        return f"anytls://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    return ""


def outbound_to_singbox(node: dict, name: str) -> dict:
    n = dict(node)
    n["tag"] = name
    return n


# ═══════════════════════════════════════════N═══════════════════════
# 分类 + 导出
# ═══════════════════════════════════════════N═══════════════════════

def scamalytics_fraud_score(ip: str) -> int:
    """Scamalytics 免费风控评分 (HTML 抓取, subs-check 同款方案)
    返回 0-100: 越高越危险; 失败返回 -1 (不参与判定)"""
    try:
        r = DIRECT_SESSION.get(f"https://scamalytics.com/ip/{ip}", timeout=10)
        if r.status_code != 200:
            return -1
        m = re.search(r"Fraud Score:\s*(\d+)", r.text)
        return int(m.group(1)) if m else -1
    except Exception:
        return -1


def ipapi_is_verify(ip: str) -> dict:
    """ipapi.is 免费交叉源 (1000 req/天, 无 key)
    实测对 AS62610 Zenlayer (收购 speakeasy DSL 段伪装家宽) 能给出
    company=Bunny Communications; 对真家宽 (SK Broadband) 给运营商名。
    仅用其 company/asn 字段做家宽候选的二次否决。失败返回 {}"""
    try:
        r = DIRECT_SESSION.get(f"https://api.ipapi.is/?q={ip}", timeout=10)
        if r.status_code != 200:
            return {}
        j = r.json()
        return {"company": j.get("company") or "", "asn": j.get("asn") or "",
                "country": j.get("country") or ""}
    except Exception:
        return {}


def cred_fingerprint(outbound: dict, proto: str) -> str:
    """凭据指纹: 各协议的核心身份字段 (同 server+port+proto+凭据 = 同一节点)"""
    try:
        if proto == "vless":
            return f"{outbound.get('uuid','')}"
        if proto == "vmess":
            return f"{outbound.get('uuid','') or outbound.get('user_id','')}"
        if proto == "trojan":
            return f"{outbound.get('password','')}"
        if proto == "shadowsocks":
            return f"{outbound.get('method','')}|{outbound.get('password','')}"
        if proto == "hysteria2":
            return f"{outbound.get('password','') or ''}|{outbound.get('server_ports','')}"
        if proto == "tuic":
            return f"{outbound.get('uuid','')}|{outbound.get('password','')}"
        if proto == "anytls":
            return f"{outbound.get('password','')}"
        return json.dumps({k: v for k, v in outbound.items()
                           if k in ("uuid", "password", "user_id", "method")}, sort_keys=True)
    except Exception:
        return ""  # 指纹失败 → 不合并 (宁慢不错)


def load_state() -> dict:
    """读取跨运行记忆 (output/state.json); 缺失/损坏一律返回空 dict"""
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_state(state: dict):
    """原子写入跨运行记忆"""
    try:
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, STATE_FILE)
    except Exception as e:
        print(f"[!] state.json 写入失败: {e}")


def state_key(server, port, proto, cred="") -> str:
    """记忆 key 含凭据: 同 host:port 上不同凭据是不同节点,
    否则活凭据会把死凭据的 consec_dead 重置, 历史轨迹会串号。"""
    return f"{(server or '').lower()}:{port}|{proto}|{cred}"


def build_state(test_results: list, prev_state: dict) -> dict:
    """按本轮结果更新记忆

    - 本轮出现的 key: 累加 ever / 重置或累加 consec_dead
    - 本轮未出现的 key: 保留最多 3 轮 (miss 计数), 防订阅源抖动导致历史被清空
    - 从未活过且连续失败超限的: 丢弃 (无参考价值, 也避免 state.json 无限膨胀)

    注: 记忆只作历史轨迹留档, 不再影响出库 (救援池已下线)。
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    merged = {}
    for r in test_results:
        k = state_key(r.get("server"), r.get("port"), r.get("proto"), r.get("cred", ""))
        alive = bool(r.get("alive"))
        if k in merged:
            merged[k] = merged[k] or alive     # 同 key 多份 (回填克隆) 任一份活即算活
        else:
            merged[k] = alive

    out = {}
    for k, rec in prev_state.items():
        if k in merged:
            continue
        miss = rec.get("miss", 0) + 1
        if miss > 3:
            continue
        out[k] = {
            "ever": rec.get("ever", 0),
            "consec_dead": rec.get("consec_dead", 0),
            "last": rec.get("last", ""),
            "miss": miss,
        }
    for k, alive in merged.items():
        prev = prev_state.get(k) or {}
        ever = prev.get("ever", 0) + (1 if alive else 0)
        consec = 0 if alive else prev.get("consec_dead", 0) + 1
        if ever == 0 and consec >= STATE_MAX_CONSEC_DEAD:
            continue      # 从没活过且已判死 → 不再记忆
        out[k] = {"ever": ever, "consec_dead": consec, "last": today, "miss": 0}
    return out


def classify_and_export(test_results: list):
    print("[*] 出口 IP 情报与分类 ...")
    # 收集全部出口 IP
    all_exit_ips = []
    seen_ip = set()
    for r in test_results:
        if r["exit_ip"] and r["exit_ip"] not in seen_ip:
            seen_ip.add(r["exit_ip"])
            all_exit_ips.append(r["exit_ip"])
    print(f"[*] 待查询出口 IP: {len(all_exit_ips)} 个 (ip-api.com 批量 {len(test_results)} 节点)")

    ip_api_info = {}
    scam_scores = {}
    if all_exit_ips:
        try:
            est_batches = (len(all_exit_ips) + IP_API_BATCH_SIZE - 1) // IP_API_BATCH_SIZE
            print(f"[*] ip-api 批量: {est_batches} 批 × ~4.2s ≈ {est_batches * 4.2:.0f}s (免费限 15 req/min, 请耐心) ...")
            ip_api_info = ip_api_batch_lookup(all_exit_ips)
            print(f"[+] ip-api.com 批量情报: {len(ip_api_info)}/{len(all_exit_ips)}")
        except Exception as e:
            print(f"[!] ip-api 批量失败, 将全量走离线: {e}")

    country_reader = asn_reader = None
    try:
        country_reader = maxminddb.open_database(os.path.join(RUNTIME_DIR, "Country.mmdb"))
        asn_reader = maxminddb.open_database(os.path.join(RUNTIME_DIR, "ASN.mmdb"))
    except Exception as e:
        print(f"[!] MaxMind 数据库打开失败: {e}")

    # ★ 预解析入口域名 (并行): 出口 IP 查不到国家时(中转隧道/内网出口)要用入口 IP 定位地区。
    #   串行 DoH 会把这一步拖成几十秒; 预检阶段已缓存的会直接跳过。
    #   只解析存活节点 —— 死节点的地区信息没有出库价值。
    pending_hosts = {
        r["server"] for r in test_results
        if r.get("alive")
        and r.get("server") and not is_ip_literal(r["server"])
        and r["server"] not in _DNS_CACHE
    }
    if pending_hosts:
        print(f"[*] 预解析入口域名: {len(pending_hosts)} 个 ...")
        with ThreadPoolExecutor(max_workers=48) as ex:
            list(ex.map(resolve_host, pending_hosts))

    nodes = []
    for r in test_results:
        exit_ip = r.get("exit_ip")
        online_country = r.get("exit_country_online")
        country = online_country
        asn, org = r.get("exit_asn_online"), r.get("exit_asn_org_online")
        if isinstance(asn, int):
            pass
        elif isinstance(asn, str):
            m = re.match(r"AS(\d+)", asn)
            asn = int(m.group(1)) if m else None

        # 在线情报缺失 → 离线 mmdb 兜底
        if country_reader and exit_ip and (not country or not asn):
            off_c, off_asn, off_org = offline_ip_lookup(exit_ip, country_reader, asn_reader)
            country = country or off_c
            asn = asn or off_asn
            org = org or off_org

        # ★ 入口 IP 情报: 仅用于"出口 IP 查不到国家"时的地区兜底
        srv = r.get("server") or ""
        entry_ip, entry_country, entry_asn, entry_org = None, None, None, None
        if srv and r.get("alive"):
            entry_ip = srv if is_ip_literal(srv) else resolve_host(srv)
            if entry_ip and country_reader:
                entry_country, entry_asn, entry_org = offline_ip_lookup(
                    entry_ip, country_reader, asn_reader)

        # ★ 出口 IP 查不到国家 (云内网/中转隧道) → 回退用入口服务器 IP 定位国家
        #    (中转节点出口常是内网地址, mmdb 也查不到; 入口国 ≠ 出口国但至少给用户可用地区)
        if (not country or country in ("OTHER", "ZZ")) and entry_country:
            if entry_country not in ("OTHER", "ZZ"):
                country = entry_country
                asn = asn or entry_asn
                org = org or entry_org

        rec = ip_api_info.get(exit_ip, {}) if exit_ip else {}
        net_type, confidence = classify_network_type(
            exit_ip, country, asn, org, rec or None)

        # 无真实出口 IP 的节点: 国家未知, 不入家宽区
        if not exit_ip:
            country = country or "OTHER"

        nodes.append({
            "raw": r["raw"],
            "server": r["server"],
            "port": r["port"],
            "proto": r["proto"],
            "outbound": r.get("outbound"),
            "status": r.get("status", "alive"),
            "fail_stage": r.get("fail_stage", ""),
            "country": (country or "OTHER").upper(),
            "net_type": net_type,
            "confidence": confidence,
            "exit_ip": exit_ip,
            "asn": asn,
            "org": org,
            "isp": r.get("exit_isp_online") or (rec.get("isp") if rec else ""),
            "latency_ms": r["latency_ms"],
            "speed_bps": r.get("speed_bps", 0),
            "speed_unmeasured": r.get("speed_unmeasured", False),
            "mitm_risk": r.get("mitm_risk", False),
            "is_stalled": r.get("is_stalled", False),
            "is_warp": r.get("is_warp", False),
            "quality_flags": r.get("quality_flags") or [],
            "entry_ip": entry_ip,
            "entry_country": entry_country,
            "entry_asn": entry_asn,
        })

    if country_reader:
        country_reader.close()
    if asn_reader:
        asn_reader.close()

    # ── 风险过滤 (仅作用于存活节点; 失败节点只用于统计失败原因, 不出库) ──
    alive_nodes = [n for n in nodes if n["status"] == "alive"]
    unreachable_nodes = [n for n in nodes if n["status"] != "alive"]

    # MITM: 只剔除证书链验证失败的 (真实 TLS 拦截), 不再用 HTTP 状态码猜测
    safe_nodes = [n for n in alive_nodes if not n["mitm_risk"]]
    mitm_dropped = len(alive_nodes) - len(safe_nodes)
    # 断流: 仅在"实测到速度且低于阈值"时剔除; 未测到速度的保留
    stalled_dropped = sum(1 for n in safe_nodes if n["is_stalled"])
    safe_nodes = [n for n in safe_nodes if not n["is_stalled"]]
    print(f"[*] 风险过滤: MITM 证书劫持剔除 {mitm_dropped} | 实测断流剔除 {stalled_dropped} "
          f"| 保留存活 {len(safe_nodes)} | 未连通(不出库) {len(unreachable_nodes)}")

    # ── Scamalytics 风控评分 (免费 HTML, 逐个; 只查家宽候选 + 抽样普通节点) ──
    # 家宽候选: 全查 (宁缺毋滥); 普通节点: 每 IP 查一次 (通常 <= 出口 IP 数)
    scam_candidates = set()
    for n in safe_nodes:
        if n["net_type"] in ("residential", "mobile") and n["exit_ip"]:
            scam_candidates.add(n["exit_ip"])
    if scam_candidates:
        print(f"[*] Scamalytics 风控评分: 查询 {len(scam_candidates)} 个家宽候选出口 IP ...")
        def _scam(ip):
            return ip, scamalytics_fraud_score(ip)
        with ThreadPoolExecutor(max_workers=6) as ex:
            for ip, score in ex.map(_scam, scam_candidates):
                scam_scores[ip] = score
        got = sum(1 for v in scam_scores.values() if v >= 0)
        print(f"[+] Scamalytics 评分获得: {got}/{len(scam_candidates)}")

    # ── ipapi.is 交叉核验 (只查家宽候选, 免费 1000 次/天) ──
    # ip-api 判 hosting/proxy 也有漏 (伪装家宽: 收购 DSL 段的云边网络)。
    # ipapi.is 独立数据源: company 含 IDC 词 → 否决家宽
    ipapi_verify = {}
    verify_candidates = set()
    for n in safe_nodes:
        if n["net_type"] in ("residential", "mobile") and n["exit_ip"]:
            verify_candidates.add(n["exit_ip"])
    if verify_candidates:
        print(f"[*] ipapi.is 交叉核验: {len(verify_candidates)} 个家宽候选 ...")
        def _verify(ip):
            return ip, ipapi_is_verify(ip)
        with ThreadPoolExecutor(max_workers=4) as ex:
            for ip, info in ex.map(_verify, verify_candidates):
                ipapi_verify[ip] = info
        # 否决: company/asn 含机房词
        vetoed = 0
        for n in safe_nodes:
            if n["net_type"] not in ("residential", "mobile"):
                continue
            info = ipapi_verify.get(n["exit_ip"]) or {}
            comp_asn = (info.get("company", "") + " " + info.get("asn", "")).lower()
            if any(kw in comp_asn for kw in (
                "zenlayer", "bunny", "cloudflare", "akamai", "fastly",
                "amazon", "google llc", "microsoft", "digitalocean", "vultr",
                "hetzner", "ovh", "contabo", "leaseweb", "datacamp",
                "serverius", "clouvider", "m247", "gcore", "g-core",
                "choopa", "linode", "alibaba", "tencent", "huawei cloud",
            )):
                n["net_type"] = "datacenter"
                n["confidence"] = 85
                vetoed += 1
        if vetoed:
            print(f"[*] ipapi.is 否决假家宽: {vetoed} 个 (云商收购家宽段伪装)")

    # 风险分 >= 75 的家宽候选降级为普通 (fraud 池/被滥用 IP 绝不入家宽区)
    downgraded = 0
    for n in safe_nodes:
        sc = scam_scores.get(n["exit_ip"], -1)
        n["fraud_score"] = sc
        if n["net_type"] in ("residential", "mobile") and sc >= 75:
            n["net_type"] = "datacenter"  # 高 fraud 分: 大概率代理池滥用 IP
            n["confidence"] = 60
            downgraded += 1
    if downgraded:
        print(f"[*] 高 fraud 分 (≥75) 家宽候选降级: {downgraded} 个")

    # ── 去重 (同出口IP+端口 只留最快) ──
    best_by_key = {}
    for n in safe_nodes:
        key = f"{n['exit_ip']}:{n['port']}" if n["exit_ip"] else f"{n['server']}:{n['port']}|{n['raw'][:64]}"
        cur = best_by_key.get(key)
        if not cur or n["latency_ms"] < cur["latency_ms"]:
            best_by_key[key] = n
    unique_nodes = list(best_by_key.values())
    dup_dropped = len(safe_nodes) - len(unique_nodes)
    print(f"[*] 去重: {len(safe_nodes)} → {len(unique_nodes)} (剔除重复 {dup_dropped})")

    # 去重: 出口IP+端口 唯一化, 家宽区严格防同IP刷屏
    # ★ 链式复测 (chain_retest) 双跳失败的家宽候选 → 不进家宽专区 (降级普通)
    chain_failed_raws = set()
    for r in test_results:
        if r.get("_chain_failed"):
            chain_failed_raws.add(r.get("raw"))
    residential = []
    res_seen_ip = set()
    for n in unique_nodes:
        if n["net_type"] in ("residential", "mobile") and n["confidence"] >= 60:
            if n.get("raw") in chain_failed_raws:
                n["net_type"] = "datacenter"
                n["confidence"] = 70
                continue
            if n["exit_ip"] and n["exit_ip"] not in res_seen_ip:
                res_seen_ip.add(n["exit_ip"])
                residential.append(n)
    # fraud 分极高 (≥90) 的节点整体剔除 (任何区都不要)
    before_total = len(unique_nodes)
    unique_nodes = [n for n in unique_nodes if not (0 <= n.get("fraud_score", -1) >= 90)]
    residential = [n for n in residential if not (0 <= n.get("fraud_score", -1) >= 90)]
    if len(unique_nodes) < before_total:
        print(f"[*] 极高危节点 (fraud≥90) 剔除: {before_total - len(unique_nodes)} 个")

    res_ids = {id(n) for n in residential}
    non_residential = [n for n in unique_nodes if id(n) not in res_ids]
    print(f"[*] 家宽/移动网络节点: {len(residential)} | 普通(机房/CDN): {len(non_residential)}")

    # 排序: 家宽在前, 延迟升序
    unique_nodes.sort(key=lambda x: (0 if id(x) in res_ids else 1, x["latency_ms"]))
    residential.sort(key=lambda x: x["latency_ms"])
    non_residential.sort(key=lambda x: x["latency_ms"])

    # 重建 outbound (测活阶段的 outbound 已验证可用); 剥离测试专用字段 (detour 等绝不入订阅)
    for n in unique_nodes:
        parsed = parse_node_uri(n["raw"])
        if parsed:
            ob = parsed[0]
            ob.pop("detour", None)
            n["outbound"] = ob
        else:
            n["outbound"] = None
    unique_nodes = [n for n in unique_nodes if n["outbound"]]
    residential = [n for n in residential if n["outbound"]]
    non_residential = [n for n in non_residential if n["outbound"]]

    return unique_nodes, residential, non_residential


def make_node_name(item, idx, force_residential=False):
    cc = item["country"]
    flag = get_country_flag(cc)
    cname = COUNTRY_NAMES.get(cc, cc)
    is_res = item["net_type"] in ("residential", "mobile") and (item["confidence"] >= 60 or force_residential)
    tag = ""
    if is_res:
        tag = " (家宽)" if item["net_type"] == "residential" else " (移动家宽)"
    # Scamalytics 风控分: 高风险节点名内标注 (R分数), 低危不标 (保持简洁)
    fraud = item.get("fraud_score", -1)
    risk_tag = f" R{fraud}" if 0 <= fraud < 75 and fraud >= 40 else (" ⚠R" if fraud >= 75 else "")
    return f"{flag} {cname} {idx:02d}{tag}{risk_tag} - xiaohe"


def export_all(unique_nodes, residential, non_residential):
    ensure_directories()

    def build_group(nodes_list, force_res=False):
        links, proxies, sb_nodes = [], [], []
        for idx, item in enumerate(nodes_list, start=1):
            name = make_node_name(item, idx, force_res)
            ob = item["outbound"]
            if not ob:
                continue
            links.append(outbound_to_v2ray_link(ob, name))
            cp = outbound_to_clash(ob, name)
            if cp:
                proxies.append(cp)
            sb_nodes.append(outbound_to_singbox(ob, name))
        return links, proxies, sb_nodes

    def write_sub(base_name, links, proxies, sb_nodes):
        """写一套订阅 (txt / clash / singbox)

        空集时写**最小合法空配置**而不是删文件 —— README 里三个链接永远指向存在的文件,
        客户端拉下来显示 0 节点, 而不是 404 报错 (用户会以为项目挂了)。
        """
        txt_path = os.path.join(OUTPUT_DIR, f"{base_name}.txt")
        clash_path = os.path.join(OUTPUT_DIR, f"{base_name}-clash.yaml")
        sb_path = os.path.join(OUTPUT_DIR, f"{base_name}-singbox.json")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(links).encode()).decode())
        if links:
            export_clash_yaml(proxies, clash_path)
            export_singbox_json(sb_nodes, sb_path)
        else:
            # 空 clash: 无 proxy, 全部走 DIRECT (clash 不接受 proxies 为空的 select 组)
            with open(clash_path, "w", encoding="utf-8") as f:
                yaml.dump({"port": 7890, "socks-port": 7891, "allow-lan": True,
                           "mode": "rule", "log-level": "info",
                           "proxies": [], "proxy-groups": [],
                           "rules": ["MATCH,DIRECT"]},
                          f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            # 空 sing-box: 只留 direct 出站
            with open(sb_path, "w", encoding="utf-8") as f:
                json.dump({"log": {"level": "warn"},
                           "outbounds": [{"type": "direct", "tag": "direct"}]},
                          f, indent=2, ensure_ascii=False)
        return len(links)

    # 1) 全量
    all_links, all_proxies, all_sb = build_group(unique_nodes)
    with open(os.path.join(OUTPUT_DIR, "v2ray.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(all_links).encode()).decode())
    export_clash_yaml(all_proxies, os.path.join(OUTPUT_DIR, "clash.yaml"))
    export_singbox_json(all_sb, os.path.join(OUTPUT_DIR, "singbox.json"))

    # 2) ★ 家宽总订阅: 所有国家/地区的家宽+移动网络节点汇总 (不按国家拆)
    res_links, res_proxies, res_sb = build_group(residential, force_res=True)
    write_sub("residential", res_links, res_proxies, res_sb)

    # 3) 4) 按国家分区 (★ 无存活节点时不动, 否则会把线上 by-country 清空)
    if unique_nodes:
        # 3) 按国家 - 普通区
        shutil.rmtree(COUNTRY_DIR, ignore_errors=True)
        os.makedirs(COUNTRY_DIR, exist_ok=True)
        by_cc = {}
        for n in non_residential:
            by_cc.setdefault(n["country"], []).append(n)
        for cc, lst in by_cc.items():
            l, p, s = build_group(lst)
            with open(os.path.join(COUNTRY_DIR, f"{cc}.txt"), "w", encoding="utf-8") as f:
                f.write(base64.b64encode("\n".join(l).encode()).decode())
            export_clash_yaml(p, os.path.join(COUNTRY_DIR, f"clash-{cc}.yaml"))
            export_singbox_json(s, os.path.join(COUNTRY_DIR, f"singbox-{cc}.json"))

        # 4) 按国家 - 家宽区
        shutil.rmtree(RESIDENTIAL_COUNTRY_DIR, ignore_errors=True)
        os.makedirs(RESIDENTIAL_COUNTRY_DIR, exist_ok=True)
        res_by_cc = {}
        for n in residential:
            res_by_cc.setdefault(n["country"], []).append(n)
        for cc, lst in res_by_cc.items():
            l, p, s = build_group(lst, force_res=True)
            with open(os.path.join(RESIDENTIAL_COUNTRY_DIR, f"{cc}.txt"), "w", encoding="utf-8") as f:
                f.write(base64.b64encode("\n".join(l).encode()).decode())
            export_clash_yaml(p, os.path.join(RESIDENTIAL_COUNTRY_DIR, f"clash-{cc}.yaml"))
            export_singbox_json(s, os.path.join(RESIDENTIAL_COUNTRY_DIR, f"singbox-{cc}.json"))

    print(f"[*] 导出完毕: 全量 {len(all_links)} | 家宽总订阅 {len(res_links)}")
    return len(all_links), len(res_links)


def export_clash_yaml(clash_proxies, filepath):
    names = [p["name"] for p in clash_proxies]
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "PROXIES", "type": "select", "proxies": ["AUTO"] + names},
            {"name": "AUTO", "type": "url-test", "url": "https://www.gstatic.com/generate_204",
             "interval": 300, "proxies": names},
        ],
        "rules": ["MATCH,PROXIES"],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)


def export_singbox_json(sb_nodes, filepath):
    names = [n["tag"] for n in sb_nodes]
    outbounds = sb_nodes + [
        {"type": "selector", "tag": "select", "outbounds": ["auto"] + names},
        {"type": "urltest", "tag": "auto", "outbounds": names,
         "url": "https://www.gstatic.com/generate_204"},
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ]
    config = {"log": {"level": "warn"},
              "outbounds": outbounds}
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════N═══════════════════════
# README 生成
# ═══════════════════════════════════════════N═══════════════════════

def update_readme(total_count, res_count):
    repo_name = os.environ.get("GITHUB_REPOSITORY", "hezhanleiok/freesub").strip()
    # ★ 订阅链接跟随当前分支 (test 分支上写死 @main 会让用户订阅到主分支的旧数据)
    branch = (os.environ.get("GITHUB_REF_NAME") or "main").strip() or "main"
    # 私有化部署 Worker 脚本里的仓库参数 (默认值兜底)
    try:
        owner, repo = repo_name.split("/", 1)
    except ValueError:
        owner, repo = "hezhanleiok", "freesub"

    def count_file(path):
        if not os.path.exists(path):
            return 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                c = f.read().strip()
                if not c:
                    return 0
                decoded = base64.b64decode(c).decode("utf-8", errors="ignore")
                return len([ln for ln in decoded.splitlines() if ln.strip()])
        except Exception:
            return 0

    res_counts, normal_counts = {}, {}
    for d, store in ((RESIDENTIAL_COUNTRY_DIR, res_counts), (COUNTRY_DIR, normal_counts)):
        if os.path.exists(d):
            for fn in os.listdir(d):
                if fn.endswith(".txt"):
                    cnt = count_file(os.path.join(d, fn))
                    if cnt > 0:
                        store[fn[:-4]] = cnt

    def table_rows(counts, sub):
        rows = []
        for cc in sorted(counts, key=lambda x: counts[x], reverse=True):
            flag = get_country_flag(cc)
            name = COUNTRY_NAMES.get(cc, cc)
            cnt = counts[cc]
            v2 = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@{branch}/output/{sub}/{cc}.txt) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/{branch}/output/{sub}/{cc}.txt)"
            cl = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@{branch}/output/{sub}/clash-{cc}.yaml) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/{branch}/output/{sub}/clash-{cc}.yaml)"
            sb = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@{branch}/output/{sub}/singbox-{cc}.json) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/{branch}/output/{sub}/singbox-{cc}.json)"
            rows.append(f"| {flag} {name} | {cnt} | {v2} | {cl} | {sb} |")
        return "\n".join(rows) if rows else "| 暂无可用节点 | 0 | - | - | - |"

    res_table = table_rows(res_counts, "residential-by-country")
    normal_table = table_rows(normal_counts, "by-country")

    readme = f"""# 🚀 免费节点自动测活订阅池 (含真实家宽/住宅IP甄选)

> 👤 **定制规范命名**: 所有订阅节点均重命名为 `国旗 地区 序号 (家宽) - xiaohe`
> ⚡ **真实可用保障**: 所有节点由 `sing-box {SINGBOX_VERSION}` 内核建立实际代理隧道, 完成真实 HTTPS 双向传输握手 + 出口 IP 穿透验证 + Cloudflare 限速下载断流检测 + TLS 证书校验 (MITM 劫持识别), 拒绝虚假通畅、断流节点与高危劫持节点。
> 🛡️ **全协议支持**: VLESS (Reality/Vision) · VMESS · Trojan · Shadowsocks · Hysteria2 · TUIC · AnyTLS

---

## 📌 全部节点总订阅链接

> 全部为**海外实测存活**节点 (sing-box 真实握手 + 出口 IP 穿透 + 断流检测通过)。国内使用请开启前置代理。

| 客户端 / 格式类型 | 节点总数 | 免翻 CDN 加速直链 | 官方原生 Raw 直链 (开启代理) |
| :--- | :---: | :--- | :--- |
| 🚀 **Clash (YAML 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@{branch}/output/clash.yaml) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/{branch}/output/clash.yaml) |
| ⚡ **V2RayN (Base64 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@{branch}/output/v2ray.txt) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/{branch}/output/v2ray.txt) |
| 📦 **sing-box (JSON 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@{branch}/output/singbox.json) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/{branch}/output/singbox.json) |

---

## 🏠 按照家宽分类节点订阅 (住宅 IP 专区)

> 家宽判定六重信号: ① ip-api.com `hosting` 字段 ② `mobile` 移动网络字段 ③ Cloudflare/主流 CDN Anycast 网段比对 ④ MaxMind GeoLite2 ASN 白/黑名单 (覆盖 60+ 国家主流民用运营商) ⑤ rDNS/ISP 名称特征 ⑥ Scamalytics 风控评分复核 (fraud ≥75 降级、≥90 剔除)。排除所有云主机/数据中心/CDN 任播, 保留真实民用宽带与移动网络。

### 🌍 家宽总订阅 (全部国家汇总 · 推荐)

> 把下面所有国家/地区的家宽 + 移动网络节点合并成一份, 不用逐个国家订阅。

| 客户端 / 格式类型 | 节点总数 | 免翻 CDN 加速直链 | 官方原生 Raw 直链 (开启代理) |
| :--- | :---: | :--- | :--- |
| 🚀 **Clash (YAML 格式)** | `{res_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@{branch}/output/residential-clash.yaml) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/{branch}/output/residential-clash.yaml) |
| ⚡ **V2RayN (Base64 格式)** | `{res_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@{branch}/output/residential.txt) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/{branch}/output/residential.txt) |
| 📦 **sing-box (JSON 格式)** | `{res_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@{branch}/output/residential-singbox.json) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/{branch}/output/residential-singbox.json) |

### 📍 按国家/地区拆分

| 家宽地区 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
{res_table}

---

## 🗺️ 按照国家分类节点订阅 (非家宽/数据中心节点)

| 地区/国家 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
{normal_table}

---

## 🔒 私有仓库（Private）无感免翻订阅方案 (基于 Cloudflare Workers)

> 如果你希望将本 GitHub 仓库设置为 **Private (私有仓库)** 保护节点资产，外部客户端无法直接拉取原生 Raw 或公共 CDN 链接，可以通过以下 Cloudflare Worker 搭建轻量级私密网关反代：

### 1. 获取 GitHub 永久个人令牌 (PAT)
1. 进入 GitHub -> **Settings** -> **Developer Settings** -> **Personal access tokens (classic)**。
2. 点击 **Generate new token (classic)**，勾选 `repo` 权限，有效期设为 `No expiration`（永不过期）。
3. 复制保存生成的以 `ghp_` 开头的 Token。

### 2. 部署 Cloudflare Worker
登录 Cloudflare Dashboard，创建一个新的 Worker，复制以下脚本粘贴并部署（把 `OWNER`/`REPO`/`GITHUB_TOKEN` 改成你自己的）：

```javascript
export default {{
  async fetch(request) {{
    const GITHUB_TOKEN = "ghp_你的GitHub永久访问令牌";
    const OWNER = "{owner}";
    const REPO = "{repo}";
    const BRANCH = "{branch}";

    const url = new URL(request.url);
    const filePath = "output" + url.pathname;
    const ghUrl = "https://raw.githubusercontent.com/" + OWNER + "/" + REPO + "/" + BRANCH + "/" + filePath;

    const res = await fetch(ghUrl, {{
      headers: {{
        "Authorization": "token " + GITHUB_TOKEN,
        "User-Agent": "Cloudflare-Worker"
      }}
    }});

    if (!res.ok) {{
      return new Response("Not Found", {{ status: 404 }});
    }}

    return new Response(await res.text(), {{
      headers: {{
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-cache"
      }}
    }});
  }}
}}
```

### 3. 私有订阅链接映射方式
部署后 Worker 会分配一个专属域名（例如 `my-sub.yourname.workers.dev`），你的客户端可以直接无感订阅：
* **总 V2RayN 订阅**: `https://你的域名.workers.dev/v2ray.txt`
* **总 Clash 订阅**: `https://你的域名.workers.dev/clash.yaml`
* **总 sing-box 订阅**: `https://你的域名.workers.dev/singbox.json`
* **家宽总订阅 (V2RayN)**: `https://你的域名.workers.dev/residential.txt`
* **家宽总订阅 (Clash)**: `https://你的域名.workers.dev/residential-clash.yaml`
* **家宽总订阅 (sing-box)**: `https://你的域名.workers.dev/residential-singbox.json`
* **台湾家宽 V2RayN**: `https://你的域名.workers.dev/residential-by-country/TW.txt`
* **香港家宽 Clash**: `https://你的域名.workers.dev/residential-by-country/clash-HK.yaml`
* **日本家宽 sing-box**: `https://你的域名.workers.dev/residential-by-country/singbox-JP.json`

---

## ⭐ 项目热度

[![Star History Chart](https://api.star-history.com/svg?repos={repo_name}&type=Date)](https://star-history.com/#{repo_name}&Date)

---

## 🛠️ 项目使用说明
1. **更新机制**：GitHub Actions **手动触发** (`workflow_dispatch`) 后刷新上述全部订阅与数据。
2. **测活标准**：① sing-box 实际隧道 + 3 个多厂商 generate_204 探测 ② 真实出口 IP 穿透 ③ 稳态吞吐测量 (剔除慢启动, ≥ 35KB/s 判为可用; 测不到速度只标记不淘汰) ④ TLS 证书链校验识别 MITM (仅证书验证失败才判劫持)。
3. **出库标准**：只有本轮**实测连通**的节点才会出库 (失败节点仅用于统计失败原因, 不写入订阅)。
4. **多客户端兼容**：Clash / v2rayN / sing-box 全格式订阅。
"""
    with open(os.path.join(BASEDIR, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)
    print(f"[+] README.md 更新完毕: 总节点 {total_count}, 家宽总订阅 {res_count}")


# ═══════════════════════════════════════════N═══════════════════════
# 主流程
# ═══════════════════════════════════════════N═══════════════════════

def main():
    t_start = time.time()
    print(f"==== 免费节点测活订阅池 v2 · 启动于 {datetime.now(timezone.utc).isoformat()} ====")
    ensure_directories()
    setup_environment()

    # 1. 抓取
    raw_nodes, fetch_failed = fetch_raw_nodes()

    # 2. 解析
    candidates = []
    parse_fail = 0
    for uri in raw_nodes:
        parsed = parse_node_uri(uri)
        if not parsed:
            parse_fail += 1
            continue
        outbound, server, port, proto = parsed
        # 屏蔽占位/广告节点
        if BLACKLIST_NAME_HINTS.search(urllib.parse.unquote(uri.split("#", 1)[-1] if "#" in uri else "")):
            continue
        candidates.append((uri, outbound, server, port, proto))

    # 2.5 ★ 测前强去重 (凭据指纹去重: 同 凭据+目标+协议 只测一次, 结果回填全部重复节点)
    #     key = (server, port, proto, 凭据指纹): 凭据不同 → 服务端校验结果可能不同, 不可合并
    #     凭据指纹由模块级 cred_fingerprint() 统一实现 (state.json 的记忆 key 也复用它)
    seen_keys, deduped, dup_count = {}, [], 0
    for item in candidates:
        uri, outbound, server, port, proto = item
        key = (server.lower() if server else "", port, proto, cred_fingerprint(outbound, proto))
        if key in seen_keys:
            seen_keys[key].append(uri)  # 记录重复 URI, 测活后回填
            dup_count += 1
        else:
            seen_keys[key] = [uri]
            deduped.append(item)
    if dup_count:
        print(f"[*] 测前去重(凭据指纹): {len(candidates)} → {len(deduped)} (剔除重复 {dup_count} — 结果将回填)")
    DEDUP_MAP = seen_keys  # 供测活后回填 (全局)
    candidates = deduped

    proto_stat = {}
    for _, _, _, _, p in candidates:
        proto_stat[p] = proto_stat.get(p, 0) + 1
    print(f"[*] 解析成功(去重后): {len(candidates)} | 失败 {parse_fail} | 协议分布 {proto_stat}")

    if not candidates:
        if fetch_failed:
            print(f"[!] 无可测节点 — 抓取阶段已有 {len(fetch_failed)} 个源站失败; "
                  f"回源补抓需要至少 1 个存活节点作出口, 本轮无出口可用, 无法补救")
        else:
            print("[!] 无可测节点 (订阅源全部失效?) — 保留上次 output, 不覆盖订阅文件")
        return

    # 3. 端口预检
    candidates = prefilter_candidates(candidates)

    # 4. 真实测活 (只测去重后的代表节点)
    test_results = run_liveness_test(candidates)

    # 4.5 ★ 重复节点结果回填: 同 凭据+目标 的重复 URI 继承测活结果 (凭据相同 → 服务端表现一致)
    #     key 用 (server, port, proto, 凭据指纹) 四元组 —— 修复旧版只用三元组导致
    #     "同一 server:port 上挂不同凭据"时结果串号 (死节点变假活 / 出口 IP 与 ASN 串号)
    if DEDUP_MAP:
        test_results, backfilled = expand_dedup(test_results, DEDUP_MAP)
        if backfilled:
            print(f"[+] 重复节点回填: +{backfilled} (继承代表测活结果)")

    # 4.55 ★ 回源补抓: 被源站 WAF 拦掉的订阅, 用已测活节点作出口重试
    #      (Actions 出口是 Azure, 免费节点站普遍按 ASN 拦数据中心 IP;
    #       换备用域名无用 = 同一 CF zone 同一套规则; 套 CF Worker 也无用 = 回源同样走数据中心)
    if fetch_failed:
        alive_items = [r for r in test_results if r.get("alive")]
        recovered = refetch_via_alive_nodes(fetch_failed, alive_items)
        if recovered:
            refetch_dedup, new_cands, skipped = {}, [], 0
            for uri in set().union(*recovered.values()):
                parsed = parse_node_uri(uri)
                if not parsed:
                    continue
                outbound, server, port, proto = parsed
                if BLACKLIST_NAME_HINTS.search(
                        urllib.parse.unquote(uri.split("#", 1)[-1] if "#" in uri else "")):
                    continue
                key = ((server or "").lower(), port, proto, cred_fingerprint(outbound, proto))
                if key in DEDUP_MAP:
                    skipped += 1      # 主批次已覆盖同一凭据, 无需重复测
                    continue
                if key in refetch_dedup:
                    refetch_dedup[key].append(uri)
                    continue
                refetch_dedup[key] = [uri]
                new_cands.append((uri, outbound, server, port, proto))
            if skipped:
                print(f"[*] 回源补抓的节点中 {skipped} 个与主批次重复, 已跳过")
            if new_cands:
                print(f"[*] 回源补抓新增 {len(new_cands)} 个待测节点 (去重后), 追加一轮测活 ...")
                extra_results = run_liveness_test(prefilter_candidates(new_cands))
                extra_results, extra_backfill = expand_dedup(extra_results, refetch_dedup)
                if extra_backfill:
                    print(f"[+] 回源批次重复回填: +{extra_backfill}")
                test_results.extend(extra_results)
            else:
                print("[*] 回源补抓的节点全部与已有节点重复, 无需追加测活")

    # 4.6 跨运行记忆: 只读来累加历史轨迹, 不参与出库判定 (救援池已下线)
    prev_state = load_state()
    print(f"[*] 跨运行记忆: {len(prev_state)} 条" if prev_state else "[*] 无跨运行记忆 (首次运行)")

    # 5. ★ 家宽链式复测: 用最快存活节点做前置双跳复测家宽候选
    #    (模拟用户 v2rayN 链式场景, 双跳失败的家宽降级普通区 — 提高链式可用率)
    test_results = chain_retest(test_results)

    # 5.5 保存跨运行记忆
    save_state(build_state(test_results, prev_state))

    # 6. 分类 + 导出
    if not test_results:
        print("[!] 无任何测活结果 — 保留上次 output, 不覆盖订阅文件")
        return
    unique_nodes, residential, non_residential = classify_and_export(test_results)
    if not unique_nodes:
        print("[!] 无存活节点 — 保留上次 output, 不覆盖订阅文件")
        return
    total, res = export_all(unique_nodes, residential, non_residential)
    update_readme(total, res)


    # 统计报告
    elapsed = time.time() - t_start
    print("\n===== 运行报告 =====")
    print(f"总耗时: {elapsed:.0f}s | 抓取 {len(raw_nodes)} → 解析成功 {len(candidates)} "
          f"→ 存活 {sum(1 for r in test_results if r.get('alive'))}/{len(test_results)} "
          f"→ 去重后 {len(unique_nodes)} → 家宽 {len(residential)}")
    by_type = {}
    for n in unique_nodes:
        by_type[n["net_type"]] = by_type.get(n["net_type"], 0) + 1
    print(f"节点类型分布: {by_type}")
    by_proto = {}
    for n in unique_nodes:
        by_proto[n["proto"]] = by_proto.get(n["proto"], 0) + 1
    print(f"协议分布(出库): {by_proto}")
    by_country = {}
    for n in unique_nodes:
        by_country[n["country"]] = by_country.get(n["country"], 0) + 1
    top_c = sorted(by_country.items(), key=lambda x: -x[1])[:10]
    print(f"国家 Top10: {top_c}")
    if fetch_failed:
        hosts = []
        for u, k, _ in fetch_failed:
            try:
                hosts.append(f"{urllib.parse.urlsplit(u).netloc or u}({k})")
            except Exception:
                hosts.append(f"{u}({k})")
        print(f"抓取失败源站: {len(fetch_failed)} 个 — " + " | ".join(hosts))


if __name__ == "__main__":
    main()
