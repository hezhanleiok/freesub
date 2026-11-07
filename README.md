# 🚀 免费节点自动测活订阅池 (含真实家宽/住宅IP甄选)

> 👤 **定制规范命名**: 所有订阅节点均重命名为 `国旗 地区 序号 (家宽) - xiaohe`
> ⚡ **真实可用保障**: 所有节点由 `sing-box v1.14.0` 内核建立实际代理隧道, 完成真实 HTTPS 双向传输握手 + 出口 IP 穿透验证 + Cloudflare 限速下载断流检测 + TLS 证书校验 (MITM 劫持识别), 拒绝虚假通畅、断流节点与高危劫持节点。
> 🛡️ **全协议支持**: VLESS (Reality/Vision) · VMESS · Trojan · Shadowsocks · Hysteria2 · TUIC · AnyTLS

---

## 📌 全部节点总订阅链接

> 全部为**海外实测存活**节点 (sing-box 真实握手 + 出口 IP 穿透 + 断流检测通过)。国内使用请开启前置代理。

| 客户端 / 格式类型 | 节点总数 | 免翻 CDN 加速直链 | 官方原生 Raw 直链 (开启代理) |
| :--- | :---: | :--- | :--- |
| 🚀 **Clash (YAML 格式)** | `637` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/clash.yaml) | [官方 Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/clash.yaml) |
| ⚡ **V2RayN (Base64 格式)** | `637` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/v2ray.txt) | [官方 Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/v2ray.txt) |
| 📦 **sing-box (JSON 格式)** | `637` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/singbox.json) | [官方 Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/singbox.json) |

---

## 🏠 按照家宽分类节点订阅 (住宅 IP 专区)

> 家宽判定六重信号: ① ip-api.com `hosting` 字段 ② `mobile` 移动网络字段 ③ Cloudflare/主流 CDN Anycast 网段比对 ④ MaxMind GeoLite2 ASN 白/黑名单 (覆盖 60+ 国家主流民用运营商) ⑤ rDNS/ISP 名称特征 ⑥ Scamalytics 风控评分复核 (fraud ≥75 降级、≥90 剔除)。排除所有云主机/数据中心/CDN 任播, 保留真实民用宽带与移动网络。
>
> **可用性三道闸门** (家宽节点入口 IP 在国内基本不可直连, 通常必须挂前置, 因此比普通区多三道准入):
> ① **协议闸门** — 只收 TCP 协议。`hysteria2` / `tuic` 是 QUIC/UDP, 而 socks5/http 前置不做 UDP 转发, 链式下 100% 失败, 一律不进家宽区 (它们仍在全量订阅里, 直连可用时照常使用)。
> ② **吞吐闸门** — 必须实测到下载吞吐。仅"握手成功但下载 0 字节"的节点不进家宽区 (客户端里表现为连上了却打不开网页)。
> ③ **前置闸门** — 在 CI 里起一个真实 socks5 前置 (亚洲节点优先), 家宽候选经它复测, 通过才放出。
>
> ⚠️ 因此家宽区的节点数会明显少于其他区: 宁可少而真, 不放多而假。

### 🌍 家宽总订阅 (全部国家汇总 · 推荐)

> 把下面所有国家/地区的家宽 + 移动网络节点合并成一份, 不用逐个国家订阅。

| 客户端 / 格式类型 | 节点总数 | 免翻 CDN 加速直链 | 官方原生 Raw 直链 (开启代理) |
| :--- | :---: | :--- | :--- |
| 🚀 **Clash (YAML 格式)** | `3` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/residential-clash.yaml) | [官方 Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/residential-clash.yaml) |
| ⚡ **V2RayN (Base64 格式)** | `3` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/residential.txt) | [官方 Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/residential.txt) |
| 📦 **sing-box (JSON 格式)** | `3` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/residential-singbox.json) | [官方 Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/residential-singbox.json) |

### 📍 按国家/地区拆分

| 家宽地区 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
| 暂无可用节点 | 0 | - | - | - |

---

## 🗺️ 按照国家分类节点订阅 (非家宽/数据中心节点)

| 地区/国家 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
| 🇺🇸 美国 (United States) | 322 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/US.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/US.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-US.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-US.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-US.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-US.json) |
| 🇳🇱 荷兰 (Netherlands) | 55 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/NL.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/NL.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-NL.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-NL.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-NL.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-NL.json) |
| 🇨🇭 瑞士 (Switzerland) | 34 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/CH.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/CH.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-CH.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-CH.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-CH.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-CH.json) |
| 🇯🇵 日本 (Japan) | 34 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/JP.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/JP.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-JP.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-JP.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-JP.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-JP.json) |
| 🇩🇪 德国 (Germany) | 32 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/DE.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/DE.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-DE.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-DE.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-DE.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-DE.json) |
| 🇨🇦 加拿大 (Canada) | 28 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/CA.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/CA.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-CA.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-CA.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-CA.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-CA.json) |
| 🇫🇷 法国 (France) | 27 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/FR.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/FR.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-FR.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-FR.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-FR.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-FR.json) |
| 🇭🇰 中国香港 (Hong Kong) | 21 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/HK.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/HK.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-HK.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-HK.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-HK.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-HK.json) |
| 🇬🇧 英国 (United Kingdom) | 18 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/GB.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/GB.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-GB.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-GB.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-GB.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-GB.json) |
| 🇰🇷 韩国 (South Korea) | 12 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/KR.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/KR.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-KR.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-KR.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-KR.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-KR.json) |
| 🇪🇸 西班牙 (Spain) | 12 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/ES.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/ES.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-ES.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-ES.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-ES.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-ES.json) |
| 🇮🇷 IR | 5 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/IR.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/IR.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-IR.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-IR.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-IR.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-IR.json) |
| 🇫🇮 芬兰 (Finland) | 4 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/FI.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/FI.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-FI.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-FI.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-FI.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-FI.json) |
| 🇦🇪 阿联酋 (UAE) | 4 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/AE.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/AE.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-AE.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-AE.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-AE.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-AE.json) |
| 🇹🇷 土耳其 (Turkey) | 3 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/TR.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/TR.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-TR.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-TR.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-TR.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-TR.json) |
| 🇹🇼 中国台湾 (Taiwan) | 3 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/TW.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/TW.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-TW.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-TW.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-TW.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-TW.json) |
| 🇷🇴 罗马尼亚 (Romania) | 3 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/RO.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/RO.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-RO.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-RO.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-RO.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-RO.json) |
| 🌐 其他地区 (Other) | 3 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/OTHER.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/OTHER.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-OTHER.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-OTHER.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-OTHER.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-OTHER.json) |
| 🇲🇽 墨西哥 (Mexico) | 3 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/MX.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/MX.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-MX.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-MX.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-MX.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-MX.json) |
| 🇦🇲 亚美尼亚 (Armenia) | 2 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/AM.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/AM.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-AM.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-AM.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-AM.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-AM.json) |
| 🇱🇰 斯里兰卡 (Sri Lanka) | 2 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/LK.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/LK.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-LK.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-LK.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-LK.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-LK.json) |
| 🇷🇺 俄罗斯 (Russia) | 2 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/RU.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/RU.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-RU.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-RU.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-RU.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-RU.json) |
| 🇸🇬 新加坡 (Singapore) | 2 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/SG.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/SG.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-SG.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-SG.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-SG.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-SG.json) |
| 🇰🇿 哈萨克斯坦 (Kazakhstan) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/KZ.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/KZ.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-KZ.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-KZ.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-KZ.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-KZ.json) |
| 🇸🇨 塞舌尔 (Seychelles) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/SC.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/SC.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-SC.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-SC.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-SC.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-SC.json) |
| 🇦🇺 澳大利亚 (Australia) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/AU.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/AU.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-AU.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-AU.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-AU.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-AU.json) |
| 🇵🇱 波兰 (Poland) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/PL.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/PL.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-PL.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-PL.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-PL.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-PL.json) |
| 🇮🇱 以色列 (Israel) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/IL.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/IL.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-IL.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-IL.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-IL.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-IL.json) |
| 🇸🇪 瑞典 (Sweden) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/SE.txt) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/SE.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/clash-SE.yaml) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/clash-SE.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/hezhanleiok/freesub@test/output/by-country/singbox-SE.json) · [Raw 直链](https://raw.githubusercontent.com/hezhanleiok/freesub/test/output/by-country/singbox-SE.json) |

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
export default {
  async fetch(request) {
    const GITHUB_TOKEN = "ghp_你的GitHub永久访问令牌";
    const OWNER = "hezhanleiok";
    const REPO = "freesub";
    const BRANCH = "test";

    const url = new URL(request.url);
    const filePath = "output" + url.pathname;
    const ghUrl = "https://raw.githubusercontent.com/" + OWNER + "/" + REPO + "/" + BRANCH + "/" + filePath;

    const res = await fetch(ghUrl, {
      headers: {
        "Authorization": "token " + GITHUB_TOKEN,
        "User-Agent": "Cloudflare-Worker"
      }
    });

    if (!res.ok) {
      return new Response("Not Found", { status: 404 });
    }

    return new Response(await res.text(), {
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-cache"
      }
    });
  }
}
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

[![Star History Chart](https://api.star-history.com/svg?repos=hezhanleiok/freesub&type=Date)](https://star-history.com/#hezhanleiok/freesub&Date)

---

## 🛠️ 项目使用说明
1. **更新机制**：GitHub Actions **手动触发** (`workflow_dispatch`) 后刷新上述全部订阅与数据。
2. **测活标准**：① sing-box 实际隧道 + 3 个多厂商 generate_204 探测 ② 真实出口 IP 穿透 ③ 稳态吞吐测量 (剔除慢启动, ≥ 35KB/s 判为可用; 测不到速度只标记不淘汰) ④ TLS 证书链校验识别 MITM (仅证书验证失败才判劫持)。
3. **出库标准**：只有本轮**实测连通**的节点才会出库 (失败节点仅用于统计失败原因, 不写入订阅)。
4. **多客户端兼容**：Clash / v2rayN / sing-box 全格式订阅。
