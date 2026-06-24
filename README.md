# AdBlock Filter Split

自动下载、分类、去重、校验 AdBlock 过滤规则，每日中午 12 点更新。

## 数据来源

上游规则来自 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters)（每 8 小时更新一次）。本项目每天定时下载，按规则类型拆分并校验格式后输出。

## 输出文件

| 文件 | 规则类型 | 格式 | 适用工具 |
|------|----------|------|----------|
| [`rules/dns.txt`](rules/dns.txt) | DNS 域名阻断 | `\|\|domain^` | AdGuard Home |
| [`rules/cosmetic.txt`](rules/cosmetic.txt) | 元素隐藏 | `##` / `###` CSS 选择器 | AdGuard / uBlock Origin |
| [`rules/network.txt`](rules/network.txt) | 网络请求过滤 | `\|\|domain/path`、`@@`白名单、`$option` | AdGuard / uBlock Origin |
| [`rules/stats.json`](rules/stats.json) | 统计摘要 | JSON | 查看规则数量及格式分布 |

## 规则统计

| 指标 | 数值 |
|------|------|
| 📊 总规则数 | ~224,000+ 条 |
| 🛡️ DNS 阻断规则 | ~130,000 条 (`rules/dns.txt`) |
| 🎨 元素隐藏规则 | ~15,000 条 (`rules/cosmetic.txt`) |
| 🌐 网络过滤规则 | ~79,000 条 (`rules/network.txt`) |
| ✅ 格式有效率 | ~99.9%+ |
| 🔄 更新频率 | 每天 12:00 CST (UTC+8) |

> 具体数值每次更新自动变化，查看 [`rules/stats.json`](rules/stats.json) 获取最新统计。

## 订阅链接

在广告拦截工具中直接使用以下 Raw 链接：

```
# DNS 规则 (AdGuard Home)
https://raw.githubusercontent.com/HE4001/adblock-filter-split/main/rules/dns.txt

# 元素隐藏规则
https://raw.githubusercontent.com/HE4001/adblock-filter-split/main/rules/cosmetic.txt

# 网络过滤规则
https://raw.githubusercontent.com/HE4001/adblock-filter-split/main/rules/network.txt
```

## 格式说明

### DNS 规则 — `rules/dns.txt`
```
||example.com^
||doubleclick.net^
```
适用于 AdGuard Home 的 DNS 查询拦截，阻止域名解析。

### 元素隐藏规则 — `rules/cosmetic.txt`
```
###ad-banner
##.sponsored-link
##div[data-ad="true"]
```
CSS 选择器规则，隐藏网页中的广告元素，适用于浏览器扩展。

### 网络过滤规则 — `rules/network.txt`
```
||example.com/path/to/ad^
||cdn.tracker.com^$third-party
@@||allowed-ads.example.com^
/$popup,domain=example.com
```
URL 路径过滤、第三方请求拦截、白名单等高级规则。

## 格式校验

脚本会对每条规则进行格式检测，识别并统计：

| 格式类型 | 说明 |
|----------|------|
| `dns` | `\|\|domain^` 纯域名阻断 |
| `network_domain` | `\|\|domain/path` 或 `\|\|domain^$option` |
| `exception` | `@@\|\|domain^` 白名单 |
| `cosmetic_generic` | `##selector` / `###selector` |
| `cosmetic_domain` | `domain##selector` 域名限定隐藏 |
| `regex` | `/pattern/` 正则规则 |
| `hosts` | `0.0.0.0 domain` hosts 格式 |
| `ip` | IP 地址 / CIDR |
| `attribute` | `[attr=value]` 属性选择器 |

未知格式的规则会记录在日志和 `stats.json` 中，便于排查问题。

## 自动更新

GitHub Actions 工作流每天 **北京时间中午 12:00** 自动运行：
1. 下载上游最新规则
2. 解析、分类、格式校验
3. 去重
4. 输出 3 个规则文件 + 统计摘要
5. 自动提交并推送

也可以手动触发：**Actions** → **Update AdBlock Filters** → **Run workflow**。

## 本地运行

```bash
# 确保已安装 Python 3.9+
python scripts/process_filters.py
```

输出文件在 `rules/` 目录下，包括 `stats.json` 统计摘要。

## 为什么拆分？

上游文件条目数过多（合计超过 22 万条），部分工具可能因性能或限制无法正常加载。按规则类型拆分后：

1. **DNS 阻断规则** — 专用于 DNS 级拦截工具（AdGuard Home），不需要加载元素隐藏规则
2. **元素隐藏规则** — 用于浏览器扩展，按需订阅
3. **网络过滤规则** — 精细控制网络请求过滤，支持白名单和高级选项

## 许可

上游规则版权归 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 及其各规则源作者所有。本项目仅做自动化重组分发。
