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
| 📊 总规则数及分类数量 | 以 [`rules/stats.json`](rules/stats.json) 为准 |
| ✅ 格式识别率 | 见 `format_validation.validity_rate` |
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

这里的校验是已知格式识别，不是 AdGuard / uBlock Origin 的完整语法解析；未知规则仍保留在 `network.txt`，避免因识别范围不足而丢失规则。列表头（如 `[Adblock Plus 2.0]`）、注释和 UTF-8 BOM 不会混入规则内容。

去重保留首次出现的顺序：纯 DNS 域名规则忽略大小写；其他规则仅去除完全相同的行，保留 CSS 选择器、脚本参数、正则和 `$match-case` 规则中的大小写差异。

## 自动更新

GitHub Actions 工作流每天 **北京时间中午 12:00** 自动运行：
1. 运行离线回归测试，并行下载两个上游规则文件
2. 解析、分类、格式校验
3. 去重
4. 输出 3 个规则文件 + 统计摘要
5. 自动提交并推送（包含新生成的文件）

下载失败、空响应、HTML 错误页、无可识别规则的响应或 UTF-8 解码失败时会终止，不覆盖现有输出。HTTP 408、429、5xx 和网络错误会重试，其他 HTTP 错误立即报告。所有输出先写入临时文件，再逐文件原子替换；多个文件之间的替换不构成事务。输出统一为 UTF-8 / LF，并共享本轮生成时间。

12:00 是计划触发时间，实际执行可能受 GitHub Actions 调度延迟影响。

也可以手动触发：**Actions** → **Update AdBlock Filters** → **Run workflow**。

## 本地运行

```bash
# 确保已安装 Python 3.10+
python scripts/process_filters.py

# 写入其他目录，便于检查结果
python scripts/process_filters.py --output-dir ./preview-rules

# 运行测试（标准库，无需联网或安装依赖）
python -m unittest discover -s tests -v
```

输出文件在 `rules/` 目录下，包括 `stats.json` 统计摘要。

## 为什么拆分？

上游文件包含数十万条规则，部分工具可能因性能或限制无法正常加载。按规则类型拆分后：

1. **DNS 阻断规则** — 专用于 DNS 级拦截工具（AdGuard Home），不需要加载元素隐藏规则
2. **元素隐藏规则** — 用于浏览器扩展，按需订阅
3. **网络过滤规则** — 精细控制网络请求过滤，支持白名单和高级选项

## 许可

上游规则版权归 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 及其各规则源作者所有。本项目仅做自动化重组分发。

