# AdBlock Filter Split

自动下载、分类、去重 AdBlock 过滤规则，每日更新。

## 数据来源

上游规则来自 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters)，每 8 小时更新一次。本项目每天定时下载并重组为三个独立文件。

## 输出文件

| 文件 | 规则类型 | 说明 | 适用工具 |
|------|----------|------|----------|
| [`rules/dns.txt`](rules/dns.txt) | DNS 域名阻断 | `\|\|domain^` 格式 | AdGuard Home / Pi-Hole |
| [`rules/cosmetic.txt`](rules/cosmetic.txt) | 元素隐藏 | `##` / `###` CSS 选择器 | AdGuard / uBlock Origin |
| [`rules/network.txt`](rules/network.txt) | 网络请求过滤 | URL 路径过滤、白名单等 | AdGuard / uBlock Origin |

## 订阅链接

在广告拦截工具中直接使用以下 Raw 链接：

```
# DNS 规则 (AdGuard Home)
https://raw.githubusercontent.com/<你的用户名>/adblock-filter-split/main/rules/dns.txt

# 元素隐藏规则
https://raw.githubusercontent.com/<你的用户名>/adblock-filter-split/main/rules/cosmetic.txt

# 网络过滤规则
https://raw.githubusercontent.com/<你的用户名>/adblock-filter-split/main/rules/network.txt
```

> 请将 `<你的用户名>` 替换为你的 GitHub 用户名。

## 自动更新

GitHub Actions 工作流每天 **北京时间凌晨 4:00** 自动运行，下载最新规则并提交更新。

也可以手动触发更新：进入仓库的 **Actions** 标签页 → 选择 **Update AdBlock Filters** → **Run workflow**。

## 本地运行

```bash
# 确保已安装 Python 3.9+
python scripts/process_filters.py
```

输出文件在 `rules/` 目录下。

## 为什么拆分？

上游文件条目数过多（合计超过 22 万条），部分工具可能因性能或限制无法正常加载。按规则类型拆分后：

1. **DNS 阻断规则** — 专用于 DNS 级拦截工具，不需要加载元素隐藏规则
2. **元素隐藏规则** — 用于浏览器扩展，按需订阅
3. **网络过滤规则** — 精细控制网络请求过滤

## 许可

上游规则版权归 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 及其各规则源作者所有。本项目仅做自动化重组分发。
