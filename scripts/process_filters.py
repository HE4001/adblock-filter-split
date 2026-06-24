#!/usr/bin/env python3
"""
AdBlock 规则下载、分类、去重、校验、输出脚本。

从上游仓库下载两个规则文件，按规则类型拆分为三个文件：
  - rules/dns.txt      : DNS 域名阻断规则 (||domain^)
  - rules/cosmetic.txt : 元素隐藏规则 (## / ###)
  - rules/network.txt  : 网络请求过滤规则 (||domain/path, $option 等)
  - rules/stats.json   : 统计摘要 (规则数、格式分布、校验结果)

纯标准库实现，零外部依赖，适用于 GitHub Actions 环境。
"""

import json
import os
import re
import sys
import time
import logging
from datetime import datetime, timezone, timedelta
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# 强制 UTF-8 输出 (Windows 兼容)
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

# 源文件 URL
URL_DNS = "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt"
URL_FILTERS = "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt"

# 输出目录
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")

# 下载设置
MAX_RETRIES = 3
RETRY_DELAY = 10  # 秒
TIMEOUT = 120     # 秒

# 北京时间时区
CST = timezone(timedelta(hours=8))

# 日志
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 下载工具
# ---------------------------------------------------------------------------

def download(url: str, description: str) -> str:
    """下载文件内容，带重试机制。"""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            log.info("下载 %s (尝试 %d/%d)...", description, attempt, MAX_RETRIES)
            req = Request(url, headers={"User-Agent": "AdBlockFilterSplit/1.0"})
            with urlopen(req, timeout=TIMEOUT) as resp:
                content = resp.read().decode("utf-8", errors="replace")
            log.info("下载 %s 成功, 大小: %d 字节", description, len(content))
            return content
        except (URLError, HTTPError, OSError) as e:
            log.warning("下载 %s 失败 (尝试 %d/%d): %s", description, attempt, MAX_RETRIES, e)
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
    raise RuntimeError(f"下载 {description} 失败，已重试 {MAX_RETRIES} 次")


# ---------------------------------------------------------------------------
# AdBlock 规则格式定义
# ---------------------------------------------------------------------------

# 各类型规则的正则模式，用于分类和格式校验
#
# AdBlock 规则语法概览:
#   ||domain^                — DNS/域名阻断
#   ||domain/path^           — URL 路径过滤
#   ||domain^$option         — 带修饰的网络过滤
#   @@||domain^              — 白名单/例外
#   ##selector  / ###selector — 通用元素隐藏
#   domain##selector         — 域名限定元素隐藏
#   /regex/ 或 /regex/$opt   — 正则规则
#   0.0.0.0 domain           — hosts 格式
#   IP/CIDR                  — IP 地址

# DNS: ||domain^  (纯域名+^结尾, 无 / 路径, 无 $option, 无后续字符)
RE_DNS = re.compile(r'^\|\|[a-zA-Z0-9*][-a-zA-Z0-9.*]*\^\s*$')

# 网络过滤: 任何以 || 开头但不是纯 DNS 的规则
RE_NETWORK_DOMAIN = re.compile(r'^\|\|')

# 通用元素隐藏: ##xxx 或 ###xxx 或 ####xxx (2个及以上#)
RE_COSMETIC_GENERIC = re.compile(r'^#{2,}')

# 元素隐藏变体 (uBlock 高级语法): #@# (例外), #?# (扩展选择器), #%# (scriptlet), #$# (CSS注入), #@?# (例外+扩展)
RE_COSMETIC_VARIANT = re.compile(r'^#(?:@\?#|@#|%\#|\$\?#|\?#|\$#)')

# 域名限定元素隐藏: domain1,domain2##xxx (支持 ~否定前缀)
RE_COSMETIC_DOMAIN = re.compile(r'^[-a-zA-Z0-9.,~*]+\#{2,}')

# 域名限定变体: domain#@#xxx, domain#?#xxx, domain#%#scriptlet, domain#$#css, domain#@?#xxx
# 支持 ~ 域名否定前缀: domain,~excludedomain##selector
RE_COSMETIC_DOMAIN_VARIANT = re.compile(r'^[-a-zA-Z0-9.,~*]+#(?:@\?#|@#|%\#|\$\?#|\?#|\$#)')

# 例外/白名单: @@ 开头
RE_EXCEPTION = re.compile(r'^@@')

# 正则规则: /pattern/ (可能带 $option)
RE_REGEX = re.compile(r'^/(?:[^/]|\\.)+/(?:\$.+)?$')

# hosts 格式: 0.0.0.0 domain 或 127.0.0.1 domain
RE_HOSTS = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+[-a-zA-Z0-9.]+')

# IP 地址 (含 CIDR)
RE_IP = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$')

# 孤立属性选择器: [attr=value] 开头 (CSS 选择器片段)
RE_ATTR_SELECTOR = re.compile(r'^\[[^\]]+\]')

# uBlock 脚本注入 / HTML 过滤: $$script[attr] 或 $$div[...]
RE_SCRIPT_INJECT = re.compile(r'^\$\$')

# 纯修饰符规则: $cookie=..., $csp=..., $~third-party,... 等 ($开头+修饰符)
RE_MODIFIER_ONLY = re.compile(r'^\$')

# URL 编码的匹配模式: %2F..., %3C..., 等
RE_URL_ENCODED = re.compile(r'^%[0-9A-Fa-f]{2}')

# 查询参数匹配: &param=... 或 &&param=...
RE_QUERY_PARAM = re.compile(r'^&+[a-zA-Z]')

# 通配符修饰符: *$denyallow=..., *$image,redirect=... 等
RE_WILDCARD_MODIFIER = re.compile(r'^\*\$')

# 通配符 URL 模式: *.domain/path, *pattern^, */path, -*-pattern 等
RE_WILDCARD_URL = re.compile(r'^[\*\-]')

# 泛化 adblock 特征: 包含标准 $option 关键词
# 捕获不以 || 开头的 URL 匹配规则 (如 */path$script, *.gif$image 等)
RE_STANDARD_OPTIONS = re.compile(
    r'\$(?:domain|script|image|third-party|xmlhttprequest|'
    r'subdocument|popup|redirect|replace|csp|denyallow|'
    r'cookie|removeparam|webrtc|object|media|font|other|'
    r'ping|stylesheet|websocket|frame|document|all|'
    r'first-party|important|badfilter|match-case|'
    r'genericblock|generichide|inline-script|'
    r'1p|3p|ehide|shide|ghide|network|'
    r'~third-party|~first-party)'
)

# 含 ^ 分隔符的规则 (adblock 特有语法, 如 *domain^)
RE_CARET_SEPARATOR = re.compile(r'\^')

# URL 片段匹配: .domain/path, .pattern^, ./path 等 (不以 || 开头的子串匹配)
RE_URL_FRAGMENT = re.compile(r'^\.')

# URL 路径匹配: /path, //domain/path 等 (不以 || 开头的路径子串匹配)
RE_URL_PATH = re.compile(r'^/')


# ---------------------------------------------------------------------------
# 格式校验
# ---------------------------------------------------------------------------

def is_valid_rule(line: str) -> tuple[bool, str]:
    """校验规则行是否符合已知的 adblock 语法格式。

    按精确度从高到低依次匹配，避免泛化模式过早捕获。

    Args:
        line: 已 strip 的规则行

    Returns:
        (is_valid, format_name)
    """
    # DNS 纯域名阻断 (精确匹配 ||domain^)
    if RE_DNS.match(line):
        return True, "dns"

    # 白名单 @@ 开头
    if RE_EXCEPTION.match(line):
        return True, "exception"

    # 域名限定变体: domain#@#xxx, domain#?#xxx, domain#%#scriptlet (最精确, 优先)
    if RE_COSMETIC_DOMAIN_VARIANT.match(line):
        return True, "cosmetic_domain_variant"

    # 域名限定元素隐藏: domain##xxx
    if RE_COSMETIC_DOMAIN.match(line):
        return True, "cosmetic_domain"

    # 通用元素隐藏变体: #@#xxx, #?#xxx, #%#scriptlet
    if RE_COSMETIC_VARIANT.match(line):
        return True, "cosmetic_variant"

    # 通用元素隐藏: ##xxx / ###xxx
    if RE_COSMETIC_GENERIC.match(line):
        return True, "cosmetic_generic"

    # 正则规则: /pattern/
    if RE_REGEX.match(line):
        return True, "regex"

    # hosts 格式: 0.0.0.0 domain
    if RE_HOSTS.match(line):
        return True, "hosts"

    # IP/CIDR
    if RE_IP.match(line):
        return True, "ip"

    # 属性选择器: [attr=value]
    if RE_ATTR_SELECTOR.match(line):
        return True, "attribute"

    # uBlock 脚本注入: $$script[...]  (在 $ 之前检测, $$ 更精确)
    if RE_SCRIPT_INJECT.match(line):
        return True, "script_inject"

    # 纯修饰符: $cookie=..., $~third-party,...  ($$ 已被上面拦截)
    if RE_MODIFIER_ONLY.match(line):
        return True, "modifier"

    # URL 编码匹配: %2F..., %3C...
    if RE_URL_ENCODED.match(line):
        return True, "url_encoded"

    # 查询参数匹配: &param=...
    if RE_QUERY_PARAM.match(line):
        return True, "query_param"

    # 通配符修饰符: *$denyallow=..., *$image,redirect=... (在泛化通配符之前)
    if RE_WILDCARD_MODIFIER.match(line):
        return True, "wildcard_modifier"

    # 通配符 URL: *.domain/path, */path, -*-pattern 等
    if RE_WILDCARD_URL.match(line) and RE_CARET_SEPARATOR.search(line):
        return True, "wildcard_url"

    # 泛化 adblock 选项检测: 包含 $domain, $script 等标准选项
    if RE_STANDARD_OPTIONS.search(line):
        return True, "generic_url"

    # 含 ^ 分隔符的 URL 模式
    if RE_WILDCARD_URL.match(line):
        return True, "wildcard_url"

    # URL 片段: .domain/path, ./path, .pattern (子串匹配)
    if RE_URL_FRAGMENT.match(line):
        return True, "url_fragment"

    # URL 路径: /path, //domain/path (子串匹配, 非正则)
    if RE_URL_PATH.match(line):
        return True, "url_path"

    # 网络域名过滤 (|| 开头, 非纯 DNS) — 兜底捕获
    if RE_NETWORK_DOMAIN.match(line):
        return True, "network_domain"

    # 未知格式
    return False, "unknown"


# ---------------------------------------------------------------------------
# 规则分类
# ---------------------------------------------------------------------------

def classify_rules(lines: list[str]) -> tuple[dict, dict, dict]:
    """将规则行按类型分类，同时进行格式校验。

    Returns:
        (categories, stats, validation) — 分类结果、计数、校验报告
    """
    categories = {"dns": [], "cosmetic": [], "network": []}
    stats = {"dns": 0, "cosmetic": 0, "network": 0, "comment": 0, "empty": 0}
    validation = {
        "total_rules": 0,
        "valid": 0,
        "invalid": 0,
        "invalid_samples": [],   # 最多保留 20 条示例
        "format_distribution": {},  # 各格式数量分布
    }

    for line in lines:
        stripped = line.strip()

        # 空行跳过
        if not stripped:
            stats["empty"] += 1
            continue

        # 注释行跳过
        if stripped.startswith("!"):
            stats["comment"] += 1
            continue

        validation["total_rules"] += 1

        # 格式校验
        is_valid, fmt = is_valid_rule(stripped)
        if is_valid:
            validation["valid"] += 1
            validation["format_distribution"][fmt] = \
                validation["format_distribution"].get(fmt, 0) + 1
        else:
            validation["invalid"] += 1
            if len(validation["invalid_samples"]) < 20:
                # 截断过长的行
                sample = stripped[:120] + ("..." if len(stripped) > 120 else "")
                validation["invalid_samples"].append(sample)

        # 分类
        if RE_DNS.match(stripped):
            categories["dns"].append(stripped)
            stats["dns"] += 1
        elif (RE_COSMETIC_GENERIC.match(stripped) or RE_COSMETIC_DOMAIN.match(stripped)
              or RE_COSMETIC_VARIANT.match(stripped) or RE_COSMETIC_DOMAIN_VARIANT.match(stripped)):
            categories["cosmetic"].append(stripped)
            stats["cosmetic"] += 1
        elif RE_EXCEPTION.match(stripped):
            categories["network"].append(stripped)
            stats["network"] += 1
        elif RE_NETWORK_DOMAIN.match(stripped):
            categories["network"].append(stripped)
            stats["network"] += 1
        else:
            # 其他类型 (正则、hosts、IP、属性选择器等) → 网络规则
            categories["network"].append(stripped)
            stats["network"] += 1

    return categories, stats, validation


# ---------------------------------------------------------------------------
# 去重
# ---------------------------------------------------------------------------

def deduplicate(rules: list[str]) -> list[str]:
    """去重，保留首次出现的顺序。"""
    seen = set()
    result = []
    for rule in rules:
        # 用 lowercase 去重（adblock 规则不区分大小写）
        key = rule.lower()
        if key not in seen:
            seen.add(key)
            result.append(rule)
    return result


# ---------------------------------------------------------------------------
# 输出文件生成
# ---------------------------------------------------------------------------

def build_output(
    rules: list[str],
    title: str,
    description: str,
    source_urls: list[str],
    rule_type: str,
    validation: dict | None = None,
) -> str:
    """构建输出文件内容（含元数据头部）。

    Args:
        rules: 规则列表
        title: 文件标题
        description: 文件描述
        source_urls: 上游源文件 URL 列表
        rule_type: 规则类型标签
        validation: 格式校验统计 (可选)
    """
    now = datetime.now(CST).strftime("%Y%m%d%H%M%S")
    now_human = datetime.now(CST).strftime("%Y/%m/%d %H:%M:%S")

    header = f"""!
! Title: {title}
! Description: {description}
! Type: {rule_type}
! Homepage: https://github.com/217heidai/adblockfilters
! Generated by: AdBlock Filter Split (GitHub Actions)
! Version: {now}
! Last modified: {now_human}
! Rule count: {len(rules)}
! Update schedule: Daily at 12:00 CST (UTC+8)
! Source:
"""
    for url in source_urls:
        header += f"!   - {url}\n"
    header += "!\n"

    return header + "\n".join(rules) + "\n"


# ---------------------------------------------------------------------------
# 统计摘要
# ---------------------------------------------------------------------------

def generate_stats(
    categories: dict,
    stats: dict,
    validation: dict,
    dedup_stats: dict,
    elapsed: float,
) -> dict:
    """生成统计摘要 JSON。"""
    return {
        "generated_at": datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S CST"),
        "generated_at_unix": int(time.time()),
        "update_schedule": "Daily at 12:00 CST (UTC+8)",
        "sources": {
            "dns": URL_DNS,
            "filters": URL_FILTERS,
        },
        "output_files": {
            "dns.txt": {
                "type": "DNS 域名阻断规则",
                "format": "||domain^",
                "count": len(categories["dns"]),
                "size_bytes": None,  # 后续填充
                "target_tools": ["AdGuard Home", "Pi-Hole (需转换)"],
            },
            "cosmetic.txt": {
                "type": "元素隐藏规则",
                "format": "## / ### CSS 选择器",
                "count": len(categories["cosmetic"]),
                "size_bytes": None,
                "target_tools": ["AdGuard", "uBlock Origin"],
            },
            "network.txt": {
                "type": "网络请求过滤规则",
                "format": "||domain/path, @@ 白名单, $option 修饰",
                "count": len(categories["network"]),
                "size_bytes": None,
                "target_tools": ["AdGuard", "uBlock Origin"],
            },
        },
        "classification": {
            "dns": stats["dns"],
            "cosmetic": stats["cosmetic"],
            "network": stats["network"],
            "comments": stats["comment"],
            "empty_lines": stats["empty"],
        },
        "deduplication": {
            "before": dedup_stats.get("before", 0),
            "after": dedup_stats.get("after", 0),
            "removed": dedup_stats.get("removed", 0),
        },
        "format_validation": {
            "total_rules": validation["total_rules"],
            "valid": validation["valid"],
            "invalid": validation["invalid"],
            "validity_rate": (
                round(validation["valid"] / max(validation["total_rules"], 1) * 100, 2)
            ),
            "format_distribution": validation["format_distribution"],
            "invalid_samples": validation["invalid_samples"][:10],
        },
        "total_rules": sum(len(v) for v in categories.values()),
        "processing_time_seconds": round(elapsed, 2),
    }


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main():
    log.info("=== AdBlock 规则处理脚本启动 ===")
    start_time = time.time()

    # 1. 下载源文件
    log.info("步骤 1/5: 下载源文件")
    dns_content = download(URL_DNS, "adblockdns.txt (DNS 规则)")
    filter_content = download(URL_FILTERS, "adblockfilters.txt (过滤规则)")

    # 2. 合并、分类、格式校验
    log.info("步骤 2/5: 解析、分类并校验格式")
    all_lines = dns_content.splitlines() + filter_content.splitlines()
    log.info("总计 %d 行待处理", len(all_lines))

    categories, stats, validation = classify_rules(all_lines)
    log.info(
        "分类结果: DNS=%d, Cosmetic=%d, Network=%d (注释=%d, 空行=%d)",
        stats["dns"], stats["cosmetic"], stats["network"],
        stats["comment"], stats["empty"],
    )
    log.info(
        "格式校验: %d/%d 有效 (%.2f%%), %d 条格式未知",
        validation["valid"], validation["total_rules"],
        validation["valid"] / max(validation["total_rules"], 1) * 100,
        validation["invalid"],
    )

    # 输出格式分布
    for fmt, count in sorted(validation["format_distribution"].items(), key=lambda x: -x[1]):
        log.info("  - %s: %d 条", fmt, count)

    # 如有格式未知的规则，输出示例
    if validation["invalid_samples"]:
        log.warning("格式未知的规则示例 (共 %d 条, 显示前 %d 条):",
                    validation["invalid"], len(validation["invalid_samples"]))
        for i, sample in enumerate(validation["invalid_samples"][:10], 1):
            log.warning("  [%d] %s", i, sample)

    # 3. 去重
    log.info("步骤 3/5: 去重")
    dedup_stats = {"before": 0, "after": 0, "removed": 0}
    for key in categories:
        before = len(categories[key])
        dedup_stats["before"] += before
        categories[key] = deduplicate(categories[key])
        after = len(categories[key])
        dedup_stats["after"] += after
        dedup_stats["removed"] += before - after
        if before != after:
            log.info("  %s: 去重 %d → %d (移除 %d 条重复)", key, before, after, before - after)

    # 4. 写入输出文件
    log.info("步骤 4/5: 写入规则文件")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    output_configs = [
        (
            "dns.txt",
            categories["dns"],
            "AdBlock DNS Rules",
            "DNS 域名阻断规则，适用于 AdGuard Home / Pi-Hole 等 DNS 级广告拦截工具。每天 12:00 CST 更新。",
            [URL_DNS],
            "dns",
        ),
        (
            "cosmetic.txt",
            categories["cosmetic"],
            "AdBlock Cosmetic Rules",
            "元素隐藏规则（CSS 选择器），适用于 AdGuard / uBlock Origin 等浏览器广告拦截工具。每天 12:00 CST 更新。",
            [URL_FILTERS],
            "cosmetic",
        ),
        (
            "network.txt",
            categories["network"],
            "AdBlock Network Rules",
            "网络请求过滤规则，包含 URL 路径过滤、内容类型过滤、白名单等。适用于 AdGuard / uBlock Origin 等浏览器广告拦截工具。每天 12:00 CST 更新。",
            [URL_DNS, URL_FILTERS],
            "network",
        ),
    ]

    file_sizes = {}
    for filename, rules, title, desc, sources, rtype in output_configs:
        output_path = os.path.join(OUTPUT_DIR, filename)
        content = build_output(rules, title, desc, sources, rtype)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        file_sizes[filename] = os.path.getsize(output_path)
        log.info("  %s: %d 条规则, 文件大小 %d 字节", filename, len(rules), file_sizes[filename])

    # 5. 生成统计摘要
    log.info("步骤 5/5: 生成统计摘要")
    elapsed = time.time() - start_time
    stats_data = generate_stats(categories, stats, validation, dedup_stats, elapsed)

    # 填充实际文件大小
    for fname in stats_data["output_files"]:
        if fname in file_sizes:
            stats_data["output_files"][fname]["size_bytes"] = file_sizes[fname]

    stats_path = os.path.join(OUTPUT_DIR, "stats.json")
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats_data, f, ensure_ascii=False, indent=2)

    log.info("=== 处理完成, 耗时 %.1f 秒 ===", elapsed)

    # 终端汇总输出
    total_rules = sum(len(v) for v in categories.values())
    validity_pct = validation["valid"] / max(validation["total_rules"], 1) * 100
    print(f"""
╔══════════════════════════════════════════════╗
║       AdBlock Filter Split - 处理汇总       ║
╠══════════════════════════════════════════════╣
║  规则来源: 217heidai/adblockfilters         ║
║  更新时间: {datetime.now(CST).strftime('%Y-%m-%d %H:%M CST'):<30} ║
╠══════════════════════════════════════════════╣
║  输出文件:                                   ║
║    dns.txt       {len(categories['dns']):>8,} 条  (DNS 域名阻断)     ║
║    cosmetic.txt  {len(categories['cosmetic']):>8,} 条  (元素隐藏)       ║
║    network.txt   {len(categories['network']):>8,} 条  (网络过滤)       ║
╠══════════════════════════════════════════════╣
║  合计:          {total_rules:>8,} 条                    ║
╠══════════════════════════════════════════════╣
║  格式校验:      {validation['valid']:>8,} / {validation['total_rules']:>8,} ({validity_pct:.2f}%)       ║
║  无效/未知:     {validation['invalid']:>8,} 条                    ║
║  去除重复:      {dedup_stats['removed']:>8,} 条                    ║
╠══════════════════════════════════════════════╣
║  下次更新: 每天 12:00 CST (UTC+8)           ║
╚══════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log.error("脚本执行失败: %s", e, exc_info=True)
        sys.exit(1)
