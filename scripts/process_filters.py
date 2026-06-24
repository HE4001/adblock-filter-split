#!/usr/bin/env python3
"""
AdBlock 规则下载、分类、去重、输出脚本。

从上游仓库下载两个规则文件，按规则类型拆分为三个文件：
  - rules/dns.txt      : DNS 域名阻断规则 (||domain^)
  - rules/cosmetic.txt : 元素隐藏规则 (## / ###)
  - rules/network.txt  : 网络请求过滤规则 (||domain/path, $option 等)

纯标准库实现，零外部依赖，适用于 GitHub Actions 环境。
"""

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
                # 某些环境返回的可能是压缩内容，但 raw.githubusercontent.com 不压缩
                content = resp.read().decode("utf-8", errors="replace")
            log.info("下载 %s 成功, 大小: %d 字节", description, len(content))
            return content
        except (URLError, HTTPError, OSError) as e:
            log.warning("下载 %s 失败 (尝试 %d/%d): %s", description, attempt, MAX_RETRIES, e)
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
    raise RuntimeError(f"下载 {description} 失败，已重试 {MAX_RETRIES} 次")


# ---------------------------------------------------------------------------
# 规则分类
# ---------------------------------------------------------------------------

# DNS 规则: ||domain^   (纯域名阻断，无路径、无 $option)
RE_DNS = re.compile(r'^\|\|[a-zA-Z0-9][-a-zA-Z0-9.]*\^\s*$')

# 元素隐藏规则: ##... 或 ###...
RE_COSMETIC = re.compile(r'^(?:###?)(.+)')

# 例外/白名单规则
RE_EXCEPTION = re.compile(r'^@@')

# 网络过滤规则: ||domain/path, ||domain^$option, 正则 /pattern/, 等
RE_NETWORK = re.compile(r'^\|\|')

# 注释行
RE_COMMENT = re.compile(r'^!')

# 用于验证规则行 (非空、非注释)
RE_RULE_LINE = re.compile(r'^[!\s]|^$')


def classify_rules(lines: list[str]) -> dict[str, list[str]]:
    """将规则行按类型分类。

    Returns:
        {
            "dns": [...],
            "cosmetic": [...],
            "network": [...],
        }
    """
    categories = {"dns": [], "cosmetic": [], "network": []}
    stats = {"dns": 0, "cosmetic": 0, "network": 0, "comment": 0, "empty": 0}

    for line in lines:
        stripped = line.strip()

        # 空行跳过
        if not stripped:
            stats["empty"] += 1
            continue

        # 注释行跳过 (不计入规则，但头部注释单独处理)
        if stripped.startswith("!"):
            stats["comment"] += 1
            continue

        # 分类
        if RE_DNS.match(stripped):
            categories["dns"].append(stripped)
            stats["dns"] += 1
        elif RE_COSMETIC.match(stripped):
            categories["cosmetic"].append(stripped)
            stats["cosmetic"] += 1
        elif RE_EXCEPTION.match(stripped):
            # 白名单规则归入网络规则
            categories["network"].append(stripped)
            stats["network"] += 1
        elif RE_NETWORK.match(stripped):
            # 带路径或选项的域名规则
            categories["network"].append(stripped)
            stats["network"] += 1
        else:
            # 其他规则类型 (正则 /pattern/, 纯域名等) → 网络规则
            categories["network"].append(stripped)
            stats["network"] += 1

    return categories, stats


# ---------------------------------------------------------------------------
# 注释头部提取
# ---------------------------------------------------------------------------

def extract_header(lines: list[str]) -> str:
    """提取源文件头部的注释块。"""
    header = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("!"):
            header.append(stripped)
        elif not stripped:
            # 头部区域的空行保留
            if header:
                header.append("")
        else:
            # 遇到第一个非注释非空行，停止
            break
    return header


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
) -> str:
    """构建输出文件内容（含元数据头部）。

    Args:
        rules: 规则列表
        title: 文件标题
        description: 文件描述
        source_urls: 上游源文件 URL 列表
        rule_type: 规则类型标签
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
! Source:
"""
    for url in source_urls:
        header += f"!   - {url}\n"
    header += "!\n"

    return header + "\n".join(rules) + "\n"


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main():
    log.info("=== AdBlock 规则处理脚本启动 ===")
    start_time = time.time()

    # 1. 下载源文件
    log.info("步骤 1/4: 下载源文件")
    dns_content = download(URL_DNS, "adblockdns.txt (DNS 规则)")
    filter_content = download(URL_FILTERS, "adblockfilters.txt (过滤规则)")

    # 2. 合并所有行并分类
    log.info("步骤 2/4: 解析并分类规则")
    all_lines = dns_content.splitlines() + filter_content.splitlines()
    log.info("总计 %d 行待处理", len(all_lines))

    categories, stats = classify_rules(all_lines)
    log.info(
        "分类结果: DNS=%d, Cosmetic=%d, Network=%d (注释=%d, 空行=%d)",
        stats["dns"], stats["cosmetic"], stats["network"],
        stats["comment"], stats["empty"],
    )

    # 3. 去重
    log.info("步骤 3/4: 去重")
    for key in categories:
        before = len(categories[key])
        categories[key] = deduplicate(categories[key])
        after = len(categories[key])
        if before != after:
            log.info("  %s: 去重 %d → %d (移除 %d 条重复)", key, before, after, before - after)

    # 4. 写入输出文件
    log.info("步骤 4/4: 写入输出文件")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    output_configs = [
        (
            "dns.txt",
            categories["dns"],
            "AdBlock DNS Rules",
            "DNS 域名阻断规则，适用于 AdGuard Home / Pi-Hole 等 DNS 级广告拦截工具。每 24 小时更新。",
            [URL_DNS],
            "dns",
        ),
        (
            "cosmetic.txt",
            categories["cosmetic"],
            "AdBlock Cosmetic Rules",
            "元素隐藏规则（CSS 选择器），适用于 AdGuard / uBlock Origin 等浏览器广告拦截工具。每 24 小时更新。",
            [URL_FILTERS],
            "cosmetic",
        ),
        (
            "network.txt",
            categories["network"],
            "AdBlock Network Rules",
            "网络请求过滤规则，包含 URL 路径过滤、内容类型过滤、白名单等。适用于 AdGuard / uBlock Origin 等浏览器广告拦截工具。每 24 小时更新。",
            [URL_DNS, URL_FILTERS],
            "network",
        ),
    ]

    for filename, rules, title, desc, sources, rtype in output_configs:
        output_path = os.path.join(OUTPUT_DIR, filename)
        content = build_output(rules, title, desc, sources, rtype)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        file_size = os.path.getsize(output_path)
        log.info("  %s: %d 条规则, 文件大小 %d 字节", filename, len(rules), file_size)

    elapsed = time.time() - start_time
    log.info("=== 处理完成, 耗时 %.1f 秒 ===", elapsed)

    # 汇总输出
    total_rules = sum(len(v) for v in categories.values())
    print(f"\n=== 处理汇总 ===")
    print(f"   DNS 规则:     {len(categories['dns']):>8,} 条 → rules/dns.txt")
    print(f"   元素隐藏规则: {len(categories['cosmetic']):>8,} 条 → rules/cosmetic.txt")
    print(f"   网络过滤规则: {len(categories['network']):>8,} 条 → rules/network.txt")
    print(f"   {'─' * 35}")
    print(f"   总计:         {total_rules:>8,} 条")
    print(f"   耗时: {elapsed:.1f} 秒")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log.error("脚本执行失败: %s", e, exc_info=True)
        sys.exit(1)
