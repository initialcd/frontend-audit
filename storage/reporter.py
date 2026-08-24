"""报告输出：JSON 全量数据 + Markdown 可读报告（带溯源链）。"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from core.config import Config
from storage.db import Store

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


async def write_reports(cfg: Config, store: Store, summary) -> Path:
    out = Path(cfg.storage.output_dir)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = out / stamp
    out.mkdir(parents=True, exist_ok=True)

    findings = await store.all_findings()
    endpoints = await store.all_endpoints()
    urls = await store.all_urls()
    stats = await store.stats()

    data = {
        "generated_at": stamp,
        "scope": cfg.scope.domains,
        "summary": {
            "total_nodes": summary.total_nodes,
            "fetched": summary.fetched,
            "html": summary.html,
            "js": summary.js,
            "json": summary.json,
            "llm_calls": summary.llm_calls,
            "llm_failures": summary.llm_failures,
            "skipped_scope": summary.skipped_scope,
            "skipped_dup": summary.skipped_dup,
            "skipped_budget": summary.skipped_budget,
            **stats,
        },
        "findings": findings,
        "endpoints": endpoints,
        "urls": urls,
    }
    (out / "full.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out / "report.md").write_text(_render_markdown(cfg, summary, stats, findings, endpoints, urls), encoding="utf-8")
    return out


def _esc(s: str) -> str:
    return str(s or "").replace("|", "\\|").replace("\n", " ")


def _render_markdown(cfg, summary, stats, findings, endpoints, urls) -> str:
    status_by_url = {u.get("url"): u.get("status") for u in urls}
    lines = [
        "# 前端代码审计报告",
        "",
        f"- 生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 授权域名白名单：{', '.join(cfg.scope.domains) or '（无）'}",
        f"- 递归深度上限：{cfg.scan.max_depth}",
        "",
        "## 统计",
        "",
        f"| 指标 | 值 |",
        f"|---|---|",
        f"| 抓取节点 | {summary.total_nodes}（HTML {summary.html} / JS {summary.js} / JSON {summary.json}） |",
        f"| 审计发现 | {stats['findings']} 条 |",
        f"| 接口探测 | {stats['endpoints']} 个（{len(endpoints)} 次 OPTIONS/POST 探测请求） |",
        f"| LLM 调用 | {summary.llm_calls} 次，失败 {summary.llm_failures} 次 |",
        f"| 跳过 | 白名单外 {summary.skipped_scope} / 重复 {summary.skipped_dup} / 超预算 {summary.skipped_budget} |",
        "",
        "## 敏感信息发现",
        "",
    ]
    if not findings:
        lines += ["（无）", ""]
    else:
        lines += ["| 级别 | 类型 | 值 | 来源 | 置信度 | 理由 |", "|---|---|---|---|---|---|"]
        for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity"), 9)):
            value = _esc(f.get("value"))[:80]
            lines.append(
                f"| {f.get('severity')} | {_esc(f.get('ftype'))} | {value} | "
                f"{_esc(f.get('source_url'))[:60]} | {f.get('confidence')} | {_esc(f.get('reason'))[:40]} |"
            )
        lines.append("")
    lines += [
        "## 接口探测（多方法）",
        "",
        "| 接口 | GET(抓取) | OPTIONS | POST | CORS |",
        "|---|---|---|---|---|",
    ]
    if not endpoints:
        lines.append("| （无） | | | | |")
    else:
        by_url: dict[str, dict[str, str]] = {}
        for e in endpoints:
            row = by_url.setdefault(e.get("url"), {})
            row[e.get("method", "").upper()] = str(e.get("status"))
            row["cors"] = e.get("cors") or ""
        for url, row in by_url.items():
            lines.append(
                f"| {_esc(url)[:80]} | {status_by_url.get(url, '-')} | {row.get('OPTIONS', '-')} | "
                f"{row.get('POST', '-')} | {_esc(row.get('cors', ''))[:30]} |"
            )
    lines += [
        "",
        "## 抓取节点明细",
        "",
        "| URL | 状态 | 类型 | 大小 | 深度 |",
        "|---|---|---|---|---|",
    ]
    for u in urls:
        lines.append(
            f"| {_esc(u.get('url'))[:80]} | {u.get('status')} | {_esc(u.get('kind'))} | "
            f"{u.get('size')} | {u.get('depth')} |"
        )
    lines.append("")
    return "\n".join(lines)
