"""报告输出：JSON 全量数据 + Markdown 可读报告 + 自包含 HTML 报告。

三种产物面向不同场景：
- `full.json`：机器读，全量数据；
- `report.md`：归档、贴进渗透报告；
- `report.html`：**无外网环境（客户内网 / 云桌面）里给人看**。单文件、零外链、
  零依赖，双击就能在浏览器打开，并且把每条发现的命中代码上下文一并渲染出来。
"""
from __future__ import annotations

import html
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
    (out / "report.html").write_text(
        _render_html(cfg, summary, stats, findings, endpoints, urls, stamp), encoding="utf-8"
    )
    return out


def _esc(s: str) -> str:
    return str(s or "").replace("|", "\\|").replace("\n", " ")


_HTML_CSS = """
:root{--bg:#f5f6f8;--panel:#fff;--bd:#d8dce4;--tx:#1c2230;--mu:#657085;
--crit:#c62b47;--high:#c26a05;--med:#8d5b00;--low:#2a63c4;--ok:#12866a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.6 "Segoe UI","Microsoft YaHei",system-ui,sans-serif}
header{background:var(--panel);border-bottom:1px solid var(--bd);padding:16px 22px}
h1{margin:0 0 6px;font-size:19px}
h2{font-size:15px;margin:26px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--bd)}
.wrap{padding:0 22px 40px;max-width:1500px}
.meta{color:var(--mu);font-size:12px}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0}
.card{background:var(--panel);border:1px solid var(--bd);border-radius:8px;padding:9px 14px;min-width:104px}
.card .k{font-size:11px;color:var(--mu)}
.card .v{font-size:19px;font-weight:600}
.finding{background:var(--panel);border:1px solid var(--bd);border-left:4px solid var(--bd);
border-radius:8px;padding:11px 14px;margin-bottom:9px}
.finding.critical{border-left-color:var(--crit)}.finding.high{border-left-color:var(--high)}
.finding.medium{border-left-color:var(--med)}.finding.low{border-left-color:var(--low)}
.fhead{display:flex;flex-wrap:wrap;gap:9px;align-items:baseline}
.sev{font-size:11px;font-weight:700;padding:1px 7px;border-radius:9px;background:#eceff4}
.critical .sev{background:rgba(198,43,71,.12);color:var(--crit)}
.high .sev{background:rgba(194,106,5,.12);color:var(--high)}
.medium .sev{background:rgba(141,91,0,.12);color:var(--med)}
.low .sev{background:rgba(42,99,196,.12);color:var(--low)}
.ftype{font-weight:600}
.fval{font-family:Consolas,monospace;color:var(--crit);word-break:break-all}
.fconf{color:var(--mu);font-size:12px;margin-left:auto}
.fsrc{color:var(--mu);font-size:12px;margin:5px 0;word-break:break-all}
pre{background:#f0f2f6;border:1px solid var(--bd);border-radius:6px;padding:9px 11px;margin:6px 0 0;
overflow-x:auto;font:12px/1.5 Consolas,monospace;white-space:pre-wrap;word-break:break-all}
.freason{color:var(--mu);font-size:12px;margin-top:6px}
table{width:100%;border-collapse:collapse;background:var(--panel);font-size:12px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--bd);word-break:break-all}
th{color:var(--mu);font-weight:500;background:#eceff4}
.s2{color:var(--ok)}.s4{color:var(--high)}.s5{color:var(--crit)}
.note{color:var(--mu);font-size:12px;margin:8px 0}
footer{color:var(--mu);font-size:12px;padding:18px 22px;border-top:1px solid var(--bd)}
"""


def _hse(s) -> str:
    """HTML 转义（值来自被抓取的页面，必须转义）。"""
    return html.escape(str(s if s is not None else ""), quote=True)


def _render_html(cfg, summary, stats, findings, endpoints, urls, stamp: str,
                 limit: int = 2000) -> str:
    """自包含 HTML 报告：无外部 CSS/JS/字体，离线可用，把命中上下文一起渲染。"""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = (f.get("severity") or "medium").lower()
        counts[sev] = counts.get(sev, 0) + 1
    ordered = sorted(findings, key=lambda x: SEVERITY_ORDER.get((x.get("severity") or "").lower(), 9))
    shown = ordered[:limit]

    offline = bool(getattr(cfg.scan, "offline", False))
    mode_txt = "离线模式（纯本地正则，不调用 LLM）" if offline else (
        f"审计模式（LLM {'开' if cfg.scan.llm_enabled else '关'}）")
    render_txt = (cfg.scan.render_mode if cfg.scan.render_enabled else "off")

    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="zh-CN"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>前端审计报告 · {_hse(stamp)}</title>",
        f"<style>{_HTML_CSS}</style></head><body>",
        "<header>",
        "<h1>前端代码审计报告</h1>",
        f'<div class="meta">生成时间 {_hse(stamp)} ｜ 白名单 {_hse("、".join(cfg.scope.domains) or "（无）")}'
        f" ｜ 深度 {cfg.scan.max_depth} ｜ {_hse(mode_txt)} ｜ 渲染 {_hse(render_txt)}</div>",
        "</header>",
        '<div class="wrap">',
        '<div class="cards">',
    ]
    for label, val in (
        ("抓取节点", summary.total_nodes),
        ("敏感发现", stats["findings"]),
        ("接口", stats["endpoints"]),
        ("critical", counts["critical"]),
        ("high", counts["high"]),
        ("medium", counts["medium"]),
        ("low", counts["low"]),
        ("渲染页面", summary.rendered),
        ("CDP 补抓 JS", summary.render_js_urls),
    ):
        parts.append(f'<div class="card"><div class="k">{_hse(label)}</div>'
                     f'<div class="v">{_hse(val)}</div></div>')
    parts.append("</div>")

    if offline:
        parts.append(
            '<div class="note">本报告由离线模式生成：全部结果来自本地正则与本地探测，'
            "未向任何外部服务发送数据。完整原始数据见同目录 <code>full.json</code>，"
            "Markdown 版见 <code>report.md</code>。</div>"
        )

    parts.append(f"<h2>敏感信息发现（{len(findings)} 条）</h2>")
    if not shown:
        parts.append('<div class="note">本次未命中任何规则。</div>')
    for f in shown:
        sev = (f.get("severity") or "medium").lower()
        if sev not in SEVERITY_ORDER:
            sev = "medium"
        parts.append(f'<div class="finding {sev}">')
        parts.append('<div class="fhead">')
        parts.append(f'<span class="sev">{_hse(sev)}</span>')
        parts.append(f'<span class="ftype">{_hse(f.get("ftype"))}</span>')
        parts.append(f'<span class="fval">{_hse(f.get("value"))}</span>')
        parts.append(f'<span class="fconf">置信度 {_hse(f.get("confidence"))}</span>')
        parts.append("</div>")
        parts.append(f'<div class="fsrc">来源：{_hse(f.get("source_url"))}</div>')
        ctx = f.get("context")
        if ctx:
            parts.append(f"<pre>{_hse(ctx)}</pre>")
        reason = f.get("reason")
        if reason:
            parts.append(f'<div class="freason">判定依据：{_hse(reason)}</div>')
        parts.append("</div>")
    if len(ordered) > limit:
        parts.append(f'<div class="note">已折叠显示前 {limit} 条，其余见 full.json。</div>')

    parts.append(f"<h2>接口探测（{len(endpoints)} 条记录）</h2>")
    if not endpoints:
        parts.append('<div class="note">未发现接口。</div>')
    else:
        status_by_url = {u.get("url"): u.get("status") for u in urls}
        by_url: dict[str, dict[str, str]] = {}
        for e in endpoints:
            row = by_url.setdefault(e.get("url") or "", {})
            row[(e.get("method") or "").upper()] = str(e.get("status"))
            if e.get("cors"):
                row["cors"] = e["cors"]
        parts.append("<table><thead><tr><th>接口</th><th>GET</th><th>OPTIONS</th>"
                     "<th>POST</th><th>CORS</th></tr></thead><tbody>")
        for url, row in by_url.items():
            parts.append(
                f"<tr><td>{_hse(url)}</td><td>{_hse(status_by_url.get(url, '-'))}</td>"
                f"<td>{_hse(row.get('OPTIONS', '-'))}</td><td>{_hse(row.get('POST', '-'))}</td>"
                f"<td>{_hse(row.get('cors', ''))}</td></tr>"
            )
        parts.append("</tbody></table>")

    parts.append(f"<h2>抓取节点（{len(urls)}）</h2>")
    if not urls:
        parts.append('<div class="note">无节点记录。</div>')
    else:
        parts.append("<table><thead><tr><th>URL</th><th>状态</th><th>类型</th>"
                     "<th>大小</th><th>深度</th></tr></thead><tbody>")
        for u in urls[:limit]:
            parts.append(
                f"<tr><td>{_hse(u.get('url'))}</td><td>{_hse(u.get('status'))}</td>"
                f"<td>{_hse(u.get('kind'))}</td><td>{_hse(u.get('size'))}</td>"
                f"<td>{_hse(u.get('depth'))}</td></tr>"
            )
        parts.append("</tbody></table>")
        if len(urls) > limit:
            parts.append(f'<div class="note">已折叠显示前 {limit} 个节点，其余见 full.json。</div>')

    parts.append("</div>")
    parts.append(
        f"<footer>frontend-audit ｜ 统计：抓取 {summary.total_nodes}，"
        f"HTML {summary.html} / JS {summary.js} / JSON {summary.json}，"
        f"跳过 白名单外 {summary.skipped_scope} / 重复 {summary.skipped_dup} / 超预算 {summary.skipped_budget}"
        f"</footer>"
    )
    parts.append("</body></html>")
    return "\n".join(parts)


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
