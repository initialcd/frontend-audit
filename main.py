"""前端代码敏感信息审计 + API 递归发现 + 前端资源下载工具。

用法示例：
  # 审计模式
  python main.py -u urls.txt -c config.yaml
  python main.py -u https://target.example.com --no-llm --domains target.example.com
  python main.py -u urls.txt -d 4 --domains example.com

  # 下载模式：递归爬取前端资源并存盘（不审计、不调 LLM）
  python main.py --download -u https://target.example.com --domains target.example.com -o ./dump
  python main.py --download -u urls.txt --domains example.com -o ./dump -d 3

  # 同一个目标要重扫时加 --fresh（否则命中去重记录会显示「成功 0」）
  python main.py --download -u urls.txt --domains example.com --fresh

从项目根目录运行。审计与下载共用同一套 Orchestrator 引擎（下载模式即
download_only=True），两者都具备增强渲染、节点预算控制与统一的去重逻辑。
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from core.auditor import Auditor
from core.config import Config
from core.dedup import Dedup
from core.fetcher import Fetcher
from core.normalizer import parse_domains
from core.orchestrator import Orchestrator
from core.proxy_pool import ProxyPool
from core.renderer import Renderer
from storage.db import Store
from storage.reporter import write_reports


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="前端代码敏感信息审计 + API 递归发现 + 前端资源下载 by inicd")
    p.add_argument("-u", "--urls", required=True,
                   help="URL 列表文件或单个 URL（http(s) 开头）")
    p.add_argument("-c", "--config", default="config.yaml", help="配置文件路径")
    p.add_argument("-d", "--depth", type=int, default=None, help="覆盖递归深度")
    p.add_argument("--domains", default=None,
                   help="覆盖授权域名白名单，逗号分隔（如 example.com,a.example.com）")
    p.add_argument("--no-llm", action="store_true",
                   help="关闭 DeepSeek 审计，仅本地正则")
    p.add_argument("--audit-json", action="store_true",
                   help="对 JSON 内容也启用 LLM 语义审计（默认关闭，省 token）")
    p.add_argument("--download", action="store_true",
                   help="下载模式：递归爬取前端资源并存盘，不审计")
    p.add_argument("-o", "--output", default="downloads",
                   help="下载模式输出目录（默认 downloads）")
    p.add_argument("--fresh", action="store_true",
                   help="忽略断点续跑：清空历史状态库后从零重扫"
                        "（不加则重跑同一目标会因命中去重记录而显示「成功 0」）")
    p.add_argument("--render", choices=["off", "hybrid", "full"], default=None,
                   help="增强渲染模式（覆盖 config.yaml）：off=纯 httpx / "
                        "hybrid=仅 SPA 空壳 / full=对所有 HTML 页面启用")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()


def load_seeds(target: str) -> list[str]:
    if target.startswith(("http://", "https://")):
        return [target]
    path = Path(target)
    if not path.exists():
        print(f"错误：找不到文件 {target}", file=sys.stderr)
        sys.exit(2)
    seeds = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    return seeds


def purge_state(cfg: Config) -> None:
    """--fresh：删除历史状态库，从零重扫。

    断点续跑靠 state.db 里的 URL 哈希去重，重复执行同一目标时所有种子都会被
    判成"已抓过"，表现为"成功 0 / 跳过重复 N"。要重扫就必须清掉这批记录。
    """
    base = Path(cfg.storage.db_path)
    removed: list[str] = []
    for p in (base, Path(str(base) + "-wal"), Path(str(base) + "-shm")):
        if not p.exists():
            continue
        try:
            p.unlink()
            removed.append(p.name)
        except OSError as exc:
            print(f"警告：无法删除 {p}：{exc}", file=sys.stderr)
    if removed:
        print(f"[*] --fresh：已清空历史记录（{'、'.join(removed)}）")


def render_state(cfg: Config) -> str:
    """增强渲染的实际可用状态：包/内核缺失都明确讲出来，避免"以为开了"。"""
    if not cfg.scan.render_enabled or cfg.scan.render_mode == "off":
        return "关"
    r = Renderer(cfg)
    if not r.available():
        return (f"开（{cfg.scan.render_mode}）但 Playwright 未安装 → 本次会静默跳过渲染"
                "（pip install playwright && python -m playwright install chromium）")
    if not r.browser_ready():
        return (f"开（{cfg.scan.render_mode}）但浏览器内核未下载 → 首次渲染会失败并降级"
                "（补：python -m playwright install chromium）")
    return f"开（{cfg.scan.render_mode}）"


def _logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


async def amain(args: argparse.Namespace) -> int:
    cfg = Config.load(args.config)
    if args.depth is not None:
        cfg.scan.max_depth = args.depth
    if args.domains:
        cfg.scope.domains = parse_domains(args.domains)
    if args.no_llm:
        cfg.scan.llm_enabled = False
    if args.audit_json:
        cfg.scan.audit_json = True
    if args.render:
        cfg.scan.render_mode = args.render
        cfg.scan.render_enabled = args.render != "off"
    if args.fresh:
        purge_state(cfg)

    # 安全约束：无授权白名单则拒绝运行
    if not cfg.scope.domains:
        print(
            "错误：未配置授权域名白名单。请在 config.yaml 的 scope.domains "
            "或 --domains 参数中指定（如 example.com）。拒绝运行。",
            file=sys.stderr,
        )
        return 2
    if cfg.scan.llm_enabled and not cfg.resolve_api_key():
        print("警告：未配置 DEEPSEEK_API_KEY，自动降级为纯本地正则模式。", file=sys.stderr)
        cfg.scan.llm_enabled = False

    _logging(args.verbose)

    proxy_pool = ProxyPool(cfg)
    fetcher = Fetcher(cfg, proxy_pool)
    auditor = Auditor(cfg)
    dedup = Dedup()
    store = Store(cfg.storage.db_path)
    orch = Orchestrator(cfg, store, fetcher, auditor, dedup)

    seeds = load_seeds(args.urls)
    print(f"[*] 授权域名白名单：{cfg.scope.domains}")
    print(f"[*] 种子数：{len(seeds)}，深度上限：{cfg.scan.max_depth}，"
          f"并发：{cfg.scan.concurrency}，LLM：{'开' if cfg.scan.llm_enabled else '关'}，"
          f"代理：{'开' if cfg.proxy.enabled else '关'}")
    print(f"[*] 增强渲染：{render_state(cfg)}")
    print(f"[*] 断点续跑：{'关（--fresh）' if args.fresh else '开（命中去重记录会跳过）'}")
    try:
        summary = await orch.run(seeds)
    finally:
        await fetcher.close()
        await orch.renderer.close()
    out = await write_reports(cfg, store, summary)
    store.close()

    print("\n===== 扫描完成 =====")
    print(f"节点：{summary.total_nodes}（HTML {summary.html} / JS {summary.js} / JSON {summary.json}）")
    print(f"审计发现：{summary.findings} 条，接口探测：{summary.endpoints} 个")
    print(f"LLM 调用：{summary.llm_calls} 次，失败 {summary.llm_failures} 次")
    if summary.rendered or summary.render_js_urls:
        print(f"增强渲染：{summary.rendered} 个页面，CDP 多拦截 {summary.render_js_urls} 个 JS，"
              f"{summary.render_route_count} 条路由")
    print(f"跳过：白名单外 {summary.skipped_scope}，重复 {summary.skipped_dup}，超预算 {summary.skipped_budget}")
    print(f"报告目录：{out}")
    return 0


async def download_mode(args: argparse.Namespace) -> int:
    """下载模式：递归爬取前端资源并存盘，不审计、不调 LLM。

    与 Web UI 的下载模式走完全相同的 Orchestrator 引擎（download_only=True），
    因此同样具备增强渲染（SPA 动态 chunk 只有渲染才抓得到）、节点预算控制，
    以及统一的 URL 规范化 / 白名单 / 去重逻辑。
    """
    cfg = Config.load(args.config)
    if args.depth is not None:
        cfg.scan.max_depth = args.depth
    if args.domains:
        cfg.scope.domains = parse_domains(args.domains)
    if args.render:
        cfg.scan.render_mode = args.render
        cfg.scan.render_enabled = args.render != "off"
    if args.fresh:
        purge_state(cfg)

    if not cfg.scope.domains:
        print(
            "错误：下载模式也需要配置授权域名白名单。请在 config.yaml 的 "
            "scope.domains 或 --domains 参数中指定。拒绝运行。",
            file=sys.stderr,
        )
        return 2

    # 下载模式不审计：强制关掉 LLM 与 JSON 审计，避免误触发 API 调用
    cfg.scan.llm_enabled = False
    cfg.scan.audit_json = False

    output_dir = Path(args.output)
    if not output_dir.is_absolute():
        output_dir = (Path.cwd() / output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    seeds = load_seeds(args.urls)
    _logging(args.verbose)

    proxy_pool = ProxyPool(cfg)
    fetcher = Fetcher(cfg, proxy_pool)
    auditor = Auditor(cfg)
    dedup = Dedup()
    store = Store(cfg.storage.db_path)
    orch = Orchestrator(cfg, store, fetcher, auditor, dedup)
    orch.download_only = True
    orch.download_dir = output_dir

    print(f"[*] 下载模式：种子 {len(seeds)} 个，深度 {cfg.scan.max_depth}，"
          f"并发 {cfg.scan.concurrency}，输出目录 {output_dir}")
    print(f"[*] 授权域名白名单：{cfg.scope.domains}")
    print(f"[*] 节点预算：每域 {cfg.scan.max_nodes_per_domain}，全局 {cfg.scan.max_total_nodes}")
    print(f"[*] 增强渲染：{render_state(cfg)}")
    print(f"[*] 断点续跑：{'关（--fresh）' if args.fresh else '开（命中去重记录会跳过，想全量重跑加 --fresh）'}")

    try:
        summary = await orch.run(seeds)
    finally:
        await fetcher.close()
        await orch.renderer.close()
    store.close()

    print("\n===== 下载完成 =====")
    print(f"成功落盘：{summary.downloaded}，下载失败：{summary.download_failed}")
    if summary.rendered or summary.render_js_urls:
        print(f"增强渲染：{summary.rendered} 个页面，CDP 多拦截 {summary.render_js_urls} 个 JS，"
              f"{summary.render_route_count} 条路由")
    print(f"跳过：白名单外 {summary.skipped_scope}，重复 {summary.skipped_dup}，超预算 {summary.skipped_budget}")
    print(f"输出目录：{output_dir}")
    return 0


def main() -> None:
    args = parse_args()
    if args.download:
        sys.exit(asyncio.run(download_mode(args)))
    sys.exit(asyncio.run(amain(args)))


if __name__ == "__main__":
    main()
