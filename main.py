"""前端代码敏感信息审计 + API 递归发现工具。

用法示例：
  python main.py -u urls.txt -c config.yaml
  python main.py -u https://target.example.com --no-llm --domains target.example.com
  python main.py -u urls.txt -d 4 --domains example.com

从项目根目录运行。断点续跑默认开启（复用 state.db 的去重记录）。
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
from core.orchestrator import Orchestrator
from core.proxy_pool import ProxyPool
from storage.db import Store
from storage.reporter import write_reports


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="前端代码敏感信息审计 + API 递归发现")
    p.add_argument("-u", "--urls", required=True,
                   help="URL 列表文件或单个 URL（http(s) 开头）")
    p.add_argument("-c", "--config", default="config.yaml", help="配置文件路径")
    p.add_argument("-d", "--depth", type=int, default=None, help="覆盖递归深度")
    p.add_argument("--domains", default=None,
                   help="覆盖授权域名白名单，逗号分隔（如 example.com,a.example.com）")
    p.add_argument("--no-llm", action="store_true",
                   help="关闭 DeepSeek 审计，仅本地正则")
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


async def amain(args: argparse.Namespace) -> int:
    cfg = Config.load(args.config)
    if args.depth is not None:
        cfg.scan.max_depth = args.depth
    if args.domains:
        cfg.scope.domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    if args.no_llm:
        cfg.scan.llm_enabled = False

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

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

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
    print(f"跳过：白名单外 {summary.skipped_scope}，重复 {summary.skipped_dup}，超预算 {summary.skipped_budget}")
    print(f"报告目录：{out}")
    return 0


def main() -> None:
    args = parse_args()
    sys.exit(asyncio.run(amain(args)))


if __name__ == "__main__":
    main()
