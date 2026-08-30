"""前端代码敏感信息审计 + API 递归发现 + 前端资源下载工具。

用法示例：
  # 审计模式
  python main.py -u urls.txt -c config.yaml
  python main.py -u https://target.example.com --no-llm --domains target.example.com
  python main.py -u urls.txt -d 4 --domains example.com

  # 下载模式：递归爬取前端资源并存盘（不审计、不调 LLM）
  python main.py --download -u https://target.example.com --domains target.example.com -o ./dump
  python main.py --download -u urls.txt --domains example.com -o ./dump -d 3

从项目根目录运行。断点续跑默认开启（复用 state.db 的去重记录）。
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from urllib.parse import urlparse, unquote

from core.auditor import Auditor
from core.config import Config
from core.dedup import Dedup
from core.fetcher import Fetcher
from core.normalizer import (
    content_hash,
    host_of,
    is_in_scope,
    is_static_asset,
    normalize_url,
    resolve_url,
    url_hash,
)
from core.prefilter import decode, extract_scripts, prefilter_js
from core.proxy_pool import ProxyPool
from core.orchestrator import Orchestrator
from storage.db import Store
from storage.reporter import write_reports


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="前端代码敏感信息审计 + API 递归发现 + 前端资源下载")
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
    if args.audit_json:
        cfg.scan.audit_json = True

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


def _url_to_filepath(url: str, output_dir: Path, content_type: str) -> Path:
    """将 URL 转为本地文件路径，保留目录结构，按 Content-Type 补后缀。"""
    parsed = urlparse(url)
    host = (parsed.hostname or "unknown").lower()
    # 路径：URL 解码后去掉开头的 /
    path = unquote(parsed.path).lstrip("/") or "index.html"
    if path.endswith("/"):
        path += "index.html"
    fp = output_dir / host / path
    # 无后缀时按 Content-Type 补后缀
    if not fp.suffix:
        if "javascript" in content_type or "ecmascript" in content_type:
            fp = fp.with_suffix(".js")
        elif "json" in content_type:
            fp = fp.with_suffix(".json")
        elif "css" in content_type:
            fp = fp.with_suffix(".css")
        else:
            fp = fp.with_suffix(".html")
    # 路径穿越防护：解码后的 .. 会被 resolve() 展开，校验是否仍在输出目录内
    base = output_dir.resolve()
    if not fp.resolve().is_relative_to(base):
        raise ValueError(f"拒绝写出输出目录之外：{url} -> {fp}")
    return fp


async def download_mode(args: argparse.Namespace) -> int:
    """下载模式：递归爬取前端资源并存盘，不审计、不调 LLM。"""
    cfg = Config.load(args.config)
    if args.depth is not None:
        cfg.scan.max_depth = args.depth
    if args.domains:
        cfg.scope.domains = [d.strip() for d in args.domains.split(",") if d.strip()]

    if not cfg.scope.domains:
        print(
            "错误：下载模式也需要配置授权域名白名单。请在 config.yaml 的 "
            "scope.domains 或 --domains 参数中指定。拒绝运行。",
            file=sys.stderr,
        )
        return 2

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    seeds = load_seeds(args.urls)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    proxy_pool = ProxyPool(cfg)
    fetcher = Fetcher(cfg, proxy_pool)
    store = Store(cfg.storage.db_path)
    dedup = Dedup()
    # 断点续跑：载入历史 URL 与内容哈希，避免重跑从头再来、避免相同内容重复写盘
    dedup.seen_urls |= await store.load_seen_urls()
    dedup.audited_contents |= await store.load_seen_content_hashes()

    print(f"[*] 下载模式：种子 {len(seeds)} 个，深度 {cfg.scan.max_depth}，"
          f"并发 {cfg.scan.concurrency}，输出目录 {output_dir.resolve()}")
    print(f"[*] 授权域名白名单：{cfg.scope.domains}")
    print(f"[*] 断点续跑：已加载 {len(dedup.seen_urls)} 条历史 URL、{len(dedup.audited_contents)} 条内容记录")

    downloaded = 0
    failed = 0
    skipped = 0
    queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
    lock = asyncio.Lock()
    logger = logging.getLogger("download")

    for seed in seeds:
        await queue.put((seed, 0))

    async def worker() -> None:
        nonlocal downloaded, failed, skipped
        while True:
            url, depth = await queue.get()
            if depth < 0:  # 哨兵信号，退出
                queue.task_done()
                return
            try:
                canonical = normalize_url(url)
                if is_static_asset(canonical, cfg.scan.excluded_extensions):
                    skipped += 1
                    continue
                if not is_in_scope(canonical, cfg.scope.domains, cfg.scope.allow_subdomains):
                    skipped += 1
                    continue
                h = url_hash(canonical)
                if dedup.seen_url(h):
                    skipped += 1
                    continue
                dedup.mark_url(h)

                fr = await fetcher.fetch(url)
                if fr.error or fr.body is None:
                    logger.warning("下载失败 %s：%s", url, fr.error or "空响应")
                    failed += 1
                    continue

                kind = fetcher.classify(fr)
                ch = content_hash(fr.body)

                # 持久化 URL 记录（断点续跑）：即使内容重复也标记已处理
                await store.save_url({
                    "url_hash": h, "url": canonical, "final_url": fr.final_url,
                    "status": fr.status, "content_type": fr.content_type, "size": fr.size,
                    "depth": depth, "kind": kind, "source": "download", "content_hash": ch,
                })

                # 内容去重：不同 query 的相同内容（app.js?v=1 / app.js?v=2）只写盘一次
                if dedup.seen_content(ch):
                    skipped += 1
                    logger.debug("内容重复跳过 %s", url)
                    continue
                dedup.mark_content(ch)

                try:
                    filepath = _url_to_filepath(fr.final_url, output_dir, fr.content_type)
                except ValueError as exc:
                    logger.warning("跳过非法路径 %s：%s", url, exc)
                    skipped += 1
                    continue
                filepath.parent.mkdir(parents=True, exist_ok=True)
                filepath.write_bytes(fr.body)

                async with lock:
                    downloaded += 1
                logger.info("[%d] %s → %s (%d B)", downloaded, url, filepath.name, fr.size)

                # 递归提取子链接（复用审计管道的提取逻辑，下载能力不降级）
                if depth >= cfg.scan.max_depth:
                    continue
                kind = fetcher.classify(fr)
                if kind == "html":
                    html = decode(fr.body)
                    external, _ = extract_scripts(html)
                    for src in external:
                        target = resolve_url(fr.final_url, src)
                        if target:
                            await queue.put((target, depth + 1))
                elif kind == "js":
                    text = decode(fr.body)
                    pf = prefilter_js(text, cfg.scan.snippet_context, cfg.scan.llm_snippet_cap)
                    for c in pf.chunk_urls:
                        target = resolve_url(fr.final_url, c)
                        if target:
                            await queue.put((target, depth + 1))
                    if pf.source_map:
                        target = resolve_url(fr.final_url, pf.source_map)
                        if target:
                            await queue.put((target, depth + 1))
            except Exception:
                logger.exception("处理失败 %s", url)
                failed += 1
            finally:
                queue.task_done()

    # 启动并发 worker
    n_workers = cfg.scan.concurrency
    workers = [asyncio.create_task(worker()) for _ in range(n_workers)]

    # 等待队列排空，然后发送退出信号
    await queue.join()
    for _ in range(n_workers):
        await queue.put(("", -1))
    await asyncio.gather(*workers, return_exceptions=True)

    await fetcher.close()
    store.close()

    print(f"\n===== 下载完成 =====")
    print(f"成功：{downloaded}，失败：{failed}，跳过（重复/白名单外/静态资源）：{skipped}")
    print(f"输出目录：{output_dir.resolve()}")
    return 0


def main() -> None:
    args = parse_args()
    if args.download:
        sys.exit(asyncio.run(download_mode(args)))
    sys.exit(asyncio.run(amain(args)))


if __name__ == "__main__":
    main()
