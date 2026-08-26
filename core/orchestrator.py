"""BFS 递归调度器：种子 → 预检 → 预处理 → LLM 审计 → 接口探测 → 递归。

边界控制：
- 深度上限（种子为 0，子节点 +1，超过不再入队）；
- 每域节点数上限 + 全局节点数上限；
- 严格域名白名单（递归永远出不了白名单）；
- URL 规范化哈希去重（跨轮次持久化，断点续跑）+ 响应内容哈希去重（省 token）。
"""
from __future__ import annotations

import asyncio
import logging
from collections import Counter
from dataclasses import dataclass

from core.auditor import Auditor
from core.config import Config
from core.dedup import Dedup
from core.fetcher import Fetcher
from core.method_prober import MethodProber
from core.normalizer import (
    content_hash,
    host_of,
    is_in_scope,
    is_static_asset,
    normalize_url,
    resolve_url,
    url_hash,
)
from core.prefilter import (
    PrefilterResult,
    decode,
    extract_scripts,
    prefilter_js,
    prefilter_text,
)
from core.renderer import Renderer, is_spa_shell
from storage.db import Store

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Summary:
    total_nodes: int = 0
    discovered: int = 0
    pending: int = 0
    fetched: int = 0
    html: int = 0
    js: int = 0
    json: int = 0
    findings: int = 0
    endpoints: int = 0
    llm_calls: int = 0
    llm_failures: int = 0
    rendered: int = 0
    render_failures: int = 0
    render_js_urls: int = 0
    render_route_count: int = 0
    skipped_scope: int = 0
    skipped_dup: int = 0
    skipped_budget: int = 0


class Orchestrator:
    def __init__(self, cfg: Config, store: Store, fetcher: Fetcher, auditor: Auditor, dedup: Dedup):
        self.cfg = cfg
        self.store = store
        self.fetcher = fetcher
        self.auditor = auditor
        self.dedup = dedup
        self.method_prober = MethodProber(cfg, fetcher.proxy_pool, fetcher.client)
        self.renderer = Renderer(cfg)
        self.summary = Summary()
        self.queue: asyncio.Queue[tuple[str, int, str]] = asyncio.Queue()
        self.per_domain: Counter[str] = Counter()
        self._cancel = False
        self._paused = False
        self._pause_event = asyncio.Event()
        self._pause_event.set()
        self._concurrency = cfg.scan.concurrency
        self._workers: list[asyncio.Task] = []
        self._worker_seq = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._finished = False

    # ---------- 暂停 / 恢复 / 动态调参（线程安全，均派发到事件循环） ----------
    def cancel(self) -> bool:
        """请求取消：置标志并排空队列（派发到事件循环执行，线程安全）。"""
        self._cancel = True
        return self._schedule(self._do_cancel)

    def pause(self) -> bool:
        """暂停：worker 处理完当前节点后挂起，队列与进度全部保留。"""
        return self._schedule(self._do_pause)

    def resume(self) -> bool:
        """恢复暂停的扫描，从断点继续，无需重跑。"""
        return self._schedule(self._do_resume)

    def set_concurrency(self, n: int) -> bool:
        """运行时调整并发：新增/缩减 worker（缩减时 worker 处理完当前节点再退出）。"""
        n = max(1, min(n, 500))
        self._concurrency = n
        self.cfg.scan.concurrency = n
        return self._schedule(self._sync_workers)

    def set_max_depth(self, n: int) -> bool:
        """运行时调整递归深度上限（各处深度判断均为实时读取，立即生效）。"""
        self.cfg.scan.max_depth = max(0, n)
        return True

    def set_qps(self, q: float) -> bool:
        """运行时调整每域 QPS 限速。"""
        q = max(0.0, q)
        self.cfg.scan.per_domain_qps = q
        limiter = getattr(self.fetcher, "limiter", None)
        if limiter is not None:
            limiter.qps = q
        return True

    async def _do_cancel(self) -> None:
        self._cancel = True
        self._pause_event.set()  # 唤醒暂停中的 worker，让其看到取消标志后退出
        self._drain_queue()

    async def _do_pause(self) -> None:
        self._paused = True
        self._pause_event.clear()

    async def _do_resume(self) -> None:
        self._paused = False
        self._pause_event.set()

    def _schedule(self, make_coro) -> bool:
        """把协程派发到扫描事件循环。传入工厂函数，仅在确实要调度时才创建协程。"""
        loop = self._loop
        if loop is None or loop.is_closed() or self._finished:
            return False
        try:
            current = asyncio.get_running_loop()
        except RuntimeError:
            current = None
        coro = make_coro()
        if current is loop:
            asyncio.create_task(coro)
        else:
            asyncio.run_coroutine_threadsafe(coro, loop)
        return True

    def _drain_queue(self) -> None:
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            self.queue.task_done()
            self.summary.pending -= 1

    @property
    def paused(self) -> bool:
        return self._paused

    @property
    def concurrency(self) -> int:
        return self._concurrency

    @property
    def max_depth(self) -> int:
        return self.cfg.scan.max_depth

    async def _sync_workers(self) -> None:
        """按当前并发目标增/减 worker 数量。"""
        if self._finished:
            return
        # 清理已退出的 worker（缩减并发后它们会自行退出）
        self._workers = [w for w in self._workers if not w.done()]
        while len(self._workers) < self._concurrency:
            wid = self._worker_seq
            self._worker_seq += 1
            self._workers.append(asyncio.create_task(self._worker(wid)))

    # ---------- 入口 ----------
    async def run(self, seeds: list[str]) -> Summary:
        self._loop = asyncio.get_running_loop()
        self._finished = False
        self._cancel = False
        self._paused = False
        self._pause_event.set()
        self._workers = []
        seen = await self.store.load_seen_urls()
        self.dedup.seen_urls |= seen
        if seen:
            logger.info("断点续跑：已加载 %d 条历史 URL 记录", len(seen))
        for seed in seeds:
            if "://" not in seed:
                logger.warning("忽略非法种子：%s", seed)
                continue
            if not is_in_scope(seed, self.cfg.scope.domains, self.cfg.scope.allow_subdomains):
                self.summary.skipped_scope += 1
                logger.warning("种子不在白名单内，跳过：%s", seed)
                continue
            await self._enqueue(seed, 0, "seed")
        if self.queue.empty():
            logger.warning("队列为空，没有可扫描的目标")
            self._finished = True
            return self.summary
        await self._sync_workers()
        # 等待队列排空；暂停时 worker 挂起在 _pause_event，join 持续等待属正常。
        # 支持中途取消：cancel 会排空队列并唤醒暂停 worker。
        while True:
            try:
                await asyncio.wait_for(self.queue.join(), timeout=0.5)
                break
            except asyncio.TimeoutError:
                if self._cancel:
                    self._drain_queue()
                    break
        # 结束：先置完成标志，阻止后续动态调参再派生 worker
        self._finished = True
        for w in self._workers:
            w.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        return self.summary

    async def _enqueue(self, url: str, depth: int, source: str) -> bool:
        """入队（depth 为入队节点自身深度）。返回是否入队。"""
        canonical = normalize_url(url)
        if is_static_asset(canonical, self.cfg.scan.excluded_extensions):
            return False
        if not is_in_scope(canonical, self.cfg.scope.domains, self.cfg.scope.allow_subdomains):
            return False
        h = url_hash(canonical)
        if self.dedup.seen_url(h):
            self.summary.skipped_dup += 1
            return False
        self.dedup.mark_url(h)
        await self.queue.put((canonical, depth, source))
        self.summary.discovered += 1
        self.summary.pending += 1
        return True

    async def _worker(self, wid: int) -> None:
        while True:
            if self._cancel or wid >= self._concurrency:
                return
            await self._pause_event.wait()
            if self._cancel or wid >= self._concurrency:
                return
            url, depth, source = await self.queue.get()
            try:
                await self._process(url, depth, source)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.exception("处理失败 %s：%s", url, exc)
            finally:
                self.queue.task_done()
                self.summary.pending -= 1

    # ---------- 单节点处理 ----------
    async def _process(self, url: str, depth: int, source: str) -> None:
        domain = host_of(url)
        if self.summary.total_nodes >= self.cfg.scan.max_total_nodes:
            self.summary.skipped_budget += 1
            return
        if self.per_domain[domain] >= self.cfg.scan.max_nodes_per_domain:
            self.summary.skipped_budget += 1
            return
        self.summary.total_nodes += 1
        self.per_domain[domain] += 1

        fr = await self.fetcher.fetch(url)
        kind = self.fetcher.classify(fr)
        ch = content_hash(fr.body) if fr.body else ""
        await self.store.save_url({
            "url_hash": url_hash(url), "url": url, "final_url": fr.final_url,
            "status": fr.status, "content_type": fr.content_type, "size": fr.size,
            "depth": depth, "kind": kind, "source": source, "content_hash": ch,
        })
        if fr.status == 0 or fr.body is None:
            return
        self.summary.fetched += 1

        if kind == "html":
            self.summary.html += 1
            await self._handle_html(fr, depth)
        elif kind == "js":
            self.summary.js += 1
            await self._handle_js(fr, depth)
        elif kind == "json":
            self.summary.json += 1
            await self._handle_json(fr, depth)

    # ---------- 分类处理 ----------
    async def _handle_html(self, fr, depth: int) -> None:
        html = decode(fr.body)
        external, inline = extract_scripts(html)
        for src in external:
            if depth + 1 > self.cfg.scan.max_depth:
                continue
            target = resolve_url(fr.final_url, src)
            if target:
                await self._enqueue(target, depth + 1, fr.url)
        for code in inline:
            pf = prefilter_text(code, self.cfg.scan.snippet_context, self.cfg.scan.llm_snippet_cap)
            await self._record_local(fr.url, pf, depth)

        # 增强渲染（三种模式）
        render_mode = getattr(self.cfg.scan, "render_mode", "hybrid")
        if not self.cfg.scan.render_enabled or render_mode == "off":
            return
        if depth >= self.cfg.scan.max_depth:
            return
        if not self.renderer.available():
            return

        should_render = False
        if render_mode == "full":
            # 对所有 HTML 页面启用增强渲染（覆盖率最高）
            should_render = True
        elif render_mode == "hybrid":
            # 仅对 SPA 空壳启用（默认，平衡覆盖率和速度）
            should_render = is_spa_shell(html, external)

        if should_render:
            logger.info("增强渲染 %s（模式：%s）：%s", render_mode, "SPA空壳" if render_mode == "hybrid" else "全量", fr.url)
            self.summary.rendered += 1
            rr = await self.renderer.render_and_collect(
                fr.final_url, max_clicks=self.cfg.scan.render_max_clicks
            )
            if rr.error and not rr.js_urls:
                self.summary.render_failures += 1
                logger.warning("渲染失败：%s", rr.error)
            # 记录 CDP 拦截到的 JS URL
            self.summary.render_js_urls += len(rr.js_urls)
            for js_url in rr.js_urls:
                if depth + 1 <= self.cfg.scan.max_depth:
                    await self._enqueue(js_url, depth + 1, f"cdp:{fr.url}")
            # 记录 Hook 捕获的动态代码执行
            self.summary.render_route_count += len(rr.routes)
            for hf in rr.hook_findings:
                htype = hf.get("type", "unknown")
                code = hf.get("code", "") or hf.get("src", "") or hf.get("url", "")
                if code:
                    await self._record_finding(
                        fr.url, f"hook_{htype}", "low", str(code)[:512], "", 0.3,
                        f"JS Hook 捕获：{htype}"
                    )

    async def _handle_js(self, fr, depth: int) -> None:
        text = decode(fr.body)
        pf = prefilter_js(text, self.cfg.scan.snippet_context, self.cfg.scan.llm_snippet_cap)

        # sourcemap：记录泄露 + 尝试抓取（.map 内容本身有价值）
        if pf.source_map:
            await self._record_finding(fr.url, "sourcemap", "low", pf.source_map, "", 0.9,
                                       "JS 暴露 sourceMappingURL，可还原原始源码")
            if depth + 1 <= self.cfg.scan.max_depth:
                target = resolve_url(fr.final_url, pf.source_map)
                if target:
                    await self._enqueue(target, depth + 1, fr.url)
        # chunk / 动态加载脚本
        for c in pf.chunk_urls:
            if depth + 1 > self.cfg.scan.max_depth:
                break
            target = resolve_url(fr.final_url, c)
            if target:
                await self._enqueue(target, depth + 1, fr.url)

        await self._record_local(fr.url, pf, depth)

        # LLM 审计（内容级去重：不同 URL 返回相同 JS 只审计一次）
        if pf.snippets and self.cfg.scan.llm_enabled and self.auditor.available():
            ch = content_hash(fr.body)
            if self.dedup.seen_content(ch):
                logger.debug("内容重复，跳过 LLM：%s", fr.url)
                return
            self.dedup.mark_content(ch)
            self.summary.llm_calls += 1
            result = await self.auditor.audit(fr.url, pf.snippets)
            if result is None:
                self.summary.llm_failures += 1
                return
            await self._record_llm(fr.url, result, depth)

    async def _handle_json(self, fr, depth: int) -> None:
        # JSON 不做代码审计，只做零成本本地扫描 + 接口记录
        text = decode(fr.body)
        pf = prefilter_text(text, self.cfg.scan.snippet_context, self.cfg.scan.llm_snippet_cap)
        await self._record_local(fr.url, pf, depth)

    # ---------- 结果记录与递归 ----------
    async def _record_local(self, source: str, pf: PrefilterResult, depth: int) -> None:
        for f in pf.findings:
            await self._record_finding(source, f.ftype, f.severity, f.value,
                                       f.context, f.confidence, f.reason)
        for p in pf.api_paths:
            await self._handle_endpoint(source, p, depth)

    async def _record_llm(self, source: str, result, depth: int) -> None:
        for f in result.findings:
            severity = f.severity.lower()
            if severity not in SEVERITY_RANK:
                severity = "medium"
            await self._record_finding(source, f.type, severity, f.value,
                                       f.context, f.confidence, f.reason)
        for e in result.endpoints:
            await self._handle_endpoint(source, e.path, depth)

    async def _record_finding(self, source: str, ftype: str, severity: str, value: str,
                              context: str, confidence: float, reason: str = "") -> None:
        if severity not in SEVERITY_RANK:
            severity = "medium"
        self.summary.findings += 1
        await self.store.save_finding({
            "source_url": source, "ftype": ftype, "severity": severity,
            "value": (value or "")[:512], "context": (context or "")[:1000],
            "confidence": confidence, "reason": (reason or "")[:300],
        })

    async def _handle_endpoint(self, source: str, path: str, depth: int) -> None:
        target = resolve_url(source, path)
        if not target:
            return
        canonical = normalize_url(target)
        if not is_in_scope(canonical, self.cfg.scope.domains, self.cfg.scope.allow_subdomains):
            return
        ep_hash = url_hash(canonical)
        # 1) 多方法探测（OPTIONS/POST；GET 状态由抓取阶段记录）
        if not self.dedup.seen_endpoint(ep_hash):
            self.dedup.mark_endpoint(ep_hash)
            results = await self.method_prober.probe(canonical)
            for r in results:
                await self.store.save_endpoint({
                    "ep_hash": ep_hash, "method": r.method, "url": canonical,
                    "source": source, "status": r.status, "allow": r.allow, "cors": r.cors,
                })
            self.summary.endpoints += 1
        # 2) 递归抓取该路径（返回 HTML/JS 则继续审计）
        if depth + 1 <= self.cfg.scan.max_depth:
            await self._enqueue(canonical, depth + 1, source)
