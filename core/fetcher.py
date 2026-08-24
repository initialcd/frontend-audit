"""HTTP 探测与下载：状态码/Content-Type 预检、大小上限、重试、每域限速。

这里实现的就是"递归阶段的廉价预检"——在消耗 token 之前，
先判断响应是否值得下载和审计（替代独立的 httpx 存活探测流程）。
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from urllib.parse import urlparse

import httpx

from core.config import Config
from core.normalizer import host_of
from core.proxy_pool import ProxyPool

logger = logging.getLogger(__name__)


def _path_of(url: str) -> str:
    try:
        return urlparse(url).path
    except ValueError:
        return ""


@dataclass
class FetchResult:
    url: str
    final_url: str = ""
    status: int = 0
    content_type: str = ""
    size: int = 0
    headers: dict = field(default_factory=dict)
    body: bytes | None = None
    error: str = ""


class RateLimiter:
    """按域名的最小间隔限速（token bucket 简化版）。"""

    def __init__(self, qps: float):
        self.qps = qps
        self._next: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def wait(self, domain: str) -> None:
        if self.qps <= 0:
            return
        loop = asyncio.get_running_loop()
        interval = 1.0 / self.qps
        async with self._lock:
            now = loop.time()
            t = max(now, self._next.get(domain, now))
            self._next[domain] = t + interval
            delay = t - now
        if delay > 0:
            await asyncio.sleep(delay)


class Fetcher:
    def __init__(self, cfg: Config, proxy_pool: ProxyPool):
        self.cfg = cfg.scan
        self.proxy_pool = proxy_pool
        self.limiter = RateLimiter(cfg.scan.per_domain_qps)
        self.client = httpx.AsyncClient(
            timeout=cfg.scan.timeout,
            follow_redirects=True,
            verify=cfg.scan.verify_tls,
            headers={
                "User-Agent": cfg.scan.user_agent,
                "Accept": (
                    "text/html,application/xhtml+xml,application/javascript,"
                    "application/json,*/*;q=0.8"
                ),
            },
            limits=httpx.Limits(max_connections=cfg.scan.concurrency * 2),
        )

    async def close(self) -> None:
        await self.client.aclose()

    @staticmethod
    def content_type_of(url: str, headers: dict) -> str:
        """Content-Type 归一化 + 后缀嗅探（部分服务器把 .js 发成 text/plain）。"""
        ct = headers.get("content-type", "").split(";")[0].strip().lower()
        if ct in ("", "text/plain", "application/octet-stream"):
            suffix = PurePosixPath(_path_of(url)).suffix.lower()
            if suffix in (".js", ".mjs"):
                return "application/javascript"
            if suffix in (".html", ".htm"):
                return "text/html"
            if suffix == ".json":
                return "application/json"
        return ct

    async def fetch(self, url: str) -> FetchResult:
        domain = host_of(url) or url
        for attempt in range(self.cfg.retries + 1):
            if attempt:
                await asyncio.sleep(min(2 ** attempt, 8))
            await self.limiter.wait(domain)
            options = await self.proxy_pool.options()
            try:
                result = await self._once(url, options)
                if result.status == 0:
                    await self.proxy_pool.report_failure()
                    continue
                return result
            except Exception as exc:  # noqa: BLE001
                logger.debug("请求失败 %s（第 %d 次）：%s", url, attempt + 1, exc)
                await self.proxy_pool.report_failure()
        return FetchResult(url=url, error="max retries exceeded")

    async def _once(self, url: str, options: dict) -> FetchResult:
        limit = self.cfg.max_asset_kb * 1024
        async with self.client.stream("GET", url, **options) as resp:
            fr = FetchResult(
                url=url,
                final_url=str(resp.url),
                status=resp.status_code,
                content_type=self.content_type_of(url, dict(resp.headers)),
                headers=dict(resp.headers),
            )
            # 非 2xx/3xx：只记录状态，不读响应体
            if not (200 <= resp.status_code < 400):
                return fr
            # Content-Type 不允许：只记录元信息，不下载（省流量省 token）
            if fr.content_type not in self.cfg.allowed_content_types:
                return fr
            chunks: list[bytes] = []
            size = 0
            overflow = False
            async for chunk in resp.aiter_bytes():
                size += len(chunk)
                if size > limit:
                    overflow = True
                    break
                chunks.append(chunk)
            if overflow:
                fr.error = f"size exceeds {self.cfg.max_asset_kb}KB"
                return fr
            fr.body = b"".join(chunks)
            fr.size = size
            return fr

    def classify(self, fr: FetchResult) -> str:
        """把响应分成 html / js / json / text / empty / other，决定后续管道。"""
        if not fr.body:
            return "empty"
        ct = fr.content_type
        if ct in ("text/html", "application/xhtml+xml"):
            return "html"
        if "javascript" in ct or "ecmascript" in ct:
            return "js"
        if ct in ("application/json", "text/json"):
            return "json"
        if ct in ("text/plain", "application/octet-stream"):
            return "text"
        return "other"
