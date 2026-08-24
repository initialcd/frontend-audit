"""接口多方法探测：OPTIONS / POST（GET 状态由抓取阶段记录）。

安全策略：POST 空 body、不跟随重定向、命中危险词（delete/upload/pay...）的路径跳过。
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import httpx

from core.config import Config
from core.proxy_pool import ProxyPool

logger = logging.getLogger(__name__)


@dataclass
class MethodResult:
    url: str
    method: str
    status: int
    allow: str = ""
    cors: str = ""


class MethodProber:
    def __init__(self, cfg: Config, proxy_pool: ProxyPool, client: httpx.AsyncClient):
        self.cfg = cfg
        self.proxy_pool = proxy_pool
        self.client = client
        self.sem = asyncio.Semaphore(max(4, cfg.scan.concurrency // 2))
        self.count = 0

    def dangerous(self, url: str) -> bool:
        path = url.lower()
        return any(p in path for p in self.cfg.methods.dangerous_patterns)

    async def probe(self, url: str) -> list[MethodResult]:
        results: list[MethodResult] = []
        for method in self.cfg.methods.probe:
            if method.upper() == "POST" and self.dangerous(url):
                logger.debug("跳过危险路径的 POST：%s", url)
                continue
            async with self.sem:
                if self.count >= self.cfg.scan.max_method_probes:
                    return results
                self.count += 1
                options = await self.proxy_pool.options()
                try:
                    resp = await self.client.request(
                        method.upper(), url, content=b"", follow_redirects=False, **options
                    )
                    status = resp.status_code
                    headers = dict(resp.headers)
                    await resp.aclose()
                except Exception as exc:  # noqa: BLE001
                    logger.debug("探测 %s %s 失败：%s", method, url, exc)
                    continue
            results.append(MethodResult(
                url=url,
                method=method.upper(),
                status=status,
                allow=headers.get("allow", ""),
                cors=headers.get("access-control-allow-origin", ""),
            ))
        return results
