"""代理池适配器（tscan/TscanPlus 等）。

- local 模式：所有流量走固定本地 HTTP 代理端口（如 TscanPlus 代理池入口）。
- api 模式：定时从代理池 API 拉取代理列表并轮询使用，请求失败自动切换。
"""
from __future__ import annotations

import asyncio
import logging
import time

import httpx

from core.config import Config

logger = logging.getLogger(__name__)


class ProxyPool:
    def __init__(self, cfg: Config):
        self.cfg = cfg.proxy
        self._proxies: list[str] = []
        self._idx = 0
        self._last_refresh = 0.0
        self._lock = asyncio.Lock()

    def enabled(self) -> bool:
        return self.cfg.enabled

    async def _refresh(self) -> None:
        if not self.cfg.api_url:
            return
        now = time.monotonic()
        if now - self._last_refresh < self.cfg.refresh_seconds:
            return
        headers = {"Authorization": self.cfg.api_key} if self.cfg.api_key else {}
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(self.cfg.api_url, headers=headers)
                data = resp.json()
            items = data.get("data", data) if isinstance(data, dict) else data
            fresh = [str(p) for p in items if p]
            if fresh:
                self._proxies = fresh
                self._idx = 0
                self._last_refresh = now
                logger.info("代理池刷新：%d 个代理", len(fresh))
        except Exception as exc:  # noqa: BLE001
            logger.warning("代理池刷新失败：%s", exc)

    async def options(self) -> dict:
        """返回传给 httpx 单次请求的参数（含 proxies）。"""
        if not self.cfg.enabled:
            return {}
        if self.cfg.mode == "local":
            return {"proxies": self.cfg.local_url}
        await self._refresh()
        async with self._lock:
            if not self._proxies:
                return {}
            proxy = self._proxies[self._idx % len(self._proxies)]
            self._idx += 1
        return {"proxies": proxy}

    async def report_failure(self) -> None:
        """请求失败时立即切换到下一个代理（api 模式）。"""
        if self.cfg.mode != "api":
            return
        async with self._lock:
            if self._proxies:
                self._idx += 1
