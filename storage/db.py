"""SQLite 持久化：URL 状态、接口探测结果、审计发现，支持断点续跑。

所有写操作经 asyncio.to_thread + 锁串行化，避免阻塞事件循环。
"""
from __future__ import annotations

import asyncio
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS urls (
    url_hash TEXT PRIMARY KEY,
    url TEXT, final_url TEXT, status INTEGER, content_type TEXT,
    size INTEGER, depth INTEGER, kind TEXT, source TEXT,
    content_hash TEXT, probed_at TEXT
);
CREATE TABLE IF NOT EXISTS endpoints (
    ep_hash TEXT, method TEXT, url TEXT, source TEXT, status INTEGER,
    allow TEXT, cors TEXT, probed_at TEXT,
    PRIMARY KEY (ep_hash, method)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_url TEXT, ftype TEXT, severity TEXT, value TEXT,
    context TEXT, confidence REAL, reason TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_endpoints_url ON endpoints(url);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self._lock = asyncio.Lock()

    async def _run(self, fn, *args):
        async with self._lock:
            return await asyncio.to_thread(fn, *args)

    # ---------- urls ----------
    def _insert_url(self, row: dict) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO urls VALUES "
                "(:url_hash,:url,:final_url,:status,:content_type,:size,:depth,:kind,:source,:content_hash,:probed_at)",
                row,
            )

    async def save_url(self, row: dict) -> None:
        row.setdefault("probed_at", now_iso())
        await self._run(self._insert_url, row)

    def _load_seen_urls(self) -> set[str]:
        cur = self.conn.execute("SELECT url_hash FROM urls")
        return {r[0] for r in cur.fetchall()}

    async def load_seen_urls(self) -> set[str]:
        return await self._run(self._load_seen_urls)

    def _load_seen_content_hashes(self) -> set[str]:
        cur = self.conn.execute(
            "SELECT DISTINCT content_hash FROM urls WHERE content_hash IS NOT NULL AND content_hash != ''"
        )
        return {r[0] for r in cur.fetchall()}

    async def load_seen_content_hashes(self) -> set[str]:
        return await self._run(self._load_seen_content_hashes)

    # ---------- endpoints ----------
    def _insert_endpoint(self, row: dict) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO endpoints VALUES "
                "(:ep_hash,:method,:url,:source,:status,:allow,:cors,:probed_at)",
                row,
            )

    async def save_endpoint(self, row: dict) -> None:
        row.setdefault("probed_at", now_iso())
        await self._run(self._insert_endpoint, row)

    # ---------- findings ----------
    def _insert_finding(self, row: dict) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO findings "
                "(source_url,ftype,severity,value,context,confidence,reason,created_at) "
                "VALUES (:source_url,:ftype,:severity,:value,:context,:confidence,:reason,:created_at)",
                row,
            )

    async def save_finding(self, row: dict) -> None:
        row.setdefault("created_at", now_iso())
        await self._run(self._insert_finding, row)

    # ---------- 读取 ----------
    def _fetch_rows(self, sql: str, params: tuple = ()) -> list[dict]:
        cur = self.conn.execute(sql, params)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    async def all_findings(self) -> list[dict]:
        sql = (
            "SELECT * FROM findings ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 ELSE 3 END, id"
        )
        return await self._run(self._fetch_rows, sql)

    async def all_endpoints(self) -> list[dict]:
        return await self._run(self._fetch_rows, "SELECT * FROM endpoints ORDER BY url, method")

    async def all_urls(self) -> list[dict]:
        return await self._run(self._fetch_rows, "SELECT * FROM urls ORDER BY probed_at")

    async def stats(self) -> dict:
        def _s() -> dict:
            return {
                "urls": self.conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0],
                "endpoints": self.conn.execute("SELECT COUNT(DISTINCT ep_hash) FROM endpoints").fetchone()[0],
                "findings": self.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            }

        return await self._run(_s)

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:  # noqa: BLE001
            pass
