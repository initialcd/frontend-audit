"""三层去重：URL 规范化哈希（跨轮次持久化）、响应内容哈希、接口探测去重。"""
from __future__ import annotations


class Dedup:
    def __init__(self) -> None:
        # URL 级去重：启动时从 SQLite 载入历史，实现断点续跑
        self.seen_urls: set[str] = set()
        # 内容级去重：不同 URL 返回相同 JS 时只审计一次，节省 token
        self.audited_contents: set[str] = set()
        # 接口多方法探测去重（单次运行内）
        self.probed_endpoints: set[str] = set()

    def seen_url(self, h: str) -> bool:
        return h in self.seen_urls

    def mark_url(self, h: str) -> None:
        self.seen_urls.add(h)

    def seen_content(self, h: str) -> bool:
        return h in self.audited_contents

    def mark_content(self, h: str) -> None:
        self.audited_contents.add(h)

    def seen_endpoint(self, h: str) -> bool:
        return h in self.probed_endpoints

    def mark_endpoint(self, h: str) -> None:
        self.probed_endpoints.add(h)
