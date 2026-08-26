"""配置加载与校验（pydantic 模型 + YAML + 环境变量覆盖）。"""
from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class DeepSeekConfig(BaseModel):
    api_key: str = ""
    base_url: str = "https://api.deepseek.com"
    model: str = "deepseek-v4-flash"
    temperature: float = 0.0
    max_tokens: int = 4096


class ScanConfig(BaseModel):
    concurrency: int = 20
    per_domain_qps: float = 5.0
    timeout: float = 15.0
    retries: int = 2
    max_depth: int = 5
    max_nodes_per_domain: int = 2000
    max_total_nodes: int = 10000
    max_method_probes: int = 3000
    max_asset_kb: int = 2048
    snippet_context: int = 100
    llm_snippet_cap: int = 12000
    llm_enabled: bool = True
    verify_tls: bool = True
    render_enabled: bool = True         # 启用 Playwright 渲染
    render_mode: str = "hybrid"         # off=纯httpx / hybrid=仅SPA空壳启用 / full=全部HTML启用增强渲染
    render_max_clicks: int = 30         # 渲染时最多点击多少个元素触发懒加载
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )
    allowed_content_types: list[str] = Field(
        default_factory=lambda: [
            "text/html",
            "application/xhtml+xml",
            "application/javascript",
            "text/javascript",
            "application/x-javascript",
            "text/ecmascript",
            "application/json",
            "text/json",
            "text/plain",
            "application/octet-stream",
        ]
    )
    excluded_extensions: list[str] = Field(
        default_factory=lambda: [
            ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
            ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".mp4", ".mp3", ".webm", ".zip", ".gz", ".tar",
            ".pdf", ".doc", ".xls",
        ]
    )


class ScopeConfig(BaseModel):
    domains: list[str] = Field(default_factory=list)
    allow_subdomains: bool = True


class ProxyConfig(BaseModel):
    enabled: bool = False
    mode: str = "local"  # local | api
    local_url: str = "http://127.0.0.1:8080"
    api_url: str = ""
    api_key: str = ""
    refresh_seconds: int = 300


class MethodsConfig(BaseModel):
    probe: list[str] = Field(default_factory=lambda: ["OPTIONS", "POST"])
    dangerous_patterns: list[str] = Field(
        default_factory=lambda: [
            "delete", "remove", "upload", "pay", "order",
            "reset", "transfer", "logout", "deactivate",
        ]
    )


class StorageConfig(BaseModel):
    db_path: str = "state.db"
    output_dir: str = "reports"


class Config(BaseModel):
    deepseek: DeepSeekConfig = Field(default_factory=DeepSeekConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    methods: MethodsConfig = Field(default_factory=MethodsConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        path = Path(path)
        data: dict = {}
        if path.exists():
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        cfg = cls.model_validate(data)
        env_key = os.environ.get("DEEPSEEK_API_KEY")
        if env_key:
            cfg.deepseek.api_key = env_key
        return cfg

    def resolve_api_key(self) -> str:
        return self.deepseek.api_key or os.environ.get("DEEPSEEK_API_KEY", "")

    @property
    def api_base(self) -> str:
        base = self.deepseek.base_url.rstrip("/")
        if base.endswith("/v1"):
            return base
        return f"{base}/v1"
