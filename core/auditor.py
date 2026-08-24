"""DeepSeek 审计客户端：JSON 结构化输出 + 容错解析 + 重试。"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path

import httpx
from pydantic import BaseModel, Field

from core.config import Config

logger = logging.getLogger(__name__)


class Finding(BaseModel):
    type: str = "other"
    severity: str = "medium"
    value: str = ""
    context: str = ""
    confidence: float = 0.5
    reason: str = ""


class Endpoint(BaseModel):
    path: str
    method: str = "GET"
    params: list[str] = Field(default_factory=list)
    confidence: float = 0.5
    note: str = ""


class AuditResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)


def _coerce(data: dict) -> AuditResult:
    """逐条容错：单条不合法只丢弃该条，不让整个结果作废。"""
    findings: list[Finding] = []
    for item in data.get("findings") or []:
        try:
            findings.append(Finding.model_validate(item))
        except Exception:  # noqa: BLE001
            continue
    endpoints: list[Endpoint] = []
    for item in data.get("endpoints") or []:
        if isinstance(item, str):
            item = {"path": item}
        try:
            endpoints.append(Endpoint.model_validate(item))
        except Exception:  # noqa: BLE001
            continue
    return AuditResult(findings=findings, endpoints=endpoints)


class Auditor:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.api_key = cfg.resolve_api_key()
        self._prompt = self._load_prompt()

    def _load_prompt(self) -> str:
        path = Path(__file__).resolve().parent.parent / "prompts" / "audit.md"
        if path.exists():
            return path.read_text(encoding="utf-8")
        return "你是一名前端安全审计专家。"

    def available(self) -> bool:
        return bool(self.api_key)

    def _url(self) -> str:
        return f"{self.cfg.api_base}/chat/completions"

    async def audit(self, url: str, snippets: str) -> AuditResult | None:
        if not snippets.strip() or not self.api_key:
            return None
        payload = {
            "model": self.cfg.deepseek.model,
            "temperature": self.cfg.deepseek.temperature,
            "max_tokens": self.cfg.deepseek.max_tokens,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": self._prompt},
                {"role": "user", "content": f"来源文件：{url}\n\n待审计片段：\n{snippets}"},
            ],
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        last_error = ""
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=120) as client:
                    resp = await client.post(self._url(), json=payload, headers=headers)
                if resp.status_code == 429:
                    await asyncio.sleep(min(10 * (attempt + 1), 30))
                    continue
                if resp.status_code >= 500:
                    await asyncio.sleep(3)
                    continue
                if resp.status_code != 200:
                    last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
                    break
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                obj = json.loads(_strip_fences(content))
                return _coerce(obj)
            except (httpx.HTTPError, json.JSONDecodeError, KeyError, ValueError) as exc:
                last_error = str(exc)
                await asyncio.sleep(2)
        logger.warning("LLM 审计失败 %s：%s", url, last_error)
        return None


def _strip_fences(content: str) -> str:
    content = content.strip()
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
    return content
