"""前端审计工具 Web UI（标准库实现，无额外依赖）。

启动：
  python webui.py                 # 默认 http://127.0.0.1:8000
  python webui.py -p 9000

DeepSeek API key 仍读 config.yaml / 环境变量 DEEPSEEK_API_KEY，不在 UI 暴露。
浏览器里填授权扫描清单 + 域名白名单、调参、看实时进度与结果、下载报告。
"""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import logging
import threading
import time
import traceback
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from core.auditor import Auditor
from core.config import Config
from core.dedup import Dedup
from core.fetcher import Fetcher
from core.orchestrator import Orchestrator
from core.proxy_pool import ProxyPool
from storage.db import Store
from storage.reporter import write_reports

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"

logger = logging.getLogger("webui")


# ---------- 日志缓冲 ----------
class MemoryHandler(logging.Handler):
    def __init__(self, buf: deque):
        super().__init__()
        self.buf = buf
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))

    def emit(self, record):
        try:
            self.buf.append(self.format(record))
        except Exception:  # noqa: BLE001
            pass


# ---------- 扫描状态 ----------
class ScanState:
    def __init__(self):
        self.scan_id = ""
        self.status = "idle"  # idle|running|cancelling|done|error|cancelled
        self.params: dict = {}
        self.started_monotonic = 0.0
        self.summary: dict = {}
        self.logs: deque = deque(maxlen=400)
        self.findings: list = []
        self.endpoints: list = []
        self.urls: list = []
        self.report_dir: str = ""
        self.error: str = ""
        self.orch: Orchestrator | None = None

    def live_snapshot(self) -> dict:
        # 运行中读 orchestrator 的实时计数器（跨线程读 int 字段，GIL 下安全）
        if self.status in ("running", "cancelling") and self.orch is not None:
            try:
                s = dataclasses.asdict(self.orch.summary)
            except Exception:  # noqa: BLE001
                s = self.summary
        else:
            s = dict(self.summary)
        s["status"] = self.status
        s["scan_id"] = self.scan_id
        s["elapsed"] = int(time.monotonic() - self.started_monotonic) if self.started_monotonic else 0
        s["logs"] = list(self.logs)
        return s


class ScanManager:
    def __init__(self, base_cfg: Config):
        self.base_cfg = base_cfg
        self.state = ScanState()
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self.state.status in ("running", "cancelling")

    def start(self, params: dict) -> dict:
        with self._lock:
            if self.running:
                return {"error": "已有扫描正在运行"}
        state = ScanState()
        state.scan_id = time.strftime("%Y%m%d-%H%M%S")
        state.params = params
        state.status = "running"
        state.started_monotonic = time.monotonic()
        self.state = state
        t = threading.Thread(target=self._run, args=(state, params), daemon=True)
        t.start()
        return {"scan_id": state.scan_id, "status": "running"}

    def cancel(self) -> dict:
        if not self.running:
            return {"status": "idle"}
        if self.state.orch is not None:
            self.state.orch.cancel()
        self.state.status = "cancelling"
        return {"status": "cancelling"}

    # ---------- 扫描线程 ----------
    def _run(self, state: ScanState, params: dict) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._async(state, params))
        except Exception as exc:  # noqa: BLE001
            state.status = "error"
            state.error = repr(exc)
            state.logs.append("FATAL: " + traceback.format_exc())
        finally:
            loop.close()

    async def _async(self, state: ScanState, params: dict) -> None:
        # 基于全局配置深拷贝后用 UI 参数覆盖
        cfg = self.base_cfg.model_copy(deep=True)
        cfg.scan.max_depth = int(params.get("depth", cfg.scan.max_depth))
        cfg.scan.concurrency = int(params.get("concurrency", cfg.scan.concurrency))
        cfg.scan.per_domain_qps = float(params.get("qps", cfg.scan.per_domain_qps))
        cfg.scan.llm_enabled = bool(params.get("llm", True)) and bool(cfg.resolve_api_key())
        cfg.proxy.enabled = bool(params.get("proxy", False))
        cfg.scan.render_mode = str(params.get("render_mode", cfg.scan.render_mode))
        cfg.scope.domains = list(params.get("domains", []))
        # 每次 UI 扫描用全新状态库（独立、可复现；不与 CLI 的 state.db 互相干扰）
        for p in Path(".").glob("state-ui.db*"):
            try:
                p.unlink(missing_ok=True)
            except Exception:  # noqa: BLE001
                pass
        cfg.storage.db_path = "state-ui.db"
        cfg.storage.output_dir = "reports-ui"

        handler = MemoryHandler(state.logs)
        root = logging.getLogger()
        # 运行时也把 httpx 的 INFO 日志收进来（可见请求进度）
        root.setLevel(logging.INFO)
        root.addHandler(handler)

        proxy_pool = ProxyPool(cfg)
        fetcher = Fetcher(cfg, proxy_pool)
        auditor = Auditor(cfg)
        dedup = Dedup()
        store = Store(cfg.storage.db_path)
        orch = Orchestrator(cfg, store, fetcher, auditor, dedup)
        state.orch = orch
        state.logs.append(f"[*] 开始扫描：种子 {len(params.get('seeds', []))} 个，"
                          f"白名单 {cfg.scope.domains}，深度 {cfg.scan.max_depth}，"
                          f"LLM {'开' if cfg.scan.llm_enabled else '关'}，"
                          f"代理 {'开' if cfg.proxy.enabled else '关'}")
        try:
            summary = await orch.run(params.get("seeds", []))
            state.summary = dataclasses.asdict(summary)
            # 物化结果到普通 list（供 HTTP 线程读取，无需再进 asyncio）
            state.findings = await store.all_findings()
            state.endpoints = await store.all_endpoints()
            state.urls = await store.all_urls()
            out = await write_reports(cfg, store, summary)
            state.report_dir = str(out)
            state.status = "cancelled" if orch._cancel else "done"
            state.logs.append(f"[*] 扫描{state.status}：{state.summary.get('findings',0)} 条发现，"
                              f"{state.summary.get('endpoints',0)} 个接口")
        except asyncio.CancelledError:
            state.status = "cancelled"
        finally:
            await fetcher.close()
            await orch.renderer.close()
            store.close()
            logging.getLogger().removeHandler(handler)


MGR: ScanManager | None = None


# ---------- HTTP 处理 ----------
MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".md": "text/markdown; charset=utf-8",
    ".json": "application/json; charset=utf-8",
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静默默认访问日志
        pass

    # ---- 辅助 ----
    def _send(self, body: bytes, content_type: str, code: int = 200,
              attachment: str | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if attachment:
            self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj: dict, code: int = 200) -> None:
        self._send(json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8", code)

    def _serve_file(self, path: Path, content_type: str) -> None:
        if not path.exists() or not path.is_file():
            self._json({"error": "not found"}, 404)
            return
        self._send(path.read_bytes(), content_type)

    # ---- GET ----
    def do_GET(self):  # noqa: N802
        u = urlparse(self.path)
        path = u.path
        if path in ("/", "/index.html"):
            return self._serve_file(WEB / "index.html", MIME[".html"])
        if path.startswith("/web/"):
            name = path[len("/web/"):]
            target = (WEB / name).resolve()
            try:
                target.relative_to(WEB.resolve())
            except ValueError:
                return self._json({"error": "forbidden"}, 403)
            return self._serve_file(target, MIME.get(target.suffix.lower(), "application/octet-stream"))
        if path == "/api/config":
            return self._json(self._config_view())
        if path == "/api/scan/status":
            return self._json(MGR.state.live_snapshot())
        if path == "/api/scan/findings":
            return self._json({"findings": MGR.state.findings})
        if path == "/api/scan/endpoints":
            return self._json({"endpoints": MGR.state.endpoints})
        if path == "/api/scan/urls":
            return self._json({"urls": MGR.state.urls})
        if path == "/api/scan/report":
            fmt = parse_qs(u.query).get("format", ["md"])[0]
            return self._serve_report(fmt)
        return self._json({"error": "not found"}, 404)

    # ---- POST ----
    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            params = json.loads(raw or "{}") if raw else {}
        except json.JSONDecodeError:
            return self._json({"error": "请求体不是合法 JSON"}, 400)

        if path == "/api/scan":
            return self._handle_start(params)
        if path == "/api/scan/cancel":
            return self._json(MGR.cancel())
        return self._json({"error": "not found"}, 404)

    def _handle_start(self, params: dict) -> None:
        seeds_raw = str(params.get("seeds", ""))
        seeds = [s.strip() for s in seeds_raw.splitlines()
                 if s.strip() and not s.strip().startswith("#")]
        seeds = [s for s in seeds if s.startswith(("http://", "https://"))]
        domains_raw = str(params.get("domains", ""))
        domains = [d.strip() for d in domains_raw.split(",") if d.strip()]
        if not seeds:
            return self._json({"error": "授权扫描清单为空或无合法 http(s) URL"}, 400)
        if not domains:
            return self._json({"error": "授权域名白名单为空（安全约束，拒绝运行）"}, 400)
        params["seeds"] = seeds
        params["domains"] = domains
        res = MGR.start(params)
        self._json(res, 200 if "error" not in res else 409)

    def _serve_report(self, fmt: str) -> None:
        if not MGR.state.report_dir:
            return self._json({"error": "尚无报告，请先完成一次扫描"}, 404)
        d = Path(MGR.state.report_dir)
        if fmt == "json":
            f = d / "full.json"
            return self._serve_file(f, MIME[".json"]) if f.exists() else self._json({"error": "报告不存在"}, 404)
        f = d / "report.md"
        return self._serve_file(f, MIME[".md"]) if f.exists() else self._json({"error": "报告不存在"}, 404)

    def _config_view(self) -> dict:
        cfg = MGR.base_cfg
        return {
            "max_depth": cfg.scan.max_depth,
            "concurrency": cfg.scan.concurrency,
            "per_domain_qps": cfg.scan.per_domain_qps,
            "llm_enabled": cfg.scan.llm_enabled,
            "llm_available": bool(cfg.resolve_api_key()),
            "proxy_enabled": cfg.proxy.enabled,
            "render_mode": cfg.scan.render_mode,
        }


def main() -> None:
    global MGR
    ap = argparse.ArgumentParser(description="前端审计工具 Web UI")
    ap.add_argument("-c", "--config", default="config.yaml", help="配置文件（DeepSeek key 等在此）")
    ap.add_argument("-p", "--port", type=int, default=8000, help="监听端口")
    ap.add_argument("--host", default="127.0.0.1", help="监听地址（默认仅本机）")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    base_cfg = Config.load(args.config)
    MGR = ScanManager(base_cfg)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"[*] 前端审计 Web UI 已启动：{url}")
    print(f"[*] DeepSeek: {'已配置' if base_cfg.resolve_api_key() else '未配置（UI 将走纯本地正则模式）'}")
    print("[*] 按 Ctrl+C 停止")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 已停止")


if __name__ == "__main__":
    main()
