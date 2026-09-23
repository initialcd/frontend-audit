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
import sys
import threading
import time
import traceback
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from core.auditor import Auditor
from core.config import Config
from core.dedup import Dedup
from core.fetcher import Fetcher
from core.normalizer import expand_seed, is_in_scope, normalize_url, parse_domains
from core.orchestrator import Orchestrator
from core.proxy_pool import ProxyPool
from core.renderer import Renderer
from storage.db import Store
from storage.reporter import write_reports

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"

logger = logging.getLogger("webui")


# ---------- 日志缓冲 ----------
class MemoryHandler(logging.Handler):
    """按线程收集日志：每个任务跑在独立线程，只收本线程的记录。

    否则旧任务被放弃后仍在收尾，它的日志会串进新任务的日志面板。
    """

    def __init__(self, buf: deque, thread_id: int | None = None):
        super().__init__()
        self.buf = buf
        self.thread_id = thread_id
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))

    def emit(self, record):
        if self.thread_id is not None and record.thread != self.thread_id:
            return
        try:
            self.buf.append(self.format(record))
        except Exception:  # noqa: BLE001
            pass


# ---------- 扫描状态 ----------
ACTIVE_STATUSES = ("running", "paused", "cancelling")


class ScanState:
    def __init__(self, scan_id: str = "", mode: str = "audit"):
        self.scan_id = scan_id
        self.status = "idle"  # idle|running|paused|cancelling|done|error|cancelled|abandoned
        self.params: dict = {}
        self.mode = mode       # audit | download
        self.started_monotonic = 0.0
        self.summary: dict = {}
        self.logs: deque = deque(maxlen=400)
        self.findings: list = []
        self.endpoints: list = []
        self.urls: list = []
        self.files: list = []          # 下载模式：已落盘文件清单
        self.report_dir: str = ""
        self.download_dir: str = ""    # 下载模式：输出目录绝对路径
        self.db_path: str = ""         # 本任务独占的状态库（任务间不共享，重开即全新）
        self.error: str = ""
        self.orch: Orchestrator | None = None
        self.thread: threading.Thread | None = None
        # 取消请求：在 orch 尚未建好（线程启动窗口）时也能被 _async 读到并立即执行
        self.cancel_requested = False
        self.cancel_requested_at = 0.0
        # 被"强制复位"放弃：其线程继续自行收尾，但已不是当前任务，前端不再读它
        self.abandoned = False

    def live_snapshot(self) -> dict:
        # 运行中读 orchestrator 的实时计数器（跨线程读 int 字段，GIL 下安全）
        if self.status in ACTIVE_STATUSES and self.orch is not None:
            try:
                s = dataclasses.asdict(self.orch.summary)
            except Exception:  # noqa: BLE001
                s = self.summary
            try:
                s["paused"] = bool(self.orch.paused)
                s["concurrency"] = int(self.orch.concurrency)
                s["max_depth"] = int(self.orch.max_depth)
            except Exception:  # noqa: BLE001
                pass
        else:
            s = dict(self.summary)
            s["paused"] = self.status == "paused"
            s["concurrency"] = int(self.params.get("concurrency", 0) or 0)
            s["max_depth"] = int(self.params.get("depth", 0) or 0)
        s.setdefault("discovered", 0)
        s.setdefault("pending", 0)
        s.setdefault("downloaded", 0)
        s.setdefault("download_failed", 0)
        done = int(s.get("total_nodes", 0) or 0)
        queued = int(s.get("pending", 0) or 0)
        known = done + queued
        if self.status == "done":
            s["progress"] = 100.0
        elif known > 0:
            s["progress"] = round(done / known * 100.0, 1)
        else:
            s["progress"] = 0.0
        s["status"] = self.status
        s["scan_id"] = self.scan_id
        s["mode"] = self.mode
        s["download_dir"] = self.download_dir
        s["report_dir"] = self.report_dir
        s["cancel_requested"] = self.cancel_requested
        s["abandoned"] = self.abandoned
        s["cancelling_seconds"] = (
            round(time.monotonic() - self.cancel_requested_at, 1)
            if self.status == "cancelling" and self.cancel_requested_at else 0
        )
        s["elapsed"] = int(time.monotonic() - self.started_monotonic) if self.started_monotonic else 0
        s["logs"] = list(self.logs)
        return s


class ScanManager:
    def __init__(self, base_cfg: Config):
        self.base_cfg = base_cfg
        self.state = ScanState()
        self.archived: list[dict] = []   # 被放弃任务的摘要（仅保留最近几条）
        self._lock = threading.RLock()

    @property
    def running(self) -> bool:
        return self.state.status in ACTIVE_STATUSES

    @property
    def can_start(self) -> bool:
        return self.state.status not in ACTIVE_STATUSES

    def start(self, params: dict, force: bool = False) -> dict:
        with self._lock:
            if self.running:
                if not force:
                    return {"error": "已有任务在运行：请先「取消」，或点「放弃并重开」"}
                # 抢占：放弃旧任务（其线程自行收尾，产物保留），再开新任务
                self._abandon_locked("被新任务抢占")
            self._cleanup_orphan_dbs_locked()
            state = ScanState()
            state.scan_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
            state.params = params
            state.mode = "download" if params.get("mode") == "download" else "audit"
            state.status = "running"
            state.started_monotonic = time.monotonic()
            self.state = state
            t = threading.Thread(target=self._run, args=(state, params), daemon=True)
            state.thread = t
            t.start()
            return {"scan_id": state.scan_id, "status": "running", "mode": state.mode}

    def cancel(self) -> dict:
        """请求取消当前任务：中断在飞请求，秒级停下，进度与已入库结果全部保留。"""
        with self._lock:
            st = self.state
            if st.status not in ACTIVE_STATUSES and not st.cancel_requested:
                return {"status": st.status}
            st.cancel_requested = True
            st.cancel_requested_at = time.monotonic()
            st.status = "cancelling"
            st.logs.append("[*] 已请求取消：正在中断在飞请求与任务队列…")
            orch = st.orch
        # 锁外调用：orch.cancel 会派发到扫描事件循环，不在这里阻塞 HTTP 线程
        if orch is not None:
            orch.cancel(force=True)
        return {"status": "cancelling", "scan_id": st.scan_id}

    def abandon(self) -> dict:
        """强制复位：不等旧任务收尾，立刻把当前状态换回 idle，可以马上重开。

        旧线程继续在后台把产物写完（各自独立的库/目录，互不干扰），
        只是不再是"当前任务"。
        """
        with self._lock:
            if self.state.status not in ACTIVE_STATUSES:
                return {"status": self.state.status, "can_start": True}
            old = self._abandon_locked("用户强制复位")
        return {"status": "idle", "abandoned": old.scan_id, "can_start": True}

    def _abandon_locked(self, reason: str) -> ScanState:
        """标记旧任务被放弃并归档，切换到全新的空闲状态（调用方需持锁）。"""
        st = self.state
        st.abandoned = True
        st.cancel_requested = True
        if st.status in ACTIVE_STATUSES:
            st.status = "abandoned"
        st.logs.append(f"[!] 任务被放弃（{reason}）：后台线程自行收尾，"
                       f"已抓取的数据与报告保留在 reports-ui/{st.scan_id}/")
        st.cancel_requested_at = st.cancel_requested_at or time.monotonic()
        self.archived.append({
            "scan_id": st.scan_id,
            "mode": st.mode,
            "reason": reason,
            "report_dir": st.report_dir,
            "download_dir": st.download_dir,
        })
        self.archived = self.archived[-5:]
        self.state = ScanState()
        if st.orch is not None:
            st.orch.cancel(force=True)
        return st

    def _cleanup_orphan_dbs_locked(self) -> None:
        """清理历史任务遗留的独立状态库；仍被旧线程占用的跳过（Windows 下删除会失败）。

        每个任务用 state-ui-<scan_id>.db，重开即全新库，绝不会把上一轮的
        URL 记录当成"已抓过"从而把新任务判成空跑。
        """
        keep = self.state.db_path
        for p in Path(".").glob("state-ui-*.db*"):
            if keep and str(p) == keep:
                continue
            try:
                p.unlink()
            except OSError:
                pass

    def pause(self) -> dict:
        if self.state.status != "running":
            return {"status": self.state.status}
        if self.state.orch is not None:
            self.state.orch.pause()
        self.state.status = "paused"
        self.state.logs.append("[*] 已暂停（当前节点处理完成后挂起，进度保留，可直接改并发/深度）")
        return {"status": "paused"}

    def resume(self) -> dict:
        if self.state.status != "paused":
            return {"status": self.state.status}
        if self.state.orch is not None:
            self.state.orch.resume()
        self.state.status = "running"
        self.state.logs.append("[*] 已继续")
        return {"status": "running"}

    def update_config(self, params: dict) -> dict:
        """运行时调整并发/深度/QPS，无需重跑。"""
        if not self.running or self.state.orch is None:
            return {"error": "当前没有运行中的扫描"}
        orch = self.state.orch
        changed: list[str] = []
        if "concurrency" in params:
            n = int(params["concurrency"])
            if 1 <= n <= 500:
                orch.set_concurrency(n)
                self.state.params["concurrency"] = n
                changed.append(f"并发={n}")
        if "depth" in params:
            d = int(params["depth"])
            if 0 <= d <= 20:
                orch.set_max_depth(d)
                self.state.params["depth"] = d
                changed.append(f"深度={d}")
        if "qps" in params:
            q = float(params["qps"])
            if q >= 0:
                orch.set_qps(q)
                self.state.params["qps"] = q
                changed.append(f"QPS={q}")
        if changed:
            self.state.logs.append("[*] 已应用运行时配置：" + "，".join(changed))
        return {
            "status": self.state.status,
            "concurrency": orch.concurrency,
            "max_depth": orch.max_depth,
            "changed": changed,
        }

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
        download_only = state.mode == "download"
        cfg.scan.max_depth = int(params.get("depth", cfg.scan.max_depth))
        cfg.scan.concurrency = int(params.get("concurrency", cfg.scan.concurrency))
        cfg.scan.per_domain_qps = float(params.get("qps", cfg.scan.per_domain_qps))
        # 下载模式强制关 LLM：不审计 → 不需要 API Key → 可完全离线
        cfg.scan.llm_enabled = (
            bool(params.get("llm", True)) and bool(cfg.resolve_api_key())
        ) if not download_only else False
        cfg.scan.audit_json = bool(params.get("audit_json", False)) and not download_only
        # 离线模式（客户内网 / 云桌面等"只能进不能出"的环境）：切断一切外联。
        # LLM 不发、代理不连；渲染仍可用，但白名单外请求会被阻断。
        cfg.scan.offline = bool(params.get("offline", False))
        if cfg.scan.offline:
            cfg.scan.llm_enabled = False
            cfg.scan.audit_json = False
        cfg.proxy.enabled = bool(params.get("proxy", False)) and not cfg.scan.offline
        # 渲染：UI 的 render_mode 即总开关（选 off 就是关，选 hybrid/full 就开），
        # 避免 config.yaml 里 render_enabled=false 时"选了模式却不生效"的困惑
        cfg.scan.render_mode = str(params.get("render_mode", cfg.scan.render_mode))
        cfg.scan.render_enabled = cfg.scan.render_mode != "off"
        # TLS 校验：内网/政企/银行站点常用自签或私有 CA 证书，开着校验会整站抓不到
        if "verify_tls" in params:
            cfg.scan.verify_tls = bool(params["verify_tls"])
        cfg.scope.domains = list(params.get("domains", []))
        # 每个任务独占一套状态库与报告目录（含 scan_id）。旧任务被取消/放弃后
        # 无论是否收尾完毕，都不会污染新任务：新库是空的，种子一定会被真正抓取。
        db_path = f"state-ui-{state.scan_id}.db"
        cfg.storage.db_path = db_path
        state.db_path = db_path
        cfg.storage.output_dir = f"reports-ui/{state.scan_id}"

        # 下载模式输出目录：沿用 _url_to_filepath 结构（<dir>/<host>/<path>）
        if download_only:
            out = str(params.get("out_dir", "") or "").strip() or "downloads-ui"
            dl_dir = Path(out)
            if not dl_dir.is_absolute():
                dl_dir = (ROOT / dl_dir).resolve()
            dl_dir.mkdir(parents=True, exist_ok=True)
            state.download_dir = str(dl_dir)

        handler = MemoryHandler(state.logs, thread_id=threading.get_ident())
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
        if download_only:
            orch.download_only = True
            orch.download_dir = Path(state.download_dir)
        state.orch = orch
        # 渲染与 TLS 是"开了却没生效"最容易困惑的两项，开工前明确讲清状态
        if not cfg.scan.render_enabled:
            state.logs.append("[*] 增强渲染：关闭（纯 httpx 模式）")
        elif not orch.renderer.available():
            state.logs.append("[!] 增强渲染已选 " + cfg.scan.render_mode +
                              "，但 Playwright 未安装 → 本次会静默跳过渲染"
                              "（安装：pip install playwright && python -m playwright install chromium）")
        elif not orch.renderer.browser_ready():
            state.logs.append("[!] 增强渲染已选 " + cfg.scan.render_mode +
                              "，Playwright 包在但浏览器内核未下载 → 首次渲染会失败并降级"
                              "（补：python -m playwright install chromium）")
        else:
            state.logs.append("[*] 增强渲染：" + cfg.scan.render_mode +
                              ("（对所有 HTML 页面）" if cfg.scan.render_mode == "full" else "（仅 SPA 空壳）"))
        if not cfg.scan.verify_tls:
            state.logs.append("[*] TLS 证书校验：已关闭")
        if cfg.scan.offline:
            state.logs.append("[*] 离线模式：不调 LLM、不连代理，渲染阻断白名单外请求；"
                              "审计结果全部来自本地正则，报告就地生成 report.html")
        # 竞态兜底：取消请求可能落在"线程已起、orch 还没建好"的窗口里，
        # 那时 nobody 能通知 orch；这里补执行，避免取消丢单、任务照跑到底。
        if state.cancel_requested:
            orch.cancel(force=True)
            state.logs.append("[*] 取消请求在启动阶段到达：已立即中断任务")
        if download_only:
            state.logs.append(f"[*] 开始下载：种子 {len(params.get('seeds', []))} 个，"
                              f"白名单 {cfg.scope.domains}，深度 {cfg.scan.max_depth}，"
                              f"并发 {cfg.scan.concurrency}，输出 {state.download_dir}")
            state.logs.append("[*] 下载模式：不调 LLM、不需要 API Key、不产生审计结果，可完全离线运行")
        else:
            state.logs.append(f"[*] 开始扫描：种子 {len(params.get('seeds', []))} 个，"
                              f"白名单 {cfg.scope.domains}，深度 {cfg.scan.max_depth}，"
                              f"LLM {'开' if cfg.scan.llm_enabled else '关'}，"
                              f"代理 {'开' if cfg.proxy.enabled else '关'}")
        try:
            # 边跑边物化结果：运行中即把 SQLite 里的最新发现/接口/节点同步到
            # state，供前端「发现/接口/节点」选项卡实时展示（不再等任务完成）。
            scan_task = asyncio.create_task(orch.run(params.get("seeds", [])))
            while True:
                done, _ = await asyncio.wait({scan_task}, timeout=2.0)
                if done:
                    break
                await self._materialize(state, store)
            summary = await scan_task
            state.summary = dataclasses.asdict(summary)
            cancelled = bool(orch._cancel or state.cancel_requested)
            # 最终全量刷新一次，保证 done 后数据完整
            await self._materialize(state, store)
            if download_only:
                # 下载模式无审计报告，改为按落盘文件清单生成一份索引
                state.files = self._collect_files(state.download_dir)
                state.report_dir = await self._write_download_manifest(state)
            else:
                # 取消后仍落一份报告：已抓到的发现不白费；失败不影响终态判定
                try:
                    out = await write_reports(cfg, store, summary)
                    state.report_dir = str(out)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("报告生成失败：%s", exc)
                    state.logs.append(f"[!] 报告生成失败：{exc!r}")
            state.status = "cancelled" if cancelled else "done"
            if download_only:
                state.logs.append(f"[*] 下载{state.status}：成功 {summary.downloaded}，"
                                  f"失败 {summary.download_failed}，目录 {state.download_dir}")
            else:
                state.logs.append(f"[*] 扫描{state.status}：{state.summary.get('findings',0)} 条发现，"
                                  f"{state.summary.get('endpoints',0)} 个接口")
            if state.status == "cancelled":
                state.logs.append("[*] 任务已结束，现在可以重新选择模式/参数后直接开始新任务")
        except asyncio.CancelledError:
            state.status = "cancelled"
            if download_only and state.download_dir:
                state.files = self._collect_files(state.download_dir)
        finally:
            await fetcher.close()
            await orch.renderer.close()
            store.close()
            logging.getLogger().removeHandler(handler)

    @staticmethod
    def _collect_files(root: str) -> list[dict]:
        """枚举下载目录下的文件，供前端「文件」选项卡展示与清单导出。"""
        if not root:
            return []
        base = Path(root)
        if not base.exists():
            return []
        rows: list[dict] = []
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            try:
                rel = p.relative_to(base).as_posix()
                st = p.stat()
            except OSError:
                continue
            rows.append({"path": rel, "size": st.st_size, "mtime": int(st.st_mtime)})
        return rows

    async def _write_download_manifest(self, state: ScanState) -> str:
        """下载模式产物清单：落盘到输出目录下的 _manifest.json，便于核对完整性。"""
        if not state.download_dir:
            return ""
        d = Path(state.download_dir)
        total = sum(r["size"] for r in state.files)
        manifest = {
            "mode": "download",
            "scan_id": state.scan_id,
            "output_dir": str(d),
            "file_count": len(state.files),
            "total_bytes": total,
            "seeds": state.params.get("seeds", []),
            "domains": state.params.get("domains", []),
            "max_depth": state.params.get("depth"),
            "files": state.files,
        }
        try:
            (d / "_manifest.json").write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError:
            return ""
        return str(d)

    async def _materialize(self, state: ScanState, store: Store) -> None:
        """把数据库里的最新结果增量同步到 state（HTTP 线程可读）。"""
        try:
            st = await store.stats()
            if st["findings"] != len(state.findings):
                state.findings = await store.all_findings()
            if st["endpoints"] != len(state.endpoints):
                state.endpoints = await store.all_endpoints()
            if st["urls"] != len(state.urls):
                state.urls = await store.all_urls()
        except Exception:  # noqa: BLE001
            pass


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
            snap = MGR.state.live_snapshot()
            # can_start：当前是否可以直接开新任务（取消中也可强制重开）
            snap["can_start"] = MGR.can_start
            snap["archived"] = MGR.archived[-3:]
            return self._json(snap)
        if path == "/api/scan/findings":
            return self._json({"findings": MGR.state.findings})
        if path == "/api/scan/endpoints":
            return self._json({"endpoints": MGR.state.endpoints})
        if path == "/api/scan/urls":
            return self._json({"urls": MGR.state.urls})
        if path == "/api/scan/files":
            # 下载模式：实时枚举落盘文件（运行中也能看进度）
            rows = MGR.state.files
            if MGR.state.mode == "download" and MGR.state.download_dir:
                if MGR.state.status in ACTIVE_STATUSES:
                    rows = ScanManager._collect_files(MGR.state.download_dir)
            return self._json({"files": rows, "dir": MGR.state.download_dir})
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
        if path == "/api/scan/abandon":
            # 强制复位：不等旧任务收尾，立刻解除占用，可马上换模式重开
            return self._json(MGR.abandon())
        if path == "/api/scan/pause":
            return self._json(MGR.pause())
        if path == "/api/scan/resume":
            return self._json(MGR.resume())
        if path == "/api/scan/config":
            return self._json(MGR.update_config(params))
        return self._json({"error": "not found"}, 404)

    def _handle_start(self, params: dict) -> None:
        seeds_raw = str(params.get("seeds", ""))
        # 每行一条：URL、主机名或 IP 都收。没写协议的条目会被展开成 http/https
        # 两条（内网两种都常见），用户不必猜目标协议。
        seeds: list[str] = []
        auto_scheme: list[str] = []
        for line in seeds_raw.splitlines():
            urls = expand_seed(line)
            if not urls:
                continue
            if len(urls) > 1:
                auto_scheme.append(line.strip())
            seeds.extend(urls)
        seen: set[str] = set()
        seeds = [s for s in seeds if not (s in seen or seen.add(s))]

        domains = parse_domains(str(params.get("domains", "")))
        mode = "download" if str(params.get("mode", "audit")) == "download" else "audit"
        if not seeds:
            return self._json({
                "error": "授权扫描清单为空：每行填一个 URL、主机名或 IP 均可"
                         "（如 192.168.1.10 或 https://app.corp.local）"
            }, 400)
        if not domains:
            return self._json({"error": "授权域名白名单为空（安全约束，拒绝运行）"}, 400)

        params["seeds"] = seeds
        params["domains"] = domains
        params["mode"] = mode

        # 种子落在白名单外会被递归层直接跳过（表现为"任务秒退、0 个节点"），
        # 这里提前算出来提示用户，而不是让他去日志里猜。
        allow_sub = MGR.base_cfg.scope.allow_subdomains
        outside = [s for s in seeds if not is_in_scope(normalize_url(s), domains, allow_sub)]

        # force=True：运行中直接抢占（放弃旧任务后开新任务），供"放弃并重开"用
        force = bool(params.get("force"))
        res = MGR.start(params, force=force)
        if isinstance(res, dict) and "error" not in res:
            notes: list[str] = []
            if auto_scheme:
                notes.append("以下条目未写协议，已按 http 与 https 各试一次："
                             + "、".join(auto_scheme[:5])
                             + ("…" if len(auto_scheme) > 5 else ""))
            if outside:
                notes.append("以下种子不在白名单内，会被跳过："
                             + "、".join(outside[:5]) + ("…" if len(outside) > 5 else ""))
            if notes:
                res["notice"] = "；".join(notes)
        self._json(res, 200 if "error" not in res else 409)

    def _serve_report(self, fmt: str) -> None:
        # 下载模式没有审计报告，导出落盘清单（_manifest.json）
        if MGR.state.mode == "download":
            if not MGR.state.download_dir:
                return self._json({"error": "尚无下载任务"}, 404)
            d = Path(MGR.state.download_dir)
            files = MGR.state.files or ScanManager._collect_files(str(d))
            total = sum(r["size"] for r in files)
            manifest = {
                "mode": "download", "scan_id": MGR.state.scan_id,
                "output_dir": str(d), "file_count": len(files), "total_bytes": total,
                "files": files,
            }
            if fmt == "txt":
                body = "\n".join(f'{r["size"]}\t{r["path"]}' for r in files)
                return self._send(body.encode("utf-8"), "text/plain; charset=utf-8",
                                  attachment="manifest.txt")
            return self._send(
                json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"),
                MIME[".json"], attachment="_manifest.json",
            )
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
        renderer = Renderer(cfg)
        return {
            "max_depth": cfg.scan.max_depth,
            "concurrency": cfg.scan.concurrency,
            "per_domain_qps": cfg.scan.per_domain_qps,
            "llm_enabled": cfg.scan.llm_enabled,
            "llm_available": bool(cfg.resolve_api_key()),
            "audit_json": cfg.scan.audit_json,
            "proxy_enabled": cfg.proxy.enabled,
            "render_mode": cfg.scan.render_mode,
            # 包与浏览器内核都就绪才算真的能渲染；否则页面直接给出提示，
            # 避免"选了 hybrid 却什么都没发生"
            "render_ready": renderer.available() and renderer.browser_ready(),
            "verify_tls": cfg.scan.verify_tls,
            "offline": cfg.scan.offline,
            # 离线可用性：下载模式永远可离线；审计模式在无 Key 时自动降级为纯本地正则
            "network_required": False,
            "offline_ready": True,
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

    try:
        httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as e:
        if e.errno == 10013 or "10013" in str(e):
            print(f"[!] 错误：端口 {args.port} 已被其他进程占用")
            print(f"    解决方案：")
            print(f"    1. 换端口运行：python webui.py -p {args.port + 1}")
            print(f"    2. 或以管理员身份执行：netstat -ano | findstr :{args.port}")
            print(f"       然后：taskkill /PID <占用PID> /F")
        else:
            print(f"[!] 绑定失败：{e}")
        sys.exit(1)
    url = f"http://{args.host}:{args.port}"
    print(f"[*] 前端审计/下载 Web UI 已启动：{url}")
    if base_cfg.resolve_api_key():
        print("[*] DeepSeek: 已配置（审计模式可开 LLM；下载模式不调 LLM）")
    else:
        print("[*] DeepSeek: 未配置 → 审计模式自动走纯本地正则，下载模式不受影响")
    print("[*] 离线提示：选「仅下载」模式时不需要 API Key，也不访问任何外部 LLM")
    print("[*] 按 Ctrl+C 停止")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 已停止")


if __name__ == "__main__":
    main()
