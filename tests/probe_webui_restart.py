"""手动回归探测：Web UI 的「取消 / 放弃并重开 / 强制复位」是否真的可用。

用法（两个终端）：
    cd tests/smoke_site && python -m http.server 8877 --bind 127.0.0.1
    cd <工具根目录>  && python webui.py -p 8899
    cd <工具根目录>  && python tests/probe_webui_restart.py

脚本自带一个"慢站"（每个响应延迟 SLOW_DELAY 秒）用来验证取消真的中断了
在飞请求：旧实现要等当前请求自然返回，耗时必然 >= SLOW_DELAY；新实现应在秒级返回。

验证点：
    1. 取消要秒级生效（不再等当前节点自然收尾）；
    2. 取消后能立刻重开，且新任务真的重新抓取（不因旧状态库被判重而空跑）；
    3. 强制复位绕过收尾等待，复位后可立即启动新任务。
"""
from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8899"
TARGET = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8877/"
HOST = TARGET.split("//", 1)[1].split("/", 1)[0].split(":")[0]

SLOW_PORT = 8878
SLOW_DELAY = 5.0
SLOW_URL = f"http://127.0.0.1:{SLOW_PORT}/"


class SlowHandler(BaseHTTPRequestHandler):
    """每个响应都慢慢来，逼出"取消时正好有请求在飞"的状态。"""

    def do_GET(self):  # noqa: N802
        time.sleep(SLOW_DELAY)
        links = "".join(f"<a href='/p{i}'>p{i}</a>" for i in range(1, 5))
        body = f"<html><body><h1>slow</h1>{links}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # noqa: D102
        pass


def start_slow_site() -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", SLOW_PORT), SlowHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def api(path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data,
        headers={"Content-Type": "application/json"},
        method="POST" if data is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def start(target: str = TARGET, **over) -> dict:
    body = {
        "seeds": target + "\n", "domains": HOST, "depth": 3, "concurrency": 5,
        "qps": 0, "llm": False, "proxy": False, "render_mode": "off",
        "mode": "download", "out_dir": "downloads-uitest",
    }
    body.update(over)
    return api("/api/scan", body)


def wait_for(pred, timeout: float):
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = api("/api/scan/status")
        if pred(s):
            return s, time.time() - t0
        time.sleep(0.25)
    return api("/api/scan/status"), time.time() - t0


failures: list[str] = []


def check(label: str, ok: bool, detail: str) -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {label}：{detail}")
    if not ok:
        failures.append(label)


def main() -> int:
    print(f"webui={BASE}  target={TARGET}  domains={HOST}\n")
    print(f"慢站 {SLOW_URL} 已就绪（每响应 {SLOW_DELAY:.0f}s）")

    # ---- 1. 取消要秒级生效：慢站上取消时必有请求在飞 ----
    r = start(SLOW_URL, depth=2, concurrency=4)
    print("任务A 启动响应:", r)
    wait_for(lambda s: int(s.get("total_nodes", 0)) >= 1, 20)
    t0 = time.time()
    api("/api/scan/cancel", {})
    s, _ = wait_for(lambda s: s["status"] in ("cancelled", "done", "error"), 30)
    elapsed = time.time() - t0
    # 旧实现必须等当前请求自然返回（>= SLOW_DELAY），新实现应远快于此
    check("取消能中断在飞请求（秒级）",
          s["status"] == "cancelled" and elapsed < SLOW_DELAY / 2,
          f"终态={s['status']}，取消耗时={elapsed:.1f}s（对照：单请求延迟 {SLOW_DELAY:.0f}s）")

    # ---- 2. 取消后立刻重开，且新任务真的重新抓取（旧状态库不污染） ----
    r2 = start()
    check("取消后可直接重开", "error" not in r2, f"响应={r2}")
    if "error" in r2:
        return 1
    s2, _ = wait_for(lambda s: s["status"] != "running", 25)
    check("重开任务真正抓取（非空跑）",
          s2["status"] == "done" and int(s2.get("downloaded", 0)) > 0
          and int(s2.get("skipped_dup", 0)) == 0,
          f"终态={s2['status']}，已下载={s2.get('downloaded')}，判重跳过={s2.get('skipped_dup')}")
    check("新旧任务号不同", r2.get("scan_id") != r.get("scan_id"),
          f"A={r.get('scan_id')} / B={r2.get('scan_id')}")

    # ---- 3. 强制复位：不等收尾立刻解除占用（慢站在飞时复位） ----
    r3 = start(SLOW_URL, depth=2, concurrency=4)
    wait_for(lambda s: int(s.get("total_nodes", 0)) >= 1, 20)
    t0 = time.time()
    ab = api("/api/scan/abandon", {})
    idle = api("/api/scan/status")
    reset_cost = time.time() - t0
    check("强制复位立即回到可开新任务",
          ab.get("can_start") is True and idle["status"] == "idle" and reset_cost < 1.0,
          f"abandon={ab}，status={idle['status']}，耗时={reset_cost:.2f}s")

    r4 = start()
    check("复位后能立刻启动新任务", "error" not in r4, f"响应={r4}")
    s4, _ = wait_for(lambda s: int(s.get("downloaded", 0)) > 0 or s["status"] != "running", 15)
    check("复位后的新任务同样在抓取", int(s4.get("downloaded", 0)) > 0,
          f"状态={s4['status']}，已下载={s4.get('downloaded')}")
    api("/api/scan/cancel", {})
    wait_for(lambda s: s["status"] in ("cancelled", "done", "error"), 20)

    # ---- 4. 审计模式（走报告落盘路径）同样可取消并重开 ----
    r5 = start(TARGET, mode="audit", llm=False, depth=2)
    s5, _ = wait_for(lambda s: s["status"] != "running", 25)
    check("审计模式任务可正常完成并出报告",
          s5["status"] == "done" and bool(s5.get("report_dir")),
          f"终态={s5['status']}，发现={s5.get('findings')}，接口={s5.get('endpoints')}，报告={s5.get('report_dir')}")

    r6 = start(SLOW_URL, mode="audit", llm=False, depth=2)
    wait_for(lambda s: int(s.get("total_nodes", 0)) >= 1, 20)
    t0 = time.time()
    api("/api/scan/cancel", {})
    s6, _ = wait_for(lambda s: s["status"] in ("cancelled", "done", "error"), 30)
    check("审计模式取消同样秒级且保留报告",
          s6["status"] == "cancelled" and time.time() - t0 < SLOW_DELAY / 2 and bool(s6.get("report_dir")),
          f"终态={s6['status']}，耗时={time.time() - t0:.1f}s，报告={s6.get('report_dir')}")

    # 取消后仍能直接开新任务
    r7 = start()
    check("审计任务取消后可重开任意模式", "error" not in r7, f"响应={r7}")
    wait_for(lambda s: s["status"] != "running", 20)

    print("\n结果：" + ("全部通过" if not failures else "失败项 " + "，".join(failures)))
    return 0 if not failures else 1


if __name__ == "__main__":
    start_slow_site()
    try:
        sys.exit(main())
    except urllib.error.URLError as exc:
        print(f"无法连接 webui（{BASE}）：{exc}")
        sys.exit(2)
