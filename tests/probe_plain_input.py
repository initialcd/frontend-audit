"""验证：种子与白名单都只写 IP（不给协议、白名单用换行分隔）时能否正常工作。"""
import json
import time
import urllib.request

BASE = "http://127.0.0.1:8899"


def api(path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, headers={"Content-Type": "application/json"},
        method="POST" if data is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


# 完全模拟截图里的填法：种子只写 IP:端口，白名单只写 IP 且用换行分隔
body = {
    "seeds": "127.0.0.1:8888",
    "domains": "127.0.0.1\n127.0.0.2",
    "depth": 2, "concurrency": 4, "qps": 0,
    "llm": False, "proxy": False, "render_mode": "off",
    "mode": "download", "out_dir": "downloads-plainip",
}
res = api("/api/scan", body)
print("启动响应：", json.dumps(res, ensure_ascii=False))

for _ in range(40):
    s = api("/api/scan/status")
    if s["status"] in ("done", "cancelled", "error"):
        break
    time.sleep(0.4)
print(f"终态：{s['status']}  节点={s.get('total_nodes')}  落盘={s.get('downloaded')}")
print("日志尾部：")
for line in s["logs"][-5:]:
    print("   ", line)
