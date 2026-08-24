"""快速探针：验证 LINKFINDER_RE 在关键边界上的行为，找出与预期的差距。"""
from core.prefilter import LINKFINDER_RE, API_ABSOLUTE_RE

CASES = [
    # (描述, 样本, 期望命中的路径集合)
    ("双引号相对路径", 'fetch("/api/v1/users");', {"/api/v1/users"}),
    ("单引号相对路径", "fetch('/api/v2/orders');", {"/api/v2/orders"}),
    ("反引号模板字面量", "fetch(`/api/v3/profile`);", {"/api/v3/profile"}),
    ("反引号模板带插值", "fetch(`/api/v4/u/${id}`);", {"/api/v4/u/${id}"}),
    ("协议相对 URL", 'var u="//cdn.example.com/lib.js";', {"//cdn.example.com/lib.js"}),
    ("绝对 https URL", 'var u="https://api.example.com/rest";', {"https://api.example.com/rest"}),
    ("拼接路径片段", 'var p="/api/"+"v5/items";', {"/api/", "v5/items"}),
    ("点号相对路径", 'get("./config.json");', {"./config.json"}),
    ("上级相对路径", 'get("../shared/util.js");', {"../shared/util.js"}),
    ("带扩展名文件名", 'load("user.json");', {"user.json"}),
    ("带查询串", 'get("/api/list?type=a&pg=1");', {"/api/list?type=a&pg=1"}),
    ("webpack chunk 哈希", 'src="/static/js/app.a1b2c3d4.js";', {"/static/js/app.a1b2c3d4.js"}),
]


def run():
    for desc, sample, expected in CASES:
        got = {m.group(1) for m in LINKFINDER_RE.finditer(sample)}
        # API_ABSOLUTE_RE 补充绝对 URL
        for m in API_ABSOLUTE_RE.finditer(sample):
            got.add(m.group(1))
        status = "OK " if got == expected else "GAP"
        miss = expected - got
        extra = got - expected
        print(f"[{status}] {desc}")
        print(f"      got   = {sorted(got)}")
        if miss:
            print(f"      MISS  = {sorted(miss)}")
        if extra:
            print(f"      EXTRA = {sorted(extra)}")
        print()


if __name__ == "__main__":
    run()
