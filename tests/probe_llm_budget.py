"""LLM 输出预算剖面：验证 deepseek.max_tokens 对长片段够不够用。

要回答的问题：工具单次最多把 llm_snippet_cap（默认 12000）字符的片段送 LLM，
推理型模型会先产出 reasoning_content，它与 content 共享 max_tokens 预算。
预算不足时 finish_reason=length、content 里的 JSON 被截断 → 整条结果作废
（core/auditor.py 会重试 3 次，仍然失败就计一次 llm_failures）。

用法：
    python tests/probe_llm_budget.py            # 默认测 3000 / 12000 字符两档片段
    python tests/probe_llm_budget.py 20000      # 自定义片段字符数

输出每个组合的：finish_reason、输入/输出 token、reasoning 占比、JSON 是否可解析、解析出的 findings 数。
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import httpx
import yaml

ROOT = Path(__file__).resolve().parent.parent
CFG = ROOT / "config.yaml"
PROMPT = ROOT / "prompts" / "audit.md"

# 命中行（每行都会产生一条 LLM finding）与普通代码行，按 1:3 混合，贴近真实片段构成。
#
# 注意：这里的样本一律用低熵占位值（AKIDEXAMPLEKEY0000000000 这类）。
# 高熵的"假"凭证一样会被 GitHub Push Protection 判定为真凭证而拒绝推送——
# 实测踩过：AKID + 一串随机字符会被识别成 Tencent Cloud Secret ID。
# 只要保持格式合法（能被 SECRET_PATTERNS 命中）且熵足够低即可。
HIT_LINES = [
    'const awsKey = "AKIAIOSFODNN7EXAMPLE";',
    'const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";',
    'const dbUrl = "mysql://root:Passw0rd123@10.0.12.7:3306/appdb";',
    'const wx = { appId: "wx0123456789abcdef", secret: "wxb1a2b3c4d5e6f7g8" };',
    'headers["x-header-signature"] = md5(str + ts).toUpperCase();',
    'axios.get("/api/v1/user/profile", { params: { token: t } });',
    'axios.post("/api/v2/orders/export", payload);',
    'fetch("/api/v1/internal/settlement/query?page=1");',
    'const tencentSecretId = "AKIDEXAMPLEKEY0000000000";',
    'const aliyunAk = "LTAIEXAMPLEKEY000000";',
]
FILLER_LINES = [
    'function formatAmount(n) { return n.toFixed(2).replace(/\\B(?=(\\d{3})+(?!\\d))/g, ","); }',
    'export const routes = [{ path: "/home", component: () => import("./views/Home.vue") }];',
    'const store = createStore({ state: { list: [], page: 1, size: 20 } });',
    'if (process.env.NODE_ENV !== "production") { console.warn("dev mode"); }',
    'const fmt = (d) => new Date(d).toISOString().slice(0, 10);',
    'onMounted(() => { loadList(); window.addEventListener("resize", onResize); });',
    'class ApiClient { constructor(base) { this.base = base; } }',
    'const debounce = (fn, t) => { let h; return (...a) => { clearTimeout(h); h = setTimeout(() => fn(...a), t); }; };',
]


def build_snippet(size: int) -> str:
    """构造指定字符数的片段：命中行与普通行 1:3 混合。"""
    out: list[str] = []
    total = 0
    i = 0
    while total < size:
        line = HIT_LINES[i % len(HIT_LINES)] if i % 4 == 0 else FILLER_LINES[i % len(FILLER_LINES)]
        out.append(line)
        total += len(line) + 1
        i += 1
    return "\n".join(out)


def load_cfg() -> tuple[str, str, str, int]:
    data = yaml.safe_load(CFG.read_text(encoding="utf-8")) or {}
    ds = data.get("deepseek", {}) or {}
    scan = data.get("scan", {}) or {}
    base = (ds.get("base_url") or "https://api.deepseek.com").rstrip("/")
    return ds.get("api_key", ""), base, ds.get("model", ""), int(scan.get("llm_snippet_cap", 12000))


def call(api: str, key: str, model: str, system: str, snippet: str, max_tokens: int) -> dict:
    t0 = time.time()
    try:
        r = httpx.post(
            f"{api}/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            timeout=300,
            json={
                "model": model,
                "temperature": 0,
                "max_tokens": max_tokens,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": f"来源文件：https://demo.local/app.js\n\n待审计片段：\n{snippet}"},
                ],
            },
        )
    except Exception as exc:  # noqa: BLE001
        return {"error": repr(exc), "cost": round(time.time() - t0, 1)}

    row: dict = {"http": r.status_code, "cost": round(time.time() - t0, 1)}
    if r.status_code != 200:
        row["error"] = r.text[:160]
        return row

    body = r.json()
    choice = (body.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    content = msg.get("content") or ""
    reasoning = msg.get("reasoning_content") or ""
    usage = body.get("usage") or {}
    details = usage.get("completion_tokens_details") or {}

    row.update({
        "finish": choice.get("finish_reason"),
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
        "reasoning_tokens": details.get("reasoning_tokens", "?"),
        "content_chars": len(content),
        "reasoning_chars": len(reasoning),
    })
    try:
        obj = json.loads(content)
        row["json_ok"] = True
        row["findings"] = len(obj.get("findings") or [])
        row["endpoints"] = len(obj.get("endpoints") or [])
    except json.JSONDecodeError as exc:
        row["json_ok"] = False
        row["json_err"] = str(exc)[:80]
    return row


def stress(api: str, key: str, model: str, system: str, snippet: str,
           concurrency: int = 5, rounds: int = 3, max_tokens: int = 4096) -> int:
    """并发稳定性：工具默认并发 20，服务端在高并发下是否稳定直接决定 llm_failures。"""
    import asyncio

    async def one(client: httpx.AsyncClient) -> dict:
        try:
            r = await client.post(
                f"{api}/chat/completions",
                headers={"Authorization": f"Bearer {key}"},
                json={
                    "model": model, "temperature": 0, "max_tokens": max_tokens,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": f"待审计片段：\n{snippet}"},
                    ],
                },
            )
            if r.status_code != 200:
                return {"ok": False, "why": f"HTTP {r.status_code}"}
            body = r.json()
            content = ((body.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
            try:
                json.loads(content)
                return {"ok": True, "why": ""}
            except json.JSONDecodeError as exc:
                return {"ok": False, "why": f"JSON: {str(exc)[:40]}"}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "why": type(exc).__name__}

    async def run() -> list[dict]:
        sem = asyncio.Semaphore(concurrency)

        async def bounded(client, _i):
            async with sem:
                return await one(client)

        async with httpx.AsyncClient(timeout=300) as client:
            out = []
            for _ in range(rounds):
                out.extend(await asyncio.gather(*(bounded(client, i) for i in range(concurrency))))
            return out

    print(f"===== 并发稳定性：并发 {concurrency} × {rounds} 轮，片段 {len(snippet)} 字符，max_tokens={max_tokens} =====")
    results = asyncio.run(run())
    bad = [r for r in results if not r["ok"]]
    reasons: dict[str, int] = {}
    for r in bad:
        reasons[r["why"]] = reasons.get(r["why"], 0) + 1
    print(f"  成功 {len(results) - len(bad)}/{len(results)}，失败 {len(bad)}")
    for why, n in reasons.items():
        print(f"    失败原因 {why} × {n}")
    print("\n  提示：单次失败 auditor 会重试 3 次；若失败率偏高，优先降 concurrency，而不是调 max_tokens\n")
    return 0


def main() -> int:
    key, base, model, cap = load_cfg()
    api = base if base.endswith("/v1") else base + "/v1"
    if not key:
        print("未配置 api_key")
        return 2
    system = PROMPT.read_text(encoding="utf-8") if PROMPT.exists() else "只输出 JSON"

    if "--stress" in sys.argv:
        return stress(api, key, model, system, build_snippet(3000))

    sizes = [int(sys.argv[1])] if len(sys.argv) > 1 else [3000, cap]
    budgets = [2048, 4096, 8192]

    print(f"模型={model}  llm_snippet_cap={cap}  当前 config 值 max_tokens=4096")
    print(f"system prompt={len(system)} 字符\n")

    verdict: list[str] = []
    for size in sizes:
        snippet = build_snippet(size)
        # 真实链路不会送超过 cap 的片段
        if size > cap:
            snippet = snippet[:cap]
        hits = sum(1 for line in snippet.splitlines() if line in HIT_LINES)
        print(f"===== 片段 {len(snippet)} 字符（命中行 {hits}，理论上限 {hits} 条 finding）=====")
        for mt in budgets:
            row = call(api, key, model, system, snippet, mt)
            if row.get("error"):
                print(f"  max_tokens={mt:5d}  失败：{row['error']}")
                continue
            ok = row.get("json_ok")
            line = (f"  max_tokens={mt:5d}  finish={row['finish']:<8} "
                    f"prompt={row['prompt_tokens']:<6} completion={row['completion_tokens']:<6} "
                    f"reasoning={row['reasoning_tokens']:<6} content={row['content_chars']}字符 / "
                    f"reasoning={row['reasoning_chars']}字符  耗时={row['cost']}s  ")
            if ok:
                line += f"JSON 可解析，findings={row['findings']} endpoints={row['endpoints']}"
            else:
                line += f"JSON 截断/非法：{row.get('json_err','')}"
            print(line)
            if mt == 4096 and not ok:
                verdict.append(f"{len(snippet)} 字符片段在 max_tokens=4096 下截断")
            if mt == 4096 and ok and row["reasoning_tokens"] not in ("?", None):
                ratio = row["reasoning_tokens"] / max(1, row["completion_tokens"])
                verdict.append(f"{len(snippet)} 字符片段：reasoning 占 completion 的 {ratio:.0%}")
        print()

    print("结论：" + ("；".join(verdict) if verdict else "无异常"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
