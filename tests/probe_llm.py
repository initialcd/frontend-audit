"""LLM 链路探测：验证 config.yaml 里的模型名 / Key / JSON 输出是否真的可用。

用法：cd <工具根目录> && python tests/probe_llm.py

逐项打印：当前配置的模型名是否被服务端接受、可用模型清单、JSON 结构化输出是否生效。
审计模式"LLM 调用 N 次、失败 N 次"基本都是模型名或 Key 的问题，先跑这个再排。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import yaml

ROOT = Path(__file__).resolve().parent.parent
CFG = ROOT / "config.yaml"


def load() -> tuple[str, str, str]:
    data = yaml.safe_load(CFG.read_text(encoding="utf-8")) or {}
    ds = data.get("deepseek", {}) or {}
    return ds.get("api_key", ""), (ds.get("base_url") or "https://api.deepseek.com").rstrip("/"), ds.get("model", "")


def main() -> int:
    key, base, model = load()
    api = base if base.endswith("/v1") else base + "/v1"
    if not key:
        print("未配置 api_key（config.yaml 或环境变量 DEEPSEEK_API_KEY 均可）")
        return 2
    print(f"base_url = {base}")
    print(f"model    = {model}")
    print(f"key      = {key[:8]}…{key[-4:]}（长度 {len(key)}）\n")

    headers = {"Authorization": f"Bearer {key}"}
    problems: list[str] = []

    # 1) 当前模型名的极简调用
    try:
        r = httpx.post(
            f"{api}/chat/completions", headers=headers, timeout=30,
            json={"model": model, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 4},
        )
        print(f"[模型调用] HTTP {r.status_code}：{r.text[:300]}")
        if r.status_code != 200:
            problems.append(f"当前模型名 {model!r} 调用失败（HTTP {r.status_code}）")
    except Exception as exc:  # noqa: BLE001
        print(f"[模型调用] 连接失败：{exc!r}")
        problems.append("无法连接 base_url（网络或代理问题）")

    # 2) 服务端可用模型清单
    try:
        r = httpx.get(f"{api}/models", headers=headers, timeout=30)
        print(f"[模型清单] HTTP {r.status_code}")
        if r.status_code == 200:
            ids = [m.get("id") for m in (r.json().get("data") or [])]
            print("  可用模型：" + ", ".join(str(i) for i in ids))
            if model not in ids:
                problems.append(f"配置的模型 {model!r} 不在服务端清单里：{ids}")
        else:
            print("  " + r.text[:200])
    except Exception as exc:  # noqa: BLE001
        print(f"[模型清单] 失败：{exc!r}")

    # 3) JSON 结构化输出（审计链路依赖它），给足 token 避免自造截断
    try:
        r = httpx.post(
            f"{api}/chat/completions", headers=headers, timeout=90,
            json={
                "model": model,
                "temperature": 0,
                "max_tokens": 2048,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": '只输出 JSON：{"findings":[],"endpoints":[]}'},
                    {"role": "user", "content": '片段：const k="AKIAIOSFODNN7EXAMPLE";'},
                ],
            },
        )
        print(f"[JSON 模式] HTTP {r.status_code}")
        if r.status_code == 200:
            body = r.json()
            ch = body["choices"][0]
            content = ch["message"].get("content") or ""
            reasoning = ch["message"].get("reasoning_content") or ""
            print(f"  finish_reason={ch.get('finish_reason')}  content 长度={len(content)}  "
                  f"reasoning 长度={len(reasoning)}")
            print("  返回：" + content[:300])
            if not content.strip():
                problems.append("content 为空（推理内容吃掉了 token 预算），审计结果会解析失败")
            else:
                try:
                    json.loads(content)
                    print("  JSON 解析：通过")
                except json.JSONDecodeError as exc:
                    problems.append(f"返回内容不是合法 JSON：{exc}")
        else:
            print("  " + r.text[:200])
            problems.append("JSON 结构化输出不可用（审计结果会全部解析失败）")
    except Exception as exc:  # noqa: BLE001
        print(f"[JSON 模式] 失败：{exc!r}")

    # 4) 端到端复现工具的审计链路：跑真实 Auditor + _coerce，看结果是否被丢弃
    print("\n---- 端到端：真实 Auditor.audit() ----")
    try:
        sys.path.insert(0, str(ROOT))
        import asyncio
        from core.auditor import Auditor, _coerce
        from core.config import Config

        cfg = Config.load(CFG)
        aud = Auditor(cfg)
        snippet = 'const aws = "AKIAIOSFODNN7EXAMPLE";\nconst pwd = "P@ssw0rd123";'
        res = asyncio.run(aud.audit("https://demo.local/app.js", snippet))
        if res is None:
            print("  audit() 返回 None：LLM 调用失败（看上面日志里的 last_error）")
            problems.append("真实审计调用失败，审计模式会显示「LLM 调用 N 次，失败 N 次」")
        else:
            print(f"  解析后 findings={len(res.findings)} endpoints={len(res.endpoints)}")
            for f in res.findings:
                print(f"    - {f.type}/{f.severity} value={f.value[:40]!r} conf={f.confidence}")
            if not res.findings:
                problems.append("LLM 有返回但 findings 被容错解析全部丢弃（confidence/字段类型不匹配）")
    except Exception as exc:  # noqa: BLE001
        print(f"  端到端复现失败：{exc!r}")
        problems.append(f"端到端链路异常：{exc!r}")

    print("\n结论：" + ("链路正常" if not problems else " / ".join(problems)))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
