from core.auditor import _coerce, _strip_fences


def test_strip_fences():
    assert _strip_fences('```json\n{"a":1}\n```') == '{"a":1}'
    assert _strip_fences('  {"a":1}  ') == '{"a":1}'


def test_coerce_tolerant_parsing():
    data = {
        "findings": [
            {"type": "aksk", "severity": "critical", "value": "AKIAEXAMPLE", "confidence": 0.9},
            "garbage",
            None,
        ],
        "endpoints": [
            {"path": "/api/v1/x", "method": "GET"},
            "/api/v1/from-string",
            {"no_path": 1},  # 缺 path 字段 → 丢弃该条
        ],
    }
    r = _coerce(data)
    assert len(r.findings) == 1
    assert r.findings[0].severity == "critical"
    assert [e.path for e in r.endpoints] == ["/api/v1/x", "/api/v1/from-string"]


def test_coerce_empty_ok():
    r = _coerce({"findings": [], "endpoints": []})
    assert r.findings == [] and r.endpoints == []
