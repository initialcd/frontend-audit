from core.prefilter import extract_scripts, prefilter_js, prefilter_text

JS = """
var cfg = { accessKeyId: "AKIAIOSFODNN7EXAMPLE", secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" };
axios.get("/api/v1/users", { params: { page: 1 } });
fetch("/api/v2/orders");
var u = "https://api.example.com/rest/status";
const pwd = "admin123";
//# sourceMappingURL=app.js.map
import("/js/chunk-home.js");
"""


def test_prefilter_js_finds_secrets_and_paths():
    pf = prefilter_js(JS, 80, 8000)
    names = [f.ftype for f in pf.findings]
    assert "aws_ak" in names
    assert any(f.ftype == "generic_secret" and "admin123" in f.value for f in pf.findings)
    paths = " | ".join(pf.api_paths)
    assert "/api/v1/users" in paths
    assert "/api/v2/orders" in paths
    assert "https://api.example.com/rest/status" in paths
    assert pf.source_map == "app.js.map"
    assert any("chunk-home.js" in c for c in pf.chunk_urls)


def test_extract_scripts_external_and_inline():
    html = '<html><script src="/js/a.js"></script><script>var x=1;</script></html>'
    external, inline = extract_scripts(html)
    assert external == ["/js/a.js"]
    assert inline and "var x=1;" in inline[0]


def test_snippets_are_capped():
    text = ("AKIAIOSFODNN7EXAMPLE " * 20) + ("x" * 30000)
    pf = prefilter_js(text, 10, 2000)
    assert len(pf.snippets) <= 2200


def test_prefilter_text_on_json():
    data = '{"code":0,"data":{"user":"admin","token":"fake-token-1234567890"}}'
    pf = prefilter_text(data, 60, 4000)
    assert any(
        f.ftype == "generic_secret" and "fake-token-1234567890" in f.value
        for f in pf.findings
    )


def test_linkfinder_backtick_template():
    # 反引号模板字面量路径（含插值）应被提取
    js = 'fetch(`/api/v3/profile`); const u = `/api/v4/u/${id}`;'
    pf = prefilter_js(js, 40, 4000)
    paths = " | ".join(pf.api_paths)
    assert "/api/v3/profile" in paths
    assert "/api/v4/u/${id}" in paths


def test_new_secret_patterns():
    js = (
        'var s="xoxb-1234567890-abcdefghij";'
        'var k="sk_live_abcdef1234567890abcdef";'
        'var db="mongodb://root:s3cr3t@10.0.0.1:27017/db";'
        'h.set("Authorization","Bearer ya29.abcdef1234567890");'
    )
    pf = prefilter_js(js, 40, 4000)
    names = {f.ftype for f in pf.findings}
    assert "slack_token" in names
    assert "stripe_key" in names
    assert "db_connection" in names
    assert "bearer_token" in names
    # bearer_token 只取 token 值，不含 "Bearer " 前缀
    assert any(f.ftype == "bearer_token" and f.value == "ya29.abcdef1234567890"
               for f in pf.findings)


def test_generic_secret_backtick():
    # 反引号包裹的通用密钥也应命中
    js = "const cfg = { secret: `backtick12345` };"
    pf = prefilter_js(js, 40, 4000)
    assert any(f.ftype == "generic_secret" and "backtick12345" in f.value
               for f in pf.findings)
