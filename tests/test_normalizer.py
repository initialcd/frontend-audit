from core.normalizer import (
    content_hash,
    is_in_scope,
    is_static_asset,
    normalize_url,
    resolve_url,
    url_hash,
)


def test_normalize_scheme_host_case_and_default_port():
    assert normalize_url("HTTP://Example.COM:80/a//b?x=2&x=1") == "http://example.com/a/b?x=1&x=2"


def test_normalize_https_default_port():
    assert normalize_url("https://example.com:443/p") == "https://example.com/p"


def test_normalize_drops_fragment_and_keeps_custom_port():
    assert normalize_url("https://example.com:8443/p#frag") == "https://example.com:8443/p"


def test_url_hash_query_order_independent():
    assert url_hash("http://a.com/p?a=1&b=2") == url_hash("http://a.com/p?b=2&a=1")


def test_scope_exact_and_subdomain():
    assert is_in_scope("https://example.com/x", ["example.com"])
    assert is_in_scope("https://a.b.example.com/x", ["example.com"])
    assert not is_in_scope("https://example.com.evil.com/x", ["example.com"])
    assert not is_in_scope("https://other.com/x", ["example.com"])


def test_scope_no_subdomains():
    assert not is_in_scope("https://a.example.com/x", ["example.com"], allow_subdomains=False)


def test_resolve_relative_protocol_relative_and_bad_scheme():
    base = "https://example.com/js/app.js"
    assert resolve_url(base, "../api/v1/users") == "https://example.com/api/v1/users"
    assert resolve_url(base, "//cdn.example.com/lib.js") == "https://cdn.example.com/lib.js"
    assert resolve_url(base, "javascript:alert(1)") is None
    assert resolve_url(base, "") is None


def test_static_asset():
    assert is_static_asset("https://a.com/x/logo.png", [".png", ".jpg"])
    assert not is_static_asset("https://a.com/x/app.js", [".png", ".jpg"])


def test_content_hash_deterministic():
    assert content_hash(b"abc") == content_hash(b"abc")
    assert content_hash(b"abc") != content_hash(b"abd")
