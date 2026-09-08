from core.normalizer import (
    content_hash,
    is_in_scope,
    is_static_asset,
    normalize_domain,
    normalize_url,
    parse_domains,
    primary_domain_index,
    primary_domain_of,
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


# ---------- 多主域名白名单（归一化 + 分组） ----------

def test_normalize_domain_strips_scheme_port_path_case():
    assert normalize_domain("https://Sub.Example.COM:8443/a?b=1") == "sub.example.com"
    assert normalize_domain("example.com:8080") == "example.com"
    assert normalize_domain("Example.COM.") == "example.com"
    assert normalize_domain("  a.com /x ") == "a.com"
    assert normalize_domain("") == ""
    assert normalize_domain("not a domain at all") == "notadomainatall"  # 非法字符被剔除


def test_parse_domains_multi_separators():
    # 半角逗号 / 中文逗号 / 换行 / 顿号 混用
    assert parse_domains("a.com，b.com\nc.com、d.com; e.com") == \
        ["a.com", "b.com", "c.com", "d.com", "e.com"]
    # 去重
    assert parse_domains("a.com,a.com") == ["a.com"]
    # 列表输入
    assert parse_domains(["a.com", "https://b.com:443/x", "", "  "]) == ["a.com", "b.com"]


def test_multi_domain_scope_all_groups_match():
    domains = ["jxnu.edu.cn", "example.com"]
    assert is_in_scope("https://stuworkyx.jxnu.edu.cn/xxl-job-admin/", domains)
    assert is_in_scope("https://www.example.com/app.js", domains)
    assert not is_in_scope("https://other.org/x", domains)


def test_is_in_scope_with_dirty_entries():
    # 用户把完整 URL / 带端口地址直接粘进白名单也能匹配
    assert is_in_scope("https://a.jxnu.edu.cn/x", ["https://jxnu.edu.cn", "example.com"])
    assert is_in_scope("https://www.example.com/x", ["jxnu.edu.cn", "example.com:8080"])


def test_primary_domain_longest_match():
    domains = ["example.com", "sub.example.com"]
    assert primary_domain_of("sub.example.com", domains) == "sub.example.com"  # 更长更具体
    assert primary_domain_of("a.sub.example.com", domains) == "sub.example.com"
    assert primary_domain_of("example.com", domains) == "example.com"          # 精确匹配优先
    assert primary_domain_of("other.com", domains) is None


def test_primary_domain_index_is_stable():
    domains = ["a.com", "b.com"]
    assert primary_domain_index("www.a.com", domains) == 0
    assert primary_domain_index("b.com", domains) == 1
    assert primary_domain_index("c.com", domains) is None
    # 平局取白名单先出现者
    assert primary_domain_index("x.deep.com", ["deep.com", "deep.com"]) == 0


def test_scope_no_subdomains_still_works_with_multiple():
    domains = ["a.com", "b.com"]
    assert not is_in_scope("https://sub.a.com/x", domains, allow_subdomains=False)
    assert is_in_scope("https://a.com/x", domains, allow_subdomains=False)
