"""URL 归一化、作用域判断、相对路径拼接与哈希。"""
from __future__ import annotations

import hashlib
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse


def normalize_url(url: str) -> str:
    """规范化 URL：scheme/host 小写、去默认端口、去 fragment、
    路径连续斜杠折叠、query 参数排序。"""
    url = url.strip()
    try:
        u = urlparse(url)
    except ValueError:
        return url
    scheme = (u.scheme or "http").lower()
    host = (u.hostname or "").lower()
    if not host:
        return url
    port = u.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        netloc = host
    elif port:
        netloc = f"{host}:{port}"
    else:
        netloc = host
    path = u.path or "/"
    while "//" in path:
        path = path.replace("//", "/")
    query = urlencode(sorted(parse_qsl(u.query, keep_blank_values=True)))
    return urlunparse((scheme, netloc, path, u.params, query, ""))


def url_hash(url: str) -> str:
    return hashlib.sha256(normalize_url(url).encode("utf-8")).hexdigest()


def content_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def is_in_scope(url: str, domains: list[str], allow_subdomains: bool = True) -> bool:
    """域名白名单判断：精确匹配或子域匹配，防后缀绕过（evil.com 不匹配 example.com）。"""
    host = host_of(url)
    if not host or not domains:
        return False
    for d in domains:
        d = d.strip().lower().rstrip(".")
        if not d:
            continue
        if host == d:
            return True
        if allow_subdomains and host.endswith("." + d):
            return True
    return False


def resolve_url(base: str, ref: str) -> str | None:
    """把 ref（可能是相对路径/协议相对/绝对 URL）基于 base 拼接；非 http(s) 返回 None。"""
    ref = ref.strip()
    if not ref:
        return None
    try:
        joined = urljoin(base, ref)
        u = urlparse(joined)
    except ValueError:
        return None
    if u.scheme not in ("http", "https"):
        return None
    return joined


def is_static_asset(url: str, excluded_extensions: list[str]) -> bool:
    try:
        path = urlparse(url).path.lower()
    except ValueError:
        return False
    return any(path.endswith(ext) for ext in excluded_extensions)
