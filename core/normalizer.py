"""URL 归一化、作用域判断、相对路径拼接与哈希。"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

# 域名输入允许的分隔符：半角逗号、全角逗号、顿号、分号、换行、空白
_DOMAIN_SPLIT_RE = re.compile(r"[,，、;；\s]+")


def normalize_domain(raw: str) -> str:
    """把用户输入的域名条目规范化：去协议/路径/端口/用户名，小写，去尾点。

    例如 'https://Sub.Example.COM:8443/a?b=1' -> 'sub.example.com'。
    用户常把整条 URL 或带端口的地址直接粘进白名单，这里统一清洗为纯域名。
    非法条目返回空串，由调用方过滤。
    """
    s = (raw or "").strip().lower()
    if not s:
        return ""
    if "://" in s:
        # 用户误填完整 URL：按 URL 解析取 hostname
        try:
            u = urlparse(s)
        except ValueError:
            return ""
        host = u.hostname or ""
    else:
        # 无协议：去掉可能的端口与路径（'example.com:8443' -> 'example.com'）
        host = s.split("/", 1)[0].split(":", 1)[0]
    host = host.strip().rstrip(".").lower()
    # 只保留域名合法字符（ascii 字母数字、点、横线、下划线）
    host = "".join(ch for ch in host if ch.isascii() and (ch.isalnum() or ch in ".-_"))
    return host


def parse_domains(raw) -> list[str]:
    """把任意来源（字符串/列表）的域名条目解析为规范化域名列表，去重去空。"""
    if isinstance(raw, (list, tuple)):
        items: list[str] = [str(x) for x in raw]
    else:
        items = _DOMAIN_SPLIT_RE.split(str(raw or ""))
    out: list[str] = []
    seen: set[str] = set()
    for it in items:
        d = normalize_domain(it)
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


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


def primary_domain_of(host: str, domains: list[str], allow_subdomains: bool = True) -> str | None:
    """返回主机命中的最佳主域名：精确匹配优先，其次最长子域匹配，平局取白名单先出现者。

    多个主域名同时存在于白名单时，每个 URL 都唯一归属于一个主域名分组
    （比"第一个匹配"更稳：example.com 与 sub.example.com 同在白名单时，
    sub.example.com 的资产归属更具体的 sub.example.com 组）。
    """
    if not host or not domains:
        return None
    best = None
    best_len = -1
    for raw in domains:
        d = normalize_domain(raw)
        if not d:
            continue
        if host == d:
            return d  # 精确匹配即为最佳
        if allow_subdomains and host.endswith("." + d) and len(d) > best_len:
            best = d
            best_len = len(d)
    return best


def primary_domain_index(host: str, domains: list[str], allow_subdomains: bool = True) -> int | None:
    """primary_domain_of 的下标版本：返回命中分组在白名单中的下标（稳定、可复现）。"""
    if not host or not domains:
        return None
    norm = [normalize_domain(d) for d in domains]
    best_i = None
    best_len = -1
    for i, d in enumerate(norm):
        if not d:
            continue
        if host == d:
            return i  # 精确匹配即为最佳
        if allow_subdomains and host.endswith("." + d) and len(d) > best_len:
            best_i = i
            best_len = len(d)
    return best_i


def is_in_scope(url: str, domains: list[str], allow_subdomains: bool = True) -> bool:
    """域名白名单判断：精确匹配或子域匹配，防后缀绕过（evil.com 不匹配 example.com）。

    域名条目自动清洗（协议/端口/路径/大小写），多主域名只需逗号/换行分隔即可并存。
    """
    host = host_of(url)
    return primary_domain_of(host, domains, allow_subdomains) is not None


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
