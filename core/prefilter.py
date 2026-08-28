"""零 token 成本的预处理管道。

职责：
1. 从 HTML 提取外部 script 与内联脚本；
2. 从 JS 提取 chunk/动态加载的脚本地址、sourceMappingURL；
3. 本地正则提取 API 路径候选、硬编码敏感信息、版本信息；
4. 把命中位置裁剪成"片段"，只把片段（而非整个文件）送 LLM。

所有本地正则命中的结果都会直接入库，不经过 LLM。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------- HTML ----------
SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>""", re.I)
INLINE_SCRIPT_RE = re.compile(r"""<script\b[^>]*>(.*?)</script>""", re.I | re.S)

# ---------- JS 结构 ----------
SOURCE_MAP_RE = re.compile(r"//[@#]\s*sourceMappingURL=(\S+)", re.I)
CHUNK_RE = re.compile(
    r"""["'`]([^"'`\s]*?(?:chunk|static|assets|js/)[^"'`\s]*?\.(?:js|mjs)(?:\?[^"'`]*)?)["'`]""",
    re.I,
)
WEBPACK_CHUNK_RE = re.compile(r"[0-9a-zA-Z_\-$]+\.(?:[a-f0-9]{8}|[a-f0-9]{20})\.js")

# ---------- 路径提取（LinkFinder 级正则）----------
# LinkFinder 核心：从字符串字面量里提取端点路径，覆盖单/双/反引号、
# 拼接表达式、相对/绝对路径。比"引号+特征词"精准得多，能从压缩混淆 JS 里抠端点。
LINKFINDER_RE = re.compile(
    r"""
    ["'`]                                # 起始引号（单/双/反引号）
    (
      ((?:[a-zA-Z]{1,10}://|//)          # 协议相对/绝对 URL
        [^"'`/]{1,}\.[a-zA-Z]{2,}[^"'`]{0,})
      |
      ((?:/|\.\./|\./)                   # 相对路径
        [^"'`><,;| *()(%%$^/\\\[\]][^"'`><,;|()]{1,})
      |
      ([a-zA-Z0-9_\-/]{1,}/              # 路径段
        [a-zA-Z0-9_\-/.]{1,}\.(?:[a-zA-Z]{1,4}|action)  # 扩展名
        (?:[\?|/][^"|'`]{0,}|))
      |
      ([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|do)(?:\?[^"|'`]{0,}|))  # 带扩展名的文件名
    )
    ["'`]                                # 结束引号（单/双/反引号）
    """,
    re.VERBOSE,
)
# 绝对 URL 单独提取（用于跨域 API 发现）
API_ABSOLUTE_RE = re.compile(r"""["'`](https?://[^"'`\s]{2,512})["'`]""")

# ---------- 敏感信息 ----------
# (名称, 严重级别, 正则)
SECRET_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("aws_ak", "critical", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("tencent_ak", "critical", re.compile(r"\bAKID[0-9A-Za-z]{13,}\b")),
    ("aliyun_ak", "critical", re.compile(r"\bLTAI[0-9A-Za-z]{12,30}\b")),
    ("openai_key", "critical", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("github_token", "critical", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("google_api_key", "critical", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("jwt", "high", re.compile(r"\beyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\b")),
    ("private_key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    # 第三方 SaaS 凭证
    ("slack_token", "critical", re.compile(r"\bxox[baprs]-[0-9a-zA-Z-]{10,}")),
    ("stripe_key", "critical", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}")),
    # 数据库/中间件连接串（含内嵌账号密码 user:pass@host）
    (
        "db_connection",
        "critical",
        re.compile(
            r"""(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^:\s"'`<>]+:[^@\s"'`<>]+@[^\s"'`<>]+"""
        ),
    ),
    # HTTP Authorization 头里的 Bearer token
    ("bearer_token", "high", re.compile(r"""(?i)\bbearer\s+([A-Za-z0-9\-_.=]{20,})""")),
    (
        "generic_secret",
        "medium",
        re.compile(
            r"""(?i)(?:password|passwd|pwd|secret|token|access[_-]?key|api[_-]?key|app[_-]?secret|private[_-]?key|client[_-]?secret|db[_-]?(?:password|pass))["'`]?\s*[:=]\s*["'`]([^"'`\n]{4,128})["'`]"""
        ),
    ),
]

# ---------- 版本信息 ----------
# 每条规则的第一捕获组必须是版本号本身（_iter_hits 统一取 group(1)）。
VERSION_PATTERNS: list[tuple[str, re.Pattern]] = [
    # 1) 赋值/JSON：version / appVersion / build_version / release 等，值可带 v 前缀、可无引号
    (
        "assignment",
        re.compile(
            r"""(?i)(?:version|ver|\b(?:release|build|revision)\b)["']?[_\-]*(?:str|num|no|code)?["']?\s*[:=]\s*["']?(v?\d[\w.\-]{0,24})"""
        ),
    ),
    # 2) 库指纹 / CDN 路径：jquery/3.6.0、jquery-3.6.0.min.js、vue@2.6.14（点分结构，避免吃到 .min.js）
    (
        "lib_fingerprint",
        re.compile(
            r"""(?i)(?:jquery|vue(?:\.min)?|react(?:-dom)?|angular(?:js)?|bootstrap|lodash|moment|axios|echarts|element-ui|element-plus|antd|d3|three|layui|swiper)[./@-]v?(\d+(?:\.\d+){0,3})"""
        ),
    ),
    # 3) JSDoc / 注释标注：@version 1.2.3
    (
        "jsdoc",
        re.compile(r"""(?i)@version\s+v?(\d[\w.\-]{0,12})"""),
    ),
    # 4) HTML meta generator：WordPress / Drupal / Discuz 等建站程序版本
    (
        "meta_generator",
        re.compile(
            r"""(?i)<meta[^>]+(?:name|content)\s*=\s*["'][^"']*?\b(?:wordpress|drupal|joomla|phpbb|discuz|empirecms|dedecms|thinkphp)[^"']*?[v\s/-](\d[\w.\-]{0,12})"""
        ),
    ),
    # 5) URL 查询参数：?v=3.6.0、?version=1.2、?ver=2.0
    (
        "query_param",
        re.compile(r"""(?i)[?&](?:v|ver|version)=v?(\d+(?:\.\d+){0,3})"""),
    ),
    # 6) 库版权注释：/*! jQuery v3.6.0 | ... */
    (
        "lib_comment",
        re.compile(
            r"""(?i)(?:jquery|vue|react(?:-dom)?|angular(?:js)?|bootstrap|lodash|moment|axios|echarts|element-ui|element-plus|antd|d3|three|layui|swiper)\s+v?(\d[\w.\-]{0,12})"""
        ),
    ),
    # 7) 依赖声明：package.json 风格 "lodash": "^4.17.21"
    (
        "dep_decl",
        re.compile(
            r"""(?i)["'](?:jquery|vue|react(?:-dom)?|angular(?:js)?|bootstrap|lodash|moment|axios|echarts|element-ui|element-plus|antd|d3|three|layui|swiper)["']\s*:\s*["'](?:[\^~]|>=?|<=?)?v?(\d[\w.\-]{0,12})"""
        ),
    ),
]


@dataclass
class LocalFinding:
    ftype: str
    severity: str
    value: str
    context: str
    confidence: float
    reason: str = ""


@dataclass
class PrefilterResult:
    script_urls: list[str] = field(default_factory=list)
    chunk_urls: list[str] = field(default_factory=list)
    api_paths: list[str] = field(default_factory=list)
    source_map: str = ""
    findings: list[LocalFinding] = field(default_factory=list)
    snippets: str = ""


def decode(data: bytes) -> str:
    for enc in ("utf-8", "gb18030", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="ignore")


def extract_scripts(html: str) -> tuple[list[str], list[str]]:
    """返回 (外部 script src 列表, 内联脚本内容列表)。"""
    external = [m.group(1) for m in SCRIPT_SRC_RE.finditer(html)]
    inline = [m.group(1) for m in INLINE_SCRIPT_RE.finditer(html) if m.group(1).strip()]
    return external, inline


def _iter_hits(pattern: re.Pattern, text: str) -> list[tuple[int, int, str]]:
    out: list[tuple[int, int, str]] = []
    for m in pattern.finditer(text):
        value = m.group(1) if m.groups() else m.group(0)
        out.append((m.start(), m.end(), value))
    return out


def _context(text: str, start: int, end: int, ctx: int) -> str:
    return text[max(0, start - ctx): min(len(text), end + ctx)]


def _build_snippets(text: str, hits: list[tuple[int, int]], ctx: int, cap: int) -> str:
    """把命中位置扩成上下文窗口、合并重叠、截断到总字符上限。"""
    if not hits:
        return ""
    windows = sorted((max(0, s - ctx), min(len(text), e + ctx)) for s, e in hits)
    merged: list[list[int]] = []
    for a, b in windows:
        if merged and a <= merged[-1][1] + 20:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    parts: list[str] = []
    total = 0
    for a, b in merged:
        if total >= cap:
            break
        seg = text[a:b].strip()
        if not seg:
            continue
        remaining = cap - total
        if len(seg) > remaining:
            seg = seg[:remaining]
        parts.append(seg)
        total += len(seg) + 4
    return "\n\n-----\n\n".join(parts)


def prefilter_js(text: str, context: int = 100, cap: int = 12000) -> PrefilterResult:
    res = PrefilterResult()
    m = SOURCE_MAP_RE.search(text)
    if m:
        res.source_map = m.group(1)
    for m in CHUNK_RE.finditer(text):
        res.chunk_urls.append(m.group(1))
    for m in WEBPACK_CHUNK_RE.finditer(text):
        res.chunk_urls.append(m.group(0))
    for m in API_ABSOLUTE_RE.finditer(text):
        res.api_paths.append(m.group(1))
    for m in LINKFINDER_RE.finditer(text):
        s = m.group(1)
        if s and s not in res.api_paths:
            res.api_paths.append(s)

    hits: list[tuple[int, int]] = []
    for name, severity, pattern in SECRET_PATTERNS:
        for start, end, value in _iter_hits(pattern, text):
            conf = 0.9 if name in ("generic_secret", "jwt") else 0.95
            res.findings.append(LocalFinding(
                name, severity, value, _context(text, start, end, context), conf, "本地正则命中"
            ))
            hits.append((start, end))
    for name, pattern in VERSION_PATTERNS:
        for start, end, value in _iter_hits(pattern, text):
            res.findings.append(LocalFinding(
                "version", "low", value, _context(text, start, end, context), 0.7, name
            ))
            hits.append((start, end))
    res.snippets = _build_snippets(text, hits, context, cap)
    return res


def prefilter_text(text: str, context: int = 100, cap: int = 12000) -> PrefilterResult:
    """对 JSON / 内联脚本等非 JS 文本做轻量扫描：路径 + 密钥 + 版本（不进 LLM）。"""
    res = PrefilterResult()
    for m in API_ABSOLUTE_RE.finditer(text):
        res.api_paths.append(m.group(1))
    for m in LINKFINDER_RE.finditer(text):
        s = m.group(1)
        if s and s not in res.api_paths:
            res.api_paths.append(s)
    hits: list[tuple[int, int]] = []
    for name, severity, pattern in SECRET_PATTERNS:
        for start, end, value in _iter_hits(pattern, text):
            conf = 0.9 if name in ("generic_secret", "jwt") else 0.95
            res.findings.append(LocalFinding(
                name, severity, value, _context(text, start, end, context), conf, "本地正则命中"
            ))
            hits.append((start, end))
    for name, pattern in VERSION_PATTERNS:
        for start, end, value in _iter_hits(pattern, text):
            res.findings.append(LocalFinding(
                "version", "low", value, _context(text, start, end, context), 0.7, name
            ))
            hits.append((start, end))
    res.snippets = _build_snippets(text, hits, context, cap)
    return res
