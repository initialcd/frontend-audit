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
    # 扩展：哈希类字段（permissionsHash / authorizationHash / csrfToken 等）
    (
        "hash_token",
        "medium",
        re.compile(
            r"""(?i)(?:permissions?[_-]?hash|authorization[_-]?hash|csrf[_-]?token|session[_-]?token|auth[_-]?token|signing[_-]?key|encryption[_-]?key|private[_-]?secret)["'`]?\s*[:=]\s*["'`]([0-9a-f]{32,128})["'`]"""
        ),
    ),
    # 硬编码经纬度/坐标（银行网点、ATM 位置泄露）
    (
        "hardcoded_coords",
        "low",
        re.compile(
            r"""(?i)(?:lat|lng|longitude|latitude|coord)["'`]?\s*[:=]\s*["'`]?(-?\d{1,3}\.\d{4,10})"""
        ),
    ),
    # --- 国内云服务凭证（实测样本：weshine SCRM 前端泄露腾讯创意云密钥）---
    # 腾讯云创意云 APPID：cc + 14位数字（如 cc20210224145031）
    ("creative_cloud_appid", "high", re.compile(r"\bcc\d{14}\b")),
    # 腾讯云创意云 SECRET：cc + 小写字母数字 25-40 位（如 ccjktx6spz7ys26643q9z15urjh183c1）
    (
        "creative_cloud_secret",
        "critical",
        re.compile(r"""["'](cc[a-z0-9]{25,40})["']"""),
    ),
    # 腾讯云 COS/API SecretId 变体：AKID 之外的其他腾讯云格式
    ("tencent_other_secret", "critical", re.compile(r"\bAK[0-9A-Za-z]{20,}\b")),
    # --- 企业微信/微信生态凭证 ---
    # 企业微信 corpid/appid：ww + 16位十六进制（如 wwf336afe442d36264）
    ("wecom_corpid", "high", re.compile(r"\bww[a-f0-9]{16}\b")),
    # 企业微信 agentId 声明：agentId = 4-10位数字
    ("wecom_agentid", "high", re.compile(r"""(?i)agentid["']?\s*[:=]\s*["']?(\d{4,10})""")),
    # 企业微信服务商凭证：suite_id / suite_ticket / pre_auth_code
    ("wecom_suite", "high", re.compile(r"""(?i)(?:suite_id|suite_ticket|pre_auth_code)\s*[:=]""")),
    # 微信开放平台 appid：wx + 16位十六进制（公众号/小程序）
    ("wechat_appid", "medium", re.compile(r"\bwx[a-f0-9]{16}\b")),
    # --- 内网/保留 IP 硬编码 ---
    (
        "internal_ip",
        "medium",
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
            r"192\.168\.\d{1,3}\.\d{1,3}|"
            r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
        ),
    ),
    # --- 自定义安全头/签名机制（可伪造签名风险）---
    # x-header-signature 等自定义签名头：签名算法通常在前端，可逆向伪造
    ("custom_sign_header", "high", re.compile(r"""(?i)x-[a-z0-9_-]*signature""")),
]

# ---------- CMS 敏感路径规则 ----------
# 当工具抓取到这些 URL 时，自动标记为安全发现（零 token 成本）。
# 格式：(路径模式正则, 发现类型, 严重级别, 说明)
CMS_SENSITIVE_PATHS: list[tuple[str, str, str, str]] = [
    # --- 依赖/配置文件泄露 ---
    (r"/composer\.json$", "dependency_file", "high", "composer.json 依赖声明泄露，可还原完整技术栈"),
    (r"/composer\.lock$", "dependency_file", "critical", "composer.lock 泄露精确版本号，可匹配所有已知 CVE"),
    (r"/vendor/composer/installed\.json$", "dependency_file", "critical", "installed.json 泄露所有依赖精确版本，攻击面完全暴露"),
    (r"/\.env$", "env_file", "critical", ".env 环境变量文件泄露，可能含数据库密码、API 密钥"),
    (r"/\.env\.\w+$", "env_file", "critical", ".env 变体文件泄露（.env.local / .env.production 等）"),
    (r"/\.git/HEAD$", "git_leak", "critical", ".git 目录泄露，可还原完整源码历史"),
    (r"/\.git/config$", "git_leak", "critical", ".git/config 泄露，含远程仓库地址和凭证"),
    (r"/\.svn/entries$", "vcs_leak", "high", ".svn 目录泄露，SVN 版本控制信息暴露"),
    # --- CMS 配置文件 ---
    (r"/sites/default/settings\.php$", "cms_config", "critical", "Drupal settings.php 泄露数据库密码、加密密钥"),
    (r"/sites/default/services\.yml$", "cms_config", "high", "Drupal services.yml 服务配置泄露"),
    (r"/sites/default/default\.settings\.php$", "cms_config", "medium", "Drupal 默认配置模板，可能含数据库连接示例"),
    (r"/wp-config\.php\.bak$", "cms_config", "critical", "WordPress 配置备份泄露"),
    (r"/configuration\.php$", "cms_config", "critical", "Joomla 配置文件泄露"),
    # --- 源码/敏感文件 ---
    (r"/core/includes/.*\.inc$", "source_disclosure", "high", "Drupal 核心 .inc 文件泄露，nginx 未配置 PHP 解析导致源码暴露"),
    (r"/core/modules/.*\.(?:install|module|inc)$", "source_disclosure", "medium", "Drupal 模块源码泄露"),
    (r"/themes/[^/]+/[^/]*\.(?:theme|info\.yml|libraries\.yml)$", "theme_source", "high", "Drupal 主题源码/配置泄露"),
    (r"/themes/custom/.*\.php$", "theme_source", "critical", "自定义主题 PHP 源码泄露"),
    (r"/modules/custom/.*\.php$", "module_source", "critical", "自定义模块 PHP 源码泄露"),
    (r"/vendor/bin/", "binary_exposure", "high", "vendor/bin 目录暴露，可能含可执行工具（drush 等）"),
    (r"/vendor/autoload\.php$", "vendor_exposure", "medium", "Composer 自动加载文件泄露"),
    # --- 管理后台/敏感路径 ---
    (r"/phpinfo\.php$", "admin_exposure", "high", "phpinfo.php 暴露完整服务器配置"),
    (r"/phpMyAdmin/", "admin_exposure", "critical", "phpMyAdmin 暴露数据库管理界面"),
    (r"/adminer\.php$", "admin_exposure", "critical", "Adminer 数据库管理工具暴露"),
    (r"/wp-admin/", "admin_exposure", "medium", "WordPress 后台入口暴露"),
    (r"/webmail/", "admin_exposure", "medium", "Webmail 入口暴露"),
    (r"/admin/config", "admin_exposure", "medium", "管理后台配置路径暴露"),
    (r"/debug/", "admin_exposure", "medium", "调试路径暴露"),
    (r"/test\.php$", "admin_exposure", "medium", "测试文件暴露"),
    (r"/backup\.(?:sql|tar\.gz|zip|rar)$", "backup_file", "critical", "数据库备份文件泄露"),
    (r"/db\.sql$", "backup_file", "critical", "数据库 SQL 备份泄露"),
    (r"/dump\.sql$", "backup_file", "critical", "数据库导出文件泄露"),
]

# ---------- 源码暴露检测 ----------
# 当 HTTP 响应内容包含 PHP/Python 源码特征，但 Content-Type 不是 application/x-php 等时，
# 判定为源码泄露。用在 orchestrator 层，配合 fetcher 的 content_type 做交叉判断。
SOURCE_CODE_SIGNATURES: list[tuple[str, re.Pattern]] = [
    ("php_open_tag", re.compile(r"<\?php\s")),
    ("php_echo", re.compile(r"<\?=\s*\$")),
    ("php_class_def", re.compile(r"(?:abstract\s+)?class\s+[A-Z]\w+\s+(?:extends|implements|\{)")),
    ("php_function_def", re.compile(r"(?:public|private|protected|static)\s+function\s+\w+\s*\(")),
    ("php_namespace", re.compile(r"namespace\s+[A-Z]\\")),
    ("php_use_statement", re.compile(r"^use\s+[A-Z]\\", re.M)),
    ("python_import", re.compile(r"^(?:from|import)\s+(?:os|sys|django|flask|requests)\b", re.M)),
    ("ruby_class", re.compile(r"class\s+\w+\s*<\s*(?:ActiveRecord|ApplicationController)")),
]

# PHP 文件后缀（nginx 交给 PHP-FPM 处理的）
_PHP_EXTENSIONS = frozenset({".php", ".phtml", ".php3", ".php4", ".php5", ".phps"})

# 不应该返回源码的 Content-Types
_SAFE_CONTENT_TYPES_FOR_PHP = frozenset({
    "text/html", "application/xhtml+xml", "application/json",
    "text/css", "image/svg+xml",
})


# ---------- 版本信息 ----------
# 每条规则的第一捕获组必须是版本号本身（_iter_hits 统一取 group(1)）。
# 前端库名列表统一维护：新增库只改这一处，三条指纹正则自动同步。
_LIB_NAMES = (
    r"jquery|vue(?:\.min)?|react(?:-dom)?|angular(?:js)?|bootstrap|lodash|moment|"
    r"axios|echarts|element-ui|element-plus|antd|d3|three|layui|swiper"
)

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
        re.compile(rf"""(?i)(?:{_LIB_NAMES})[./@-]v?(\d+(?:\.\d+){{0,3}})"""),
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
        re.compile(rf"""(?i)(?:{_LIB_NAMES})\s+v?(\d[\w.\-]{{0,12}})"""),
    ),
    # 7) 依赖声明：package.json 风格 "lodash": "^4.17.21"
    (
        "dep_decl",
        re.compile(rf"""(?i)["'](?:{_LIB_NAMES})["']\s*:\s*["'](?:[\^~]|>=?|<=?)?v?(\d[\w.\-]{{0,12}})"""),
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


def _scan_segment(
    text: str, context: int, skip_start: int | None = None
) -> tuple[list[LocalFinding], list[tuple[int, int]]]:
    """扫描单块文本的密钥 + 版本，返回 (findings, 命中偏移)。

    skip_start：块内偏移，>= 该偏移的命中跳过（分块时交给下一块重叠区处理，避免重复）。
    """
    findings: list[LocalFinding] = []
    hits: list[tuple[int, int]] = []
    for name, severity, pattern in SECRET_PATTERNS:
        for start, end, value in _iter_hits(pattern, text):
            if skip_start is not None and start >= skip_start:
                continue
            conf = 0.9 if name in ("generic_secret", "jwt") else 0.95
            findings.append(LocalFinding(
                name, severity, value, _context(text, start, end, context), conf, "本地正则命中"
            ))
            hits.append((start, end))
    for name, pattern in VERSION_PATTERNS:
        for start, end, value in _iter_hits(pattern, text):
            if skip_start is not None and start >= skip_start:
                continue
            findings.append(LocalFinding(
                "version", "low", value, _context(text, start, end, context), 0.7, name
            ))
            hits.append((start, end))
    return findings, hits


def _scan_patterns(text: str, context: int, cap: int) -> tuple[list[LocalFinding], str]:
    """整块扫描密钥 + 版本，返回 (findings, snippets)。"""
    findings, hits = _scan_segment(text, context)
    return findings, _build_snippets(text, hits, context, cap)


def _scan_chunked(
    text: str, context: int, cap: int, chunk_size: int
) -> tuple[list[LocalFinding], str]:
    """大文本按块扫描密钥 + 版本：块间带重叠避免边界漏报，命中不重复。"""
    if len(text) <= chunk_size:
        return _scan_patterns(text, context, cap)
    overlap = context * 2 + 512
    if overlap >= chunk_size:
        overlap = chunk_size // 4
    findings: list[LocalFinding] = []
    parts: list[str] = []
    used = 0
    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        seg = text[start:end]
        last = end >= len(text)
        skip_start = None if last else max(0, len(seg) - overlap)
        seg_findings, hits = _scan_segment(seg, context, skip_start)
        findings.extend(seg_findings)
        if used < cap:
            s = _build_snippets(seg, hits, context, cap)
            if s:
                remaining = cap - used
                if len(s) > remaining:
                    s = s[:remaining]
                parts.append(s)
                used += len(s) + 4
        if last:
            break
        start = end - overlap
    return findings, "\n\n-----\n\n".join(parts)


def prefilter_js(
    text: str, context: int = 100, cap: int = 12000, chunk_kb: int | None = None
) -> PrefilterResult:
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

    if chunk_kb and chunk_kb > 0:
        res.findings, res.snippets = _scan_chunked(text, context, cap, chunk_kb * 1024)
    else:
        res.findings, res.snippets = _scan_patterns(text, context, cap)
    # 逻辑型发现：签名/请求保护机制（独立于正则值型发现的组合检测）
    res.findings.extend(detect_signature_mechanism(text, context))
    return res


def prefilter_text(
    text: str, context: int = 100, cap: int = 12000, chunk_kb: int | None = None
) -> PrefilterResult:
    """对 JSON / 内联脚本等非 JS 文本做轻量扫描：路径 + 密钥 + 版本（不进 LLM）。"""
    res = PrefilterResult()
    for m in API_ABSOLUTE_RE.finditer(text):
        res.api_paths.append(m.group(1))
    for m in LINKFINDER_RE.finditer(text):
        s = m.group(1)
        if s and s not in res.api_paths:
            res.api_paths.append(s)
    if chunk_kb and chunk_kb > 0:
        res.findings, res.snippets = _scan_chunked(text, context, cap, chunk_kb * 1024)
    else:
        res.findings, res.snippets = _scan_patterns(text, context, cap)
    return res


# ============================================================
# 新增：CMS 敏感路径分析 + 源码暴露检测
# ============================================================

def analyze_url_for_cms_findings(url: str) -> list[LocalFinding]:
    """分析 URL 路径是否命中 CMS 敏感路径规则库。

    纯路径匹配，零网络开销，在 orchestrator._process 阶段调用。
    """
    from urllib.parse import urlparse as _urlparse
    findings: list[LocalFinding] = []
    try:
        path = _urlparse(url).path
    except Exception:  # noqa: BLE001
        return findings
    for pattern, ftype, severity, reason in CMS_SENSITIVE_PATHS:
        if re.search(pattern, path, re.I):
            findings.append(LocalFinding(
                ftype=ftype,
                severity=severity,
                value=path,
                context=f"URL 路径匹配: {path}",
                confidence=0.9,
                reason=reason,
            ))
    return findings


def detect_source_code_exposure(
    body: bytes, url: str, content_type: str
) -> list[LocalFinding]:
    """检测源码暴露：当响应内容包含 PHP/Python 源码特征但 Content-Type 不应含源码时。

    专门针对 nginx 配置错误导致 .inc/.module 等文件返回源码的场景。
    在 orchestrator._process 阶段，拿到 fetcher 响应后调用。
    """
    findings: list[LocalFinding] = []
    if not body:
        return findings

    # 如果 Content-Type 已经是 PHP 相关，那是正常执行，不算泄露
    ct_lower = content_type.lower()
    if "php" in ct_lower or "x-httpd" in ct_lower:
        return findings

    # 仅对非 PHP content-type 检测源码特征
    # 如果是 text/html 但内容实际是 PHP 源码 → 这是泄露
    try:
        text = body.decode("utf-8", errors="ignore")[:50000]  # 只看前 50KB
    except Exception:  # noqa: BLE001
        return findings

    matched_signatures: list[str] = []
    for name, pattern in SOURCE_CODE_SIGNATURES:
        if pattern.search(text):
            matched_signatures.append(name)

    # 至少命中 2 个 PHP 特征才判定为源码泄露（避免误报）
    php_hits = [s for s in matched_signatures if s.startswith("php_")]
    if len(php_hits) >= 2:
        from urllib.parse import urlparse as _urlparse
        path = ""
        try:
            path = _urlparse(url).path
        except Exception:  # noqa: BLE001
            pass
        findings.append(LocalFinding(
            ftype="source_code_disclosure",
            severity="high",
            value=path,
            context=f"Content-Type: {content_type} | PHP 特征: {', '.join(php_hits[:5])}",
            confidence=0.95,
            reason=(
                f"响应包含 PHP 源码特征 ({', '.join(php_hits[:3])})，"
                f"但 Content-Type 为 {content_type}，疑似 nginx 配置错误导致源码泄露"
            ),
        ))
    elif matched_signatures:
        # 只有 1 个特征，低置信度
        from urllib.parse import urlparse as _urlparse
        path = ""
        try:
            path = _urlparse(url).path
        except Exception:  # noqa: BLE001
            pass
        findings.append(LocalFinding(
            ftype="source_code_disclosure",
            severity="medium",
            value=path,
            context=f"Content-Type: {content_type} | 特征: {', '.join(matched_signatures)}",
            confidence=0.6,
            reason=f"响应包含代码特征 ({', '.join(matched_signatures)})，可能为源码泄露",
        ))

    return findings


def detect_json_config_secrets(text: str) -> list[LocalFinding]:
    """扫描 JSON 配置块（如 drupal-settings-json）中的敏感字段。

    专门针对 <script type="application/json"> 中的配置泄露。
    比 generic_secret 更宽泛：捕获哈希、签名密钥、session 相关字段。
    """
    findings: list[LocalFinding] = []
    # 匹配 JSON key:value 中 value 为长十六进制串的情况
    # 例：{"permissionsHash":"0ee66c0b...d5b5"}
    for m in re.finditer(
        r"""["']([\w.-]{3,50})["']\s*:\s*["']([0-9a-f]{32,128})["']""",
        text,
    ):
        key, value = m.group(1), m.group(2)
        # 只关注安全相关字段
        security_keywords = (
            "hash", "token", "secret", "key", "sign",
            "auth", "csrf", "session", "nonce", "signature",
        )
        if any(kw in key.lower() for kw in security_keywords):
            findings.append(LocalFinding(
                ftype="config_hash_leak",
                severity="high",
                value=f"{key}={value[:32]}...",
                context=m.group(0)[:200],
                confidence=0.8,
                reason=f"JSON 配置块中安全相关字段 '{key}' 泄露哈希值，可能用于会话伪造或权限绕过",
            ))
    return findings


# ---------- 签名机制 / 请求保护逻辑检测 ----------
# 前端出现"自定义签名头 + 拦截器注入 + hash 算法"组合时，说明整个 API 网关的
# 签名/防篡改算法暴露在客户端 JS 中，可被逆向并随意伪造——这是高价值逻辑型发现
# （区别于上面的值型密钥泄露）。参考样本：weshine SCRM 的 paramsHandler.js。
SIGN_HEADER_RE = re.compile(r"""["']x-[a-z0-9_-]*signature["']""", re.I)
MD5_CALL_RE = re.compile(r"\bmd5\s*\(", re.I)
SHA_CALL_RE = re.compile(r"\b(?:sha1|sha256|sha512)\s*\(", re.I)
SET_HEADER_RE = re.compile(r"""setRequestHeader\s*\(""", re.I)
APPEND_HEADER_RE = re.compile(r"""headers\s*\[\s*["']x-[a-z0-9_-]*signature["']\s*\]""", re.I)


def detect_signature_mechanism(text: str, context: int = 120) -> list[LocalFinding]:
    """检测前端签名/请求保护机制（逻辑型泄露，非值型）。

    命中组合：
    - 自定义 x-*-signature 头（SIGN_HEADER_RE / APPEND_HEADER_RE）
    - 同时伴随 hash 算法调用（md5/sha）。
    返回的 finding 指向"签名算法可在前端逆向"这一事实。
    """
    findings: list[LocalFinding] = []
    hits: list[tuple[int, int]] = []

    for pat in (SIGN_HEADER_RE, APPEND_HEADER_RE):
        for m in pat.finditer(text):
            hits.append((m.start(), m.end()))

    if not hits:
        return findings

    has_hash = bool(MD5_CALL_RE.search(text) or SHA_CALL_RE.search(text))
    has_set_header = bool(SET_HEADER_RE.search(text))

    # 合并重叠命中，取唯一上下文
    merged: list[list[int]] = []
    for a, b in sorted(hits):
        if merged and a <= merged[-1][1] + 40:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])

    for a, b in merged:
        ctx_text = text[max(0, a - context): min(len(text), b + context)].strip().replace("\n", " ")
        sig_name = text[a:b][:80]
        reason_parts = ["前端代码中存在自定义签名头"]
        if has_hash:
            reason_parts.append("且调用 hash 算法(md5/sha)")
        if has_set_header:
            reason_parts.append("且通过 setRequestHeader 注入请求头")
        reason_parts.append("——签名/防篡改算法暴露在客户端，可被逆向伪造")
        findings.append(LocalFinding(
            ftype="signature_mechanism",
            severity="high",
            value=sig_name,
            context=ctx_text[:300],
            confidence=0.85,
            reason="".join(reason_parts),
        ))
    return findings
