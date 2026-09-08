# 前端代码审计 + 下载工具

递归下载目标网站的前端资源（HTML / JS / JSON / sourcemap），本地正则扫描敏感信息与接口路径，可选调用 DeepSeek 做二次语义审计。提供 CLI 和 Web UI 两种入口，另附纯下载模式。

## 功能

- 递归爬取：从种子 URL 出发，提取 HTML 中的 `<script>`、JS 中的 chunk/sourcemap，持续扩展下载范围，不做目录爆破。
- 本地正则扫描：密钥、Token、版本号、API 路径，零 token 成本。
- LLM 二次审计：把正则命中的可疑片段交给 DeepSeek 确认，默认只对 JS 开启，JSON 可按需开启。
- 接口探测：对发现的 API 路径发 OPTIONS / POST，判断可用方法与 CORS。
- 增强渲染：Playwright + CDP + JS Hook，捕获 SPA 动态加载的代码。
- 域名白名单约束：未配置白名单拒绝运行，递归不越界。
- 多主域名并存：白名单支持多个主域名，资产按"最长匹配主域名"自动分组，各组独立配额互不挤占。
- Web UI 实时结果：扫描运行中「发现/接口/节点」选项卡动态刷新，无需等任务完成。

## 安装

```bash
pip install -r requirements.txt
```

需要 SPA 动态渲染时，额外安装 Playwright 浏览器：

```bash
pip install playwright
python -m playwright install chromium
```

## 配置

复制 `config.example.yaml` 为 `config.yaml` 后按需修改。DeepSeek API Key 也可通过环境变量 `DEEPSEEK_API_KEY` 提供，避免写入文件。

```yaml
deepseek:
  api_key: ""            # DeepSeek API Key，留空则关闭 LLM
  base_url: "https://api.deepseek.com"
  model: "deepseek-chat"

scan:
  concurrency: 20        # 并发请求数
  per_domain_qps: 5.0    # 每域名每秒请求上限
  timeout: 15.0
  retries: 2
  max_depth: 5           # 递归深度，种子为第 0 层
  max_nodes_per_domain: 2000
  max_total_nodes: 10000
  max_body_kb: 51200     # 响应体硬上限（KB），超过丢弃保护内存（默认 50MB）
  chunk_scan_kb: 2048    # 大文本分段扫描块大小（KB），超过则分块 prefilter
  llm_enabled: true      # 是否启用 LLM 审计
  audit_json: false      # 是否对 JSON 也送 LLM（默认关）
  llm_full_audit: false  # 全量片段送 LLM：对无正则命中但可能有语义漏洞的 JS 也送全文片段
  llm_full_audit_domains: []  # 特定域名白名单：命中则全量片段送 LLM
  render_mode: "hybrid"  # off / hybrid / full

scope:
  domains: []            # 授权域名白名单，必填（支持多主域名，见下文）
  allow_subdomains: true

proxy:
  enabled: false
  mode: "local"          # local / api
  local_url: "http://127.0.0.1:8080"

storage:
  db_path: "state.db"
  output_dir: "reports"
```

域名白名单也可以在命令行用 `--domains` 覆盖，或 Web UI 中填写。

## 多主域名白名单

白名单支持多个主域名并存，常见写法都能识别（自动清洗协议/端口/大小写，防后缀绕过）：

- 分隔符：半角逗号 `,`、中文逗号 `，`、顿号 `、`、分号 `;`、换行、空白均可
- `https://a.com`、`b.com:8080`、`SUb.A.com` 均会归一为纯域名 `a.com` / `b.com`
- 每个 URL 归属白名单中"最长匹配"的主域名分组（`example.com` 与 `sub.example.com` 同在白名单时，
  `sub.example.com` 的资产归入更具体的 `sub.example.com` 组）
- 每个主域名（含其子域）按 `max_nodes_per_domain` 独立配额：A 主域名的预算不会被 B 主域名挤占，
  同时 URL 全局去重，跨域名引用的资产不会重复抓取

```bash
# 同时扫描多个主域名
python main.py -u urls.txt --domains "a.com，b.com"    # 中文逗号也可以
python main.py -u urls.txt --domains "https://a.com,sub.b.com:8443"
```

## CLI 用法

### 审计模式

```bash
# 从 URL 清单扫描
python main.py -u urls.txt -c config.yaml

# 单个 URL
python main.py -u https://target.example.com --domains target.example.com

# 关闭 LLM，仅本地正则
python main.py -u urls.txt --domains example.com --no-llm

# JSON 也送 LLM 审计
python main.py -u urls.txt --domains example.com --audit-json
```

### 下载模式

只递归下载前端资源到本地，不审计、不调 LLM、不探测接口。递归引擎与审计模式一致。

```bash
python main.py --download -u https://target.example.com/ --domains target.example.com -o ./dump

# 批量下载
python main.py --download -u targets.txt --domains example.com -o ./dump -d 3
```

下载目录结构按 `输出目录/域名/URL路径` 保存。

### 参数表

| 参数 | 默认 | 说明 |
|------|------|------|
| `-u` / `--urls` | 必填 | URL 清单文件或单个 URL |
| `-c` / `--config` | `config.yaml` | 配置文件路径 |
| `-d` / `--depth` | 配置值 | 覆盖递归深度 |
| `--domains` | 配置值 | 覆盖域名白名单，逗号分隔 |
| `--no-llm` | 关 | 关闭 LLM，仅本地正则 |
| `--audit-json` | 关 | JSON 内容也送 LLM 审计 |
| `--download` | 关 | 下载模式 |
| `-o` / `--output` | `downloads` | 下载模式输出目录 |
| `-v` / `--verbose` | 关 | 输出 DEBUG 日志 |

## Web UI 用法

```bash
python webui.py            # 默认 http://127.0.0.1:8000
python webui.py -p 9000
```

在页面填写授权扫描清单（每行一个 URL）和域名白名单，调整深度、并发、QPS，勾选是否启用 LLM、是否对 JSON 送 LLM、是否启用代理，然后点击开始。运行中可实时改并发/深度并应用，无需重跑。完成后可下载 `report.md` 和 `full.json`。

`audit_json` 开关仅在勾选「启用 DeepSeek 审计」时可用；未配置 API Key 时自动禁用。

## 递归 vs 目录爆破

工具采用递归爬取：只下载页面代码里实际引用的资源。它能覆盖带 hash 的动态文件名（如 `chunk-2d0a3b4c.js`）；目录爆破靠字典猜路径，无法命中这类文件名，且产生大量 404 噪声。

## 存活探测方式（要不要内置 httpx？）

**httpx 不是外置二进制，而是本工具已经依赖的 Python HTTP 库**（`requirements.txt` 第一行，
`core/fetcher.py` 用它发起全部请求），不需要额外"内置"。

本工具没有独立的"存活探测阶段"：**每次抓取本身就是预检**，见 `core/fetcher.py`：

1. 并发 GET 请求，先看响应头；
2. 只把 `2xx/3xx` 当作存活；`4xx/5xx` 记状态但不读 body（死链零成本跳过）；
3. Content-Type 不在白名单（图片/视频/下载文件等）不下载 body；
4. 响应体超过 `max_body_kb` 丢弃保护内存；
5. 失败自动重试（`retries` 次，指数退避），死主机消耗约 1 次超时即被跳过；
6. 每域 QPS 限速（`per_domain_qps`），限速间隔带 `qps_jitter` 抖动打散节奏。

这套"预检即探测"的优点是省去一轮独立的 HEAD/存活扫描（少一半请求、更快）；缺点是不会像
httpx 那样一次性把一批存活 URL 列出来。若你需要"先列存活清单再审计"两阶段模式，可以在
`--download` 模式跑一遍拿全量节点，或在此基础上加一个 `HEAD` 预检阶段（当前实现刻意不做，
因为对大部分站点 HEAD 并不比 GET 头快，反而多一轮往返）。

## 会被防火墙 / WAF 拦截吗？

工具本身只做**静态抓取 + 本地正则 + 可选 LLM 审计**，不发送攻击载荷，因此不会因为"攻击行为"
被拦截；但**请求频率与指纹**仍可能触发防护：

- **高并发是最大诱因**：全局并发默认 20、每域 QPS 默认 5/s，大多数站点安全；把并发拉到
  100–500 且提高 QPS 时，教育/政务等部署了 WAF 的站点很容易封 IP 或弹验证码。
- **接口探测更像"扫描"**：OPTIONS/POST 探测（`core/method_prober.py`）在 WAF 眼里属于主动探测
  行为，建议保持 `max_method_probes` 上限，必要时只保留 OPTIONS。
- **降低被识别概率的手段**：每域 QPS 调低（1–3/s）、保留 `qps_jitter` 抖动、走代理池
  （`proxy.enabled`）、使用真实浏览器 UA（默认已带）、避免对同一站点长时间高频递归。
- 目标站点防护强度未知时，先小并发试跑一轮看是否有验证码/429，再决定是否加码。

## 输出报告

每次扫描在 `reports/<时间戳>/` 下生成：

- `report.md`：敏感信息表、接口探测表、节点明细。
- `full.json`：全量结构化数据。

## 注意事项

- 仅用于自有资产或已获书面授权的目标，遵守当地法律法规。
- 必须配置授权域名白名单，否则拒绝运行。
- QPS 根据目标承受能力调整，避免触发 WAF 或封禁。
