# 前端代码审计 + 下载工具

递归下载目标网站的前端资源（HTML / JS / JSON / sourcemap），本地正则扫描敏感信息与接口路径，可选调用 DeepSeek 做二次语义审计。提供 CLI 和 Web UI 两种入口，另附纯下载模式。

## 功能

- 递归爬取：从种子 URL 出发，提取 HTML 中的 `<script>`、JS 中的 chunk/sourcemap，持续扩展下载范围，不做目录爆破。
- 本地正则扫描：密钥、Token、版本号、API 路径，零 token 成本。
- LLM 二次审计：把正则命中的可疑片段交给 DeepSeek 确认，默认只对 JS 开启，JSON 可按需开启。
- 接口探测：对发现的 API 路径发 OPTIONS / POST，判断可用方法与 CORS。
- 增强渲染：Playwright + CDP + JS Hook，捕获 SPA 动态加载的代码。
- 域名白名单约束：未配置白名单拒绝运行，递归不越界。

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
  domains: []            # 授权域名白名单，必填
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

## 输出报告

每次扫描在 `reports/<时间戳>/` 下生成：

- `report.md`：敏感信息表、接口探测表、节点明细。
- `full.json`：全量结构化数据。

## 注意事项

- 仅用于自有资产或已获书面授权的目标，遵守当地法律法规。
- 必须配置授权域名白名单，否则拒绝运行。
- QPS 根据目标承受能力调整，避免触发 WAF 或封禁。
