# 前端代码审计 + 下载工具

递归下载目标网站的前端资源（HTML / JS / JSON / sourcemap），本地正则扫描敏感信息与接口路径，可选调用 DeepSeek 做二次语义审计。提供 CLI 和 Web UI 两种入口，两者都内置纯下载模式：不审计、不调 LLM、不需要 API Key，可完全离线运行。

## 功能

- 双模式：仅下载（离线可用）与审计（可选 LLM），共用同一套递归引擎。
- 递归爬取：从种子 URL 出发，提取 HTML 中的 `<script>`、JS 中的 chunk 与 sourcemap，持续扩展范围，不做目录爆破。
- 本地正则扫描：密钥、Token、版本号、API 路径，不消耗 token。
- CMS 敏感路径检测：按路径规则库标记依赖与配置泄露，详见下文。
- 源码暴露检测：响应体含源码特征但 Content-Type 不对时判定泄露。
- JSON 配置块分析：内联 JSON 中的安全字段哈希泄露检测。
- LLM 二次审计：把正则命中的可疑片段交给 DeepSeek 确认，默认只对 JS 开启，JSON 可按需开启。未配置 Key 时自动降级为纯本地正则，不报错、不中断。
- 接口探测：对发现的 API 路径发 OPTIONS / POST，判断可用方法与 CORS。
- 增强渲染：Playwright + CDP + JS Hook，捕获 SPA 动态加载的代码。
- 域名白名单约束：未配置白名单拒绝运行，递归不越界。
- 多主域名并存：白名单支持多个主域名，资产按最长匹配分组，各组独立配额。
- Web UI 实时结果：运行中「发现 / 接口 / 节点 / 文件」选项卡动态刷新，无需等任务完成。

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

不需要 API Key，可完全离线运行。

```bash
python main.py --download -u https://target.example.com/ --domains target.example.com -o ./dump

# 批量下载
python main.py --download -u targets.txt --domains example.com -o ./dump -d 3
```

目录结构按 `输出目录/域名/URL路径` 保存，无后缀文件按 Content-Type 补 `.js` / `.json` / `.html` / `.css`。

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
python webui.py -c config.local.yaml   # 指定配置
```

页面左上角先选运行模式，两种模式共用同一套递归引擎。

仅下载是默认项，离线可用。它只做递归抓取存盘，不审计、不调 LLM、不需要 API Key，界面显示「进度 / 节点 / 文件」三个选项卡，可指定输出目录。

审计模式在抓取基础上做敏感信息审计和接口发现，显示「发现 / 接口 / 节点」选项卡，完成后可下载 `report.md` 与 `full.json`。未配置 API Key 时页面会提示将自动降级为纯本地正则，效果等同 CLI 的 `--no-llm`。

两种模式都支持运行中改并发和深度并即时应用、暂停继续、取消。下载完成后在「文件」选项卡查看落盘清单，可导出 JSON 或 TXT，同时在输出目录写入 `_manifest.json`。

### 离线环境

不通外网时按下面配置：

1. 模式选仅下载，全程不触碰 LLM，不需要任何 Key。
2. 增强渲染选 `off`，否则会因缺少 Playwright 浏览器而空等。
3. 确实需要审计能力时，选审计模式但不勾选 LLM，纯本地正则，零外网依赖。

Web UI 每次任务使用独立的 `state-ui.db` 并在启动时清理，不做跨次断点续跑；CLI 的 `state.db` 则持久保留。同一个 URL 在 CLI 下重复执行会因去重而显示"成功 0"，属预期行为，想全量重跑请删除 `state.db`。

## 递归 vs 目录爆破

工具采用递归爬取，只下载页面代码里实际引用的资源，能覆盖带 hash 的动态文件名（如 `chunk-2d0a3b4c.js`）。目录爆破靠字典猜路径，命中不了这类文件名，还会产生大量 404 噪声。

## 存活判断

工具没有独立的存活探测阶段，每次抓取本身就是预检，实现在 `core/fetcher.py`：

1. 并发 GET，只取响应头；
2. `2xx/3xx` 视为存活；`4xx/5xx` 只记状态码，不读响应体；
3. Content-Type 不在白名单（图片、视频、下载文件等）不下载；
4. 响应体超过 `max_body_kb` 直接丢弃，防止大文件撑爆内存；
5. 失败按 `retries` 次指数退避重试，死主机约一次超时即被跳过；
6. 每域 QPS 限速，间隔带 `qps_jitter` 抖动，避免固定节奏。

这么做的代价是拿不到一份独立的"存活 URL 清单"。需要那种效果，可以在下载模式跑一遍收集全量节点，再针对结果做审计。

## 请求特征与触发防护的风险

工具只做静态抓取、本地正则和可选的 LLM 审计，不发送攻击载荷，因此不会因为载荷本身被拦。但请求频率和指纹仍可能触发防护：

- 全局并发默认 20、每域 QPS 默认 5/s，多数站点无压力。并发提到 100-500 并抬高 QPS 后，部署了 WAF 的站点很容易封 IP 或弹验证码。
- 接口探测（`core/method_prober.py` 的 OPTIONS/POST）在 WAF 看来属于主动探测，建议保留 `max_method_probes` 上限，必要时只留 OPTIONS。
- 降低触发概率：每域 QPS 压到 1-3/s、保留 `qps_jitter` 抖动、走代理池、使用浏览器 UA（默认已带）、避免对同一站点长时间高频递归。
- 摸不清目标防护强度时，先用小并发试跑一轮，看有无验证码或 429，再决定是否加码。

## 检测规则

零 token 成本的本地检测全部在 `core/prefilter.py`。

### CMS 敏感路径（`CMS_SENSITIVE_PATHS`）

对抓取到的 URL 路径做正则匹配，命中即入库。已覆盖：

| 类别 | 示例路径 | 严重级别 |
|------|---------|---------|
| 依赖声明 | `/composer.json`、`/composer.lock` | high / critical |
| 精确版本 | `/vendor/composer/installed.json` | critical |
| 环境变量 | `/.env`、`/.env.production` | critical |
| 版本控制 | `/.git/HEAD`、`/.git/config`、`/.svn/entries` | critical / high |
| CMS 配置 | `/sites/default/settings.php`、`/services.yml` | critical / high |
| 源码泄露 | `/core/includes/*.inc`、`/themes/*/*.theme|*.info.yml` | high |
| 可执行文件 | `/vendor/bin/...`（drush 等） | high |
| 管理入口 | `/phpMyAdmin/`、`/adminer.php`、`/phpinfo.php` | critical / high |
| 备份文件 | `/backup.sql`、`/db.sql`、`/dump.sql` | critical |

添加规则就往 `CMS_SENSITIVE_PATHS` 追加 `(正则, 类型, 严重级别, 说明)`。

### 源码暴露（`detect_source_code_exposure`）

响应体含 PHP/Python/Ruby 源码特征（`<?php`、`class X extends`、`function`、`namespace`、`import` 等），但 Content-Type 不是源码类型（`text/plain`、`text/html`）时判定源码泄露。典型场景是 nginx 只对 `.php` 走 PHP-FPM，`.inc` / `.module` / `.theme` 被当静态文件原样返回。

为控制误报，命中 2 个以上 PHP 特征才算 high，单项命中只记 medium。

### JSON 配置块哈希泄露（`detect_json_config_secrets`）

扫描内联 `<script type="application/json">`（如 Drupal 的 `drupal-settings-json`）中的安全字段：`permissionsHash`、`csrfToken`、`sessionToken`、`nonce` 等命名的 32-128 位十六进制值，可用于会话伪造或权限绕过。`generic_secret` 正则另有 `hash_token` 规则。

### 云服务与企业微信凭证（`SECRET_PATTERNS`）

| 规则 | 正则特征 | 严重级别 |
|------|---------|---------|
| `creative_cloud_appid` | `cc` + 14 位数字 | high |
| `creative_cloud_secret` | `cc` + 小写字母数字 25-40 位 | critical |
| `tencent_other_secret` | `AK` + 20 位以上 | critical |
| `wecom_corpid` | `ww` + 16 位十六进制 | high |
| `wecom_agentid` | `agentId = 4-10 位数字` | high |
| `wecom_suite` | `suite_id` / `suite_ticket` / `pre_auth_code` | high |
| `wechat_appid` | `wx` + 16 位十六进制 | medium |
| `internal_ip` | RFC1918 内网 IP | medium |
| `custom_sign_header` | `x-*-signature` 自定义头 | high |

`ww` / `wx` 开头的 appid 若没命中，可能是运行时从接口动态获取的，不在静态 JS 里。这是静态审计的边界，需要结合动态测试。

### 签名机制（`detect_signature_mechanism`）

这是逻辑型发现，不是值型密钥。当 JS 中同时出现自定义签名头（`x-*-signature`）、hash 算法调用（`md5()` / `sha*()`）和 `setRequestHeader()` 注入时，判定签名算法暴露在客户端，可被逆向伪造：

```javascript
var signature = md5(str);
_this.setRequestHeader('x-header-signature', signature.toUpperCase());
```

报告类型为 `signature_mechanism`，severity `high`。

### LLM 提示词（`prompts/audit.md`）

- 识别签名机制组合，报告 `signature_mechanism`
- 识别企业微信 / 腾讯创意云凭证，报告 `wecom_credential`
- 接口含 `isToken: true` 或路径含 `/public/` 时，在 note 标注为免认证接口

## 输出报告

每次扫描在 `reports/<时间戳>/` 下生成：

- `report.md`：敏感信息表、接口探测表、节点明细。
- `full.json`：全量结构化数据。

## 注意事项

- 仅用于自有资产或已获书面授权的目标，遵守当地法律法规。
- 必须配置授权域名白名单，否则拒绝运行。
- QPS 根据目标承受能力调整，避免触发 WAF 或封禁。
