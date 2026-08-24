# 前端代码批量审计工具 — 功能讲解

## 一、这个工具是做什么的？

简单来说，这个工具可以**自动访问你指定的网站，把前端代码（网页源码、JavaScript 文件）全部下载下来，然后自动扫描里面有没有泄露的敏感信息**，比如：

- 账号密码
- 云服务密钥（阿里云、腾讯云、AWS 的 AccessKey / SecretKey）
- API 接口地址
- 数据库连接串
- 各种 Token、私钥、第三方服务凭证

同时，它还会**自动发现网站背后隐藏的 API 接口路径**，并尝试探测这些接口支持哪些请求方法（GET、POST、OPTIONS 等），帮你梳理出完整的接口清单。

---

## 二、核心功能一览

### 1. 网站资源自动下载

你把一个网站 URL 列表交给工具，它会：

- 自动访问每个 URL，下载网页（HTML）和 JavaScript 文件
- 从 HTML 中提取 `<script>` 标签引用的外部 JS 文件，一并下载
- 从 JS 文件中提取动态加载的 chunk 分包、sourcemap 文件，继续下载
- 自动跳过图片、字体、视频等静态资源（不浪费时间和流量）
- 支持断点续跑：如果中途中断了，下次运行会自动跳过已经下载过的内容

### 2. 正则匹配敏感信息（本地扫描，零成本）

工具内置了大量正则表达式规则，可以在下载到的代码中自动匹配以下敏感信息：

| 类型 | 说明 |
|------|------|
| 阿里云 AK | `LTAI` 开头的 AccessKey |
| 腾讯云 AK | `AKID` 开头的密钥 |
| AWS AK | `AKIA` / `ASIA` 开头的密钥 |
| OpenAI API Key | `sk-` 开头的密钥 |
| GitHub Token | `ghp_` / `ghs_` 等开头的令牌 |
| Google API Key | `AIza` 开头的密钥 |
| JWT Token | 三段式 Base64 编码的令牌 |
| 私钥 | `-----BEGIN PRIVATE KEY-----` 格式的私钥文件内容 |
| 数据库连接串 | `mongodb://`、`mysql://`、`redis://` 等含账号密码的连接地址 |
| 通用密码/Token | 代码中 `password = "xxx"`、`secret = "xxx"` 等硬编码 |
| 第三方凭证 | Slack Token、Stripe 支付密钥等 |

这些正则匹配完全在本地运行，**不需要联网、不消耗任何费用**。

### 3. API 路径智能发现（LinkFinder 级别正则）

这个功能就是你提到的"**正则匹配路径**"——工具使用了业界知名的 **LinkFinder 正则模式**，能从 JS 代码的字符串字面量中精准提取出 API 接口路径，包括：

- 绝对路径：`https://api.example.com/v1/users`
- 相对路径：`/api/v1/login`、`../admin/config`
- 带扩展名的路径：`/user/info.action`、`/data/list.json`、`/config.php`
- 字符串拼接的路径：`"/api/" + version + "/user"` 也会被提取出来

**发现路径后，工具会自动递归访问这些路径**（限定在白名单范围内），如果返回的是 HTML 或 JS，就继续下载和审计，形成"发现 → 下载 → 再发现 → 再下载"的递归链条。

### 4. DeepSeek AI 智能审计（可选）

对于本地正则无法覆盖的复杂场景（比如各种奇怪的编码方式、业务逻辑中硬编码的凭证），工具可以调用 DeepSeek 大模型进行二次审计。

**但是不会浪费钱**——只有本地正则命中了可疑内容，才会把命中位置周围的一小段代码（约 200 字符）发给 AI 确认，不会把整个文件发过去。这叫做"Token 漏斗"设计，每一层都尽量便宜。

不想用 AI 的话，可以关掉，工具会变成纯本地正则模式，完全免费。

### 5. 接口多方法探测

发现 API 路径后，工具会自动用 OPTIONS 和 POST 方法去探测：

- **OPTIONS**：查看接口支持哪些 HTTP 方法（Allow 头），以及是否允许跨域（CORS 头）
- **POST**：发送空请求体，查看接口返回什么状态码（判断接口是否存在）

安全保护：路径中包含 `delete`、`upload`、`pay`、`order`、`reset` 等危险词的，会自动跳过 POST 探测，避免误触发业务操作。

### 6. 增强渲染引擎 — 前端代码近全覆盖下载（v2.0 新增）

这是本工具最强大的功能。普通的 HTTP 请求工具只能下载 HTML 中直接引用的 JS 文件，面对现代前端应用（Vue、React、Angular 等）会大量遗漏。增强渲染引擎通过**三层捕获机制**，将前端代码覆盖率从 ~60% 提升到 ~95%。

#### 三层捕获机制

**第一层：CDP 协议层拦截（核心）**

通过 Chrome DevTools Protocol 直接监听浏览器内核层面的**所有网络请求和响应**。浏览器加载的每一个 JS 文件——无论是通过 `<script>` 标签、`import()`、`fetch()`、`XMLHttpRequest` 还是 WebSocket 加载的——都能被完整捕获。

```
传统方式：用正则猜 URL → 发请求验证 → 漏掉大量动态加载的 JS
CDP 方式：浏览器发出的每一个请求 → 全部拦截记录 → 一个不漏
```

**第二层：JS 运行时 Hook（深层）**

在页面中注入 JavaScript 拦截代码，捕获以下动态代码执行：

| Hook 目标 | 说明 |
|-----------|------|
| `eval()` | 拦截通过 eval 执行的动态代码 |
| `new Function()` | 拦截通过 Function 构造函数执行的代码 |
| `document.createElement('script')` | 拦截动态创建的 script 标签 |
| `MutationObserver` | 监听 DOM 中新增的 script 和 iframe 元素 |
| `WebSocket` | 拦截 WebSocket 连接和消息发送 |

**第三层：全交互自动化（广度）**

不再只是点击 `<a>` 和 `<button>`，而是模拟完整用户行为来触发所有懒加载代码：

| 交互类型 | 触发的代码 |
|----------|-----------|
| 滚动所有可滚动区域 | 无限滚动列表、图片懒加载 |
| Hover 所有下拉菜单和弹出层 | 菜单组件、工具提示的按需加载 |
| 填写表单输入框和下拉选择 | 搜索联想、联动筛选的 JS |
| 遍历 SPA 路由（Vue Router / React Router） | 每个页面对应的 chunk 分包 |
| 点击 Tab、手风琴、折叠面板 | 隐藏内容区域的按需加载 |

#### 三种渲染模式

在 `config.yaml` 中通过 `render_mode` 配置：

| 模式 | 说明 | 适用于 |
|------|------|--------|
| `hybrid`（默认） | 仅对 SPA 空壳页面启用增强渲染 | 一般场景，平衡覆盖率和速度 |
| `full` | 对所有 HTML 页面都启用增强渲染 | 追求最高覆盖率，速度较慢 |
| `off` | 完全关闭渲染，纯 httpx 模式 | 不需要动态分析的场景 |

#### 效果对比

| 场景 | 纯 httpx 模式 | 增强渲染模式 |
|------|-------------|-------------|
| 传统多页网站 | 能抓到大部分 | 能抓到全部 |
| Vue/React SPA | 只能抓到空壳 | 能抓到所有 chunk |
| 动态 import() 加载 | 完全抓不到 | 能抓到 |
| eval() 执行的代码 | 完全抓不到 | Hook 拦截记录 |
| 懒加载的组件 | 完全抓不到 | 全交互触发后能抓到 |
| WebSocket 推送 | 完全抓不到 | Hook 拦截记录 |

### 7. 代理池支持

如果你需要通过代理访问目标（比如配合 TscanPlus 等代理池工具），工具支持两种模式：

- **本地代理模式**：所有流量走你指定的本地代理端口
- **API 代理池模式**：定时从代理池 API 拉取代理列表，轮询使用，失败自动切换

### 8. 域名白名单安全约束

工具**强制要求**配置授权域名白名单，不配置就拒绝运行。递归扫描永远不会跳出白名单范围，确保不会误扫到其他网站。

---

## 三、两种使用方式

### 方式一：Web UI（推荐，图形界面）

```bash
python webui.py
```

浏览器打开 `http://127.0.0.1:8000`，在网页上操作：

- 左侧填授权扫描清单（每行一个 URL）和域名白名单
- 调整深度、并发数、QPS 等参数
- 勾选是否启用 DeepSeek AI 和代理
- 点击"开始扫描"
- 右侧实时看进度日志和计数器
- 完成后切换到"发现/接口/节点"标签查看结果
- 可以下载 `report.md` 和 `full.json` 报告

### 方式二：命令行

```bash
# 从 URL 列表文件扫描
python main.py -u urls.txt -c config.yaml

# 扫描单个 URL
python main.py -u https://target.example.com --domains target.example.com

# 纯本地正则模式（不调 AI）
python main.py -u urls.txt -d 4 --no-llm --domains example.com
```

---

## 四、输出报告

每次扫描完成后，会在 `reports/` 目录下生成以时间戳命名的文件夹，包含：

| 文件 | 内容 |
|------|------|
| `report.md` | 可读报告，包含敏感信息表、接口探测表、抓取节点明细 |
| `full.json` | 全量结构化数据，方便导入其他系统分析 |

示例报告内容：

```
## 敏感信息发现
| 级别 | 类型 | 值 | 来源 | 置信度 |
| critical | aliyun_ak | LTAI5txxxxxxxxxx | app.js | 0.95 |
| high | jwt | eyJhbGciOi... | chunk-home.js | 0.90 |

## 接口探测
| 接口 | GET(抓取) | OPTIONS | POST | CORS |
| /api/v1/users | 200 | 200 | 405 | * |
| /api/v1/login | 200 | 200 | 200 | - |

## 抓取节点明细
| URL | 状态 | 类型 | 大小 | 深度 |
| /index.html | 200 | html | 15KB | 0 |
| /js/app.js | 200 | js | 320KB | 1 |
```

---

## 五、关键参数说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| 递归深度 | 5 | 种子 URL 为第 0 层，每发现一个子链接深度 +1 |
| 每域节点上限 | 2000 | 同一个域名最多抓取 2000 个 URL |
| 全局节点上限 | 10000 | 整个扫描最多抓取 10000 个 URL |
| 并发数 | 20 | 同时发起多少个请求 |
| 每域 QPS | 5 | 每个域名每秒最多发几个请求（防封 IP） |
| 文件大小上限 | 2MB | 超过此大小的文件只记录不下载 |
| 渲染模式 | hybrid | off=纯httpx / hybrid=仅SPA空壳启用 / full=全部HTML启用增强渲染 |

---

## 六、安装

```bash
pip install -r requirements.txt
```

如果需要 SPA 渲染功能，还需安装 Playwright 浏览器：

```bash
pip install playwright
python -m playwright install chromium
```

---

## 七、注意事项

1. **仅用于授权测试**：本工具只应在自有资产或获得书面授权的目标上使用，请遵守当地法律法规。
2. **配置白名单**：必须在 `config.yaml` 的 `scope.domains` 中填写授权域名，否则工具拒绝运行。
3. **DeepSeek Key**：如果需要 AI 审计功能，在 `config.yaml` 中填写 `api_key`，或设置环境变量 `DEEPSEEK_API_KEY`。
4. **QPS 控制**：建议根据目标承受能力调整 `per_domain_qps`，避免触发 WAF 或封禁。

---

## 八、工作流程总结

```
你提供一个 URL 列表
    ↓
工具自动访问每个 URL，下载 HTML/JS 代码
    ↓
（可选）增强渲染引擎：CDP 拦截 + JS Hook + 全交互自动化，捕获动态加载代码
    ↓
本地正则扫描：匹配密钥、密码、Token、API 路径
    ↓
（可选）DeepSeek AI 对可疑片段二次确认
    ↓
发现的新 API 路径自动递归访问（在白名单范围内）
    ↓
对发现的接口做 OPTIONS/POST 探测
    ↓
生成 report.md 和 full.json 报告
```

整个过程全自动，你只需要提供 URL 和域名白名单，等报告出来就行。如果追求最高覆盖率，建议安装 Playwright 并将 `render_mode` 设为 `full`。