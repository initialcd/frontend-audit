const $ = (id) => document.getElementById(id);
let pollTimer = null;
let startedAt = null;
let currentStatus = "idle";
let currentScanId = "";        // 当前展示的任务号：一旦变化就清空结果区，避免新旧任务串台
let cancelSince = 0;           // 进入"取消中"的时间戳，用于判断是否卡住
let liveMode = "";             // 当前正在跑的任务实际使用的模式
let lastLiveLoad = 0; // 运行中结果表刷新的节流时间戳（2s 一次，避免大表高频重建）
let llmAvailable = false;
let renderReady = false;      // Playwright 是否真的可用（不可用时渲染选项形同虚设）
let currentMode = "download"; // download | audit

const ACTIVE = ["running", "paused", "cancelling"];
const isActive = (s) => ACTIVE.includes(s);

// 渲染下拉的实时说明：把"选了但没生效"的情况直接写在界面上
function updateRenderHint() {
  const hint = $("render-hint");
  const mode = $("render_mode").value;
  if (mode === "off") {
    hint.textContent = "已关闭渲染：只抓 HTML 里静态写着的资源，SPA 运行时动态加载的 chunk 抓不到";
    hint.style.color = "";
    return;
  }
  if (!renderReady) {
    hint.textContent = "[!] Playwright 不可用，该选项当前无效（不会真的渲染）。"
      + "安装：pip install playwright && python -m playwright install chromium";
    hint.style.color = "var(--err)";
    return;
  }
  hint.textContent = mode === "full"
    ? "所有 HTML 页面都会启动浏览器渲染：覆盖最全，最慢"
    : "仅当页面是 SPA 空壳（正文很短 + 有外链脚本）时才渲染";
  hint.style.color = "";
}

// ---------- 初始化 ----------
async function init() {
  try {
    const cfg = await fetchJSON("/api/config");
    $("depth").value = cfg.max_depth;
    $("concurrency").value = cfg.concurrency;
    $("qps").value = cfg.per_domain_qps;
    llmAvailable = !!cfg.llm_available;
    $("llm").checked = cfg.llm_enabled && cfg.llm_available;
    $("audit_json").checked = !!cfg.audit_json;
    $("proxy").checked = cfg.proxy_enabled;
    $("verify_tls").checked = cfg.verify_tls !== false;
    $("render_mode").value = cfg.render_mode || "hybrid";
    renderReady = !!cfg.render_ready;
    updateRenderHint();
    $("live-concurrency").value = cfg.concurrency;
    $("live-depth").value = cfg.max_depth;
    const llmBadge = $("badge-llm");
    llmBadge.textContent = "DeepSeek: " + (llmAvailable ? "已配置" : "未配置");
    llmBadge.className = "badge " + (llmAvailable ? "on" : "off");
    if (!llmAvailable) {
      $("llm").disabled = true;
      $("llm").title = "未配置 DEEPSEEK_API_KEY，请在 config.yaml 设置";
    }
    syncAuditJson();
    const proxyBadge = $("badge-proxy");
    proxyBadge.textContent = "代理: " + (cfg.proxy_enabled ? "开" : "关");
    proxyBadge.className = "badge " + (cfg.proxy_enabled ? "on" : "off");
    applyMode("download");
  } catch (e) {
    setStatus("加载配置失败：" + e, true);
  }
}

function syncAuditJson() {
  $("audit_json").disabled = $("llm").disabled || !$("llm").checked;
}

// ---------- 模式切换：控制哪些控件与选项卡可见 ----------
function applyMode(mode) {
  currentMode = mode;
  const isDownload = mode === "download";

  document.querySelectorAll(".audit-only").forEach((el) => {
    el.style.display = isDownload ? "none" : "";
  });
  document.querySelectorAll(".file-only").forEach((el) => {
    el.style.display = isDownload ? "" : "none";
  });
  $("row-outdir").style.display = isDownload ? "" : "none";
  $("offline-note").style.display = isDownload ? "" : "none";
  $("offline-note-audit").style.display = (!isDownload && !llmAvailable) ? "" : "none";
  $("card-downloaded").style.display = isDownload ? "" : "none";

  const badge = $("badge-mode");
  badge.textContent = "模式: " + (isDownload ? "仅下载（离线可用）" : "审计");
  badge.className = "badge " + (isDownload ? "on" : "");

  document.querySelectorAll(".mode-card").forEach((c) => {
    c.classList.toggle("active", c.dataset.mode === mode);
  });

  // 切到隐藏选项卡时回到进度页，避免停留在不存在的内容上
  const active = document.querySelector(".tab.active");
  if (active && active.classList.contains("audit-only") && isDownload) switchTab("progress");
  if (active && active.classList.contains("file-only") && !isDownload) switchTab("progress");

  // 运行中改模式不打断当前任务：按钮文案与提示需要跟着刷新
  updateControls(currentStatus);
}

document.querySelectorAll('input[name="mode"]').forEach((r) =>
  r.addEventListener("change", () => applyMode(r.value))
);

// ---------- 标签切换 ----------
document.querySelectorAll(".tab").forEach((t) =>
  t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    $("tab-" + t.dataset.tab).classList.add("active");
  })
);

// ---------- LLM 开关联动 JSON 审计 ----------
$("llm").addEventListener("change", syncAuditJson);
$("render_mode").addEventListener("change", updateRenderHint);

// ---------- 从种子提取域名 ----------
$("extract-domains").addEventListener("click", () => {
  const lines = $("seeds").value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  const hosts = new Set();
  for (const l of lines) {
    try {
      const u = new URL(l);
      if (u.hostname) hosts.add(u.hostname);
    } catch {}
  }
  if (hosts.size) $("domains").value = [...hosts].join(",");
  else alert("未能从种子中提取到域名，请检查 URL 格式");
});

// ---------- 开始 / 放弃并重开 ----------
$("start").addEventListener("click", async () => {
  const seeds = $("seeds").value.split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith("#"));
  const domains = $("domains").value.split(",").map((s) => s.trim()).filter(Boolean);
  if (!seeds.length) return alert("请填写授权扫描清单（至少一个 URL）");
  if (!domains.length) return alert("请填写授权域名白名单（安全约束，未填拒绝运行）");

  // 运行中点击 = 放弃当前任务，按现在的模式/参数立刻重开（模式选错的主路径）
  const busy = isActive(currentStatus);
  if (busy) {
    const ok = confirm(
      "当前任务正在运行（" + statusText(currentStatus) + "）。\n\n" +
      "继续将【放弃】它，并按现在的选择立即开始新任务：\n" +
      "  模式：" + (currentMode === "download" ? "仅下载" : "审计") + "\n\n" +
      "被放弃的任务在后台自行收尾，已抓到的数据与报告保留在 reports-ui/<任务号>/。\n\n确定重开吗？"
    );
    if (!ok) return;
  }

  const body = {
    seeds: seeds.join("\n"),
    domains: domains.join(","),
    depth: parseInt($("depth").value, 10),
    concurrency: parseInt($("concurrency").value, 10),
    qps: parseFloat($("qps").value),
    llm: $("llm").checked,
    audit_json: $("audit_json").checked,
    proxy: $("proxy").checked,
    verify_tls: $("verify_tls").checked,
    render_mode: $("render_mode").value,
    mode: currentMode,
    out_dir: $("out_dir").value.trim(),
    force: busy,          // 给后端顺手兜底：即使复位接口没走到也能抢占
  };
  startedAt = Date.now();
  cancelSince = 0;
  switchTab("progress");
  setStatus(busy ? "正在放弃旧任务并启动新任务…" : "正在启动…");
  try {
    const res = await fetchJSON("/api/scan", { method: "POST", body });
    if (res.error) {
      setStatus(res.error, true);
      updateControls(currentStatus);
      return;
    }
    currentScanId = res.scan_id || "";
    resetResultViews();
    ensurePolling();
  } catch (e) {
    setStatus("启动失败：" + e, true);
    updateControls(currentStatus);
  }
});

// ---------- 暂停 / 继续 ----------
$("pause").addEventListener("click", async () => {
  const target = currentStatus === "paused" ? "/api/scan/resume" : "/api/scan/pause";
  try {
    await fetchJSON(target, { method: "POST" });
    poll();
  } catch (e) {
    setStatus("操作失败：" + e, true);
  }
});

// ---------- 运行时应用配置（并发 / 深度） ----------
$("apply-config").addEventListener("click", async () => {
  const body = {
    concurrency: parseInt($("live-concurrency").value, 10),
    depth: parseInt($("live-depth").value, 10),
  };
  try {
    const res = await fetchJSON("/api/scan/config", { method: "POST", body });
    if (res.error) setStatus(res.error, true);
    else setStatus("已应用：并发 " + res.concurrency + "，深度 " + res.max_depth);
    poll();
  } catch (e) {
    setStatus("应用失败：" + e, true);
  }
});

// ---------- 取消：立即中断，已抓到的结果保留 ----------
$("cancel").addEventListener("click", async () => {
  try {
    const res = await fetchJSON("/api/scan/cancel", { method: "POST" });
    if (res.error) { setStatus(res.error, true); return; }
    cancelSince = Date.now();
    setStatus("正在取消…（即刻中断在飞请求，已抓到的结果保留）");
    updateControls("cancelling");
    ensurePolling();
  } catch (e) {
    setStatus("取消失败：" + e, true);
  }
});

// ---------- 强制复位：不等收尾，立刻解除占用可重开 ----------
$("reset").addEventListener("click", async () => {
  const ok = confirm(
    "强制复位：立即解除任务占用，不再等待后台收尾。\n" +
    "被放弃的任务会自行把产物写到 reports-ui/<任务号>/。\n\n确定吗？"
  );
  if (!ok) return;
  try {
    const res = await fetchJSON("/api/scan/abandon", { method: "POST" });
    if (res.error) { setStatus(res.error, true); return; }
    currentStatus = "idle";
    currentScanId = "";
    cancelSince = 0;
    resetResultViews();
    updateControls("idle");
    setStatus("已强制复位：确认模式与参数后即可开始新任务");
    ensurePolling();
  } catch (e) {
    setStatus("复位失败：" + e, true);
  }
});

// ---------- 轮询进度 ----------
async function poll() {
  try {
    const s = await fetchJSON("/api/scan/status");
    currentStatus = s.status;
    $("m-nodes").textContent = s.total_nodes ?? 0;
    $("m-discovered").textContent = `${s.discovered ?? 0}/${s.pending ?? 0}`;
    $("m-kinds").textContent = `${s.html ?? 0}/${s.js ?? 0}/${s.json ?? 0}`;
    $("m-downloaded").textContent = s.downloaded ?? 0;
    $("m-findings").textContent = s.findings ?? 0;
    $("m-endpoints").textContent = s.endpoints ?? 0;
    $("m-llm").textContent = `${s.llm_calls ?? 0}${s.llm_failures ? "/" + s.llm_failures : ""}`;
    $("m-conc").textContent = `${s.concurrency ?? "-"}/${s.max_depth ?? "-"}`;
    $("m-skip").textContent = `${s.skipped_scope ?? 0}/${s.skipped_dup ?? 0}/${s.skipped_budget ?? 0}`;
    if (startedAt) $("m-elapsed").textContent = Math.floor((Date.now() - startedAt) / 1000) + "s";

    // 进度条
    const pct = clamp(s.progress ?? 0, 0, 100);
    $("progress-fill").style.width = pct + "%";
    $("progress-text").textContent =
      `${pct}% · 完成 ${s.total_nodes ?? 0} / 排队 ${s.pending ?? 0} / 发现 ${s.discovered ?? 0}`;

    // 运行中同步当前并发/深度到输入框（输入框聚焦时不覆盖，避免打断用户输入）
    if (s.concurrency != null) syncInput($("live-concurrency"), s.concurrency);
    if (s.max_depth != null) syncInput($("live-depth"), s.max_depth);

    if (s.logs) {
      const log = $("log");
      log.textContent = s.logs.join("\n");
      log.scrollTop = log.scrollHeight;
    }
    // 选项卡计数：发现/接口/节点 实时显示条数
    setTabCount("findings", s.findings ?? 0);
    setTabCount("endpoints", s.endpoints ?? 0);
    setTabCount("nodes", s.total_nodes ?? 0);
    if (s.mode === "download") setTabCount("files", s.downloaded ?? 0);

    // 换任务了（取消/复位后重开）：清空结果区与计时，避免上一个任务的数据串进来
    if (s.scan_id !== currentScanId) {
      currentScanId = s.scan_id || "";
      if (s.scan_id) {
        startedAt = Date.now();
        resetResultViews();
      }
    }
    liveMode = s.mode || liveMode;

    // 动态结果：运行中（含暂停/取消中）每 2s 渐进刷新结果表，
    // 完成后强制再全量刷新一次，杜绝"只有任务结束才有内容"。
    const active = isActive(s.status);
    const terminal = s.status === "done" || s.status === "error" || s.status === "cancelled";
    if (active || terminal) {
      const now = Date.now();
      if (terminal || now - lastLiveLoad >= 2000) {
        lastLiveLoad = now;
        await loadResults();
      }
    }

    updateControls(s.status);
    let text = statusText(s.status);
    if (s.status === "cancelling") {
      if (!cancelSince) cancelSince = Date.now();
      const secs = Math.floor((Date.now() - cancelSince) / 1000);
      if (secs >= 5) text = `取消中（已 ${secs}s）：仍在收尾，可直接点「强制复位」立刻解除占用`;
    } else {
      cancelSince = 0;
    }
    if (active && liveMode && liveMode !== currentMode) {
      text += `　·　本任务=${liveMode === "download" ? "仅下载" : "审计"}` +
              `，已选=${currentMode === "download" ? "仅下载" : "审计"}（点「放弃并重开」生效）`;
    }
    setStatus(text);
    if (terminal) {
      clearInterval(pollTimer);
      pollTimer = null;
      if (s.status === "done") switchTab("findings");
    }
  } catch (e) {
    console.error(e);
  }
}

function statusText(s) {
  const map = {
    idle: "空闲", running: "扫描中…", paused: "已暂停", done: "完成",
    error: "出错", cancelled: "已取消", cancelling: "取消中…", abandoned: "已放弃",
  };
  if (s === "running") return liveMode === "download" ? "下载中…" : "扫描中…";
  return map[s] || s;
}

function syncInput(el, val) {
  if (document.activeElement !== el) el.value = val;
}

function clamp(v, lo, hi) {
  return Math.min(hi, Math.max(lo, Number(v) || 0));
}

// ---------- 加载结果 ----------
async function loadResults() {
  try {
    const [f, e, n] = await Promise.all([
      fetchJSON("/api/scan/findings"),
      fetchJSON("/api/scan/endpoints"),
      fetchJSON("/api/scan/urls"),
    ]);
    renderFindings(f.findings || []);
    renderEndpoints(e.endpoints || []);
    renderNodes(n.urls || []);
    if (currentMode === "download") {
      const fl = await fetchJSON("/api/scan/files");
      $("files-dir").textContent = fl.dir ? "输出目录：" + fl.dir : "";
      renderFiles(fl.files || []);
    }
  } catch (e) {
    console.error(e);
  }
}

function renderFiles(rows) {
  const tb = $("tb-files");
  if (!rows.length) { tb.innerHTML = '<tr><td colspan="2" class="empty">暂无文件</td></tr>'; return; }
  const sorted = rows.slice().sort((a, b) => b.size - a.size);
  tb.innerHTML = sorted.map((r) =>
    `<tr><td>${esc(r.path)}</td><td>${fmtSize(r.size)}</td></tr>`
  ).join("");
}

function fmtSize(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(2) + " MB";
}

function renderFindings(rows) {
  const tb = $("tb-findings");
  if (!rows.length) { tb.innerHTML = '<tr><td colspan="6" class="empty">无发现</td></tr>'; return; }
  tb.innerHTML = rows.map((r) => {
    const sev = (r.severity || "medium").toLowerCase();
    return `<tr><td><span class="sev ${sev}">${sev}</span></td>
      <td>${esc(r.ftype)}</td><td>${esc(trunc(r.value, 80))}</td>
      <td>${esc(trunc(r.source_url, 70))}</td>
      <td>${r.confidence}</td><td>${esc(trunc(r.reason, 50))}</td></tr>`;
  }).join("");
}

function renderEndpoints(rows) {
  const tb = $("tb-endpoints");
  if (!rows.length) { tb.innerHTML = '<tr><td colspan="5" class="empty">无接口</td></tr>'; return; }
  // 按 url 聚合各方法状态；同时预建 url→cors 映射，避免 O(n²) 查找
  const byUrl = {};
  const corsMap = {};
  for (const r of rows) {
    (byUrl[r.url] = byUrl[r.url] || {})[(r.method || "").toUpperCase()] = r.status;
    if (r.cors) corsMap[r.url] = r.cors;
  }
  tb.innerHTML = Object.entries(byUrl).map(([url, m]) =>
    `<tr><td>${esc(trunc(url, 90))}</td>
     <td>${cell(m.GET)}</td><td>${cell(m.OPTIONS)}</td><td>${cell(m.POST)}</td>
     <td>${esc(trunc(corsMap[url] || "", 30))}</td></tr>`
  ).join("");
}
function cell(v) {
  if (v === undefined || v === null) return '<span class="muted">-</span>';
  const c = v >= 200 && v < 300 ? "s2" : v === 404 ? "" : v >= 500 ? "s5" : "s4";
  return `<span class="stat ${c}">${v}</span>`;
}

function renderNodes(rows) {
  const tb = $("tb-nodes");
  if (!rows.length) { tb.innerHTML = '<tr><td colspan="5" class="empty">无节点</td></tr>'; return; }
  tb.innerHTML = rows.map((r) =>
    `<tr><td>${esc(trunc(r.url, 90))}</td><td>${r.status}</td>
     <td>${esc(r.kind)}</td><td>${r.size}</td><td>${r.depth}</td></tr>`
  ).join("");
}

// ---------- 下载 ----------
function dl(fmt) { window.location.href = "/api/scan/report?format=" + fmt; }

// ---------- 工具 ----------
async function fetchJSON(url, opts) {
  const init = { method: "GET", headers: { "Accept": "application/json" } };
  if (opts && opts.method) init.method = opts.method;
  if (opts && opts.body) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  const r = await fetch(url, init);
  let data;
  try { data = await r.json(); } catch { data = {}; }
  if (!r.ok && !data.error) data.error = "HTTP " + r.status;
  return data;
}
function updateControls(status) {
  const active = isActive(status);
  const sbtn = $("start");
  // 永远可点：运行中点击即"放弃当前任务并按现在的选择重开"
  sbtn.disabled = false;
  sbtn.textContent = active ? "放弃并重开" : (currentMode === "download" ? "开始下载" : "开始扫描");
  sbtn.classList.toggle("primary", !active);
  sbtn.title = active ? "放弃当前任务，按左侧模式/参数立刻重开" : "按左侧参数开始任务";
  $("cancel").style.display = (status === "running" || status === "paused") ? "" : "none";
  $("reset").style.display = active ? "" : "none";
  const pbtn = $("pause");
  const showPause = status === "running" || status === "paused";
  pbtn.style.display = showPause ? "" : "none";
  if (status === "paused") {
    pbtn.textContent = "继续";
    pbtn.classList.add("paused");
  } else {
    pbtn.textContent = "暂停";
    pbtn.classList.remove("paused");
  }
  $("apply-config").disabled = !(status === "running" || status === "paused");
  if (!active) startedAt = null;
}

// 复位后前端自己的轮询可能已经停了，这里确保它继续跑
function ensurePolling() {
  if (!pollTimer) pollTimer = setInterval(poll, 1000);
  poll();
}

// 换任务时清空结果区、日志与进度条，杜绝新旧任务数据混在一起
function resetResultViews() {
  lastLiveLoad = 0;
  renderFindings([]);
  renderEndpoints([]);
  renderNodes([]);
  renderFiles([]);
  $("files-dir").textContent = "";
  $("log").textContent = "";
  $("progress-fill").style.width = "0%";
  $("progress-text").textContent = "0% · 完成 0 / 排队 0 / 发现 0";
  ["findings", "endpoints", "nodes", "files"].forEach((n) => setTabCount(n, 0));
}
function setStatus(text, isError) {
  const el = $("m-status");
  el.textContent = text;
  el.style.color = isError ? "var(--err)" : "var(--text)";
}
function switchTab(name) {
  document.querySelector(`.tab[data-tab="${name}"]`).click();
}
const TAB_LABELS = { progress: "进度", findings: "发现", endpoints: "接口", nodes: "节点", files: "文件" };
function setTabCount(name, n) {
  const t = document.querySelector(`.tab[data-tab="${name}"]`);
  if (!t) return;
  const label = TAB_LABELS[name] || name;
  t.textContent = n > 0 ? `${label} (${n})` : label;
}
function esc(s) { return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
function trunc(s, n) { s = String(s ?? ""); return s.length > n ? s.slice(0, n) + "…" : s; }

init();
