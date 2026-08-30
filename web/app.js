const $ = (id) => document.getElementById(id);
let pollTimer = null;
let startedAt = null;
let currentStatus = "idle";

// ---------- 初始化 ----------
async function init() {
  try {
    const cfg = await fetchJSON("/api/config");
    $("depth").value = cfg.max_depth;
    $("concurrency").value = cfg.concurrency;
    $("qps").value = cfg.per_domain_qps;
    $("llm").checked = cfg.llm_enabled && cfg.llm_available;
    $("proxy").checked = cfg.proxy_enabled;
    $("render_mode").value = cfg.render_mode || "hybrid";
    $("live-concurrency").value = cfg.concurrency;
    $("live-depth").value = cfg.max_depth;
    const llmBadge = $("badge-llm");
    llmBadge.textContent = "DeepSeek: " + (cfg.llm_available ? "已配置" : "未配置");
    llmBadge.className = "badge " + (cfg.llm_available ? "on" : "off");
    if (!cfg.llm_available) {
      $("llm").disabled = true;
      $("llm").title = "未配置 DEEPSEEK_API_KEY，请在 config.yaml 设置";
    }
    syncAuditJson();
    const proxyBadge = $("badge-proxy");
    proxyBadge.textContent = "代理: " + (cfg.proxy_enabled ? "开" : "关");
    proxyBadge.className = "badge " + (cfg.proxy_enabled ? "on" : "off");
  } catch (e) {
    setStatus("加载配置失败：" + e, true);
  }
}

function syncAuditJson() {
  $("audit_json").disabled = $("llm").disabled || !$("llm").checked;
}

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

// ---------- 开始扫描 ----------
$("start").addEventListener("click", async () => {
  const seeds = $("seeds").value.split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith("#"));
  const domains = $("domains").value.split(",").map((s) => s.trim()).filter(Boolean);
  if (!seeds.length) return alert("请填写授权扫描清单（至少一个 URL）");
  if (!domains.length) return alert("请填写授权域名白名单（安全约束，未填拒绝运行）");

  const body = {
    seeds: seeds.join("\n"),
    domains: domains.join(","),
    depth: parseInt($("depth").value, 10),
    concurrency: parseInt($("concurrency").value, 10),
    qps: parseFloat($("qps").value),
    llm: $("llm").checked,
    audit_json: $("audit_json").checked,
    proxy: $("proxy").checked,
    render_mode: $("render_mode").value,
  };
  updateControls("running");
  startedAt = Date.now();
  switchTab("progress");
  try {
    const res = await fetchJSON("/api/scan", { method: "POST", body });
    if (res.error) {
      setStatus(res.error, true);
      updateControls("idle");
      return;
    }
    pollTimer = setInterval(poll, 1000);
    poll();
  } catch (e) {
    setStatus("启动失败：" + e, true);
    updateControls("idle");
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

// ---------- 取消 ----------
$("cancel").addEventListener("click", async () => {
  try {
    await fetchJSON("/api/scan/cancel", { method: "POST" });
    setStatus("正在取消…");
  } catch (e) {}
});

// ---------- 轮询进度 ----------
async function poll() {
  try {
    const s = await fetchJSON("/api/scan/status");
    currentStatus = s.status;
    $("m-nodes").textContent = s.total_nodes ?? 0;
    $("m-discovered").textContent = `${s.discovered ?? 0}/${s.pending ?? 0}`;
    $("m-kinds").textContent = `${s.html ?? 0}/${s.js ?? 0}/${s.json ?? 0}`;
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
    setStatus(statusText(s.status));
    updateControls(s.status);
    if (s.status === "done" || s.status === "error" || s.status === "cancelled") {
      clearInterval(pollTimer);
      pollTimer = null;
      await loadResults();
      if (s.status === "done") switchTab("findings");
    }
  } catch (e) {
    console.error(e);
  }
}

function statusText(s) {
  return {
    idle: "空闲", running: "扫描中…", paused: "已暂停", done: "完成",
    error: "出错", cancelled: "已取消", cancelling: "取消中…",
  }[s] || s;
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
  } catch (e) {
    console.error(e);
  }
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
  // 按 url 聚合各方法状态
  const byUrl = {};
  for (const r of rows) {
    (byUrl[r.url] = byUrl[r.url] || {})[(r.method || "").toUpperCase()] = r.status;
  }
  tb.innerHTML = Object.entries(byUrl).map(([url, m]) =>
    `<tr><td>${esc(trunc(url, 90))}</td>
     <td>${cell(m.GET)}</td><td>${cell(m.OPTIONS)}</td><td>${cell(m.POST)}</td>
     <td>${esc(trunc(r_cors(rows, url), 30))}</td></tr>`
  ).join("");
}

function r_cors(rows, url) {
  const r = rows.find((x) => x.url === url);
  return r ? r.cors : "";
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
  const active = status === "running" || status === "paused" || status === "cancelling";
  $("start").disabled = active;
  $("cancel").style.display = active ? "" : "none";
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
function setStatus(text, isError) {
  const el = $("m-status");
  el.textContent = text;
  el.style.color = isError ? "var(--err)" : "var(--text)";
}
function switchTab(name) {
  document.querySelector(`.tab[data-tab="${name}"]`).click();
}
function esc(s) { return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
function trunc(s, n) { s = String(s ?? ""); return s.length > n ? s.slice(0, n) + "…" : s; }

init();
