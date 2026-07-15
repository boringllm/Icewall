"use strict";

// ------------------------------------------------------------------ helpers
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "html") n.innerHTML = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) n.append(kid?.nodeType ? kid : document.createTextNode(kid ?? ""));
  return n;
};
const fmt = (n) => (n ?? 0).toLocaleString();
const money = (n) => "$" + (n ?? 0).toFixed(4);

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).detail || msg; } catch {}
    throw new Error(msg);
  }
  return r.status === 204 ? null : r.json();
}
let toastTimer;
function toast(msg, isErr = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 4000);
}

const ROLES = ["triage", "tracer", "analyzer", "validator", "remediator", "summarizer"];
const FILE_PALETTE = ["#4aa8ff", "#a48bff", "#ffcf5c", "#f78c6b", "#63d2ff", "#c3e88d", "#ff9cee", "#89ddff"];

// ------------------------------------------------------------------ routing
function showView(name) {
  $$(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + name));
  $$("nav button").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  if (name === "sessions") loadSessions();
  if (name === "presets") loadPresets();
}
$$("nav button").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));

// ------------------------------------------------------------------ settings form
// A single "shared provider" config model that all agents use — the common UI
// case. Presets built here round-trip cleanly.
function agentDefaults(model, maxTokens, thinking = 0) {
  return { model, max_tokens: maxTokens, temperature: 0, thinking_tokens: thinking, params: {}, raw: "" };
}

// Provider-aware standard generation parameters. OpenAI and Anthropic differ in
// both names and available knobs; the raw-JSON box covers anything else.
const PARAM_SPECS = {
  openai: [
    { key: "top_p", label: "top_p", type: "number", step: 0.05 },
    { key: "frequency_penalty", label: "frequency_penalty", type: "number", step: 0.1 },
    { key: "presence_penalty", label: "presence_penalty", type: "number", step: 0.1 },
    { key: "seed", label: "seed", type: "int" },
    { key: "n", label: "n (choices)", type: "int" },
    { key: "stop", label: "stop (comma-sep)", type: "csv" },
    { key: "reasoning_effort", label: "reasoning_effort", type: "select", options: ["", "minimal", "low", "medium", "high"] },
  ],
  anthropic: [
    { key: "top_p", label: "top_p", type: "number", step: 0.05 },
    { key: "top_k", label: "top_k", type: "int" },
    { key: "stop_sequences", label: "stop_sequences (comma-sep)", type: "csv" },
  ],
  mock: [],
};

function defaultFormModel() {
  return {
    provider: { type: "mock", base_url: "", api_key: "", api_key_env: "", verify_ssl: true },
    agents: {
      triage: agentDefaults("claude-haiku-4-5", 2048),
      tracer: agentDefaults("claude-haiku-4-5", 3072),
      analyzer: agentDefaults("claude-sonnet-5", 4096, 2048),
      validator: agentDefaults("claude-opus-4-8", 4096, 4096),
      remediator: agentDefaults("claude-sonnet-5", 4096),
      summarizer: agentDefaults("claude-haiku-4-5", 1536),
    },
    budget: { max_total_tokens: 2000000, max_llm_calls: 2000, min_suspicion: 0.3 },
    concurrency: { neural_workers: 8, symbolic_workers: 8, max_context_requests: 4 },
    context: { enabled: true, max_context_tokens: 6000, summarize_to_tokens: 2000 },
    memory: { enabled: true, share_across_stages: true },
    workshop: { enabled: true, root: ".icewall", keep_last: 0 },
    scan: { analyze_all_functions: false },
    pricing: [],
  };
}

// Build the real IcewallConfig dict from a form model.
function modelToConfig(m) {
  const prov = { type: m.provider.type };
  if (m.provider.base_url) prov.base_url = m.provider.base_url;
  if (m.provider.api_key) prov.api_key = m.provider.api_key;
  if (m.provider.api_key_env) prov.api_key_env = m.provider.api_key_env;
  prov.verify_ssl = m.provider.verify_ssl !== false;
  const agents = {};
  for (const r of ROLES) {
    const a = m.agents[r];
    if (!a) continue;
    const ac = { provider: "ui", model: a.model, max_tokens: Number(a.max_tokens) };
    if (a.temperature !== "" && a.temperature != null) ac.temperature = Number(a.temperature);
    if (Number(a.thinking_tokens)) ac.thinking_tokens = Number(a.thinking_tokens);
    // Merge the provider-aware params with the raw-JSON escape hatch (raw wins).
    const params = { ...(a.params || {}) };
    if (a.raw && a.raw.trim()) {
      let extra;
      try { extra = JSON.parse(a.raw); }
      catch (e) { throw new Error(`Invalid JSON in ${r} extra params: ${e.message}`); }
      Object.assign(params, extra);
    }
    if (Object.keys(params).length) ac.params = params;
    agents[r] = ac;
  }
  const pricing = {};
  for (const p of m.pricing) if (p.model) pricing[p.model] = { input: Number(p.input), output: Number(p.output) };
  return {
    providers: { ui: prov },
    agents,
    budget: {
      max_total_tokens: Number(m.budget.max_total_tokens),
      max_llm_calls: Number(m.budget.max_llm_calls),
      min_suspicion: Number(m.budget.min_suspicion),
    },
    concurrency: {
      neural_workers: Number(m.concurrency.neural_workers),
      symbolic_workers: Number(m.concurrency.symbolic_workers),
      max_context_requests: Number(m.concurrency.max_context_requests),
    },
    context: {
      enabled: m.context.enabled,
      max_context_tokens: Number(m.context.max_context_tokens),
      summarize_to_tokens: Number(m.context.summarize_to_tokens),
    },
    memory: { enabled: m.memory.enabled, share_across_stages: m.memory.share_across_stages },
    workshop: { enabled: m.workshop.enabled, root: m.workshop.root, keep_last: Number(m.workshop.keep_last) },
    scan: { analyze_all_functions: !!(m.scan && m.scan.analyze_all_functions) },
    pricing,
  };
}

// Best-effort load a stored config dict back into a form model.
function configToModel(cfg) {
  const m = defaultFormModel();
  const provNames = Object.keys(cfg.providers || {});
  // Use the provider referenced by the triage agent (or the first one).
  const triageProv = cfg.agents?.triage?.provider || provNames[0];
  const p = (cfg.providers || {})[triageProv] || {};
  m.provider = { type: p.type || "mock", base_url: p.base_url || "", api_key: p.api_key || "", api_key_env: p.api_key_env || "", verify_ssl: p.verify_ssl !== false };
  const specKeys = new Set((PARAM_SPECS[m.provider.type] || []).map((s) => s.key));
  for (const r of ROLES) {
    const a = (cfg.agents || {})[r];
    if (!a) continue;
    // Split stored params: known (shown as fields) vs. the rest (raw JSON box).
    const known = {}, extra = {};
    for (const [k, v] of Object.entries(a.params || {})) (specKeys.has(k) ? known : extra)[k] = v;
    m.agents[r] = {
      model: a.model, max_tokens: a.max_tokens ?? 4096,
      temperature: a.temperature ?? 0, thinking_tokens: a.thinking_tokens ?? 0,
      params: known, raw: Object.keys(extra).length ? JSON.stringify(extra, null, 2) : "",
    };
  }
  for (const key of ["budget", "concurrency", "context", "memory", "workshop"])
    if (cfg[key]) m[key] = { ...m[key], ...cfg[key] };
  m.scan = { analyze_all_functions: !!(cfg.scan && cfg.scan.analyze_all_functions) };
  m.pricing = Object.entries(cfg.pricing || {}).map(([model, v]) => ({ model, input: v.input ?? v.input_per_mtok, output: v.output ?? v.output_per_mtok }));
  return m;
}

function num(label, obj, key, step) {
  const inp = el("input", { type: "number", value: obj[key], step: step || 1, oninput: (e) => (obj[key] = e.target.value) });
  return el("div", { class: "field" }, el("label", {}, label), inp);
}
function txt(label, obj, key, ph) {
  const inp = el("input", { value: obj[key] || "", placeholder: ph || "", oninput: (e) => (obj[key] = e.target.value) });
  return el("div", { class: "field" }, el("label", {}, label), inp);
}
function chk(label, obj, key) {
  const inp = el("input", { type: "checkbox", oninput: (e) => (obj[key] = e.target.checked) });
  inp.checked = !!obj[key];
  return el("div", { class: "field check" }, inp, el("label", { style: "margin:0" }, label));
}

// One provider-aware parameter input, bound into a params dict. Clears the key
// when empty so we never send null/empty values to the API.
function paramInput(spec, params) {
  const set = (v) => {
    if (v === "" || v === null || v === undefined || (Array.isArray(v) && !v.length) || (typeof v === "number" && isNaN(v)))
      delete params[spec.key];
    else params[spec.key] = v;
  };
  let input;
  if (spec.type === "select") {
    input = el("select", { onchange: (e) => set(e.target.value) },
      ...spec.options.map((o) => el("option", { value: o }, o || "(default)")));
    input.value = params[spec.key] ?? "";
  } else if (spec.type === "csv") {
    input = el("input", {
      value: (params[spec.key] || []).join(", "), placeholder: "a, b",
      oninput: (e) => set(e.target.value.split(",").map((s) => s.trim()).filter(Boolean)),
    });
  } else {
    input = el("input", {
      type: "number", step: spec.step || 1, value: params[spec.key] ?? "",
      oninput: (e) => {
        const raw = e.target.value;
        if (raw === "") return set("");
        set(spec.type === "int" ? parseInt(raw, 10) : parseFloat(raw));
      },
    });
  }
  return el("div", { class: "field" }, el("label", {}, spec.label), input);
}

// Render the settings form into `container`, bound to model `m`.
function renderSettings(container, m) {
  container.innerHTML = "";
  container.append(el("div", { class: "subhead" }, "Provider (shared by all agents)"));
  const typeSel = el("select", { onchange: (e) => { m.provider.type = e.target.value; renderSettings(container, m); } },
    ...["mock", "anthropic", "openai"].map((t) => el("option", { value: t }, t)));
  typeSel.value = m.provider.type;
  container.append(el("div", { class: "field" }, el("label", {}, "Type"), typeSel));
  container.append(el("div", { class: "row" }, txt("Base URL (openai-compatible)", m.provider, "base_url", "https://api.example.com/v1")));
  container.append(el("div", { class: "row" },
    txt("API key (inline, optional)", m.provider, "api_key", "sk-…"),
    txt("or API key env var", m.provider, "api_key_env", "ANTHROPIC_API_KEY")));
  container.append(chk("Verify SSL certificate (uncheck to skip cert check — insecure)", m.provider, "verify_ssl"));

  container.append(el("div", { class: "subhead" }, "Agents — model & generation parameters"));
  container.append(el("div", { class: "muted", style: "font-size:11.5px; margin:-4px 0 8px" },
    "Click an agent to expand its full parameter set (" + m.provider.type + " format)."));
  const specs = PARAM_SPECS[m.provider.type] || [];
  for (const r of ROLES) {
    const a = m.agents[r] || (m.agents[r] = agentDefaults("", 4096));
    a.params = a.params || {};
    const det = el("details", { class: "agent-editor" });
    det.append(el("summary", {},
      el("b", { class: "rolename" }, r),
      el("span", { class: "muted", style: "margin-left:8px; font-size:12px" }, a.model || "(no model)")));
    det.append(el("div", { class: "row" }, txt("model id", a, "model"), num("max_tokens", a, "max_tokens")));
    det.append(el("div", { class: "row" },
      num("temperature", a, "temperature", 0.05),
      num("thinking_tokens (Anthropic)", a, "thinking_tokens")));
    if (specs.length) {
      det.append(el("div", { class: "subhead2" }, m.provider.type + " parameters"));
      const grid = el("div", { class: "param-grid" });
      for (const spec of specs) grid.append(paramInput(spec, a.params));
      det.append(grid);
    }
    det.append(el("div", { class: "field" },
      el("label", {}, "Extra params (raw JSON — merged last: response_format, tools, metadata, …)"),
      el("textarea", { rows: 3, placeholder: '{"response_format": {"type": "json_object"}}', oninput: (e) => (a.raw = e.target.value) },
        a.raw || "")));
    container.append(det);
  }

  container.append(el("div", { class: "subhead" }, "Scan coverage (Custom intensity)"));
  m.scan = m.scan || { analyze_all_functions: false };
  container.append(chk("Analyze every function (bypass source/sink pre-filter — max recall, higher cost)", m.scan, "analyze_all_functions"));

  container.append(el("div", { class: "subhead" }, "Budget"));
  container.append(el("div", { class: "row" },
    num("Max total tokens", m.budget, "max_total_tokens"),
    num("Max LLM calls", m.budget, "max_llm_calls"),
    num("Min suspicion", m.budget, "min_suspicion", 0.05)));

  container.append(el("div", { class: "subhead" }, "Concurrency"));
  container.append(el("div", { class: "row" },
    num("Neural workers", m.concurrency, "neural_workers"),
    num("Symbolic workers", m.concurrency, "symbolic_workers"),
    num("Max context hops", m.concurrency, "max_context_requests")));

  container.append(el("div", { class: "subhead" }, "Dynamic context management"));
  container.append(chk("Enable summarizer compression", m.context, "enabled"));
  container.append(el("div", { class: "row" },
    num("Max context tokens", m.context, "max_context_tokens"),
    num("Summarize to tokens", m.context, "summarize_to_tokens")));

  container.append(el("div", { class: "subhead" }, "Session memory"));
  container.append(chk("Enable memory", m.memory, "enabled"));
  container.append(chk("Share notes across stages", m.memory, "share_across_stages"));

  container.append(el("div", { class: "subhead" }, "Workshop"));
  container.append(chk("Enable per-session workshop folder", m.workshop, "enabled"));
  container.append(el("div", { class: "row" },
    txt("Root", m.workshop, "root"),
    num("Keep last N (0=all)", m.workshop, "keep_last")));

  container.append(el("div", { class: "subhead" }, "Custom pricing (USD / 1M tokens)"));
  const priceBox = el("div", {});
  const renderPrices = () => {
    priceBox.innerHTML = "";
    m.pricing.forEach((p, i) => {
      priceBox.append(el("div", { class: "agent-model-row" },
        el("input", { value: p.model, placeholder: "model id", oninput: (e) => (p.model = e.target.value) }),
        el("input", { type: "number", step: 0.01, value: p.input ?? "", placeholder: "in", oninput: (e) => (p.input = e.target.value) }),
        el("input", { type: "number", step: 0.01, value: p.output ?? "", placeholder: "out", oninput: (e) => (p.output = e.target.value) })));
    });
    priceBox.append(el("button", { class: "ghost", onclick: () => { m.pricing.push({ model: "", input: 0, output: 0 }); renderPrices(); } }, "+ add price"));
  };
  renderPrices();
  container.append(priceBox);
}

// ------------------------------------------------------------------ scan view
let scanModel = defaultFormModel();
let currentES = null;
let scanIntensity = "balanced";
let INTENSITIES = [];

async function initIntensity() {
  let data;
  try { data = await api("/api/config/intensities"); }
  catch { data = { levels: [], default: "balanced" }; }
  INTENSITIES = data.levels || [];
  scanIntensity = data.default || "balanced";
  renderIntensity();
}

function renderIntensity() {
  const box = $("#intensity"); box.innerHTML = "";
  const opts = [...INTENSITIES, { id: "custom", label: "Custom", description: "Use the exact suspicion floor, trace depth and full-function setting from Configuration below." }];
  for (const lvl of opts) {
    box.append(el("button", {
      class: "seg" + (lvl.id === scanIntensity ? " active" : ""),
      onclick: () => { scanIntensity = lvl.id; renderIntensity(); },
    }, lvl.label));
  }
  const cur = opts.find((o) => o.id === scanIntensity);
  $("#intensity-desc").textContent = cur ? cur.description : "";
}

async function initScanForm() {
  try {
    const tmpl = await api("/api/config/template");
    scanModel = configToModel(tmpl);
  } catch { scanModel = defaultFormModel(); }
  renderSettings($("#settings-form"), scanModel);
  // Editing any configuration field means "use my edits" — drop the preset
  // selection so Start scan sends the form config instead of the preset.
  $("#settings-form").addEventListener("input", () => { $("#preset-select").value = ""; });
  await refreshPresetDropdown();
}

async function refreshPresetDropdown() {
  const sel = $("#preset-select");
  const cur = sel.value;
  const items = await api("/api/presets").catch(() => []);
  sel.innerHTML = '<option value="">— none —</option>';
  for (const p of items) sel.append(el("option", { value: p.name }, p.name + (p.description ? " — " + p.description : "")));
  sel.value = cur;
}

$("#load-preset").addEventListener("click", async () => {
  const name = $("#preset-select").value;
  if (!name) return toast("Pick a preset first");
  const data = await api("/api/presets/" + name).catch((e) => toast(e.message, true));
  if (!data) return;
  scanModel = configToModel(data.config || {});
  renderSettings($("#settings-form"), scanModel);
  $("#settings").open = true;
  $("#preset-name").value = data.name;
  toast("Loaded preset '" + data.name + "' into the form");
});

$("#save-preset").addEventListener("click", async () => {
  const name = $("#preset-name").value.trim();
  if (!name) return toast("Enter a preset name", true);
  try {
    await api("/api/presets/" + encodeURIComponent(name), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ description: "", config: modelToConfig(scanModel) }),
    });
    toast("Saved preset '" + name + "'");
    refreshPresetDropdown();
  } catch (e) { toast("Save failed: " + e.message, true); }
});

$("#start-scan").addEventListener("click", startScan);

async function startScan() {
  const target = $("#target").value.trim();
  if (!target) return toast("Enter a target path", true);
  const dry = $("#dry-run").checked;
  const preset = $("#preset-select").value;
  // Precedence: dry-run > a selected preset (full fidelity, server-side) > the
  // form config. Editing any settings field clears the preset selection so your
  // edits win (see the input listener below).
  let body;
  if (dry) body = { target, dry_run: true };
  else if (preset) body = { target, preset };
  else {
    try { body = { target, config: modelToConfig(scanModel) }; }
    catch (e) { return toast(e.message, true); }
  }
  body.intensity = scanIntensity;  // applies to dry-run / preset / form alike
  let job;
  try {
    job = await api("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  } catch (e) { return toast("Could not start: " + e.message, true); }
  beginLive(job.id);
}

// ---- live view state
const live = {};
function beginLive(jobId) {
  $("#live-empty").classList.add("hidden");
  $("#live").classList.remove("hidden");
  $("#live-status").textContent = "running";
  $("#live-status").className = "pill running";
  $("#live-session-link").classList.add("hidden");
  live.total = 0; live.done = 0; live.jobId = jobId; live.traces = {}; live.expanded = {};
  setProg(0, "Starting…");
  setTile("t-cost", money(0)); setTile("t-tokens", "0"); setTile("t-calls", "0"); setTile("t-findings", "–");
  buildAgentCards();
  $("#log").innerHTML = "";
  if (window.__cy) { window.__cy.destroy(); window.__cy = null; }
  if (currentES) currentES.close();
  currentES = new EventSource(`/api/scan/${jobId}/events`);
  currentES.onmessage = (e) => handleEvent(JSON.parse(e.data));
  currentES.onerror = () => { /* stream ends server-side; ignore */ };
}

function setProg(pct, label) {
  $("#prog").style.width = Math.min(100, Math.round(pct * 100)) + "%";
  $("#prog-pct").textContent = Math.min(100, Math.round(pct * 100)) + "%";
  if (label) $("#prog-label").textContent = label;
}
const setTile = (id, v) => ($("#" + id).textContent = v);

function buildAgentCards() {
  const box = $("#agents"); box.innerHTML = "";
  live.cards = {};
  for (const r of ROLES) {
    const card = el("div", { class: "agent-card", id: "ag-" + r, title: "Click to see everything this agent did",
        onclick: () => openAgentModal(r) },
      el("div", { class: "top" }, el("span", { class: "dot" }), el("span", { class: "role" }, r)),
      el("div", { class: "doing", id: "doing-" + r }, "idle"),
      el("div", { class: "nums" },
        el("span", {}, "tasks ", el("b", { id: "tasks-" + r }, "0")),
        el("span", {}, el("b", { id: "cost-" + r }, "$0.0000"))));
    box.append(card);
    live.cards[r] = { active: 0, tasks: 0, calls: 0, cost: 0, log: [] };
  }
}

const MILE = {
  graph_start: "Building code graph",
  graph_done: (k) => `Graph: ${k.files} files, ${k.symbols} symbols, ${k.call_edges} edges`,
  triage_start: (k) => `Triaging ${k.candidates} candidates`,
  triage_done: (k) => `Entry points: ${k.entry_points}`,
  trace_done: (k) => `Traced ${k.candidate_paths} paths`,
  analyze_done: (k) => `Raw findings: ${k.findings}`,
  validate_done: (k) => `Confirmed: ${k.confirmed}`,
  remediate_done: (k) => `Remediations: ${k.count}`,
};

function logLine(text) {
  const l = $("#log");
  l.append(el("div", { html: text }));
  l.scrollTop = l.scrollHeight;
}

function handleEvent(ev) {
  const t = ev.event;
  if (t === "stage_tasks") {
    live.total += ev.total || 0;
    setProg(live.total ? live.done / live.total : 0, STAGE_LABEL[ev.stage] || ev.stage);
  } else if (t === "task_done") {
    live.done++;
    setProg(live.total ? live.done / live.total : 0);
    setTile("t-cost", money(ev.cost)); setTile("t-tokens", fmt(ev.tokens));
  } else if (t === "agent") {
    onAgentEvent(ev);
    setTile("t-cost", money(ev.cost)); setTile("t-tokens", fmt(ev.tokens)); setTile("t-calls", fmt(ev.calls));
  } else if (t === "agent_trace") {
    (live.traces[ev.task_id] = live.traces[ev.task_id] || []).push(ev);
    if (live.openRole) renderAgentModal(live.openRole);
  } else if (t === "graph_data") {
    renderGraph("graph", ev);
    $("#graph-count").textContent = `${ev.shown} of ${ev.total_symbols} symbols`;
  } else if (t === "scan_complete") {
    setProg(1, "Complete");
    $("#live-status").textContent = "done";
    $("#live-status").className = "pill done";
    setTile("t-findings", ev.findings);
    fillAgentCosts(ev.cost_by_role || {});
    logLine(`<b>done</b> — ${ev.findings} findings, ${money(ev.cost)}, ${ev.duration}s`);
    if (ev.workshop_dir) {
      const link = $("#live-session-link");
      link.classList.remove("hidden");
      const sid = ev.workshop_dir.replace(/[\\/]$/, "").split(/[\\/]/).pop();
      link.onclick = () => { showView("sessions"); openSession(sid); };
    }
  } else if (t === "scan_error") {
    $("#live-status").textContent = "error";
    $("#live-status").className = "pill error";
    logLine(`<b style="color:#ff5c7a">error</b> — ${ev.message}`);
    toast("Scan failed: " + ev.message, true);
  } else if (t === "stream_end") {
    if (currentES) currentES.close();
  }
  if (MILE[t]) logLine("<b>" + t.replace(/_/g, " ") + "</b> " + (typeof MILE[t] === "function" ? MILE[t](ev) : MILE[t]));
}

const STAGE_LABEL = {
  triage: "Triaging attack surface", trace: "Tracing source→sink paths",
  analyze: "Analyzing candidate paths", validate: "Validating findings", remediate: "Proposing remediations",
};

function onAgentEvent(ev) {
  const c = live.cards[ev.role];
  if (!c) return;
  const card = $("#ag-" + ev.role);
  if (ev.phase === "start") {
    c.active++; c.tasks++;
    c.log.push({ label: ev.label, subject: ev.subject, outcome: null, task_id: ev.task_id, t: Date.now() });
    $("#doing-" + ev.role).textContent = ev.label;
    $("#tasks-" + ev.role).textContent = c.tasks;
    card.classList.add("active");
  } else {
    c.active = Math.max(0, c.active - 1);
    c.calls++;
    // Attach the outcome to the most recent still-open entry with this label.
    for (let i = c.log.length - 1; i >= 0; i--) {
      if (c.log[i].label === ev.label && c.log[i].outcome === null) { c.log[i].outcome = ev.outcome || "done"; break; }
    }
    if (c.active === 0) { card.classList.remove("active"); $("#doing-" + ev.role).textContent = "idle"; }
  }
  // Live per-agent cost — updates during the scan, not just at the end.
  if (typeof ev.role_cost === "number") {
    c.cost = ev.role_cost;
    $("#cost-" + ev.role).textContent = money(ev.role_cost);
  }
  if (live.openRole === ev.role) renderAgentModal(ev.role);
}

// ---- per-agent transcript modal
function openAgentModal(role) {
  live.openRole = role;
  $("#agent-modal").classList.remove("hidden");
  renderAgentModal(role);
}
function closeAgentModal() {
  live.openRole = null;
  $("#agent-modal").classList.add("hidden");
}
function renderAgentModal(role) {
  const c = live.cards[role];
  if (!c) return;
  $("#am-title").textContent = role + " agent";
  $("#am-stats").textContent = `${c.tasks} tasks · ${c.calls} completed · ${money(c.cost)}`;
  const box = $("#am-log"); box.innerHTML = "";
  if (!c.log.length) { box.append(el("div", { class: "muted" }, "No activity yet.")); return; }
  c.log.forEach((e, i) => {
    const traces = (live.traces && live.traces[e.task_id]) || [];
    const isOpen = live.expanded[e.task_id];
    const entry = el("div", { class: "agent-log-entry" + (traces.length ? " has-trace" : "") });
    const head = el("div", { class: "ale-head", onclick: () => {
      if (!traces.length) return;
      live.expanded[e.task_id] = !live.expanded[e.task_id];
      renderAgentModal(role);
    }},
      el("span", { class: "ale-n" }, (traces.length ? (isOpen ? "▾ " : "▸ ") : "") + "#" + (i + 1)),
      el("span", { class: "ale-label" }, e.label),
      e.subject ? el("span", { class: "ale-subj mono" }, e.subject) : "",
      traces.length ? el("span", { class: "ale-badge" }, traces.length + (traces.length > 1 ? " calls" : " call")) : "");
    entry.append(head);
    entry.append(el("div", { class: "ale-outcome" + (e.outcome ? "" : " pending") },
      e.outcome ? ("→ " + e.outcome) : "…running"));
    if (isOpen && traces.length) entry.append(renderExchanges(traces));
    box.append(entry);
  });
}

function renderExchanges(traces) {
  const wrap = el("div", { class: "ale-detail" });
  traces.forEach((tr, k) => {
    const tokline = `${tr.model} · ${fmt(tr.input_tokens)} in / ${fmt(tr.output_tokens)} out`;
    const call = el("div", { class: "exchange" }, el("div", { class: "exchange-meta mono" }, tokline));
    call.append(section("System prompt", tr.system));
    call.append(section("User input", tr.user));
    if (tr.reasoning && tr.reasoning.trim()) call.append(section("Reasoning / thinking", tr.reasoning, true));
    call.append(section("Answer", tr.response, true));
    wrap.append(call);
  });
  return wrap;
}

function section(title, body, open) {
  const d = el("details", open ? { open: "" } : {});
  d.append(el("summary", {}, title));
  d.append(el("pre", { class: "exchange-body" }, body || "(empty)"));
  return d;
}

function fillAgentCosts(byRole) {
  for (const [role, r] of Object.entries(byRole)) {
    const n = $("#cost-" + role);
    if (n) n.textContent = money(r.cost_usd);
    if (live.cards && live.cards[role]) { live.cards[role].cost = r.cost_usd; live.cards[role].calls = r.calls; }
  }
  if (live.openRole) renderAgentModal(live.openRole);
}

// ------------------------------------------------------------------ graph render
function renderGraph(containerId, g) {
  if (!window.cytoscape) { $("#" + containerId).innerHTML = '<div class="muted" style="padding:16px">Graph library unavailable offline. ' + g.shown + ' symbols, ' + g.edges.length + ' edges.</div>'; return; }
  const elements = [];
  for (const n of g.nodes) elements.push({ data: { id: n.id, label: n.label, ...n } });
  for (const e of g.edges) elements.push({ data: { source: e.source, target: e.target } });
  const cy = cytoscape({
    container: document.getElementById(containerId),
    elements,
    style: [
      { selector: "node", style: {
        "background-color": (n) => n.data("has_sink") ? "#ff5c7a" : n.data("has_source") ? "#38e1c6" : FILE_PALETTE[(n.data("file_group") || 0) % FILE_PALETTE.length],
        "label": "data(label)", "color": "#dce6f5", "font-size": 9, "text-valign": "center", "text-halign": "center",
        "width": (n) => 14 + Math.min(28, (n.data("degree") || 0) * 4), "height": (n) => 14 + Math.min(28, (n.data("degree") || 0) * 4),
        "text-outline-color": "#0b1220", "text-outline-width": 2, "border-width": (n) => n.data("has_sink") ? 2 : 0, "border-color": "#ffd0da",
      }},
      { selector: "edge", style: { "width": 1.2, "line-color": "#3a4a6a", "target-arrow-color": "#3a4a6a", "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 0.7, "opacity": 0.7 } },
    ],
  });
  const layout = cy.layout({ name: "cose", animate: false, nodeRepulsion: 8000, idealEdgeLength: 80, padding: 30 });
  layout.one("layoutstop", () => cy.fit(undefined, 30));
  layout.run();
  // Fallback fit in case the container was sizing when the layout ran.
  setTimeout(() => cy.fit(undefined, 30), 60);
  if (containerId === "graph") window.__cy = cy;
  else window.__cyS = cy;
}

// ------------------------------------------------------------------ sessions
async function loadSessions() {
  $("#session-detail").classList.add("hidden");
  $("#sessions-index").classList.remove("hidden");
  const rows = $("#sessions-rows"); rows.innerHTML = "";
  const list = await api("/api/sessions").catch(() => []);
  $("#sessions-empty").classList.toggle("hidden", list.length > 0);
  for (const s of list) {
    const when = s.finished || s.started || "";
    rows.append(el("tr", { class: "click", onclick: () => openSession(s.id) },
      el("td", { class: "mono" }, s.id),
      el("td", {}, s.target || "–"),
      el("td", {}, el("span", { class: "pill " + (s.status || "") }, s.status || "?")),
      el("td", {}, s.findings ?? "–"),
      el("td", { class: "cost" }, s.cost != null ? money(s.cost) : "–"),
      el("td", { class: "muted" }, when.replace("T", " ").slice(0, 19)),
    ));
  }
}
$("#refresh-sessions").addEventListener("click", loadSessions);
$("#back-sessions").addEventListener("click", loadSessions);

async function openSession(sid) {
  const d = await api("/api/sessions/" + sid).catch((e) => toast(e.message, true));
  if (!d) return;
  $("#sessions-index").classList.add("hidden");
  $("#session-detail").classList.remove("hidden");
  $("#sd-title").textContent = d.meta.target || sid;
  $("#sd-status").textContent = d.meta.status || "";
  $("#sd-status").className = "pill " + (d.meta.status || "");
  const st = d.stats || {};
  $("#sd-findings").textContent = d.findings.length;
  $("#sd-cost").textContent = st.estimated_cost_usd != null ? money(st.estimated_cost_usd) : "–";
  $("#sd-tokens").textContent = fmt((st.input_tokens || 0) + (st.output_tokens || 0));
  $("#sd-calls").textContent = fmt(st.llm_calls || 0);
  $("#sd-dur").textContent = (st.duration_seconds ?? "–") + "s";

  renderCostBars(st.cost_by_role || {});
  renderFindings(d.findings);
  renderArtifacts(sid, d.artifacts);
  loadMemory(sid);
  if (d.has_graph) {
    const g = await api("/api/sessions/" + sid + "/graph").catch(() => null);
    if (g) renderGraph("sess-graph", g);
  } else $("#sess-graph").innerHTML = '<div class="muted" style="padding:16px">No graph saved.</div>';
}

function renderCostBars(byRole) {
  const box = $("#sd-costbars"); box.innerHTML = "";
  const entries = Object.entries(byRole);
  if (!entries.length) { box.append(el("div", { class: "muted" }, "No per-agent cost recorded.")); return; }
  const maxCost = Math.max(...entries.map(([, r]) => r.cost_usd || 0));
  const maxCalls = Math.max(...entries.map(([, r]) => r.calls || 0));
  const useCost = maxCost > 0;
  entries.sort((a, b) => (b[1].cost_usd || 0) - (a[1].cost_usd || 0) || (b[1].calls || 0) - (a[1].calls || 0));
  for (const [role, r] of entries) {
    const frac = useCost ? (r.cost_usd || 0) / maxCost : (maxCalls ? (r.calls || 0) / maxCalls : 0);
    box.append(el("div", { class: "costbar" },
      el("div", { class: "name" }, role),
      el("div", { class: "track" }, el("i", { style: `width:${Math.max(2, frac * 100)}%` })),
      el("div", { class: "amt" }, useCost ? money(r.cost_usd) : (r.calls || 0) + " calls")));
  }
  box.append(el("div", { class: "muted", style: "margin-top:6px; font-size:12px" },
    entries.map(([role, r]) => `${role}: ${r.calls} calls · ${fmt((r.input_tokens || 0) + (r.output_tokens || 0))} tok · ${r.model}`).join("  |  ")));
}

function renderFindings(findings) {
  const rows = $("#sd-findings-rows"); rows.innerHTML = "";
  if (!findings.length) { rows.append(el("tr", {}, el("td", { colspan: 5, class: "muted" }, "No confirmed findings."))); return; }
  for (const f of findings) {
    const chain = (f.call_chain || []).map((c) => c.symbol).join(" → ");
    rows.append(el("tr", {},
      el("td", {}, el("span", { class: "sev " + f.severity }, f.severity)),
      el("td", {}, String(f.confidence)),
      el("td", {}, f.vuln_class),
      el("td", { class: "mono" }, `${f.location.file}:${f.location.start_line}`),
      el("td", { class: "muted" }, chain || f.entry_point || "–")));
  }
}

function renderArtifacts(sid, names) {
  const box = $("#sd-artifacts"); box.innerHTML = "";
  for (const n of names)
    box.append(el("a", {
      href: `/api/sessions/${sid}/artifact/${n}`,
      download: `${sid}-${n}`, class: "pill",
      title: "Download " + n,
    }, "⬇ " + n));
}

async function loadMemory(sid) {
  const m = await api("/api/sessions/" + sid + "/memory").catch(() => null);
  const box = $("#sd-memory");
  if (!m) { box.textContent = "–"; return; }
  box.textContent = m.master || "(no memory)";
}

// ------------------------------------------------------------------ presets tab
let peModel = defaultFormModel();
async function loadPresets() {
  const rows = $("#preset-rows"); rows.innerHTML = "";
  const list = await api("/api/presets").catch(() => []);
  $("#presets-empty").classList.toggle("hidden", list.length > 0);
  for (const p of list) {
    rows.append(el("tr", { class: "click", onclick: () => editPreset(p.name) },
      el("td", {}, el("b", {}, p.name), el("div", { class: "muted", style: "font-size:12px" }, p.description || "")),
    ));
  }
}
async function editPreset(name) {
  const data = await api("/api/presets/" + name).catch((e) => toast(e.message, true));
  if (!data) return;
  $("#pe-title").textContent = "Edit: " + data.name;
  $("#pe-name").value = data.name;
  $("#pe-desc").value = data.description || "";
  peModel = configToModel(data.config || {});
  renderSettings($("#pe-form"), peModel);
}
$("#new-preset").addEventListener("click", async () => {
  $("#pe-title").textContent = "New preset";
  $("#pe-name").value = "";
  $("#pe-desc").value = "";
  try { peModel = configToModel(await api("/api/config/template")); } catch { peModel = defaultFormModel(); }
  renderSettings($("#pe-form"), peModel);
});
$("#pe-save").addEventListener("click", async () => {
  const name = $("#pe-name").value.trim();
  if (!name) return toast("Enter a name", true);
  try {
    await api("/api/presets/" + encodeURIComponent(name), {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ description: $("#pe-desc").value, config: modelToConfig(peModel) }),
    });
    toast("Saved '" + name + "'"); loadPresets(); refreshPresetDropdown();
  } catch (e) { toast("Save failed: " + e.message, true); }
});
$("#import-btn").addEventListener("click", async () => {
  const path = $("#import-path").value.trim() || "icewall.yaml";
  try {
    const info = await api("/api/presets/import", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
    });
    toast("Imported preset '" + info.name + "'");
    loadPresets(); refreshPresetDropdown();
  } catch (e) { toast("Import failed: " + e.message, true); }
});
$("#pe-delete").addEventListener("click", async () => {
  const name = $("#pe-name").value.trim();
  if (!name) return;
  await api("/api/presets/" + encodeURIComponent(name), { method: "DELETE" }).catch((e) => toast(e.message, true));
  toast("Deleted '" + name + "'"); loadPresets(); refreshPresetDropdown();
});

// ------------------------------------------------------------------ boot
$("#am-close").addEventListener("click", closeAgentModal);
$("#agent-modal").addEventListener("click", (e) => { if (e.target.id === "agent-modal") closeAgentModal(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeAgentModal(); });

(async function boot() {
  try {
    const h = await api("/api/health");
    $("#version").textContent = "v" + h.version;
  } catch { $("#version").textContent = "offline"; }
  await initScanForm();
  await initIntensity();
})();
