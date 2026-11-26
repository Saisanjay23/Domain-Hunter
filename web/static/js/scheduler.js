"use strict";
// =============================================================================
// Scan Scheduler UI. Every number and row comes from /api/scheduler/* (MongoDB). The browser never schedules
// scans: the backend engine does. The timers here only refresh the open page (fast while a run is active).
// All actions use delegated [data-sch] buttons; every server value is escaped before it is rendered.
// =============================================================================

const SCH = {
  view: "list", batchId: null, domainId: null, domainTab: "new", execOpen: null,
  overview: null, batches: [], batch: null, domain: null, list: null,
  page: 1, q: "", sort: "score", selected: new Set(), poll: null, editor: null, tz: null, busy: false,
};
const SCH_DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const SCH_STATUS_LABEL = {
  running: "Running", queued: "Queued", completed: "Completed", partially_completed: "Partially Completed", failed: "Failed",
  cancelled: "Cancelled", interrupted: "Interrupted", skipped: "Skipped", active: "Active", paused: "Paused", disabled: "Disabled",
  scheduled: "Scheduled", manual: "Manual", ok: "OK", retry: "Retrying", waiting: "Waiting",
};
const SCH_TRIGGER = { schedule: "Scheduled", manual: "Run now", manual_domain: "Domain run", retry: "Retry" };
const SCH_TABS = [["new", "New Discoveries"], ["all", "All Results"], ["confirmed", "Confirmed"], ["potential", "Potential"], ["inactive", "Inactive"], ["dismissed", "Dismissed"],
  ["history", "Historical Results"], ["scans", "Scan History"], ["settings", "Domain Settings"]];

// ----------------------------------------------------------------------------- formatting
function schSlug(s) { return String(s || "").toLowerCase().replace(/[^a-z_]+/g, "_"); }
function schPill(status, label) {
  const key = schSlug(status);
  return `<span class="st st-${esc(key)}">${esc(label || SCH_STATUS_LABEL[key] || status || "—")}</span>`;
}
function schWhen(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
function schRel(ts) {
  if (!ts) return "—";
  const s = Math.round(ts - Date.now() / 1000);
  if (s <= 0) return typeof ago === "function" ? ago(ts) : schWhen(ts);
  if (s < 90) return "in <1 min";
  if (s < 3600) return `in ${Math.round(s / 60)} min`;
  if (s < 86400) return `in ${Math.round(s / 3600)} h`;
  return `in ${Math.round(s / 86400)} d`;
}
function schDur(a, b) {
  if (!a) return "—";
  const s = Math.max(0, Math.round((b || Date.now() / 1000) - a));
  return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m`;
}
function schNum(n) { return Number(n || 0).toLocaleString(); }
function schKw(list) {
  const l = list || [];
  return l.length ? `<div class="sch-kw">${l.slice(0, 6).map(k => `<span>${esc(k)}</span>`).join("")}${l.length > 6 ? `<span>+${l.length - 6}</span>` : ""}</div>` : `<span class="hint">brand name only</span>`;
}
function schBtn(act, label, attrs = {}, cls = "btn btn-secondary btn-sm") {
  const extra = Object.entries(attrs).map(([k, v]) => ` data-${k}="${esc(v)}"`).join("");
  return `<button type="button" class="${cls}" data-sch="${act}"${extra}>${label}</button>`;
}
function schProgress(e) {
  const total = e.total || 0;
  const done = (e.completed || 0) + (e.failed || 0) + (e.cancelled || 0) + (e.skipped || 0);
  const pos = Math.min(total, done + (e.running || 0));
  const pct = total ? Math.round((done / total) * 100) : 0;
  const label = e.status === "queued" ? "Queued: waiting for a worker" : `Scanning ${pos} of ${total}`;
  return `<div class="sch-progress"><div class="p-line"><span><b>${esc(label)}</b>${e.failed ? ` · <span style="color:var(--danger-accent)">${schNum(e.failed)} failed</span>` : ""}</span><span>${pct}%</span></div>
    <div class="sch-bar"><span style="width:${pct}%"></span></div></div>`;
}

// ----------------------------------------------------------------------------- navigation & polling
async function loadScheduler() { await schRefresh(); }

function schGo(view, opts = {}) {
  SCH.view = view;
  if (opts.batchId !== undefined) SCH.batchId = opts.batchId;
  if (opts.domainId !== undefined) SCH.domainId = opts.domainId;
  if (view === "domain") { SCH.domainTab = opts.tab || "new"; SCH.page = 1; SCH.q = ""; SCH.selected.clear(); }
  if (view !== "batch") SCH.execOpen = null;
  if (typeof currentTab !== "undefined" && currentTab !== "scheduler") switchTab("scheduler");
  else schRefresh();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function schStopPolling() { clearTimeout(SCH.poll); SCH.poll = null; }

function schArm(fast) {
  schStopPolling();
  SCH.poll = setTimeout(() => {
    if (typeof currentTab !== "undefined" && currentTab !== "scheduler") return;
    const ae = document.activeElement;
    const typing = ae && ae.closest && ae.closest("#sch-root") && /^(INPUT|TEXTAREA|SELECT)$/.test(ae.tagName) && ae.type !== "checkbox";
    if (document.hidden || typing || document.querySelector("#sch-dialog[open], #dm-dialog[open]")) return schArm(fast);
    schRefresh(true);
  }, fast ? 3000 : 20000);
}

async function schRefresh(quiet = false) {
  const root = document.getElementById("sch-root");
  if (!root) return;
  try {
    let fast = false;
    if (SCH.view === "batch" && SCH.batchId) fast = await schLoadBatch();
    else if (SCH.view === "domain" && SCH.domainId) fast = await schLoadDomain();
    else fast = await schLoadList();
    schArm(fast);
  } catch (err) {
    if (!quiet) root.innerHTML = `<div class="alert alert-danger">${I.alert}<div><strong>Scheduler data could not be loaded.</strong><div class="hint">${esc(err.message)}</div></div></div>`;
    if (/not found/i.test(err.message) && SCH.view !== "list") { SCH.view = "list"; return schRefresh(quiet); }
    schArm(false);
  }
}

function schBadge(n) {
  const b = document.getElementById("sched-nav-badge");
  if (!b) return;
  b.hidden = !n;
  b.textContent = n ? String(n) : "";
}

// ----------------------------------------------------------------------------- list view
async function schLoadList() {
  const [ov, bl] = await Promise.all([settingsCall("GET", "/api/scheduler/overview"), settingsCall("GET", "/api/scheduler/batches")]);
  SCH.overview = ov;
  SCH.batches = bl.batches || [];
  schBadge((ov.running || []).length);
  schRenderList();
  return (ov.running || []).length > 0;
}

function schRenderList() {
  const ov = SCH.overview, f = ov.findings || {}, last = ov.last_24h || {};
  const eng = ov.engine || {};
  const engineLine = !ov.settings?.enabled ? `<span class="st st-paused">Automatic scheduling is off</span>`
    : eng.running ? `<span class="st st-ok">Engine running</span><span class="hint">last check ${eng.last_tick ? esc(ago(eng.last_tick)) : "pending"}${eng.last_error ? ` · ${esc(eng.last_error)}` : ""}</span>`
      : `<span class="st st-disabled">Engine stopped in this process</span><span class="hint">set BRAND_HUNTER_SCHEDULER=1 and restart to run schedules</span>`;
  const cards = SCH.batches.map(schCard).join("") || `<div class="sch-panel sch-empty" style="grid-column:1/-1"><b>No scan batches yet</b>Create a batch, paste or upload your domains with their keywords, pick a schedule. The server scans them automatically.<div style="margin-top:14px">${schBtn("new-batch", "+ New batch", {}, "btn btn-primary")}</div></div>`;
  const live = (ov.running || []).map(e => `<div class="sch-live-item"><div class="l-top"><button type="button" class="sch-card-name" style="font-size:13.5px" data-sch="open-batch" data-id="${esc(e.batch_id)}">${esc(e.batch_name || "Batch")}</button>${schPill(e.status)}</div>
      ${schProgress(e)}${(e.current || []).length ? `<div class="l-cur">${esc(e.current.join(" · "))}</div>` : ""}
      <div class="row" style="gap:6px">${schBtn("open-batch", "Open", { id: e.batch_id }, "btn btn-ghost btn-xs")}${schBtn("cancel-exec", "Cancel", { id: e.id }, "btn btn-danger-ghost btn-xs")}</div></div>`).join("")
    || `<div class="hint">No scans running right now.</div>`;
  const upcoming = (ov.upcoming || []).map(u => `<li><span class="t-when">${esc(schWhen(u.at))} · ${esc(schRel(u.at))}</span>
      <button type="button" class="t-name" data-sch="open-batch" data-id="${esc(u.batch_id)}">${esc(u.name)}</button><span class="t-sub">${esc(u.schedule_text)}</span></li>`).join("");
  document.getElementById("sch-root").innerHTML = `
    <div class="stack" style="gap:18px">
      <div class="sch-head"><div><div class="sch-sub row" style="gap:8px;flex-wrap:wrap;margin:0">${engineLine}</div></div>
        <div class="sch-actions">${schBtn("settings", "Engine settings", {}, "btn btn-ghost btn-sm")}${schBtn("new-batch", "+ New batch", {}, "btn btn-primary")}</div></div>
      <div class="sch-kpis">
        <div class="sch-kpi"><div class="k-label">Scan batches</div><div class="k-val">${schNum(ov.batches)}</div><div class="k-foot">${schNum(ov.active_batches)} active</div></div>
        <div class="sch-kpi"><div class="k-label">Monitored domains</div><div class="k-val">${schNum(ov.domains)}</div><div class="k-foot">each with its own keywords</div></div>
        <div class="sch-kpi k-danger"><div class="k-label">Confirmed</div><div class="k-val">${schNum(f.confirmed)}</div><div class="k-foot">${schNum(f.potential)} potential · ${schNum(f.total)} total</div></div>
        <div class="sch-kpi k-warn"><div class="k-label">New discoveries</div><div class="k-val">${schNum(f.new)}</div><div class="k-foot">${schNum((f.updated || 0) + (f.reappeared || 0))} updated / reappeared</div></div>
        <div class="sch-kpi k-ok"><div class="k-label">Runs · last 24 h</div><div class="k-val">${schNum(last.runs)}</div><div class="k-foot">${schNum(last.failed)} failed · ${schNum(last.partial)} partial · ${schNum(last.new_findings)} new</div></div>
      </div>
      <div class="sch-cols">
        <div class="sch-cards">${cards}</div>
        <div class="stack" style="gap:14px">
          <div class="sch-panel"><h3>Running now <span class="hint" style="text-transform:none;letter-spacing:0">${(ov.running || []).length ? "updates every 3 s" : ""}</span></h3><div class="sch-live">${live}</div></div>
          <div class="sch-panel"><h3>Upcoming runs</h3>${upcoming ? `<ul class="sch-timeline">${upcoming}</ul>` : `<div class="hint">Nothing scheduled. Manual batches run with “Run now”.</div>`}</div>
        </div>
      </div>
    </div>`;
}

function schCard(b) {
  const c = b.counts || {}, last = b.last_execution, act = b.active_execution;
  const lastLine = act ? schProgress(act)
    : last ? `<span class="sch-last">Last run ${esc(ago(last.started || last.created))} · ${schNum(last.completed)}/${schNum(last.total)} ok${last.failed ? ` · <span style="color:var(--danger-accent)">${schNum(last.failed)} failed</span>` : ""}</span>`
      : `<span class="sch-last">Never run</span>`;
  const pauseBtn = b.status === "active" ? schBtn("batch-status", "Pause", { id: b.id, status: "paused" }, "btn btn-ghost btn-xs")
    : b.status === "paused" ? schBtn("batch-status", "Resume", { id: b.id, status: "active" }, "btn btn-ghost btn-xs")
      : schBtn("batch-status", "Enable", { id: b.id, status: "active" }, "btn btn-ghost btn-xs");
  return `<article class="sch-card${act ? " is-running" : ""}">
    <div class="sch-card-top"><div style="min-width:0"><button type="button" class="sch-card-name" data-sch="open-batch" data-id="${esc(b.id)}">${esc(b.name)}</button>
      ${b.description ? `<p class="sch-card-desc">${esc(b.description)}</p>` : ""}</div>${schPill(b.display_status)}</div>
    <div class="sch-card-sched"><span>${esc(b.schedule_text)}</span>${b.next_run_at ? `<span>Next <b>${esc(schRel(b.next_run_at))}</b></span>` : ""}${b.organization ? `<span>${esc(b.organization)}</span>` : ""}</div>
    <div class="sch-metrics">
      <div class="sch-metric m-accent"><div class="m-val">${schNum(b.domain_count)}</div><div class="m-label">Domains</div></div>
      <div class="sch-metric m-warn"><div class="m-val">${schNum(c.new)}</div><div class="m-label">New</div></div>
      <div class="sch-metric m-danger"><div class="m-val">${schNum(c.confirmed)}</div><div class="m-label">Confirmed</div></div>
      <div class="sch-metric"><div class="m-val">${schNum(c.potential)}</div><div class="m-label">Potential</div></div>
    </div>
    ${lastLine}
    <div class="sch-card-foot"><div class="row" style="gap:6px">${schBtn("open-batch", "Open", { id: b.id }, "btn btn-secondary btn-xs")}
      ${act ? schBtn("cancel-exec", "Cancel run", { id: act.id }, "btn btn-danger-ghost btn-xs") : schBtn("run-batch", "Run now", { id: b.id }, "btn btn-primary btn-xs")}
      ${pauseBtn}</div>
      <div class="row" style="gap:6px">${schBtn("edit-batch", "Edit", { id: b.id }, "btn btn-ghost btn-xs")}${schBtn("dup-batch", "Duplicate", { id: b.id }, "btn btn-ghost btn-xs")}</div></div>
  </article>`;
}

// ----------------------------------------------------------------------------- batch view
async function schLoadBatch() {
  const d = await settingsCall("GET", `/api/scheduler/batches/${encodeURIComponent(SCH.batchId)}`);
  SCH.batch = d;
  const act = d.batch.active_execution;
  const openId = SCH.execOpen || (act && act.id);
  SCH.execDetail = openId ? await settingsCall("GET", `/api/scheduler/executions/${encodeURIComponent(openId)}`).catch(() => null) : null;
  schRenderBatch();
  return !!act;
}

function schJobRows(jobs) {
  return (jobs || []).map(j => {
    const st = j.status === "queued" && j.attempts > 0 ? "retry" : j.status === "queued" && /waiting/i.test(j.message || "") ? "waiting" : j.status;
    const counts = j.counts || {};
    return `<tr><td class="sch-mono">${esc(j.domain)}</td><td>${schPill(st)}</td><td class="num">${schNum(j.attempts)}/${schNum(j.max_attempts)}</td>
      <td>${j.status === "running" ? `<div class="sch-bar" style="min-width:90px"><span style="width:${Math.round(j.progress || 0)}%"></span></div><span class="hint">${esc(j.message || j.stage || "")}</span>`
        : j.status === "completed" ? `<span class="hint">${schNum(counts.new)} new · ${schNum((counts.updated || 0) + (counts.reappeared || 0))} changed · ${schNum(counts.confirmed)} confirmed</span>`
          : `<span class="hint" title="${esc(j.error || "")}">${esc((j.error || j.message || "").slice(0, 120))}</span>`}</td>
      <td class="hint">${esc(schDur(j.started, j.finished))}</td>
      <td class="col-actions">${schBtn("open-domain", "Open", { id: j.domain_id }, "btn btn-ghost btn-xs")}</td></tr>`;
  }).join("");
}

function schRenderBatch() {
  const { batch: b, domains, executions } = SCH.batch;
  const act = b.active_execution, det = SCH.execDetail;
  const statusBtns = b.status === "active" ? schBtn("batch-status", "Pause", { id: b.id, status: "paused" }) + schBtn("batch-status", "Disable", { id: b.id, status: "disabled" }, "btn btn-ghost btn-sm")
    : b.status === "paused" ? schBtn("batch-status", "Resume", { id: b.id, status: "active" }) + schBtn("batch-status", "Disable", { id: b.id, status: "disabled" }, "btn btn-ghost btn-sm")
      : schBtn("batch-status", "Enable", { id: b.id, status: "active" });
  const domRows = (domains || []).map(d => {
    const c = d.counts || {};
    return `<tr class="clickable" data-sch-row="open-domain" data-id="${esc(d.id)}">
      <td><div class="sch-mono" style="font-weight:600">${esc(d.domain)}</div>${d.organization ? `<div class="hint">${esc(d.organization)}</div>` : ""}</td>
      <td>${schKw(d.keywords)}</td><td>${schPill(d.status)}</td>
      <td class="hint">${d.last_scan_at ? esc(ago(d.last_scan_at)) : "never"}${d.last_status && d.last_status !== "ok" ? `<div style="color:var(--danger-accent)" title="${esc(d.last_status)}">failed</div>` : ""}</td>
      <td class="num">${c.new ? `<span class="lc lc-new">${schNum(c.new)}</span>` : "0"}</td><td class="num" style="color:var(--danger-accent);font-weight:700">${schNum(c.confirmed)}</td><td class="num">${schNum(c.potential)}</td>
      <td class="col-actions">${schBtn("run-domain", "Run", { id: d.id, batch: b.id }, "btn btn-ghost btn-xs")}
        ${d.status === "active" ? schBtn("domain-status", "Pause", { id: d.id, status: "paused" }, "btn btn-ghost btn-xs") : schBtn("domain-status", "Resume", { id: d.id, status: "active" }, "btn btn-ghost btn-xs")}
        ${schBtn("remove-domain", "Remove", { id: d.id, batch: b.id, name: d.domain }, "btn btn-danger-ghost btn-xs")}</td></tr>`;
  }).join("");
  const execRows = (executions || []).map(e => `<tr class="${SCH.execOpen === e.id ? "expanded" : ""}">
      <td>${esc(schWhen(e.started || e.created))}<div class="hint">${esc(SCH_TRIGGER[e.trigger] || e.trigger)}${e.scheduled_for ? ` · slot ${esc(schWhen(e.scheduled_for))}` : ""}</div></td>
      <td>${schPill(e.status)}</td><td class="num">${schNum(e.completed)}/${schNum(e.total)}</td><td class="num" style="color:var(--danger-accent)">${schNum(e.failed)}</td>
      <td class="num">${schNum(e.new_findings)}</td><td class="hint">${esc(schDur(e.started, e.finished))}</td>
      <td class="col-actions">${schBtn("toggle-exec", SCH.execOpen === e.id ? "Hide" : "Domains", { id: e.id }, "btn btn-ghost btn-xs")}
        ${["queued", "running"].includes(e.status) ? schBtn("cancel-exec", "Cancel", { id: e.id }, "btn btn-danger-ghost btn-xs")
          : (e.failed || e.cancelled) ? schBtn("retry-exec", "Retry failed", { id: e.id }, "btn btn-secondary btn-xs") : ""}</td></tr>
      ${SCH.execOpen === e.id && det && det.execution.id === e.id ? `<tr class="detail"><td colspan="7"><div class="table-wrap"><table class="table sch-table"><thead><tr><th>Domain</th><th>Status</th><th class="num">Attempts</th><th>Result</th><th>Time</th><th></th></tr></thead><tbody>${schJobRows(det.jobs)}</tbody></table></div></td></tr>` : ""}`).join("");
  const notify = b.notify || {};
  document.getElementById("sch-root").innerHTML = `
    <div class="stack" style="gap:18px">
      <div><div class="sch-crumbs"><button type="button" data-sch="go-list">Scan Scheduler</button><span>/</span><span>${esc(b.name)}</span></div>
      <div class="sch-head"><div><h2>${esc(b.name)} ${schPill(b.display_status)}</h2><div class="sch-sub">${esc(b.schedule_text)}${b.next_run_at ? ` · next run ${esc(schWhen(b.next_run_at))} (${esc(schRel(b.next_run_at))})` : ""} · depth ${esc(b.depth)} · missed runs: ${b.missed_policy === "skip" ? "skip" : "run once"}${b.description ? `<br>${esc(b.description)}` : ""}</div></div>
        <div class="sch-actions">${act ? schBtn("cancel-exec", "Cancel run", { id: act.id }, "btn btn-danger-ghost btn-sm") : schBtn("run-batch", "Run now", { id: b.id }, "btn btn-primary btn-sm")}
          ${statusBtns}${schBtn("add-domains", "+ Domains", { id: b.id })}${schBtn("edit-batch", "Edit", { id: b.id })}${schBtn("dup-batch", "Duplicate", { id: b.id }, "btn btn-ghost btn-sm")}
          <a class="btn btn-secondary btn-sm" href="/api/scheduler/batches/${encodeURIComponent(b.id)}/export?format=csv&view=all" download title="All findings of every domain in this batch">Export CSV</a>
          ${schBtn("dm-batch", "Delete…", { id: b.id }, "btn btn-danger-ghost btn-sm")}</div></div></div>
      <div class="sch-tiles">
        <div class="sch-tile t-accent"><div class="t-val">${schNum(b.domain_count)}</div><div class="t-label">Domains</div></div>
        <div class="sch-tile t-warn"><div class="t-val">${schNum(b.counts.new)}</div><div class="t-label">New</div></div>
        <div class="sch-tile t-danger"><div class="t-val">${schNum(b.counts.confirmed)}</div><div class="t-label">Confirmed</div></div>
        <div class="sch-tile"><div class="t-val">${schNum(b.counts.potential)}</div><div class="t-label">Potential</div></div>
        <div class="sch-tile"><div class="t-val">${schNum((b.counts.updated || 0) + (b.counts.reappeared || 0))}</div><div class="t-label">Changed</div></div>
        <div class="sch-tile"><div class="t-val">${schNum(b.counts.unreachable)}</div><div class="t-label">Unreachable</div></div>
      </div>
      ${act ? `<div class="sch-panel"><h3>Live run <span>${schPill(act.status)}</span></h3>${schProgress(act)}${(act.current || []).length ? `<div class="hint sch-mono" style="margin-top:6px">Now: ${esc(act.current.join(", "))}</div>` : ""}
        ${det && det.execution.id === act.id ? `<div class="table-wrap" style="margin-top:12px"><table class="table sch-table"><thead><tr><th>Domain</th><th>Status</th><th class="num">Attempts</th><th>Result</th><th>Time</th><th></th></tr></thead><tbody>${schJobRows(det.jobs)}</tbody></table></div>` : ""}</div>` : ""}
      <div class="sch-panel"><h3>Monitored domains <span class="hint" style="text-transform:none;letter-spacing:0">click a row for its dashboard</span></h3>
        ${domRows ? `<div class="table-wrap"><table class="table sch-table"><thead><tr><th>Domain</th><th>Keywords</th><th>Status</th><th>Last scan</th><th class="num">New</th><th class="num">Confirmed</th><th class="num">Potential</th><th></th></tr></thead><tbody>${domRows}</tbody></table></div>`
          : `<div class="sch-empty"><b>No domains in this batch</b>${schBtn("add-domains", "+ Add domains", { id: b.id }, "btn btn-primary btn-sm")}</div>`}</div>
      <div class="sch-panel"><h3>Execution history</h3>
        ${execRows ? `<div class="table-wrap"><table class="table sch-table"><thead><tr><th>Started</th><th>Status</th><th class="num">Done</th><th class="num">Failed</th><th class="num">New</th><th>Duration</th><th></th></tr></thead><tbody>${execRows}</tbody></table></div>` : `<div class="hint">No runs yet.</div>`}</div>
      <div class="sch-panel"><h3>Notifications</h3><div class="hint">In-app alerts ${notify.in_app ? "on" : "off"} · new findings ${notify.on_new ? "on" : "off"} (${esc(notify.min_classification || "potential")} and above) · failures ${notify.on_failure ? "on" : "off"} · webhook ${notify.webhook && notify.webhook.set ? esc(notify.webhook.hint) : "not set"}</div></div>
    </div>`;
}

// ----------------------------------------------------------------------------- domain dashboard
async function schLoadDomain() {
  const id = encodeURIComponent(SCH.domainId);
  const tab = SCH.domainTab;
  const reqs = [settingsCall("GET", `/api/scheduler/domains/${id}`)];
  if (["new", "all", "confirmed", "potential", "inactive", "dismissed"].includes(tab)) {
    const qs = new URLSearchParams({ view: tab, page: SCH.page, page_size: 50, sort: SCH.sort, q: SCH.q });
    reqs.push(settingsCall("GET", `/api/scheduler/domains/${id}/findings?${qs}`));
  } else if (tab === "history") reqs.push(settingsCall("GET", `/api/scheduler/domains/${id}/observations?limit=300`));
  else if (tab === "scans") reqs.push(settingsCall("GET", `/api/scheduler/domains/${id}/jobs?limit=100`));
  const [dom, list] = await Promise.all(reqs);
  SCH.domain = dom;
  SCH.list = list || null;
  schRenderDomain();
  return !!dom.active_job;
}

function schFindingRows(items) {
  return items.map(f => {
    const sel = SCH.selected.has(f.id);
    return `<tr class="${sel ? "is-selected" : ""}">
      <td><input type="checkbox" data-sch-check="${esc(f.id)}" ${sel ? "checked" : ""} aria-label="Select ${esc(f.host)}"></td>
      <td><div class="sch-mono" style="font-weight:600;word-break:break-all">${esc(f.host)}</div>${f.unicode && f.unicode !== f.host ? `<div class="hint">${esc(f.unicode)}</div>` : ""}${f.title ? `<div class="hint" title="${esc(f.title)}">${esc(f.title.slice(0, 70))}</div>` : ""}</td>
      <td><span class="lc cls-${esc(f.classification)}">${esc(f.classification)}</span></td>
      <td><span class="lc lc-${esc(f.lifecycle)}">${esc(f.lifecycle_label || f.lifecycle)}</span>${f.under_review ? ` <span class="lc lc-review">Under review</span>` : ""}</td>
      <td><span class="score ${f.score >= 70 ? "score-high" : f.score >= 40 ? "score-med" : "score-low"}">${esc(f.score)}</span></td>
      <td class="hint">${esc(f.matched_keyword || "—")}<div>${esc(f.matching_technique || "")}</div></td>
      <td class="hint">${esc(f.dns_status || "")}<div class="sch-mono">${esc((f.a || [])[0] || "")}</div></td>
      <td class="hint" title="${esc(schWhen(f.first_seen))}">${esc(ago(f.first_seen))}</td><td class="hint" title="${esc(schWhen(f.last_seen))}">${esc(ago(f.last_seen))}</td>
      <td class="col-actions">${schBtn("finding-history", "History", { id: f.id, host: f.host }, "btn btn-ghost btn-xs")}${schBtn("investigate", "Investigate", { host: f.host }, "btn btn-ghost btn-xs")}</td></tr>`;
  }).join("");
}

function schBulkHtml() {
  const dismissedTab = SCH.domainTab === "dismissed";
  return SCH.selected.size ? `<div class="row" style="gap:6px;flex-wrap:wrap"><span class="hint">${SCH.selected.size} selected</span>
      ${schBtn("review", "Mark under review", { on: "1" }, "btn btn-ghost btn-xs")}${schBtn("review", "Clear review", { on: "0" }, "btn btn-ghost btn-xs")}
      ${dismissedTab ? schBtn("dismiss", "Restore", { on: "0" }, "btn btn-secondary btn-xs") : schBtn("dismiss", "Dismiss as false positive", { on: "1" }, "btn btn-secondary btn-xs")}
      ${schBtn("dm-findings", "Delete selected…", {}, "btn btn-danger-ghost btn-xs")}</div>` : "";
}

function schSelectionChanged() {
  // update the rows and the bulk bar in place (no full re-render: keeps focus and scroll position)
  document.querySelectorAll("#sch-root [data-sch-check]").forEach(c => {
    c.checked = SCH.selected.has(c.dataset.schCheck);
    c.closest("tr").classList.toggle("is-selected", c.checked);
  });
  const bar = document.getElementById("sch-bulk");
  if (bar) bar.innerHTML = schBulkHtml();
}

function schRenderDomain() {
  const d = SCH.domain, c = d.counts || {}, tab = SCH.domainTab, list = SCH.list;
  const batch = (d.batches || [])[0];
  const id = d.id;
  const tabs = SCH_TABS.map(([k, label]) => {
    const n = { new: c.new, all: c.total, confirmed: c.confirmed, potential: c.potential, inactive: c.inactive, dismissed: c.dismissed, scans: d.scans, history: d.observations }[k];
    return `<button type="button" class="tab ${tab === k ? "active" : ""}" data-sch="domain-tab" data-tab="${k}" role="tab" aria-selected="${tab === k}">${label}${n !== undefined ? ` <span class="count">${schNum(n)}</span>` : ""}</button>`;
  }).join("");
  let body = "";
  if (["new", "all", "confirmed", "potential", "inactive", "dismissed"].includes(tab)) {
    const items = (list && list.items) || [];
    const bulk = `<div id="sch-bulk">${schBulkHtml()}</div>`;
    body = `<div class="sch-toolbar"><div class="row" style="gap:8px">
        <input class="input" id="sch-q" type="search" placeholder="Search hosts" value="${esc(SCH.q)}" maxlength="100">
        <select class="select select-sm" id="sch-sort" style="width:auto">${[["score", "Highest score"], ["last_seen", "Last seen"], ["first_seen", "First seen"], ["host", "Host A–Z"]].map(([v, l]) => `<option value="${v}" ${SCH.sort === v ? "selected" : ""}>${l}</option>`).join("")}</select></div>${bulk}</div>
      ${items.length ? `<div class="table-wrap"><table class="table sch-table"><thead><tr><th><input type="checkbox" data-sch-checkall aria-label="Select all on this page"></th><th>Host</th><th>Class</th><th>Lifecycle</th><th>Score</th><th>Match</th><th>DNS</th><th>First seen</th><th>Last seen</th><th></th></tr></thead><tbody>${schFindingRows(items)}</tbody></table>
        <div class="sch-pager"><span>${schNum(list.total)} findings · page ${list.page} of ${list.pages}</span>${schBtn("page", "‹ Prev", { p: list.page - 1 }, "btn btn-ghost btn-xs")}${schBtn("page", "Next ›", { p: list.page + 1 }, "btn btn-ghost btn-xs")}</div></div>`
        : `<div class="sch-empty"><b>${tab === "new" ? "No new discoveries" : tab === "dismissed" ? "Nothing dismissed" : "No findings here"}</b>${d.last_scan_at ? `Last scan ${esc(ago(d.last_scan_at))}.` : "This domain has not been scanned yet."}</div>`}`;
  } else if (tab === "history") {
    const obs = (list && list.observations) || [];
    body = obs.length ? `<div class="table-wrap"><table class="table sch-table"><thead><tr><th>Observed</th><th>Host</th><th>Change</th><th>Class</th><th>Score</th><th>DNS</th></tr></thead><tbody>${obs.map(o => `<tr>
        <td class="hint">${esc(schWhen(o.observed_at))}</td><td class="sch-mono">${esc(o.host)}</td><td><span class="lc lc-${esc(o.change)}">${esc(o.change)}</span></td>
        <td>${o.classification ? `<span class="lc cls-${esc(o.classification)}">${esc(o.classification)}</span>` : "—"}</td><td>${o.score ?? "—"}</td><td class="hint">${esc(o.dns_status || "")}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="sch-empty"><b>No observations yet</b>Every scan records what it saw for each finding here.</div>`;
  } else if (tab === "scans") {
    const jobs = (list && list.jobs) || [];
    body = jobs.length ? `<div class="table-wrap"><table class="table sch-table"><thead><tr><th>Started</th><th>Status</th><th class="num">Attempts</th><th>Result</th><th>Keywords used</th><th>Duration</th><th></th></tr></thead><tbody>${jobs.map(j => `<tr>
        <td class="hint">${esc(schWhen(j.started || j.created))}</td><td>${schPill(j.status === "queued" && j.attempts ? "retry" : j.status)}</td><td class="num">${schNum(j.attempts)}</td>
        <td class="hint">${j.status === "completed" ? esc(j.message || "") : `<span title="${esc(j.error || "")}">${esc((j.error || j.message || "").slice(0, 110))}</span>`}</td>
        <td>${schKw(j.keywords_used)}</td><td class="hint">${esc(schDur(j.started, j.finished))}</td>
        <td class="col-actions">${j.hunt_id ? schBtn("open-hunt", "Full report", { id: j.hunt_id }, "btn btn-ghost btn-xs") : ""}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="sch-empty"><b>No scans yet</b></div>`;
  } else {
    body = `<form class="stack" id="sch-domain-form" data-sch-form="domain" data-id="${esc(id)}" style="max-width:760px">
      <div class="sch-form-grid">
        <label class="field span-2"><span>Keywords used for this domain only</span><input class="input" name="keywords" value="${esc((d.keywords || []).join(", "))}" placeholder="paypal, venmo, braintree"><span class="hint">Comma separated. Empty = the brand name from the domain only.</span></label>
        <label class="field span-2"><span>Allowlist (your own domains, never reported)</span><input class="input" name="allowlist" value="${esc((d.allowlist || []).join(", "))}" placeholder="paypal.me, paypalobjects.com"></label>
        <label class="field"><span>Organization</span><input class="input" name="organization" value="${esc(d.organization || "")}" maxlength="120"></label>
        <label class="field"><span>Scan depth</span><select class="select" name="depth">${["quick", "standard", "deep"].map(x => `<option ${d.depth === x ? "selected" : ""}>${x}</option>`).join("")}</select></label>
      </div><div class="row"><button type="submit" class="btn btn-primary btn-sm">Save settings</button></div></form>
      <div class="sch-panel sch-danger" style="margin-top:18px"><h3>Danger zone</h3><div class="row" style="gap:8px;flex-wrap:wrap">
        ${schBtn("dm-clear-history", "Clear scan history…", { id }, "btn btn-danger-ghost btn-sm")}${schBtn("dm-all-findings", "Delete all findings…", { id }, "btn btn-danger-ghost btn-sm")}${schBtn("dm-domain", "Delete domain and its data…", { id }, "btn btn-danger btn-sm")}</div>
        <div class="hint" style="margin-top:8px">Each action shows exactly what will be removed and asks you to type <code>${esc(d.domain)}</code>.</div></div>`;
  }
  const act = d.active_job;
  document.getElementById("sch-root").innerHTML = `
    <div class="stack" style="gap:16px">
      <div><div class="sch-crumbs"><button type="button" data-sch="go-list">Scan Scheduler</button><span>/</span>${batch ? `<button type="button" data-sch="open-batch" data-id="${esc(batch.id)}">${esc(batch.name)}</button><span>/</span>` : ""}<span>${esc(d.domain)}</span></div>
      <div class="sch-head"><div><h2 class="sch-mono" style="font-family:var(--font-display)">${esc(d.domain)} ${schPill(d.status)}</h2>
        <div class="sch-sub">${d.organization ? `${esc(d.organization)} · ` : ""}last scan ${d.last_scan_at ? esc(ago(d.last_scan_at)) : "never"}${d.last_status && d.last_status !== "ok" ? ` · <span style="color:var(--danger-accent)">${esc(d.last_status)}</span>` : ""} · in ${schNum((d.batches || []).length)} batch(es)</div>
        <div style="margin-top:6px">${schKw(d.keywords)}</div></div>
        <div class="sch-actions">${act ? schPill(act.status) : schBtn("run-domain", "Run now", { id, batch: batch ? batch.id : "" }, "btn btn-primary btn-sm")}
          ${d.status === "active" ? schBtn("domain-status", "Pause", { id, status: "paused" }) : schBtn("domain-status", "Resume", { id, status: "active" })}
          ${schBtn("domain-tab", "Edit keywords", { tab: "settings" })}
          ${schBtn("copy-urls", "Copy URLs", { id, view: ["new", "all", "confirmed", "potential", "inactive", "dismissed"].includes(tab) ? tab : "all" }, "btn btn-secondary btn-sm")}
          <a class="btn btn-secondary btn-sm" href="/api/scheduler/domains/${encodeURIComponent(id)}/export?format=csv&view=${["new", "confirmed", "potential"].includes(tab) ? tab : "all"}" download>Export CSV</a>
          <a class="btn btn-ghost btn-sm" href="/api/scheduler/domains/${encodeURIComponent(id)}/export?format=json&view=all" download>JSON</a></div></div></div>
      ${act ? `<div class="sch-panel"><h3>Scanning now</h3><div class="sch-progress"><div class="p-line"><span><b>${esc(act.message || act.stage || "Working")}</b></span><span>${Math.round(act.progress || 0)}%</span></div><div class="sch-bar"><span style="width:${Math.round(act.progress || 0)}%"></span></div></div></div>` : ""}
      <div class="sch-tiles">
        <div class="sch-tile"><div class="t-val">${schNum(c.total)}</div><div class="t-label">Findings</div></div>
        <div class="sch-tile t-danger"><div class="t-val">${schNum(c.confirmed)}</div><div class="t-label">Confirmed</div></div>
        <div class="sch-tile t-warn"><div class="t-val">${schNum(c.potential)}</div><div class="t-label">Potential</div></div>
        <div class="sch-tile t-accent"><div class="t-val">${schNum(c.new)}</div><div class="t-label">New</div></div>
        <div class="sch-tile"><div class="t-val">${schNum((c.updated || 0) + (c.reappeared || 0))}</div><div class="t-label">Changed</div></div>
        <div class="sch-tile"><div class="t-val">${schNum(c.unreachable)}</div><div class="t-label">Unreachable</div></div>
        <div class="sch-tile"><div class="t-val">${schNum(d.scans)}</div><div class="t-label">Scans</div></div>
      </div>
      <div class="tabs" role="tablist">${tabs}</div>
      <div>${body}</div>
    </div>`;
}

// ----------------------------------------------------------------------------- editor (create / edit / add domains)
async function schTimezones() {
  if (SCH.tz) return SCH.tz;
  try { SCH.tz = (await settingsCall("GET", "/api/scheduler/timezones")).timezones; } catch (e) { SCH.tz = ["UTC"]; }
  return SCH.tz;
}

function schCloseDialog() { const d = document.getElementById("sch-dialog"); if (d.open) d.close(); SCH.editor = null; }

async function schOpenEditor(batch, importOnly = false) {
  const tzs = await schTimezones();
  const local = (Intl.DateTimeFormat().resolvedOptions().timeZone) || "UTC";
  const s = (batch && batch.schedule) || { frequency: "daily", time: "02:00", timezone: tzs.includes(local) ? local : "UTC", weekdays: [0], interval_hours: 24 };
  const n = (batch && batch.notify) || { in_app: true, on_new: true, on_failure: true, min_classification: "potential" };
  SCH.editor = { batch, importOnly, freq: s.frequency, entries: [] };
  document.getElementById("sch-dialog-title").textContent = importOnly ? `Add domains to ${batch.name}` : batch ? `Edit ${batch.name}` : "New scan batch";
  const importer = !batch || importOnly ? `
    <div class="sch-section-title">Domains</div>
    <div class="sch-import">
      <textarea class="textarea" id="sch-imp-text" rows="6" placeholder="One per line. Optional keywords and organization after commas:&#10;paypal.com, paypal; venmo, PayPal Holdings&#10;https://www.microsoft.com/login&#10;amazon.com, amazon; aws"></textarea>
      <div class="row" style="gap:8px;flex-wrap:wrap">${schBtn("imp-validate", "Validate list")}<label class="btn btn-ghost btn-sm" style="cursor:pointer">Upload TXT / CSV / Excel<input type="file" id="sch-imp-file" accept=".txt,.csv,.tsv,.xlsx" hidden></label>
        <span class="hint">URLs become hostnames, duplicates are merged, nothing is dropped silently. Max 2 MB.</span></div>
      <div id="sch-imp-out"></div>
    </div>` : "";
  const settings = importOnly ? "" : `
    <div class="sch-form-grid">
      <label class="field"><span>Batch name</span><input class="input" name="name" required maxlength="120" value="${esc(batch ? batch.name : "")}" placeholder="Retail banking brands"></label>
      <label class="field"><span>Organization (default for its domains)</span><input class="input" name="organization" maxlength="120" value="${esc(batch ? batch.organization || "" : "")}"></label>
      <label class="field span-2"><span>Description</span><input class="input" name="description" maxlength="1000" value="${esc(batch ? batch.description || "" : "")}"></label>
    </div>
    <div class="sch-section-title">Schedule</div>
    <div class="sch-seg" role="group" aria-label="Frequency">${[["daily", "Daily"], ["weekly", "Weekly"], ["interval", "Every N hours"], ["manual", "Manual only"]].map(([v, l]) => `<button type="button" data-sch="freq" data-v="${v}" class="${s.frequency === v ? "active" : ""}">${l}</button>`).join("")}</div>
    <div class="sch-form-grid" id="sch-freq-fields">
      <label class="field" data-show="daily weekly"><span>Time of day</span><input class="input" type="time" name="time" value="${esc(s.time || "02:00")}"></label>
      <label class="field" data-show="daily weekly"><span>Time zone</span><input class="input" name="timezone" list="sch-tz-list" value="${esc(s.timezone || "UTC")}"><datalist id="sch-tz-list">${tzs.map(t => `<option value="${esc(t)}">`).join("")}</datalist></label>
      <div class="field span-2" data-show="weekly"><span>Days</span><div class="sch-days">${SCH_DAYS.map((d, i) => `<label><input type="checkbox" name="wd" value="${i}" ${(s.weekdays || []).includes(i) ? "checked" : ""}>${d}</label>`).join("")}</div></div>
      <label class="field" data-show="interval"><span>Every (hours)</span><input class="input" type="number" name="interval_hours" min="1" max="720" step="1" value="${esc(s.interval_hours || 24)}"></label>
      <label class="field"><span>Scan depth</span><select class="select" name="depth">${["quick", "standard", "deep"].map(x => `<option ${(batch ? batch.depth : "standard") === x ? "selected" : ""}>${x}</option>`).join("")}</select></label>
      <label class="field"><span>If a run was missed (server off)</span><select class="select" name="missed_policy"><option value="run_once" ${(!batch || batch.missed_policy !== "skip") ? "selected" : ""}>Run once when back</option><option value="skip" ${batch && batch.missed_policy === "skip" ? "selected" : ""}>Skip to the next slot</option></select></label>
    </div>
    <div class="sch-section-title">Notifications</div>
    <div class="switches">
      <label class="switch"><input type="checkbox" name="in_app" ${n.in_app ? "checked" : ""}><span class="track"></span><span>In-app alerts</span></label>
      <label class="switch"><input type="checkbox" name="on_new" ${n.on_new ? "checked" : ""}><span class="track"></span><span>New findings</span></label>
      <label class="switch"><input type="checkbox" name="on_failure" ${n.on_failure ? "checked" : ""}><span class="track"></span><span>Failed runs</span></label>
    </div>
    <div class="sch-form-grid">
      <label class="field"><span>Alert on</span><select class="select" name="min_classification"><option value="potential" ${n.min_classification !== "confirmed" ? "selected" : ""}>Potential and confirmed</option><option value="confirmed" ${n.min_classification === "confirmed" ? "selected" : ""}>Confirmed only</option></select></label>
      <label class="field"><span>Webhook (Slack / Teams / Discord)</span><input class="input" name="webhook_url" maxlength="2000" placeholder="${batch && n.webhook && n.webhook.set ? `Saved (${esc(n.webhook.hint)}). Type to replace` : "https://hooks.slack.com/…"}">
        ${batch && n.webhook && n.webhook.set ? `<label class="hint" style="display:flex;gap:6px;align-items:center"><input type="checkbox" name="webhook_remove"> remove the saved webhook</label>` : ""}</label>
    </div>`;
  document.getElementById("sch-dialog-body").innerHTML = `
    <form class="stack" id="sch-editor" data-sch-form="editor" novalidate>
      ${settings}${importer}
      <div id="sch-editor-error"></div>
      <div class="row" style="justify-content:flex-end;gap:8px"><button type="button" class="btn btn-ghost" onclick="schCloseDialog()">Cancel</button>
        <button type="submit" class="btn btn-primary" id="sch-editor-save">${importOnly ? "Add domains" : batch ? "Save changes" : "Create batch"}</button></div>
    </form>`;
  schShowFreq();
  const file = document.getElementById("sch-imp-file");
  if (file) file.addEventListener("change", schUpload);
  document.getElementById("sch-dialog").showModal();
}

function schShowFreq() {
  const f = SCH.editor && SCH.editor.freq;
  document.querySelectorAll("#sch-freq-fields [data-show]").forEach(el => { el.hidden = !el.dataset.show.split(" ").includes(f); });
  document.querySelectorAll('#sch-dialog [data-sch="freq"]').forEach(b => b.classList.toggle("active", b.dataset.v === f));
}

async function schParse(payload) {
  const out = document.getElementById("sch-imp-out");
  out.innerHTML = `<div class="hint">Validating…</div>`;
  try {
    const r = await settingsCall("POST", "/api/scheduler/parse", { ...payload, batch_id: SCH.editor.batch ? SCH.editor.batch.id : null });
    SCH.editor.entries = r.entries;
    schRenderImport();
  } catch (err) { out.innerHTML = `<div class="alert alert-danger">${I.alert}<div>${esc(err.message)}</div></div>`; }
}

function schUpload(e) {
  const f = e.target.files && e.target.files[0];
  if (!f) return;
  if (f.size > 2 * 1024 * 1024) { showToast("The file is larger than 2 MB"); e.target.value = ""; return; }
  const reader = new FileReader();
  reader.onload = () => {
    const b64 = String(reader.result || "").split(",")[1] || "";
    schParse({ filename: f.name, content_b64: b64 });
  };
  reader.readAsDataURL(f);
  e.target.value = "";
}

function schRenderImport() {
  const es = SCH.editor.entries || [];
  const valid = es.filter(x => x.status === "valid").length, invalid = es.filter(x => x.status === "invalid").length, dup = es.filter(x => x.status === "duplicate").length;
  const rows = es.map((x, i) => `<tr class="row-${esc(x.status)}">
      <td class="hint">${esc(x.line)}</td>
      <td>${x.status === "invalid" ? `<input class="input sch-mono" data-imp-fix="${i}" value="${esc(x.fix ?? x.input)}" aria-label="Correct line ${esc(x.line)}"><div class="hint" style="color:var(--danger)">${esc(x.error)}</div>`
        : `<div class="sch-mono">${esc(x.domain)}</div>${x.input !== x.domain ? `<div class="hint">${esc(x.input.slice(0, 80))}</div>` : ""}${x.already_in_batch ? `<div class="hint">already in this batch</div>` : ""}`}</td>
      <td>${x.status === "valid" ? `<input class="input" data-imp-kw="${i}" value="${esc((x.keywords || []).join(", "))}" placeholder="keywords">` : `<span class="hint">${esc((x.keywords || []).join(", "))}</span>`}</td>
      <td>${x.status === "valid" ? `<input class="input" data-imp-org="${i}" value="${esc(x.organization || "")}" placeholder="organization">` : ""}</td>
      <td>${schPill(x.status === "valid" ? "ok" : x.status === "duplicate" ? "skipped" : "failed", x.status === "valid" ? "Valid" : x.status === "duplicate" ? "Merged" : "Invalid")}${(x.warnings || []).length ? `<div class="hint">${esc(x.warnings.join("; "))}</div>` : ""}</td>
      <td class="col-actions"><button type="button" class="icon-btn" data-sch="imp-remove" data-i="${i}" aria-label="Remove line">&times;</button></td></tr>`).join("");
  document.getElementById("sch-imp-out").innerHTML = es.length ? `
    <div class="sch-import-summary">${schPill("ok", `${valid} valid`)}${invalid ? schPill("failed", `${invalid} invalid`) : ""}${dup ? schPill("skipped", `${dup} merged duplicates`) : ""}
      ${invalid ? schBtn("imp-revalidate", "Re-check corrections", {}, "btn btn-secondary btn-xs") : ""}</div>
    <div class="sch-preview"><table class="table sch-table"><thead><tr><th>Line</th><th>Domain</th><th>Keywords</th><th>Organization</th><th>Status</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
    ${invalid ? `<div class="hint" style="color:var(--warning)">${invalid} invalid line(s) will not be added until corrected or removed.</div>` : ""}` : `<div class="hint">No lines found.</div>`;
}

function schSyncImportEdits() {
  const es = (SCH.editor && SCH.editor.entries) || [];
  document.querySelectorAll("[data-imp-kw]").forEach(el => { const e = es[+el.dataset.impKw]; if (e) e.keywords = el.value.split(/[,;|]/).map(k => k.trim()).filter(Boolean); });
  document.querySelectorAll("[data-imp-org]").forEach(el => { const e = es[+el.dataset.impOrg]; if (e) e.organization = el.value.trim(); });
  document.querySelectorAll("[data-imp-fix]").forEach(el => { const e = es[+el.dataset.impFix]; if (e) e.fix = el.value.trim(); });
}

function schImportText() {
  // rebuild the list (valid rows with their edited keywords, corrected invalid rows) for a fresh server-side check
  return (SCH.editor.entries || []).filter(x => x.status !== "duplicate").map(x => {
    if (x.status === "invalid") return x.fix ?? x.input;
    return [x.domain, (x.keywords || []).join("; "), x.organization || ""].join(", ").replace(/,\s*,\s*$/, "").replace(/,\s*$/, "");
  }).join("\n");
}

async function schSaveEditor(form) {
  schSyncImportEdits();
  const ed = SCH.editor, fd = new FormData(form), errBox = document.getElementById("sch-editor-error");
  const entries = (ed.entries || []).filter(x => x.status === "valid").map(x => ({ domain: x.domain, keywords: x.keywords || [], organization: x.organization || "" }));
  const textLeft = document.getElementById("sch-imp-text");
  if (textLeft && textLeft.value.trim() && !(ed.entries || []).length) { errBox.innerHTML = `<div class="alert alert-warning">${I.alert}<div>Click “Validate list” first so you can review the domains before saving.</div></div>`; return; }
  const invalid = (ed.entries || []).filter(x => x.status === "invalid").length;
  if (invalid && !window.confirm(`${invalid} invalid line(s) will not be added. Continue with the ${entries.length} valid domain(s)?`)) return;
  const btn = document.getElementById("sch-editor-save");
  setBusy(btn, true, "Saving…");
  errBox.innerHTML = "";
  try {
    if (ed.importOnly) {
      if (!entries.length) throw new Error("Add at least one valid domain");
      const r = await settingsCall("POST", `/api/scheduler/batches/${encodeURIComponent(ed.batch.id)}/domains`, { entries });
      showToast(`Added ${r.added.length} domain(s)${r.already_in_batch.length ? `, ${r.already_in_batch.length} already present` : ""}${r.errors.length ? `, ${r.errors.length} rejected` : ""}`);
    } else {
      const schedule = { frequency: ed.freq, time: fd.get("time") || "02:00", timezone: (fd.get("timezone") || "UTC").trim(),
        weekdays: fd.getAll("wd").map(Number), interval_hours: Number(fd.get("interval_hours") || 24) };
      const notify = { in_app: !!fd.get("in_app"), on_new: !!fd.get("on_new"), on_failure: !!fd.get("on_failure"), min_classification: fd.get("min_classification") };
      const hook = (fd.get("webhook_url") || "").trim();
      if (hook) notify.webhook_url = hook;
      else if (fd.get("webhook_remove")) notify.webhook_url = "";
      else if (!ed.batch) notify.webhook_url = "";
      const body = { name: (fd.get("name") || "").trim(), description: (fd.get("description") || "").trim(), organization: (fd.get("organization") || "").trim(),
        schedule, depth: fd.get("depth"), missed_policy: fd.get("missed_policy"), notify };
      if (!body.name) throw new Error("The batch needs a name");
      if (ed.batch) {
        await settingsCall("PATCH", `/api/scheduler/batches/${encodeURIComponent(ed.batch.id)}`, body);
        showToast("Batch updated");
      } else {
        const r = await settingsCall("POST", "/api/scheduler/batches", { ...body, domains: entries });
        showToast(`Batch created with ${r.import.added.length} domain(s)`);
        SCH.batchId = r.batch.id;
        SCH.view = "batch";
      }
    }
    schCloseDialog();
    schRefresh();
  } catch (err) {
    errBox.innerHTML = `<div class="alert alert-danger">${I.alert}<div>${esc(err.message)}</div></div>`;
  } finally { setBusy(btn, false); }
}

async function schEngineSettings() {
  const r = await settingsCall("GET", "/api/scheduler/settings");
  const s = r.settings, L = r.limits;
  SCH.editor = { settings: true };
  document.getElementById("sch-dialog-title").textContent = "Scheduler engine settings";
  const num = (k, label, hint) => `<label class="field"><span>${label}</span><input class="input" type="number" name="${k}" min="${L[k][0]}" max="${L[k][1]}" value="${esc(s[k])}"><span class="hint">${hint} (${L[k][0]}–${L[k][1]})</span></label>`;
  document.getElementById("sch-dialog-body").innerHTML = `<form class="stack" data-sch-form="settings">
    <label class="switch"><input type="checkbox" name="enabled" ${s.enabled ? "checked" : ""}><span class="track"></span><span>Run schedules automatically</span></label>
    <div class="sch-form-grid">${num("concurrency", "Parallel domain scans per run", "domains scanned at the same time")}${num("max_parallel_executions", "Parallel batch runs", "batches running at the same time")}
      ${num("job_timeout", "Per-domain timeout (s)", "a scan running longer is stopped and retried")}${num("max_attempts", "Attempts per domain", "retries use exponential back-off")}
      ${num("retry_base_seconds", "First retry delay (s)", "doubles on every attempt; rate limits wait 3× longer")}</div>
    <div id="sch-editor-error"></div>
    <div class="row" style="justify-content:flex-end;gap:8px"><button type="button" class="btn btn-ghost" onclick="schCloseDialog()">Cancel</button><button type="submit" class="btn btn-primary">Save</button></div></form>`;
  document.getElementById("sch-dialog").showModal();
}

// ----------------------------------------------------------------------------- actions
async function schAction(act, ds, el) {
  const id = ds.id;
  const post = (path, body) => settingsCall("POST", path, body || {});
  switch (act) {
    case "go-list": return schGo("list");
    case "open-batch": return schGo("batch", { batchId: id });
    case "open-domain": return schGo("domain", { domainId: id });
    case "new-batch": return schOpenEditor(null);
    case "settings": return schEngineSettings();
    case "edit-batch": {
      const b = (SCH.batch && SCH.batch.batch.id === id) ? SCH.batch.batch : (await settingsCall("GET", `/api/scheduler/batches/${encodeURIComponent(id)}`)).batch;
      return schOpenEditor(b);
    }
    case "add-domains": {
      const b = (SCH.batch && SCH.batch.batch.id === id) ? SCH.batch.batch : (await settingsCall("GET", `/api/scheduler/batches/${encodeURIComponent(id)}`)).batch;
      return schOpenEditor(b, true);
    }
    case "run-batch": await post(`/api/scheduler/batches/${encodeURIComponent(id)}/run`); showToast("Run started"); break;
    case "batch-status": await post(`/api/scheduler/batches/${encodeURIComponent(id)}/status`, { status: ds.status }); showToast(`Batch ${ds.status === "active" ? "resumed" : ds.status}`); break;
    case "dup-batch": { const r = await post(`/api/scheduler/batches/${encodeURIComponent(id)}/duplicate`); showToast(`Duplicated as “${r.batch.name}” (paused)`); break; }
    case "cancel-exec": if (!window.confirm("Cancel this run? Running scans stop at their next checkpoint.")) return; await post(`/api/scheduler/executions/${encodeURIComponent(id)}/cancel`); showToast("Cancelling the run"); break;
    case "retry-exec": await post(`/api/scheduler/executions/${encodeURIComponent(id)}/retry`); showToast("Retry started for the failed domains"); break;
    case "toggle-exec": SCH.execOpen = SCH.execOpen === id ? null : id; break;
    case "run-domain": await post(`/api/scheduler/domains/${encodeURIComponent(id)}/run`, ds.batch ? { batch_id: ds.batch } : {}); showToast("Domain scan started"); break;
    case "domain-status": await settingsCall("PATCH", `/api/scheduler/domains/${encodeURIComponent(id)}`, { status: ds.status }); showToast(ds.status === "paused" ? "Domain paused" : "Domain resumed"); break;
    case "remove-domain": return dmOpen({ type: "batch-remove", id: ds.batch, domainIds: [id], label: ds.name });
    case "domain-tab": SCH.domainTab = ds.tab; SCH.page = 1; SCH.selected.clear(); break;
    case "copy-urls": {
      const items = (SCH.list && SCH.list.items) || [];
      const view = ds.view || "all";
      const total = SCH.list ? Number(SCH.list.total || 0) : 0;
      const domainUrlOf = f => safeExternalDomainUrl(f.host, f.final_url || f.url || "");
      if (items.length && items.length >= total) {
        copyDomainUrls(items, `${view} tab`, domainUrlOf);
      } else {
        const exp = await settingsCall("GET", `/api/scheduler/domains/${encodeURIComponent(id)}/export?format=json&view=${encodeURIComponent(view)}`);
        copyDomainUrls(exp.findings || [], `${view} tab`, domainUrlOf);
      }
      return;
    }
    case "page": { const p = Number(ds.p); if (!SCH.list || p < 1 || p > SCH.list.pages) return; SCH.page = p; break; }
    case "finding-history": return schFindingHistory(id, ds.host);
    case "investigate": if (typeof investigateDomain === "function") investigateDomain(ds.host); return;
    case "open-hunt": if (typeof openHistoryHunt === "function") { switchTab("history"); openHistoryHunt(id); } return;
    case "review": {
      const r = await post(`/api/scheduler/domains/${encodeURIComponent(SCH.domainId)}/findings/review`, { ids: [...SCH.selected], under_review: ds.on === "1" });
      showToast(`${r.updated} finding(s) updated`); SCH.selected.clear(); break;
    }
    case "dismiss": {
      const on = ds.on === "1";
      const reason = on ? (window.prompt("Why is this a false positive? (optional, kept with the finding)", "") ?? null) : "";
      if (reason === null) return;
      const r = await post(`/api/scheduler/domains/${encodeURIComponent(SCH.domainId)}/findings/dismiss`, { ids: [...SCH.selected], dismissed: on, reason });
      showToast(on ? `${r.updated} finding(s) dismissed: hidden from review and alerts` : `${r.updated} finding(s) restored`);
      SCH.selected.clear(); break;
    }
    case "dm-findings": return dmOpen({ type: "findings", id: SCH.domainId, ids: [...SCH.selected] });
    case "dm-all-findings": return dmOpen({ type: "findings", id, all: true });
    case "dm-clear-history": return dmOpen({ type: "domain-history", id });
    case "dm-domain": return dmOpen({ type: "domain", id });
    case "dm-batch": return dmOpen({ type: "batch", id });
    case "freq": SCH.editor.freq = ds.v; return schShowFreq();
    case "imp-validate": { const t = document.getElementById("sch-imp-text").value; if (!t.trim()) return showToast("Paste some domains first"); return schParse({ text: t }); }
    case "imp-revalidate": schSyncImportEdits(); return schParse({ text: schImportText() });
    case "imp-remove": schSyncImportEdits(); SCH.editor.entries.splice(Number(ds.i), 1); return schRenderImport();
    default: return;
  }
  schRefresh();
}

async function schFindingHistory(fid, host) {
  SCH.editor = { history: true };
  document.getElementById("sch-dialog-title").textContent = `History of ${host}`;
  document.getElementById("sch-dialog-body").innerHTML = `<div class="hint">Loading…</div>`;
  document.getElementById("sch-dialog").showModal();
  try {
    const r = await settingsCall("GET", `/api/scheduler/domains/${encodeURIComponent(SCH.domainId)}/findings/history?finding_id=${encodeURIComponent(fid)}`);
    document.getElementById("sch-dialog-body").innerHTML = r.history.length ? `<div class="table-wrap"><table class="table sch-table"><thead><tr><th>Observed</th><th>Change</th><th>Class</th><th>Score</th><th>Verdict</th><th>DNS</th><th>Sources</th></tr></thead><tbody>
      ${r.history.map(o => `<tr><td class="hint">${esc(schWhen(o.observed_at))}</td><td><span class="lc lc-${esc(o.change)}">${esc(o.change)}</span></td><td>${o.classification ? `<span class="lc cls-${esc(o.classification)}">${esc(o.classification)}</span>` : "—"}</td>
        <td>${o.score ?? "—"}</td><td class="hint">${esc(o.verdict || "")}</td><td class="hint">${esc(o.dns_status || "")}</td><td class="hint">${esc((o.sources || []).join(", "))}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="hint">No observations recorded.</div>`;
  } catch (err) { document.getElementById("sch-dialog-body").innerHTML = `<div class="alert alert-danger">${I.alert}<div>${esc(err.message)}</div></div>`; }
}

// delegated events (one listener for the page and one for the dialog)
document.addEventListener("click", async e => {
  const root = e.target.closest("#sch-root, #sch-dialog");
  if (!root) return;
  const btn = e.target.closest("[data-sch]");
  const row = !btn && e.target.closest("[data-sch-row]");
  if (row && !e.target.closest("button, a, input, select")) { e.preventDefault(); return schAction(row.dataset.schRow, row.dataset, row); }
  if (!btn) return;
  e.preventDefault();
  if (SCH.busy && !["freq", "imp-remove", "toggle-exec", "domain-tab", "page"].includes(btn.dataset.sch)) return;
  SCH.busy = true;
  btn.disabled = true;
  try { await schAction(btn.dataset.sch, btn.dataset, btn); }
  catch (err) { showToast(err.message || "Something went wrong", 4200, "danger"); }
  finally { SCH.busy = false; if (btn.isConnected) btn.disabled = false; }
});

document.addEventListener("change", e => {
  const chk = e.target.closest("[data-sch-check]");
  if (chk) {
    if (chk.checked) SCH.selected.add(chk.dataset.schCheck); else SCH.selected.delete(chk.dataset.schCheck);
    return schSelectionChanged();
  }
  if (e.target.matches("[data-sch-checkall]")) {
    ((SCH.list && SCH.list.items) || []).forEach(f => { if (e.target.checked) SCH.selected.add(f.id); else SCH.selected.delete(f.id); });
    return schSelectionChanged();
  }
  if (e.target.id === "sch-sort") { SCH.sort = e.target.value; SCH.page = 1; schRefresh(); }
});

let schSearchTimer = null;
document.addEventListener("input", e => {
  if (e.target.id !== "sch-q") return;
  clearTimeout(schSearchTimer);
  schSearchTimer = setTimeout(() => { SCH.q = e.target.value.trim(); SCH.page = 1; schRefresh().then(() => { const q = document.getElementById("sch-q"); if (q) { q.focus(); q.setSelectionRange(q.value.length, q.value.length); } }); }, 350);
});

document.addEventListener("submit", async e => {
  const form = e.target.closest("[data-sch-form]");
  if (!form) return;
  e.preventDefault();
  const kind = form.dataset.schForm;
  try {
    if (kind === "editor") return await schSaveEditor(form);
    if (kind === "settings") {
      const fd = new FormData(form);
      const body = { enabled: !!fd.get("enabled") };
      ["concurrency", "max_parallel_executions", "job_timeout", "max_attempts", "retry_base_seconds"].forEach(k => { body[k] = Number(fd.get(k)); });
      await settingsCall("PUT", "/api/scheduler/settings", body);
      showToast("Scheduler settings saved");
      schCloseDialog();
      return schRefresh();
    }
    if (kind === "domain") {
      const fd = new FormData(form);
      const split = v => String(v || "").split(/[,;\n]/).map(x => x.trim()).filter(Boolean);
      await settingsCall("PATCH", `/api/scheduler/domains/${encodeURIComponent(form.dataset.id)}`, {
        keywords: split(fd.get("keywords")), allowlist: split(fd.get("allowlist")), organization: (fd.get("organization") || "").trim(), depth: fd.get("depth") });
      showToast("Domain settings saved");
      return schRefresh();
    }
  } catch (err) {
    const box = document.getElementById("sch-editor-error");
    if (box) box.innerHTML = `<div class="alert alert-danger">${I.alert}<div>${esc(err.message)}</div></div>`;
    else showToast(err.message, 4200, "danger");
  }
});

document.addEventListener("visibilitychange", () => {
  if (!document.hidden && typeof currentTab !== "undefined" && currentTab === "scheduler") schRefresh(true);
});
