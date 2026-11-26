"use strict";
// =============================================================================
// Case Management: Triage, Takedown Pack, History, Watchlist & Alerts
// =============================================================================

function fmtTs(ts) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function fmtIn(ts) {
  if (!ts) return "-";
  const sec = Math.round(ts - Date.now() / 1000);
  if (sec <= 0) return "due now";
  return sec < 5400 ? `in ${Math.max(1, Math.round(sec / 60))} min` : sec < 172800 ? `in ${Math.round(sec / 3600)} h` : `in ${Math.round(sec / 86400)} d`;
}

function caseBlockHtml(c) {
  return `<div>
    <h4>Case</h4>
    <div class="stack" style="gap: 8px;">
      <select class="select" data-domain="${esc(c.domain)}" aria-label="Case status" onchange="onTriageChange(this)">${triageOptions(triageStatus(c))}</select>
      <input class="input" type="text" maxlength="1000" data-note-for="${esc(c.domain)}" aria-label="Analyst note" placeholder="Analyst note" value="${esc((c.triage && c.triage.note) || "")}">
      <div class="row">
        <button type="button" class="btn btn-secondary btn-sm" data-domain="${esc(c.domain)}" onclick="saveCaseNote(this)">Save note</button>
        <button type="button" class="btn btn-primary btn-sm" data-domain="${esc(c.domain)}" onclick="openTakedown(this)">Takedown pack</button>
      </div>
    </div>
  </div>`;
}

function findCandidate(domain) {
  return (currentHunt?.candidates || []).find(x => x.domain === domain);
}

async function setTriage(domain, status, note = null) {
  const c = findCandidate(domain);
  if (!c) return;
  try {
    c.triage = await settingsCall("PUT", "/api/triage", { brand: currentHunt.target, domain, status, note: note ?? ((c.triage && c.triage.note) || "") });
    renderHuntTable();
    showToast(status === "false_positive" ? `${domain} marked as a false positive and hidden from review` : `${domain}: ${TRIAGE_LABEL[status]}`);
  } catch (err) {
    showToast(`Could not save: ${err.message}`, 6000);
    renderHuntTable();
  }
}

function onTriageChange(select) { setTriage(select.dataset.domain, select.value); }

function saveCaseNote(btn) {
  const domain = btn.dataset.domain;
  const input = [...document.querySelectorAll("input[data-note-for]")].find(i => i.dataset.noteFor === domain);
  const c = findCandidate(domain);
  if (input && c) setTriage(domain, triageStatus(c), input.value);
}

function closeTakedown() {
  const dlg = document.getElementById("takedown-dialog");
  if (dlg.open) dlg.close();
}

function contactRow(label, name, email) {
  return `<div class="kv-row"><span class="kv-label">${esc(label)}</span><span>${esc(name || "Unknown")}</span>${email ? `<code>${esc(email)}</code>${copyBtn(email, "Address copied")}` : `<span class="muted">no abuse address published</span>`}</div>`;
}

async function openTakedown(btn) {
  const domain = btn.dataset.domain;
  const dlg = document.getElementById("takedown-dialog");
  const body = document.getElementById("td-body");
  document.getElementById("td-title").innerText = `Takedown pack: ${domain}`;
  body.innerHTML = `<div class="loading show" style="padding: 8px 0;"><div class="spinner"></div><div><div style="font-weight: 600;">Looking up abuse contacts…</div><div class="hint">Registrar and hosting provider (RDAP)</div></div></div>`;
  if (!dlg.open) dlg.showModal();
  if (!currentHunt?.hunt_id) {
    body.innerHTML = `<div class="alert alert-danger">${I.alert}<div>This hunt was not saved to history, so no pack can be built.</div></div>`;
    return;
  }
  try {
    const hid = encodeURIComponent(currentHunt.hunt_id);
    const q = `domain=${encodeURIComponent(domain)}`;
    const pack = await settingsCall("GET", `/api/hunts/${hid}/takedown?${q}`);
    const ct = pack.contacts;
    const mail = pack.email;
    body.innerHTML = `
      <section>
        <h3 class="group-title">Who can take it down</h3>
        <div class="stack" style="gap: 6px;">
          ${contactRow("Registrar", ct.registrar.name, ct.registrar.abuse_email)}
          ${(ct.hosting || []).map(h => contactRow("Host", [h.network, h.org].filter(Boolean).join(" · ") + ` (${h.ip})`, h.abuse_email)).join("")}
          ${(ct.forms || []).map(f => `<div class="kv-row"><span class="kv-label">Form</span>${linkBtn(f.url, f.name, f.name, "btn btn-secondary btn-xs")}</div>`).join("")}
          ${!ct.registrar.abuse_email && !(ct.hosting || []).length ? `<div class="hint">No contacts were found. Try the reporting channels below.</div>` : ""}
        </div>
      </section>
      <section>
        <h3 class="group-title">Draft abuse report <span class="muted" style="text-transform: none; letter-spacing: 0;">(review before sending)</span></h3>
        <div class="stack" style="gap: 8px;">
          <div class="query-row"><span class="q-label">To</span><code title="${esc(mail.to)}">${esc(mail.to)}</code><div class="q-actions">${copyBtn(mail.to, "Recipients copied")}</div></div>
          <div class="query-row"><span class="q-label">Subject</span><code title="${esc(mail.subject)}">${esc(mail.subject)}</code><div class="q-actions">${copyBtn(mail.subject, "Subject copied")}</div></div>
          <textarea class="textarea mono" rows="14" readonly aria-label="Abuse report text">${esc(mail.body)}</textarea>
          <div class="row"><button type="button" class="btn btn-secondary btn-sm" data-copy="${esc(mail.body)}" data-copy-label="Report text copied">Copy report text</button></div>
        </div>
      </section>
      <section>
        <h3 class="group-title">Evidence &amp; wider reporting</h3>
        <div class="row">
          ${linkBtn(`/api/hunts/${hid}/report?${q}`, "Open evidence report", "Opens a printable report (Print to PDF)", "btn btn-primary btn-sm")}
          ${(ct.channels || []).map(ch => ch.url ? linkBtn(ch.url, ch.name, ch.does, "btn btn-secondary btn-sm") : `<span class="badge" title="${esc(ch.does)}">${esc(ch.name)}: ${esc(ch.email)}</span>${copyBtn(ch.email, "Address copied")}`).join("")}
        </div>
      </section>
      <div class="spread" style="border-top: 1px solid var(--border); padding-top: 14px;">
        <span class="hint">Nothing is sent by this tool. After you report, record it on the case.</span>
        <button type="button" class="btn btn-secondary btn-sm" data-domain="${esc(domain)}" onclick="markTakedownSent(this)">Mark as takedown sent</button>
      </div>`;
  } catch (err) {
    body.innerHTML = `<div class="alert alert-danger">${I.alert}<div>${esc(err.message)}</div></div>`;
  }
}

async function markTakedownSent(btn) {
  await setTriage(btn.dataset.domain, "takedown_sent");
  closeTakedown();
}

let historyData = [];

async function loadHistory() {
  try { historyData = (await settingsCall("GET", "/api/hunts")).hunts || []; }
  catch (err) { showToast(`Could not load history: ${err.message}`, 6000); historyData = []; }
  const sel = document.getElementById("history-brand");
  const keep = sel.value;
  const brands = [...new Set(historyData.map(h => h.target))].sort();
  sel.innerHTML = `<option value="">All brands (${brands.length})</option>` + brands.map(b => `<option value="${esc(b)}">${esc(b)}</option>`).join("");
  if (brands.includes(keep)) sel.value = keep;
  renderHistory();
}

function renderHistory() {
  const brand = document.getElementById("history-brand").value;
  const rows = historyData.filter(h => !brand || h.target === brand);
  document.getElementById("history-tbody").innerHTML = rows.length ? rows.map(h => `
    <tr class="plain">
      <td data-label="Brand"><span class="domain-name">${esc(h.target)}</span>${h.scheduled ? ` <span class="badge badge-sm">scheduled</span>` : ""}</td>
      <td data-label="When">${esc(fmtTs(h.created))}</td>
      <td data-label="Depth">${esc(h.depth || "")}</td>
      <td data-label="High risk" class="num">${h.high_risk ? `<span class="badge badge-danger">${h.high_risk}</span>` : "0"}</td>
      <td data-label="Suspicious" class="num">${h.suspicious ? `<span class="badge badge-warning">${h.suspicious}</span>` : "0"}</td>
      <td data-label="Registered" class="num">${esc(h.registered)}</td>
      <td data-label="New" class="num">${h.new_count ? `<span class="badge badge-accent">${h.new_count}</span>` : "0"}</td>
      <td class="col-actions"><div class="row" style="gap: 4px; flex-wrap: nowrap; justify-content: flex-end;">
        <button type="button" class="btn btn-secondary btn-xs" onclick="openHistoryHunt('${esc(h.id)}')">Open</button>
        <button type="button" class="btn btn-danger-ghost btn-xs" onclick="deleteHistoryHunt('${esc(h.id)}')">Delete</button></div></td>
    </tr>`).join("") : `<tr><td colspan="8">${emptyState("No hunts saved yet", "Every hunt is saved automatically and appears here.")}</td></tr>`;
}

async function openHistoryHunt(id) {
  try {
    currentHunt = await settingsCall("GET", `/api/hunts/${encodeURIComponent(id)}`);
    huntFilter = (currentHunt.stats.high_risk || currentHunt.stats.suspicious) ? "risky" : "all";
    huntPlatformFilter = "all";
    huntView = "lookalikes";
    huntExpanded.clear();
    switchTab("hunt");
    renderHunt(currentHunt);
  } catch (err) {
    showToast(`Could not open the hunt: ${err.message}`, 6000);
  }
}

async function deleteHistoryHunt(id) {
  if (!window.confirm("Delete this hunt from history? Case notes and statuses are kept.")) return;
  try {
    await settingsCall("DELETE", `/api/hunts/${encodeURIComponent(id)}`);
    if (currentHunt?.hunt_id === id) currentHunt = null;
    await loadHistory();
    showToast("Hunt deleted");
  } catch (err) {
    showToast(`Could not delete: ${err.message}`, 6000);
  }
}

let watchData = null;
const LEVEL_BADGE = { high: "badge-danger", medium: "badge-warning", error: "badge-danger", info: "" };

function updateAlertBadge(n) {
  const b = document.getElementById("watch-nav-badge");
  if (!b) return;
  b.hidden = !n;
  b.innerText = n > 99 ? "99+" : String(n || "");
}

async function refreshAlertBadge() {
  try { updateAlertBadge((await settingsCall("GET", "/api/alerts")).unread); } catch (e) { /* offline */ }
}

async function loadWatch() {
  try { watchData = await settingsCall("GET", "/api/watchlist"); }
  catch (err) { showToast(`Could not load the watchlist: ${err.message}`, 6000); return; }
  renderWatch();
  updateAlertBadge(watchData.unread);
}

function renderWatch() {
  const { watchlist, alerts, scheduler } = watchData;
  document.getElementById("watch-sched-note").innerText = scheduler
    ? "The scheduler is running while this server is up. It checks for due brands every 30 seconds."
    : "The scheduler is off (BRAND_HUNTER_SCHEDULER=0). Use Run now to hunt manually.";
  document.getElementById("watch-tbody").innerHTML = watchlist.length ? watchlist.map(w => {
    const st = w.last_status || "";
    const stBadge = st === "ok" ? `<span class="badge badge-sm badge-success">OK</span>` : st === "running" ? `<span class="badge badge-sm badge-accent">Running</span>`
      : st ? `<span class="badge badge-sm badge-danger" title="${esc(st)}">Failed</span>` : `<span class="badge badge-sm">Waiting</span>`;
    return `<tr class="plain">
      <td data-label="Brand"><span class="domain-name">${esc(w.brand)}</span><div class="hint">${esc(w.depth)} depth · alert at ${w.min_score}+${(w.allowlist || []).length ? ` · ${w.allowlist.length} own domain(s)` : ""}</div></td>
      <td data-label="Every">${w.interval_hours} h</td>
      <td data-label="Last run">${esc(fmtTs(w.last_run))}</td>
      <td data-label="Next run">${w.enabled ? esc(fmtIn(w.next_run)) : `<span class="muted">paused</span>`}</td>
      <td data-label="Status">${stBadge}</td>
      <td data-label="Webhook">${w.webhook.set ? `<code title="Saved webhook">${esc(w.webhook.hint)}</code>` : `<span class="muted">in-app only</span>`}</td>
      <td data-label="Active"><label class="switch"><input type="checkbox" ${w.enabled ? "checked" : ""} onchange="patchWatch(${w.id}, { enabled: this.checked })" aria-label="Monitor ${esc(w.brand)}"><span class="track"></span></label></td>
      <td class="col-actions"><div class="row" style="gap: 4px; flex-wrap: wrap; justify-content: flex-end;">
        <button type="button" class="btn btn-secondary btn-xs" onclick="runWatch(${w.id})">Run now</button>
        ${w.webhook.set ? `<button type="button" class="btn btn-ghost btn-xs" onclick="testWebhook(${w.id})">Test webhook</button>` : ""}
        ${w.last_hunt ? `<button type="button" class="btn btn-ghost btn-xs" onclick="openHistoryHunt('${esc(w.last_hunt)}')">Last result</button>` : ""}
        <button type="button" class="btn btn-danger-ghost btn-xs" onclick="removeWatch(${w.id}, '${esc(w.brand)}')">Remove</button></div></td>
    </tr>`;
  }).join("") : `<tr><td colspan="8">${emptyState("No brands monitored yet", "Add a brand above. The first hunt sets the baseline; later hunts alert only on new lookalikes.")}</td></tr>`;

  document.getElementById("alerts-list").innerHTML = alerts.length ? alerts.map(a => `
    <div class="alert-item${a.read ? "" : " unread"}">
      <div class="spread"><div class="row"><span class="badge badge-sm ${LEVEL_BADGE[a.level] || ""}">${esc(a.level)}</span><strong>${esc(a.title)}</strong></div><span class="hint">${esc(fmtTs(a.created))}</span></div>
      <pre class="alert-body">${esc(a.body)}</pre>
      <div class="row">${a.delivery ? `<span class="hint">${esc(a.delivery)}</span>` : ""}${a.hunt_id ? `<button type="button" class="btn btn-ghost btn-xs" onclick="openHistoryHunt('${esc(a.hunt_id)}')">Open hunt</button>` : ""}</div>
    </div>`).join("") : emptyState("No alerts yet", "New high-risk and suspicious lookalikes of monitored brands appear here.");
  document.getElementById("btn-alerts-read").hidden = !watchData.unread;
}

async function addWatch(e) {
  e.preventDefault();
  const btn = document.getElementById("btn-watch-add");
  setBusy(btn, true, "Adding…");
  try {
    watchData = await settingsCall("POST", "/api/watchlist", {
      brand: document.getElementById("watch-brand").value.trim(),
      interval_hours: Number(document.getElementById("watch-interval").value),
      depth: document.getElementById("watch-depth").value,
      min_score: Number(document.getElementById("watch-min").value || 45),
      webhook_url: document.getElementById("watch-webhook").value.trim(),
      allowlist: document.getElementById("watch-allow").value.split(/[\s,;]+/).map(x => x.trim()).filter(Boolean),
    });
    e.target.reset();
    renderWatch();
    showToast("Added. The baseline hunt is starting now.");
  } catch (err) {
    showToast(err.message, 6000);
  } finally {
    setBusy(btn, false);
  }
}

async function patchWatch(id, body) {
  try { watchData = await settingsCall("PATCH", `/api/watchlist/${id}`, body); renderWatch(); }
  catch (err) { showToast(err.message, 6000); loadWatch(); }
}

async function runWatch(id) {
  try { await settingsCall("POST", `/api/watchlist/${id}/run`); showToast("Hunt started. Open History when it finishes."); setTimeout(loadWatch, 1500); }
  catch (err) { showToast(err.message, 6000); }
}

async function testWebhook(id) {
  try { const r = await settingsCall("POST", `/api/watchlist/${id}/test-webhook`); showToast(r.ok ? `Test alert ${r.message}` : `Test failed: ${r.message}`, r.ok ? 3000 : 7000); }
  catch (err) { showToast(err.message, 6000); }
}

async function removeWatch(id, brand) {
  if (!window.confirm(`Stop monitoring ${brand}? Past hunts stay in History.`)) return;
  try { watchData = await settingsCall("DELETE", `/api/watchlist/${id}`); renderWatch(); }
  catch (err) { showToast(err.message, 6000); }
}

async function markAlertsRead() {
  try { await settingsCall("POST", "/api/alerts/read", {}); await loadWatch(); }
  catch (err) { showToast(err.message, 6000); }
}

function updateIocLinks(data) {
  const base = data.hunt_id ? `/api/hunts/${encodeURIComponent(data.hunt_id)}/ioc` : null;
  [["hunt-ioc-txt", "txt"], ["hunt-ioc-stix", "stix"]].forEach(([id, fmt]) => {
    const a = document.getElementById(id);
    if (!a) return;
    a.hidden = !base;
    if (base) a.href = `${base}?format=${fmt}&min_score=45`;
  });
}
