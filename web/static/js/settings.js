"use strict";
// =============================================================================
// Settings: Threat-Intel API Keys (with multi-key rotation) & MongoDB storage
// =============================================================================

let storageData = null;
let keysData = null;
let keysRefreshTimer = null;
const keyResults = {};

const EYE = svg('<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>', 15);
const EYE_OFF = svg('<path d="M9.9 4.2A10 10 0 0 1 12 4c6.5 0 10 8 10 8a17 17 0 0 1-3.2 4.2M6.6 6.6A17 17 0 0 0 2 12s3.5 8 10 8a9.7 9.7 0 0 0 5.4-1.6M14.1 14.1a3 3 0 1 1-4.2-4.2M2 2l20 20"/>', 15);
const I_TRASH = svg('<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>', 15);
const I_UP = svg('<path d="m18 15-6-6-6 6"/>', 15);
const I_PULSE = svg('<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>', 15);

function setStorageResult(ok, message) {
  document.getElementById("storage-test-result").innerHTML = message
    ? `<div class="alert ${ok ? "alert-success" : "alert-danger"}">${ok ? I.check.replace('width="12" height="12"', 'width="16" height="16"') : I.alert}<div>${esc(message)}</div></div>` : "";
}

async function loadStorage() {
  const errBox = document.getElementById("storage-error");
  try { storageData = await settingsCall("GET", "/api/storage"); errBox.innerHTML = ""; renderStorage(); }
  catch (err) { errBox.innerHTML = `<div class="alert alert-danger">${I.alert}<div>${esc(err.message)}</div></div>`; }
}

function countsHtml(c, withCandidates = false) {
  const items = [["Hunts", c.hunts], ...(withCandidates ? [["Lookalike documents", c.candidates]] : []), ["Case notes", c.triage], ["Watched brands", c.watchlist], ["Alerts", c.alerts]];
  return items.filter(([, v]) => v !== undefined && v !== null).map(([k, v]) => `<div class="stat"><div class="stat-label">${k}</div><div class="stat-value" style="font-size: 20px;">${esc(Number(v).toLocaleString())}</div></div>`).join("");
}

function renderStorage() {
  const st = storageData;
  const mongoConfigured = !!st.explicit;
  const badge = st.connected
    ? `<span class="badge badge-success">MongoDB · connected</span>`
    : `<span class="badge badge-danger">MongoDB unreachable</span>`;

  let where;
  if (st.connected) {
    where = kvRows([["Hosts", (st.uri.hosts || []).join(", ")], ["Database", st.uri.database], ["Credentials", st.uri.has_credentials ? "in connection string (hidden)" : "none"],
    ["Connection", st.uri.srv ? "mongodb+srv (Atlas / DNS seed list)" : "mongodb://"], ["Driver", st.driver],
    ["Transactions", st.transactions ? "Supported: deletes are all-or-nothing" : "Standalone server: deletes use the recoverable workflow (enable a replica set for transactions)"]]);
  } else {
    where = `<div class="alert alert-danger">${I.alert}<div><strong>${esc(st.error || "Cannot connect")}</strong><div class="hint" style="margin-top: 4px;">Hunts still run but are not saved until MongoDB connects again.</div></div></div>`;
  }
  document.getElementById("storage-active").innerHTML = `
    <div class="stack" style="gap: 16px;">
      <div class="row">${badge}<span class="hint">${mongoConfigured ? "Saved connection string (MONGODB_URI)" : `Local default server (${esc(st.default_uri || "")})`}</span></div>
      ${where}
      ${st.connected && st.stats ? `<div class="stats">${countsHtml(st.stats, true)}</div>` : ""}
    </div>`;

  const locked = !st.editable;
  document.getElementById("mongo-uri").disabled = locked;
  document.getElementById("mongo-db").disabled = locked;
  document.getElementById("btn-storage-save").disabled = locked;
  document.getElementById("storage-locked").hidden = !locked;
  document.getElementById("btn-storage-clear").hidden = !(mongoConfigured && !locked);
  document.getElementById("mongo-uri").placeholder = mongoConfigured
    ? `Saved (${(st.uri.hosts || []).join(", ")}). Enter a new connection string to replace it` : "mongodb://127.0.0.1:27017";
  document.getElementById("mongo-db").placeholder = mongoConfigured ? st.uri.database : "brand_hunter";
}

async function testStorage(btn) {
  setBusy(btn, true, "Testing…");
  setStorageResult(true, "");
  try {
    const r = await settingsCall("POST", "/api/storage/test", { uri: document.getElementById("mongo-uri").value.trim(), db: document.getElementById("mongo-db").value.trim() });
    setStorageResult(r.ok, r.message);
  } catch (err) { setStorageResult(false, err.message); }
  finally { setBusy(btn, false); }
}

async function saveStorage(e) {
  e.preventDefault();
  const uri = document.getElementById("mongo-uri").value.trim();
  if (!uri) return showToast("Enter a connection string first");
  const btn = document.getElementById("btn-storage-save");
  setBusy(btn, true, "Connecting…");
  try {
    const r = await settingsCall("PUT", "/api/storage", { uri, db: document.getElementById("mongo-db").value.trim() });
    document.getElementById("mongo-uri").value = "";
    document.getElementById("mongo-db").value = "";
    setStorageResult(true, `${r.test.message} Storage is now MongoDB.`);
    storageData = r.status;
    renderStorage();
    currentHunt = null;
    historyData = [];
    loadSources();
    showToast("Storage switched to MongoDB");
  } catch (err) { setStorageResult(false, `Not saved. ${err.message}`); }
  finally { setBusy(btn, false); }
}

async function clearStorage() {
  if (!window.confirm("Forget the saved connection string and use the local MongoDB server (mongodb://127.0.0.1:27017)?")) return;
  try {
    storageData = await settingsCall("DELETE", "/api/storage");
    setStorageResult(true, "Using the local default MongoDB server.");
    renderStorage();
    currentHunt = null;
    historyData = [];
    loadSources();
  } catch (err) { setStorageResult(false, err.message); }
}

async function loadStorageBadge() {
  const el = document.getElementById("sidebar-storage");
  if (!el) return;
  try {
    const st = await settingsCall("GET", "/api/storage");
    const label = st.connected ? "MongoDB" : "offline";
    el.innerHTML = `<button type="button" class="src-row" onclick="switchTab('storage')" title="Where hunts and case notes are saved. Click to change"><span class="dot ${st.connected ? "dot-success" : "dot-danger"}"></span><span>Storage</span><span>${label}</span></button>`;
  } catch (e) { el.innerHTML = ""; }
}

// ----------------------------------------------------------------------------- Source availability
const HEALTH_BADGE = { up: "badge-success", challenged: "badge-warning", rate_limited: "badge-warning", degraded: "badge-warning", down: "badge-danger" };

async function checkSourceHealth(btn) {
  const box = document.getElementById("source-health-list");
  if (btn) { btn.disabled = true; btn.textContent = "Checking..."; }
  try {
    const r = await fetch(`/api/sources/health${btn ? "?force=true" : ""}`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const d = await r.json();
    box.innerHTML = d.free.map(s => `<span class="badge ${HEALTH_BADGE[s.status] || ""}" title="${esc(`${s.purpose} · ${s.detail} · ${s.ms} ms`)}">${esc(s.name)}: ${esc(s.status.replace("_", " "))}</span>`).join("")
      + `<span class="hint" style="margin-left: 6px;">${d.summary.up}/${d.summary.total} free sources up${d.cached ? " (cached)" : ""}</span>`;
  } catch (e) {
    box.innerHTML = `<span class="badge badge-danger">Check failed: ${esc(e.message)}</span>`;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Check availability"; }
  }
}

// ----------------------------------------------------------------------------- Source activity (moved off the results screens)
const ACTIVITY_BADGE = { plan: "", rate: "badge-warning", challenge: "", auth: "badge-danger", overloaded: "badge-warning", network: "badge-warning", other: "badge-warning" };

function agoText(ts) {
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  return s < 90 ? `${s}s ago` : s < 5400 ? `${Math.round(s / 60)} min ago` : s < 172800 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} days ago`;
}

async function loadSourceActivity() {
  const box = document.getElementById("source-activity-list");
  if (!box) return;
  try {
    const d = await (await fetch("/api/sources/events?hours=72")).json();
    document.getElementById("source-activity-mode").innerHTML = d.free_only
      ? `<strong>Free mode is on.</strong> Only free sources are used. Paid platforms (${esc((d.paid_sources || []).join(", "))}) are never called, even with a key saved. Skipped searches and limits from recent runs are logged here, not on the results screens.`
      : "Free mode is off: paid platforms with a saved key are used. Skipped searches and limits from recent runs are logged here.";
    if (!(d.sources || []).length) {
      box.innerHTML = `<span class="muted">No source issues in the last 72 hours.</span>`;
      return;
    }
    box.innerHTML = `<div class="table-wrap"><table class="table"><thead><tr><th>Source</th><th>What happened</th><th>Last seen</th><th>Times</th><th>What to do</th></tr></thead><tbody>
      ${d.sources.map(s => `<tr class="plain">
        <td>${pfLabel(s.source)}</td>
        <td><span class="badge badge-sm ${ACTIVITY_BADGE[s.latest.kind] || ""}">${esc(s.title)}</span>
          <div class="hint" style="margin-top:4px;">${esc(s.latest.message)}</div>
          <div class="hint">${esc([s.latest.context, s.latest.label, s.latest.target].filter(Boolean).join(" · "))}</div></td>
        <td class="mono">${esc(agoText(s.latest.time))}</td>
        <td class="num">${s.count}</td>
        <td class="hint">${esc(s.advice)}</td></tr>`).join("")}
      </tbody></table></div>`;
  } catch (e) {
    box.innerHTML = `<span class="muted">Could not load source activity.</span>`;
  }
}

async function clearSourceActivity() {
  try { await settingsCall("DELETE", "/api/sources/events"); } catch (e) { /* ignore */ }
  loadSourceActivity();
}

// ----------------------------------------------------------------------------- API Keys
async function loadKeys({ silent = false } = {}) {
  const errBox = document.getElementById("keys-error");
  try {
    keysData = await settingsCall("GET", "/api/settings/keys");
    errBox.innerHTML = "";
    renderKeys();
    if (!silent) loadSourceActivity();
  } catch (err) {
    if (silent) return;
    document.getElementById("keys-list").innerHTML = "";
    errBox.innerHTML = `<div class="alert alert-danger">${I.alert}<div>${esc(err.message)}</div></div>`;
  }
  clearTimeout(keysRefreshTimer);
  if (currentTab === "keys") keysRefreshTimer = setTimeout(() => loadKeys({ silent: true }), 15000);
}

function capitalize(t) { return t ? t[0].toUpperCase() + t.slice(1) : t; }
function fmtWait(sec) {
  if (sec === null || sec === undefined) return "";
  if (sec < 90) return `${sec}s`;
  if (sec < 5400) return `${Math.round(sec / 60)}m`;
  return `${Math.round(sec / 3600)}h`;
}

function keyStateBadge(k) {
  switch (k.state) {
    case "active": return `<span class="badge badge-sm badge-success">In use</span>`;
    case "cooling": return `<span class="badge badge-sm badge-warning" title="${esc(k.last_error || "")}">${esc(capitalize(k.reason || "paused"))} · ${fmtWait(k.available_in)}</span>`;
    case "exhausted": return `<span class="badge badge-sm badge-warning" title="${esc(k.last_error || "")}">Quota used up · retry in ${fmtWait(k.available_in)}</span>`;
    case "invalid": return `<span class="badge badge-sm badge-danger" title="${esc(k.last_error || "")}">Invalid key</span>`;
    default: return `<span class="badge badge-sm">Standby</span>`;
  }
}

function sourceSummary(src, main) {
  if (src.free_mode_off) return ["", "Paid platform · not used in free mode"];
  if (main.origin === "system") return ["badge-success", "Set in system environment"];
  const n = (main.keys || []).length;
  if (n) {
    const healthy = main.keys.filter(k => k.state === "active" || k.state === "standby").length;
    if (!healthy) return ["badge-danger", `${n === 1 ? "Key" : `All ${n} keys`} paused`];
    return ["badge-success", n === 1 ? "1 key" : `${n} keys · ${healthy} ready`];
  }
  if (!src.key_required) return ["badge-warning", "Working without a key"];
  return ["", "Not configured"];
}

function keyRowsHtml(src, f) {
  if (!f.keys.length) return "";
  const paused = f.keys.some(k => ["cooling", "exhausted", "invalid"].includes(k.state));
  return `
    <div class="key-list" role="list">
      ${f.keys.map(k => `
        <div class="key-row" role="listitem">
          <span class="key-pos">#${k.position}</span>
          <code class="key-hint">${esc(k.hint)}</code>
          ${keyStateBadge(k)}
          <span class="key-uses muted num">${k.uses ? plural(k.uses, "call") : ""}</span>
          <span class="key-actions">
            <button type="button" class="icon-btn" title="Test this key" onclick="testSavedKey(this, '${esc(src.id)}', '${esc(k.id)}')">${I_PULSE}</button>
            ${f.editable && k.position > 1 ? `<button type="button" class="icon-btn" title="Make primary" onclick="keyAction('primary', '${esc(f.name)}', '${esc(k.id)}')">${I_UP}</button>` : ""}
            ${f.editable ? `<button type="button" class="icon-btn danger" title="Remove this key" onclick="removeKey('${esc(src.id)}', '${esc(f.name)}', '${esc(k.id)}', ${k.position})">${I_TRASH}</button>` : ""}
          </span>
        </div>`).join("")}
    </div>
    ${f.keys.length > 1 || paused ? `<div class="row" style="gap: 6px;">
      ${f.keys.length > 1 ? `<button type="button" class="btn btn-ghost btn-xs" onclick="testAllKeys(this, '${esc(src.id)}')">Test all</button>` : ""}
      ${paused ? `<button type="button" class="btn btn-ghost btn-xs" onclick="resetKeys('${esc(src.id)}')">Reset paused keys</button>` : ""}
    </div>` : ""}`;
}

function renderKeys() {
  const { fields, sources } = keysData;
  const list = document.getElementById("keys-list");
  const typed = {};
  list.querySelectorAll("input[name]").forEach(i => { if (i.value) typed[i.name] = { value: i.value, type: i.type }; });
  const focused = document.activeElement?.closest?.("#keys-list") ? document.activeElement.getAttribute("name") : null;
  list.innerHTML = sources.map(src => {
    const fs = fields.filter(f => f.source === src.id);
    const main = fs.find(f => f.multi) || fs[0];
    const extras = fs.filter(f => !f.multi);
    const [cls, label] = sourceSummary(src, main);
    const full = main.keys.length >= main.max_keys;
    return `
      <section class="card key-card" data-source="${esc(src.id)}">
        <div class="card-head">
          <div>
            <h2 class="row" style="gap: 10px;">${pfLabel(src.id)}<span class="badge badge-sm ${cls}">${esc(label)}</span></h2>
            <p>${esc(src.does)}.${src.key_required ? "" : " Works anonymously; a key raises the limits."}</p>
          </div>
          <div class="actions">${src.link ? linkBtn(src.link, "Get a key", `Open ${src.name}`, "btn btn-ghost btn-sm") : ""}</div>
        </div>
        <div class="card-body stack">
          <div class="field">
            <span>${esc(main.label)}s <span class="muted" style="font-weight: 400;">(rotated in order)</span></span>
            ${keyRowsHtml(src, main)}
            ${main.editable ? (full ? `<span class="hint">Maximum of ${main.max_keys} keys reached.</span>` : `
              <form class="add-key" onsubmit="addKey(event, '${esc(src.id)}', '${esc(main.name)}')" autocomplete="off">
                <div class="secret-input">
                  <input class="input mono" name="${esc(main.name)}" type="password" autocomplete="off" spellcheck="false"
                    aria-label="${main.keys.length ? "Add another key" : "Paste your key"}" placeholder="${main.keys.length ? "Add another key for rotation" : "Paste your key"}">
                  <button type="button" class="icon-btn" aria-label="Show or hide" onclick="toggleSecret(this)">${EYE}</button>
                </div>
                <button type="submit" class="btn btn-primary btn-sm">Add key</button>
                <button type="button" class="btn btn-secondary btn-sm" onclick="testTypedKey(this, '${esc(src.id)}')">Test${src.id === "censys" ? " (1 query)" : ""}</button>
              </form>`) : `<span class="hint">Set in the system environment.</span>`}
            <span class="hint mono">${esc(main.name)}</span>
          </div>
          ${extras.map(f => `
            <form class="field" onsubmit="saveExtra(event, '${esc(src.id)}', '${esc(f.name)}')" autocomplete="off">
              <span>${esc(f.label)} <span class="muted" style="font-weight: 400;">(optional)</span></span>
              <div class="add-key">
                <input class="input mono" name="${esc(f.name)}" type="text" autocomplete="off" spellcheck="false" ${f.editable ? "" : "disabled"}
                  placeholder="${esc(f.set ? `Saved ${f.hint}. Enter a new value to replace it` : "Optional")}">
                <button type="submit" class="btn btn-secondary btn-sm" ${f.editable ? "" : "disabled"}>Save</button>
                ${f.set && f.editable ? `<button type="button" class="btn btn-danger-ghost btn-sm" onclick="clearExtra('${esc(src.id)}', '${esc(f.name)}')">Clear</button>` : ""}
              </div>
              <span class="hint mono">${esc(f.name)}</span>
            </form>`).join("")}
          <div class="key-result" id="keytest-${esc(src.id)}" aria-live="polite">${keyResults[src.id] || ""}</div>
        </div>
      </section>`;
  }).join("");
  Object.entries(typed).forEach(([name, t]) => {
    const input = list.querySelector(`input[name="${name}"]`);
    if (input && !input.disabled) { input.value = t.value; input.type = t.type; }
  });
  if (focused) list.querySelector(`input[name="${focused}"]`)?.focus();
}

function toggleSecret(btn) {
  const input = btn.parentElement.querySelector("input");
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  btn.innerHTML = show ? EYE_OFF : EYE;
}

function setKeyResult(source, ok, message, details = []) {
  keyResults[source] = `<div class="alert ${ok ? "alert-success" : "alert-danger"}">${ok ? I.check.replace('width="12" height="12"', 'width="16" height="16"') : I.alert}
    <div>${esc(message)}${details.length ? `<ul class="key-test-list">${details.map(d => `<li><code>#${d.position}</code> ${esc(d.message)}</li>`).join("")}</ul>` : ""}</div></div>`;
  const el = document.getElementById(`keytest-${source}`);
  if (el) el.innerHTML = keyResults[source];
}

function sourceName(source) { return keysData?.sources.find(s => s.id === source)?.name || source; }

async function refreshAfter(payload, source, message) {
  keysData = payload.fields ? payload : await settingsCall("GET", "/api/settings/keys");
  renderKeys();
  loadSources();
  if (message) showToast(message);
}

async function addKey(e, source, name) {
  e.preventDefault();
  const input = e.target.querySelector("input");
  const value = input.value.trim();
  if (!value) return showToast("Paste a key first");
  const btn = e.submitter || e.target.querySelector("[type=submit]");
  setBusy(btn, true, "Adding…");
  try {
    const payload = await settingsCall("POST", "/api/settings/keys/add", { name, value });
    input.value = "";
    await refreshAfter(payload, source, `${sourceName(source)} key added`);
    const f = keysData.fields.find(x => x.name === name);
    const last = f.keys[f.keys.length - 1];
    if (last) testSavedKey(null, source, last.id);
  } catch (err) { setBusy(btn, false); setKeyResult(source, false, err.message); }
}

async function keyAction(action, name, id) {
  const source = keysData.fields.find(f => f.name === name)?.source;
  try {
    const payload = await settingsCall("POST", `/api/settings/keys/${action}`, { name, id });
    await refreshAfter(payload, source, action === "primary" ? "Key moved to top" : "");
  } catch (err) { setKeyResult(source, false, err.message); }
}

async function removeKey(source, name, id, position) {
  if (!window.confirm(`Remove key #${position} from ${sourceName(source)}?`)) return;
  try { const payload = await settingsCall("POST", "/api/settings/keys/remove", { name, id }); await refreshAfter(payload, source, "Key removed"); }
  catch (err) { setKeyResult(source, false, err.message); }
}

async function resetKeys(source) {
  try { const payload = await settingsCall("POST", "/api/settings/keys/reset", { source }); delete keyResults[source]; await refreshAfter(payload, source, `${sourceName(source)} keys reset`); }
  catch (err) { setKeyResult(source, false, err.message); }
}

async function testSavedKey(btn, source, id) {
  if (btn) btn.disabled = true;
  try {
    const r = await settingsCall("POST", "/api/settings/keys/test", { source, key_id: id });
    const f = keysData.fields.find(x => x.source === source && x.multi);
    const pos = f?.keys.find(k => k.id === id)?.position;
    setKeyResult(source, r.ok, `Key #${pos ?? "?"}: ${r.message}`);
    await loadKeys({ silent: true });
  } catch (err) { setKeyResult(source, false, err.message); }
  finally { if (btn) btn.disabled = false; }
}

async function testAllKeys(btn, source) {
  setBusy(btn, true, "Testing…");
  try {
    const r = await settingsCall("POST", "/api/settings/keys/test", { source, all: true });
    const f = keysData.fields.find(x => x.source === source && x.multi);
    const details = (r.results || []).map(x => ({ position: f?.keys.find(k => k.id === x.id)?.position ?? "?", message: `${x.ok ? "OK" : "Failed"}: ${x.message}` }));
    setKeyResult(source, r.ok, r.message, details);
    await loadKeys({ silent: true });
  } catch (err) { setKeyResult(source, false, err.message); }
  finally { setBusy(btn, false); }
}

async function testTypedKey(btn, source) {
  const card = document.querySelector(`.key-card[data-source="${source}"]`);
  const values = {};
  card.querySelectorAll("input[name]").forEach(i => { if (!i.disabled && i.value.trim()) values[i.name] = i.value.trim(); });
  const main = keysData.fields.find(x => x.source === source && x.multi);
  if (!values[main.name] && source !== "urlscan") return showToast("Paste a key to test first");
  setBusy(btn, true, "Testing…");
  try { const r = await settingsCall("POST", "/api/settings/keys/test", { source, values }); setKeyResult(source, r.ok, r.message); }
  catch (err) { setKeyResult(source, false, err.message); }
  finally { setBusy(btn, false); }
}

async function saveExtra(e, source, name) {
  e.preventDefault();
  const value = e.target.querySelector("input").value.trim();
  if (!value) return showToast("Enter a value to save");
  try { const payload = await settingsCall("PUT", "/api/settings/keys", { values: { [name]: value } }); e.target.querySelector("input").value = ""; await refreshAfter(payload, source, "Saved"); }
  catch (err) { setKeyResult(source, false, err.message); }
}

async function clearExtra(source, name) {
  try { const payload = await settingsCall("PUT", "/api/settings/keys", { values: { [name]: "" } }); await refreshAfter(payload, source, "Cleared"); }
  catch (err) { setKeyResult(source, false, err.message); }
}
