"use strict";
// =============================================================================
// Shell: theme engine, toasts, command palette, notification centre, Overview dashboard.
// Loaded after the feature scripts and before app.js. Functions declared here intentionally
// replace the simpler originals in api.js / cases.js (applyTheme, showToast, updateAlertBadge).
// =============================================================================

const ICO = (p, s = 16, w = 2) => `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${w}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${p}</svg>`;
const PATHS = {
  check: '<path d="M20 6 9 17l-5-5"/>',
  alert: '<path d="m10.3 3.9-8.2 14A2 2 0 0 0 3.8 21h16.4a2 2 0 0 0 1.7-3.1l-8.2-14a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 8h.01M11 12h1v5h1"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  bell: '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
  radar: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  graph: '<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="18" r="2.5"/><circle cx="19" cy="18" r="2.5"/><path d="M10.8 7.2 6.2 15.8M13.2 7.2l4.6 8.6M7.5 18h9"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  zap: '<path d="M13 2 3 14h9l-1 8 10-12h-9z"/>',
  arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
  key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.8 12.2 8.7-8.7"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/>',
};
const REDUCED = () => !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
// Browser APIs are looked up defensively so the same code also runs in the headless test sandbox.
const RAF = fn => (typeof requestAnimationFrame === "function" ? window.requestAnimationFrame(fn) : setTimeout(() => fn(Date.now()), 0));
const NOW = () => (typeof performance !== "undefined" ? performance.now() : Date.now());
const isDomain = t => /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i.test((t || "").trim().replace(/^https?:\/\//i, "").split("/")[0]);
const cleanDomain = t => (t || "").trim().replace(/^https?:\/\//i, "").split("/")[0].toLowerCase();

// ----------------------------------------------------------------------------- theme engine
function resolveTheme(pref) {
  if (pref === "system") return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  return pref === "light" ? "light" : "dark";
}

function currentTheme() {
  try { return localStorage.getItem("bih-theme") || "dark"; } catch (e) { return "dark"; }
}

function applyTheme(pref, { announce = false } = {}) {
  if (!["light", "dark", "system"].includes(pref)) pref = "dark";
  const root = document.documentElement;
  root.classList?.add("theme-switching");               // brief cross-fade of colours
  root.dataset.theme = resolveTheme(pref);
  root.dataset.themePref = pref;
  try { localStorage.setItem("bih-theme", pref); } catch (e) { /* ignore */ }
  document.querySelectorAll(".theme-seg [data-theme-set]").forEach(b => b.classList.toggle("on", b.dataset.themeSet === pref));
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.content = root.dataset.theme === "dark" ? "#05070f" : "#f3f5fb";
  setTimeout(() => root.classList?.remove("theme-switching"), 420);
  if (announce) showToast(`${pref === "system" ? "Following system theme" : pref[0].toUpperCase() + pref.slice(1) + " theme"}`, 1800, "info");
  if (typeof OVc !== "undefined" && OVc.last) RAF(() => renderOverview(OVc.last, { animate: false }));
}

function cycleTheme() {
  const order = ["light", "dark", "system"];
  applyTheme(order[(order.indexOf(currentTheme()) + 1) % 3], { announce: true });
}

if (window.matchMedia) {
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { if (currentTheme() === "system") applyTheme("system"); });
}
(function injectThemeFade() {
  if (!document.head || typeof document.createElement !== "function") return;
  const st = document.createElement("style");
  st.textContent = ".theme-switching, .theme-switching *, .theme-switching *::before, .theme-switching *::after { transition: background-color .35s ease, border-color .35s ease, color .25s ease, fill .35s ease, stroke .35s ease, box-shadow .35s ease !important; }";
  document.head.appendChild(st);
})();

// ----------------------------------------------------------------------------- toasts
const SESSION_LOG = [];   // recent in-app events, shown in the notification centre

function toastKind(msg) {
  const m = String(msg || "").toLowerCase();
  if (/(could not|failed|error|unable|invalid|denied|refused|cannot|can't|not allowed)/.test(m)) return "danger";
  if (/(warning|limit|paused|offline|already|wait|rate)/.test(m)) return "warn";
  if (/(saved|copied|done|complete|found|started|added|removed|cleared|updated|exported|ready|enabled|theme)/.test(m)) return "success";
  return "info";
}

function showToast(message, duration = 3400, kind) {
  const host = document.getElementById("toasts");
  if (!host) return;
  kind = kind || toastKind(message);
  const ic = { success: PATHS.check, danger: PATHS.alert, warn: PATHS.alert, info: PATHS.info }[kind];
  const card = document.createElement("div");
  card.className = `toast-card ${kind}`;
  card.setAttribute("role", kind === "danger" ? "alert" : "status");
  card.innerHTML = `<span class="toast-ic">${ICO(ic, 16, 2.4)}</span><span>${esc(message)}</span>
    <button type="button" class="toast-x" aria-label="Dismiss">${ICO(PATHS.x, 14)}</button><span class="toast-bar" style="animation-duration:${duration}ms"></span>`;
  const dismiss = () => { if (!card.isConnected) return; card.classList.add("out"); setTimeout(() => card.remove(), 260); };
  card.querySelector(".toast-x").onclick = dismiss;
  card.onmouseenter = () => { card.dataset.hold = "1"; card.querySelector(".toast-bar").style.animationPlayState = "paused"; };
  card.onmouseleave = () => { delete card.dataset.hold; card.querySelector(".toast-bar").style.animationPlayState = "running"; };
  host.appendChild(card);
  while (host.children.length > 4) host.firstElementChild.remove();
  setTimeout(() => { if (!card.dataset.hold) dismiss(); else setTimeout(dismiss, 2500); }, duration);
  SESSION_LOG.unshift({ kind, message: String(message), time: Date.now() / 1000 });
  SESSION_LOG.length = Math.min(SESSION_LOG.length, 12);
}

// ----------------------------------------------------------------------------- small helpers
function ago(ts) {
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  if (s < 86400 * 14) return `${Math.round(s / 86400)}d ago`;
  return new Date(ts * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function countUp(el, to, ms = 1100) {
  if (!el) return;
  to = Number(to) || 0;
  if (REDUCED() || to === 0) { el.textContent = to.toLocaleString(); return; }
  const t0 = NOW();
  const step = now => {
    const p = Math.min(1, (now - t0) / ms);
    el.textContent = Math.round(to * (1 - Math.pow(1 - p, 4))).toLocaleString();
    if (p < 1) RAF(step);
  };
  RAF(step);
}

async function getJson(url) {
  try { const r = await fetch(url); if (!r.ok) return null; return await r.json(); } catch (e) { return null; }
}

// ----------------------------------------------------------------------------- navigation helpers
function newHunt() {
  switchTab("hunt");
  setTimeout(() => document.getElementById("hunt-target-input")?.focus(), 60);
}

function runHuntFor(domain, mode = "hunt") {
  const d = cleanDomain(domain);
  if (!isDomain(d)) { showToast("Enter a valid domain such as paypal.com", 3000, "warn"); return; }
  switchTab("hunt");
  setHeroMode(mode);
  document.getElementById("hunt-target-input").value = d;
  handleHuntSubmit({ preventDefault() { } });
}

function ovLaunch(e) {
  e.preventDefault();
  const v = document.getElementById("ov-target").value;
  if (!v.trim()) { showToast("Enter a domain to hunt, for example paypal.com", 3000, "warn"); document.getElementById("ov-target").focus(); return; }
  runHuntFor(v);
}

function ovInvestigate() {
  const d = cleanDomain(document.getElementById("ov-target").value);
  if (!isDomain(d)) { showToast("Enter the domain you want to investigate", 3000, "warn"); document.getElementById("ov-target").focus(); return; }
  investigateDomain(d);
}

function goHome() {
  if (typeof showLandingPage === "function") showLandingPage();
  else switchTab("overview");
}

// ----------------------------------------------------------------------------- command palette
const PAL = { items: [], sel: 0, recent: null, recentAt: 0 };

function navItems() {
  return [...document.querySelectorAll(".sidebar .nav-item[data-tab]")].map(b => ({
    group: "Go to", label: b.querySelector(".nav-text")?.textContent.trim() || b.dataset.tab,
    sub: ({
      overview: "Executive dashboard", hunt: "360° brand scan", daily: "Last 24 hours", infra: "Operation mapping", impersonation: "Keyword dorks", single: "Favicon and logo hashes",
      batch: "Many domains at once", reverse: "Compare suspect images", aggregator: "Merge hash queries", history: "Saved hunts", watch: "Scheduled monitoring", keys: "Sources and keys", storage: "MongoDB connection",
      scheduler: "Automated batch scans", data: "Delete and audit stored data"
    })[b.dataset.tab] || "",
    icon: b.querySelector("svg")?.innerHTML || PATHS.arrow, run: () => switchTab(b.dataset.tab),
  }));
}

async function openPalette() {
  const el = document.getElementById("palette");
  if (!el) return;
  closeNotifications();
  el.hidden = false;
  const inp = document.getElementById("palette-input");
  inp.value = "";
  PAL.sel = 0;
  paletteFilter();
  inp.focus();
  if (!PAL.recent || Date.now() - PAL.recentAt > 30000) {
    const d = await getJson("/api/hunts");
    PAL.recent = (d?.hunts || []).slice(0, 5);
    PAL.recentAt = Date.now();
    if (!el.hidden) paletteFilter();
  }
}

function closePalette() { const el = document.getElementById("palette"); if (el) el.hidden = true; }

function paletteFilter() {
  const q = document.getElementById("palette-input").value.trim();
  const low = q.toLowerCase();
  let items = [];
  const dom = cleanDomain(q);
  if (isDomain(dom)) {
    items.push({ group: "Run on this domain", label: `Hunt ${dom}`, sub: "360° scan across all free sources", icon: PATHS.search, run: () => runHuntFor(dom) },
      { group: "Run on this domain", label: `Daily radar for ${dom}`, sub: "Last 24 hours of lookalikes", icon: PATHS.radar, run: () => runHuntFor(dom, "daily") },
      { group: "Run on this domain", label: `Investigate ${dom}`, sub: "Map linked infrastructure and the operator", icon: PATHS.graph, run: () => investigateDomain(dom) });
  }
  const actions = [
    { group: "Actions", label: "Return to Landing Page", sub: "Main hero search entrance", icon: PATHS.shield, run: goHome, kw: "home landing start" },
    { group: "Actions", label: "Switch to dark theme", sub: "Obsidian", icon: PATHS.moon, run: () => applyTheme("dark", { announce: true }), kw: "theme dark night" },
    { group: "Actions", label: "Switch to light theme", sub: "Porcelain", icon: ICOPATH_SUN, run: () => applyTheme("light", { announce: true }), kw: "theme light day" },
    { group: "Actions", label: "Follow system theme", sub: "Matches your operating system", icon: ICOPATH_MON, run: () => applyTheme("system", { announce: true }), kw: "theme system auto" },
    { group: "Actions", label: "Check source availability", sub: "Probe every free intelligence source", icon: PATHS.zap, run: () => { switchTab("keys"); setTimeout(() => checkSourceHealth(document.querySelector("#source-health-card button")), 300); }, kw: "health status sources" },
    { group: "Actions", label: "Start a new hunt", sub: "Open the hunt form", icon: PATHS.search, run: newHunt, kw: "scan new" },
    { group: "Actions", label: OVc.sample ? "Exit sample data view" : "Preview dashboard with sample data", sub: "Clearly labelled, not stored", icon: PATHS.eye, run: () => { switchTab("overview"); ovSample(!OVc.sample); }, kw: "demo sample preview" },
  ];
  const recents = (PAL.recent || []).map(h => ({ group: "Recent hunts", label: h.target, sub: `${h.high_risk} high-risk · ${h.suspicious} suspicious · ${ago(h.created)}`, icon: PATHS.shield, run: () => { switchTab("history"); setTimeout(() => openHistoryHunt(h.id), 250); }, kw: h.target }));
  const all = [...items, ...navItems(), ...actions, ...recents];
  const out = low ? all.filter(i => i.group === "Run on this domain" || `${i.label} ${i.sub || ""} ${i.kw || ""}`.toLowerCase().includes(low)) : [...navItems(), ...actions.slice(0, 4), ...recents];
  PAL.items = out.slice(0, 30);
  PAL.sel = Math.min(PAL.sel, Math.max(0, PAL.items.length - 1));
  paletteRender();
}

function paletteRender() {
  const box = document.getElementById("palette-list");
  if (!PAL.items.length) { box.innerHTML = `<div class="palette-empty">No matches. Type a domain such as <strong>paypal.com</strong> to hunt it.</div>`; return; }
  let last = "", html = "";
  PAL.items.forEach((it, i) => {
    if (it.group !== last) { html += `<div class="palette-group">${esc(it.group)}</div>`; last = it.group; }
    html += `<button type="button" class="palette-item${i === PAL.sel ? " sel" : ""}" role="option" data-i="${i}" onmousemove="paletteHover(${i})" onclick="paletteRun(${i})">
      <span class="pi"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${it.icon}</svg></span>
      <span><span>${esc(it.label)}</span>${it.sub ? `<small>${esc(it.sub)}</small>` : ""}</span>
      <span class="go">${ICO(PATHS.arrow, 15)}</span></button>`;
  });
  box.innerHTML = html;
  box.querySelector(".sel")?.scrollIntoView({ block: "nearest" });
}

function paletteHover(i) { if (PAL.sel !== i) { PAL.sel = i; document.querySelectorAll(".palette-item").forEach((el, k) => el.classList.toggle("sel", k === i)); } }
function paletteRun(i) { const it = PAL.items[i]; closePalette(); if (it) it.run(); }

const ICOPATH_SUN = '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>';
const ICOPATH_MON = '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>';

document.addEventListener("keydown", e => {
  const mod = e.ctrlKey || e.metaKey;
  const typing = /^(input|textarea|select)$/i.test(e.target.tagName) || e.target.isContentEditable;
  if (mod && e.key.toLowerCase() === "k") { e.preventDefault(); document.getElementById("palette").hidden ? openPalette() : closePalette(); return; }
  if (!typing && e.key === "/" && !mod) { e.preventDefault(); openPalette(); return; }
  if (!document.getElementById("palette").hidden) {
    if (e.key === "Escape") { closePalette(); }
    else if (e.key === "ArrowDown") { e.preventDefault(); PAL.sel = (PAL.sel + 1) % Math.max(1, PAL.items.length); paletteRender(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); PAL.sel = (PAL.sel - 1 + PAL.items.length) % Math.max(1, PAL.items.length); paletteRender(); }
    else if (e.key === "Enter") { e.preventDefault(); paletteRun(PAL.sel); }
  } else if (e.key === "Escape") { closeNotifications(); }
});
{ const k = document.getElementById("cmdk-key"); if (k) k.textContent = (typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform)) ? "⌘ K" : "Ctrl K"; }

// ----------------------------------------------------------------------------- notification centre
const NOTIF = { tab: "all", alerts: [], events: [], open: false };
const seenKey = "bih-notif-seen";
const seenAt = () => { try { return Number(localStorage.getItem(seenKey)) || 0; } catch (e) { return 0; } };

function notifKind(level) {
  const l = String(level || "").toLowerCase();
  if (/(error|high|critical|phish)/.test(l)) return "danger";
  if (/(warn|medium|suspicious)/.test(l)) return "warn";
  if (/(ok|success|done)/.test(l)) return "ok";
  return "info";
}

async function refreshNotifications() {
  const [a, ev] = await Promise.all([getJson("/api/alerts"), getJson("/api/sources/events?hours=48")]);
  NOTIF.alerts = a?.alerts || [];
  NOTIF.events = ev?.events || [];
  NOTIF.unread = a?.unread || 0;
  const newEvents = NOTIF.events.filter(e => e.time > seenAt()).length;
  updateBell((a?.unread || 0) + Math.min(newEvents, 9));
  if (a) updateAlertBadgeOriginal(a.unread);
  if (NOTIF.open) renderNotifications();
  const fm = document.getElementById("mode-chip");
  if (fm && ev && ev.free_only === false) { fm.querySelector(".txt-long").textContent = "Paid sources enabled"; fm.title = "Paid platforms with a saved key are used"; }
}

function updateAlertBadgeOriginal(n) {
  const b = document.getElementById("watch-nav-badge");
  if (!b) return;
  b.hidden = !n;
  b.innerText = n > 99 ? "99+" : String(n || "");
}
function updateAlertBadge(n) { updateAlertBadgeOriginal(n); }
async function refreshAlertBadge() { refreshNotifications(); }

function updateBell(n) {
  const d = document.getElementById("bell-dot");
  if (!d) return;
  d.hidden = !n;
  d.textContent = n > 99 ? "99+" : String(n || "");
}

function toggleNotifications() {
  const p = document.getElementById("notif-panel");
  if (!p.hidden) { closeNotifications(); return; }
  closePalette();
  NOTIF.open = true;
  p.hidden = false;
  renderNotifications();
  refreshNotifications();
}
function closeNotifications() { NOTIF.open = false; const p = document.getElementById("notif-panel"); if (p) p.hidden = true; }
function setNotifTab(t) { NOTIF.tab = t; document.querySelectorAll("#notif-tabs button").forEach(b => b.classList.toggle("on", b.dataset.nt === t)); renderNotifications(); }

function renderNotifications() {
  const rows = [];
  if (huntJobId) rows.push({ kind: "info", t: "Hunt in progress", b: document.getElementById("hunt-progress-msg")?.innerText || "Scanning sources…", time: Date.now() / 1000, live: true });
  if (typeof infraJobId !== "undefined" && infraJobId) rows.push({ kind: "info", t: "Infrastructure investigation running", b: document.getElementById("infra-progress-msg")?.innerText || "", time: Date.now() / 1000, live: true });
  if (NOTIF.tab !== "sources") NOTIF.alerts.forEach(a => rows.push({ kind: notifKind(a.level), t: a.title, b: a.body, time: a.created, unread: !a.read, brand: a.brand, hunt: a.hunt_id }));
  if (NOTIF.tab !== "alerts") {
    const seen = new Map();
    NOTIF.events.forEach(e => { const k = `${e.source}|${e.kind}`; if (!seen.has(k)) seen.set(k, e); });
    seen.forEach(e => rows.push({
      kind: e.kind === "auth" ? "danger" : "warn", t: `${e.name || e.source}: ${({ plan: "plan limit", rate: "rate limited", challenge: "anti-bot challenge", auth: "key rejected", overloaded: "service busy", network: "network error", other: "error" })[e.kind] || "issue"}`,
      b: `${e.context}${e.target ? " · " + e.target : ""}. Details under API keys → Source activity.`, time: e.time, unread: e.time > seenAt(), tab: "keys"
    }));
  }
  if (NOTIF.tab === "all") SESSION_LOG.slice(0, 5).forEach(s => rows.push({ kind: s.kind === "success" ? "ok" : s.kind, t: s.message, b: "This session", time: s.time }));
  rows.sort((a, b) => (b.live ? 1 : 0) - (a.live ? 1 : 0) || b.time - a.time);
  const ic = { danger: PATHS.alert, warn: PATHS.alert, ok: PATHS.check, info: PATHS.info };
  document.getElementById("notif-list").innerHTML = rows.length ? rows.slice(0, 40).map(r => `
    <div class="notif-item${r.unread ? " unread" : ""}"${r.tab ? ` onclick="closeNotifications(); switchTab('${r.tab}')" style="cursor:pointer"` : r.hunt ? ` onclick="closeNotifications(); switchTab('history'); setTimeout(() => openHistoryHunt('${esc(r.hunt)}'), 250)" style="cursor:pointer"` : ""}>
      <span class="notif-ic ${r.kind}">${ICO(ic[r.kind] || PATHS.info, 16, 2.3)}</span>
      <div><div class="notif-title">${esc(r.t)}</div><div class="notif-body">${esc(r.b || "")}</div></div>
      <span class="notif-time">${r.live ? '<span class="live-dot"></span>' : esc(ago(r.time))}</span></div>`).join("")
    : `<div class="notif-empty">${ICO(PATHS.bell, 28)}You are all caught up.<br>New alerts and source issues appear here.</div>`;
}

async function markAllNotificationsRead() {
  try { localStorage.setItem(seenKey, String(Date.now() / 1000)); } catch (e) { /* ignore */ }
  try { await apiPost("/api/alerts/read", {}); } catch (e) { /* offline */ }
  await refreshNotifications();
  showToast("All notifications marked as read", 2000, "success");
}
document.addEventListener("click", e => {
  if (NOTIF.open && !e.target.closest("#notif-panel") && !e.target.closest("#notif-btn")) closeNotifications();
});

// ----------------------------------------------------------------------------- Overview dashboard
const OVc = { sample: false, last: null, health: null };

// A stable gradient per brand name, so every brand is recognisable at a glance.
function brandGrad(name) {
  let h = 0; for (const ch of String(name)) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  const a = h % 360, b = (a + 48) % 360;
  return `linear-gradient(135deg, hsl(${a} 78% 58%), hsl(${b} 82% 50%))`;
}

function expoOf(h) { return Math.min(100, (h.high_risk || 0) * 18 + (h.suspicious || 0) * 4 + (h.new_count || 0) * 3); }
function levelOf(v) { return v >= 70 ? "critical" : v >= 45 ? "elevated" : v >= 20 ? "guarded" : "low"; }
const LEVEL_LABEL = { low: "Low", guarded: "Guarded", elevated: "Elevated", critical: "Critical" };

function ovCompute(d) {
  const hunts = [...(d.hunts || [])].sort((a, b) => a.created - b.created);
  const latest = new Map(), prev = new Map();
  [...hunts].reverse().forEach(h => { if (!latest.has(h.target)) latest.set(h.target, h); else if (!prev.has(h.target)) prev.set(h.target, h); });
  const brands = [...latest.values()].sort((a, b) => expoOf(b) - expoOf(a));
  const sum = (arr, k) => arr.reduce((n, h) => n + (h[k] || 0), 0);
  const maxE = brands.length ? Math.max(...brands.map(expoOf)) : 0;
  const meanE = brands.length ? brands.reduce((n, h) => n + expoOf(h), 0) / brands.length : 0;
  const index = Math.round(0.6 * maxE + 0.4 * meanE);
  const prevArr = [...prev.values()];
  return {
    hunts, brands, prev, index, level: levelOf(index),
    high: sum(brands, "high_risk"), susp: sum(brands, "suspicious"), reg: sum(brands, "registered"), fresh: sum(brands, "new_count"),
    dHigh: prevArr.length ? sum(brands, "high_risk") - sum(brands.filter(b => prev.has(b.target)).map(b => prev.get(b.target)), "high_risk") : null,
    dSusp: prevArr.length ? sum(brands, "suspicious") - sum(brands.filter(b => prev.has(b.target)).map(b => prev.get(b.target)), "suspicious") : null,
  };
}

function sparkPath(vals, w = 86, h = 28) {
  if (!vals.length) return { line: "", fill: "" };
  const v = vals.length === 1 ? [vals[0], vals[0]] : vals;
  const max = Math.max(...v, 1), min = Math.min(...v, 0);
  const pts = v.map((y, i) => [(i / (v.length - 1)) * w, h - 3 - ((y - min) / Math.max(1, max - min)) * (h - 6)]);
  const line = pts.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(" ");
  return { line, fill: `${line} L${w} ${h} L0 ${h} Z` };
}

function deltaPill(d, goodDown = true) {
  if (d === null || d === undefined) return `<span class="delta flat">new</span>`;
  if (d === 0) return `<span class="delta flat">no change</span>`;
  const up = d > 0;
  return `<span class="delta ${up === goodDown ? "up" : "down"}">${up ? "▲" : "▼"} ${Math.abs(d)}</span>`;
}

function kpiCard(cls, icon, label, val, foot, spark) {
  const sp = spark ? sparkPath(spark) : null;
  return `<div class="kpi ${cls}"><div class="kpi-top"><span class="kpi-ic">${ICO(icon, 19, 2.1)}</span>${sp ? `<svg class="kpi-spark" viewBox="0 0 86 28" aria-hidden="true"><path class="fill" d="${sp.fill}"/><path d="${sp.line}"/></svg>` : ""}</div>
    <div class="kpi-label">${esc(label)}</div><div class="kpi-val" data-count="${val}">0</div><div class="kpi-foot">${foot}</div></div>`;
}

function gaugeHtml(c) {
  const R = 84, C = 2 * Math.PI * R;
  const col = { low: ["#34d399", "#10b981"], guarded: ["#38bdf8", "#6366f1"], elevated: ["#fbbf24", "#f97316"], critical: ["#fb7185", "#e11d48"] }[c.level];
  const cap = !c.brands.length ? "Run your first hunt to calculate your exposure index."
    : `Blended from the worst brand (60%) and the average across ${c.brands.length} brand${c.brands.length === 1 ? "" : "s"} (40%): each high-risk domain adds 18 points, suspicious 4, new 3.`;
  return `<div class="gauge" data-level="${c.brands.length ? c.level : "guarded"}" title="Exposure index 0-100, derived from your saved hunts">
    <svg viewBox="0 0 200 200"><defs><linearGradient id="gGrad" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${col[0]}"/><stop offset="1" stop-color="${col[1]}"/></linearGradient></defs>
      <circle class="track" cx="100" cy="100" r="${R}"/><circle class="arc" id="gauge-arc" cx="100" cy="100" r="${R}" stroke="url(#gGrad)" stroke-dasharray="${C}" stroke-dashoffset="${C}" data-c="${C}"/></svg>
    <div class="gauge-center"><b data-count="${c.brands.length ? c.index : 0}">0</b><span>${c.brands.length ? LEVEL_LABEL[c.level] : "No data"}</span></div></div>
    <div class="gauge-caption">${esc(cap)}</div>`;
}

function trendHtml(c) {
  const pts = c.hunts.slice(-14);
  if (pts.length < 2) return emptyCard(PATHS.graph, pts.length ? "One hunt so far" : "No hunts yet", "Run at least two hunts to see how exposure changes over time.", pts.length ? "" : `<button type="button" class="btn btn-primary btn-sm" onclick="newHunt()">Run a hunt</button>`);
  const W = 640, H = 230, L = 34, R = 14, T = 14, B = 30;
  const max = Math.max(4, ...pts.map(p => Math.max(p.high_risk, p.suspicious)));
  const nice = Math.ceil(max / 4) * 4;
  const x = i => L + (i / (pts.length - 1)) * (W - L - R), y = v => T + (1 - v / nice) * (H - T - B);
  const smooth = key => pts.map((p, i) => [x(i), y(p[key])]).reduce((d, p, i, a) => {
    if (!i) return `M${p[0]} ${p[1]}`;
    const p0 = a[i - 1], mx = (p0[0] + p[0]) / 2;
    return `${d} C${mx} ${p0[1]} ${mx} ${p[1]} ${p[0]} ${p[1]}`;
  }, "");
  const area = key => `${smooth(key)} L${x(pts.length - 1)} ${H - B} L${x(0)} ${H - B} Z`;
  const grid = [0, 1, 2, 3, 4].map(i => { const v = (nice / 4) * i, yy = y(v); return `<line x1="${L}" x2="${W - R}" y1="${yy}" y2="${yy}"/><text class="ax" x="${L - 8}" y="${yy + 3.5}" text-anchor="end">${Math.round(v)}</text>`; }).join("");
  const shortSpan = (pts[pts.length - 1].created - pts[0].created) < 2 * 86400;   // within ~2 days: show the time of day too
  const fmt = p => new Date(p.created * 1000).toLocaleString(undefined, shortSpan ? { month: "short", day: "numeric", hour: "numeric" } : { month: "short", day: "numeric" });
  const labels = pts.map((p, i) => (i % Math.ceil(pts.length / (shortSpan ? 5 : 7)) === 0 || i === pts.length - 1) ? `<text class="ax" x="${x(i)}" y="${H - 9}" text-anchor="${i === 0 ? "start" : i === pts.length - 1 ? "end" : "middle"}">${fmt(p)}</text>` : "").join("");
  const dots = key => pts.map((p, i) => `<circle class="pt" cx="${x(i)}" cy="${y(p[key])}" r="4.5" fill="var(--c-${key})" data-tip="${esc(`${p.target} · ${new Date(p.created * 1000).toLocaleDateString()}||${p.high_risk} high-risk · ${p.suspicious} suspicious`)}"/>`).join("");
  document.getElementById("ov-trend-legend").innerHTML = `<span><i style="background:#f43f5e"></i>High-risk</span><span><i style="background:#f59e0b"></i>Suspicious</span>`;
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" style="--c-high_risk:#f43f5e;--c-suspicious:#f59e0b" role="img" aria-label="Exposure trend">
    <defs><linearGradient id="aR" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f43f5e" stop-opacity=".38"/><stop offset="1" stop-color="#f43f5e" stop-opacity="0"/></linearGradient>
    <linearGradient id="aA" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f59e0b" stop-opacity=".3"/><stop offset="1" stop-color="#f59e0b" stop-opacity="0"/></linearGradient></defs>
    <g class="grid">${grid}</g>${labels}
    <path class="area" d="${area("suspicious")}" fill="url(#aA)"/><path class="area" d="${area("high_risk")}" fill="url(#aR)"/>
    <path class="line" d="${smooth("suspicious")}" stroke="#f59e0b"/><path class="line" d="${smooth("high_risk")}" stroke="#f43f5e"/>${dots("suspicious")}${dots("high_risk")}</svg>`;
}

function mixHtml(c) {
  const other = Math.max(0, c.reg - c.high - c.susp);
  const total = c.high + c.susp + other;
  if (!total) return emptyCard(PATHS.shield, "Nothing to show yet", "The mix of risk levels appears after your first hunt.");
  const R = 70, C = 2 * Math.PI * R;
  let off = 0;
  // every non-zero slice gets at least 4% of the ring so small, important slices (high-risk) never vanish
  const share = v => (v ? Math.max(v / total, 0.04) : 0);
  const norm = [c.high, c.susp, other].map(share), nsum = norm.reduce((a, b) => a + b, 0) || 1;
  const frac = norm.map(n => n / nsum);
  const seg = (idx, color) => { const len = frac[idx] * C; const s = `<circle cx="95" cy="95" r="${R}" stroke="${color}" stroke-dasharray="0 ${C}" data-len="${len}" data-c="${C}" stroke-dashoffset="${-off}"/>`; off += len; return s; };
  return `<div class="mix"><div class="donut"><svg viewBox="0 0 190 190"><circle cx="95" cy="95" r="${R}" stroke="color-mix(in srgb, var(--text-muted) 16%, transparent)"/>
    ${seg(0, "#f43f5e")}${seg(1, "#f59e0b")}${seg(2, "#6366f1")}</svg>
    <div class="donut-mid"><b data-count="${total}">0</b><span>registered</span></div></div>
    <div class="mix-legend"><div><i style="background:#f43f5e;color:#f43f5e"></i>High-risk<b>${c.high}</b></div><div><i style="background:#f59e0b;color:#f59e0b"></i>Suspicious<b>${c.susp}</b></div><div><i style="background:#6366f1;color:#6366f1"></i>Other registered<b>${other}</b></div></div></div>`;
}

function emptyCard(icon, title, text, action = "") {
  return `<div class="ov-empty"><div class="art">${ICO(icon, 30, 2)}</div><h3>${esc(title)}</h3><p>${esc(text)}</p>${action}</div>`;
}

function brandsHtml(c, sample) {
  if (!c.brands.length) return emptyCard(PATHS.shield, "No brands under protection yet", "Run a hunt for your domain and it appears here with its exposure index. Add it to the watchlist for scheduled monitoring.",
    `<div class="row" style="justify-content:center;"><button type="button" class="btn btn-primary btn-sm" onclick="newHunt()">Run your first hunt</button><button type="button" class="btn btn-secondary btn-sm" onclick="ovSample(true)">Preview with sample data</button></div>`);
  const guard = sample ? `onclick="showToast('Sample data: run a real hunt to open results', 2600, 'info')"` : "";
  return `<div class="brand-row head"><span></span><span>Brand</span><span>Exposure</span><span style="text-align:center">High</span><span style="text-align:center">Susp.</span><span style="text-align:center">New</span><span></span></div>` +
    c.brands.map(h => {
      const e = expoOf(h), lv = levelOf(e);
      return `<div class="brand-row"><div class="avatar" aria-hidden="true" style="background:${brandGrad(h.target)}">${esc((h.target || "?")[0])}</div>
        <div><div class="ov-bn">${esc(h.target)}</div><div class="ov-bs">Last hunt ${esc(ago(h.created))}${h.scheduled ? " · scheduled" : ""}</div></div>
        <div class="expo" data-level="${lv}"><div class="t"><span data-w="${Math.max(4, e)}"></span></div><small>${e} · ${LEVEL_LABEL[lv]}</small></div>
        <div class="num-cell d">${h.high_risk}<small>high</small></div><div class="num-cell w">${h.suspicious}<small>susp</small></div><div class="num-cell">${h.new_count || 0}<small>new</small></div>
        <div class="row-actions">
          <button type="button" class="btn btn-secondary btn-xs" ${sample ? guard : `onclick="switchTab('history'); setTimeout(() => openHistoryHunt('${esc(h.id)}'), 250)"`}>Open</button>
          <button type="button" class="btn btn-ghost btn-xs" ${sample ? guard : `onclick="runHuntFor('${esc(h.target)}')"`} title="Run a fresh hunt">Re-hunt</button></div></div>`;
    }).join("");
}

function activityHtml(d) {
  const items = [];
  (d.watch?.alerts || []).slice(0, 6).forEach(a => items.push({ k: notifKind(a.level), ic: PATHS.bell, t: a.title, s: a.brand, time: a.created }));
  (d.hunts || []).slice().sort((a, b) => b.created - a.created).slice(0, 6).forEach(h => items.push({ k: h.high_risk ? "danger" : "brand", ic: PATHS.search, t: `Hunt completed for ${h.target}`, s: `${h.high_risk} high-risk · ${h.suspicious} suspicious · ${h.registered} registered`, time: h.created }));
  const seen = new Set();
  (d.events || []).forEach(e => { const k = `${e.source}|${e.kind}`; if (seen.has(k) || items.length > 14) return; seen.add(k); items.push({ k: "warn", ic: PATHS.alert, t: `${e.name || e.source} was limited`, s: `${e.context}`, time: e.time }); });
  items.sort((a, b) => b.time - a.time);
  if (!items.length) return `<div class="notif-empty">${ICO(PATHS.bell, 26)}No activity yet.</div>`;
  return `<ul class="tl">${items.slice(0, 8).map(i => `<li><span class="nd ${i.k}">${ICO(i.ic, 13, 2.4)}</span><div><b>${esc(i.t)}</b><span>${esc(i.s || "")}</span></div><time>${esc(ago(i.time))}</time></li>`).join("")}</ul>`;
}

function coverageHtml(h) {
  if (h && !h.summary) return `<div class="notif-empty">Source status is unavailable right now.</div>`;
  if (!h) return `<div class="cov"><div class="skel" style="height:36px"></div><div class="skel" style="height:36px"></div><div class="skel" style="height:36px"></div></div>`;
  const cls = s => s === "up" ? "" : s === "down" ? "down" : "warn";
  const free = (h.free || []).slice().sort((a, b) => (a.status === "up") - (b.status === "up"));
  const pct = h.summary.total ? Math.round(100 * h.summary.up / h.summary.total) : 0;
  return `<div class="row" style="justify-content:space-between;"><strong style="font:800 22px var(--font-display);letter-spacing:-.03em;">${h.summary.up}/${h.summary.total}</strong><span class="hint">free sources online</span></div>
    <div class="cov-bar"><span data-w="${pct}"></span></div>
    <div class="cov">${free.slice(0, 7).map(s => `<div class="cov-pill ${cls(s.status)}" title="${esc(s.purpose + " · " + s.detail)}"><i></i><span>${esc(s.name.replace(/ \(.*\)$/, ""))}</span><small>${s.status === "up" ? s.ms + " ms" : esc(s.status.replace("_", " "))}</small></div>`).join("")}
    <div class="cov-pill off"><i></i><span>Paid platforms</span><small>off · free mode</small></div></div>`;
}

function ovAnimate() {
  document.querySelectorAll("#overview-page [data-count]").forEach(el => countUp(el, el.dataset.count));
  const arc = document.querySelector("#gauge-arc");
  if (arc) { const C = Number(arc.dataset.c); const v = Number(document.querySelector("#overview-page .gauge-center b")?.dataset.count || 0); RAF(() => RAF(() => { arc.style.strokeDashoffset = String(C * (1 - v / 100)); })); }
  document.querySelectorAll("#overview-page .donut circle[data-len]").forEach(c => RAF(() => RAF(() => { c.style.strokeDasharray = `${Math.max(0, Number(c.dataset.len) - 2)} ${c.dataset.c}`; })));
  document.querySelectorAll("#overview-page .expo .t span[data-w], #overview-page .cov-bar span[data-w]").forEach(s => RAF(() => RAF(() => { s.style.width = s.dataset.w + "%"; })));
}

function renderOverview(d, { animate = true } = {}) {
  OVc.last = d;
  const c = ovCompute(d);
  const sample = !!d.sample;
  document.getElementById("ov-banner").hidden = !sample;
  // headline reflects reality once there is data
  document.getElementById("ov-title").innerHTML = c.brands.length
    ? `Exposure is <em>${LEVEL_LABEL[c.level]}</em> across ${c.brands.length} brand${c.brands.length === 1 ? "" : "s"}.`
    : `Know who is impersonating you <em>before your customers do.</em>`;
  document.getElementById("ov-sub").textContent = c.brands.length
    ? `${c.high} high-risk and ${c.susp} suspicious lookalike${c.susp === 1 ? "" : "s"} in the latest hunts, ${c.fresh} new since the previous scans. Review the brands below or launch a new investigation.`
    : "Hunt lookalike domains, map the infrastructure behind them and track exposure across every brand you protect, using free intelligence sources only.";
  document.getElementById("ov-gauge").innerHTML = gaugeHtml(c);
  const series = k => c.hunts.slice(-10).map(h => h[k] || 0);
  const watchOn = (d.watch?.watchlist || []).filter(w => w.enabled).length;
  document.getElementById("ov-kpis").innerHTML = [
    kpiCard("info", PATHS.shield, "Brands protected", c.brands.length, `<span>${watchOn} on watchlist</span>`, null),
    kpiCard("", PATHS.search, "Hunts completed", c.hunts.length, `<span>${c.hunts.filter(h => h.scheduled).length} scheduled</span>`, c.hunts.slice(-10).map((_, i) => i + 1)),
    kpiCard("danger", PATHS.alert, "High-risk lookalikes", c.high, deltaPill(c.dHigh), series("high_risk")),
    kpiCard("warn", PATHS.eye, "Suspicious domains", c.susp, deltaPill(c.dSusp), series("suspicious")),
    kpiCard("info", PATHS.zap, "New since last hunt", c.fresh, `<span>across latest scans</span>`, series("new_count")),
    kpiCard(d.watch?.unread ? "warn" : "ok", PATHS.bell, "Unread alerts", d.watch?.unread || 0, `<span>${d.watch?.scheduler ? "scheduler running" : "scheduler off"}</span>`, null),
  ].join("");
  document.getElementById("ov-trend").innerHTML = trendHtml(c);
  document.getElementById("ov-mix").innerHTML = mixHtml(c);
  document.getElementById("ov-brands").innerHTML = brandsHtml(c, sample);
  document.getElementById("ov-activity").innerHTML = activityHtml(d);
  document.getElementById("ov-cov").innerHTML = coverageHtml(OVc.health);
  if (animate) ovAnimate(); else {
    document.querySelectorAll("#overview-page [data-count]").forEach(el => { el.textContent = Number(el.dataset.count).toLocaleString(); });
    const arc = document.querySelector("#gauge-arc"); if (arc) arc.style.strokeDashoffset = String(Number(arc.dataset.c) * (1 - (c.brands.length ? c.index : 0) / 100));
    document.querySelectorAll("#overview-page .donut circle[data-len]").forEach(x => { x.style.strokeDasharray = `${Math.max(0, Number(x.dataset.len) - 2)} ${x.dataset.c}`; });
    document.querySelectorAll("#overview-page [data-w]").forEach(s => { s.style.width = s.dataset.w + "%"; });
  }
}

async function ovRefreshCoverage(force = false) {
  const box = document.getElementById("ov-cov");
  if (box && force) box.innerHTML = coverageHtml(null);
  const h = OVc.sample ? sampleOverview().health : await getJson(`/api/sources/health${force ? "?force=true" : ""}`);
  OVc.health = h;
  if (box) { box.innerHTML = coverageHtml(h); document.querySelectorAll("#ov-cov .cov-bar span[data-w]").forEach(s => RAF(() => RAF(() => { s.style.width = s.dataset.w + "%"; }))); }
  const dot = document.getElementById("side-dot"), t = document.getElementById("side-title"), sub = document.getElementById("side-sub");
  if (h && h.summary && t) {
    const all = h.summary.up === h.summary.total;
    dot.className = `live-dot${all ? "" : " warn"}`;
    t.textContent = `${h.summary.up}/${h.summary.total} sources online`;
    sub.textContent = all ? "Free intelligence mode" : "Some free sources are limited";
  }
}

async function loadOverview() {
  if (OVc.sample) { renderOverview(sampleOverview()); ovRefreshCoverage(); return; }
  if (!OVc.last) {
    document.getElementById("ov-kpis").innerHTML = Array.from({ length: 6 }, () => `<div class="kpi"><div class="skel" style="height:38px;width:38px"></div><div class="skel" style="height:12px;width:60%;margin-top:10px"></div><div class="skel" style="height:34px;width:40%"></div></div>`).join("");
  }
  const [hunts, watch, events] = await Promise.all([getJson("/api/hunts"), getJson("/api/watchlist"), getJson("/api/sources/events")]);
  renderOverview({ hunts: hunts?.hunts || [], watch: watch || { watchlist: [], alerts: [], unread: 0, scheduler: false }, events: events?.events || [] });
  ovRefreshCoverage();
}

function ovSample(on) {
  OVc.sample = !!on;
  if (on) { OVc.last = null; renderOverview(sampleOverview()); ovRefreshCoverage(); showToast("Showing sample data. Nothing is stored.", 2600, "info"); }
  else { OVc.last = null; loadOverview(); }
}

// Clearly-labelled sample data for first-run previews and demos. Never stored, never sent anywhere.
function sampleOverview() {
  const now = Date.now() / 1000, day = 86400;
  const mk = (id, target, ago, hi, su, rg, nw) => ({ id, target, created: now - ago * day, depth: "standard", high_risk: hi, suspicious: su, registered: rg, new_count: nw, scheduled: ago % 2 === 0 ? 1 : 0 });
  const hunts = [
    mk("s1", "paypal.com", 13, 1, 6, 71, 4), mk("s2", "microsoft.com", 12, 2, 9, 118, 6), mk("s3", "paypal.com", 10, 2, 8, 80, 7), mk("s4", "netflix.com", 9, 0, 4, 42, 2),
    mk("s5", "microsoft.com", 8, 3, 12, 131, 9), mk("s6", "amazon.com", 7, 0, 2, 19, 1), mk("s7", "paypal.com", 5, 2, 7, 86, 3), mk("s8", "netflix.com", 4, 1, 6, 55, 5),
    mk("s9", "microsoft.com", 3, 4, 14, 140, 8), mk("s10", "amazon.com", 2, 0, 3, 22, 2), mk("s11", "paypal.com", 1, 3, 9, 92, 6), mk("s12", "netflix.com", 0.4, 1, 5, 58, 1),
  ];
  return {
    sample: true, hunts,
    watch: {
      scheduler: true, unread: 3, watchlist: [{ enabled: true }, { enabled: true }, { enabled: true }], alerts: [
        { level: "high", title: "3 new high-risk domains for microsoft.com", brand: "microsoft.com", created: now - 3 * 3600 },
        { level: "warning", title: "Subdomain impersonation detected: login.netflix.attacker.example", brand: "netflix.com", created: now - 9 * 3600 },
        { level: "info", title: "Scheduled hunt completed", brand: "amazon.com", created: now - 30 * 3600 }]
    },
    events: [{ source: "otx", name: "AlienVault OTX", kind: "rate", context: "Brand Hunt", time: now - 2 * 3600 }],
    health: {
      summary: { up: 9, total: 10 }, free: [
        { id: "crt.sh", name: "crt.sh (Certificate Transparency)", status: "up", ms: 612, purpose: "TLS certificates", detail: "responding" }, { id: "urlscan", name: "URLScan.io (anonymous)", status: "up", ms: 340, purpose: "scans", detail: "responding" },
        { id: "rdap", name: "RDAP bootstrap (IANA)", status: "up", ms: 180, purpose: "registration", detail: "responding" }, { id: "bing", name: "Bing RSS search", status: "up", ms: 420, purpose: "search", detail: "responding" },
        { id: "wayback", name: "Wayback CDX", status: "up", ms: 510, purpose: "archive", detail: "responding" }, { id: "otx", name: "AlienVault OTX passive DNS", status: "rate_limited", ms: 220, purpose: "passive DNS", detail: "rate limited" },
        { id: "dns", name: "DNS resolver", status: "up", ms: 20, purpose: "dns", detail: "ok" }]
    },
  };
}

// chart tooltips (event delegation)
document.addEventListener("mouseover", e => {
  const pt = e.target.closest?.(".chart .pt");
  let tip = document.querySelector("#chart-tip");
  if (!pt) { if (tip) tip.remove(); return; }
  if (!tip) { tip = document.createElement("div"); tip.id = "chart-tip"; tip.className = "chart-tip"; document.body.appendChild(tip); }
  const [a, b] = pt.dataset.tip.split("||");
  tip.innerHTML = `<strong>${esc(a)}</strong><br><span class="muted">${esc(b)}</span>`;
});
document.addEventListener("mousemove", e => {
  const tip = document.querySelector("#chart-tip");
  if (tip) { tip.style.left = Math.min(e.clientX + 14, innerWidth - 230) + "px"; tip.style.top = (e.clientY + 14) + "px"; }
});
