"use strict";
// =============================================================================
// Brand Impersonation Hunter: web UI
// All remote data is rendered through esc(). Query syntax mirrors core/platforms.py.
// =============================================================================

// ----------------------------------------------------------------------------- state
let currentResult = null;
let currentBatchResult = null;
let currentBatchIndex = 0;
let uploadedFilesList = [];
let currentReverseBulkResult = null;
let currentQueries = null;
let currentImpersonationResult = null;
let currentCapturedDomains = null;
let currentAggregatorResult = null;
let currentHunt = null;
let huntJobId = null;
let huntPollTimer = null;
let huntFilter = "risky";
let huntView = "lookalikes";
let huntRowLimit = 100;
let currentTab = "hunt";
window.iconStore = {};
window.reverseCandidateStore = {};

// ----------------------------------------------------------------------------- platforms
const PLATFORMS = {
  fofa: { name: "FOFA" },
  shodan: { name: "Shodan" },
  censys: { name: "Censys" },
  urlscan: { name: "URLScan" },
};
const PLATFORM_KEYS = Object.keys(PLATFORMS);
const SOURCE_LABELS = { urlscan: "URLScan", shodan: "Shodan", fofa: "FOFA", censys: "Censys", serpapi: "Google Lens", "google-lens": "Google Lens", "crt.sh": "crt.sh", openphish: "OpenPhish", phishingdb: "Phishing.Database" };

const CENSYS_MD5_FIELDS = ["host.services.endpoints.http.favicons.hash_md5", "web.endpoints.http.favicons.hash_md5"];
const CENSYS_SHA256_FIELD = "web.endpoints.http.favicons.hash_sha256";

function safeBtoa(str) {
  try { return btoa(str); } catch (e) { return btoa(unescape(encodeURIComponent(str))); }
}

function platformUrl(platform, query) {
  if (!query) return "";
  const q = String(query);
  switch (platform) {
    case "fofa": return `https://fofa.info/result?qbase64=${encodeURIComponent(safeBtoa(q))}`;
    case "shodan": return `https://www.shodan.io/search?query=${encodeURIComponent(q)}`;
    case "censys": case "censys_sha256": case "censys_md5": return `https://platform.censys.io/search?q=${encodeURIComponent(q)}`;
    case "urlscan": return `https://urlscan.io/search/#${encodeURIComponent(q)}`;
    default: return "";
  }
}

const fofaIconQuery = h => `icon_hash="${h}"`;
const shodanIconQuery = h => `http.favicon.hash:${h}`;
const censysMd5Query = m => CENSYS_MD5_FIELDS.map(f => `${f}: "${m}"`).join(" or ");
const urlscanHashQuery = s => `hash:${s}`;
const isFaviconLike = icon => (icon.kind || "favicon") !== "logo";

// Logos are never indexed by favicon-hash filters; URLScan indexes any resource.
function iconQueries(icon) {
  const q = {};
  if (isFaviconLike(icon)) {
    if (icon.mmh3 !== null && icon.mmh3 !== undefined) {
      q.fofa = fofaIconQuery(icon.mmh3);
      q.shodan = shodanIconQuery(icon.mmh3);
    }
    if (icon.md5) q.censys = censysMd5Query(icon.md5);
  }
  if (icon.sha256) q.urlscan = urlscanHashQuery(icon.sha256);
  return q;
}

// ----------------------------------------------------------------------------- icons
const svg = (d, size = 16, sw = 2) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
const I = {
  copy: svg('<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>', 15),
  external: svg('<path d="M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>', 15),
  check: svg('<path d="M20 6 9 17l-5-5"/>', 12, 3),
  alert: svg('<path d="m10.3 3.9-8.2 14A2 2 0 0 0 3.8 21h16.4a2 2 0 0 0 1.7-3.1l-8.2-14a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>', 16),
  dot: svg('<circle cx="12" cy="12" r="3"/>', 14),
  chevron: svg('<path d="m9 18 6-6-6-6"/>', 14, 2.4),
  sun: svg('<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>', 16),
  moon: svg('<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>', 16),
  monitor: svg('<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>', 16),
  search: svg('<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>', 14),
};
const PLACEHOLDER_IMG = "data:image/svg+xml;utf8," + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#98a2b3" stroke-width="1.6"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/></svg>');

// ----------------------------------------------------------------------------- html helpers
function esc(value) {
  return String(value ?? "").replace(/[&<>"'`]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" })[c]);
}

function copyBtn(text, label = "Copied") {
  if (text === null || text === undefined || text === "") return "";
  return `<button type="button" class="icon-btn" data-copy="${esc(text)}" data-copy-label="${esc(label)}" aria-label="Copy" title="Copy">${I.copy}</button>`;
}

function openIcon(url, title = "Open in new tab") {
  if (!url) return "";
  return `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer" class="icon-btn" aria-label="${esc(title)}" title="${esc(title)}">${I.external}</a>`;
}

function linkBtn(url, label, title = "", cls = "btn btn-secondary btn-xs") {
  if (!url) return "";
  return `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer" class="${cls}" title="${esc(title || label)}">${esc(label)}</a>`;
}

function pfLabel(p) {
  return `<span class="pf pf-${esc(p)}">${esc(SOURCE_LABELS[p] || PLATFORMS[p]?.name || p)}</span>`;
}

// One copyable query: label (html), query text, search url
function queryRow(labelHtml, query, url, { wrap = false } = {}) {
  if (!query) return "";
  return `
    <div class="query-row${wrap ? " wrap" : ""}">
      ${labelHtml ? `<span class="q-label">${labelHtml}</span>` : ""}
      <code title="${esc(query)}">${esc(query)}</code>
      <div class="q-actions">${copyBtn(query, "Query copied")}${openIcon(url, "Run this search")}</div>
    </div>`;
}

function platformCard(p, inner, actionsHtml = "") {
  return `
    <div class="platform-card">
      <div class="spread">${pfLabel(p)}${actionsHtml ? `<div class="row">${actionsHtml}</div>` : ""}</div>
      <div class="query-list">${inner}</div>
    </div>`;
}

function emptyState(title, text = "") {
  return `<div class="empty"><strong>${esc(title)}</strong>${esc(text)}</div>`;
}

function displayUrl(url) {
  if (!url) return "";
  if (url.startsWith("data:")) return `inline ${url.slice(0, url.indexOf(",") + 1 || 30)}… (${url.length} chars)`;
  return url;
}

function shortList(items, n) {
  const list = items || [];
  return list.length > n ? `${list.slice(0, n).join(", ")} +${list.length - n} more` : list.join(", ");
}

function plural(n, word, pluralWord) {
  return `${n} ${n === 1 ? word : (pluralWord || word + "s")}`;
}

// Delegated copy handler for every [data-copy] element
document.addEventListener("click", e => {
  const el = e.target.closest("[data-copy]");
  if (!el) return;
  e.preventDefault();
  e.stopPropagation();
  copyText(el.dataset.copy, el.dataset.copyLabel || "Copied");
});

// ----------------------------------------------------------------------------- generic ui
let toastTimeout = null;
function showToast(message, duration = 2600) {
  const toast = document.getElementById("toast");
  document.getElementById("toast-message").innerText = message;
  toast.classList.add("show");
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => toast.classList.remove("show"), duration);
}

function copyText(text, label = "Copied") {
  if (!text) return;
  const fallback = () => {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) { /* ignore */ }
    document.body.removeChild(ta);
    showToast(label);
  };
  if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(() => showToast(label)).catch(fallback);
  else fallback();
}

function setLoading(on, status) {
  document.getElementById("loading-panel").classList.toggle("show", !!on);
  document.getElementById("loading-status").innerText = status || "";
}

async function apiPost(path, body) {
  const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  let data = null;
  try { data = await res.json(); } catch (e) { /* non-JSON error body */ }
  if (!res.ok) {
    const detail = data && data.detail;
    throw new Error(typeof detail === "string" ? detail : (detail ? JSON.stringify(detail) : `HTTP ${res.status}`));
  }
  return data;
}

function downloadBlob(content, filename, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function csvCell(v) {
  return `"${String(v ?? "").replace(/"/g, '""')}"`;
}

function setBusy(btn, busy, busyLabel = "Working…") {
  if (!btn) return;
  if (busy) {
    btn.dataset.label = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner" style="width:14px;height:14px;border-width:2px;border-color:rgba(255,255,255,.4);border-top-color:#fff"></span>${esc(busyLabel)}`;
  } else {
    btn.disabled = false;
    if (btn.dataset.label) btn.innerHTML = btn.dataset.label;
  }
}

// ----------------------------------------------------------------------------- theme
const THEMES = ["system", "light", "dark"];
function currentTheme() {
  try { return localStorage.getItem("bih-theme") || "system"; } catch (e) { return "system"; }
}
function applyTheme(theme) {
  if (theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
  try { localStorage.setItem("bih-theme", theme); } catch (e) { /* storage blocked */ }
  const btn = document.getElementById("theme-toggle");
  if (btn) {
    btn.innerHTML = theme === "light" ? I.sun : theme === "dark" ? I.moon : I.monitor;
    btn.title = `Theme: ${theme} (click to change)`;
    btn.setAttribute("aria-label", `Colour theme: ${theme}. Click to change.`);
  }
}
function cycleTheme() {
  const next = THEMES[(THEMES.indexOf(currentTheme()) + 1) % THEMES.length];
  applyTheme(next);
  showToast(`Theme: ${next}`);
}

// ----------------------------------------------------------------------------- navigation
const PAGE_META = {
  hunt: ["Impersonation hunt", "Enter a brand's domain. The hunt generates lookalikes, pulls brand hostnames from CT logs and threat-intel platforms, checks DNS, inspects every live site against the brand, and ranks them by risk."],
  single: ["Asset scan", "Discover every favicon, touch icon, manifest icon and logo on a site, hash them (MMH3, MD5, SHA-256, pHash) and get hunting queries for each platform."],
  batch: ["Batch scan", "Scan many domains at once and compare their icon hashes and queries."],
  reverse: ["Logo inspector", "Hash images found through reverse image search or on suspect pages, compare them with the scanned brand, and build queries to find every host serving them."],
  aggregator: ["Hash aggregator", "Merge favicon hashes from anywhere into one OR query per platform."],
  impersonation: ["Dork generator", "Title, hostname, certificate and page-content dorks for brand names, project names and domains across FOFA, Censys, URLScan and Shodan."],
  storage: ["Storage", "Choose where hunts, case notes, the watchlist and alerts are saved: the local SQLite file (default) or MongoDB."],
  history: ["History", "Every hunt is saved. Reopen past results, see what changed between hunts, and keep your case notes."],
  watch: ["Watchlist", "Monitor brands automatically. A scheduled hunt compares with the previous one and alerts you (in-app and by webhook) only when new risky lookalikes appear."],
  keys: ["API keys", "Connect threat-intel platforms. Shodan, FOFA, Censys and Google Lens find impersonating servers and pages that permutations and CT logs miss."],
};
const TAB_FORMS = {
  hunt: "hunt-scan-form", single: "single-scan-form", batch: "batch-scan-form",
  reverse: "reverse-scan-form", aggregator: "aggregator-scan-form", impersonation: "impersonation-scan-form",
  keys: "keys-page", history: "history-page", watch: "watch-page", storage: "storage-page",
};
const RESULT_SECTIONS = ["hunt-results-section", "results-section", "reverse-results-section", "aggregator-results-section", "impersonation-results-section"];

function showOnlySection(id) {
  RESULT_SECTIONS.forEach(s => {
    const el = document.getElementById(s);
    if (el) el.hidden = s !== id;
  });
}

function toggleNav(open) {
  document.getElementById("app").classList.toggle("nav-open", open);
}

function switchTab(tab) {
  currentTab = tab;
  Object.entries(TAB_FORMS).forEach(([key, formId]) => {
    document.getElementById(formId).hidden = key !== tab;
  });
  document.querySelectorAll(".nav-item[data-tab]").forEach(btn => {
    const on = btn.dataset.tab === tab;
    btn.classList.toggle("active", on);
    if (on) btn.setAttribute("aria-current", "page"); else btn.removeAttribute("aria-current");
  });
  const [title, desc] = PAGE_META[tab];
  document.getElementById("page-title").innerText = title;
  document.getElementById("topbar-title").innerText = title;
  document.getElementById("page-desc").innerText = desc;
  document.title = `${title} · Brand Hunter`;
  document.getElementById("hunt-progress-panel").hidden = !(tab === "hunt" && huntJobId);
  updateHuntEmpty();
  toggleNav(false);

  if (tab === "hunt") showOnlySection(currentHunt ? "hunt-results-section" : null);
  else if (tab === "single") showOnlySection(currentResult && !currentBatchResult ? "results-section" : null);
  else if (tab === "batch") showOnlySection(currentBatchResult ? "results-section" : null);
  else if (tab === "reverse") {
    showOnlySection(currentReverseBulkResult ? "reverse-results-section" : null);
    const badge = document.getElementById("compare-target-badge");
    const brandIcon = getPrimaryBrandIcon();
    badge.innerText = brandIcon && currentResult?.domain
      ? `Comparing with ${currentResult.domain}`
      : "Tip: run an asset scan first to get similarity scores.";
  } else if (tab === "aggregator") showOnlySection(currentAggregatorResult ? "aggregator-results-section" : null);
  else if (tab === "impersonation") showOnlySection(currentImpersonationResult ? "impersonation-results-section" : null);
  else if (tab === "keys") {
    showOnlySection(null);
    loadKeys();
  } else if (tab === "history") {
    showOnlySection(null);
    loadHistory();
  } else if (tab === "watch") {
    showOnlySection(null);
    loadWatch();
  } else if (tab === "storage") {
    showOnlySection(null);
    loadStorage();
  }
}

function updateHuntEmpty() {
  const el = document.getElementById("hunt-empty");
  if (el) el.hidden = !(currentTab === "hunt" && !huntJobId && !currentHunt);
}

function getPrimaryBrandIcon() {
  const icons = currentResult?.icons || [];
  return icons.find(i => i.is_primary && i.phash) || icons.find(i => i.kind === "logo" && i.phash) || icons.find(i => i.phash) || null;
}

function setTarget(domain) {
  const input = document.getElementById("target-input");
  input.value = domain;
  input.focus();
}

// =============================================================================
// ASSET SCAN & BATCH
// =============================================================================
async function handleSingleScan(e) {
  e.preventDefault();
  const target = document.getElementById("target-input").value.trim();
  if (!target) return;
  const btn = document.getElementById("btn-scan");
  setBusy(btn, true, "Scanning…");
  setLoading(true, `Crawling ${target}: homepage, manifests, fallbacks and subdomains`);
  showOnlySection(null);
  try {
    const data = await apiPost("/api/scan", {
      target,
      include_logos: document.getElementById("toggle-logos").checked,
      probe_subdomains: document.getElementById("toggle-probe-subdomains").checked,
      save_icons: document.getElementById("toggle-save-icons").checked,
      timeout: 12,
    });
    currentResult = data;
    currentBatchResult = null;
    renderBatchNav();
    renderScanResult(data);
  } catch (err) {
    showToast(`Scan failed: ${err.message}`, 6000);
  } finally {
    setBusy(btn, false);
    setLoading(false);
  }
}

async function handleBatchScan(e) {
  e.preventDefault();
  const targets = document.getElementById("batch-targets-input").value.split(/\r?\n/).map(s => s.trim()).filter(s => s && !s.startsWith("#"));
  if (!targets.length) return showToast("Enter at least one domain");
  const btn = document.getElementById("btn-batch-scan");
  setBusy(btn, true, "Scanning…");
  setLoading(true, `Scanning ${plural(targets.length, "domain")}, four at a time`);
  showOnlySection(null);
  try {
    const data = await apiPost("/api/batch", {
      targets,
      include_logos: document.getElementById("toggle-batch-logos").checked,
      probe_subdomains: document.getElementById("toggle-batch-probe-subdomains").checked,
      timeout: 10,
    });
    if (!data.results?.length) return showToast("The batch scan returned no results");
    currentBatchResult = data;
    selectBatchResult(0);
    showToast(`Batch complete: ${plural(data.results.length, "target")}`);
  } catch (err) {
    showToast(`Batch scan failed: ${err.message}`, 6000);
  } finally {
    setBusy(btn, false);
    setLoading(false);
  }
}

function selectBatchResult(idx) {
  if (!currentBatchResult) return;
  currentBatchIndex = idx;
  currentResult = currentBatchResult.results[idx];
  renderBatchNav();
  renderScanResult(currentResult, { scroll: false });
}

function renderBatchNav() {
  const nav = document.getElementById("batch-nav");
  if (!currentBatchResult) {
    nav.hidden = true;
    nav.innerHTML = "";
    return;
  }
  nav.hidden = false;
  nav.innerHTML = `<span class="option-label">Targets</span>` + currentBatchResult.results.map((r, i) => {
    const n = (r.icons || []).length;
    return `<button type="button" class="chip${i === currentBatchIndex ? " active" : ""}" data-batch-idx="${i}">
      ${r.error ? `<span class="dot dot-danger"></span>` : ""}${esc(r.domain)} <span class="count">${r.error ? "error" : n}</span></button>`;
  }).join("");
  nav.querySelectorAll("[data-batch-idx]").forEach(btn => btn.addEventListener("click", () => selectBatchResult(Number(btn.dataset.batchIdx))));
}

function renderScanResult(data, { scroll = true } = {}) {
  const icons = data.icons || [];
  document.getElementById("res-target-domain").innerText = data.domain || "Unknown domain";
  const resolved = document.getElementById("res-resolved-url");
  resolved.innerText = data.resolved_url || "";
  resolved.title = data.resolved_url || "";
  document.getElementById("res-icons-count").innerText = plural(icons.length, "icon");

  const grid = document.getElementById("icons-grid-container");
  window.iconStore = {};
  grid.innerHTML = "";
  if (data.error) {
    grid.innerHTML = `<div class="alert alert-danger" style="grid-column: 1 / -1;">${I.alert}<div>Scan failed: ${esc(data.error)}</div></div>`;
  } else if (!icons.length) {
    grid.innerHTML = `<div class="card" style="grid-column: 1 / -1;">${emptyState("No icons found",
      data.reachable === false
        ? "The site could not be reached over HTTPS or HTTP (DNS failure, timeout or connection refused)."
        : "The site responded, but no favicon, manifest icon or fallback returned a valid image.")}</div>`;
  } else {
    icons.forEach((icon, idx) => grid.appendChild(createIconCard(icon, idx)));
  }
  renderQueryDeck(data.queries || {});
  const section = document.getElementById("results-section");
  section.hidden = false;
  if (scroll) section.scrollIntoView({ behavior: "smooth", block: "start" });
}

const KIND_BADGES = {
  logo: `<span class="badge badge-sm badge-purple" title="Brand logo / og:image. Not indexed by favicon-hash filters; used for pHash comparison and URLScan resource search.">Logo</span>`,
  subdomain: `<span class="badge badge-sm badge-warning" title="Favicon of a probed subdomain portal. Kept out of master queries because portals are often hosted by SaaS vendors whose favicon is shared by all their customers.">Subdomain portal</span>`,
};

function reverseImageLinks(url) {
  const u = encodeURIComponent(url);
  return [
    ["Lens", `https://lens.google.com/uploadbyurl?url=${u}`],
    ["Yandex", `https://yandex.com/images/search?rpt=imageview&url=${u}`],
    ["TinEye", `https://tineye.com/search?url=${u}`],
    ["Bing", `https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:${u}`],
  ].map(([label, href]) => linkBtn(href, label, `Reverse image search on ${label}`)).join("");
}

function hashTable(rows) {
  return `<dl class="hash-table">${rows.map(([label, value, shown]) => `
    <dt>${label}</dt><dd title="${esc(value ?? "")}">${esc(shown ?? value ?? "n/a")}</dd><span>${copyBtn(value, `${label} copied`)}</span>`).join("")}</dl>`;
}

function createIconCard(icon, idx) {
  window.iconStore[idx] = icon;
  const card = document.createElement("article");
  card.className = "asset-card";
  const isData = (icon.url || "").startsWith("data:");
  const previewSrc = icon.preview || (isData ? icon.url : PLACEHOLDER_IMG);
  const sizeKb = icon.size_bytes ? `${(icon.size_bytes / 1024).toFixed(1)} KB` : "";
  const q = iconQueries(icon);
  const aliases = icon.also_found_at || [];

  card.innerHTML = `
    <div class="asset-head">
      <div class="asset-preview"><img src="${esc(previewSrc)}" alt="" loading="lazy"></div>
      <div style="min-width: 0; flex: 1;">
        ${isData
      ? `<span class="asset-title" title="${esc(displayUrl(icon.url))}">${esc(displayUrl(icon.url))}</span>`
      : `<a class="asset-title" href="${esc(icon.url)}" target="_blank" rel="noopener noreferrer" title="${esc(icon.url)}">${esc(icon.url)}</a>`}
        <div class="tags">
          ${icon.is_primary ? `<span class="badge badge-sm badge-success">Primary favicon</span>` : ""}
          ${KIND_BADGES[icon.kind] || ""}
          <span class="badge badge-sm badge-mono">${esc(icon.format || "IMG")}</span>
          ${icon.dimensions ? `<span class="badge badge-sm badge-mono">${esc(icon.dimensions)}</span>` : ""}
          ${sizeKb ? `<span class="badge badge-sm">${esc(sizeKb)}</span>` : ""}
          ${icon.source ? `<span class="badge badge-sm" title="${esc(icon.source)}">${esc(icon.source.split(":")[0])}</span>` : ""}
          ${aliases.length ? `<span class="badge badge-sm" title="${esc(aliases.join("\n"))}">+${aliases.length} identical</span>` : ""}
        </div>
      </div>
    </div>
    ${hashTable([["MMH3", icon.mmh3], ["MD5", icon.md5], ["SHA-256", icon.sha256], ["pHash", icon.phash]])}
    <div class="asset-foot">
      ${!isData ? `<div class="link-row"><span class="label">Reverse image</span>${reverseImageLinks(icon.url)}</div>` : ""}
      ${Object.keys(q).length ? `<div class="link-row"><span class="label">Search</span>
        ${Object.entries(q).map(([p, query]) => linkBtn(platformUrl(p, query), PLATFORMS[p].name, `Search this icon on ${PLATFORMS[p].name}`)).join("")}
        <button type="button" class="btn btn-ghost btn-xs" data-launch-icon="${idx}">Open all</button></div>` : ""}
    </div>`;
  card.querySelector("[data-launch-icon]")?.addEventListener("click", () => launchSingleIconAllEngines(idx));
  return card;
}

function launchSingleIconAllEngines(idx) {
  const icon = window.iconStore[idx];
  if (icon) launchAllSearchEngines(iconQueries(icon), `icon ${icon.mmh3 ?? icon.md5}`);
}

function renderQueryDeck(queries) {
  currentQueries = queries;
  const combined = queries.combined || {};
  const counts = queries.hash_counts || {};
  const available = PLATFORM_KEYS.filter(p => combined[p]);

  document.getElementById("master-combined-query-deck").hidden = !available.length;
  document.getElementById("master-query-rows").innerHTML = available.map(p => queryRow(pfLabel(p), combined[p], platformUrl(p, combined[p]))).join("")
    + (combined.censys_sha256 ? queryRow(`${pfLabel("censys")} <span class="muted">SHA-256</span>`, combined.censys_sha256, platformUrl("censys", combined.censys_sha256)) : "");
  const n = counts.mmh3 ?? (queries.fofa || []).length;
  document.getElementById("master-hash-count").innerText = `${plural(n, "favicon hash", "favicon hashes")} OR-ed`;
  const notes = [];
  if (counts.excluded_subdomain_icons) notes.push(`${plural(counts.excluded_subdomain_icons, "subdomain-portal icon")} kept out (often shared SaaS favicons).`);
  notes.push("Logos are searched on URLScan only.");
  document.getElementById("master-query-note").innerText = notes.join(" ");

  const grid = document.getElementById("platform-queries-grid");
  grid.innerHTML = "";
  PLATFORM_KEYS.forEach(p => {
    const list = queries[p] || [];
    const wrapper = document.createElement("div");
    wrapper.innerHTML = platformCard(p,
      list.length ? list.map((q, i) => queryRow(i === 0 && (p === "fofa" || p === "shodan") ? `<span class="badge badge-sm badge-success">Primary</span>` : "", q, platformUrl(p, q), { wrap: p === "censys" })).join("")
        : `<span class="hint">None generated</span>`,
      list.length > 1 ? `<span class="badge badge-sm">${list.length}</span><button type="button" class="btn btn-ghost btn-xs" data-open-platform="${p}">Open all</button>` : "");
    wrapper.querySelector("[data-open-platform]")?.addEventListener("click", () => launchUrlsInNewWindow(list.map(q => platformUrl(p, q)), `${PLATFORMS[p].name} tabs`));
    grid.appendChild(wrapper.firstElementChild);
  });
}

function launchMasterAllEngines() {
  const combined = currentResult?.queries?.combined;
  if (!combined || !Object.keys(combined).length) return showToast("Scan a domain first");
  launchAllSearchEngines(combined, currentResult?.domain);
}

function copyMasterAllQueries() {
  const combined = currentResult?.queries?.combined;
  if (!combined) return showToast("Scan a domain first");
  const lines = [`# Master favicon queries: ${currentResult?.domain || "target"}`];
  PLATFORM_KEYS.forEach(p => lines.push(`${PLATFORMS[p].name}: ${combined[p] || "n/a"}`));
  copyText(lines.join("\n"), "All master queries copied");
}

async function openAllFofaHashesMultipleTabs(customList = null) {
  let fofaQueries = [];
  if (Array.isArray(customList) && customList.length) {
    fofaQueries = customList.map(item => { const s = String(item).trim(); return s.startsWith("icon_hash=") ? s : fofaIconQuery(s); });
  } else if (currentTab === "reverse" && currentReverseBulkResult?.unique_mmh3?.length) {
    fofaQueries = currentReverseBulkResult.unique_mmh3.map(fofaIconQuery);
  } else if (currentQueries?.fofa?.length) {
    fofaQueries = currentQueries.fofa;
  } else if (currentReverseBulkResult?.unique_mmh3?.length) {
    fofaQueries = currentReverseBulkResult.unique_mmh3.map(fofaIconQuery);
  }
  fofaQueries = [...new Set(fofaQueries)];
  if (!fofaQueries.length) return showToast("No FOFA hashes yet: scan a domain or analyze images first");
  await launchUrlsInNewWindow(fofaQueries.map(q => platformUrl("fofa", q)), "FOFA tabs");
}

function stripPreviews(obj) {
  return JSON.parse(JSON.stringify(obj, (k, v) => (k === "preview" ? undefined : v)));
}

function exportCurrentJSON() {
  const data = currentBatchResult || currentResult;
  if (!data) return;
  const filename = currentBatchResult ? "batch_favicon_hashes.json" : `${data.domain || "scan"}_favicon_hashes.json`;
  downloadBlob(JSON.stringify(stripPreviews(data), null, 2), filename, "application/json");
  showToast("JSON downloaded");
}

function exportCurrentCSV() {
  const items = currentBatchResult ? currentBatchResult.results : (currentResult ? [currentResult] : []);
  if (!items.length) return;
  const header = ["domain", "resolved_url", "icon_url", "kind", "is_primary", "format", "dimensions", "size_bytes",
    "mmh3", "md5", "sha256", "phash", "fofa_query", "shodan_query", "censys_query", "urlscan_query"];
  const rows = [header.join(",")];
  items.forEach(t => {
    const icons = t.icons || [];
    if (!icons.length) {
      rows.push([t.domain, t.resolved_url || "", t.error ? `ERROR: ${t.error}` : "No icons found"].map(csvCell).join(","));
      return;
    }
    icons.forEach(icon => {
      const q = iconQueries(icon);
      rows.push([t.domain, t.resolved_url, icon.url, icon.kind, icon.is_primary ? "yes" : "", icon.format, icon.dimensions,
      icon.size_bytes, icon.mmh3, icon.md5, icon.sha256, icon.phash, q.fofa, q.shodan, q.censys, q.urlscan].map(csvCell).join(","));
    });
  });
  const filename = currentBatchResult ? "batch_favicon_hashes.csv" : `${currentResult.domain || "scan"}_favicon_hashes.csv`;
  downloadBlob("﻿" + rows.join("\r\n") + "\r\n", filename, "text/csv;charset=utf-8;");
  showToast("CSV downloaded");
}

// ----------------------------------------------------------------------------- multi-tab launcher
// window.open with "noopener" returns null, so sever the opener manually instead.
function openTab(url) {
  const w = window.open(url, "_blank");
  if (w) w.opener = null;
  return w;
}

// The first tab opens via window.open (user gesture); the rest go through the local backend
// (OS shell launcher), which is not subject to the popup blocker.
async function launchUrlsInNewWindow(urls, label = "tabs") {
  urls = (urls || []).filter(Boolean);
  if (!urls.length) return showToast("Nothing to open");
  showToast(`Opening ${urls.length} ${label}…`);
  let firstWin = null;
  try { firstWin = openTab(urls[0]); } catch (e) { /* blocked */ }
  const remaining = urls.slice(1);
  if (!remaining.length) return;
  try {
    const result = await apiPost("/api/launch-engines", { urls: remaining });
    if (result.status === "ok") return showToast(`Opened ${urls.length} ${label}`);
  } catch (err) { /* fall back to window.open */ }
  let opened = firstWin ? 1 : 0;
  remaining.forEach(u => { try { if (openTab(u)) opened++; } catch (e) { /* blocked */ } });
  showToast(opened < urls.length
    ? "The popup blocker stopped some tabs. Allow pop-ups for this site and try again."
    : `Opened ${opened} ${label}`, opened < urls.length ? 7000 : 2600);
}

async function launchAllSearchEngines(queriesObj, targetName) {
  if (!queriesObj) return;
  const urls = PLATFORM_KEYS.map(p => platformUrl(p, queriesObj[p])).filter(Boolean);
  if (!urls.length) return showToast("No queries to open");
  await launchUrlsInNewWindow(urls, targetName ? `searches for ${targetName}` : "searches");
}

// =============================================================================
// LOGO INSPECTOR
// =============================================================================
function handleMultipleFileUpload(e) {
  const files = e.target.files;
  if (!files?.length) return;
  Array.from(files).forEach(file => {
    const reader = new FileReader();
    reader.onload = ev => {
      uploadedFilesList.push({ name: file.name, data: ev.target.result });
      updateUploadDisplay();
    };
    reader.readAsDataURL(file);
  });
}

function updateUploadDisplay() {
  const nameDisplay = document.getElementById("file-name-display");
  const clearBtn = document.getElementById("btn-clear-uploaded-files");
  nameDisplay.innerText = !uploadedFilesList.length ? "" :
    uploadedFilesList.length === 1 ? uploadedFilesList[0].name : `${uploadedFilesList.length} files selected`;
  clearBtn.hidden = !uploadedFilesList.length;
}

function clearUploadedFiles() {
  uploadedFilesList = [];
  document.getElementById("reverse-file-input").value = "";
  updateUploadDisplay();
  showToast("Uploads cleared");
}

async function handleReverseLogoScan(e) {
  e.preventDefault();
  const urlList = [];
  for (const line of (document.getElementById("reverse-image-urls-input").value || "").split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    if (!t.startsWith("data:") && t.includes(",") && !/^https?:\/\//i.test(t)) t.split(",").map(s => s.trim()).filter(Boolean).forEach(u => urlList.push(u));
    else urlList.push(t);
  }
  if (!urlList.length && !uploadedFilesList.length) return showToast("Paste an image URL or upload an image");

  const brandIcon = getPrimaryBrandIcon();
  const btn = document.getElementById("btn-reverse-scan");
  setBusy(btn, true, "Analyzing…");
  setLoading(true, `Downloading and hashing ${plural(urlList.length + uploadedFilesList.length, "image")}`);
  showOnlySection(null);
  try {
    const data = await apiPost("/api/analyze-images-bulk", {
      image_urls: urlList, images_base64: uploadedFilesList, compare_phash: brandIcon ? brandIcon.phash : null, timeout: 15,
    });
    currentReverseBulkResult = data;
    renderBulkReverseAnalysis(data, brandIcon);
  } catch (err) {
    showToast(`Image analysis failed: ${err.message}`, 6000);
  } finally {
    setBusy(btn, false);
    setLoading(false);
  }
}

function renderBulkReverseAnalysis(data, brandIcon) {
  document.getElementById("reverse-source-domain-tag").innerText =
    `${plural(data.total_submitted, "candidate")} · ${data.successful_count} processed · ${plural(data.unique_mmh3_count, "unique hash", "unique hashes")}`;
  const mq = data.master_queries || {};
  const available = PLATFORM_KEYS.filter(p => mq[p]);
  document.getElementById("reverse-master-deck").hidden = !available.length;
  document.getElementById("reverse-master-query-grid").innerHTML = available.map(p => platformCard(p, queryRow("", mq[p], platformUrl(p, mq[p])))).join("");

  const container = document.getElementById("reverse-candidates-container");
  window.reverseCandidateStore = {};
  container.innerHTML = "";
  if (!data.candidates.length) container.innerHTML = `<div class="card" style="grid-column: 1 / -1;">${emptyState("No images analyzed")}</div>`;
  else data.candidates.forEach((cand, idx) => container.appendChild(createCandidateCard(cand, idx, brandIcon)));

  showOnlySection("reverse-results-section");
  document.getElementById("reverse-results-section").scrollIntoView({ behavior: "smooth", block: "start" });
}

function createCandidateCard(cand, idx, brandIcon) {
  window.reverseCandidateStore[cand.id] = cand;
  const card = document.createElement("article");
  card.className = "asset-card";

  if (cand.error) {
    card.innerHTML = `
      <div class="spread"><span class="card-title">Candidate ${idx + 1}</span><span class="badge badge-sm badge-danger">Fetch failed</span></div>
      <div class="alert alert-danger">${I.alert}<div><div>${esc(cand.error)}</div><div class="mono" style="word-break: break-all; margin-top: 4px; opacity: .8;">${esc(displayUrl(cand.original_url) || "Unknown URL")}</div></div></div>`;
    return card;
  }

  const a = cand.analysis || {};
  const sim = cand.similarity;
  const simScore = sim ? sim.similarity_percent : null;
  const simCls = simScore === null ? "" : simScore >= 90 ? "sim-high" : simScore >= 75 ? "sim-mod" : "";
  const displayDomain = cand.source_domain || "Candidate image";
  const isPageAsset = displayDomain.includes("(");
  const pivotHost = cand.type === "url" ? displayDomain.split(" ")[0] : "";
  const q = iconQueries(a);
  const dims = Array.isArray(a.dimensions) ? a.dimensions.join("x") : (a.dimensions || "");

  card.innerHTML = `
    <div class="asset-head">
      <div class="asset-preview lg"><img src="${esc(cand.preview_base64 || PLACEHOLDER_IMG)}" alt=""></div>
      <div style="min-width: 0; flex: 1;">
        <div class="spread" style="gap: 6px;"><span class="card-title">Candidate ${idx + 1}</span>
          <span class="row" style="gap: 4px;"><span class="badge badge-sm badge-mono">${esc(a.format || "IMG")}</span>${dims ? `<span class="badge badge-sm badge-mono">${esc(dims)}</span>` : ""}</span></div>
        <div class="asset-title" style="margin-top: 4px;" title="${esc(cand.real_url || cand.original_url)}">${esc(displayDomain)}</div>
        <div class="tags">
          ${isPageAsset ? `<span class="badge badge-sm badge-accent" title="Extracted from ${esc(cand.original_url)}">Logo from page</span>` : ""}
          ${cand.is_unwrapped ? `<span class="badge badge-sm badge-accent" title="Unwrapped from ${esc(cand.original_url)}">Unwrapped search link</span>` : ""}
          ${pivotHost ? `<button type="button" class="btn btn-ghost btn-xs" data-pivot="${esc(pivotHost)}">Scan ${esc(pivotHost)}</button>` : ""}
        </div>
      </div>
    </div>
    ${sim && brandIcon ? `
      <div class="similarity ${simCls}">
        <div><strong>${esc(simScore)}%</strong> <span class="hint">visual match</span><div class="hint">${esc(sim.match_verdict)}</div></div>
        ${sim.distance !== null ? `<span class="badge badge-sm badge-mono">${esc(sim.distance)} bits</span>` : ""}
      </div>` : ""}
    ${hashTable([["MMH3", a.mmh3], ["MD5", a.md5], ["SHA-256", a.sha256], ["pHash", a.phash]])}
    <div class="asset-foot">
      <div class="link-row"><span class="label">Search</span>
        ${Object.entries(q).map(([p, query]) => linkBtn(platformUrl(p, query), PLATFORMS[p].name)).join("")}
        <button type="button" class="btn btn-ghost btn-xs" data-launch-cand>Open all</button>
      </div>
    </div>`;
  card.querySelector("[data-launch-cand]")?.addEventListener("click", () => launchAllSearchEngines(q, displayDomain));
  card.querySelector("[data-pivot]")?.addEventListener("click", ev => pivotToDomainScan(ev.currentTarget.dataset.pivot));
  return card;
}

function launchReverseBulkEngines() {
  if (!currentReverseBulkResult?.master_queries) return showToast("Analyze images first");
  launchAllSearchEngines(currentReverseBulkResult.master_queries, "candidate images");
}

function copyReverseBulkQueries() {
  if (!currentReverseBulkResult?.master_queries) return showToast("Analyze images first");
  const q = currentReverseBulkResult.master_queries;
  const lines = [`# Candidate image queries (${currentReverseBulkResult.successful_count} images)`];
  PLATFORM_KEYS.forEach(p => lines.push(`${PLATFORMS[p].name}: ${q[p] || "n/a"}`));
  copyText(lines.join("\n"), "Queries copied");
}

function pivotToDomainScan(domain) {
  if (!domain) return;
  switchTab("single");
  document.getElementById("target-input").value = domain;
  document.getElementById("btn-scan").click();
}

// =============================================================================
// HASH AGGREGATOR
// =============================================================================
function loadGdSampleHashes() {
  const input = document.getElementById("aggregator-input");
  input.value = '(icon_hash="-405598701" || icon_hash="356140581" || icon_hash="1799690930" || icon_hash="995302468" || icon_hash="190868939" || icon_hash="-1010204208" || icon_hash="-1570316353" || icon_hash="-625357297" || icon_hash="846494219" || icon_hash="1246530638" || icon_hash="-1615468998")';
  input.focus();
  showToast("Sample loaded");
}

async function handleAggregatorSubmit(e) {
  e.preventDefault();
  const rawText = document.getElementById("aggregator-input").value.trim();
  if (!rawText) return;
  const btn = document.getElementById("btn-aggregate");
  setBusy(btn, true, "Building…");
  showOnlySection(null);
  try {
    const data = await apiPost("/api/aggregate-hashes", { input_text: rawText });
    currentAggregatorResult = data;
    renderAggregatorResult(data);
  } catch (err) {
    showToast(`Could not build queries: ${err.message}`, 6000);
  } finally {
    setBusy(btn, false);
  }
}

function renderAggregatorResult(data) {
  const mmh3 = data.unique_hashes || [], md5 = data.unique_md5 || [], sha = data.unique_sha256 || [];
  document.getElementById("agg-hash-count-tag").innerText = `${mmh3.length} MMH3 · ${md5.length} MD5 · ${sha.length} SHA-256`;
  const chips = (label, values) => values.length ? `
    <div><h3 class="group-title">${label} <span class="muted" style="text-transform: none; letter-spacing: 0;">(${values.length}, click to copy)</span></h3>
      <div class="chips">${values.map(h => `<button type="button" class="badge badge-mono" data-copy="${esc(h)}" data-copy-label="Copied">${esc(String(h).length > 20 ? String(h).slice(0, 16) + "…" : h)}</button>`).join("")}</div></div>` : "";
  document.getElementById("aggregator-query-grid").innerHTML = `
    <section class="card"><div class="card-body stack">${chips("MMH3 · FOFA, Shodan", mmh3)}${chips("MD5 · Censys", md5)}${chips("SHA-256 · URLScan", sha)}</div></section>
    <div class="platform-grid">${PLATFORM_KEYS.filter(p => data.queries?.[p]).map(p => platformCard(p, queryRow("", data.queries[p], platformUrl(p, data.queries[p]), { wrap: true }))).join("")}
      ${data.queries?.censys_sha256 ? platformCard("censys", queryRow(`<span class="muted">SHA-256</span>`, data.queries.censys_sha256, platformUrl("censys", data.queries.censys_sha256), { wrap: true })) : ""}</div>`;
  showOnlySection("aggregator-results-section");
  document.getElementById("aggregator-results-section").scrollIntoView({ behavior: "smooth", block: "start" });
  showToast(`Queries built for ${plural(data.hashes_count, "hash", "hashes")}`);
}

function launchAggregatorEngines() {
  if (!currentAggregatorResult?.queries) return showToast("Build queries first");
  launchAllSearchEngines(currentAggregatorResult.queries, "aggregated hashes");
}

function copyAggregatorQueries() {
  if (!currentAggregatorResult?.queries) return showToast("Build queries first");
  const q = currentAggregatorResult.queries;
  const lines = [`# Aggregated hash queries (${currentAggregatorResult.hashes_count} hashes)`];
  PLATFORM_KEYS.forEach(p => lines.push(`${PLATFORMS[p].name}: ${q[p] || "n/a"}`));
  copyText(lines.join("\n"), "Queries copied");
}

// =============================================================================
// DORK GENERATOR
// =============================================================================
function loadImpersonationSample(type) {
  const samples = {
    lnt: "L&T Avinya Enclave\nL&T The Gateway\nL&T Island Cove\nL&T Veridian\nL&T Elixir Reserve\nlntrealty.com\nthanisandra\nmanapakkam",
    crypto: "binance.com, metamask.io, coinbase.com, ledger.com",
    brands: "paypal.com, netflix.com, microsoft.com, apple.com",
    cyber: "cyfirma.com, de-cix.net, gi-de.com",
  };
  const input = document.getElementById("impersonation-input");
  input.value = samples[type] || "";
  input.focus();
}

// Dork types per platform: [key, label, note]
const DORK_TYPES = {
  fofa: [
    ["all_domains", "All domains (*=)", "Substring *= across domain, host, cert, CNAME (all status codes; requires FOFA membership)"],
    ["exhaustive", "Deep capture (domains+body+headers)", "Matches domain, host, cert, CNAME, title, HTML body, and redirect headers"],
    ["scam_lures", "Scam & phishing lures", "Matches login, verify, KYC, OTP, seed-phrase, wallet, or support kits"],
    ["free_hosting", "Free hosting & cloud", "Brand pages on pages.dev, workers.dev, vercel, firebase, s3, trycloudflare, etc."],
    ["idn_homoglyph", "IDN Punycode (xn--)", "Unicode homoglyph domains impersonating the brand"],
    ["master", "Master (free tier)", "Token match across title, host, domain, cert (free tier compatible, no 200 gate)"],
    ["title_spoof", "Title"],
    ["domain_wildcard", "Host token", "Token match on hostnames (free)"],
    ["domain_contains", "Host contains", "host*= substring wildcard needs FOFA membership or F-points"],
    ["cert_wildcard", "Certificate"],
    ["body_content", "Page body"],
  ],
  censys: [
    ["all_domains", "All domains (regex)", "Case-insensitive CenQL regex across web.hostname, cert.names, and host.dns.names"],
    ["exhaustive", "Deep capture (domains+title+body)", "Case-insensitive regex including HTML titles and response bodies"],
    ["scam_lures", "Scam & phishing lures", "Brand + credential/OTP/KYC/wallet/offer indicators"],
    ["free_hosting", "Free hosting & cloud", "Cloud/static site builders hosting brand pages"],
    ["idn_homoglyph", "IDN Punycode (xn--)", "Punycode lookalikes & IDN sites with brand titles/bodies"],
    ["master", "Master (tokenized)", "Tokenized match across title, web.hostname, cert.names, host.dns.names"],
    ["title_spoof", "Title"],
    ["domain_wildcard", "Hostnames"],
    ["cert_wildcard", "Cert names"],
  ],
  urlscan: [
    ["all_domains", "All domains (.keyword)", "Full infix/prefix/suffix match on page.domain.keyword & task.domain.keyword (signed-in / API key)"],
    ["exhaustive", "Deep capture (domains+URLs+assets+titles)", "Catches compromised sites (/brand/), redirect sources (task.url), and sub-resources (filename)"],
    ["scam_lures", "Scam & phishing lures", "Combines brand with login, verify, kyc, refund, wallet, offer, booking lures (free)"],
    ["free_hosting", "Free hosting & cloud", "Catches kits on pages.dev, workers.dev, vercel, netlify, firebase, trycloudflare (free)"],
    ["idn_homoglyph", "IDN Punycode (xn--)", "Catches Unicode homoglyph domains (e.g. xn--pypal*) even anonymously"],
    ["master", "Master (free tier)", "Anonymous-safe: title, domain prefix, page.url, task.url & filename prefix"],
    ["domain_wildcard", "Domain prefix", "Matches any domain level starting with token (free)"],
    ["url_prefix", "URL token (free)", "Matches hyphenated domains & URL paths anonymously"],
    ["domain_contains", "Domain contains", "Leading wildcard needs a signed-in urlscan account"],
    ["title_spoof", "Title"],
    ["body_content", "Page text", "text.content is a urlscan Pro field"],
  ],
  shodan: [
    ["all_domains", "Hostnames (PTR)", "Comma-separated OR across PTR/DNS hostnames"],
    ["ssl_all", "SSL all (CN + SANs)", "Searches all SSL/TLS certificate data including Subject Alternative Names"],
    ["scam_lures", "Scam login pages", "HTML containing both the brand keyword and password prompts"],
    ["master", "Master (Cert CN)", "Comma-separated OR across SSL Subject CN"],
    ["title_spoof", "Title"],
    ["cert_wildcard", "Cert CN", "Comma-separated values are OR-ed"],
    ["body_content", "HTML body"],
  ],
};

async function handleImpersonationSubmit(e) {
  e.preventDefault();
  const rawInput = document.getElementById("impersonation-input").value.trim();
  if (!rawInput) return;
  const includeVariants = !!document.getElementById("imp-toggle-variants")?.checked;
  const btn = document.getElementById("btn-impersonation-generate");
  setBusy(btn, true, "Generating…");
  try {
    const data = await apiPost("/api/impersonation-dorks", { keywords: rawInput, include_variants: includeVariants });
    currentImpersonationResult = data;
    currentCapturedDomains = null;
    document.getElementById("impersonation-captured-panel").hidden = true;
    renderImpersonationResults(data);
    showOnlySection("impersonation-results-section");
    document.getElementById("impersonation-results-section").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    showToast(`Could not generate dorks: ${err.message}`, 6000);
  } finally {
    setBusy(btn, false);
  }
}

function subQueryRow(label, query, url, note = "") {
  return queryRow(`<span class="muted" title="${esc(note)}">${esc(label)}${note ? " *" : ""}</span>`, query, url);
}

function renderImpersonationResults(data) {
  const subs = data.all_substring_terms || [];
  document.getElementById("impersonation-count-tag").innerText =
    `${plural(data.total_keywords, "keyword")}: ${data.keywords.join(", ")}` +
    (subs.length ? ` · match terms: ${subs.join(", ")}` : "") +
    ((data.legit_domains || []).length ? ` · excluding ${data.legit_domains.join(", ")}` : "");

  const masterGrid = document.getElementById("impersonation-master-grid");
  masterGrid.innerHTML = "";
  PLATFORM_KEYS.forEach(p => {
    const item = data.master_queries[p];
    if (!item) return;
    let rows = "";
    if (p === "fofa") {
      rows = subQueryRow("All domains (*=)", item.all_domains_query, item.all_domains_url, "Substring wildcard across domain, host, cert, CNAME (membership)") +
        subQueryRow("Deep (domains+body+headers)", item.exhaustive_query, item.exhaustive_url, "Also matches HTML titles, bodies, and redirect headers") +
        subQueryRow("Scam & phishing lures", item.scam_lures_query, item.scam_lures_url, "Login, verify, KYC, OTP, seed-phrase, wallet, support kits") +
        subQueryRow("Free hosting & cloud", item.free_hosting_query, item.free_hosting_url, "Cloud/static site builders hosting brand pages") +
        subQueryRow("IDN Punycode (xn--)", item.idn_query, item.idn_url, "Unicode homoglyph domains impersonating the brand") +
        subQueryRow("Master (free)", item.query, item.url, "Token match on hostnames without status_code filter");
    } else if (p === "censys") {
      rows = subQueryRow("All domains (regex)", item.all_domains_query, item.all_domains_url, "Case-insensitive regex across web.hostname, cert.names, host.dns.names") +
        subQueryRow("Deep (domains+title+body)", item.exhaustive_query, item.exhaustive_url, "Regex including HTML titles and response bodies") +
        subQueryRow("Scam & phishing lures", item.scam_lures_query, item.scam_lures_url, "Brand + credential/OTP/KYC/wallet lures") +
        subQueryRow("Free hosting & cloud", item.free_hosting_query, item.free_hosting_url, "Cloud/static site builders hosting brand pages") +
        subQueryRow("IDN Punycode (xn--)", item.idn_query, item.idn_url, "Punycode lookalikes & IDN sites") +
        subQueryRow("Tokenized", item.query, item.url, "Fast tokenized web.hostname match");
    } else if (p === "urlscan") {
      rows = subQueryRow("All domains", item.all_domains_query, item.all_domains_url, "Leading+trailing wildcard across page.domain.keyword & task.domain.keyword (signed-in)") +
        subQueryRow("Deep (domains+URLs+assets)", item.exhaustive_query, item.exhaustive_url, "Full substring match including URL paths & loaded resources (signed-in)") +
        subQueryRow("Scam & phishing lures", item.scam_lures_query, item.scam_lures_url, "Brand + login/verify/kyc/refund/wallet/offer lures (free)") +
        subQueryRow("Free hosting & cloud", item.free_hosting_query, item.free_hosting_url, "Kits on pages.dev, workers.dev, vercel, firebase, etc. (free)") +
        subQueryRow("IDN Punycode (xn--)", item.idn_query, item.idn_url, "Punycode homoglyph lookalikes (works anonymously)") +
        subQueryRow("Master (free)", item.query, item.url, "Anonymous-compatible title, domain, URL, task & filename prefix") +
        subQueryRow("Titles", item.title_query, item.title_url) +
        subQueryRow("Domains", item.domain_query, item.domain_url) +
        subQueryRow("Page text (Pro)", item.body_query, item.body_url);
    } else if (p === "shodan") {
      rows = subQueryRow("Hostnames (PTR)", item.hostname_query, item.hostname_url, "Reverse DNS / PTR hostnames") +
        subQueryRow("SSL all (CN+SAN)", item.ssl_query, item.ssl_url, "All SSL certificate text including SANs") +
        subQueryRow("Scam login pages", item.scam_lures_query, item.scam_lures_url, "HTML with both brand keyword and password prompts") +
        subQueryRow("Cert CN", item.query, item.url, "Comma-separated OR on Subject CN");
    }
    const w = document.createElement("div");
    w.innerHTML = platformCard(p, rows,
      `<button type="button" class="btn btn-ghost btn-xs" data-imp-platform="${p}" title="Open each keyword's search in its own tab">Open per keyword</button>`);
    w.querySelector("[data-imp-platform]").addEventListener("click", () => openImpersonationPlatformTabs(p));
    masterGrid.appendChild(w.firstElementChild);
  });

  // Certificate Transparency & Search Engines card
  const extraCard = document.getElementById("impersonation-extra-card");
  const extraBody = document.getElementById("impersonation-extra-body");
  const crtList = data.crtsh || [];
  const se = data.search_engines || {};
  if (crtList.length || Object.keys(se).length) {
    extraCard.hidden = false;
    const crtRows = crtList.map(c => `
      <div class="query-row">
        <span class="q-label"><span class="muted">crt.sh</span></span>
        <code title="${esc(c.query)}">${esc(c.query)}</code>
        <div class="q-actions">${copyBtn(c.query, "Pattern copied")}
          ${linkBtn(c.url, "All certs", "Search all CT logs on crt.sh", "btn btn-ghost btn-xs")}
          ${linkBtn(c.active_url, "Active", "Search non-expired CT logs on crt.sh", "btn btn-ghost btn-xs")}
        </div>
      </div>`).join("");
    const seRows = Object.entries({
      inurl: "URL & domain",
      credential_lure: "Credential / KYC lures",
      wildcard_site: "Wildcard domain",
      free_hosting: "Free hosting kits",
      scam_campaigns: "Fake support / jobs / offers",
      social_and_apps: "Social, Telegram & APKs",
      leaks_and_redirects: "Code leaks & redirects",
    })
      .filter(([k]) => se[k])
      .map(([k, lbl]) => `
        <div class="query-row">
          <span class="q-label"><span class="muted">${esc(lbl)}</span></span>
          <code title="${esc(se[k].query)}">${esc(se[k].query)}</code>
          <div class="q-actions">${copyBtn(se[k].query, "Dork copied")}
            ${Object.entries(se[k].links || {}).map(([e, href]) => linkBtn(href, e === "duckduckgo" ? "DDG" : e[0].toUpperCase() + e.slice(1), `Search on ${e}`, "btn btn-ghost btn-xs")).join("")}
          </div>
        </div>`).join("");
    extraBody.innerHTML = `<div class="query-list">${crtRows}${seRows}</div>`;
  } else {
    extraCard.hidden = true;
    extraBody.innerHTML = "";
  }

  const container = document.getElementById("impersonation-cards-container");
  container.innerHTML = "";
  data.items.forEach((it, idx) => {
    const dec = it.decomposition || {};
    const titles = dec.titles || [it.keyword];
    const tokens = dec.tokens || [];
    const slugs = dec.compound_slugs || [];
    const variants = dec.variants || [];
    const card = document.createElement("section");
    card.className = "keyword-card";
    const blocks = PLATFORM_KEYS.map(p => {
      const pd = it[p];
      if (!pd) return "";
      const dorks = DORK_TYPES[p].filter(([key]) => pd[key]);
      const primaryUrl = pd.all_domains_url || pd.master_url;
      return `<div class="platform-block stack" style="gap: 10px;">
        <div class="spread">${pfLabel(p)}${linkBtn(primaryUrl, `Open search`, `Open this keyword's best domain-capture query on ${PLATFORMS[p].name}`, "btn btn-ghost btn-xs")}</div>
        <div class="query-list">${dorks.map(([key, label, note]) => queryRow(`<span class="${key === "all_domains" || key === "master" ? "" : "muted"}" title="${esc(note || "")}">${esc(label)}${note ? " *" : ""}</span>`, pd[key], pd[`${key}_url`])).join("")}</div>
      </div>`;
    }).join("");
    card.innerHTML = `
      <div class="card-head">
        <div>
          <h2><span class="muted">#${idx + 1}</span> <span class="mono">${esc(it.keyword)}</span></h2>
          <p>${[titles.length > 1 ? `Titles: ${titles.map(t => `"${t}"`).join(", ")}` : "",
      tokens.length ? `Tokens: ${tokens.join(", ")}` : "",
      slugs.length ? `Slugs: ${shortList(slugs, 4)}` : "",
      variants.length ? `Variants: ${shortList(variants, 5)}` : "",
      dec.legit_domain ? `Excludes ${dec.legit_domain}` : ""].filter(Boolean).map(esc).join(" · ")}</p>
        </div>
        <div class="actions"><button type="button" class="btn btn-secondary btn-sm" data-kw-all>Open all platforms</button></div>
      </div>
      ${blocks}`;
    card.querySelector("[data-kw-all]").addEventListener("click", () => launchKeywordAllPlatforms(idx));
    container.appendChild(card);
  });
}

async function handleImpersonationCapture() {
  const rawInput = document.getElementById("impersonation-input").value.trim();
  if (!rawInput) return showToast("Enter keywords first");
  const includeVariants = !!document.getElementById("imp-toggle-variants")?.checked;
  const useDns = !!document.getElementById("imp-toggle-dns")?.checked;
  const btn = document.getElementById("btn-impersonation-capture");
  setBusy(btn, true, "Capturing domains…");
  try {
    const data = await apiPost("/api/impersonation-dorks/capture", {
      keywords: rawInput,
      include_variants: includeVariants,
      use_ct: true,
      use_intel: true,
      use_feeds: true,
      use_dns: useDns,
    });
    currentCapturedDomains = data;
    if (data.suite) {
      currentImpersonationResult = data.suite;
      renderImpersonationResults(data.suite);
    }
    const panel = document.getElementById("impersonation-captured-panel");
    panel.hidden = false;
    renderCapturedDomains();
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
    showToast(`Captured ${plural(data.total_domains, "matching domain")} (${plural(data.total_apex_domains, "apex domain")})`);
  } catch (err) {
    showToast(`Domain capture failed: ${err.message}`, 6000);
  } finally {
    setBusy(btn, false);
  }
}

function filteredCapturedDomains() {
  const list = currentCapturedDomains?.domains || [];
  const q = (document.getElementById("imp-capture-filter")?.value || "").trim().toLowerCase();
  if (!q) return list;
  return list.filter(d =>
    d.domain.toLowerCase().includes(q) ||
    (d.apex_domain || "").toLowerCase().includes(q) ||
    (d.title || "").toLowerCase().includes(q) ||
    (d.sources || []).join(" ").toLowerCase().includes(q)
  );
}

function renderCapturedDomains() {
  const data = currentCapturedDomains;
  if (!data) return;
  const rows = filteredCapturedDomains();
  document.getElementById("imp-capture-count").innerText = `${data.total_domains}`;
  document.getElementById("imp-capture-meta").innerText =
    `${plural(data.total_domains, "unique domain")} across ${plural(data.total_apex_domains, "apex domain")}` +
    (rows.length !== data.total_domains ? ` (showing ${rows.length} filtered)` : "");

  document.getElementById("imp-capture-sources").innerHTML = (data.source_status || []).map(s => {
    const dot = !s.ran ? "dot-off" : s.error ? "dot-warning" : "dot-success";
    const detail = !s.ran ? s.error : s.error ? `${s.count} (${s.error})` : `${s.count}`;
    return `<span class="source-pill" title="${esc(s.query || s.error || "")}"><span class="dot ${dot}"></span>${esc(s.source)} <em>${esc(detail)}</em></span>`;
  }).join("");

  const tbody = document.getElementById("imp-capture-tbody");
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="6">${emptyState("No matching domains found", "Try broadening keywords, enabling typosquat variants, or adding threat-intel API keys in Settings.")}</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.slice(0, 500).map(d => `
    <tr class="plain">
      <td data-label="Domain"><span class="domain-name">${esc(d.domain)}</span>${d.ip ? `<div class="hint mono">${esc(d.ip)}</div>` : ""}</td>
      <td data-label="Apex" class="mono">${esc(d.apex_domain)}</td>
      <td data-label="Sources"><div class="row" style="gap:4px;">${(d.sources || []).map(s => `<span class="badge badge-sm">${esc(s)}</span>`).join("")}</div></td>
      <td data-label="Title">${esc(d.title || "-")}</td>
      <td data-label="Last seen" class="nowrap">${esc((d.last_seen || "").slice(0, 10) || "-")}</td>
      <td class="col-actions">
        <div class="row" style="justify-content:flex-end;">
          ${copyBtn(d.domain, "Domain copied")}
          ${d.url ? openIcon(d.url, "Open captured reference") : ""}
          <button type="button" class="btn btn-ghost btn-xs" onclick="huntCapturedDomain('${esc(d.apex_domain || d.domain)}')" title="Launch full impersonation hunt on this domain">Hunt</button>
        </div>
      </td>
    </tr>`).join("");
}

function copyCapturedDomains(apexOnly) {
  const rows = filteredCapturedDomains();
  if (!rows.length) return showToast("No domains to copy");
  const list = apexOnly ? [...new Set(rows.map(d => d.apex_domain || d.domain))] : rows.map(d => d.domain);
  copyText(list.join("\n"), `Copied ${plural(list.length, apexOnly ? "apex domain" : "domain")}`);
}

function exportCapturedDomainsCSV() {
  const rows = filteredCapturedDomains();
  if (!rows.length) return showToast("No domains to export");
  const csvRows = ["domain,apex_domain,sources,title,ip,last_seen,url"];
  rows.forEach(d => csvRows.push([d.domain, d.apex_domain, (d.sources || []).join(";"), d.title || "", d.ip || "", d.last_seen || "", d.url || ""].map(csvCell).join(",")));
  downloadBlob("\uFEFF" + csvRows.join("\r\n") + "\r\n", `captured_domains_${new Date().toISOString().slice(0, 10)}.csv`, "text/csv;charset=utf-8;");
  showToast("Captured domains CSV downloaded");
}

function huntCapturedDomain(domain) {
  switchTab("hunt");
  const input = document.getElementById("hunt-target-input");
  if (input) {
    input.value = domain;
    input.focus();
  }
}

async function openImpersonationPlatformTabs(platform) {
  if (!currentImpersonationResult?.items?.length) return showToast("Generate dorks first");
  const urls = currentImpersonationResult.items.map(it => it[platform]?.master_url).filter(Boolean);
  if (!urls.length) return showToast(`No ${PLATFORMS[platform].name} queries`);
  await launchUrlsInNewWindow(urls, `${PLATFORMS[platform].name} tabs`);
}

async function launchKeywordAllPlatforms(kwIndex) {
  const it = currentImpersonationResult?.items?.[kwIndex];
  if (!it) return;
  await launchUrlsInNewWindow(PLATFORM_KEYS.map(p => it[p]?.master_url).filter(Boolean), `searches for ${it.keyword}`);
}

async function launchAllImpersonationTabs() {
  if (!currentImpersonationResult?.master_queries) return showToast("Generate dorks first");
  await launchUrlsInNewWindow(PLATFORM_KEYS.map(p => currentImpersonationResult.master_queries[p]?.url).filter(Boolean), "master queries");
}

function exportImpersonationCSV() {
  if (!currentImpersonationResult?.items?.length) return showToast("Generate dorks first");
  const rows = ["keyword,platform,dork_type,query,search_url"];
  currentImpersonationResult.items.forEach(it => PLATFORM_KEYS.forEach(p => {
    const pd = it[p];
    if (!pd) return;
    Object.keys(pd).filter(k => !k.endsWith("_url")).forEach(t => rows.push([it.keyword, p, t, pd[t], pd[`${t}_url`] || ""].map(csvCell).join(",")));
  }));
  downloadBlob("﻿" + rows.join("\r\n") + "\r\n", `impersonation_dorks_${new Date().toISOString().slice(0, 10)}.csv`, "text/csv;charset=utf-8;");
  showToast("CSV downloaded");
}

// =============================================================================
// IMPERSONATION HUNT
// =============================================================================
const HUNT_STAGES = [
  ["fingerprint", "Fingerprint"], ["generate", "Generate"], ["ct", "CT logs"], ["feeds", "Phishing feeds"], ["intel", "Threat intel"],
  ["dns", "DNS"], ["verify", "Inspect sites"], ["rdap", "Registration"], ["score", "Score"],
];

const VERDICT_META = {
  phishing: { label: "High risk", cls: "badge-danger" },
  suspicious: { label: "Suspicious", cls: "badge-warning" },
  parked: { label: "Parked / for sale", cls: "badge-purple" },
  offline: { label: "Offline", cls: "badge-purple" },
  no_website: { label: "No website", cls: "" },
  unreachable: { label: "Web unreachable", cls: "" },
  live_unrelated: { label: "Live, unrelated", cls: "" },
  redirect_brand: { label: "Redirects to brand", cls: "badge-success" },
  brand_owned: { label: "Brand-owned", cls: "badge-success" },
};

const HUNT_FILTERS = [
  ["risky", "Needs review", c => (c.verdict === "phishing" || c.verdict === "suspicious") && !isClosed(c)],
  ["all", "All", () => true],
  ["new_since", "New since last hunt", c => !!c.is_new],
  ["phishing", "High risk", c => c.verdict === "phishing"],
  ["suspicious", "Suspicious", c => c.verdict === "suspicious"],
  ["case", "In progress", c => ["investigating", "confirmed", "takedown_sent"].includes(triageStatus(c))],
  ["done", "Taken down", c => triageStatus(c) === "taken_down"],
  ["feed", "Phishing feeds", c => (c.intel || []).some(i => i.match === "feed")],
  ["intel", "Threat intel", c => (c.intel || []).length > 0],
  ["new", "Registered < 90 days", c => c.rdap && c.rdap.age_days !== null && c.rdap.age_days !== undefined && c.rdap.age_days <= 90],
  ["ct", "CT logs", c => (c.sources || []).includes("crt.sh")],
  ["parked", "Parked", c => c.verdict === "parked"],
  ["offline", "Offline", c => c.verdict === "offline"],
  ["live_unrelated", "Unrelated", c => c.verdict === "live_unrelated"],
  ["no_website", "No website", c => c.verdict === "no_website" || c.verdict === "unreachable"],
  ["safe", "Brand-owned", c => c.verdict === "redirect_brand" || c.verdict === "brand_owned"],
  ["fp", "False positives", c => isFP(c)],
];

const MATCH_LABELS = { feed: "phishing feed", favicon_hash: "brand favicon", asset_hash: "brand files", analytics: "analytics ID", hosting: "free hosting", lens: "logo match", dork: "search" };
const STRONG_MATCHES = new Set(["feed", "favicon_hash", "asset_hash", "analytics", "hosting"]);

function huntOptions() {
  const split = id => document.getElementById(id).value.split(/[\s,;]+/).map(x => x.trim()).filter(Boolean);
  return {
    target: document.getElementById("hunt-target-input").value.trim(),
    depth: document.querySelector('input[name="hunt-depth"]:checked')?.value || "standard",
    use_ct: document.getElementById("hunt-toggle-ct").checked,
    verify: document.getElementById("hunt-toggle-verify").checked,
    use_rdap: document.getElementById("hunt-toggle-rdap").checked,
    use_intel: document.getElementById("hunt-toggle-intel").checked,
    use_feeds: document.getElementById("hunt-toggle-feeds").checked,
    allowlist: split("hunt-allowlist"),
    keywords: split("hunt-keywords"),
  };
}

async function handleHuntSubmit(e) {
  e.preventDefault();
  const opts = huntOptions();
  if (!opts.target) return;
  const btn = document.getElementById("btn-hunt");
  setBusy(btn, true, "Hunting…");
  try {
    const { job_id } = await apiPost("/api/hunt", opts);
    huntJobId = job_id;
    showOnlySection(null);
    renderHuntProgress({ stage: "fingerprint", progress: 0, message: `Starting hunt for ${opts.target}`, stats: {} });
    document.getElementById("hunt-progress-panel").hidden = false;
    updateHuntEmpty();
    pollHunt();
  } catch (err) {
    showToast(`Could not start the hunt: ${err.message}`, 6000);
    setBusy(btn, false);
  }
}

async function pollHunt() {
  clearTimeout(huntPollTimer);
  if (!huntJobId) return;
  let job;
  try {
    const res = await fetch(`/api/hunt/${huntJobId}`);
    job = await res.json();
    if (!res.ok) throw new Error(job.detail || `HTTP ${res.status}`);
  } catch (err) {
    finishHunt();
    return showToast(`Lost track of the hunt: ${err.message}`, 6000);
  }
  renderHuntProgress(job);
  if (job.status === "running") {
    huntPollTimer = setTimeout(pollHunt, 1000);
    return;
  }
  finishHunt();
  if (job.status === "done") {
    currentHunt = job.result;
    huntFilter = (currentHunt.stats.high_risk || currentHunt.stats.suspicious) ? "risky" : "all";
    huntView = "lookalikes";
    renderHunt(currentHunt);
    showToast(`Hunt complete: ${currentHunt.stats.high_risk || 0} high risk, ${currentHunt.stats.suspicious || 0} suspicious`);
  } else if (job.status === "error") {
    showToast(`Hunt failed: ${job.message}`, 8000);
  } else {
    showToast("Hunt cancelled");
  }
}

function finishHunt() {
  huntJobId = null;
  clearTimeout(huntPollTimer);
  setBusy(document.getElementById("btn-hunt"), false);
  document.getElementById("hunt-progress-panel").hidden = true;
  updateHuntEmpty();
}

async function cancelHunt() {
  if (!huntJobId) return;
  try { await fetch(`/api/hunt/${huntJobId}`, { method: "DELETE" }); } catch (e) { /* ignore */ }
}

function renderHuntProgress(job) {
  const idx = Math.max(0, HUNT_STAGES.findIndex(([k]) => k === job.stage));
  const done = job.stage === "done";
  document.getElementById("hunt-steps").innerHTML = HUNT_STAGES.map(([, label], i) => {
    const state = done || i < idx ? "done" : i === idx ? "active" : "";
    return `<span class="step ${state}"><span class="step-icon">${state === "done" ? I.check : ""}</span>${label}</span>`;
  }).join("");
  document.getElementById("hunt-bar-fill").style.width = `${job.progress || 0}%`;
  document.getElementById("hunt-progress-msg").innerText = job.message || "";
  const st = job.stats || {};
  const parts = [
    ["brand icons", st.brand_icons], ["brand files", st.brand_assets], ["generated", st.generated], ["CT hosts", st.ct_hosts],
    ["intel hits", st.intel_hits], ["DNS checked", st.dns_checked], ["registered", st.registered], ["live", st.live],
    ["inspected", st.verified !== undefined ? `${st.verified}/${st.verify_total}` : undefined],
  ].filter(([, v]) => v !== undefined && v !== null);
  document.getElementById("hunt-live-stats").innerHTML = parts.map(([k, v]) => `<span><b>${esc(v)}</b> ${k}</span>`).join("");
}

function setHuntView(view) {
  huntView = view;
  document.querySelectorAll("#hunt-view-tabs [data-hview]").forEach(t => {
    const on = t.dataset.hview === view;
    t.classList.toggle("active", on);
    t.setAttribute("aria-selected", on);
  });
  document.querySelectorAll("[data-hpanel]").forEach(p => { p.hidden = p.dataset.hpanel !== view; });
}

function renderHunt(data) {
  const st = data.stats || {};
  const bv = st.by_verdict || {};
  document.getElementById("hunt-res-domain").innerText = `Impersonations of ${data.target}`;
  document.getElementById("hunt-res-meta").innerText =
    `${data.depth} depth · ${st.elapsed_sec}s · own domains: ${shortList(data.brand.allowlist, 3)}`;

  const tiles = [
    ["High risk", st.high_risk || 0, "stat-danger"],
    ["Suspicious", st.suspicious || 0, "stat-warning"],
    ...(st.has_previous ? [["New since last hunt", st.new_domains || 0, st.new_risky ? "stat-warning" : ""]] : []),
    ["Registered", st.registered],
    ["Live websites", st.live],
    ["Threat-intel hits", st.intel_hits ?? 0],
    ["Phishing-feed hits", st.feed_hits ?? 0],
    ["From CT logs", st.ct_hosts],
    ["Generated", st.generated],
    ["Parked", bv.parked || 0],
  ];
  updateIocLinks(data);
  document.getElementById("hunt-tiles").innerHTML = tiles.map(([label, val, cls]) =>
    `<div class="stat ${cls || ""}"><div class="stat-label">${label}</div><div class="stat-value">${esc((val ?? 0).toLocaleString())}</div></div>`).join("");

  document.getElementById("hunt-errors").innerHTML = (data.errors || []).slice(0, 4).map(e =>
    `<div class="alert alert-warning">${I.alert}<div>${esc(e)}</div></div>`).join("");

  const intelRan = ((data.intel || {}).status || []).filter(s => s.ran).length;
  document.getElementById("hv-count-lookalikes").innerText = (data.candidates || []).length.toLocaleString();
  document.getElementById("hv-count-intel").innerText = intelRan;

  huntRowLimit = 100;
  document.getElementById("hunt-search").value = "";
  renderHuntFilters();
  renderHuntTable();
  renderHuntIntel(data);
  renderHuntBrand(data);
  renderHuntQueries(data);
  setHuntView(huntView);
  const section = document.getElementById("hunt-results-section");
  showOnlySection("hunt-results-section");
  section.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderHuntFilters() {
  const cands = currentHunt?.candidates || [];
  document.getElementById("hunt-filters").innerHTML = HUNT_FILTERS.map(([key, label, fn]) => {
    const n = cands.filter(fn).filter(c => key === "all" || key === "fp" || !isFP(c)).length;
    if (!n && key !== "risky" && key !== "all") return "";
    return `<button type="button" class="chip${key === huntFilter ? " active" : ""}" aria-pressed="${key === huntFilter}" onclick="setHuntFilter('${key}')">${label} <span class="count">${n.toLocaleString()}</span></button>`;
  }).join("");
}

function setHuntFilter(key) {
  huntFilter = key;
  huntRowLimit = 100;
  renderHuntFilters();
  renderHuntTable();
}

function filteredHuntCandidates() {
  const fn = (HUNT_FILTERS.find(([k]) => k === huntFilter) || HUNT_FILTERS[1])[2];
  const q = (document.getElementById("hunt-search").value || "").trim().toLowerCase();
  const hideFP = huntFilter !== "all" && huntFilter !== "fp";
  return (currentHunt?.candidates || []).filter(fn).filter(c => !(hideFP && isFP(c))).filter(c => {
    if (!q) return true;
    const ev = c.evidence || {};
    return [c.domain, c.unicode, c.fuzzer, ev.title, ...(c.reasons || [])].join(" ").toLowerCase().includes(q);
  });
}

function scoreClass(s) {
  return s >= 70 ? "score-high" : s >= 45 ? "score-med" : s >= 25 ? "score-low" : "score-min";
}

function renderHuntTable() {
  const rows = filteredHuntCandidates();
  const tbody = document.getElementById("hunt-tbody");
  const foot = document.getElementById("hunt-table-foot");
  if (!rows.length) {
    const any = (currentHunt?.candidates || []).length;
    tbody.innerHTML = `<tr><td colspan="8">${emptyState(any ? "Nothing matches this filter" : "No registered lookalikes found",
      any ? "Try “All”, or clear the search box." : "None of the generated or discovered lookalikes exist in DNS.")}</td></tr>`;
    foot.innerHTML = "";
    return;
  }
  tbody.innerHTML = rows.slice(0, huntRowLimit).map(huntRowHtml).join("");
  foot.innerHTML = rows.length > huntRowLimit
    ? `<span>Showing ${huntRowLimit.toLocaleString()} of ${rows.length.toLocaleString()}</span><button type="button" class="btn btn-secondary btn-sm" onclick="huntRowLimit += 200; renderHuntTable()">Show more</button>`
    : `<span>${plural(rows.length, "domain")}</span>`;
}

function intelBadges(c) {
  const seen = new Set();
  const out = (c.intel || []).filter(i => { const k = `${i.source}|${i.match}`; if (seen.has(k)) return false; seen.add(k); return true; })
    .map(i => `<span class="badge badge-sm ${STRONG_MATCHES.has(i.match) ? "badge-danger" : ""}" title="${esc(i.label || "")}">${esc(SOURCE_LABELS[i.source] || i.source)} · ${esc(MATCH_LABELS[i.match] || i.match)}</span>`);
  return out.length ? `<div class="tags">${out.join("")}</div>` : "";
}

const TRIAGE = [["open", "Open"], ["investigating", "Investigating"], ["confirmed", "Confirmed"], ["takedown_sent", "Takedown sent"], ["taken_down", "Taken down"], ["false_positive", "False positive"]];
const TRIAGE_LABEL = Object.fromEntries(TRIAGE);
const huntExpanded = new Set();
const triageStatus = c => (c.triage && c.triage.status) || "open";
const isFP = c => triageStatus(c) === "false_positive";
const isClosed = c => ["false_positive", "taken_down"].includes(triageStatus(c));

function triageOptions(current) {
  return TRIAGE.map(([v, label]) => `<option value="${v}"${v === current ? " selected" : ""}>${label}</option>`).join("");
}

function huntRowHtml(c, i) {
  const ev = c.evidence || {};
  const rd = c.rdap || {};
  const vm = VERDICT_META[c.verdict] || { label: c.verdict, cls: "" };
  const age = rd.age_days !== null && rd.age_days !== undefined ? `${rd.age_days}d` : "-";
  const reasons = (c.reasons || []).slice(0, 3);
  const id = `hunt-detail-${i}`;
  const open = huntExpanded.has(c.domain);
  return `
    <tr class="clickable${open ? " expanded" : ""}${isClosed(c) ? " closed" : ""}" tabindex="0" aria-expanded="${open}" aria-controls="${id}" data-detail="${id}" data-domain="${esc(c.domain)}" onclick="toggleHuntDetail(this)" onkeydown="if(event.target===this&&(event.key==='Enter'||event.key===' ')){event.preventDefault();toggleHuntDetail(this)}">
      <td class="c-score"><span class="score ${scoreClass(c.score)}">${c.score}</span></td>
      <td class="c-domain domain-cell">
        <div class="domain-name">${esc(c.domain)}</div>
        ${c.unicode ? `<div class="domain-uni" title="How it renders in a browser">${esc(c.unicode)}</div>` : ""}
        ${intelBadges(c)}
      </td>
      <td class="c-verdict">
        <span class="badge ${vm.cls}">${vm.label}</span>${c.is_new ? `<span class="badge badge-accent" title="Not in the previous hunt of this brand">New</span>` : ""}
        <select class="select select-sm triage-select" data-domain="${esc(c.domain)}" aria-label="Case status for ${esc(c.domain)}" onclick="event.stopPropagation()" onchange="onTriageChange(this)">${triageOptions(triageStatus(c))}</select>
      </td>
      <td class="c-why" data-label="Evidence">${reasons.length ? `<ul class="reason-list">${reasons.map(r => `<li>${esc(r)}</li>`).join("")}</ul>` : `<span class="muted">No signals</span>`}</td>
      <td class="c-type"><span class="type-tag">${esc(c.fuzzer)}</span></td>
      <td class="c-age num muted">${age}</td>
      <td class="c-icon">${ev.preview ? `<img class="thumb" src="${esc(ev.preview)}" alt="" loading="lazy">` : ""}</td>
      <td class="c-actions col-actions" onclick="event.stopPropagation()">
        <div class="row" style="gap: 2px; flex-wrap: nowrap; justify-content: flex-end;">
          ${copyBtn(c.defanged || c.domain, "Defanged domain copied")}
          ${linkBtn(`https://urlscan.io/search/#${encodeURIComponent("page.domain:" + c.domain)}`, "URLScan", "Search URLScan for this domain", "btn btn-ghost btn-xs")}
          ${linkBtn(`https://www.virustotal.com/gui/domain/${encodeURIComponent(c.domain)}`, "VT", "Open the VirusTotal report", "btn btn-ghost btn-xs")}
        </div>
      </td>
    </tr>
    <tr class="detail" id="${id}"${open ? "" : " hidden"}><td colspan="8">${huntDetailHtml(c)}</td></tr>`;
}

function toggleHuntDetail(row) {
  const detail = document.getElementById(row.dataset.detail);
  if (!detail) return;
  const open = detail.hidden;
  detail.hidden = !open;
  row.classList.toggle("expanded", open);
  row.setAttribute("aria-expanded", open);
  if (open) huntExpanded.add(row.dataset.domain); else huntExpanded.delete(row.dataset.domain);
}

function kvRows(pairs) {
  const rows = pairs.filter(([, v]) => !(v === null || v === undefined || v === "" || (Array.isArray(v) && !v.length)));
  if (!rows.length) return `<span class="muted">Nothing recorded</span>`;
  return `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(Array.isArray(v) ? v.join(", ") : v)}</dd>`).join("")}</dl>`;
}

function huntDetailHtml(c) {
  const ev = c.evidence || {};
  const http = ev.http || {};
  const rd = c.rdap || {};
  const ct = c.ct || {};
  const fav = ev.favicon || {};
  const dns = c.dns || {};
  const defangUrl = u => (u || "").replace(/^http/, "hxxp").replace(/\./g, "[.]");
  return `
    <div class="detail-grid">
      <div>
        <h4>Why this score</h4>
        <ul class="check-list">${(c.reasons || []).map(r => `<li>${I.dot}<span>${esc(r)}</span></li>`).join("") || `<li class="muted">No signals</li>`}</ul>
      </div>
      <div>
        <h4>Website</h4>
        ${c.evidence ? kvRows([["Final URL", defangUrl(http.final_url)], ["HTTP status", http.status], ["Title", ev.title], ["Server", http.server],
  ["Password form", ev.password_form ? "yes" : ""], ["Brand resources", ev.brand_resources || ""], ["Shared analytics", ev.shared_analytics],
  ["Favicon MMH3", fav.mmh3], ["pHash distance", ev.visual_distance], ["TLS cert org", (ev.cert || {}).subject_org], ["TLS issuer", (ev.cert || {}).issuer_org],
  ["Status", http.status ? "" : "No HTTP response"]]) : `<span class="muted">Not inspected</span>`}
      </div>
      <div>
        <h4>DNS &amp; registration</h4>
        ${kvRows([["A", dns.a], ["AAAA", dns.aaaa], ["MX", dns.mx], ["NS", dns.ns], ["Created", (rd.created || "").slice(0, 10)], ["First seen here", c.first_seen ? new Date(c.first_seen * 1000).toISOString().slice(0, 10) : ""], ["Registrar", rd.registrar],
  ["Abuse contact", rd.abuse_email], ["CT first seen", ct.first_seen], ["CT issuer", ct.issuer], ["CT hostnames", (ct.hosts || []).slice(0, 8)]])}
      </div>
      ${(c.intel || []).length ? `<div>
        <h4>Threat intel</h4>
        <dl class="kv">${uniqueIntel(c.intel).map(i => `<dt>${esc(SOURCE_LABELS[i.source] || i.source)}</dt><dd>${esc(MATCH_LABELS[i.match] || i.match)}${i.title ? " · " + esc(i.title.slice(0, 60)) : ""}${i.time ? " · " + esc(i.time.slice(0, 10)) : ""}</dd>`).join("")}</dl>
      </div>` : ""}
      ${caseBlockHtml(c)}
    </div>`;
}

function uniqueIntel(list) {
  const seen = new Set();
  return (list || []).filter(i => {
    const k = `${i.source}|${i.match}|${i.title || ""}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function renderHuntIntel(data) {
  const infra = data.infrastructure || [];
  document.getElementById("hunt-infra-panel").hidden = !infra.length;
  document.getElementById("hunt-infra-tbody").innerHTML = infra.slice(0, 300).map(i => {
    const by = [...new Set((i.matches || []).map(m => `${SOURCE_LABELS[m.source] || m.source} · ${MATCH_LABELS[m.match] || m.match}`))];
    const hp = `${i.ip}${i.port ? ":" + i.port : ""}`;
    return `<tr class="plain">
      <td data-label="IP:port"><span class="domain-name">${esc(hp)}</span></td>
      <td data-label="Title">${esc((i.title || "").slice(0, 80)) || `<span class="muted">-</span>`}</td>
      <td data-label="Network">${esc([i.org, i.country].filter(Boolean).join(" · ")) || `<span class="muted">-</span>`}</td>
      <td data-label="Matched by"><div class="tags" style="margin: 0;">${by.map(b => `<span class="badge badge-sm badge-danger">${esc(b)}</span>`).join("")}</div></td>
      <td class="col-actions"><div class="row" style="gap: 2px; flex-wrap: nowrap; justify-content: flex-end;">${copyBtn(hp, "Copied")}
        ${linkBtn(`https://www.shodan.io/host/${encodeURIComponent(i.ip)}`, "Shodan", "Shodan host page", "btn btn-ghost btn-xs")}
        ${linkBtn(`https://www.virustotal.com/gui/ip-address/${encodeURIComponent(i.ip)}`, "VT", "VirusTotal IP report", "btn btn-ghost btn-xs")}</div></td>
    </tr>`;
  }).join("");

  const status = ((data.intel || {}).status || []).slice().sort((a, b) => (b.ran - a.ran) || (b.count - a.count));
  const urlFor = s => s.source === "serpapi" ? `https://lens.google.com/uploadbyurl?url=${encodeURIComponent(s.query)}` : platformUrl(s.source, s.query);
  document.getElementById("hunt-intel-tbody").innerHTML = status.length ? status.map(s => `<tr class="plain">
      <td data-label="Source">${pfLabel(s.source)}</td>
      <td data-label="Looking for">${esc(s.label)}</td>
      <td data-label="Hits" class="num">${s.ran ? esc(s.count) : `<span class="muted">-</span>`}</td>
      <td data-label="Status">${s.error
      ? `<span class="badge badge-sm ${s.ran ? "badge-warning" : ""}">${esc(s.error)}</span>`
      : `<span class="badge badge-sm badge-success">OK</span>`}</td>
      <td class="col-actions"><div class="row" style="gap: 2px; flex-wrap: nowrap; justify-content: flex-end;">${s.source !== "serpapi" ? copyBtn(s.query, "Query copied") : ""}${openIcon(urlFor(s), "Run this search")}</div></td>
    </tr>`).join("") : `<tr><td colspan="5">${emptyState("Threat-intel platforms were off for this hunt")}</td></tr>`;
}

function renderHuntBrand(data) {
  const b = data.brand || {};
  const icons = b.icons || [];
  const facts = [
    ["Resolved URL", b.resolved_url], ["Title", b.title], ["Name tokens", (b.tokens || []).join(", ")],
    ["Own domains", shortList(b.allowlist, 20)], ["Analytics IDs", (b.analytics_ids || []).join(", ")],
    ["TLS organisation", b.cert_org],
    ["Brand JS/CSS", ((data.pivots || {}).assets || []).map(a => a.url.split("/").pop().split("?")[0]).join(", ")],
  ];
  document.getElementById("hunt-brand").innerHTML = `
    <div class="fingerprint">
      <div><h3 class="group-title">Profile</h3>${kvRows(facts)}</div>
      <div><h3 class="group-title">Icons &amp; logos (${icons.length})</h3>
        ${icons.length ? `<div class="fingerprint-icons">${icons.map(i => `
          <div class="asset-card" style="padding: 12px; gap: 10px;">
            <div class="asset-head" style="gap: 10px;">
              <div class="asset-preview"><img src="${esc(i.preview || PLACEHOLDER_IMG)}" alt=""></div>
              <div style="min-width: 0;">
                <div class="row" style="gap: 4px;"><span class="badge badge-sm ${i.kind === "logo" ? "badge-purple" : ""}">${esc(i.kind)}</span>${i.is_primary ? `<span class="badge badge-sm badge-success">primary</span>` : ""}
                  <span class="badge badge-sm badge-mono">${esc(i.format || "?")}${i.dimensions ? " " + esc(i.dimensions) : ""}</span></div>
              </div>
            </div>
            ${hashTable([["MMH3", i.mmh3], ["SHA-256", i.sha256, i.sha256 ? i.sha256.slice(0, 16) + "…" : null], ["pHash", i.phash]])}
            ${String(i.url || "").startsWith("http") ? `<div class="link-row">${reverseImageLinks(i.final_url || i.url)}</div>` : ""}
          </div>`).join("")}</div>` : `<div class="alert alert-info">${I.alert}<div>No favicon or logo could be downloaded from the brand site, so visual matching was skipped.</div></div>`}
      </div>
    </div>`;
}

function renderHuntQueries(data) {
  const combined = (data.queries || {}).combined || {};
  document.getElementById("hunt-hash-grid").innerHTML = PLATFORM_KEYS.map(p => {
    const rows = queryRow("", combined[p], platformUrl(p, combined[p]))
      + (p === "censys" && combined.censys_sha256 ? queryRow(`<span class="muted">SHA-256</span>`, combined.censys_sha256, platformUrl("censys", combined.censys_sha256)) : "");
    return platformCard(p, rows || `<span class="hint">No favicon hashes</span>`);
  }).join("");

  const pq = data.pivot_queries || [];
  document.getElementById("hunt-pivot-panel").hidden = !pq.length;
  document.getElementById("hunt-pivot-list").innerHTML = pq.map(q => queryRow(`${pfLabel(q.platform)} <span class="muted">${esc(q.label)}</span>`, q.query, q.url)).join("");

  const groups = {};
  (data.search_dorks || []).forEach(d => (groups[d.group] = groups[d.group] || []).push(d));
  document.getElementById("hunt-search-dorks").innerHTML = Object.entries(groups).map(([g, list]) => `
    <h3 class="group-title">${esc(g)}</h3>
    <div class="query-list">${list.map(d => `
      <div class="query-row">
        <code title="${esc(d.query)}">${esc(d.query)}</code>
        <div class="q-actions">${copyBtn(d.query, "Dork copied")}
          ${Object.entries(d.links).map(([e, href]) => linkBtn(href, e === "duckduckgo" ? "DDG" : e[0].toUpperCase() + e.slice(1), `Search on ${e}`, "btn btn-ghost btn-xs")).join("")}
        </div>
      </div>`).join("")}</div>`).join("");

  const labels = {
    all_domains: "All domains", exhaustive: "Deep capture", scam_lures: "Scam lures",
    free_hosting: "Free hosting", idn_homoglyph: "IDN (xn--)", master: "Master",
    title_spoof: "Title", domain_wildcard: "Hostname", domain_contains: "Host contains",
    url_prefix: "URL token", ssl_all: "SSL (CN+SAN)", cert_wildcard: "Certificate", body_content: "Page content",
  };
  document.getElementById("hunt-dork-grid").innerHTML = PLATFORM_KEYS.map(p => {
    const d = (data.dorks || {})[p] || {};
    const rows = Object.keys(labels).filter(k => d[k]).map(k => queryRow(`<span class="muted">${labels[k]}</span>`, d[k], d[`${k}_url`])).join("");
    return platformCard(p, rows || `<span class="hint">None</span>`);
  }).join("");
}

const HUNT_CSV_COLUMNS = [
  ["score", c => c.score], ["verdict", c => c.verdict_label || c.verdict], ["domain", c => c.domain],
  ["unicode", c => c.unicode], ["defanged", c => c.defanged], ["type", c => c.fuzzer],
  ["sources", c => (c.sources || []).join(";")], ["a", c => (c.dns?.a || []).join(";")],
  ["mx", c => (c.dns?.mx || []).join(";")], ["ns", c => (c.dns?.ns || []).join(";")],
  ["created", c => (c.rdap?.created || "").slice(0, 10)], ["age_days", c => c.rdap?.age_days ?? ""],
  ["registrar", c => c.rdap?.registrar || ""], ["abuse_email", c => c.rdap?.abuse_email || ""],
  ["http_status", c => c.evidence?.http?.status ?? ""], ["final_url", c => c.evidence?.http?.final_url || ""],
  ["title", c => c.evidence?.title || ""], ["favicon_exact", c => c.evidence?.favicon?.exact_match ? "yes" : ""],
  ["phash_distance", c => c.evidence?.visual_distance ?? ""], ["password_form", c => c.evidence?.password_form ? "yes" : ""],
  ["shared_analytics", c => (c.evidence?.shared_analytics || []).join(";")],
  ["ct_first_seen", c => c.ct?.first_seen || ""],
  ["intel", c => [...new Set((c.intel || []).map(i => `${i.source}:${i.match}`))].join(";")],
  ["case_status", c => triageStatus(c)], ["case_note", c => (c.triage && c.triage.note) || ""],
  ["new_since_last_hunt", c => c.is_new ? "yes" : ""],
  ["reasons", c => (c.reasons || []).join(" | ")],
];

function exportHuntCSV() {
  if (!currentHunt) return;
  const rows = filteredHuntCandidates();
  const lines = [HUNT_CSV_COLUMNS.map(([h]) => csvCell(h)).join(",")].concat(rows.map(c => HUNT_CSV_COLUMNS.map(([, fn]) => csvCell(fn(c))).join(",")));
  downloadBlob("﻿" + lines.join("\r\n"), `hunt_${currentHunt.target}_${huntFilter}.csv`, "text/csv;charset=utf-8");
  showToast(`CSV downloaded (${plural(rows.length, "row")})`);
}

function exportHuntJSON() {
  if (!currentHunt) return;
  const data = JSON.parse(JSON.stringify(currentHunt));
  (data.brand?.icons || []).forEach(i => delete i.preview);
  (data.candidates || []).forEach(c => { if (c.evidence) delete c.evidence.preview; });
  downloadBlob(JSON.stringify(data, null, 2), `hunt_${currentHunt.target}.json`, "application/json");
  showToast("JSON downloaded");
}

// ----------------------------------------------------------------------------- sources
async function loadSources() {
  let sources = [];
  try { sources = (await (await fetch("/api/sources")).json()).sources || []; } catch (e) { /* offline */ }
  const dotCls = s => s.mode === "key" ? "dot-success" : s.mode === "anonymous" ? "dot-warning" : "dot-off";
  const stateText = s => s.mode === "key" ? (s.key_count > 1 ? `${s.key_count} keys` : "API key") : s.mode === "anonymous" ? "no key" : "off";
  document.getElementById("sidebar-sources").innerHTML = sources.length
    ? sources.map(s => `<button type="button" class="src-row" onclick="switchTab('keys')" title="${esc(s.does)}. Click to manage API keys"><span class="dot ${dotCls(s)}"></span><span>${esc(s.name)}</span><span>${stateText(s)}</span></button>`).join("")
    + `<div class="src-row" title="Always on"><span class="dot dot-success"></span><span>crt.sh, DNS, RDAP</span><span>free</span></div>`
    + `<div class="src-row" title="Matched against the brand on every hunt"><span class="dot dot-success"></span><span>OpenPhish, Phishing.DB</span><span>free</span></div>`
    : `<span class="muted">Unavailable</span>`;
  document.getElementById("hunt-sources").innerHTML = sources.length
    ? `<span class="option-label">Sources</span>` + sources.map(s => `<button type="button" class="source-pill" onclick="switchTab('keys')" title="${esc(s.does)}. Click to manage API keys"><span class="dot ${dotCls(s)}"></span>${esc(s.name)} <em>${s.mode === "off" ? "add key" : stateText(s)}</em></button>`).join("")
    : "";
  loadStorageBadge();
  const missing = sources.filter(s => s.mode === "off").length;
  const badge = document.getElementById("keys-nav-badge");
  badge.hidden = !missing;
  badge.innerText = `${missing} off`;
}


// =============================================================================
// CASE MANAGEMENT: triage, takedown pack, history, watchlist, alerts
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
    renderHuntFilters();
    renderHuntTable();
    showToast(status === "false_positive" ? `${domain} marked as a false positive and hidden from review` : `${domain}: ${TRIAGE_LABEL[status]}`);
  } catch (err) {
    showToast(`Could not save: ${err.message}`, 6000);
    renderHuntTable();
  }
}

function onTriageChange(select) {
  setTriage(select.dataset.domain, select.value);
}

function saveCaseNote(btn) {
  const domain = btn.dataset.domain;
  const input = [...document.querySelectorAll("input[data-note-for]")].find(i => i.dataset.noteFor === domain);
  const c = findCandidate(domain);
  if (input && c) setTriage(domain, triageStatus(c), input.value);
}

// ----------------------------------------------------------------------------- takedown pack
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

// ----------------------------------------------------------------------------- history
let historyData = [];

async function loadHistory() {
  try {
    historyData = (await settingsCall("GET", "/api/hunts")).hunts || [];
  } catch (err) {
    showToast(`Could not load history: ${err.message}`, 6000);
    historyData = [];
  }
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

// ----------------------------------------------------------------------------- watchlist & alerts
let watchData = null;
const LEVEL_BADGE = { high: "badge-danger", medium: "badge-warning", error: "badge-danger", info: "" };

function updateAlertBadge(n) {
  const b = document.getElementById("watch-nav-badge");
  b.hidden = !n;
  b.innerText = n > 99 ? "99+" : String(n || "");
}

async function refreshAlertBadge() {
  try { updateAlertBadge((await settingsCall("GET", "/api/alerts")).unread); } catch (e) { /* offline */ }
}

async function loadWatch() {
  try {
    watchData = await settingsCall("GET", "/api/watchlist");
  } catch (err) {
    showToast(`Could not load the watchlist: ${err.message}`, 6000);
    return;
  }
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
  try {
    watchData = await settingsCall("PATCH", `/api/watchlist/${id}`, body);
    renderWatch();
  } catch (err) {
    showToast(err.message, 6000);
    loadWatch();
  }
}

async function runWatch(id) {
  try {
    await settingsCall("POST", `/api/watchlist/${id}/run`);
    showToast("Hunt started. Open History when it finishes.");
    setTimeout(loadWatch, 1500);
  } catch (err) {
    showToast(err.message, 6000);
  }
}

async function testWebhook(id) {
  try {
    const r = await settingsCall("POST", `/api/watchlist/${id}/test-webhook`);
    showToast(r.ok ? `Test alert ${r.message}` : `Test failed: ${r.message}`, r.ok ? 3000 : 7000);
  } catch (err) {
    showToast(err.message, 6000);
  }
}

async function removeWatch(id, brand) {
  if (!window.confirm(`Stop monitoring ${brand}? Past hunts stay in History.`)) return;
  try {
    watchData = await settingsCall("DELETE", `/api/watchlist/${id}`);
    renderWatch();
  } catch (err) {
    showToast(err.message, 6000);
  }
}

async function markAlertsRead() {
  try {
    await settingsCall("POST", "/api/alerts/read", {});
    await loadWatch();
  } catch (err) {
    showToast(err.message, 6000);
  }
}

function updateIocLinks(data) {
  const base = data.hunt_id ? `/api/hunts/${encodeURIComponent(data.hunt_id)}/ioc` : null;
  [["hunt-ioc-txt", "txt"], ["hunt-ioc-stix", "stix"]].forEach(([id, fmt]) => {
    const a = document.getElementById(id);
    a.hidden = !base;
    if (base) a.href = `${base}?format=${fmt}&min_score=45`;
  });
}

refreshAlertBadge();
setInterval(refreshAlertBadge, 60000);


// =============================================================================
// STORAGE (SQLite / MongoDB)
// =============================================================================
let storageData = null;
const I_DB = svg('<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/>', 16);

function setStorageResult(ok, message) {
  document.getElementById("storage-test-result").innerHTML = message
    ? `<div class="alert ${ok ? "alert-success" : "alert-danger"}">${ok ? I.check.replace('width="12" height="12"', 'width="16" height="16"') : I.alert}<div>${esc(message)}</div></div>` : "";
}

async function loadStorage() {
  const errBox = document.getElementById("storage-error");
  try {
    storageData = await settingsCall("GET", "/api/storage");
    errBox.innerHTML = "";
    renderStorage();
  } catch (err) {
    errBox.innerHTML = `<div class="alert alert-danger">${I.alert}<div>${esc(err.message)}</div></div>`;
  }
}

function countsHtml(c, withCandidates = false) {
  const items = [["Hunts", c.hunts], ...(withCandidates ? [["Lookalike documents", c.candidates]] : []), ["Case notes", c.triage], ["Watched brands", c.watchlist], ["Alerts", c.alerts]];
  return items.filter(([, v]) => v !== undefined && v !== null).map(([k, v]) => `<div class="stat"><div class="stat-label">${k}</div><div class="stat-value" style="font-size: 20px;">${esc(Number(v).toLocaleString())}</div></div>`).join("");
}

function renderStorage() {
  const st = storageData;
  const mongoConfigured = st.configured === "mongodb";
  let badge;
  if (st.connected) badge = `<span class="badge badge-success">${st.active === "mongodb" ? "MongoDB" : "SQLite"} · connected</span>`;
  else badge = `<span class="badge badge-danger">MongoDB unreachable</span>`;

  let where;
  if (st.connected && st.active === "mongodb") {
    where = kvRows([["Hosts", (st.uri.hosts || []).join(", ")], ["Database", st.uri.database], ["Credentials", st.uri.has_credentials ? "in connection string (hidden)" : "none"],
    ["Connection", st.uri.srv ? "mongodb+srv (Atlas / DNS seed list)" : "mongodb://"], ["Driver", st.driver]]);
  } else if (st.connected) {
    where = kvRows([["File", st.sqlite.path], ["Driver", "sqlite3 (built in)"]]);
  } else {
    where = `<div class="alert alert-danger">${I.alert}<div><strong>${esc(st.error || "Cannot connect")}</strong><div class="hint" style="margin-top: 4px;">Hunts still run but are not saved, and History, Watchlist and triage are unavailable until the connection works again. Fix the connection string below, or switch back to local SQLite.</div></div></div>`;
  }
  document.getElementById("storage-active").innerHTML = `
    <div class="stack" style="gap: 16px;">
      <div class="row">${badge}<span class="hint">${mongoConfigured ? "Selected by MONGODB_URI" : "Default: no MongoDB connection string is set"}</span></div>
      ${where}
      ${st.connected && st.stats ? `<div class="stats">${countsHtml(st.stats, st.active === "mongodb")}</div>` : ""}
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

  const mig = document.getElementById("storage-migrate-card");
  mig.hidden = !(st.connected && st.active === "mongodb");
  if (!mig.hidden) {
    const lc = st.sqlite || {};
    document.getElementById("storage-migrate-info").innerText = lc.exists
      ? `Local SQLite file: ${lc.hunts ?? 0} hunts, ${lc.triage ?? 0} case notes, ${lc.watchlist ?? 0} watched brands, ${lc.alerts ?? 0} alerts.`
      : "There is no local SQLite history.";
    document.getElementById("btn-migrate-up").disabled = !lc.exists;
  }
}

async function testStorage(btn) {
  setBusy(btn, true, "Testing…");
  setStorageResult(true, "");
  try {
    const r = await settingsCall("POST", "/api/storage/test", { uri: document.getElementById("mongo-uri").value.trim(), db: document.getElementById("mongo-db").value.trim() });
    setStorageResult(r.ok, r.message);
  } catch (err) {
    setStorageResult(false, err.message);
  } finally {
    setBusy(btn, false);
  }
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
  } catch (err) {
    setStorageResult(false, `Not saved. ${err.message}`);
  } finally {
    setBusy(btn, false);
  }
}

async function clearStorage() {
  if (!window.confirm("Switch back to the local SQLite file? Nothing is deleted from MongoDB, but its data will no longer be shown here.")) return;
  try {
    storageData = await settingsCall("DELETE", "/api/storage");
    setStorageResult(true, "Storage is now the local SQLite file.");
    renderStorage();
    currentHunt = null;
    historyData = [];
    loadSources();
  } catch (err) {
    setStorageResult(false, err.message);
  }
}

async function migrateStorage(direction, btn) {
  const up = direction === "to_mongodb";
  if (!window.confirm(up ? "Copy the local SQLite history, case notes, watchlist and alerts into MongoDB? Existing MongoDB records with the same ids are updated; nothing is deleted."
    : "Copy everything from MongoDB into the local SQLite file? Existing local records with the same ids are updated; nothing is deleted.")) return;
  setBusy(btn, true, "Copying…");
  const out = document.getElementById("storage-migrate-result");
  out.innerHTML = "";
  try {
    const r = await settingsCall("POST", "/api/storage/migrate", { direction });
    const c = r.copied;
    out.innerHTML = `<div class="alert alert-success">${I.check.replace('width="12" height="12"', 'width="16" height="16"')}<div>Copied ${plural(c.hunts, "hunt")}, ${plural(c.triage, "case note")}, ${plural(c.watchlist, "watched brand")}${c.watchlist_skipped ? ` (${c.watchlist_skipped} already present)` : ""}, ${c.alerts_skipped ? "alerts skipped (the destination already has alerts)" : plural(c.alerts, "alert")}.</div></div>`;
    storageData = r.status;
    renderStorage();
  } catch (err) {
    out.innerHTML = `<div class="alert alert-danger">${I.alert}<div>${esc(err.message)}</div></div>`;
  } finally {
    setBusy(btn, false);
  }
}

async function loadStorageBadge() {
  const el = document.getElementById("sidebar-storage");
  if (!el) return;
  try {
    const st = await settingsCall("GET", "/api/storage");
    const label = st.connected ? (st.active === "mongodb" ? "MongoDB" : "SQLite") : "offline";
    el.innerHTML = `<button type="button" class="src-row" onclick="switchTab('storage')" title="Where hunts and case notes are saved. Click to change"><span class="dot ${st.connected ? "dot-success" : "dot-danger"}"></span><span>Storage</span><span>${label}</span></button>`;
  } catch (e) {
    el.innerHTML = ""; // not allowed from this address, or the server is down
  }
}

// ----------------------------------------------------------------------------- init
document.addEventListener("keydown", e => {
  if (e.key === "Escape") toggleNav(false);
});
applyTheme(currentTheme());
switchTab("hunt");
loadSources();


// =============================================================================
// API KEYS (multiple keys per source, rotated on rate limit / quota)
// =============================================================================
let keysData = null;
let keysRefreshTimer = null;
const keyResults = {};  // last test / error message per source (survives re-renders)
const EYE = svg('<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>', 15);
const EYE_OFF = svg('<path d="M9.9 4.2A10 10 0 0 1 12 4c6.5 0 10 8 10 8a17 17 0 0 1-3.2 4.2M6.6 6.6A17 17 0 0 0 2 12s3.5 8 10 8a9.7 9.7 0 0 0 5.4-1.6M14.1 14.1a3 3 0 1 1-4.2-4.2M2 2l20 20"/>', 15);
const I_TRASH = svg('<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>', 15);
const I_UP = svg('<path d="m18 15-6-6-6 6"/>', 15);
const I_PULSE = svg('<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>', 15);

async function settingsCall(method, path, body) {
  const res = await fetch(path, { method, headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
  return data;
}

async function loadKeys({ silent = false } = {}) {
  const errBox = document.getElementById("keys-error");
  try {
    keysData = await settingsCall("GET", "/api/settings/keys");
    errBox.innerHTML = "";
    renderKeys();
  } catch (err) {
    if (silent) return;
    document.getElementById("keys-list").innerHTML = "";
    errBox.innerHTML = `<div class="alert alert-danger">${I.alert}<div>${esc(err.message)}</div></div>`;
  }
  clearTimeout(keysRefreshTimer);
  // Keep cooldown timers fresh while the page is open
  if (currentTab === "keys") keysRefreshTimer = setTimeout(() => loadKeys({ silent: true }), 15000);
}

function capitalize(t) {
  return t ? t[0].toUpperCase() + t.slice(1) : t;
}

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
          <span class="key-pos" title="Rotation order">#${k.position}</span>
          <code class="key-hint">${esc(k.hint)}</code>
          ${keyStateBadge(k)}
          <span class="key-uses muted num" title="Successful calls since the server started">${k.uses ? plural(k.uses, "call") : ""}</span>
          <span class="key-actions">
            <button type="button" class="icon-btn" title="Test this key" aria-label="Test key ${k.position}" onclick="testSavedKey(this, '${esc(src.id)}', '${esc(k.id)}')">${I_PULSE}</button>
            ${f.editable && k.position > 1 ? `<button type="button" class="icon-btn" title="Make primary (try first)" aria-label="Move key ${k.position} to the top" onclick="keyAction('primary', '${esc(f.name)}', '${esc(k.id)}')">${I_UP}</button>` : ""}
            ${f.editable ? `<button type="button" class="icon-btn danger" title="Remove this key" aria-label="Remove key ${k.position}" onclick="removeKey('${esc(src.id)}', '${esc(f.name)}', '${esc(k.id)}', ${k.position})">${I_TRASH}</button>` : ""}
          </span>
        </div>`).join("")}
    </div>
    ${f.keys.length > 1 || paused ? `<div class="row" style="gap: 6px;">
      ${f.keys.length > 1 ? `<button type="button" class="btn btn-ghost btn-xs" onclick="testAllKeys(this, '${esc(src.id)}')">Test all</button>` : ""}
      ${paused ? `<button type="button" class="btn btn-ghost btn-xs" onclick="resetKeys('${esc(src.id)}')" title="Clear cooldowns so paused keys are tried again">Reset paused keys</button>` : ""}
    </div>` : ""}`;
}

function renderKeys() {
  const { fields, sources } = keysData;
  const list = document.getElementById("keys-list");
  // Status refreshes re-render the cards: keep whatever the user is typing, and the focus.
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
            <h2 class="row" style="gap: 10px;"><span class="pf pf-${esc(src.id)}">${esc(src.name)}</span><span class="badge badge-sm ${cls}">${esc(label)}</span></h2>
            <p>${esc(src.does)}.${src.key_required ? "" : " Works anonymously; a key raises the limits."}</p>
          </div>
          <div class="actions">${src.link ? linkBtn(src.link, "Get a key", `Open ${src.name} to create or copy a key`, "btn btn-ghost btn-sm") : ""}</div>
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
                  <button type="button" class="icon-btn" aria-label="Show or hide the value" title="Show / hide" onclick="toggleSecret(this)">${EYE}</button>
                </div>
                <button type="submit" class="btn btn-primary btn-sm">Add key</button>
                <button type="button" class="btn btn-secondary btn-sm" onclick="testTypedKey(this, '${esc(src.id)}')" title="Check the key before adding it">Test${src.id === "censys" ? " (1 query)" : ""}</button>
              </form>`) : `<span class="hint">Set in the system environment. Change it there.</span>`}
            <span class="hint mono">${esc(main.name)}</span>
          </div>
          ${extras.map(f => `
            <form class="field" onsubmit="saveExtra(event, '${esc(src.id)}', '${esc(f.name)}')" autocomplete="off">
              <span>${esc(f.label)} <span class="muted" style="font-weight: 400;">(optional, applies to all keys)</span></span>
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
    if (input && !input.disabled) {
      input.value = t.value;
      input.type = t.type;
    }
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

function sourceName(source) {
  return keysData?.sources.find(s => s.id === source)?.name || source;
}

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
    // Check the new key straight away (it is last in the list)
    const f = keysData.fields.find(x => x.name === name);
    const last = f.keys[f.keys.length - 1];
    if (last) testSavedKey(null, source, last.id);
  } catch (err) {
    setBusy(btn, false);
    setKeyResult(source, false, err.message);
  }
}

async function keyAction(action, name, id) {
  const source = keysData.fields.find(f => f.name === name)?.source;
  try {
    const payload = await settingsCall("POST", `/api/settings/keys/${action}`, { name, id });
    await refreshAfter(payload, source, action === "primary" ? "Key moved to the top of the rotation" : "");
  } catch (err) {
    setKeyResult(source, false, err.message);
  }
}

async function removeKey(source, name, id, position) {
  const f = keysData.fields.find(x => x.name === name);
  const last = f.keys.length === 1;
  if (!window.confirm(`Remove key #${position} from ${sourceName(source)}?${last ? ` ${sourceName(source)} will stop being used until you add a key again.` : ""}`)) return;
  try {
    const payload = await settingsCall("POST", "/api/settings/keys/remove", { name, id });
    await refreshAfter(payload, source, "Key removed");
  } catch (err) {
    setKeyResult(source, false, err.message);
  }
}

async function resetKeys(source) {
  try {
    const payload = await settingsCall("POST", "/api/settings/keys/reset", { source });
    delete keyResults[source];
    await refreshAfter(payload, source, `${sourceName(source)} keys will be tried again`);
  } catch (err) {
    setKeyResult(source, false, err.message);
  }
}

async function testSavedKey(btn, source, id) {
  if (btn) btn.disabled = true;
  try {
    const r = await settingsCall("POST", "/api/settings/keys/test", { source, key_id: id });
    const f = keysData.fields.find(x => x.source === source && x.multi);
    const pos = f?.keys.find(k => k.id === id)?.position;
    setKeyResult(source, r.ok, `Key #${pos ?? "?"}: ${r.message}`);
    await loadKeys({ silent: true });
  } catch (err) {
    setKeyResult(source, false, err.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function testAllKeys(btn, source) {
  setBusy(btn, true, "Testing…");
  try {
    const r = await settingsCall("POST", "/api/settings/keys/test", { source, all: true });
    const f = keysData.fields.find(x => x.source === source && x.multi);
    const details = (r.results || []).map(x => ({ position: f?.keys.find(k => k.id === x.id)?.position ?? "?", message: `${x.ok ? "OK" : "Failed"}: ${x.message}` }));
    setKeyResult(source, r.ok, r.message, details);
    await loadKeys({ silent: true });
  } catch (err) {
    setKeyResult(source, false, err.message);
  } finally {
    setBusy(btn, false);
  }
}

async function testTypedKey(btn, source) {
  const card = document.querySelector(`.key-card[data-source="${source}"]`);
  const values = {};
  card.querySelectorAll("input[name]").forEach(i => { if (!i.disabled && i.value.trim()) values[i.name] = i.value.trim(); });
  const main = keysData.fields.find(x => x.source === source && x.multi);
  if (!values[main.name] && source !== "urlscan") return showToast("Paste a key to test, or use the test button next to a saved key");
  setBusy(btn, true, "Testing…");
  try {
    const r = await settingsCall("POST", "/api/settings/keys/test", { source, values });
    setKeyResult(source, r.ok, r.message);
  } catch (err) {
    setKeyResult(source, false, err.message);
  } finally {
    setBusy(btn, false);
  }
}

async function saveExtra(e, source, name) {
  e.preventDefault();
  const value = e.target.querySelector("input").value.trim();
  if (!value) return showToast("Enter a value to save");
  try {
    const payload = await settingsCall("PUT", "/api/settings/keys", { values: { [name]: value } });
    e.target.querySelector("input").value = "";
    await refreshAfter(payload, source, "Saved");
  } catch (err) {
    setKeyResult(source, false, err.message);
  }
}

async function clearExtra(source, name) {
  try {
    const payload = await settingsCall("PUT", "/api/settings/keys", { values: { [name]: "" } });
    await refreshAfter(payload, source, "Cleared");
  } catch (err) {
    setKeyResult(source, false, err.message);
  }
}
