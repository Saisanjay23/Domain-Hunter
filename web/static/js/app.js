"use strict";
// =============================================================================
// Navigation, Clean Titles & Bootstrap
// =============================================================================

const PAGE_META = {
  overview: ["Overview", ""],
  hunt: ["Brand Hunt", ""],
  daily: ["Daily Radar", "Last 24h lookalikes across URLScan, crt.sh, Free NRD & Phishing Feeds"],
  infra: ["Infrastructure Investigator", "One domain in: the linked infrastructure, the operator's intent, targets, tradecraft and next moves"],
  single: ["Asset Scan", "Extract favicons, logos & hashes"],
  batch: ["Batch Scan", "Scan multiple domains at once"],
  reverse: ["Logo Check", "Compare suspect images against your brand"],
  aggregator: ["Hash Tools", "Combine hashes into platform queries"],
  impersonation: ["OSINT Dorks", "Generate reconnaissance queries & capture domains"],
  storage: ["Storage", "MongoDB connection"],
  history: ["History", "Saved brand hunts"],
  watch: ["Watchlist", "Automated scheduled monitoring"],
  scheduler: ["Scan Scheduler", "Batches of monitored domains, scanned automatically on their schedules"],
  data: ["Data Management", "Volumes, scoped deletions and the audit trail"],
  keys: ["API Keys", "Optional keys (all core features run free without keys)"],
};

const TAB_FORMS = {
  overview: "overview-page",
  hunt: "hunt-scan-form",
  daily: "daily-scan-form",
  infra: "infra-scan-form",
  single: "single-scan-form",
  batch: "batch-scan-form",
  reverse: "reverse-scan-form",
  aggregator: "aggregator-scan-form",
  impersonation: "impersonation-scan-form",
  keys: "keys-page",
  history: "history-page",
  watch: "watch-page",
  storage: "storage-page",
  scheduler: "scheduler-page",
  data: "data-page",
};

const RESULT_SECTIONS = [
  "hunt-results-section",
  "daily-results-section",
  "results-section",
  "reverse-results-section",
  "aggregator-results-section",
  "impersonation-results-section",
  "infra-results-section",
];

function showOnlySection(id) {
  RESULT_SECTIONS.forEach(s => {
    const el = document.getElementById(s);
    if (el) el.hidden = s !== id;
  });
}

function toggleNav(open) {
  document.getElementById("app").classList.toggle("nav-open", open);
}

function toggleSidebar(force) {
  const app = document.getElementById("app");
  if (!app) return;
  const collapsed = typeof force === "boolean" ? force : !app.classList.contains("sidebar-collapsed");
  app.classList.toggle("sidebar-collapsed", collapsed);
  const btn = document.getElementById("btn-sidebar-toggle");
  if (btn) {
    btn.setAttribute("aria-expanded", String(!collapsed));
    btn.setAttribute("aria-label", collapsed ? "Expand sidebar" : "Collapse sidebar");
  }
  try { localStorage.setItem("dh-sidebar-collapsed", collapsed ? "1" : "0"); } catch (e) { /* ignore */ }
}

function initSidebarState() {
  try {
    if (localStorage.getItem("dh-sidebar-collapsed") === "1") toggleSidebar(true);
  } catch (e) { /* ignore */ }
}

function setHeroMode(mode) {
  heroMode = mode || "hunt";
  document.querySelectorAll("[data-hero-mode]").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.heroMode === heroMode);
  });
  const btnLabel = document.getElementById("hero-scan-label");
  if (btnLabel) {
    btnLabel.innerText = heroMode === "daily" ? "Scan 24h Radar" : "Scan Domain";
  }
}

function setHuntTarget(domain) {
  const input = document.getElementById("hunt-target-input");
  if (input) { input.value = domain; input.focus(); }
}

function setDailyTarget(domain) {
  const input = document.getElementById("daily-target-input");
  if (input) { input.value = domain; input.focus(); }
}

function toggleLandingMenu(force) {
  const menu = document.getElementById("landing-tools-menu");
  const btn = document.getElementById("btn-landing-tools");
  if (!menu) return;
  const open = typeof force === "boolean" ? force : menu.hidden;
  menu.hidden = !open;
  if (btn) btn.setAttribute("aria-expanded", String(open));
}

function showLandingPage() {
  currentTab = "home";
  const lp = document.getElementById("landing-page");
  if (lp) lp.hidden = false;
  document.body.classList.toggle("landing-home", true);
  document.body.classList.toggle("is-landing", true);
  toggleLandingMenu(false);
  toggleNav(false);
  document.title = "Domain Hunter · Created by Sai Sanjay";
}

function switchTab(tab) {
  if (tab === "home") {
    showLandingPage();
    return;
  }
  const lp = document.getElementById("landing-page");
  if (lp) lp.hidden = true;
  document.body.classList.toggle("landing-home", false);
  toggleLandingMenu(false);
  if (tab !== "scheduler" && typeof schStopPolling === "function") schStopPolling();
  currentTab = tab;
  Object.entries(TAB_FORMS).forEach(([key, formId]) => {
    const el = document.getElementById(formId);
    if (el) el.hidden = key !== tab;
  });
  document.querySelectorAll(".nav-item[data-tab]").forEach(btn => {
    const on = btn.dataset.tab === tab;
    btn.classList.toggle("active", on);
    if (on) btn.setAttribute("aria-current", "page"); else btn.removeAttribute("aria-current");
  });
  const [title, desc] = PAGE_META[tab] || ["Domain Hunter", ""];
  document.getElementById("page-title").innerText = title;
  document.getElementById("topbar-title").innerText = title;
  document.getElementById("page-desc").innerText = desc;
  document.title = `${title} · Domain Hunter`;
  const pageHead = document.getElementById("page-head");
  if (pageHead) pageHead.hidden = tab === "hunt" || !desc;

  document.getElementById("hunt-progress-panel").hidden = !(tab === "hunt" && huntJobId);
  updateHuntEmpty();
  updateShellMode();
  toggleNav(false);

  if (tab === "overview") { showOnlySection(null); loadOverview(); }
  else if (tab === "hunt") showOnlySection(currentHunt ? "hunt-results-section" : null);
  else if (tab === "daily") showOnlySection(currentDailyResult ? "daily-results-section" : null);
  else if (tab === "single") showOnlySection(currentResult && !currentBatchResult ? "results-section" : null);
  else if (tab === "batch") showOnlySection(currentBatchResult ? "results-section" : null);
  else if (tab === "reverse") {
    showOnlySection(currentReverseBulkResult ? "reverse-results-section" : null);
    const badge = document.getElementById("compare-target-badge");
    const brandIcon = getPrimaryBrandIcon();
    badge.innerText = brandIcon && currentResult?.domain
      ? `Comparing with ${currentResult.domain}`
      : "Scan a brand first to compare similarity";
  } else if (tab === "aggregator") showOnlySection(currentAggregatorResult ? "aggregator-results-section" : null);
  else if (tab === "impersonation") showOnlySection(currentImpersonationResult ? "impersonation-results-section" : null);
  else if (tab === "infra") {
    showOnlySection(typeof currentInfra !== "undefined" && currentInfra ? "infra-results-section" : null);
    if (typeof infraGraph !== "undefined" && infraGraph) requestAnimationFrame(() => { infraGraph.resize(); });
    if (typeof loadInfraHistory === "function") loadInfraHistory();
  }
  else if (tab === "keys") { showOnlySection(null); loadKeys(); }
  else if (tab === "history") { showOnlySection(null); loadHistory(); }
  else if (tab === "watch") { showOnlySection(null); loadWatch(); }
  else if (tab === "storage") { showOnlySection(null); loadStorage(); }
  else if (tab === "scheduler") { showOnlySection(null); loadScheduler(); }
  else if (tab === "data") { showOnlySection(null); loadDataManagement(); }
}

// The navigation rail is visible in workspace mode. "is-landing" decides whether the animated threat-mesh
// background plays (Landing home, Overview and the empty Brand Hunt form).
function updateShellMode(forceDashboard = false) {
  const landing = !forceDashboard && (currentTab === "home" || currentTab === "overview" || (currentTab === "hunt" && !huntJobId && !currentHunt));
  document.body.classList.toggle("is-landing", landing);
}

function updateHuntEmpty() {
  const el = document.getElementById("hunt-empty");
  if (el) el.hidden = !(currentTab === "hunt" && !huntJobId && !currentHunt);
}

async function loadSources() {
  let sources = [];
  try { sources = (await (await fetch("/api/sources")).json()).sources || []; } catch (e) { /* offline */ }
  const missing = sources.filter(s => s.mode === "off").length;
  const badge = document.getElementById("keys-nav-badge");
  if (badge) badge.hidden = true; // Never nag users about optional paid keys in Free Mode
  const hs = document.getElementById("hunt-sources");
  if (hs) hs.innerHTML = "";
  const ss = document.getElementById("sidebar-sources");
  if (ss) ss.innerHTML = `${sources.length - missing} optional keys`;
  loadStorageBadge();
}

document.addEventListener("keydown", e => {
  if (e.key === "Escape") {
    toggleNav(false);
    toggleLandingMenu(false);
  }
});
document.addEventListener("click", e => {
  const menu = document.getElementById("landing-tools-menu");
  if (menu && !menu.hidden && !e.target?.closest?.("#landing-tools-menu") && !e.target?.closest?.("#btn-landing-tools")) {
    toggleLandingMenu(false);
  }
});
initSidebarState();
applyTheme(currentTheme());
setHeroMode("hunt");
showLandingPage();
loadSources();
refreshAlertBadge();
setInterval(refreshAlertBadge, 60000);
