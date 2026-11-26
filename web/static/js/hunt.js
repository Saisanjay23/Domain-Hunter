"use strict";
// =============================================================================
// Impersonation Hunt: Animated Cyber Radar, Executive Risk Donut,
// Platform Attribution Spotlight & Deep Forensics Table
// =============================================================================

const HUNT_STAGES = [
  ["fingerprint", "Fingerprint"],
  ["generate", "Permutations"],
  ["ct", "CT Logs"],
  ["feeds", "Phishing Feeds"],
  ["intel", "URLScan + WhoisXML + Intel"],
  ["dns", "DNS"],
  ["verify", "Inspect Sites"],
  ["rdap", "Registration"],
  ["score", "Risk Scoring"],
];

const VERDICT_META = {
  phishing: { label: "High risk", cls: "badge-danger", color: "var(--danger)", desc: "Strong impersonation or phishing signals" },
  suspicious: { label: "Suspicious", cls: "badge-warning", color: "var(--warning)", desc: "Notable lookalike or brand overlap" },
  parked: { label: "Parked / for sale", cls: "badge-purple", color: "var(--purple)", desc: "Domain parking or aftermarket listing" },
  offline: { label: "Offline", cls: "badge-purple", color: "var(--purple)", desc: "Seen in threat intel/feeds, now unreachable" },
  no_website: { label: "No website", cls: "", color: "var(--text-3)", desc: "Registered in DNS without an active web server" },
  unreachable: { label: "Web unreachable", cls: "", color: "var(--text-3)", desc: "DNS resolves, HTTP connection failed" },
  live_unrelated: { label: "Live, unrelated", cls: "", color: "var(--success)", desc: "Active website with no brand indicators" },
  redirect_brand: { label: "Redirects to brand", cls: "badge-success", color: "var(--success)", desc: "Forwards cleanly to official brand" },
  brand_owned: { label: "Brand-owned", cls: "badge-success", color: "var(--success)", desc: "Verified official organization asset" },
};

const HUNT_FILTERS = [
  ["risky", "Needs review", c => (c.verdict === "phishing" || c.verdict === "suspicious" || c.classification === "Confirmed Impersonation" || c.classification === "Potential Impersonation") && !isClosed(c)],
  ["all", "All", () => true],
  ["confirmed_imp", "Confirmed", c => c.classification === "Confirmed Impersonation" || c.verdict === "phishing"],
  ["potential_imp", "Potential", c => c.classification === "Potential Impersonation"],
  ["subdomain", "Subdomain Spoofs", c => !!(c.match_meta?.is_subdomain_impersonation || c.matching_subdomain || c.fuzzer === "brand-subdomain")],
  ["idn", "IDN / Homograph", c => !!(c.match_meta?.is_idn || c.match_meta?.mixed_script || c.fuzzer === "homoglyph" || c.fuzzer === "idn-homoglyph")],
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
  ["live_unrelated", "Benign / Unrelated", c => c.classification === "Benign/Unrelated" || c.verdict === "live_unrelated"],
  ["no_website", "No website", c => c.verdict === "no_website" || c.verdict === "unreachable"],
  ["safe", "Brand-owned", c => c.verdict === "redirect_brand" || c.verdict === "brand_owned"],
  ["fp", "False positives", c => isFP(c)],
];

const MATCH_LABELS = {
  reputation: "VirusTotal reputation",
  safe_browsing: "Safe Browsing listed",
  passive_dns: "passive DNS",
  feed: "phishing feed",
  favicon_hash: "brand favicon",
  asset_hash: "brand files",
  analytics: "analytics ID",
  hosting: "free hosting",
  lens: "logo match",
  daily_domain: "daily domain",
  daily_title: "daily brand title",
  subdomain_spoof: "subdomain impersonation",
  ct_recent: "new SSL cert",
  ct_log: "CT cert",
  nrd_feed: "Free Daily NRD",
  openphish_feed: "OpenPhish",
  phishingdb_feed: "Phishing.Database",
  dns_typo: "live typosquat DNS",
  whoisxml_brand: "Brand Alert",
  whoisxml_discovery: "Domain Discovery",
  pivot: "2nd-hop IP pivot",
  dork: "search",
};

const STRONG_MATCHES = new Set(["feed", "favicon_hash", "asset_hash", "analytics", "hosting", "daily_title", "subdomain_spoof", "whoisxml_brand"]);

function showScanRadar(on, message = "", customSteps = null) {
  const panel = document.getElementById("hunt-progress-panel");
  if (!panel) return;
  panel.hidden = !on;
  if (window.setScanPulse) window.setScanPulse(!!on);
  if (!on) return;

  if (customSteps) {
    document.getElementById("hunt-steps").innerHTML = customSteps.map((lbl, i) =>
      `<span class="step ${i === 0 ? "active" : ""}"><span class="step-icon"></span>${esc(lbl)}</span>`
    ).join("");
    document.getElementById("hunt-bar-fill").style.width = "52%";
    document.getElementById("radar-pct").innerText = "LIVE";
    document.getElementById("hunt-progress-msg").innerText = message;
    document.getElementById("hunt-live-stats").innerHTML =
      `<span><b>URLScan.io</b> Free</span><span><b>crt.sh</b> CT Logs</span><span><b>Daily NRD + Feeds</b> Free</span><span><b>DNS</b> Live Probe</span>`;
  }
}

function huntOptions() {
  const split = id => (document.getElementById(id)?.value || "").split(/[,;\n]+/).map(x => x.trim()).filter(Boolean);
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

async function executeHuntStart(opts, { btn = null, busyLabel = "Scanning…", onError = null } = {}) {
  setBusy(btn, true, busyLabel);
  try {
    const { job_id } = await apiPost("/api/hunt", opts);
    setBusy(btn, false);
    const huntInp = document.getElementById("hunt-target-input");
    if (huntInp && opts.target) huntInp.value = opts.target;
    huntJobId = job_id;
    if (currentTab !== "hunt") switchTab("hunt");
    showOnlySection(null);
    renderHuntProgress({ stage: "fingerprint", progress: 2, message: `Initializing 360° scan for ${opts.target}`, stats: {} });
    document.getElementById("hunt-progress-panel").hidden = false;
    if (window.setScanPulse) window.setScanPulse(true);
    updateHuntEmpty();
    if (window.updateShellMode) updateShellMode();
    pollHunt();
  } catch (err) {
    setBusy(btn, false);
    if (typeof onError === "function") onError(err);
    showToast(`Could not start the hunt: ${err.message}`, 6000);
  }
}

async function handleHuntSubmit(e) {
  e.preventDefault();
  const target = document.getElementById("hunt-target-input").value.trim();
  if (!target) return;

  // Dispatch according to selected Hero Scan Mode
  if (heroMode === "daily") {
    const split = id => (document.getElementById(id)?.value || "").split(/[,;\n]+/).map(x => x.trim()).filter(Boolean);
    return runDailySweep({
      target,
      keywords: split("hunt-keywords"),
      allowlist: split("hunt-allowlist"),
      lookback_hours: 24,
      include_urlscan: true,
      include_ct: true,
      include_feeds: true,
      include_dns: true,
      include_whoisxml: false,
      with_typos: true,
    }, document.getElementById("btn-hunt"));
  }
  if (heroMode === "single") {
    switchTab("single");
    document.getElementById("target-input").value = target;
    return runAssetScan(target, { include_logos: true, probe_subdomains: true, save_icons: true, timeout: 12 }, document.getElementById("btn-hunt"));
  }

  return executeHuntStart(huntOptions(), { btn: document.getElementById("btn-hunt"), busyLabel: "Scanning…" });
}

function cleanLandingTarget(raw) {
  let s = String(raw || "").trim().replace(/^['"`<>]+|['"`<>]+$/g, "");
  s = s.replace(/^https?:\/\//i, "").split(/[/?#]/)[0];
  s = s.replace(/^.*@/, "").replace(/:\d+$/, "").replace(/\.+$/, "").toLowerCase();
  return s;
}

function isValidLandingDomain(host) {
  if (!host || /\s/.test(host) || !host.includes(".")) return false;
  const parts = host.split(".");
  if (parts.length < 2) return false;
  const tld = parts[parts.length - 1];
  if (tld.length < 2 || /[^a-z0-9\u0080-\uffff-]/i.test(tld)) return false;
  return parts.every(p => p.length >= 1 && p.length <= 63 && !p.startsWith("-") && !p.endsWith("-"));
}

function clearLandingError() {
  const box = document.getElementById("landing-input-box");
  if (box) box.classList.remove("is-invalid");
  const errEl = document.getElementById("landing-error");
  if (errEl) {
    errEl.hidden = true;
    errEl.innerHTML = "";
  }
}

function showLandingError(msg, brandKeyword = "") {
  const box = document.getElementById("landing-input-box");
  if (box) box.classList.add("is-invalid");
  const errEl = document.getElementById("landing-error");
  if (!errEl) return;
  const extra = brandKeyword
    ? `<button type="button" class="dh-error-action" data-brand-kw="${esc(brandKeyword)}" onclick="openDorksFromLanding(this.dataset.brandKw)">Search “${esc(brandKeyword.slice(0, 32))}” in Dorks &amp; Capture →</button>`
    : "";
  errEl.innerHTML = `<span>${esc(msg)}</span>${extra}`;
  errEl.hidden = false;
}

function setLandingTarget(domain) {
  clearLandingError();
  const inp = document.getElementById("landing-domain-input");
  if (inp) {
    inp.value = domain;
    inp.focus();
  }
}

function openDorksFromLanding(keyword) {
  clearLandingError();
  switchTab("impersonation");
  const dorkInp = document.getElementById("impersonation-input");
  if (dorkInp) {
    dorkInp.value = keyword || "";
    dorkInp.focus();
  }
}

async function handleLandingSubmit(e) {
  e.preventDefault();
  const inp = document.getElementById("landing-domain-input");
  const raw = (inp?.value || "").trim();
  clearLandingError();

  if (!raw) {
    showLandingError("Enter a domain to investigate, e.g. paypal.com or microsoft.com.");
    if (inp) inp.focus();
    return;
  }

  const cleaned = cleanLandingTarget(raw);
  if (!isValidLandingDomain(cleaned)) {
    showLandingError("Full domain scans require a valid domain with a suffix (for example, example.com).", raw);
    if (inp) inp.focus();
    return;
  }

  const opts = {
    ...huntOptions(),
    target: cleaned,
  };
  await executeHuntStart(opts, {
    btn: document.getElementById("btn-landing-hunt"),
    busyLabel: "Starting…",
    onError: err => showLandingError(`Could not start impersonation scan: ${err.message}`),
  });
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
    huntPlatformFilter = "all";
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
  if (window.setScanPulse) window.setScanPulse(false);
  updateHuntEmpty();
  if (window.updateShellMode) updateShellMode();
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
  const pct = Math.round(job.progress || 0);
  document.getElementById("hunt-bar-fill").style.width = `${pct}%`;
  const pctEl = document.getElementById("radar-pct");
  if (pctEl) pctEl.innerText = `${pct}%`;
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

function renderRiskDonut(data) {
  const el = document.getElementById("hunt-donut-card");
  if (!el) return;
  const bv = (data.stats || {}).by_verdict || {};
  const cands = data.candidates || [];
  const total = cands.length;

  const buckets = [
    { key: "phishing", label: "High Risk", count: bv.phishing || 0, color: "#dc2626" },
    { key: "suspicious", label: "Suspicious", count: bv.suspicious || 0, color: "#d97706" },
    { key: "parked_offline", label: "Parked / Offline", count: (bv.parked || 0) + (bv.offline || 0), color: "#6366f1" },
    { key: "safe", label: "Brand-Owned", count: (bv.brand_owned || 0) + (bv.redirect_brand || 0), color: "#059669" },
    { key: "other", label: "Other", count: (bv.live_unrelated || 0) + (bv.no_website || 0) + (bv.unreachable || 0), color: "#94a3b8" },
  ].filter(b => b.count > 0);

  const r = 46;
  const circ = 2 * Math.PI * r;
  let offset = 0;
  const segments = total > 0
    ? buckets.map(b => {
      const frac = b.count / total;
      const dash = frac * circ;
      const seg = `<circle cx="66" cy="66" r="${r}" fill="none" stroke="${b.color}" stroke-width="15" stroke-dasharray="${dash.toFixed(2)} ${circ.toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}" transform="rotate(-90 66 66)"/>`;
      offset += dash;
      return seg;
    }).join("")
    : `<circle cx="66" cy="66" r="${r}" fill="none" stroke="var(--border-strong)" stroke-width="15"/>`;

  el.innerHTML = `
    <div class="section-label" style="margin-bottom: 10px;">Risk Breakdown</div>
    <div class="donut-wrap">
      <svg class="donut-svg" viewBox="0 0 132 132" aria-label="Risk distribution chart">
        <circle cx="66" cy="66" r="${r}" fill="none" stroke="var(--surface-3)" stroke-width="15"/>
        ${segments}
        <text x="66" y="64" text-anchor="middle" fill="var(--text)" font-size="22" font-weight="800">${total.toLocaleString()}</text>
        <text x="66" y="80" text-anchor="middle" fill="var(--text-3)" font-size="9" font-weight="700">DOMAINS</text>
      </svg>
      <div class="donut-legend">
        ${buckets.length ? buckets.map(b => `
          <div class="donut-legend-row">
            <span class="donut-legend-label"><span class="donut-dot" style="background:${b.color}"></span>${esc(b.label)}</span>
            <strong class="num">${b.count.toLocaleString()}</strong>
          </div>`).join("") : `<span class="hint">None found</span>`}
      </div>
    </div>`;
}

function setPlatformFilter(source) {
  const next = huntPlatformFilter === source ? "all" : (source || "all");
  huntPlatformFilter = next;
  huntPage = 1;
  if (next !== "all") {
    huntFilter = "all";
    const minSel = document.getElementById("hunt-min-score");
    if (minSel) minSel.value = "0";
    const techSel = document.getElementById("hunt-technique-filter");
    if (techSel) techSel.value = "all";
  }
  const srcSel = document.getElementById("hunt-source-filter");
  if (srcSel) srcSel.value = next;
  setHuntView("lookalikes");
  renderPlatformSpotlight(currentHunt);
  renderHuntTable();
  document.getElementById("hunt-view-tabs")?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderPlatformSpotlight(data) {
  const el = document.getElementById("hunt-platform-spotlight");
  const rail = document.getElementById("hunt-rail-sources");
  if (!el || !data) return;
  const counts = {};
  for (const c of data.candidates || []) {
    for (const src of c.sources || []) {
      counts[src] = (counts[src] || 0) + 1;
    }
  }
  const order = ["urlscan", "crt.sh", "bing", "duckduckgo", "wayback", "virustotal", "openphish", "phishingdb", "nrd_free", "hackertarget", "permutation", "whoisxml", "shodan", "fofa", "censys", "google-lens"];
  const activePlatforms = order.filter(s => counts[s] > 0);
  const meta = {
    urlscan: ["#5b5ce6", "Live scans, titles & favicons"],
    "crt.sh": ["#0d9488", "SSL certificates issued"],
    bing: ["#2563eb", "Bing dork search results"],
    duckduckgo: ["#d97706", "DuckDuckGo web results"],
    wayback: ["#6366f1", "Archived & free-host clones"],
    virustotal: ["#1d4ed8", "AV detections & subdomains"],
    openphish: ["#dc2626", "Verified active phishing URLs"],
    phishingdb: ["#be185d", "Active phishing domain list"],
    nrd_free: ["#d97706", "Newly registered domains"],
    hackertarget: ["#7c3aed", "Reverse-IP sibling domains"],
    permutation: ["#2563eb", "Active typosquats in DNS"],
    shodan: ["#dc2626", "Matching servers & certs"],
    fofa: ["#d97706", "Host & favicon matches"],
    censys: ["#2563eb", "Certificates & web hosts"],
    whoisxml: ["#0d9488", "Daily NRD brand alerts"],
    "google-lens": ["#059669", "Visual logo matches"],
  };

  if (!activePlatforms.length) {
    el.innerHTML = `<div class="mini-card" style="grid-column:1/-1;"><div class="mini-card-label">Platforms</div><div class="mini-card-sub">No platform hits recorded</div></div>`;
    if (rail) rail.innerHTML = "";
    return;
  }

  el.innerHTML = activePlatforms.slice(0, 6).map(src => {
    const [col, desc] = meta[src] || ["#2563eb", "Threat intelligence match"];
    const active = huntPlatformFilter === src;
    return `
      <button type="button" class="plat-card${active ? " active" : ""}" style="--plat-color:${col}" onclick="setPlatformFilter('${esc(src)}')" title="Click to filter findings from ${esc(SOURCE_LABELS[src] || src)}">
        <div class="plat-head">
          <span class="plat-name">${esc(SOURCE_LABELS[src] || src)}</span>
          ${active ? `<span class="badge badge-sm badge-accent">Active</span>` : ""}
        </div>
        <div class="plat-count">${counts[src].toLocaleString()}</div>
        <div class="plat-desc">${esc(desc)}</div>
      </button>`;
  }).join("");

  if (rail) {
    const pastels = ["pastel-lavender", "pastel-mint", "pastel-pink", "pastel-gold", "pastel-blue"];
    rail.innerHTML = activePlatforms.map((src, idx) => `
      <button type="button" class="pastel-pill ${pastels[idx % pastels.length]}" onclick="setPlatformFilter('${esc(src)}')">
        <span>${esc(SOURCE_LABELS[src] || src)}</span>
        <strong>${counts[src].toLocaleString()}</strong>
      </button>`).join("");
  }
}

function renderHunt(data) {
  const st = data.stats || {};
  const b = data.brand || {};
  const cands = data.candidates || [];
  const primaryIcon = (b.icons || []).find(i => i.is_primary && i.preview) || (b.icons || []).find(i => i.preview);
  const avatar = document.getElementById("hunt-brand-avatar");
  if (avatar) {
    avatar.innerHTML = primaryIcon
      ? `<img src="${esc(primaryIcon.preview)}" alt="">`
      : `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
  }

  document.getElementById("hunt-res-domain").innerText = `Brand Threat Report · ${data.target}`;
  document.getElementById("hunt-res-meta").innerText =
    `${plural(cands.length, "discovered domain")} · ${st.elapsed_sec}s · Protected own domains excluded: ${(b.allowlist || []).length}`;

  const snap = document.getElementById("hunt-brand-snapshot");
  if (snap) {
    snap.innerHTML = `
      <div class="section-label">Protected Brand</div>
      <div class="domain-name" style="font-size: 14.5px; margin-bottom: 4px;">${esc(b.title || data.target)}</div>
      <div class="hint" style="margin-bottom: 8px;">Official allowlist excluded from alerts:</div>
      <div class="chips">${(b.allowlist || []).slice(0, 6).map(d => `<span class="badge badge-sm badge-success">${esc(d)}</span>`).join("")}</div>`;
  }

  const bc = st.by_classification || {};
  const confirmedCount = bc["Confirmed Impersonation"] ?? cands.filter(c => c.classification === "Confirmed Impersonation" || c.verdict === "phishing").length;
  const potentialCount = bc["Potential Impersonation"] ?? cands.filter(c => c.classification === "Potential Impersonation").length;
  const benignCount = bc["Benign/Unrelated"] ?? Math.max(0, cands.length - confirmedCount - potentialCount);
  const todayIso = new Date().toISOString().slice(0, 10);
  const recentCount = cands.filter(c =>
    (c.rdap?.age_days !== null && c.rdap?.age_days !== undefined && c.rdap.age_days <= 7) ||
    (c.ct?.last_seen || "").startsWith(todayIso) ||
    (c.intel || []).some(i => String(i.time || "").startsWith(todayIso))
  ).length;
  const subCount = st.subdomain_impersonations ?? cands.filter(c => c.match_meta?.is_subdomain_impersonation || c.matching_subdomain).length;

  const tiles = [
    ["Total Discovered", cands.length, "Unique domain findings", "kpi-blue", "all"],
    ["Confirmed Impersonation", confirmedCount, "High-confidence threats", "kpi-danger", "confirmed_imp"],
    ["Potential Impersonation", potentialCount, "Lookalikes & unverified hits", "kpi-warning", "potential_imp"],
    ["Benign / Unrelated", benignCount, "Brand-owned & harmless matches", "kpi-muted", "live_unrelated"],
    ["Recent / Today", recentCount, "Registered <=7d or seen today", "kpi-teal", "new"],
    ["Subdomain Spoofs", subCount, "Brand in 3rd-party subdomain", "kpi-blue", "subdomain"],
  ];
  updateIocLinks(data);
  document.getElementById("hunt-tiles").innerHTML = tiles.map(([label, val, sub, cls, filterKey]) => `
    <button type="button" class="mini-card ${cls}" onclick="setHuntFilter('${filterKey}', true)">
      <div class="mini-card-label">${esc(label)}</div>
      <div class="mini-card-val">${esc(Number(val).toLocaleString())}</div>
      <div class="mini-card-sub">${esc(sub)}</div>
    </button>`).join("");

  renderHuntAnalyticsCharts(data);
  populateHuntDropdowns(data);
  renderRiskDonut(data);
  renderPlatformSpotlight(data);

  // Source problems (plan limits, quotas, challenges, outages) are logged on Settings > API keys, never shown here.
  // Only problems with the hunt itself (e.g. it could not be saved) are surfaced. Older saved hunts still carry
  // source notes in `errors`, so those are filtered out too.
  const visibleErrors = (data.errors || []).filter(e => /could not save|history|storage/i.test(String(e || "")));
  document.getElementById("hunt-errors").innerHTML = visibleErrors.slice(0, 4).map(e =>
    `<div class="alert alert-warning">${I.alert}<div>${esc(e)}</div></div>`).join("");

  const intelRan = ((data.intel || {}).status || []).filter(s => s.ran).length;
  document.getElementById("hv-count-lookalikes").innerText = (data.candidates || []).length.toLocaleString();
  document.getElementById("hv-count-intel").innerText = intelRan;

  huntPage = 1;
  document.getElementById("hunt-search").value = "";
  const minSel = document.getElementById("hunt-min-score");
  if (minSel) minSel.value = "0";
  renderHuntFilters();
  renderHuntTable();
  renderHuntIntel(data);
  renderHuntBrand(data);
  renderHuntQueries(data);
  setHuntView(huntView);
  const section = document.getElementById("hunt-results-section");
  showOnlySection("hunt-results-section");
  if (window.updateShellMode) updateShellMode();
  section.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderHuntAnalyticsCharts(data) {
  const el = document.getElementById("hunt-analytics-charts");
  if (!el) return;
  const cands = data.candidates || [];
  const srcCounts = {};
  const techCounts = {};
  for (const c of cands) {
    for (const s of c.sources || []) {
      const lbl = SOURCE_LABELS[s] || s;
      srcCounts[lbl] = (srcCounts[lbl] || 0) + 1;
    }
    const tech = c.matching_technique || c.fuzzer || "Unclassified";
    techCounts[tech] = (techCounts[tech] || 0) + 1;
  }
  const srcEntries = Object.entries(srcCounts).sort((a, b) => b[1] - a[1]);
  const techEntries = Object.entries(techCounts).sort((a, b) => b[1] - a[1]);
  el.innerHTML =
    renderDistBarChart("Discovery Source Distribution", srcEntries, "var(--accent)") +
    renderDistBarChart("Detection Technique Distribution", techEntries, "#0f766e");
}

function populateHuntDropdowns(data) {
  const cands = data.candidates || [];
  const srcSel = document.getElementById("hunt-source-filter");
  if (srcSel) {
    const sources = [...new Set(cands.flatMap(c => c.sources || []))].sort();
    srcSel.innerHTML = `<option value="all" selected>Source: All (${sources.length})</option>` +
      sources.map(s => `<option value="${esc(s)}">${esc(SOURCE_LABELS[s] || s)}</option>`).join("");
  }
  const techSel = document.getElementById("hunt-technique-filter");
  if (techSel) {
    const techs = [...new Set(cands.map(c => c.matching_technique || c.fuzzer).filter(Boolean))].sort();
    techSel.innerHTML = `<option value="all" selected>Technique: All</option>` +
      techs.map(t => `<option value="${esc(t)}">${esc(t)}</option>`).join("");
  }
}

function renderHuntFilters() {
  const cands = currentHunt?.candidates || [];
  document.getElementById("hunt-filters").innerHTML = HUNT_FILTERS.map(([key, label, fn]) => {
    const n = cands.filter(fn).filter(c => key === "all" || key === "fp" || !isFP(c)).length;
    if (!n && key !== "risky" && key !== "all") return "";
    return `<button type="button" class="chip${key === huntFilter ? " active" : ""}" aria-pressed="${key === huntFilter}" onclick="setHuntFilter('${key}')">${label} <span class="count">${n.toLocaleString()}</span></button>`;
  }).join("") + (huntPlatformFilter !== "all"
    ? `<button type="button" class="chip active" onclick="setPlatformFilter('all')">Platform: ${esc(SOURCE_LABELS[huntPlatformFilter] || huntPlatformFilter)} ✕</button>`
    : "");
}

function setHuntFilter(key, fromCard = false) {
  huntFilter = key;
  huntPage = 1;
  if (fromCard) {
    huntPlatformFilter = "all";
    const srcSel = document.getElementById("hunt-source-filter");
    if (srcSel) srcSel.value = "all";
    const minSel = document.getElementById("hunt-min-score");
    if (minSel) minSel.value = "0";
    const techSel = document.getElementById("hunt-technique-filter");
    if (techSel) techSel.value = "all";
    renderPlatformSpotlight(currentHunt);
  }
  setHuntView("lookalikes");
  renderHuntFilters();
  renderHuntTable();
  if (fromCard) {
    document.getElementById("hunt-view-tabs")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function setHuntPage(p) {
  huntPage = Math.max(1, p);
  renderHuntTable();
  document.getElementById("hunt-tbody")?.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function filteredHuntCandidates() {
  const fn = (HUNT_FILTERS.find(([k]) => k === huntFilter) || HUNT_FILTERS[1])[2];
  const q = (document.getElementById("hunt-search")?.value || "").trim().toLowerCase();
  const minScore = Number(document.getElementById("hunt-min-score")?.value || 0);
  const srcFilter = document.getElementById("hunt-source-filter")?.value || "all";
  const techFilter = document.getElementById("hunt-technique-filter")?.value || "all";
  const sortBy = document.getElementById("hunt-sort")?.value || "score";
  const hideFP = huntFilter !== "all" && huntFilter !== "fp";
  const list = (currentHunt?.candidates || []).filter(fn).filter(c => !(hideFP && isFP(c))).filter(c => {
    if (huntPlatformFilter !== "all" && !(c.sources || []).includes(huntPlatformFilter)) return false;
    if (srcFilter !== "all" && !(c.sources || []).includes(srcFilter)) return false;
    if (techFilter !== "all" && (c.matching_technique || c.fuzzer || "") !== techFilter) return false;
    if (minScore > 0 && Number(c.score || 0) < minScore) return false;
    if (!q) return true;
    const ev = c.evidence || {};
    return [
      c.domain, c.registered_domain, c.matching_subdomain, c.matched_keyword,
      c.matching_technique, c.classification, c.unicode, c.fuzzer, ev.title,
      ...(c.sources || []), ...(c.reasons || []),
    ].join(" ").toLowerCase().includes(q);
  });
  return list.slice().sort((a, b) => {
    if (sortBy === "similarity") return (b.similarity_percent || 0) - (a.similarity_percent || 0) || (b.score - a.score);
    if (sortBy === "newest") return (a.rdap?.age_days ?? 999999) - (b.rdap?.age_days ?? 999999) || (b.score - a.score);
    if (sortBy === "domain") return String(a.domain || "").localeCompare(String(b.domain || ""));
    return (b.score - a.score) || String(a.domain || "").localeCompare(String(b.domain || ""));
  });
}

function scoreClass(s) {
  return s >= 70 ? "score-high" : s >= 45 ? "score-med" : s >= 25 ? "score-low" : "score-min";
}

function renderHuntTable() {
  renderHuntFilters();
  const rows = filteredHuntCandidates();
  const tbody = document.getElementById("hunt-tbody");
  const pgEl = document.getElementById("hunt-pagination");
  const pageSize = Number(document.getElementById("hunt-page-size")?.value || 50);
  if (!rows.length) {
    const any = (currentHunt?.candidates || []).length;
    tbody.innerHTML = `<tr><td colspan="7">${emptyState(any ? "Nothing matches these filters" : "No registered lookalikes found",
      any ? "Try clicking “All”, or clear the score, source, technique, or search filters." : "None of the generated or discovered lookalikes exist in DNS.")}</td></tr>`;
    if (pgEl) pgEl.innerHTML = "";
    return;
  }
  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  if (huntPage > totalPages) huntPage = totalPages;
  const start = (huntPage - 1) * pageSize;
  const slice = rows.slice(start, start + pageSize);
  tbody.innerHTML = slice.map((c, idx) => huntRowHtml(c, start + idx)).join("");
  if (pgEl) pgEl.innerHTML = paginationControlsHtml(rows.length, huntPage, pageSize, "setHuntPage");
}

function intelBadges(c) {
  const out = [];
  const seen = new Set();
  for (const i of c.intel || []) {
    const k = `${i.source}|${i.match}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(pfBadge(i.source, MATCH_LABELS[i.match] || i.match));
  }
  for (const src of c.sources || []) {
    if (src === "permutation") continue;
    if (![...seen].some(k => k.startsWith(`${src}|`))) {
      out.push(pfBadge(src));
    }
  }
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
  const clsLabel = c.classification || vm.label;
  const clsBadge = clsLabel === "Confirmed Impersonation" ? "badge-danger" : (clsLabel === "Potential Impersonation" ? "badge-warning" : vm.cls);
  const conf = confidenceMeta(c);
  const age = rd.age_days !== null && rd.age_days !== undefined ? `${rd.age_days}d` : "-";
  const sim = c.similarity_percent ? `${Math.round(c.similarity_percent)}%` : "";
  const loc = detectKeywordLocation(c, currentHunt?.target);
  const explanationShort = buildDetectionExplanation(c, currentHunt?.target);
  const id = `hunt-detail-${i}`;
  const open = huntExpanded.has(c.domain);
  const rootDom = c.registered_domain || apexFromDomain(c.domain);
  const showRoot = rootDom && rootDom !== c.domain;
  const fullUrl = ev.http?.final_url || safeExternalDomainUrl(c.domain);
  return `
    <tr class="clickable${open ? " expanded" : ""}${isClosed(c) ? " closed" : ""}" tabindex="0" aria-expanded="${open}" aria-controls="${id}" data-detail="${id}" data-domain="${esc(c.domain)}" onclick="toggleHuntDetail(this)" onkeydown="if(event.target===this&&(event.key==='Enter'||event.key===' ')){event.preventDefault();toggleHuntDetail(this)}">
      <td class="c-score">
        <div class="stack" style="gap: 4px; align-items: flex-start;">
          <span class="score ${scoreClass(c.score)}">${c.score}</span>
          <span class="badge badge-sm ${conf.cls}" title="Detection confidence">${esc(conf.label)}</span>
        </div>
      </td>
      <td class="c-domain domain-cell">
        <div class="row" style="gap: 6px; align-items: center;">
          ${ev.preview ? `<img class="thumb" src="${esc(ev.preview)}" alt="" loading="lazy">` : ""}
          <span class="domain-name">${esc(c.domain)}</span>
          ${copyBtn(c.domain, "Domain copied")}
        </div>
        <div class="hint" style="margin-top: 4px;">
          ${showRoot ? `Root: <strong class="mono">${esc(rootDom)}</strong>` : `<span class="mono">${esc(rootDom)}</span>`}
          ${c.matching_subdomain ? ` · Subdomain: <span class="badge badge-sm badge-purple">${esc(c.matching_subdomain)}</span>` : ""}
          · Matched in: <strong>${esc(loc)}</strong>
        </div>
        ${ev.title ? `<div class="finding-subtitle" style="font-size:13px;">${esc(ev.title.slice(0, 78))}</div>` : ""}
        ${c.unicode ? `<div class="domain-uni" title="Rendered IDN Unicode form">${esc(c.unicode)}</div>` : ""}
        ${intelBadges(c)}
      </td>
      <td class="c-verdict">
        <div class="row" style="gap: 5px;">
          <span class="badge ${clsBadge}" title="${esc(vm.label + ': ' + (vm.desc || ''))}">${esc(clsLabel)}</span>
          ${c.matched_keyword ? `<span class="badge badge-sm badge-accent" title="Matched keyword">${esc(c.matched_keyword)}</span>` : ""}
          ${c.is_new ? `<span class="badge badge-accent" title="First seen in this hunt">New</span>` : ""}
        </div>
        <select class="select select-sm triage-select" data-domain="${esc(c.domain)}" aria-label="Case status for ${esc(c.domain)}" onclick="event.stopPropagation()" onchange="onTriageChange(this)">${triageOptions(triageStatus(c))}</select>
      </td>
      <td class="c-why" data-label="Detection Explanation">
        <div style="font-size: 13px; color: var(--text-2); line-height: 1.5; max-width: 44ch;">${esc(explanationShort)}</div>
      </td>
      <td class="c-type">
        <span class="type-tag">${esc(c.matching_technique || c.fuzzer)}</span>
        ${sim ? `<div class="hint" style="margin-top: 4px;">Similarity: <strong>${sim}</strong></div>` : ""}
      </td>
      <td class="c-age num">
        <div class="stack" style="gap: 3px; align-items: flex-start;">
          <span class="badge badge-sm ${c.dns_status === "resolves" ? "badge-success" : (c.dns_status === "nxdomain" ? "badge-warning" : "")}">${esc((c.dns_status || "unknown").toUpperCase())}</span>
          <span class="hint">Age: <strong>${esc(age)}</strong></span>
          ${rd.registrar ? `<span class="hint" title="${esc(rd.registrar)}">${esc(rd.registrar.slice(0, 22))}</span>` : ""}
        </div>
      </td>
      <td class="c-actions col-actions" onclick="event.stopPropagation()">
        <div class="row" style="gap: 5px; flex-wrap: nowrap; justify-content: flex-end;">
          ${openDomainBtn(c.domain, fullUrl)}
          <button type="button" class="btn btn-secondary btn-xs" onclick="const r=this.closest('tr'); if(r) toggleHuntDetail(r)" aria-label="Toggle details">${open ? "Hide" : "Details"}</button>
        </div>
      </td>
    </tr>
    <tr class="detail" id="${id}"${open ? "" : " hidden"}><td colspan="7">${huntDetailHtml(c)}</td></tr>`;
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

function uniqueIntel(list) {
  const seen = new Set();
  return (list || []).filter(i => {
    const k = `${i.source}|${i.match}|${i.title || ""}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function dns_status_str(c) {
  const s = c.dns_status || "";
  return s ? s.toUpperCase() : "";
}

function scoreReasonsHtml(c) {
  const bd = c.score_breakdown || [];
  if (bd.length) {
    return [...bd].sort((a, b) => b.points - a.points).map(b =>
      `<li>${I.dot}<span><strong class="mono">${b.points > 0 ? "+" : ""}${b.points}</strong> ${esc(b.reason)}</span></li>`).join("");
  }
  return (c.reasons || []).map(r => `<li>${I.dot}<span>${esc(r)}</span></li>`).join("") || `<li class="muted">No signals</li>`;
}

function huntDetailHtml(c) {
  const ev = c.evidence || {};
  const http = ev.http || {};
  const rd = c.rdap || {};
  const ct = c.ct || {};
  const fav = ev.favicon || {};
  const dns = c.dns || {};
  const orig = c.original_domain || currentHunt?.target || "";
  const rootDom = c.registered_domain || apexFromDomain(c.domain);
  const loc = detectKeywordLocation(c, orig);
  const conf = confidenceMeta(c);
  const fullUrl = http.final_url || safeExternalDomainUrl(c.domain);
  const explanation = buildDetectionExplanation(c, orig);
  const clsLabel = c.classification || (VERDICT_META[c.verdict] || {}).label;
  const sevCls = c.score >= 70 ? "sev-high" : c.score >= 40 ? "sev-med" : "";
  const defangUrl = u => (u || "").replace(/^http/, "hxxp").replace(/\./g, "[.]");

  // Transparency: distinguish Discovery Sources from Enrichment Sources
  const discoveryList = uniqueIntel(c.intel);
  const extraDiscSources = (c.sources || []).filter(s => !discoveryList.some(i => i.source === s));
  const enrichmentTags = [];
  if (c.dns_status && c.dns_status !== "unknown") enrichmentTags.push(`DNS (${c.dns_status.toUpperCase()})`);
  if (c.evidence) enrichmentTags.push(http.status ? `Live HTTP (${http.status})` : "HTTP probed");
  if (rd.registrar || rd.created) enrichmentTags.push("RDAP / WHOIS");
  if (ct.first_seen) enrichmentTags.push("CT Metadata");

  return `
    <div class="explain-banner ${sevCls}">
      <div class="spread" style="margin-bottom: 6px;">
        <div class="explain-banner-label">Detection Explanation &amp; Analyst Summary</div>
        <div class="row" style="gap: 6px;">
          ${openDomainBtn(c.domain, fullUrl, "btn btn-xs btn-open-domain")}
          <button type="button" class="btn btn-secondary btn-xs" data-copy="${esc(c.domain)}" data-copy-label="Domain copied">Copy Domain</button>
          <button type="button" class="btn btn-secondary btn-xs" data-copy="${esc(fullUrl)}" data-copy-label="Complete URL copied">Copy URL</button>
          ${copyBtn(c.defanged || c.domain, "Defanged domain copied")}
        </div>
      </div>
      <div>${esc(explanation)}</div>
    </div>

    <div class="dossier-grid">
      <div class="dossier-card">
        <h4>A. Domain &amp; Hostname Breakdown</h4>
        ${kvRows([
    ["Discovered Domain", c.domain],
    ["Complete Hostname", c.domain],
    ["Registered Root", rootDom],
    ["Matching Subdomain", c.matching_subdomain || "None (matched in root/content)"],
    ["Original Domain", orig],
    ["Matched Keyword", c.matched_keyword || "Content / Intel indicator"],
    ["Keyword Location", loc],
    ["Unicode / IDN", c.unicode],
  ])}
      </div>

      <div class="dossier-card">
        <h4>B. Detection Reasoning &amp; Score Factors</h4>
        ${kvRows([
    ["Detection Technique", c.matching_technique || c.fuzzer],
    ["Malicious Context", (c.match_meta?.context_keywords || []).join(", ")],
    ["Brand Ownership Evidence", (c.ownership || []).join("; ")],
    ["Similarity", c.similarity_percent ? `${c.similarity_percent}%` : "N/A (non-lexical)"],
    ["Confidence", conf.label],
    ["HTTP Status / Title", ev.title ? `${http.status || ""} · ${ev.title}` : (http.status || "")],
    ["Password Form", ev.password_form ? "Yes (credential lure)" : ""],
    ["Brand Visual / Favicon", fav.exact_match ? "Byte-identical favicon" : (ev.visual_distance !== undefined && ev.visual_distance !== null ? `pHash distance ${ev.visual_distance}` : "")],
    ["Shared Analytics", ev.shared_analytics],
    ["TLS Cert Org", (ev.cert || {}).subject_org],
  ])}
        <div class="section-label" style="margin: 10px 0 6px;">Contributing Signals${c.score_capped ? ` <span class="badge badge-sm badge-warning">capped pending corroboration</span>` : ""}</div>
        <ul class="check-list">${scoreReasonsHtml(c)}</ul>
        ${(c.corroboration || []).length ? `<div class="section-label" style="margin: 10px 0 6px;">Independent Corroboration</div>
        <ul class="check-list">${c.corroboration.map(r => `<li>${I.dot}<span>${esc(r)}</span></li>`).join("")}</ul>` : ""}
        ${(c.match_meta?.keyword_hits || []).length > 1 ? `<div class="section-label" style="margin: 10px 0 6px;">All Matched Keywords</div>
        <ul class="check-list">${c.match_meta.keyword_hits.map(h => `<li>${I.dot}<span><strong>${esc(h.keyword)}</strong> · ${esc(h.technique_key.replace(/_/g, " "))} in ${esc(h.matched_in)} (${Math.round(h.similarity_percent)}%)</span></li>`).join("")}</ul>` : ""}
      </div>

      <div class="dossier-card">
        <h4>C. Intelligence Source Transparency</h4>
        <div class="stack" style="gap: 7px;">
          ${discoveryList.map(i => {
    const refUrl = sourceReferenceUrl(i.source, c.domain, i.url);
    return `<div class="src-item">
              <div>
                <div><strong>${esc(SOURCE_LABELS[i.source] || i.source)}</strong> · <span class="src-role">Discovery</span></div>
                <div class="hint">${esc(MATCH_LABELS[i.match] || i.match)}${i.time ? ` · ${esc(String(i.time).slice(0, 16))}` : ""}</div>
              </div>
              ${refUrl ? linkBtn(refUrl, "Source ↗", `Open ${SOURCE_LABELS[i.source] || i.source} record`, "btn btn-ghost btn-xs") : ""}
            </div>`;
  }).join("")}
          ${extraDiscSources.map(s => {
    const refUrl = sourceReferenceUrl(s, c.domain);
    return `<div class="src-item">
              <div><strong>${esc(SOURCE_LABELS[s] || s)}</strong> · <span class="src-role">${s === "permutation" ? "Permutation Engine" : "Discovery"}</span></div>
              ${refUrl ? linkBtn(refUrl, "Source ↗", `Open ${SOURCE_LABELS[s] || s}`, "btn btn-ghost btn-xs") : ""}
            </div>`;
  }).join("")}
          ${enrichmentTags.length ? `<div class="src-item"><div><div class="src-role">Enrichment Sources</div><div class="hint">${esc(enrichmentTags.join(" · "))}</div></div></div>` : ""}
          <p class="hint" style="margin-top: 2px;">Note: Appearing in a discovery feed or CT log confirms existence only; risk classification reflects corroborating impersonation evidence.</p>
        </div>
      </div>

      <div class="dossier-card">
        <h4>D. Threat, DNS, Registration &amp; Case</h4>
        ${kvRows([
    ["Threat Score", `${c.score} / 100 (${clsLabel})`],
    ["DNS Status", dns_status_str(c)],
    ["A / AAAA", [...(dns.a || []), ...(dns.aaaa || [])]],
    ["MX / NS", [...(dns.mx || []), ...(dns.ns || [])]],
    ["Registered", (rd.created || "").slice(0, 10)],
    ["Registrar", rd.registrar],
    ["Abuse Contact", rd.abuse_email],
    ["CT Issuer", ct.issuer],
    ["Final URL", defangUrl(http.final_url)],
  ])}
        <div style="margin-top: 12px;">${caseBlockHtml(c)}</div>
      </div>
    </div>

    <div style="margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--border); display: flex; flex-wrap: wrap; align-items: center; gap: 6px;">
      <span class="hint" style="font-weight: 600; margin-right: 4px;">Investigate Root &amp; Infrastructure Pivots:</span>
      <button type="button" class="btn btn-primary btn-xs" onclick="investigateDomain('${esc(c.domain)}')" title="Map the infrastructure and operator behind this domain">Map infrastructure</button>
      ${linkBtn(`https://www.virustotal.com/gui/domain/${encodeURIComponent(c.domain)}`, "VirusTotal", "Inspect domain report on VirusTotal", "btn btn-ghost btn-xs")}
      ${rootDomainPivotsHtml(c.domain, (dns.a || [])[0] || "")}
    </div>`;
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

  // Only searches that actually ran are listed; skipped / failed ones are on Settings > API keys > Source activity.
  const status = ((data.intel || {}).status || []).filter(s => s.ran && !s.error).sort((a, b) => b.count - a.count);
  const urlFor = s => s.source === "serpapi" ? `https://lens.google.com/uploadbyurl?url=${encodeURIComponent(s.query)}` : platformUrl(s.source, s.query);
  document.getElementById("hunt-intel-tbody").innerHTML = status.length ? status.map(s => `<tr class="plain">
      <td data-label="Source">${pfLabel(s.source)}</td>
      <td data-label="Looking for">${esc(s.label)}</td>
      <td data-label="Hits" class="num">${s.ran ? esc(s.count) : `<span class="muted">-</span>`}</td>
      <td data-label="Status"><span class="badge badge-sm badge-success">OK</span></td>
      <td class="col-actions"><div class="row" style="gap: 2px; flex-wrap: nowrap; justify-content: flex-end;">${s.source !== "serpapi" ? copyBtn(s.query, "Query copied") : ""}${openIcon(urlFor(s), "Run this search")}</div></td>
    </tr>`).join("") : `<tr><td colspan="5">${emptyState("Threat-intel platforms were off for this hunt")}</td></tr>`;
}

function renderHuntBrand(data) {
  const b = data.brand || {};
  const icons = b.icons || [];
  const primary = icons.find(i => i.is_primary) || icons[0] || {};
  const gtmList = b.analytics_ids || [];
  const facts = [
    ["Resolved URL", b.resolved_url], ["Title", b.title], ["Brand titles", (b.brand_titles || []).join(", ")],
    ["Name tokens", (b.tokens || []).join(", ")], ["Own domains", shortList(b.allowlist, 20)],
    ["Analytics IDs", gtmList.join(", ")], ["TLS organisation", b.cert_org],
    ["Brand JS/CSS", ((data.pivots || {}).assets || []).map(a => a.url.split("/").pop().split("?")[0]).join(", ")],
  ];
  document.getElementById("hunt-brand").innerHTML = `
    <div class="card card-body stack" style="margin-bottom: 18px; background: var(--surface-2);">
      <div class="section-label" style="margin-bottom: 4px;">Step 1: Extracted Brand Identifiers (For Manual &amp; Cross-Platform Pivots)</div>
      <div class="mini-grid">
        <div class="mini-card kpi-blue"><div class="mini-card-label">1. Brand Keywords</div><div class="mini-card-val" style="font-size:15px;">${esc((b.tokens || [])[0] || data.target)}</div><div class="mini-card-sub">${esc((b.tokens || []).join(", "))}</div></div>
        <div class="mini-card kpi-teal"><div class="mini-card-label">2. Exact HTML Title</div><div class="mini-card-val" style="font-size:14px;">${esc((b.title || "Not found").slice(0, 48))}</div><div class="mini-card-sub">${copyBtn(b.title || "", "Title copied")}</div></div>
        <div class="mini-card kpi-warning"><div class="mini-card-label">3. Favicon Hash (SHA-256 / MMH3)</div><div class="mini-card-val mono" style="font-size:12px;">${esc(primary.sha256 ? primary.sha256.slice(0, 20) + "…" : "None")}</div><div class="mini-card-sub">MMH3: ${esc(primary.mmh3 ?? "n/a")} ${copyBtn(primary.sha256 || "", "SHA-256 copied")}</div></div>
        <div class="mini-card kpi-danger"><div class="mini-card-label">4. Analytics / GTM IDs</div><div class="mini-card-val mono" style="font-size:14px;">${esc(gtmList[0] || "None detected")}</div><div class="mini-card-sub">${gtmList[0] ? `${copyBtn(gtmList[0], "Tag copied")} ${linkBtn(`https://publicwww.com/web/${encodeURIComponent('"' + gtmList[0] + '"')}/`, "PublicWWW", "Search mirrored pages on PublicWWW", "btn btn-ghost btn-xs")}` : "No GTM-/G-/UA- found"}</div></div>
      </div>
    </div>
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
    daily_search: "Daily Search (24h Domain + Title)", daily_domain: "Daily Domain Keyword (24h)", daily_title: "Daily Brand Title (24h)",
    subdomain_spoof: "Subdomain Impersonations (keyword.*)",
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
  ["score", c => c.score], ["classification", c => c.classification || c.verdict_label || c.verdict],
  ["verdict", c => c.verdict_label || c.verdict], ["domain", c => c.domain],
  ["registered_domain", c => c.registered_domain || ""], ["matching_subdomain", c => c.matching_subdomain || ""],
  ["original_domain", c => c.original_domain || currentHunt?.target || ""],
  ["matched_keyword", c => c.matched_keyword || ""], ["matching_technique", c => c.matching_technique || c.fuzzer || ""],
  ["similarity_percent", c => c.similarity_percent ?? ""], ["dns_status", c => c.dns_status || ""],
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
  downloadBlob("\uFEFF" + lines.join("\r\n"), `hunt_${currentHunt.target}_${huntFilter}.csv`, "text/csv;charset=utf-8");
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
