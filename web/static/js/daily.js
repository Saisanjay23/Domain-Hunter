"use strict";
// =============================================================================
// Daily Threat Radar: Enterprise Dashboard, Source Transparency & Evidence Cards
// =============================================================================

async function handleDailySubmit(e) {
  e.preventDefault();
  const target = document.getElementById("daily-target-input").value.trim();
  if (!target) return showToast("Enter a domain (e.g. paypal.com)");
  const brandTitle = (document.getElementById("daily-brand-title")?.value || "").trim() || null;
  const keywords = (document.getElementById("daily-keywords")?.value || "").split(/[,;\n]+/).map(x => x.trim()).filter(Boolean);
  const allowlist = (document.getElementById("daily-allowlist")?.value || "").split(/[,;\n]+/).map(x => x.trim()).filter(Boolean);
  const lookbackHours = Number(document.getElementById("daily-lookback")?.value || 24);
  const includeUrlscan = !!document.getElementById("daily-toggle-urlscan")?.checked;
  const includeCt = !!document.getElementById("daily-toggle-ct")?.checked;
  const includeFeeds = !!document.getElementById("daily-toggle-feeds")?.checked;
  const includeDns = !!document.getElementById("daily-toggle-dns")?.checked;

  await runDailySweep({
    target,
    brand_title: brandTitle,
    keywords,
    allowlist,
    lookback_hours: lookbackHours,
    include_urlscan: includeUrlscan,
    include_ct: includeCt,
    include_feeds: includeFeeds,
    include_dns: includeDns,
    include_whoisxml: false,
    with_typos: true,
  }, document.getElementById("btn-daily-scan"));
}

async function runDailySweep(payload, btn = null) {
  setBusy(btn, true, "Scanning…");
  showOnlySection(null);
  if (window.updateShellMode) updateShellMode(true);
  showScanRadar(true, `Scanning ${payload.target} across URLScan, crt.sh, Free NRD, Phishing feeds & Live DNS…`, ["URLScan.io", "crt.sh CT", "NRD & Feeds", "Live DNS"]);
  try {
    const data = await apiPost("/api/daily-intel", payload);
    currentDailyResult = data;
    dailyFilter = "all";
    dailyPage = 1;
    renderDailyResults(data);
    showToast(`${plural(data.stats?.total_domains || 0, "domain")} found`);
  } catch (err) {
    showToast(`Scan failed: ${err.message}`, 6000);
  } finally {
    setBusy(btn, false);
    showScanRadar(false);
    if (window.updateShellMode) updateShellMode();
  }
}

function setDailyFilter(key) {
  dailyFilter = dailyFilter === key && key !== "all" ? "all" : key;
  dailyPage = 1;
  if (dailyFilter !== "all") {
    const clsSel = document.getElementById("daily-class-filter");
    if (clsSel) clsSel.value = "all";
    const techSel = document.getElementById("daily-technique-filter");
    if (techSel) techSel.value = "all";
  }
  renderDailyResults(currentDailyResult, { scroll: false });
  if (key !== "all") {
    document.getElementById("daily-results-list")?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

function setDailyPage(p) {
  dailyPage = Math.max(1, p);
  renderDailyList();
  document.getElementById("daily-results-list")?.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function dailySeverityScore(item) {
  const mts = new Set(item.match_types || []);
  let s = 35;
  if (mts.has("openphish_feed") || mts.has("phishingdb_feed")) s += 45;
  if (mts.has("daily_title") || mts.has("whoisxml_brand")) s += 30;
  if (item.matching_subdomain) s += 22;
  if ((item.platforms || []).length > 1) s += 15;
  if (mts.has("nrd_feed") || mts.has("ct_recent")) s += 10;
  if (item.similarity_percent >= 90) s += 10;
  return Math.min(100, s);
}

function filteredDailyItems(data) {
  const list = data?.results || [];
  const q = (document.getElementById("daily-search-filter")?.value || "").trim().toLowerCase();
  const clsFilter = document.getElementById("daily-class-filter")?.value || "all";
  const techFilter = document.getElementById("daily-technique-filter")?.value || "all";
  const sortBy = document.getElementById("daily-sort")?.value || "severity";

  const filtered = list.filter(item => {
    const plats = item.platforms || [];
    const mts = item.match_types || [];
    if (dailyFilter === "multi" && plats.length < 2) return false;
    if (dailyFilter === "urlscan" && !plats.includes("urlscan")) return false;
    if (dailyFilter === "crt.sh" && !plats.includes("crt.sh")) return false;
    if (dailyFilter === "nrd_free" && !plats.includes("nrd_free")) return false;
    if (dailyFilter === "feeds" && !plats.some(p => ["nrd_free", "openphish", "phishingdb"].includes(p))) return false;
    if (dailyFilter === "openphish" && !plats.includes("openphish")) return false;
    if (dailyFilter === "phishingdb" && !plats.includes("phishingdb")) return false;
    if (dailyFilter === "permutation" && !plats.includes("permutation")) return false;
    if (dailyFilter === "daily_domain" && !mts.includes("daily_domain")) return false;
    if (dailyFilter === "daily_title" && !mts.includes("daily_title")) return false;
    if (clsFilter !== "all" && (item.classification || "Potential Impersonation") !== clsFilter) return false;
    if (techFilter !== "all" && (item.matching_technique || "") !== techFilter) return false;
    if (!q) return true;
    return [
      item.domain, item.registered_domain, item.apex_domain, item.matching_subdomain,
      item.matched_keyword, item.matching_technique, item.classification,
      item.title, item.description, ...plats,
    ].join(" ").toLowerCase().includes(q);
  });

  return filtered.slice().sort((a, b) => {
    if (sortBy === "similarity") return (b.similarity_percent || 0) - (a.similarity_percent || 0) || dailySeverityScore(b) - dailySeverityScore(a);
    if (sortBy === "newest") return String(b.first_seen || "").localeCompare(String(a.first_seen || "")) || dailySeverityScore(b) - dailySeverityScore(a);
    if (sortBy === "domain") return String(a.domain || "").localeCompare(String(b.domain || ""));
    return dailySeverityScore(b) - dailySeverityScore(a) || String(a.domain || "").localeCompare(String(b.domain || ""));
  });
}

function renderDailyResults(data, { scroll = true } = {}) {
  if (!data) return;
  const st = data.stats || {};
  const list = data.results || [];
  document.getElementById("daily-res-domain").innerText = `Daily Threat Radar · ${data.target}`;
  document.getElementById("daily-res-meta").innerText =
    `${plural(st.total_domains || 0, "matching domain")} · ${st.elapsed_sec}s · ${data.lookback_hours}h window · Official excluded: ${shortList(data.allowlist, 3)}`;

  // Top-Accented Enterprise Platform Spotlight Cards
  const platCards = [
    { key: "urlscan", name: "URLScan.io", count: st.urlscan_hits || 0, desc: "Page domains & brand titles", col: "#4f46e5" },
    { key: "crt.sh", name: "crt.sh SSL", count: st.ct_hits || 0, desc: "Issued TLS certificates", col: "#0f766e" },
    { key: "feeds", name: "NRD & Feeds", count: st.feed_hits || 0, desc: "Daily NRD, OpenPhish, PhishDB", col: "#dc2626" },
    { key: "permutation", name: "Live DNS", count: st.dns_hits || 0, desc: "Active typosquat & combo sites", col: "#1d4ed8" },
  ];
  document.getElementById("daily-platform-cards").innerHTML = platCards.map(c => `
    <button type="button" class="plat-card${dailyFilter === c.key ? " active" : ""}" style="--plat-color:${c.col}" onclick="setDailyFilter('${c.key}')">
      <div class="plat-head">
        <span class="plat-name">${esc(c.name)}</span>
        ${dailyFilter === c.key ? `<span class="badge badge-sm badge-accent">Active</span>` : ""}
      </div>
      <div class="plat-count">${esc(Number(c.count).toLocaleString())}</div>
      <div class="plat-desc">${esc(c.desc)}</div>
    </button>`).join("");

  // Overview KPIs (strictly from real data)
  const confirmed = list.filter(r => r.classification === "Confirmed Impersonation").length;
  const potential = list.filter(r => r.classification === "Potential Impersonation").length;
  const subCount = list.filter(r => !!r.matching_subdomain).length;
  const kpis = [
    ["Total Domains", st.total_domains || 0, "Unique matching hosts", "kpi-blue"],
    ["Confirmed Impersonation", confirmed, "Feed / cloned title matches", "kpi-danger"],
    ["Potential Impersonation", potential, "Lookalikes & subdomain spoofs", "kpi-warning"],
    ["Subdomain Spoofs", subCount, "Brand matched in subdomain", "kpi-teal"],
  ];
  document.getElementById("daily-tiles").innerHTML = kpis.map(([lbl, val, sub, cls]) => `
    <div class="mini-card ${cls}">
      <div class="mini-card-label">${esc(lbl)}</div>
      <div class="mini-card-val">${esc(Number(val).toLocaleString())}</div>
      <div class="mini-card-sub">${esc(sub)}</div>
    </div>`).join("");

  // Source & Detection Technique Distribution Charts
  const chartsEl = document.getElementById("daily-analytics-charts");
  if (chartsEl) {
    const srcCounts = {};
    const techCounts = {};
    for (const r of list) {
      for (const p of r.platforms || []) {
        const lbl = SOURCE_LABELS[p] || p;
        srcCounts[lbl] = (srcCounts[lbl] || 0) + 1;
      }
      const t = r.matching_technique || "Domain / Content Match";
      techCounts[t] = (techCounts[t] || 0) + 1;
    }
    chartsEl.innerHTML =
      renderDistBarChart("Discovery Source Distribution", Object.entries(srcCounts).sort((a, b) => b[1] - a[1]), "var(--accent)") +
      renderDistBarChart("Detection Technique Distribution", Object.entries(techCounts).sort((a, b) => b[1] - a[1]), "#0f766e");
  }

  // Dynamic Technique Filter Options
  const techSel = document.getElementById("daily-technique-filter");
  if (techSel) {
    const techs = [...new Set(list.map(r => r.matching_technique).filter(Boolean))].sort();
    techSel.innerHTML = `<option value="all" selected>Technique: All</option>` +
      techs.map(t => `<option value="${esc(t)}">${esc(t)}</option>`).join("");
  }

  // Active Engines Rail (full distinguishing labels — never duplicate "URLScan")
  const rail = document.getElementById("daily-rail-sources");
  if (rail) {
    const pastels = ["pastel-lavender", "pastel-mint", "pastel-pink", "pastel-gold", "pastel-blue"];
    rail.innerHTML = (data.platforms || []).map((p, idx) => `
      <button type="button" class="pastel-pill ${pastels[idx % pastels.length]}" onclick="setDailyFilter('${esc(p.source === "urlscan" ? p.match : p.source)}')">
        <span>${esc(p.label)}</span>
        <strong>${esc(p.count || 0)}</strong>
      </button>`).join("");
  }

  const dq = data.queries || {};
  document.getElementById("daily-query-rows").innerHTML = [
    queryRow(`URLScan · Domain`, dq.urlscan_domain, dq.urlscan_domain_url, { wrap: true }),
    queryRow(`URLScan · Title`, dq.urlscan_title, dq.urlscan_title_url, { wrap: true }),
  ].filter(Boolean).join("");

  const filterDefs = [
    ["all", "All Domains", list.length],
    ["urlscan", "URLScan.io", st.urlscan_hits || 0],
    ["crt.sh", "crt.sh CT", st.ct_hits || 0],
    ["feeds", "NRD & Feeds", st.feed_hits || 0],
    ["permutation", "Live DNS", st.dns_hits || 0],
  ].filter(([k, , n]) => k === "all" || n > 0);
  document.getElementById("daily-filters").innerHTML = filterDefs.map(([k, lbl, n]) =>
    `<button type="button" class="chip${dailyFilter === k ? " active" : ""}" onclick="setDailyFilter('${k}')">${esc(lbl)} <span class="count">${n}</span></button>`
  ).join("");

  renderDailyList();
  showOnlySection("daily-results-section");
  if (scroll) document.getElementById("daily-results-section").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderDailyList() {
  if (!currentDailyResult) return;
  const rows = filteredDailyItems(currentDailyResult);
  const container = document.getElementById("daily-results-list");
  const pgEl = document.getElementById("daily-pagination");
  const pageSize = Number(document.getElementById("daily-page-size")?.value || 25);

  if (!rows.length) {
    container.innerHTML = `<div class="card">${emptyState("All clear in this filter", "Try expanding the time window or clearing search/classification filters.")}</div>`;
    if (pgEl) pgEl.innerHTML = "";
    return;
  }

  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  if (dailyPage > totalPages) dailyPage = totalPages;
  const start = (dailyPage - 1) * pageSize;
  const pageRows = rows.slice(start, start + pageSize);

  container.innerHTML = pageRows.map(item => {
    const score = dailySeverityScore(item);
    const cls = item.classification || ((item.match_types || []).some(m => m === "openphish_feed" || m === "phishingdb_feed" || m === "daily_title") ? "Confirmed Impersonation" : "Potential Impersonation");
    const isHigh = cls === "Confirmed Impersonation" || (item.platforms || []).length > 1;
    const sevCls = isHigh ? "sev-high" : "sev-med";
    const clsBadge = cls === "Confirmed Impersonation" ? "badge-danger" : "badge-warning";
    const rootDom = item.registered_domain || item.apex_domain || apexFromDomain(item.domain);
    const loc = detectKeywordLocation(item, currentDailyResult?.target);
    const fullUrl = safeExternalDomainUrl(item.domain, item.url);
    const explanation = buildDetectionExplanation(item, currentDailyResult?.target);
    const primarySourceUrl = item.result_url || sourceReferenceUrl((item.platforms || [])[0], item.domain, item.url);

    return `
    <article class="finding-card ${sevCls} reveal">
      <div class="finding-card-top">
        <div class="finding-card-id">
          <div class="row" style="gap: 8px; align-items: center;">
            <span class="score ${scoreClass(score)}" title="Daily Threat Score">${score}</span>
            <h3 class="finding-title-lg">${esc(item.domain)}</h3>
            ${copyBtn(item.domain, "Domain copied")}
          </div>
          <div class="row" style="gap: 6px; margin-top: 8px;">
            <span class="badge badge-sm ${clsBadge}">${esc(cls)}</span>
            ${item.matching_subdomain ? `<span class="badge badge-sm badge-purple">Subdomain: ${esc(item.matching_subdomain)}</span>` : ""}
            ${item.matched_keyword ? `<span class="badge badge-sm badge-accent">Keyword: ${esc(item.matched_keyword)}${item.similarity_percent ? ` · ${Math.round(item.similarity_percent)}%` : ""}</span>` : ""}
            ${(item.matches || []).map(m => pfBadge(m.platform)).join("")}
            ${item.first_seen ? `<span class="badge badge-sm badge-mono" title="Discovery timestamp">${esc(String(item.first_seen).slice(0, 16))}</span>` : ""}
          </div>
        </div>

        <div class="finding-card-actions">
          ${openDomainBtn(item.domain, fullUrl)}
          <button type="button" class="btn btn-secondary btn-xs" data-copy="${esc(fullUrl || item.domain)}" data-copy-label="Complete URL copied">Copy URL</button>
          ${primarySourceUrl ? linkBtn(primarySourceUrl, "Source ↗", "Open discovery source reference", "btn btn-secondary btn-xs") : ""}
          <button type="button" class="btn btn-primary btn-xs" onclick="huntFromDaily('${esc(rootDom || item.domain)}')">Full 360° Hunt</button>
        </div>
      </div>

      ${item.title && item.title !== item.domain ? `<div class="finding-subtitle">Live Page Title: ${esc(item.title)}</div>` : ""}

      <p class="finding-desc">${esc(explanation)}</p>

      <div class="finding-meta-strip">
        <span><strong>Registered Root:</strong> <code class="mono">${esc(rootDom)}</code></span>
        <span><strong>Match Location:</strong> ${esc(loc)}</span>
        ${item.matching_technique ? `<span><strong>Technique:</strong> ${esc(item.matching_technique)}</span>` : ""}
        ${item.similarity_percent ? `<span><strong>Similarity:</strong> ${Math.round(item.similarity_percent)}%</span>` : ""}
        <span><strong>Original Brand:</strong> <code class="mono">${esc(currentDailyResult?.target || "")}</code></span>
      </div>

      <details class="finding-disclosure">
        <summary>Inspect Evidence, Discovery Source Breakdown &amp; Root Pivots</summary>
        <div class="dossier-grid">
          <div class="dossier-card">
            <h4>A. Domain Breakdown</h4>
            ${kvRows([
              ["Discovered Domain", item.domain],
              ["Registered Root", rootDom],
              ["Matching Subdomain", item.matching_subdomain || "None"],
              ["Original Brand", currentDailyResult?.target],
              ["Matched Keyword", item.matched_keyword || "Pattern / feed match"],
              ["Location", loc],
            ])}
          </div>
          <div class="dossier-card">
            <h4>B. Detection Evidence</h4>
            ${kvRows([
              ["Classification", cls],
              ["Technique", item.matching_technique],
              ["Similarity", item.similarity_percent ? `${item.similarity_percent}%` : ""],
              ["Signals", item.description],
              ["Live IP", item.ip],
            ])}
          </div>
          <div class="dossier-card">
            <h4>C. Source Transparency</h4>
            <div class="stack" style="gap: 6px;">
              ${(item.matches || []).map(m => {
                const sUrl = sourceReferenceUrl(m.platform, item.domain, m.platform === "urlscan" ? item.result_url : item.url);
                return `<div class="src-item">
                  <div><strong>${esc(SOURCE_LABELS[m.platform] || m.platform)}</strong> · <span class="src-role">Discovery</span><div class="hint">${esc(MATCH_LABELS[m.match] || m.match)}</div></div>
                  ${sUrl ? linkBtn(sUrl, "Open ↗", `Inspect on ${SOURCE_LABELS[m.platform] || m.platform}`, "btn btn-ghost btn-xs") : ""}
                </div>`;
              }).join("")}
            </div>
          </div>
        </div>
        <div style="margin-top: 12px; display: flex; flex-wrap: wrap; align-items: center; gap: 6px;">
          <span class="hint" style="font-weight: 600; margin-right: 4px;">Root &amp; Pivot Links:</span>
          ${rootDomainPivotsHtml(item.domain, item.ip || "")}
        </div>
      </details>
    </article>`;
  }).join("");

  if (pgEl) pgEl.innerHTML = paginationControlsHtml(rows.length, dailyPage, pageSize, "setDailyPage");
}

function huntFromDaily(domain) {
  switchTab("hunt");
  const input = document.getElementById("hunt-target-input");
  if (input) {
    input.value = domain;
    input.focus();
  }
}

function exportDailyCSV() {
  if (!currentDailyResult) return;
  const rows = filteredDailyItems(currentDailyResult);
  const cols = ["domain", "registered_domain", "matching_subdomain", "matched_keyword", "matching_technique", "similarity_percent", "classification", "apex_domain", "platforms", "match_types", "title", "description", "first_seen", "url", "result_url"];
  const lines = [cols.join(",")].concat(rows.map(r => [
    r.domain, r.registered_domain || r.apex_domain, r.matching_subdomain || "", r.matched_keyword || "",
    r.matching_technique || "", r.similarity_percent ?? "", r.classification || "",
    r.apex_domain, (r.platforms || []).join(";"), (r.match_types || []).join(";"),
    r.title, r.description, r.first_seen, r.url, r.result_url,
  ].map(csvCell).join(",")));
  downloadBlob("\uFEFF" + lines.join("\r\n") + "\r\n", `daily_intel_${currentDailyResult.target}.csv`, "text/csv;charset=utf-8;");
  showToast(`CSV downloaded (${plural(rows.length, "row")})`);
}
