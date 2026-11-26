"use strict";
// =============================================================================
// Asset Scan, Batch Scan, Logo Inspector & Hash Aggregator
// =============================================================================

function getPrimaryBrandIcon() {
  const icons = currentResult?.icons || [];
  return icons.find(i => i.is_primary && i.phash) || icons.find(i => i.kind === "logo" && i.phash) || icons.find(i => i.phash) || null;
}

function setTarget(domain) {
  const input = document.getElementById("target-input");
  if (input) { input.value = domain; input.focus(); }
}

async function handleSingleScan(e) {
  e.preventDefault();
  const target = document.getElementById("target-input").value.trim();
  if (!target) return;
  const btn = document.getElementById("btn-scan");
  await runAssetScan(target, {
    include_logos: document.getElementById("toggle-logos").checked,
    probe_subdomains: document.getElementById("toggle-probe-subdomains").checked,
    save_icons: document.getElementById("toggle-save-icons").checked,
    timeout: 12,
  }, btn);
}

async function runAssetScan(target, opts = {}, btn = null) {
  setBusy(btn, true, "Scanning…");
  setLoading(true, `Crawling ${target}: homepage, manifests, fallbacks & subdomain portals`);
  showOnlySection(null);
  try {
    const data = await apiPost("/api/scan", {
      target,
      include_logos: opts.include_logos ?? true,
      probe_subdomains: opts.probe_subdomains ?? true,
      save_icons: opts.save_icons ?? true,
      timeout: opts.timeout ?? 12,
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
  showOnlySection("results-section");
  if (scroll) section.scrollIntoView({ behavior: "smooth", block: "start" });
}

const KIND_BADGES = {
  logo: `<span class="badge badge-sm badge-purple" title="Brand logo / og:image. Used for visual pHash comparison and URLScan resource search.">Logo</span>`,
  subdomain: `<span class="badge badge-sm badge-warning" title="Subdomain portal icon. Excluded from master queries to prevent shared SaaS false positives.">Subdomain portal</span>`,
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
  card.className = "asset-card reveal";
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
  downloadBlob("\uFEFF" + rows.join("\r\n") + "\r\n", filename, "text/csv;charset=utf-8;");
  showToast("CSV downloaded");
}

function openTab(url) {
  const w = window.open(url, "_blank");
  if (w) w.opener = null;
  return w;
}

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
  } catch (err) { /* fallback */ }
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
