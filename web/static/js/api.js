"use strict";
// =============================================================================
// Domain Hunter (Created by Sai Sanjay): Shared State, Platform Metadata & API Helpers
// =============================================================================

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
let currentDailyResult = null;
let huntJobId = null;
let huntPollTimer = null;
let huntFilter = "risky";
let huntPlatformFilter = "all";
let huntView = "lookalikes";
let huntRowLimit = 100;
let huntPage = 1;
let dailyFilter = "all";
let dailyPage = 1;
let currentTab = "hunt";
let heroMode = "hunt";
window.iconStore = {};
window.reverseCandidateStore = {};

const PLATFORMS = {
  fofa: { name: "FOFA" },
  shodan: { name: "Shodan" },
  censys: { name: "Censys" },
  urlscan: { name: "URLScan" },
};
const PLATFORM_KEYS = Object.keys(PLATFORMS);

const SOURCE_LABELS = {
  urlscan: "URLScan.io",
  whoisxml: "WhoisXML",
  virustotal: "VirusTotal",
  shodan: "Shodan",
  fofa: "FOFA",
  censys: "Censys",
  serpapi: "Google Lens",
  "google-lens": "Google Lens",
  "crt.sh": "crt.sh",
  nrd_free: "Free Daily NRD",
  openphish: "OpenPhish",
  phishingdb: "Phishing.Database",
  permutation: "Live Typosquats",
  bing: "Bing Search",
  duckduckgo: "DuckDuckGo",
  wayback: "Wayback CDX",
  hackertarget: "HackerTarget IP",
  publicwww: "PublicWWW",
  safebrowsing: "Google Safe Browsing",
  otx: "AlienVault OTX",
};

const PLATFORM_DESCRIPTIONS = {
  urlscan: "Free live browser scans matching page.domain keywords & page.title brand hits",
  whoisxml: "Optional API: newly registered/updated lookalike domains",
  virustotal: "Optional API: malicious/suspicious domain & subdomain intelligence",
  shodan: "Internet-facing servers serving your favicon hash, HTML title or TLS certs",
  fofa: "Global web assets matching favicon MMH3, hostname substrings & headers",
  censys: "Host & web property certificates, HTML titles & favicon MD5/SHA-256",
  "google-lens": "Reverse visual matches of your brand logo across the open web",
  serpapi: "Automated Google Lens reverse logo search",
  "crt.sh": "Free public Certificate Transparency logs issuing SSL certs for brand terms",
  nrd_free: "100% Free open-source feed of newly registered domains worldwide",
  openphish: "Free live phishing URLs verified by the OpenPhish community feed",
  phishingdb: "Free curated database of active phishing domains",
  permutation: "Free live DNS & webpage title probe of brand typosquats and combosquats",
  bing: "Free automated search engine dork results across Bing",
  duckduckgo: "Free automated web discovery via DuckDuckGo",
  wayback: "Historical & free-hosting impersonations from Internet Archive CDX",
  hackertarget: "Automated Step-7 reverse-IP cluster discovery",
  safebrowsing: "Optional API: Google's phishing / malware lists for every candidate",
  otx: "Free passive DNS: sibling hostnames under suspicious registered domains",
};

const CENSYS_MD5_FIELDS = ["host.services.endpoints.http.favicons.hash_md5", "web.endpoints.http.favicons.hash_md5"];

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
    case "whoisxml": return "https://brand-alert.whoisxmlapi.com/";
    case "virustotal": return `https://www.virustotal.com/gui/search/${encodeURIComponent(q)}`;
    case "bing": return `https://www.bing.com/search?q=${encodeURIComponent(q)}`;
    case "duckduckgo": return `https://duckduckgo.com/?q=${encodeURIComponent(q)}`;
    case "wayback": return `https://web.archive.org/web/*/${encodeURIComponent(q)}`;
    case "publicwww": return `https://publicwww.com/web/${encodeURIComponent(q)}/`;
    default: return "";
  }
}

function apexFromDomain(domain) {
  const host = String(domain || "").trim().toLowerCase().replace(/:\d+$/, "");
  const parts = host.split(".").filter(Boolean);
  if (parts.length <= 2) return host;
  const twoPartTlds = new Set(["co.uk", "org.uk", "ac.uk", "com.au", "co.in", "net.in", "org.in", "co.za", "com.br", "com.sg", "com.hk", "co.jp", "ne.jp"]);
  const tail2 = parts.slice(-2).join(".");
  if (parts.length >= 3 && twoPartTlds.has(tail2)) return parts.slice(-3).join(".");
  return tail2;
}

function rootDomainPivotsHtml(domain, ip = "") {
  const apex = apexFromDomain(domain);
  if (!apex) return "";
  const reverseTarget = ip || apex;
  return [
    linkBtn(`https://urlscan.io/search/#${encodeURIComponent("domain:" + apex)}`, `URLScan Root (${apex})`, `Search all scans on root host ${apex}`, "btn btn-ghost btn-xs"),
    linkBtn(`https://crt.sh/?q=${encodeURIComponent("%." + apex)}`, `crt.sh Root`, `Inspect certificate history for %.${apex}`, "btn btn-ghost btn-xs"),
    linkBtn(`https://lookup.icann.org/en/lookup?name=${encodeURIComponent(apex)}`, "ICANN WHOIS", `Registrar & registration details for ${apex}`, "btn btn-ghost btn-xs"),
    linkBtn(`https://viewdns.info/reverseip/?host=${encodeURIComponent(reverseTarget)}&t=1`, "Reverse IP", `Find other domains sharing ${reverseTarget}`, "btn btn-ghost btn-xs"),
    linkBtn(`https://securitytrails.com/domain/${encodeURIComponent(apex)}/dns`, "SecurityTrails", `DNS & NS history for ${apex}`, "btn btn-ghost btn-xs"),
    linkBtn(`https://phishstats.info/`, "PhishStats", "Search PhishStats URL/title database", "btn btn-ghost btn-xs"),
  ].join("");
}

const fofaIconQuery = h => `icon_hash="${h}"`;
const shodanIconQuery = h => `http.favicon.hash:${h}`;
const censysMd5Query = m => CENSYS_MD5_FIELDS.map(f => `${f}: "${m}"`).join(" or ");
const urlscanHashQuery = s => `hash:${s}`;
const isFaviconLike = icon => (icon.kind || "favicon") !== "logo";

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
  '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="1.6"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/></svg>');

function esc(value) {
  return String(value ?? "").replace(/[&<>"'`]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" })[c]);
}

function copyBtn(text, label = "Copied") {
  if (text === null || text === undefined || text === "") return "";
  return `<button type="button" class="icon-btn" data-copy="${esc(text)}" data-copy-label="${esc(label)}" aria-label="Copy" title="Copy to clipboard">${I.copy}</button>`;
}

function openIcon(url, title = "Open in new tab") {
  if (!url) return "";
  return `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer" class="icon-btn" aria-label="${esc(title)}" title="${esc(title)}">${I.external}</a>`;
}

function linkBtn(url, label, title = "", cls = "btn btn-secondary btn-xs") {
  if (!url) return "";
  return `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer" class="${cls}" title="${esc(title || label)}" onclick="event.stopPropagation()">${esc(label)}</a>`;
}

// =============================================================================
// Shared Forensics Formatting: Safe External Open, Explainable Reasoning & Sources
// =============================================================================
function safeExternalDomainUrl(domain, rawUrl = "") {
  const candidate = String(rawUrl || "").trim();
  if (/^https?:\/\//i.test(candidate)) return candidate;
  const host = String(domain || "").trim().replace(/^https?:\/\//i, "").split("/")[0];
  if (!host || !host.includes(".") || /[\s<>"'`]/.test(host)) return "";
  return `https://${host}`;
}

function openDomainBtn(domain, rawUrl = "", cls = "btn btn-xs btn-open-domain") {
  const href = safeExternalDomainUrl(domain, rawUrl);
  if (!href) return "";
  return `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer" class="${cls}" title="Open untrusted domain in a new tab (noopener, noreferrer)" onclick="event.stopPropagation()">Open Domain ↗</a>`;
}

function candidateUrl(item) {
  if (!item) return "";
  if (typeof item === "string") return safeExternalDomainUrl(item);
  const evUrl = item.evidence?.http?.final_url;
  if (evUrl && /^https?:\/\//i.test(evUrl)) return evUrl;
  if (item.url && /^https?:\/\//i.test(item.url)) return item.url;
  const intelUrl = (item.intel || []).find(i => i?.url && /^https?:\/\//i.test(i.url))?.url;
  if (intelUrl) return intelUrl;
  return safeExternalDomainUrl(item.domain || item.host || "");
}

function collectDomainUrls(items, resolver = candidateUrl) {
  return [...new Set((items || []).map(resolver).filter(Boolean))];
}

function copyDomainUrls(items, label = "tab results", resolver = candidateUrl) {
  const urls = collectDomainUrls(items, resolver);
  if (!urls.length) {
    showToast(label ? `No domain URLs in ${label}` : "No domain URLs to copy");
    return 0;
  }
  copyText(urls.join("\n"), `Copied ${plural(urls.length, "domain URL")} (${label})`);
  return urls.length;
}

function syncCopyUrlButtons(ids, items, resolver = candidateUrl) {
  const count = collectDomainUrls(items, resolver).length;
  (ids || []).forEach(id => {
    const btn = document.getElementById(id);
    if (!btn) return;
    btn.innerText = count ? `Copy URLs (${count.toLocaleString()})` : "Copy URLs";
    btn.disabled = !count;
  });
}

function detectKeywordLocation(item, origApex) {
  const dom = String(item?.domain || "").toLowerCase();
  const root = String(item?.registered_domain || item?.apex_domain || apexFromDomain(dom)).toLowerCase();
  const sub = String(item?.matching_subdomain || "").trim();
  if (sub || (dom && root && dom !== root && item?.fuzzer === "brand-subdomain")) {
    return "Subdomain";
  }
  if (item?.matched_keyword) return "Registered Domain";
  return "Content / Intel";
}

function confidenceMeta(item) {
  const score = Number(item?.score ?? 0);
  const ev = item?.evidence || {};
  const intel = item?.intel || [];
  const strongContent = !!(ev.favicon?.exact_match || ev.shared_analytics?.length || ev.brand_in_title || (ev.brand_resources || 0) > 0);
  const feedHit = intel.some(i => ["feed", "openphish_feed", "phishingdb_feed"].includes(i.match));
  const sim = Number(item?.similarity_percent || 0);
  if (strongContent || feedHit || score >= 70) return { label: "High", cls: "badge-danger" };
  if (item?.matching_subdomain || sim >= 80 || score >= 40 || (item?.platforms || item?.sources || []).length >= 2) {
    return { label: "Medium", cls: "badge-warning" };
  }
  return { label: "Low", cls: "" };
}

function buildDetectionExplanation(item, origDomain = "") {
  const dom = item?.domain || "";
  const root = item?.registered_domain || item?.apex_domain || apexFromDomain(dom);
  const sub = item?.matching_subdomain || (dom !== root ? dom.slice(0, Math.max(0, dom.length - root.length - 1)) : "");
  const orig = item?.original_domain || origDomain || "target brand";
  const kw = item?.matched_keyword || "";
  const tech = item?.matching_technique || item?.fuzzer || "pattern matching";
  const sim = item?.similarity_percent ? `${Math.round(item.similarity_percent)}%` : "";
  const cls = item?.classification || "";
  const ev = item?.evidence || {};
  const rd = item?.rdap || {};

  if (item?.verdict === "brand_owned" || item?.verdict === "redirect_brand") {
    return `Verified safe asset: ${dom} is confirmed as brand-owned or redirects cleanly to ${orig}.`;
  }
  if (item?.match_meta?.is_benign_collision && cls === "Benign/Unrelated") {
    return `Suppressed false positive: '${dom}' superficially overlaps a short brand stem (${kw || orig}), but reflects a common dictionary word with no supporting impersonation evidence.`;
  }

  const parts = [];
  if (sub && kw) {
    parts.push(
      `The hostname '${dom}' was flagged because '${sub}' matches the target keyword '${kw}' in the subdomain portion rather than the registered root domain '${root}', which is unrelated to '${orig}'.`
    );
  } else if (kw) {
    parts.push(
      `Flagged via ${tech}${sim ? ` (${sim} similarity)` : ""} because '${dom}' matches brand keyword '${kw}' against the official domain '${orig}'.`
    );
  } else {
    parts.push(`Flagged against '${orig}' via ${tech}${sim ? ` (${sim} similarity)` : ""}.`);
  }

  const cues = [];
  if (ev.favicon?.exact_match) cues.push("served a byte-identical brand favicon");
  if (ev.brand_in_title && ev.title) cues.push(`used brand page title "${ev.title.slice(0, 55)}"`);
  if (ev.password_form) cues.push("hosts a credential/password login form");
  if ((ev.shared_analytics || []).length) cues.push(`embedded brand analytics ID (${ev.shared_analytics[0]})`);
  if ((item?.intel || []).some(i => i.match === "feed") || (item?.match_types || []).some(m => m === "openphish_feed" || m === "phishingdb_feed")) {
    cues.push("listed in active phishing threat feeds");
  }
  if (rd.age_days !== null && rd.age_days !== undefined && rd.age_days <= 30) {
    cues.push(`newly registered ${rd.age_days} day(s) ago`);
  }
  if (cues.length) parts.push(`Supporting evidence: ${cues.join(", ")}.`);
  return parts.join(" ");
}

function sourceReferenceUrl(source, domain, directUrl = "") {
  if (directUrl && /^https?:\/\//i.test(directUrl)) return directUrl;
  const s = String(source || "").toLowerCase();
  if (s === "crt.sh") return `https://crt.sh/?q=${encodeURIComponent(domain)}`;
  if (s === "urlscan") return `https://urlscan.io/search/#${encodeURIComponent("page.domain:" + domain)}`;
  if (s === "virustotal") return `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`;
  if (s === "wayback") return `https://web.archive.org/web/*/${encodeURIComponent(domain)}`;
  if (s === "whoisxml") return `https://whois.whoisxmlapi.com/lookup?domainName=${encodeURIComponent(domain)}`;
  return "";
}

function renderDistBarChart(title, entries, color = "var(--accent)") {
  const maxVal = Math.max(1, ...entries.map(([, n]) => n));
  return `
    <div class="dist-card">
      <div class="section-label" style="margin-bottom: 10px;">${esc(title)}</div>
      <div class="dist-list">
        ${entries.length ? entries.slice(0, 6).map(([label, n]) => `
          <div class="dist-row">
            <div class="dist-head"><span class="dist-label" title="${esc(label)}">${esc(label)}</span><span class="dist-val">${Number(n).toLocaleString()}</span></div>
            <div class="dist-track"><div class="dist-bar" style="width:${Math.max(4, Math.round((n / maxVal) * 100))}%; background:${color};"></div></div>
          </div>`).join("") : `<span class="hint">No breakdown available yet</span>`}
      </div>
    </div>`;
}

function paginationControlsHtml(total, page, pageSize, onPageFn) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const cur = Math.min(Math.max(1, page), totalPages);
  const start = total ? (cur - 1) * pageSize + 1 : 0;
  const end = Math.min(total, cur * pageSize);
  return `
    <div class="pagination-controls">
      <span>Showing <strong>${start.toLocaleString()}–${end.toLocaleString()}</strong> of <strong>${total.toLocaleString()}</strong></span>
      <button type="button" class="btn btn-secondary btn-xs" ${cur <= 1 ? "disabled" : ""} onclick="${onPageFn}(${cur - 1})">← Prev</button>
      <span class="badge badge-sm">Page ${cur} / ${totalPages}</span>
      <button type="button" class="btn btn-secondary btn-xs" ${cur >= totalPages ? "disabled" : ""} onclick="${onPageFn}(${cur + 1})">Next →</button>
    </div>`;
}

function pfSlug(src) {
  const s = String(src || "").toLowerCase();
  if (s === "crt.sh") return "crtsh";
  if (s === "nrd_free") return "nrdfree";
  if (s === "google-lens" || s === "serpapi") return "serpapi";
  return s.replace(/[^a-z0-9-]/g, "");
}

function pfLabel(p) {
  return `<span class="pf pf-${esc(pfSlug(p))}">${esc(SOURCE_LABELS[p] || PLATFORMS[p]?.name || p)}</span>`;
}

function pfBadge(source, detail = "") {
  const slug = pfSlug(source);
  const name = SOURCE_LABELS[source] || PLATFORMS[source]?.name || source;
  const label = detail ? `${name} · ${detail}` : name;
  return `<span class="pf-badge pf-badge-${esc(slug)}" title="${esc(PLATFORM_DESCRIPTIONS[source] || name)}">${esc(label)}</span>`;
}

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

document.addEventListener("click", e => {
  const el = e.target.closest("[data-copy]");
  if (!el) return;
  e.preventDefault();
  e.stopPropagation();
  copyText(el.dataset.copy, el.dataset.copyLabel || "Copied");
});

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
  if (window.setScanPulse) window.setScanPulse(!!on || !!huntJobId);
}

async function apiPost(path, body) {
  const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  let data = null;
  try { data = await res.json(); } catch (e) { /* non-JSON */ }
  if (!res.ok) {
    const detail = data && data.detail;
    throw new Error(typeof detail === "string" ? detail : (detail ? JSON.stringify(detail) : `HTTP ${res.status}`));
  }
  return data;
}

async function settingsCall(method, path, body) {
  const res = await fetch(path, { method, headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
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

// Theme handling (applyTheme / currentTheme / cycleTheme) lives in shell.js.
