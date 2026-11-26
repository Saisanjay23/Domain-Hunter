"use strict";
// =============================================================================
// Dork Generator & Live Multi-Source Capture
// =============================================================================

function loadImpersonationSample(type) {
  const samples = {
    banks: "chase.com, wellsfargo.com, hsbc.com, barclays.com",
    crypto: "binance.com, metamask.io, coinbase.com, ledger.com",
    brands: "paypal.com, netflix.com, microsoft.com, apple.com",
    cyber: "okta.com, crowdstrike.com, zscaler.com, paloaltonetworks.com",
  };
  const input = document.getElementById("impersonation-input");
  input.value = samples[type] || "";
  input.focus();
}

const DORK_TYPES = {
  fofa: [
    ["all_domains", "All domains (*=)", "Substring *= across domain, host, cert, CNAME (membership)"],
    ["subdomain_spoof", "Subdomain impersonations (keyword.*)", "Hosts starting with or embedding keyword as a subdomain"],
    ["exhaustive", "Deep capture (domains+body+headers)", "Matches domain, host, cert, CNAME, title, HTML body, and redirect headers"],
    ["scam_lures", "Scam & phishing lures", "Matches login, verify, KYC, OTP, seed-phrase, wallet, or support kits"],
    ["free_hosting", "Free hosting & cloud", "Brand pages on pages.dev, workers.dev, vercel, firebase, s3, trycloudflare"],
    ["idn_homoglyph", "IDN Punycode (xn--)", "Unicode homoglyph domains impersonating the brand"],
    ["master", "Master (free tier)", "Token match across title, host, domain, cert"],
    ["title_spoof", "Title"],
    ["domain_wildcard", "Host token"],
    ["domain_contains", "Host contains"],
    ["cert_wildcard", "Certificate"],
    ["body_content", "Page body"],
  ],
  censys: [
    ["all_domains", "All domains (regex)", "Case-insensitive CenQL regex across web.hostname, cert.names, and host.dns.names"],
    ["subdomain_spoof", "Subdomain impersonations (keyword.*)", "CenQL regex matching keyword.attacker.tld"],
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
    ["daily_search", "Daily search (24h Domain + Title)", "Last 24h URLScan matches for page.domain keywords or page.title brand titles"],
    ["subdomain_spoof", "Subdomain impersonations (keyword.*)", "Catches example.something.tld (free URLScan syntax)"],
    ["daily_domain", "Daily domain keyword (24h)", "Last 24h page.domain keyword matches excluding own domain"],
    ["daily_title", "Daily brand title (24h)", "Last 24h page.title brand matches excluding own domain"],
    ["all_domains", "All domains (.keyword)", "Full infix/prefix/suffix match on page.domain.keyword & task.domain.keyword"],
    ["exhaustive", "Deep capture (domains+URLs+assets+titles)", "Catches compromised sites, redirect sources, and sub-resources"],
    ["scam_lures", "Scam & phishing lures", "Combines brand with login, verify, kyc, refund, wallet, offer lures"],
    ["free_hosting", "Free hosting & cloud", "Catches kits on pages.dev, workers.dev, vercel, netlify, firebase"],
    ["idn_homoglyph", "IDN Punycode (xn--)", "Catches Unicode homoglyph domains even anonymously"],
    ["master", "Master (free tier)", "Anonymous-safe: title, domain prefix, page.url, task.url & filename prefix"],
    ["domain_wildcard", "Domain prefix"],
    ["url_prefix", "URL token (free)"],
    ["domain_contains", "Domain contains"],
    ["title_spoof", "Title"],
    ["body_content", "Page text"],
  ],
  shodan: [
    ["all_domains", "Hostnames (PTR)", "Comma-separated OR across PTR/DNS hostnames"],
    ["subdomain_spoof", "Subdomain hostnames (keyword.)", "Shodan hostname search for keyword-prefixed subdomains"],
    ["ssl_all", "SSL all (CN + SANs)", "Searches all SSL/TLS certificate data including SANs"],
    ["scam_lures", "Scam login pages", "HTML containing both the brand keyword and password prompts"],
    ["master", "Master (Cert CN)", "Comma-separated OR across SSL Subject CN"],
    ["title_spoof", "Title"],
    ["cert_wildcard", "Cert CN"],
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
      rows = subQueryRow("All domains (*=)", item.all_domains_query, item.all_domains_url, "Substring wildcard across domain, host, cert, CNAME") +
        subQueryRow("Subdomains (keyword.*)", item.subdomain_query, item.subdomain_url, "Hosts matching keyword as a subdomain label") +
        subQueryRow("Deep (domains+body+headers)", item.exhaustive_query, item.exhaustive_url) +
        subQueryRow("Scam & phishing lures", item.scam_lures_query, item.scam_lures_url) +
        subQueryRow("Free hosting & cloud", item.free_hosting_query, item.free_hosting_url) +
        subQueryRow("IDN Punycode (xn--)", item.idn_query, item.idn_url) +
        subQueryRow("Master (free)", item.query, item.url);
    } else if (p === "censys") {
      rows = subQueryRow("All domains (regex)", item.all_domains_query, item.all_domains_url) +
        subQueryRow("Subdomains (keyword.*)", item.subdomain_query, item.subdomain_url) +
        subQueryRow("Deep (domains+title+body)", item.exhaustive_query, item.exhaustive_url) +
        subQueryRow("Scam & phishing lures", item.scam_lures_query, item.scam_lures_url) +
        subQueryRow("Free hosting & cloud", item.free_hosting_query, item.free_hosting_url) +
        subQueryRow("IDN Punycode (xn--)", item.idn_query, item.idn_url) +
        subQueryRow("Tokenized", item.query, item.url);
    } else if (p === "urlscan") {
      rows = subQueryRow("Daily Search (24h Domain+Title)", item.daily_search_query, item.daily_search_url, "24h daily page.domain + page.title match excluding own domains") +
        subQueryRow("Subdomains (keyword.*)", item.subdomain_query, item.subdomain_url, "Catches keyword.attacker.com subdomain impersonations (free)") +
        subQueryRow("Daily Domain (24h)", item.daily_domain_query, item.daily_domain_url) +
        subQueryRow("Daily Title (24h)", item.daily_title_query, item.daily_title_url) +
        subQueryRow("All domains", item.all_domains_query, item.all_domains_url) +
        subQueryRow("Deep (domains+URLs+assets)", item.exhaustive_query, item.exhaustive_url) +
        subQueryRow("Scam & phishing lures", item.scam_lures_query, item.scam_lures_url) +
        subQueryRow("Free hosting & cloud", item.free_hosting_query, item.free_hosting_url) +
        subQueryRow("IDN Punycode (xn--)", item.idn_query, item.idn_url) +
        subQueryRow("Master (free)", item.query, item.url) +
        subQueryRow("Titles", item.title_query, item.title_url) +
        subQueryRow("Domains", item.domain_query, item.domain_url) +
        subQueryRow("Page text (Pro)", item.body_query, item.body_url);
    } else if (p === "shodan") {
      rows = subQueryRow("Hostnames (PTR)", item.hostname_query, item.hostname_url) +
        subQueryRow("Subdomains (keyword.)", item.subdomain_query, item.subdomain_url) +
        subQueryRow("SSL all (CN+SAN)", item.ssl_query, item.ssl_url) +
        subQueryRow("Scam login pages", item.scam_lures_query, item.scam_lures_url) +
        subQueryRow("Cert CN", item.query, item.url);
    }
    const w = document.createElement("div");
    w.innerHTML = platformCard(p, rows,
      `<button type="button" class="btn btn-ghost btn-xs" data-imp-platform="${p}" title="Open each keyword's search in its own tab">Open per keyword</button>`);
    w.querySelector("[data-imp-platform]").addEventListener("click", () => openImpersonationPlatformTabs(p));
    masterGrid.appendChild(w.firstElementChild);
  });

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
      inurl: "URL & domain", credential_lure: "Credential / KYC lures", wildcard_site: "Wildcard domain",
      free_hosting: "Free hosting kits", scam_campaigns: "Fake support / jobs / offers",
      social_and_apps: "Social, Telegram & APKs", leaks_and_redirects: "Code leaks & redirects",
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
        <div class="spread">${pfLabel(p)}${linkBtn(primaryUrl, `Open search`, `Open query on ${PLATFORMS[p].name}`, "btn btn-ghost btn-xs")}</div>
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
      keywords: rawInput, include_variants: includeVariants,
      use_ct: true, use_intel: true, use_feeds: true, use_dns: useDns,
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

  // Sources that were skipped or failed are logged on Settings > API keys, not shown here.
  document.getElementById("imp-capture-sources").innerHTML = (data.source_status || []).filter(s => s.ran && !s.error).map(s => {
    const dot = "dot-success";
    const detail = `${s.count}`;
    return `<span class="source-pill" title="${esc(s.query || s.error || "")}"><span class="dot ${dot}"></span>${esc(s.source)} <em>${esc(detail)}</em></span>`;
  }).join("");

  const tbody = document.getElementById("imp-capture-tbody");
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="6">${emptyState("No matching domains found", "Try broadening keywords, enabling typosquat variants, or adding threat-intel API keys in Settings.")}</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.slice(0, 500).map(d => `
    <tr class="plain">
      <td data-label="Domain"><span class="domain-name">${esc(d.domain)}</span>${d.domain !== d.apex_domain ? ` <span class="badge badge-sm badge-purple">Subdomain</span>` : ""}${d.ip ? `<div class="hint mono">${esc(d.ip)}</div>` : ""}</td>
      <td data-label="Apex" class="mono">${esc(d.apex_domain)}</td>
      <td data-label="Sources"><div class="row" style="gap:4px;">${(d.sources || []).map(s => pfBadge(s)).join("")}</div></td>
      <td data-label="Title">${esc(d.title || "-")}</td>
      <td data-label="Last seen" class="nowrap">${esc((d.last_seen || "").slice(0, 10) || "-")}</td>
      <td class="col-actions">
        <div class="row" style="justify-content:flex-end;">
          ${openDomainBtn(d.domain, d.url)}
          ${copyBtn(d.domain, "Domain copied")}
          ${d.url ? openIcon(d.url, "Open captured reference") : ""}
          ${linkBtn(`https://urlscan.io/search/#${encodeURIComponent("domain:" + d.apex_domain)}`, "Root", `URLScan domain:${d.apex_domain}`, "btn btn-ghost btn-xs")}
          ${linkBtn(`https://crt.sh/?q=${encodeURIComponent("%." + d.apex_domain)}`, "crt.sh", `Inspect certificates for %.${d.apex_domain}`, "btn btn-ghost btn-xs")}
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

function copyCapturedUrls() {
  copyDomainUrls(filteredCapturedDomains(), "Captured Domains");
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
  setHeroMode("hunt");
  const input = document.getElementById("hunt-target-input");
  if (input) { input.value = domain; input.focus(); }
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
  downloadBlob("\uFEFF" + rows.join("\r\n") + "\r\n", `impersonation_dorks_${new Date().toISOString().slice(0, 10)}.csv`, "text/csv;charset=utf-8;");
  showToast("CSV downloaded");
}
