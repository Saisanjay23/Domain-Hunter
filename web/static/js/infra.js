"use strict";
// =============================================================================
// Infrastructure Investigator: one domain -> linked infrastructure, operator dossier, predictions
// Self-contained canvas force graph (no external libraries, works offline).
// =============================================================================

let currentInfra = null;
let infraJobId = null;
let infraPollTimer = null;
let infraGraph = null;

const INFRA_TYPES = {
  domain: { label: "Domain", color: "#60a5fa" },
  ip: { label: "IP address", color: "#22d3ee" },
  asn: { label: "ASN / network", color: "#a78bfa" },
  ns: { label: "Name server", color: "#34d399" },
  cert: { label: "TLS certificate", color: "#facc15" },
  favicon: { label: "Favicon", color: "#f472b6" },
  title: { label: "Page title", color: "#e2e8f0" },
  analytics: { label: "Analytics ID", color: "#c084fc" },
  telegram_bot: { label: "Telegram bot", color: "#38bdf8" },
  telegram_handle: { label: "Telegram handle", color: "#7dd3fc" },
  telegram_chat: { label: "Telegram chat", color: "#0ea5e9" },
  wallet: { label: "Crypto wallet", color: "#fde047" },
  email: { label: "E-mail", color: "#f9a8d4" },
  exfil_host: { label: "Data-collection host", color: "#ef4444" },
  registrar: { label: "Registrar", color: "#94a3b8" },
  registrant: { label: "Public registrant", color: "#fb7185" },
};
const CONF_COLOR = { seed: "#fbbf24", high: "#f43f5e", medium: "#fb923c", low: "#60a5fa", unlinked: "#64748b", clone: "#e11d48", victim: "#10b981" };
const CONF_LABEL = { seed: "Seed", high: "High: same operator", medium: "Medium: likely related", low: "Low: shared hosting only", unlinked: "Unlinked",
  clone: "Impersonator: copies the seed", victim: "Impersonated brand (victim)" };
const EDGE_STYLE = { strong: { w: 2.1, a: 0.85, len: 95 }, medium: { w: 1.3, a: 0.5, len: 125 }, weak: { w: 0.8, a: 0.22, len: 170 } };

function setInfraTarget(v) {
  const el = document.getElementById("infra-target-input");
  if (el) { el.value = v; el.focus(); }
}

function investigateDomain(domain) {
  switchTab("infra");
  setInfraTarget(domain);
  startInvestigation({ target: domain });
}

async function handleInfraSubmit(e) {
  e.preventDefault();
  const target = document.getElementById("infra-target-input").value.trim();
  if (!target) return showToast("Enter a domain, hostname or URL");
  const keywords = (document.getElementById("infra-keywords").value || "").split(/[,;\n]+/).map(x => x.trim()).filter(Boolean);
  startInvestigation({
    target, keywords,
    depth: Number(document.getElementById("infra-depth").value || 2),
    max_domains: Number(document.getElementById("infra-max").value || 30),
  });
}

async function startInvestigation(payload) {
  const btn = document.getElementById("btn-infra-run");
  setBusy(btn, true, "Investigating…");
  showOnlySection(null);
  document.getElementById("infra-progress").hidden = false;
  renderInfraProgress({ progress: 1, message: `Starting investigation of ${payload.target}…`, stage: "queued" });
  try {
    const { job_id } = await apiPost("/api/investigate", payload);
    infraJobId = job_id;
    clearTimeout(infraPollTimer);
    pollInvestigation();
  } catch (err) {
    setBusy(btn, false);
    document.getElementById("infra-progress").hidden = true;
    showToast(err.message || "Could not start the investigation", 4200);
  }
}

async function cancelInvestigation() {
  if (!infraJobId) return;
  try { await fetch(`/api/investigate/${infraJobId}`, { method: "DELETE" }); } catch (e) { /* ignore */ }
}

async function pollInvestigation() {
  if (!infraJobId) return;
  try {
    const job = await (await fetch(`/api/investigate/${infraJobId}`)).json();
    renderInfraProgress(job);
    if (job.status === "running") {
      infraPollTimer = setTimeout(pollInvestigation, 1200);
      return;
    }
    setBusy(document.getElementById("btn-infra-run"), false);
    document.getElementById("infra-progress").hidden = true;
    infraJobId = null;
    if (job.status === "done") {
      currentInfra = job.result;
      renderInfra(job.result);
      loadInfraHistory();
    } else {
      showToast(job.message || "Investigation stopped", 4200);
    }
  } catch (e) {
    infraPollTimer = setTimeout(pollInvestigation, 2500);
  }
}

function renderInfraProgress(job) {
  document.getElementById("infra-progress-bar").style.width = `${Math.max(2, job.progress || 0)}%`;
  document.getElementById("infra-progress-msg").innerText = job.message || "";
  document.getElementById("infra-progress-stage").innerText = (job.stage || "").toUpperCase();
}

// ----------------------------------------------------------------------------- dossier
function confPill(level) {
  return `<span class="conf-pill conf-${esc(level)}">${esc(CONF_LABEL[level] || level)}</span>`;
}

function topList(items, empty = "None observed") {
  if (!items || !items.length) return `<span class="muted">${esc(empty)}</span>`;
  return items.map(i => `${esc(i.value)}${i.count > 1 ? ` <span class="muted">×${i.count}</span>` : ""}`).join("<br>");
}

function gaugeSvg(value) {
  const r = 54, c = 2 * Math.PI * r, v = Math.max(0, Math.min(100, value || 0));
  const color = v >= 70 ? "#f43f5e" : v >= 40 ? "#fb923c" : "#22d3ee";
  return `<div class="infra-gauge" title="Operation sophistication (infrastructure size, diversity, evasion, kit features)">
    <svg width="132" height="132" viewBox="0 0 132 132"><circle cx="66" cy="66" r="${r}" fill="none" stroke="rgba(148,163,184,.18)" stroke-width="10"/>
    <circle cx="66" cy="66" r="${r}" fill="none" stroke="${color}" stroke-width="10" stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${c * (1 - v / 100)}" style="filter: drop-shadow(0 0 8px ${color}); transition: stroke-dashoffset 1.2s cubic-bezier(.22,1,.36,1)"/></svg>
    <div class="lbl"><b>${v}</b><span>Sophistication</span></div></div>`;
}

function renderInfra(data) {
  renderInfraChanges(data);
  const a = data.actor || {};
  const s = data.stats || {};
  const ips = new Set((data.nodes || []).filter(n => n.type === "ip").map(n => n.label));
  const asns = new Set((data.nodes || []).filter(n => n.type === "asn").map(n => n.label));
  document.getElementById("infra-hero").innerHTML = `
    <div class="infra-hero-grid">
      <div>
        <div class="infra-eyebrow">${a.mode === "legitimate" ? "Organisation footprint · no malicious behaviour observed" : a.mode === "malicious" ? (a.purpose_confirmed === false ? "Brand impersonation · purpose not confirmed" : `Threat operation · ${esc(a.confidence || "")} confidence cluster`) : a.mode === "suspicious" ? "Suspected impersonation · content not confirmed" : "Infrastructure investigation"}</div>
        <div class="infra-seed">${esc(data.seed)}</div>
        <div class="infra-summary">${esc(a.summary || "")}</div>
        <div class="infra-kpis">
          <div class="infra-kpi"><b>${a.cluster_size || 0}</b><span>Linked domains</span></div>
          <div class="infra-kpi"><b>${s.linked_high || 0}</b><span>Same operator</span></div>
          <div class="infra-kpi"><b>${s.linked_medium || 0}</b><span>Likely related</span></div>
          <div class="infra-kpi"><b>${ips.size}</b><span>IP addresses</span></div>
          <div class="infra-kpi"><b>${asns.size}</b><span>Networks</span></div>
          <div class="infra-kpi"><b>${s.domains_profiled || 0}</b><span>Fingerprinted</span></div>
          <div class="infra-kpi"><b>${s.elapsed_sec ?? "-"}s</b><span>Elapsed</span></div>
        </div>
      </div>
      ${a.mode === "legitimate" ? `<div class="infra-gauge" title="No phishing kit, credential form on a new domain, wallet or exfiltration was seen on any linked site">
        <svg width="132" height="132" viewBox="0 0 132 132"><circle cx="66" cy="66" r="54" fill="none" stroke="#10b981" stroke-width="10" style="filter: drop-shadow(0 0 8px #10b981)"/></svg>
        <div class="lbl"><b style="font-size:20px;">Clean</b><span>No malicious<br>behaviour seen</span></div></div>` : gaugeSvg(a.sophistication)}
    </div>`;

  const attr = a.attribution || {};
  const infra = a.infrastructure || {};
  const pred = a.predictions || {};
  const linked = (data.domains || []).filter(d => d.link_confidence !== "unlinked");
  const legit = a.mode === "legitimate";
  const clones = a.clones || [];
  const chips = (arr, cls = "badge-mono") => (arr || []).map(v => `<span class="badge badge-sm ${cls}">${esc(v)}</span>`).join(" ");
  document.getElementById("infra-dossier").innerHTML = `
    ${clones.length ? `<div class="infra-card danger w12"><h4>${legit ? "Sites impersonating this domain" : "Clones of this page elsewhere"} <span class="n">${clones.length} found · same title / favicon / layout on another registered domain</span></h4>
      <div class="infra-tablewrap"><table class="infra-table"><thead><tr><th>Domain</th><th>Registered domain</th><th>Copied</th><th>Live</th><th></th></tr></thead><tbody>
      ${clones.map(c => `<tr><td class="dn">${esc(c.domain)}</td><td class="mono">${esc(c.root)}</td><td class="why">${esc(c.evidence.slice(0, 2).join(" · "))}</td>
        <td>${c.live ? `<span class="badge badge-sm badge-danger">live</span>` : `<span class="muted">${c.profiled ? "no" : "not checked"}</span>`}</td>
        <td><button type="button" class="btn btn-primary btn-xs" onclick="investigateDomain('${esc(c.domain)}')">Investigate</button></td></tr>`).join("")}
      </tbody></table></div></div>` : ""}
    <div class="infra-card ${legit ? "" : "danger"} w6"><h4>${legit ? "Behaviour observed" : "What they are doing"} <span class="n">${(a.intent || []).length} intent(s)</span></h4>
      ${(a.intent || []).map(i => `<div class="intent-row"><div class="top"><span>${esc(i.label)}</span><span class="muted">${i.domains} site(s)</span></div>
        <div class="meter"><span style="width:${Math.round((i.share || 0) * 100)}%"></span></div>
        <div class="ev">${esc((i.evidence || [])[0] || "")}</div></div>`).join("") || `<span class="muted">No page content collected (sites offline or not live yet).</span>`}
      <div class="infra-note" style="margin-top:8px;">${esc(a.status || "")}</div>
    </div>

    <div class="infra-card warn w6"><h4>${legit ? "Brand names in this estate" : "Who / what they target"}</h4>
      <div class="tags">${(a.targets || []).map(t => `<span class="badge ${t.inferred ? "" : "badge-danger"}" title="${t.inferred ? "Inferred from repeated naming tokens" : "Known brand in names / titles"}">${esc(t.value)}${t.count > 1 ? ` ×${t.count}` : ""}</span>`).join("") || `<span class="muted">No specific brand identified</span>`}</div>
      ${(a.impersonated_originals || []).length ? `<div class="infra-note" style="margin-top:10px;">Impersonated original (the victim): ${a.impersonated_originals.map(o => `<span class="badge badge-sm badge-success">${esc(o)}</span>`).join(" ")}</div>` : ""}
      <h4 style="margin-top:16px;">${legit ? "Ownership" : "Who is behind it"} <span class="n">public data only</span></h4>
      <dl class="infra-kv">
        <dt>Registrant</dt><dd>${(attr.public_registrants || []).map(r => esc([r.org || r.name, r.email, r.country].filter(Boolean).join(" · ") + ` (${r.domain})`)).join("<br>") || `<span class="muted">privacy-protected / not published</span>`}</dd>
        <dt>Telegram</dt><dd>${chips(attr.telegram) || `<span class="muted">none in the kit</span>`}</dd>
        <dt>Wallets</dt><dd>${chips(attr.wallets) || `<span class="muted">none seen</span>`}</dd>
        <dt>E-mails</dt><dd>${chips(attr.contact_emails) || `<span class="muted">none seen</span>`}</dd>
        <dt>Collects data at</dt><dd>${chips(attr.exfil_hosts, "badge-danger") || `<span class="muted">same site / unknown</span>`}</dd>
        <dt>Report to</dt><dd>${chips(attr.abuse_contacts) || `<span class="muted">see registrar / host</span>`}</dd>
      </dl>
      <div class="infra-note" style="margin-top:10px;">${esc(attr.note || "")}</div>
    </div>

    <div class="infra-card"><h4>Infrastructure habits</h4>
      <dl class="infra-kv">
        <dt>TLDs</dt><dd>${topList(infra.tlds)}</dd><dt>Registrars</dt><dd>${topList(infra.registrars)}</dd>
        <dt>Networks</dt><dd>${topList(infra.asns)}</dd><dt>Hosting</dt><dd>${topList(infra.hosting)}</dd>
        <dt>Countries</dt><dd>${topList(infra.countries)}</dd><dt>Certificates</dt><dd>${topList(infra.cert_issuers)}</dd>
      </dl></div>

    <div class="infra-card purple"><h4>Tradecraft &amp; style</h4>
      <ul class="infra-list">${(a.style || []).map(x => `<li>${esc(x)}</li>`).join("") || `<li>Not enough evidence yet</li>`}</ul>
      <div style="margin-top:12px;">${(a.attack || []).map(t => `<a class="attack-chip" href="https://attack.mitre.org/techniques/${esc(t.id.replace(".", "/"))}/" target="_blank" rel="noopener" title="${esc(t.evidence)}"><code>${esc(t.id)}</code>${esc(t.name)}</a>`).join("")}</div>
    </div>

    <div class="infra-card"><h4>Timeline <span class="n">${(a.timeline || []).length} events</span></h4>
      <ol class="infra-timeline">${(a.timeline || []).slice().reverse().map(t => `<li><time>${esc(t.date)}</time>${esc(t.event)}</li>`).join("") || `<li><time>—</time>No dated events (registration data hidden)</li>`}</ol></div>

    <div class="infra-card danger w12"><h4>${legit ? "Lookalikes to watch or register defensively" : "What they will likely do next"} <span class="n">${legit ? "names an impersonator would pick, checked in DNS" : "projections from observed behaviour"}</span></h4>
      <div class="grid-2" style="gap:16px;">
        <div><ul class="infra-list">${legit ? `<li>No hostile activity to project from this estate. Registered look-alikes on the right are the ones to check first.</li>` : (pred.outlook || []).map(x => `<li>${esc(x)}</li>`).join("") || `<li>Not enough activity to project.</li>`}</ul>
          <dl class="infra-kv" style="margin-top:12px;"><dt>Next TLDs</dt><dd>${esc((pred.likely_tlds || []).join(", ") || "-")}</dd>
          <dt>Next registrar</dt><dd>${esc((pred.likely_registrars || []).join(", ") || "-")}</dd>
          <dt>Next hosting</dt><dd>${esc((pred.likely_hosting || []).join(", ") || "-")}</dd></dl></div>
        <div><div class="infra-note" style="margin-bottom:6px;">Domains their naming pattern predicts, checked in DNS just now:</div>
          <div class="infra-tablewrap"><table class="infra-table"><thead><tr><th>Predicted domain</th><th>State</th><th></th></tr></thead><tbody>
          ${(pred.next_domains || []).map(p => `<tr><td class="dn">${esc(p.domain)}</td><td><span class="pred-state pred-${esc(p.state)}">${esc(p.state)}</span>${p.resolves ? ` <span class="badge badge-sm badge-danger">live</span>` : ""}</td>
            <td>${p.state === "registered" ? `<button type="button" class="btn btn-ghost btn-xs" onclick="investigateDomain('${esc(p.domain)}')">Investigate</button>` : ""}</td></tr>`).join("") || `<tr><td colspan="3" class="muted">No target brand identified to project from.</td></tr>`}
          </tbody></table></div></div>
      </div></div>

    <div class="infra-card w12"><h4>Linked domains <span class="n">${linked.length} of ${(data.domains || []).length} fingerprinted</span></h4>
      <div class="infra-tablewrap"><table class="infra-table"><thead><tr><th>Domain</th><th>Link</th><th>Why linked</th><th>Intent</th><th>Created</th><th>Hosting</th><th>Title</th><th></th></tr></thead><tbody>
      ${(data.domains || []).map(d => `<tr>
        <td class="dn">${esc(d.domain)}</td><td>${confPill(d.link_confidence)}</td>
        <td class="why">${esc((d.link_path || []).slice(-1)[0] || d.discovered_via || "")}</td>
        <td>${(d.intent || []).map(i => `<span class="badge badge-sm ${i.intent === "staged" ? "" : "badge-danger"}" title="${esc(i.evidence)}">${esc(i.label)}</span>`).join(" ")}</td>
        <td class="mono">${esc(((d.rdap || {}).created || "").slice(0, 10))}</td>
        <td>${esc([(d.asn || {}).asn, (d.asn || {}).country].filter(Boolean).join(" · "))}<br><span class="muted">${esc((d.dns.a || [])[0] || "")}</span></td>
        <td>${esc((d.title || "").slice(0, 60))}${d.blocked ? `<br><span class="badge badge-sm badge-warning" title="The live page returned a bot-protection challenge, not its content">${esc(d.blocked)}</span>` : ""}${d.page_via === "urlscan" ? `<br><a class="muted" href="${esc(d.scan_url || "#")}" target="_blank" rel="noopener">via URLScan scan ${esc(d.observed || "")}</a>` : ""}</td>
        <td><button type="button" class="btn btn-ghost btn-xs" onclick="infraFocus('domain:${esc(d.domain)}')">Show</button></td></tr>`).join("")}
      </tbody></table></div></div>

    <div class="infra-card w12"><h4>Method &amp; sources</h4>
      <div class="infra-note">${esc(data.disclaimer || "")} Sources used: ${(data.sources || []).map(x => `${esc(x.source)} (${x.calls})`).join(", ") || "-"}.
</div></div>`;

  showOnlySection("infra-results-section");
  requestAnimationFrame(() => {
    if (infraGraph) infraGraph.destroy();
    infraGraph = new InfraGraph(document.getElementById("infra-stage"), data);
  });
}

function infraFocus(id) {
  if (!infraGraph) return;
  document.getElementById("infra-stage").scrollIntoView({ behavior: "smooth", block: "center" });
  infraGraph.select(id, true);
}

function copyInfraUrls() {
  if (!currentInfra) return showToast("Run an Infrastructure investigation first");
  copyDomainUrls(currentInfra.domains || [], "Infrastructure");
}

function exportInfra(kind) {
  if (!currentInfra) return;
  const name = `infra-${currentInfra.seed}`;
  if (kind === "json") downloadBlob(JSON.stringify(currentInfra, null, 2), `${name}.json`, "application/json");
  else if (kind === "png" && infraGraph) {
    const a = document.createElement("a");
    a.href = infraGraph.canvas.toDataURL("image/png");
    a.download = `${name}-graph.png`;
    a.click();
  } else if (kind === "iocs") {
    const rows = [["type", "value", "confidence"]];
    for (const d of currentInfra.domains || []) {
      if (!["seed", "high", "medium"].includes(d.link_confidence)) continue;
      rows.push(["domain", d.domain, d.link_confidence]);
      (d.dns.a || []).forEach(ip => rows.push(["ipv4", ip, d.link_confidence]));
      for (const [k, vals] of Object.entries(d.artifacts || {})) {
        if (["analytics", "telegram_bots", "wallets", "emails", "exfil_hosts", "telegram_handles"].includes(k)) vals.forEach(v => rows.push([k, v, d.link_confidence]));
      }
    }
    const csv = [...new Set(rows.map(r => r.map(csvCell).join(",")))].join("\n");
    downloadBlob(csv + "\n", `${name}-iocs.csv`, "text/csv");
  }
}

// ----------------------------------------------------------------------------- graph engine
class InfraGraph {
  constructor(stage, data) {
    this.stage = stage;
    this.canvas = stage.querySelector("canvas");
    this.ctx = this.canvas.getContext("2d");
    this.tip = stage.querySelector(".infra-tip");
    this.panel = stage.querySelector(".infra-panel");
    this.hidden = new Set(["registrar"]);
    this.linkedOnly = false;
    this.showLabels = true;
    this.running = true;
    this.view = { x: 0, y: 0, k: 1 };
    this.hover = null;
    this.selected = null;
    this.t0 = performance.now();
    this.build(data);
    this.bind();
    this.resize();
    this.alpha = 1;
    this.legend();
    // Settle most of the layout before the first frame, so the graph opens calm and centred.
    for (let i = 0; i < 260 && this.alpha > 0.02; i++) this.step();
    this.fit();
    this.autoFitPending = true;
    this.loop = this.loop.bind(this);
    this.raf = requestAnimationFrame(this.loop);
  }

  build(data) {
    const seedId = `domain:${data.seed}`;
    // Sites copying a legitimate seed are a different, hostile actor: draw them as impersonators, not estate.
    const clones = new Set(((data.actor || {}).clones || []).map(c => `domain:${c.domain}`));
    const deg = {};
    (data.edges || []).forEach(e => { deg[e.source] = (deg[e.source] || 0) + 1; deg[e.target] = (deg[e.target] || 0) + 1; });
    this.nodes = (data.nodes || []).map((n, i) => {
      const conf = n.type === "domain" ? (n.data.confidence || "unlinked") : null;
      const isSeed = n.id === seedId;
      const angle = (i / Math.max(1, data.nodes.length)) * Math.PI * 2;
      const dist = isSeed ? 0 : 80 + Math.random() * 260;
      return {
        ...n, conf: clones.has(n.id) ? "clone" : n.data.role === "impersonated brand" ? "victim" : conf, seed: isSeed, deg: deg[n.id] || 0,
        x: Math.cos(angle) * dist, y: Math.sin(angle) * dist, vx: 0, vy: 0, fixed: false,
        r: isSeed ? 17 : n.type === "domain" ? (clones.has(n.id) ? 12 : conf === "high" ? 11 : conf === "medium" ? 9.5 : 7.5) + Math.min(5, (deg[n.id] || 0) * 0.4) : 5.5 + Math.min(4, (deg[n.id] || 0) * 0.35),
        color: n.type === "domain" ? CONF_COLOR[isSeed ? "seed" : clones.has(n.id) ? "clone" : n.data.role === "impersonated brand" ? "victim" : conf] : (INFRA_TYPES[n.type] || {}).color || "#cbd5e1",
      };
    });
    this.byId = Object.fromEntries(this.nodes.map(n => [n.id, n]));
    this.edges = (data.edges || []).map(e => ({ ...e, s: this.byId[e.source], t: this.byId[e.target] })).filter(e => e.s && e.t);
    this.adj = {};
    this.edges.forEach(e => {
      (this.adj[e.s.id] = this.adj[e.s.id] || []).push(e);
      (this.adj[e.t.id] = this.adj[e.t.id] || []).push(e);
    });
  }

  visible(n) {
    if (this.hidden.has(n.type)) return false;
    if (this.linkedOnly) {
      if (n.type === "domain") return ["seed", "high", "medium"].includes(n.seed ? "seed" : n.conf);
      return (this.adj[n.id] || []).some(e => {
        const o = e.s === n ? e.t : e.s;
        return o.type === "domain" && (o.seed || ["high", "medium"].includes(o.conf));
      });
    }
    return true;
  }

  bind() {
    const c = this.canvas;
    this.onResize = () => this.resize();
    window.addEventListener("resize", this.onResize);
    let drag = null, pan = null, moved = false;
    const pos = ev => {
      const r = c.getBoundingClientRect();
      return { sx: ev.clientX - r.left, sy: ev.clientY - r.top };
    };
    c.addEventListener("pointerdown", ev => {
      const p = pos(ev);
      const n = this.pick(p.sx, p.sy);
      moved = false;
      c.setPointerCapture(ev.pointerId);
      c.classList.add("dragging");
      this.autoFitPending = false;
      if (n) { drag = n; n.fixed = true; this.alpha = Math.max(this.alpha, 0.3); }
      else pan = { sx: p.sx, sy: p.sy, x: this.view.x, y: this.view.y };
    });
    c.addEventListener("pointermove", ev => {
      const p = pos(ev);
      if (drag) {
        const w = this.toWorld(p.sx, p.sy);
        drag.x = w.x; drag.y = w.y; drag.vx = drag.vy = 0; moved = true;
        this.alpha = Math.max(this.alpha, 0.25);
      } else if (pan) {
        this.view.x = pan.x + (p.sx - pan.sx); this.view.y = pan.y + (p.sy - pan.sy); moved = true;
      } else {
        const n = this.pick(p.sx, p.sy);
        if (n !== this.hover) { this.hover = n; this.showTip(n, p); }
        else if (n) this.moveTip(p);
      }
    });
    const up = ev => {
      c.classList.remove("dragging");
      if (!moved) {
        const p = pos(ev);
        const n = this.pick(p.sx, p.sy);
        this.select(n ? n.id : null);
      }
      if (drag && !ev.shiftKey) drag.fixed = false;
      drag = null; pan = null;
    };
    c.addEventListener("pointerup", up);
    c.addEventListener("pointerleave", () => { this.hover = null; this.tip.hidden = true; });
    c.addEventListener("wheel", ev => {
      ev.preventDefault();
      this.autoFitPending = false;
      const p = pos(ev);
      const k = Math.max(0.15, Math.min(4, this.view.k * Math.exp(-ev.deltaY * 0.0015)));
      const w = this.toWorld(p.sx, p.sy);
      this.view.k = k;
      this.view.x = p.sx - this.W / 2 - w.x * k;
      this.view.y = p.sy - this.H / 2 - w.y * k;
    }, { passive: false });
    c.addEventListener("dblclick", () => this.fit());
  }

  destroy() {
    cancelAnimationFrame(this.raf);
    window.removeEventListener("resize", this.onResize);
    const fresh = this.canvas.cloneNode(false);
    this.canvas.replaceWith(fresh);
    this.panel.hidden = true;
    this.tip.hidden = true;
  }

  resize() {
    const r = this.stage.getBoundingClientRect();
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    this.W = r.width; this.H = r.height;
    this.canvas.width = r.width * dpr; this.canvas.height = r.height * dpr;
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  toWorld(sx, sy) { return { x: (sx - this.W / 2 - this.view.x) / this.view.k, y: (sy - this.H / 2 - this.view.y) / this.view.k }; }

  pick(sx, sy) {
    const w = this.toWorld(sx, sy);
    let best = null, bd = Infinity;
    for (const n of this.nodes) {
      if (!this.visible(n)) continue;
      const d = Math.hypot(n.x - w.x, n.y - w.y);
      if (d < n.r + 6 / this.view.k && d < bd) { best = n; bd = d; }
    }
    return best;
  }

  fit() {
    const vis = this.nodes.filter(n => this.visible(n));
    if (!vis.length) return;
    const xs = vis.map(n => n.x), ys = vis.map(n => n.y);
    const minX = Math.min(...xs), maxX = Math.max(...xs), minY = Math.min(...ys), maxY = Math.max(...ys);
    const k = Math.max(0.2, Math.min(2.2, 0.85 * Math.min(this.W / Math.max(80, maxX - minX), (this.H - 90) / Math.max(80, maxY - minY))));
    this.view = { k, x: -((minX + maxX) / 2) * k, y: -((minY + maxY) / 2) * k };
  }

  step() {
    const vis = this.nodes.filter(n => this.visible(n));
    const a = this.alpha;
    for (let i = 0; i < vis.length; i++) {
      const p = vis[i];
      for (let j = i + 1; j < vis.length; j++) {
        const q = vis[j];
        let dx = q.x - p.x, dy = q.y - p.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 0.01) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 0.5; }
        if (d2 > 250000) continue;
        // labelled domain nodes push each other harder so their names don't collide
        const f = ((p.type === "domain" && q.type === "domain" ? 2600 : 1100) * a) / d2;
        const d = Math.sqrt(d2);
        p.vx -= (dx / d) * f; p.vy -= (dy / d) * f;
        q.vx += (dx / d) * f; q.vy += (dy / d) * f;
      }
    }
    for (const e of this.edges) {
      if (!this.visible(e.s) || !this.visible(e.t)) continue;
      const st = EDGE_STYLE[e.strength] || EDGE_STYLE.weak;
      const dx = e.t.x - e.s.x, dy = e.t.y - e.s.y;
      const d = Math.max(1, Math.hypot(dx, dy));
      const f = ((d - st.len) / d) * 0.06 * a * (e.strength === "weak" ? 0.5 : 1);
      e.s.vx += dx * f; e.s.vy += dy * f;
      e.t.vx -= dx * f; e.t.vy -= dy * f;
    }
    for (const n of vis) {
      n.vx -= n.x * 0.004 * a; n.vy -= n.y * 0.004 * a;
      if (n.seed) { n.vx -= n.x * 0.05; n.vy -= n.y * 0.05; }
      if (n.fixed) { n.vx = n.vy = 0; continue; }
      n.vx *= 0.82; n.vy *= 0.82;
      n.x += Math.max(-30, Math.min(30, n.vx));
      n.y += Math.max(-30, Math.min(30, n.vy));
    }
    this.alpha = Math.max(0, this.alpha * 0.985);
  }

  loop(now) {
    if (this.running && this.alpha > 0.008) this.step();
    else if (this.autoFitPending) { this.autoFitPending = false; this.fit(); }
    this.draw(now);
    this.raf = requestAnimationFrame(this.loop);
  }

  neighbors(n) {
    const set = new Set([n.id]);
    (this.adj[n.id] || []).forEach(e => { set.add(e.s.id); set.add(e.t.id); });
    return set;
  }

  draw(now) {
    const ctx = this.ctx, W = this.W, H = this.H, v = this.view;
    const t = (now - this.t0) / 1000;
    ctx.clearRect(0, 0, W, H);
    ctx.save();
    ctx.translate(W / 2 + v.x, H / 2 + v.y);
    ctx.scale(v.k, v.k);
    const focus = this.selected || this.hover;
    const near = focus ? this.neighbors(focus) : null;

    for (const e of this.edges) {
      if (!this.visible(e.s) || !this.visible(e.t)) continue;
      const st = EDGE_STYLE[e.strength] || EDGE_STYLE.weak;
      const lit = near && near.has(e.s.id) && near.has(e.t.id) && (e.s === focus || e.t === focus);
      const dim = near && !lit;
      ctx.globalAlpha = dim ? 0.05 : lit ? 1 : st.a;
      ctx.strokeStyle = e.strength === "strong" ? "#f43f5e" : e.strength === "medium" ? "#93c5fd" : "#64748b";
      ctx.lineWidth = (lit ? st.w + 1 : st.w) / Math.sqrt(v.k);
      if (e.strength === "weak") ctx.setLineDash([4, 5]);
      else if (e.strength === "strong") { ctx.setLineDash([10, 6]); ctx.lineDashOffset = -t * 22; }
      else ctx.setLineDash([]);
      ctx.beginPath(); ctx.moveTo(e.s.x, e.s.y); ctx.lineTo(e.t.x, e.t.y); ctx.stroke();
    }
    ctx.setLineDash([]);

    for (const n of this.nodes) {
      if (!this.visible(n)) continue;
      const dim = near && !near.has(n.id);
      ctx.globalAlpha = dim ? 0.15 : 1;
      if (n.seed) {
        const pr = n.r + 6 + 10 * ((t * 0.6) % 1);
        ctx.strokeStyle = n.color; ctx.lineWidth = 2 / v.k; ctx.globalAlpha = dim ? 0.1 : 0.7 * (1 - ((t * 0.6) % 1));
        ctx.beginPath(); ctx.arc(n.x, n.y, pr, 0, Math.PI * 2); ctx.stroke();
        ctx.globalAlpha = dim ? 0.15 : 1;
      }
      ctx.shadowColor = n.color;
      ctx.shadowBlur = n.seed || n.conf === "high" ? 22 : n.type === "domain" ? 10 : 6;
      const g = ctx.createRadialGradient(n.x - n.r / 3, n.y - n.r / 3, n.r * 0.2, n.x, n.y, n.r);
      g.addColorStop(0, "#ffffff"); g.addColorStop(0.25, n.color); g.addColorStop(1, n.color);
      ctx.fillStyle = n.type === "domain" ? g : n.color;
      ctx.beginPath();
      if (n.type === "domain") ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      else this.shape(ctx, n);
      ctx.fill();
      ctx.shadowBlur = 0;
      if (n === this.selected) { ctx.strokeStyle = "#fff"; ctx.lineWidth = 2.5 / v.k; ctx.stroke(); }
      if (n.conf === "clone") {
        ctx.strokeStyle = "#fecdd3"; ctx.lineWidth = 1.6 / v.k; ctx.setLineDash([3, 3]);
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 5, 0, Math.PI * 2); ctx.stroke(); ctx.setLineDash([]);
      }
      const strongDomain = n.type === "domain" && (n.seed || n.conf === "high" || n.conf === "clone" || n.conf === "victim" || (n.conf === "medium" && n.data.profiled));
      const showLabel = n === focus || (near && near.has(n.id)) || (this.showLabels &&
        (strongDomain ? v.k > 0.35 : n.type === "domain" ? v.k > 1.3 : v.k > 1.6));
      if (showLabel) {
        ctx.font = `${n.seed ? 700 : 500} ${Math.max(9, 11.5 / Math.sqrt(v.k))}px Inter, system-ui, sans-serif`;
        ctx.fillStyle = n.type === "domain" ? "#e2e8f0" : "#94a3b8";
        ctx.textAlign = "center";
        const lab = n.label.length > 34 ? n.label.slice(0, 32) + "…" : n.label;
        ctx.fillText(lab, n.x, n.y + n.r + 13 / Math.sqrt(v.k));
      }
    }
    ctx.restore();
    ctx.globalAlpha = 1;
  }

  shape(ctx, n) {
    const r = n.r;
    if (n.type === "ip" || n.type === "asn") { ctx.rect(n.x - r, n.y - r, r * 2, r * 2); return; }
    if (["telegram_bot", "telegram_handle", "telegram_chat", "wallet", "exfil_host", "registrant"].includes(n.type)) {
      for (let i = 0; i < 6; i++) {
        const ang = Math.PI / 3 * i - Math.PI / 6;
        ctx[i ? "lineTo" : "moveTo"](n.x + r * 1.15 * Math.cos(ang), n.y + r * 1.15 * Math.sin(ang));
      }
      ctx.closePath(); return;
    }
    ctx.moveTo(n.x, n.y - r * 1.2); ctx.lineTo(n.x + r * 1.1, n.y); ctx.lineTo(n.x, n.y + r * 1.2); ctx.lineTo(n.x - r * 1.1, n.y); ctx.closePath();
  }

  showTip(n, p) {
    if (!n) { this.tip.hidden = true; return; }
    const type = n.type === "domain" ? (n.seed ? "Seed domain" : `Domain · ${CONF_LABEL[n.conf] || n.conf}`) : (INFRA_TYPES[n.type] || {}).label || n.type;
    const d = n.data || {};
    const extra = [d.title && `“${d.title}”`, d.org, d.country, d.created && `created ${d.created}`, d.cohosted && `${d.cohosted} domains on this IP`,
      (d.intent || []).join(", ")].filter(Boolean).slice(0, 3);
    this.tip.innerHTML = `<div class="k">${esc(type)}</div><b>${esc(n.label)}</b>${extra.length ? `<div>${esc(extra.join(" · "))}</div>` : ""}<div class="k" style="margin-top:4px;">${(this.adj[n.id] || []).length} connection(s) · click for evidence</div>`;
    this.tip.hidden = false;
    this.moveTip(p);
  }

  moveTip(p) {
    const x = Math.min(p.sx, this.W - 330), y = Math.min(p.sy, this.H - 110);
    this.tip.style.left = `${x}px`; this.tip.style.top = `${y}px`;
  }

  select(id, center = false) {
    const n = id ? this.byId[id] : null;
    this.selected = n;
    if (!n) { this.panel.hidden = true; return; }
    if (center) { this.view.k = Math.max(this.view.k, 1.1); this.view.x = -n.x * this.view.k; this.view.y = -n.y * this.view.k; }
    const d = n.data || {};
    const rows = Object.entries(d).filter(([k, v]) => !["seed", "profiled", "confidence", "mainstream"].includes(k) && v !== null && v !== "" && !(Array.isArray(v) && !v.length));
    const edges = (this.adj[n.id] || []).slice().sort((a, b) => ({ strong: 0, medium: 1, weak: 2 }[a.strength] - { strong: 0, medium: 1, weak: 2 }[b.strength]));
    const dom = n.type === "domain" ? (currentInfra?.domains || []).find(x => x.domain === n.label) : null;
    this.panel.innerHTML = `
      <button type="button" class="infra-tbtn x" onclick="infraGraph.select(null)" aria-label="Close">✕</button>
      <div class="sub">${esc(n.type === "domain" ? (n.seed ? "Seed domain" : "Domain") : (INFRA_TYPES[n.type] || {}).label || n.type)}</div>
      <h5>${esc(n.label)}</h5>
      ${n.type === "domain" ? confPill(n.seed ? "seed" : n.conf) : ""}
      <dl>${rows.map(([k, v]) => `<dt>${esc(k.replace(/_/g, " "))}</dt><dd>${esc(Array.isArray(v) ? v.join(", ") : v)}</dd>`).join("")}
        ${dom ? `<dt>IP / ASN</dt><dd>${esc([(dom.dns.a || [])[0], (dom.asn || {}).asn, (dom.asn || {}).as_name].filter(Boolean).join(" · "))}</dd>
        <dt>Registrar</dt><dd>${esc((dom.rdap || {}).registrar || "-")}</dd>` : ""}</dl>
      ${dom && (dom.link_path || []).length ? `<div class="sub" style="margin:8px 0 4px;">Evidence chain to the seed</div>${dom.link_path.map(p => `<div class="edge">${esc(p)}</div>`).join("")}` : ""}
      <div class="sub" style="margin:10px 0 4px;">Connections (${edges.length})</div>
      ${edges.slice(0, 40).map(e => { const o = e.s === n ? e.t : e.s; return `<div class="edge"><span class="conf-pill conf-${e.strength === "strong" ? "high" : e.strength === "medium" ? "medium" : "unlinked"}">${esc(e.strength)}</span> ${esc(e.relation)} → <b>${esc(o.label)}</b><div class="muted">${esc(e.evidence)} · ${esc(e.via)}</div></div>`; }).join("")}
      ${n.type === "domain" && !n.seed ? `<button type="button" class="btn btn-primary btn-sm" style="margin-top:12px;width:100%;" onclick="investigateDomain('${esc(n.label)}')">Investigate this domain</button>` : ""}`;
    this.panel.hidden = false;
  }

  legend() {
    const present = new Set(this.nodes.map(n => n.type));
    const el = this.stage.querySelector(".infra-legend");
    const confs = ["seed", "high", "medium", "low", ...["clone", "victim"].filter(k => this.nodes.some(n => n.conf === k))].map(c => `<button type="button" style="color:${CONF_COLOR[c]}" disabled><i></i>${esc(CONF_LABEL[c])}</button>`).join("");
    el.innerHTML = confs + Object.entries(INFRA_TYPES).filter(([k]) => k !== "domain" && present.has(k)).map(([k, m]) =>
      `<button type="button" class="${this.hidden.has(k) ? "off" : ""}" style="color:${m.color}" onclick="infraGraph.toggleType('${k}', this)"><i></i>${esc(m.label)}</button>`).join("");
  }

  toggleType(k, btn) {
    if (this.hidden.has(k)) this.hidden.delete(k); else this.hidden.add(k);
    btn.classList.toggle("off", this.hidden.has(k));
    this.alpha = Math.max(this.alpha, 0.4);
  }

  toggle(opt, btn) {
    if (opt === "linked") { this.linkedOnly = !this.linkedOnly; btn.classList.toggle("on", this.linkedOnly); this.alpha = 0.6; setTimeout(() => this.fit(), 700); }
    if (opt === "labels") { this.showLabels = !this.showLabels; btn.classList.toggle("on", this.showLabels); }
    if (opt === "physics") { this.running = !this.running; btn.classList.toggle("on", this.running); if (this.running) this.alpha = 0.5; }
  }
}

// ----------------------------------------------------------------------------- investigation history (MongoDB)
const INFRA_HIST = { q: "", items: [], total: 0, limit: 8 };
const INFRA_MODE = { malicious: ["badge-danger", "Malicious"], suspicious: ["badge-warning", "Suspicious"], unclear: ["", "Unclear"], legitimate: ["badge-success", "Legitimate"] };

async function loadInfraHistory() {
  const box = document.getElementById("infra-history");
  if (!box) return;
  try {
    const qs = new URLSearchParams({ q: INFRA_HIST.q, limit: INFRA_HIST.limit });
    const r = await (await fetch(`/api/investigations?${qs}`)).json();
    INFRA_HIST.items = r.items || [];
    INFRA_HIST.total = r.total || 0;
    renderInfraHistory();
  } catch (e) { box.innerHTML = ""; }
}

function renderInfraHistory() {
  const box = document.getElementById("infra-history");
  const rows = INFRA_HIST.items.map(i => {
    const s = i.summary || {}, [cls, label] = INFRA_MODE[s.mode] || ["", s.mode || "—"];
    return `<div class="infra-hrow"><div class="infra-hmain"><button type="button" class="infra-hseed" data-infra-h="open" data-id="${esc(i.id)}">${esc(i.seed)}</button>
        <span class="hint">${esc(typeof ago === "function" ? ago(i.created) : new Date(i.created * 1000).toLocaleString())} · ${esc(s.domains ?? 0)} domains · ${esc(s.linked_high ?? 0)} high / ${esc(s.linked_medium ?? 0)} medium links${s.sophistication != null ? ` · sophistication ${esc(s.sophistication)}` : ""}</span></div>
      <span class="badge badge-sm ${cls}">${esc(label)}</span>
      <div class="row" style="gap:4px"><button type="button" class="btn btn-secondary btn-xs" data-infra-h="open" data-id="${esc(i.id)}">Open</button>
        <a class="btn btn-ghost btn-xs" href="/api/investigate/${encodeURIComponent(i.id)}/iocs.csv" download>IOCs</a>
        <button type="button" class="btn btn-danger-ghost btn-xs" data-infra-h="delete" data-id="${esc(i.id)}" data-seed="${esc(i.seed)}">Delete</button></div></div>`;
  }).join("");
  const more = INFRA_HIST.total > INFRA_HIST.items.length;
  box.innerHTML = (INFRA_HIST.total || INFRA_HIST.q) ? `
    <div class="row" style="justify-content:space-between;gap:8px;flex-wrap:wrap"><span class="section-label" style="margin:0">Recent investigations <span class="hint">(${esc(INFRA_HIST.total)})</span></span>
      <input type="search" class="input" id="infra-hist-q" placeholder="Search seeds" value="${esc(INFRA_HIST.q)}" maxlength="100" style="max-width:220px;height:32px"></div>
    <div class="infra-hlist">${rows || `<div class="hint">No investigation matches.</div>`}</div>
    ${more ? `<button type="button" class="btn btn-ghost btn-xs" data-infra-h="more">Show more (${esc(INFRA_HIST.total - INFRA_HIST.items.length)})</button>` : ""}` : "";
}

async function openInfraHistory(id) {
  try {
    const r = await fetch(`/api/investigations/${encodeURIComponent(id)}`);
    if (!r.ok) throw new Error((await r.json()).detail || `HTTP ${r.status}`);
    const data = await r.json();
    currentInfra = data;
    setInfraTarget(data.seed || "");
    renderInfra(data);
    document.getElementById("infra-results-section").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) { showToast(err.message || "Could not open the investigation", 4200, "danger"); }
}

function renderInfraChanges(data) {
  const el = document.getElementById("infra-changes");
  if (!el) return;
  const c = data && data.changes;
  const saved = data && data.history ? `Saved investigation from ${new Date(data.history.created * 1000).toLocaleString()}.` : "";
  if (!c) { el.innerHTML = saved ? `<div class="hint" style="margin-bottom:8px">${esc(saved)}</div>` : ""; return; }
  const list = (a, n = 6) => a.length ? esc(a.slice(0, n).join(", ")) + (a.length > n ? ` +${a.length - n}` : "") : "none";
  el.innerHTML = `<div class="alert alert-info" style="margin-bottom:10px">${I.alert}<div><strong>Since the previous investigation of this seed</strong> (${esc(new Date(c.previous_at * 1000).toLocaleString())}):
    ${c.new_domains.length} new domain(s): ${list(c.new_domains)} · ${c.newly_linked.length} newly linked: ${list(c.newly_linked)} · ${c.gone_domains.length} no longer seen: ${list(c.gone_domains)}.
    ${saved ? `<div class="hint">${esc(saved)}</div>` : ""}</div></div>`;
}

document.addEventListener("click", async e => {
  const b = e.target.closest("[data-infra-h]");
  if (!b) return;
  e.preventDefault();
  const id = b.dataset.id;
  if (b.dataset.infraH === "open") return openInfraHistory(id);
  if (b.dataset.infraH === "more") { INFRA_HIST.limit += 20; return loadInfraHistory(); }
  if (b.dataset.infraH === "delete") {
    if (!window.confirm(`Delete the saved investigation of ${b.dataset.seed}? This cannot be undone.`)) return;
    try {
      const r = await fetch(`/api/investigations/${encodeURIComponent(id)}`, { method: "DELETE" });
      if (!r.ok) throw new Error((await r.json()).detail || `HTTP ${r.status}`);
      showToast("Investigation deleted");
      if (currentInfra && currentInfra.id === id) { currentInfra = null; showOnlySection(null); }
      loadInfraHistory();
    } catch (err) { showToast(err.message, 4200, "danger"); }
  }
});

let infraHistTimer = null;
document.addEventListener("input", e => {
  if (e.target.id !== "infra-hist-q") return;
  clearTimeout(infraHistTimer);
  infraHistTimer = setTimeout(async () => {
    INFRA_HIST.q = e.target.value.trim();
    await loadInfraHistory();
    const q = document.getElementById("infra-hist-q");
    if (q) { q.focus(); q.setSelectionRange(q.value.length, q.value.length); }
  }, 300);
});
