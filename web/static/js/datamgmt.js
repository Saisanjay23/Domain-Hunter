"use strict";
// =============================================================================
// Data Management: per-domain / per-batch volumes, impact previews and scoped deletions.
// Every delete shows its impact first, needs the exact domain or batch name typed back, and is executed,
// scoped and audited by the backend (/api/data/*). Nothing here filters or deletes data client-side.
// =============================================================================

const DM = { summary: null, audit: [], op: null };

const DM_ACTIONS = {
  "findings": { title: "Delete findings", verb: "Delete findings" },
  "domain-history": { title: "Clear scan history", verb: "Clear history" },
  "domain": { title: "Delete domain and all its data", verb: "Delete domain" },
  "batch": { title: "Delete batch", verb: "Delete batch" },
  "batch-executions": { title: "Clear run history", verb: "Clear run history" },
  "batch-remove": { title: "Remove domain from batch", verb: "Remove from batch" },
};

async function loadDataManagement() {
  const root = document.getElementById("dm-root");
  root.innerHTML = `<div class="sch-skel"><div class="skel"></div><div class="skel"></div></div>`;
  try {
    const [s, a] = await Promise.all([settingsCall("GET", "/api/data/summary"), settingsCall("GET", "/api/data/audit?limit=60")]);
    DM.summary = s;
    DM.audit = a.entries || [];
    dmRender();
  } catch (err) {
    root.innerHTML = `<div class="alert alert-danger">${I.alert}<div><strong>Data could not be loaded.</strong><div class="hint">${esc(err.message)}</div></div></div>`;
  }
}

function dmBtn(act, label, attrs, cls = "btn btn-danger-ghost btn-xs") {
  return `<button type="button" class="${cls}" data-dm="${act}"${Object.entries(attrs).map(([k, v]) => ` data-${k}="${esc(v)}"`).join("")}>${label}</button>`;
}

function dmRender() {
  const s = DM.summary, t = s.totals || {};
  const tile = (v, l, cls = "") => `<div class="sch-tile ${cls}"><div class="t-val">${schNum(v)}</div><div class="t-label">${l}</div></div>`;
  const domRows = (s.domains || []).map(d => `<tr>
      <td><button type="button" class="sch-card-name sch-mono" style="font-size:13px" data-dm="open-domain" data-id="${esc(d.id)}">${esc(d.domain)}</button>${d.organization ? `<div class="hint">${esc(d.organization)}</div>` : ""}</td>
      <td class="num">${schNum(d.batches)}</td><td class="num">${schNum(d.findings)}</td><td class="num">${schNum(d.observations)}</td><td class="num">${schNum(d.scan_jobs)}</td>
      <td class="hint">${d.last_scan_at ? esc(ago(d.last_scan_at)) : "never"}</td>
      <td class="col-actions">${dmBtn("findings", "Findings…", { id: d.id })}${dmBtn("domain-history", "History…", { id: d.id })}${dmBtn("domain", "Delete…", { id: d.id }, "btn btn-danger btn-xs")}</td></tr>`).join("");
  const batchRows = (s.batches || []).map(b => `<tr>
      <td><button type="button" class="sch-card-name" style="font-size:13px" data-dm="open-batch" data-id="${esc(b.id)}">${esc(b.name)}</button></td><td>${schPill(b.status)}</td>
      <td class="num">${schNum(b.domains)}</td><td class="num">${schNum(b.executions)}</td><td class="num">${schNum(b.scan_jobs)}</td>
      <td class="col-actions">${dmBtn("batch-executions", "Run history…", { id: b.id })}${dmBtn("batch", "Delete…", { id: b.id }, "btn btn-danger btn-xs")}</td></tr>`).join("");
  const audit = DM.audit.map(a => `<div class="dm-audit-row"><span class="a-time">${esc(schWhen(a.at))}</span>
      <span><span class="a-act">${esc(a.action)}</span> <span class="hint">${esc(a.target_type)} ${esc(a.details && (a.details.domain || a.details.name) || a.target_id)}</span>
      <div class="a-det">${esc(Object.entries(a.details || {}).filter(([k]) => !["domain", "name"].includes(k)).map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`).join(" · "))}</div></span>
      <span class="hint">${esc(a.actor)}</span></div>`).join("");
  document.getElementById("dm-root").innerHTML = `
    <div class="stack" style="gap:18px">
      <div class="sch-head"><div><div class="sch-sub" style="margin:0">Everything below is stored in MongoDB. Deletions are scoped to one domain or batch, need its name typed back and are written to the audit log.</div></div>
        <div class="sch-actions">${dmBtn("refresh", "Refresh", {}, "btn btn-secondary btn-sm")}</div></div>
      <div class="sch-tiles">${tile(t.monitored_domains, "Monitored domains", "t-accent")}${tile(t.scan_batches, "Batches")}${tile(t.impersonation_findings, "Findings", "t-danger")}
        ${tile(t.scan_observations, "Observations")}${tile(t.scan_jobs, "Scan jobs")}${tile(t.batch_executions, "Batch runs")}${tile(t.hunts, "Saved hunts")}${tile(t.audit_logs, "Audit entries")}</div>
      <div class="sch-panel"><h3>Monitored domains</h3>${domRows ? `<div class="table-wrap"><table class="table sch-table"><thead><tr><th>Domain</th><th class="num">Batches</th><th class="num">Findings</th><th class="num">Observations</th><th class="num">Scans</th><th>Last scan</th><th></th></tr></thead><tbody>${domRows}</tbody></table></div>` : `<div class="hint">No monitored domains.</div>`}</div>
      <div class="sch-panel"><h3>Scan batches</h3>${batchRows ? `<div class="table-wrap"><table class="table sch-table"><thead><tr><th>Batch</th><th>Status</th><th class="num">Domains</th><th class="num">Runs</th><th class="num">Scan jobs</th><th></th></tr></thead><tbody>${batchRows}</tbody></table></div>` : `<div class="hint">No batches.</div>`}</div>
      <div class="sch-panel"><h3>Audit log <span class="hint" style="text-transform:none;letter-spacing:0">latest 60 changes</span></h3>${audit ? `<div class="dm-audit">${audit}</div>` : `<div class="hint">No changes recorded yet.</div>`}</div>
      <div class="hint">Manual Brand Hunt history is managed on the History page; Infrastructure investigations are not stored per domain, so they are never removed here.</div>
    </div>`;
}

// ----------------------------------------------------------------------------- deletion dialog
async function dmOpen(op) {
  DM.op = op;
  const dlg = document.getElementById("dm-dialog");
  const body = document.getElementById("dm-dialog-body");
  document.getElementById("dm-dialog-title").textContent = DM_ACTIONS[op.type].title;
  body.innerHTML = `<div class="hint">Checking what would be removed…</div>`;
  dlg.showModal();
  try {
    const impactType = op.type.startsWith("batch") ? "batch" : "domain";
    const imp = await settingsCall("GET", `/api/data/impact?type=${impactType}&id=${encodeURIComponent(op.id)}`);
    op.confirmText = imp.confirm_text;
    op.impact = imp;
    body.innerHTML = dmDialogHtml(op, imp);
    const inp = document.getElementById("dm-confirm-input");
    inp.addEventListener("input", () => { document.getElementById("dm-go").disabled = inp.value.trim().toLowerCase() !== op.confirmText.toLowerCase(); });
    inp.focus();
  } catch (err) {
    body.innerHTML = `<div class="alert alert-danger">${I.alert}<div>${esc(err.message)}</div></div>`;
  }
}

function dmDialogHtml(op, imp) {
  const box = (v, l) => `<div><b>${schNum(v)}</b><span>${l}</span></div>`;
  let what = "", grid = "", extra = "";
  if (op.type === "findings") {
    what = op.all ? `All findings of <b>${esc(imp.name)}</b> and their observation history.` : `${schNum(op.ids.length)} selected finding(s) of <b>${esc(imp.name)}</b> and their observation history.`;
    grid = box(op.all ? imp.findings : op.ids.length, "Findings") + box(op.all ? imp.observations : "…", "Observations");
    extra = `<div class="hint">If a deleted host is still live it will be reported again as New on the next scan.</div>`;
  } else if (op.type === "domain-history") {
    what = `Finished scan jobs of <b>${esc(imp.name)}</b>, their saved hunt reports and all observations. Current findings stay.`;
    grid = box(imp.scan_jobs, "Scan jobs") + box(imp.saved_hunts, "Saved reports") + box(imp.observations, "Observations");
  } else if (op.type === "domain") {
    what = `The monitored domain <b>${esc(imp.name)}</b>: its findings, observations, scan jobs, saved scan reports and batch memberships.`;
    grid = box(imp.findings, "Findings") + box(imp.observations, "Observations") + box(imp.scan_jobs, "Scan jobs") + box(imp.saved_hunts, "Saved reports") + box((imp.batches || []).length, "Batches");
    extra = `${imp.active_jobs ? `<label class="switch"><input type="checkbox" id="dm-cancel-active"><span class="track"></span><span>Stop the ${schNum(imp.active_jobs)} queued/running scan(s) first</span></label>` : ""}<div class="hint">${esc(imp.shared)}</div>`;
  } else if (op.type === "batch") {
    what = `The batch <b>${esc(imp.name)}</b>: its configuration, schedule, run history and memberships. Domains stay unless you tick the option below.`;
    grid = box(imp.domains, "Domains") + box(imp.executions, "Runs") + box(imp.scan_jobs, "Scan jobs") + box(imp.exclusive_domains, "Only in this batch");
    extra = imp.exclusive_domains ? `<label class="switch"><input type="checkbox" id="dm-exclusive"><span class="track"></span><span>Also delete the ${schNum(imp.exclusive_domains)} domain(s) that are in no other batch, with their ${schNum(imp.findings_of_exclusive_domains)} finding(s)</span></label>` : "";
  } else if (op.type === "batch-executions") {
    what = `All run history of <b>${esc(imp.name)}</b>: executions, scan jobs and the reports they saved. Findings stay.`;
    grid = box(imp.executions, "Runs") + box(imp.scan_jobs, "Scan jobs");
  } else if (op.type === "batch-remove") {
    what = `Remove <b>${esc(op.label)}</b> from <b>${esc(imp.name)}</b>. The domain, its findings and its history are kept (it stays in other batches and in Data Management).`;
    grid = box(op.domainIds.length, "Domains");
  }
  const busy = (imp.active_jobs || imp.active_executions) && !["batch-remove", "findings"].includes(op.type)
    ? `<div class="alert alert-warning">${I.alert}<div>A scan of this ${op.type.startsWith("batch") ? "batch" : "domain"} is queued or running. Cancel it first${op.type === "domain" ? " (or use the option below)" : ""}.</div></div>` : "";
  return `<div class="alert alert-danger">${I.alert}<div><strong>This cannot be undone.</strong><div>${what}</div></div></div>
    <div class="dm-impact">${grid}</div>${busy}${extra}
    <label class="field dm-confirm"><span>Type <code>${esc(imp.confirm_text)}</code> to confirm</span><input class="input sch-mono" id="dm-confirm-input" autocomplete="off" spellcheck="false"></label>
    <div id="dm-error"></div>
    <div class="row" style="justify-content:flex-end;gap:8px"><button type="button" class="btn btn-ghost" onclick="document.getElementById('dm-dialog').close()">Cancel</button>
      <button type="button" class="btn btn-danger" id="dm-go" data-dm="execute" disabled>${esc(DM_ACTIONS[op.type].verb)}</button></div>`;
}

async function dmExecute(btn) {
  const op = DM.op;
  const confirm = document.getElementById("dm-confirm-input").value.trim();
  const id = encodeURIComponent(op.id);
  const err = document.getElementById("dm-error");
  err.innerHTML = "";
  setBusy(btn, true, "Deleting…");
  const call = () => {
    switch (op.type) {
      case "findings": return settingsCall("POST", `/api/data/domains/${id}/findings/delete`, op.all ? { confirm, all: true } : { confirm, ids: op.ids });
      case "domain-history": return settingsCall("POST", `/api/data/domains/${id}/history/clear`, { confirm });
      case "domain": return settingsCall("POST", `/api/data/domains/${id}/delete`, { confirm, cancel_active: !!document.getElementById("dm-cancel-active")?.checked });
      case "batch": return settingsCall("POST", `/api/data/batches/${id}/delete`, { confirm, delete_exclusive_domains: !!document.getElementById("dm-exclusive")?.checked });
      case "batch-executions": return settingsCall("POST", `/api/data/batches/${id}/executions/clear`, { confirm });
      case "batch-remove": return settingsCall("POST", `/api/data/batches/${id}/domains/remove`, { confirm, domain_ids: op.domainIds });
    }
  };
  try {
    let r = null;
    for (let attempt = 0; attempt < 8; attempt++) {
      try { r = await call(); break; }
      catch (e) {
        // the backend asked the running scan to stop: give it a moment, then try again (domain delete only)
        if (op.type === "domain" && /Stopping the running scan/i.test(e.message) && attempt < 7) { await new Promise(res => setTimeout(res, 2500)); continue; }
        throw e;
      }
    }
    const d = r.deleted || {};
    const summary = typeof r.removed === "number" ? `${r.removed} membership(s) removed` : Object.entries(d).filter(([, v]) => typeof v === "number").map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`).join(", ");
    showToast(`Done: ${summary || "nothing to delete"}`, 4200, "success");
    document.getElementById("dm-dialog").close();
    if (op.type === "domain" && typeof SCH !== "undefined" && SCH.domainId === op.id) { SCH.view = "list"; SCH.domainId = null; }
    if (op.type === "batch" && typeof SCH !== "undefined" && SCH.batchId === op.id) { SCH.view = "list"; SCH.batchId = null; }
    if (op.type === "findings" && typeof SCH !== "undefined") SCH.selected.clear();
    if (typeof currentTab !== "undefined" && currentTab === "data") loadDataManagement();
    else if (typeof schRefresh === "function") schRefresh();
  } catch (e) {
    err.innerHTML = `<div class="alert alert-danger">${I.alert}<div>${esc(e.message)}</div></div>`;
  } finally { setBusy(btn, false); const inp = document.getElementById("dm-confirm-input"); if (btn.isConnected && inp) btn.disabled = inp.value.trim().toLowerCase() !== (op.confirmText || "").toLowerCase(); }
}

document.addEventListener("click", e => {
  const btn = e.target.closest("[data-dm]");
  if (!btn || !btn.closest("#dm-root, #dm-dialog")) return;
  e.preventDefault();
  const ds = btn.dataset;
  switch (ds.dm) {
    case "refresh": return loadDataManagement();
    case "open-domain": return schGo("domain", { domainId: ds.id });
    case "open-batch": return schGo("batch", { batchId: ds.id });
    case "findings": return dmOpen({ type: "findings", id: ds.id, all: true });
    case "domain-history": case "domain": case "batch": case "batch-executions": return dmOpen({ type: ds.dm, id: ds.id });
    case "execute": return dmExecute(btn);
  }
});
