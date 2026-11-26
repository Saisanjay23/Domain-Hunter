"""Scan Scheduler API: batches, bulk domain import, executions, per-domain dashboards and exports."""

import csv
import io
import json as _json
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response

from api.deps import require_local, require_same_origin
from api.schemas import (
    BatchCreateRequest,
    BatchDomainsRequest,
    BatchPatchRequest,
    BatchStatusRequest,
    DomainPatchRequest,
    DomainRunRequest,
    FindingDismissRequest,
    FindingReviewRequest,
    ParseDomainsRequest,
    SchedulerSettingsRequest,
)
from api.services.batch_scheduler import ENGINE
from core import domain_input as di
from core import schedule as sched
from core import scheduler_store as ss

router = APIRouter()
WRITE = [Depends(require_same_origin)]


def db():
    return ENGINE.db()


def actor(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def guarded(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except ss.NotFound as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ss.Conflict as e:
        raise HTTPException(status_code=409, detail=str(e))
    except (ss.DataError, di.InputError, sched.ScheduleError) as e:
        raise HTTPException(status_code=400, detail=str(e))


# ------------------------------------------------------------------ overview & settings
@router.get("/api/scheduler/overview")
def api_overview():
    d = db()
    return {**ss.overview(d), "engine": ENGINE.status(), "settings": ss.get_settings(d), "now": time.time()}


@router.get("/api/scheduler/settings")
def api_settings():
    return {"settings": ss.get_settings(db()), "limits": ss.SETTINGS_LIMITS}


@router.put("/api/scheduler/settings", dependencies=[Depends(require_local)])
def api_settings_save(req: SchedulerSettingsRequest, request: Request):
    d = db()
    out = guarded(ss.update_settings, d, req.model_dump(exclude_none=True))
    ss.audit(d, actor(request), "scheduler.settings", "settings", "scheduler", req.model_dump(exclude_none=True))
    return {"settings": out, "limits": ss.SETTINGS_LIMITS}


@router.get("/api/scheduler/timezones")
def api_timezones():
    return {"timezones": sorted(sched.valid_timezones())}


# ------------------------------------------------------------------ bulk input
@router.post("/api/scheduler/parse", dependencies=WRITE)
def api_parse(req: ParseDomainsRequest):
    """Normalises pasted text or an uploaded file into entries. Nothing is saved here; invalid lines are returned."""
    if req.content_b64:
        entries = guarded(di.parse_upload, req.filename or "", req.content_b64)
    else:
        entries = guarded(di.parse_text, req.text or "")
    existing = set()
    if req.batch_id:
        d = db()
        b = guarded(ss.get_batch, d, req.batch_id)
        ids = ss.batch_domain_ids(d, b["_id"])
        existing = {x["domain"] for x in d.monitored_domains.find({"_id": {"$in": ids}}, {"domain": 1})} if ids else set()
    summary = di.mark_duplicates(entries, existing)
    return {"entries": entries, "summary": summary}


# ------------------------------------------------------------------ batches
@router.get("/api/scheduler/batches")
def api_batches():
    return {"batches": ss.list_batches(db())}


@router.post("/api/scheduler/batches", dependencies=WRITE)
def api_create_batch(req: BatchCreateRequest, request: Request):
    d = db()
    values = req.model_dump(exclude={"domains"})
    b = guarded(ss.create_batch, d, values)
    added = guarded(ss.batch_add_entries, d, b["_id"], [e.model_dump() for e in req.domains]) if req.domains else \
        {"added": [], "already_in_batch": [], "errors": [], "domain_count": 0}
    ss.audit(d, actor(request), "batch.create", "batch", b["_id"], {"name": b["name"], "domains": len(added["added"])})
    return {"batch": ss.batch_public(d, ss.get_batch(d, b["_id"])), "import": added}


@router.get("/api/scheduler/batches/{batch_id}")
def api_batch(batch_id: str):
    d = db()
    b = guarded(ss.get_batch, d, batch_id)
    return {"batch": ss.batch_public(d, b), "domains": ss.batch_domains(d, b["_id"]),
            "executions": ss.list_executions(d, b["_id"], limit=10)}


@router.patch("/api/scheduler/batches/{batch_id}", dependencies=WRITE)
def api_patch_batch(batch_id: str, req: BatchPatchRequest, request: Request):
    d = db()
    values = req.model_dump(exclude_none=True)
    if req.notify is not None and req.notify.webhook_url is None:
        values["notify"].pop("webhook_url", None)     # not sent: keep the stored secret
    b = guarded(ss.update_batch, d, batch_id, values)
    ss.audit(d, actor(request), "batch.update", "batch", b["_id"], {"fields": sorted(values)})
    return {"batch": ss.batch_public(d, ss.get_batch(d, b["_id"]))}


@router.post("/api/scheduler/batches/{batch_id}/status", dependencies=WRITE)
def api_batch_status(batch_id: str, req: BatchStatusRequest, request: Request):
    d = db()
    b = guarded(ss.set_batch_status, d, batch_id, req.status)
    ss.audit(d, actor(request), f"batch.{req.status}", "batch", b["_id"], {})
    return {"batch": ss.batch_public(d, ss.get_batch(d, b["_id"]))}


@router.post("/api/scheduler/batches/{batch_id}/duplicate", dependencies=WRITE)
def api_duplicate(batch_id: str, request: Request):
    d = db()
    copy = guarded(ss.duplicate_batch, d, batch_id)
    ss.audit(d, actor(request), "batch.duplicate", "batch", copy["_id"], {"from": batch_id})
    return {"batch": ss.batch_public(d, copy)}


@router.post("/api/scheduler/batches/{batch_id}/run", dependencies=WRITE)
def api_run_batch(batch_id: str, request: Request):
    d = db()
    b = guarded(ss.get_batch, d, batch_id)
    if b.get("status") == "disabled":
        raise HTTPException(status_code=409, detail="The batch is disabled. Enable it first.")
    e = guarded(ss.create_execution, d, b, "manual")
    ss.audit(d, actor(request), "batch.run_now", "batch", b["_id"], {"execution_id": e["_id"]})
    _kick()
    return {"execution": ss.execution_public(e)}


@router.post("/api/scheduler/batches/{batch_id}/domains", dependencies=WRITE)
def api_batch_add(batch_id: str, req: BatchDomainsRequest, request: Request):
    d = db()
    out = guarded(ss.batch_add_entries, d, batch_id, [e.model_dump() for e in req.entries])
    ss.audit(d, actor(request), "batch.add_domains", "batch", batch_id, {"added": len(out["added"]), "errors": len(out["errors"])})
    return out


@router.get("/api/scheduler/batches/{batch_id}/executions")
def api_batch_execs(batch_id: str, limit: int = Query(30, ge=1, le=200), skip: int = Query(0, ge=0)):
    d = db()
    guarded(ss.get_batch, d, batch_id)
    return {"executions": ss.list_executions(d, batch_id, limit=limit, skip=skip)}


# ------------------------------------------------------------------ executions
@router.get("/api/scheduler/executions/{execution_id}")
def api_execution(execution_id: str):
    d = db()
    e = guarded(ss.get_execution, d, execution_id)
    return {"execution": ss.execution_public(e), "jobs": ss.execution_jobs(d, e["_id"])}


@router.post("/api/scheduler/executions/{execution_id}/cancel", dependencies=WRITE)
def api_cancel(execution_id: str, request: Request):
    d = db()
    e = guarded(ss.request_cancel, d, execution_id)
    ss.audit(d, actor(request), "execution.cancel", "execution", e["_id"], {"batch_id": e["batch_id"]})
    return {"execution": ss.execution_public(e)}


@router.post("/api/scheduler/executions/{execution_id}/retry", dependencies=WRITE)
def api_retry(execution_id: str, request: Request):
    d = db()
    e = guarded(ss.get_execution, d, execution_id)
    if e["status"] in ss.EXEC_ACTIVE:
        raise HTTPException(status_code=409, detail="The run is still in progress.")
    ids = ss.failed_domain_ids(d, e["_id"])
    if not ids:
        raise HTTPException(status_code=400, detail="No failed or cancelled domain scans to retry.")
    b = guarded(ss.get_batch, d, e["batch_id"])
    new = guarded(ss.create_execution, d, b, "retry", domain_ids=ids, retry_of=e["_id"])
    ss.audit(d, actor(request), "execution.retry", "execution", new["_id"], {"retry_of": e["_id"], "domains": len(ids)})
    _kick()
    return {"execution": ss.execution_public(new)}


# ------------------------------------------------------------------ monitored domains
@router.get("/api/scheduler/domains/{domain_id}")
def api_domain(domain_id: str):
    return guarded(ss.domain_dashboard, db(), domain_id)


@router.patch("/api/scheduler/domains/{domain_id}", dependencies=WRITE)
def api_patch_domain(domain_id: str, req: DomainPatchRequest, request: Request):
    d = db()
    out = guarded(ss.update_domain, d, domain_id, req.model_dump(exclude_none=True))
    ss.audit(d, actor(request), "domain.update", "domain", out["id"], {"fields": sorted(req.model_dump(exclude_none=True))})
    return {"domain": out}


@router.post("/api/scheduler/domains/{domain_id}/run", dependencies=WRITE)
def api_run_domain(domain_id: str, req: DomainRunRequest, request: Request):
    d = db()
    dom = guarded(ss.get_domain, d, domain_id)
    batches = ss.domain_batches(d, dom["_id"])
    if req.batch_id:
        if req.batch_id not in {b["id"] for b in batches}:
            raise HTTPException(status_code=400, detail="The domain is not in that batch.")
        bid = req.batch_id
    elif batches:
        bid = batches[0]["id"]
    else:
        raise HTTPException(status_code=400, detail="Add the domain to a batch first.")
    b = guarded(ss.get_batch, d, bid)
    e = guarded(ss.create_execution, d, b, "manual_domain", domain_ids=[dom["_id"]], include_paused=True)
    ss.audit(d, actor(request), "domain.run_now", "domain", dom["_id"], {"execution_id": e["_id"], "batch_id": bid})
    _kick()
    return {"execution": ss.execution_public(e)}


@router.get("/api/scheduler/domains/{domain_id}/findings")
def api_findings(domain_id: str, view: str = "all", q: str = Query("", max_length=100), sort: str = "score",
                 page: int = Query(1, ge=1, le=100000), page_size: int = Query(50, ge=1, le=200),
                 min_score: Optional[int] = Query(None, ge=0, le=100)):
    return guarded(ss.list_findings, db(), domain_id, view, q, sort, page, page_size, min_score)


@router.get("/api/scheduler/domains/{domain_id}/findings/history")
def api_finding_history(domain_id: str, finding_id: str = Query(..., max_length=400)):
    return {"history": guarded(ss.finding_history, db(), domain_id, finding_id)}


@router.post("/api/scheduler/domains/{domain_id}/findings/review", dependencies=WRITE)
def api_review(domain_id: str, req: FindingReviewRequest, request: Request):
    d = db()
    n = guarded(ss.set_review, d, domain_id, req.ids, req.under_review)
    ss.audit(d, actor(request), "findings.review", "domain", domain_id, {"count": n, "under_review": req.under_review})
    return {"updated": n}


@router.post("/api/scheduler/domains/{domain_id}/findings/dismiss", dependencies=WRITE)
def api_dismiss(domain_id: str, req: FindingDismissRequest, request: Request):
    d = db()
    n = guarded(ss.set_dismissed, d, domain_id, req.ids, req.dismissed, req.reason)
    ss.audit(d, actor(request), "findings.dismiss" if req.dismissed else "findings.restore", "domain", domain_id,
             {"count": n, "reason": req.reason[:120]})
    return {"updated": n}


@router.get("/api/scheduler/health")
def api_health(response: Response):
    """For external monitoring: 200 while the engine is ticking, 503 when it should run but has stalled or is off."""
    st = ENGINE.status()
    now = time.time()
    age = (now - st["last_tick"]) if st.get("last_tick") else None
    try:
        enabled = ss.get_settings(db())["enabled"]
        active = db().batch_executions.count_documents({"status": {"$in": list(ss.EXEC_ACTIVE)}})
        db_ok = True
    except Exception:
        enabled, active, db_ok = None, None, False
    healthy = bool(db_ok and st.get("running") and enabled and age is not None and age < 120)
    response.status_code = 200 if healthy else 503
    return {"healthy": healthy, "engine_running": st.get("running"), "scheduling_enabled": enabled, "database": db_ok,
            "last_tick_age_seconds": round(age, 1) if age is not None else None, "active_runs": active,
            "last_error": st.get("last_error"), "owner": st.get("owner")}


@router.get("/api/scheduler/domains/{domain_id}/jobs")
def api_domain_jobs(domain_id: str, limit: int = Query(50, ge=1, le=200)):
    d = db()
    guarded(ss.get_domain, d, domain_id)
    return {"jobs": ss.domain_jobs(d, domain_id, limit)}


@router.get("/api/scheduler/domains/{domain_id}/observations")
def api_domain_obs(domain_id: str, limit: int = Query(200, ge=1, le=500), skip: int = Query(0, ge=0)):
    d = db()
    guarded(ss.get_domain, d, domain_id)
    return {"observations": ss.domain_observations(d, domain_id, limit, skip)}


EXPORT_FIELDS = ["host", "classification", "lifecycle", "score", "verdict", "matched_keyword", "matching_technique",
                 "registered_domain", "dns_status", "a", "http_status", "final_url", "title", "sources", "first_seen",
                 "last_seen", "original_domain", "domain_id", "last_job_id", "last_execution_id", "last_batch_id", "under_review",
                 "dismissed"]


@router.get("/api/scheduler/domains/{domain_id}/export")
def api_export(domain_id: str, format: str = Query("csv", pattern="^(csv|json)$"), view: str = "all"):
    d = db()
    dom = guarded(ss.get_domain, d, domain_id)
    query = guarded(ss.findings_query, dom["_id"], view)
    return _export(d, query, format, f"findings-{dom['domain']}-{view}-{time.strftime('%Y%m%d-%H%M')}", {"domain": dom["domain"], "view": view})


@router.get("/api/scheduler/batches/{batch_id}/export")
def api_batch_export(batch_id: str, format: str = Query("csv", pattern="^(csv|json)$"), view: str = "all"):
    d = db()
    b = guarded(ss.get_batch, d, batch_id)
    query = guarded(ss.batch_findings_query, d, b["_id"], view)
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in b["name"])[:60]
    return _export(d, query, format, f"findings-batch-{safe}-{view}-{time.strftime('%Y%m%d-%H%M')}", {"batch": b["name"], "view": view})


def _export(d, query, format: str, name: str, meta):
    rows = list(d.impersonation_findings.find(query, {"fingerprint": 0}).sort([("score", -1), ("host", 1)]).limit(50000))
    if format == "json":
        body = _json.dumps({**meta, "exported": time.time(),
                            "findings": [{**{k: v for k, v in r.items() if k != "_id"}, "id": r["_id"]} for r in rows]}, default=str)
        return Response(body, media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{name}.json"'})
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=EXPORT_FIELDS, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        row = {k: r.get(k) for k in EXPORT_FIELDS}
        row["a"] = ";".join(r.get("a") or [])
        row["sources"] = ";".join(r.get("sources") or [])
        for k in ("first_seen", "last_seen"):
            row[k] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(r[k])) if r.get(k) else ""
        # neutralise spreadsheet formula injection in attacker-controlled fields (page titles, URLs)
        for k, v in row.items():
            if isinstance(v, str) and v[:1] in ("=", "+", "-", "@"):
                row[k] = "'" + v
        w.writerow(row)
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{name}.csv"'})


def _kick() -> None:
    """Start queued executions now instead of at the next tick (only when the background engine is running)."""
    if ENGINE.state.get("running"):
        try:
            ENGINE.launch_queued(ENGINE.db(), time.time(), ss.get_settings(ENGINE.db()))
        except Exception:
            pass
