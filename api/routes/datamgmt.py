"""
Data Management API: volumes, impact previews and scoped, audited deletions.

Every destructive endpoint:
  * is restricted to this machine (require_local) and same-origin requests (no CSRF / DNS rebinding),
  * requires the exact domain or batch name typed back as `confirm`,
  * is scoped by validated ids (never an unscoped delete_many),
  * refuses while a scan of the target is running (or asks it to stop, see cancel_active),
  * writes an audit_logs entry with the counts that were removed.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.deps import require_local, require_same_origin
from api.routes.scheduler import actor, db, guarded
from api.schemas import ConfirmRequest, DeleteBatchRequest, DeleteDomainRequest, DeleteFindingsRequest, DomainIdsRequest
from core import scheduler_store as ss

router = APIRouter()
DESTRUCTIVE = [Depends(require_local), Depends(require_same_origin)]


@router.get("/api/data/summary")
def api_summary():
    return ss.data_summary(db())


@router.get("/api/data/impact")
def api_impact(type: str = Query(..., pattern="^(domain|batch)$"), id: str = Query(..., max_length=40)):
    d = db()
    return guarded(ss.domain_impact if type == "domain" else ss.batch_impact, d, id)


@router.get("/api/data/audit")
def api_audit(limit: int = Query(100, ge=1, le=500), target_id: str = Query("", max_length=40)):
    return {"entries": ss.audit_list(db(), limit, target_id or None)}


@router.post("/api/data/domains/{domain_id}/findings/delete", dependencies=DESTRUCTIVE)
def api_delete_findings(domain_id: str, req: DeleteFindingsRequest, request: Request):
    d = db()
    dom = guarded(ss.get_domain, d, domain_id)
    guarded(ss.require_confirmation, dom["domain"], req.confirm)
    if not req.all and not req.ids:
        raise HTTPException(status_code=400, detail="Select findings to delete, or set all.")
    out = guarded(ss.delete_findings, d, dom["_id"], None if req.all else req.ids)
    ss.audit(d, actor(request), "findings.delete", "domain", dom["_id"], {"domain": dom["domain"], "all": req.all, **out})
    return {"deleted": out}


@router.post("/api/data/domains/{domain_id}/history/clear", dependencies=DESTRUCTIVE)
def api_clear_history(domain_id: str, req: ConfirmRequest, request: Request):
    d = db()
    dom = guarded(ss.get_domain, d, domain_id)
    guarded(ss.require_confirmation, dom["domain"], req.confirm)
    out = guarded(ss.clear_domain_history, d, dom["_id"])
    ss.audit(d, actor(request), "domain.clear_history", "domain", dom["_id"], {"domain": dom["domain"], **out})
    return {"deleted": out}


@router.post("/api/data/domains/{domain_id}/delete", dependencies=DESTRUCTIVE)
def api_delete_domain(domain_id: str, req: DeleteDomainRequest, request: Request):
    d = db()
    dom = guarded(ss.get_domain, d, domain_id)
    guarded(ss.require_confirmation, dom["domain"], req.confirm)
    running = d.scan_jobs.count_documents({"domain_id": dom["_id"], "status": "running"})
    if running:
        if not req.cancel_active:
            raise HTTPException(status_code=409, detail="A scan of this domain is running. Cancel it (or tick 'stop the running scan') first.")
        d.scan_jobs.update_many({"domain_id": dom["_id"], "status": "running"}, {"$set": {"cancel_requested": True}})
        ss.audit(d, actor(request), "domain.delete_requested_cancel", "domain", dom["_id"], {"running": running})
        raise HTTPException(status_code=409, detail="Stopping the running scan. Try again in a few seconds.")
    out = guarded(ss.delete_domain, d, dom["_id"])
    ss.audit(d, actor(request), "domain.delete", "domain", dom["_id"], {"domain": dom["domain"], **out})
    return {"deleted": out}


@router.post("/api/data/batches/{batch_id}/domains/remove", dependencies=DESTRUCTIVE)
def api_remove_domains(batch_id: str, req: DomainIdsRequest, request: Request):
    d = db()
    b = guarded(ss.get_batch, d, batch_id)
    guarded(ss.require_confirmation, b["name"], req.confirm)
    n = guarded(ss.batch_remove_domains, d, b["_id"], req.domain_ids)
    ss.audit(d, actor(request), "batch.remove_domains", "batch", b["_id"], {"name": b["name"], "removed": n, "domain_ids": req.domain_ids[:50]})
    return {"removed": n}


@router.post("/api/data/batches/{batch_id}/executions/clear", dependencies=DESTRUCTIVE)
def api_clear_executions(batch_id: str, req: ConfirmRequest, request: Request):
    d = db()
    b = guarded(ss.get_batch, d, batch_id)
    guarded(ss.require_confirmation, b["name"], req.confirm)
    out = guarded(ss.clear_batch_executions, d, b["_id"])
    ss.audit(d, actor(request), "batch.clear_executions", "batch", b["_id"], {"name": b["name"], **out})
    return {"deleted": out}


@router.post("/api/data/batches/{batch_id}/delete", dependencies=DESTRUCTIVE)
def api_delete_batch(batch_id: str, req: DeleteBatchRequest, request: Request):
    d = db()
    b = guarded(ss.get_batch, d, batch_id)
    guarded(ss.require_confirmation, b["name"], req.confirm)
    out = guarded(ss.delete_batch, d, b["_id"], req.delete_exclusive_domains)
    ss.audit(d, actor(request), "batch.delete", "batch", b["_id"], {"name": b["name"], **{k: v for k, v in out.items() if k != "domains_deleted"},
                                                                    "domains_deleted": len(out.get("domains_deleted") or [])})
    return {"deleted": out}
