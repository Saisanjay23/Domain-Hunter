"""History, triage, takedown pack, IOC exports, watchlist, and alert routes."""

import json as _json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response

from api.deps import app_attr, require_same_origin
from api.schemas import ReadRequest, TriageRequest, WatchPatch, WatchRequest
from api.services.jobs import HUNT_JOBS, SCHEDULER_STATE, _start_watch_hunt
from core import alerts as alerts_mod, takedown as takedown_mod
from core.domains import registrable_domain
from core.permutations import DEPTHS
from core.store import TRIAGE_STATUSES, StoreError, get_store

router = APIRouter()


def _hunt_or_404(hunt_id: str) -> Dict[str, Any]:
    stored = get_store().get_hunt(hunt_id)
    if not stored:
        raise HTTPException(status_code=404, detail="Hunt not found in history.")
    get_store().decorate(stored, compute_new=False)
    return stored


def _candidate_or_404(stored: Dict[str, Any], domain: str) -> Dict[str, Any]:
    cand = next((c for c in stored.get("candidates", []) if c["domain"] == domain), None)
    if not cand:
        raise HTTPException(status_code=404, detail="Domain not found in this hunt.")
    return cand


def _watch_payload() -> Dict[str, Any]:
    store = get_store()
    return {
        "watchlist": store.watch_list(),
        "alerts": store.alert_list(),
        "unread": store.alert_unread(),
        "scheduler": SCHEDULER_STATE["running"],
    }


@router.get("/api/hunts")
def api_list_hunts(target: Optional[str] = None):
    return {"hunts": get_store().list_hunts(target=target)}


@router.get("/api/hunts/{hunt_id}")
def api_get_hunt(hunt_id: str):
    return _hunt_or_404(hunt_id)


@router.delete("/api/hunts/{hunt_id}", dependencies=[Depends(require_same_origin)])
def api_delete_hunt(hunt_id: str):
    if not get_store().delete_hunt(hunt_id):
        raise HTTPException(status_code=404, detail="Hunt not found in history.")
    app_attr("HUNT_JOBS", HUNT_JOBS).pop(hunt_id, None)
    return {"status": "deleted"}


@router.put("/api/triage", dependencies=[Depends(require_same_origin)])
def api_triage(req: TriageRequest):
    try:
        return get_store().triage_set(req.brand.strip().lower(), req.domain.strip().lower(), req.status, req.note)
    except StoreError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/api/hunts/{hunt_id}/takedown")
def api_takedown(hunt_id: str, domain: str):
    stored = _hunt_or_404(hunt_id)
    cand = _candidate_or_404(stored, domain)
    td = app_attr("takedown", takedown_mod)
    contacts = td.abuse_contacts(cand)
    return {"domain": domain, "contacts": contacts, "email": td.email_draft(cand, stored["target"], contacts)}


@router.get("/api/hunts/{hunt_id}/report", response_class=HTMLResponse)
def api_evidence_report(hunt_id: str, domain: str):
    stored = _hunt_or_404(hunt_id)
    cand = _candidate_or_404(stored, domain)
    td = app_attr("takedown", takedown_mod)
    return HTMLResponse(td.evidence_html(cand, stored["target"], td.abuse_contacts(cand)))


@router.get("/api/hunts/{hunt_id}/ioc")
def api_ioc_export(hunt_id: str, format: str = "txt", min_score: int = 45, status: str = ""):
    stored = _hunt_or_404(hunt_id)
    wanted = [x for x in status.split(",") if x in TRIAGE_STATUSES] or None
    td = app_attr("takedown", takedown_mod)
    picked = td.select_iocs(stored.get("candidates", []), min_score=min_score, statuses=wanted)
    brand = stored["target"]
    if format == "stix":
        body, media, ext = _json.dumps(td.stix_bundle(brand, picked), indent=2), "application/json", "stix.json"
    elif format == "txt":
        body, media, ext = td.ioc_txt(brand, picked), "text/plain; charset=utf-8", "txt"
    else:
        raise HTTPException(status_code=400, detail="format must be txt or stix")
    return Response(
        body,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="iocs_{brand}.{ext}"', "X-IOC-Count": str(len(picked))},
    )


@router.get("/api/watchlist")
def api_watchlist():
    return _watch_payload()


@router.post("/api/watchlist", dependencies=[Depends(require_same_origin)])
def api_watch_add(req: WatchRequest):
    brand = registrable_domain(req.brand.strip().lower().replace("https://", "").replace("http://", "").split("/")[0])
    if not brand:
        raise HTTPException(status_code=400, detail="Enter a brand domain such as paypal.com")
    if req.depth not in DEPTHS:
        raise HTTPException(status_code=400, detail=f"depth must be one of {', '.join(DEPTHS)}")
    store = get_store()
    try:
        wid = store.watch_add(
            brand, req.depth, req.interval_hours, req.min_score, req.webhook_url,
            [a.strip().lower() for a in req.allowlist if a.strip()],
        )
    except StoreError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        starter = app_attr("_start_watch_hunt", _start_watch_hunt)
        starter(store.watch_get(wid))
    except HTTPException:
        pass
    return _watch_payload()


@router.patch("/api/watchlist/{wid}", dependencies=[Depends(require_same_origin)])
def api_watch_patch(wid: int, req: WatchPatch):
    store = get_store()
    if not store.watch_get(wid):
        raise HTTPException(status_code=404, detail="Not on the watchlist.")
    fields = {k: v for k, v in req.model_dump().items() if v is not None}
    if "depth" in fields and fields["depth"] not in DEPTHS:
        raise HTTPException(status_code=400, detail=f"depth must be one of {', '.join(DEPTHS)}")
    try:
        store.watch_update(wid, **fields)
    except StoreError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _watch_payload()


@router.delete("/api/watchlist/{wid}", dependencies=[Depends(require_same_origin)])
def api_watch_delete(wid: int):
    if not get_store().watch_delete(wid):
        raise HTTPException(status_code=404, detail="Not on the watchlist.")
    return _watch_payload()


@router.post("/api/watchlist/{wid}/run", dependencies=[Depends(require_same_origin)])
def api_watch_run(wid: int):
    w = get_store().watch_get(wid)
    if not w:
        raise HTTPException(status_code=404, detail="Not on the watchlist.")
    starter = app_attr("_start_watch_hunt", _start_watch_hunt)
    return {"job_id": starter(w)}


@router.post("/api/watchlist/{wid}/test-webhook", dependencies=[Depends(require_same_origin)])
def api_watch_test_webhook(wid: int):
    w = get_store().watch_get(wid, include_secret=True)
    if not w:
        raise HTTPException(status_code=404, detail="Not on the watchlist.")
    if not w.get("webhook_url"):
        return {"ok": False, "message": "No webhook is set for this brand"}
    alerts_impl = app_attr("alerts_mod", alerts_mod)
    ok, msg = alerts_impl.send_webhook(
        w["webhook_url"], f"Test alert for {w['brand']}", "Brand Impersonation Hunter can reach this webhook.",
        {"brand": w["brand"], "test": True},
    )
    return {"ok": ok, "message": msg}


@router.get("/api/alerts")
def api_alerts():
    store = get_store()
    return {"alerts": store.alert_list(), "unread": store.alert_unread()}


@router.post("/api/alerts/read", dependencies=[Depends(require_same_origin)])
def api_alerts_read(req: ReadRequest):
    get_store().alert_mark_read(req.id)
    return {"unread": get_store().alert_unread()}
