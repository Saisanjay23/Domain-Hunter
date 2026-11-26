"""Infrastructure Investigator routes: one domain -> linked infrastructure, operator profile and predictions."""

import threading
import time
import uuid
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from api.deps import require_same_origin, safe_error
from core import investigations as history
from core.infra import InvestigationCancelled, investigate as core_investigate, ioc_csv
from core.store import get_store

router = APIRouter()

INVESTIGATIONS: Dict[str, Dict[str, Any]] = {}
_LOCK = threading.Lock()
MAX_JOBS = 20
MAX_RUNNING = 2


class InvestigateRequest(BaseModel):
    target: str
    depth: int = Field(2, ge=1, le=3)
    max_domains: int = Field(30, ge=5, le=80)
    keywords: List[str] = Field(default_factory=list, max_length=20)
    timeout: int = Field(8, ge=3, le=20)


def _run(job_id: str, req: InvestigateRequest) -> None:
    job = INVESTIGATIONS[job_id]

    def progress(stage: str, pct: float, msg: str) -> None:
        job.update(stage=stage, progress=pct, message=msg, updated=time.time())

    try:
        result = core_investigate(req.target.strip(), depth=req.depth, max_domains=req.max_domains, keywords=req.keywords,
                        timeout=req.timeout, progress=progress, cancel=job["cancel"])
        result["id"] = job_id
        try:  # history: saved so it can be reopened later; a database outage never loses the live result
            db = get_store().db
            history.ensure_indexes(db)
            result["changes"] = history.diff_against_previous(db, result, job["created"])
            history.save(db, job_id, {"depth": req.depth, "max_domains": req.max_domains, "keywords": req.keywords}, result, job["created"])
            result["saved"] = True
        except Exception as e:
            result["saved"] = False
            result.setdefault("errors", []).append(f"Could not save to investigation history ({safe_error(e)})")
        job.update(status="done", progress=100, message="Investigation complete", result=result)
    except InvestigationCancelled:
        job.update(status="cancelled", message="Investigation cancelled")
    except ValueError as e:
        job.update(status="error", message=str(e))
    except Exception as e:  # pragma: no cover - surfaced to the UI
        job.update(status="error", message=f"{e.__class__.__name__}: {e}")
    finally:
        job["finished"] = time.time()


@router.post("/api/investigate", dependencies=[Depends(require_same_origin)])
def api_investigate_start(req: InvestigateRequest):
    if not req.target or not req.target.strip():
        raise HTTPException(status_code=400, detail="Give a domain, hostname or URL to investigate.")
    with _LOCK:
        if sum(1 for j in INVESTIGATIONS.values() if j["status"] == "running") >= MAX_RUNNING:
            raise HTTPException(status_code=429, detail="Two investigations are already running. Wait for one to finish or cancel it.")
        done = sorted((j for j in INVESTIGATIONS.values() if j["status"] != "running"), key=lambda j: j["created"])
        while len(INVESTIGATIONS) >= MAX_JOBS and done:
            INVESTIGATIONS.pop(done.pop(0)["id"], None)
        job_id = uuid.uuid4().hex[:12]
        INVESTIGATIONS[job_id] = {"id": job_id, "target": req.target.strip(), "status": "running", "stage": "queued", "progress": 0,
                                  "message": "Starting investigation...", "result": None, "created": time.time(),
                                  "updated": time.time(), "cancel": threading.Event()}
    threading.Thread(target=_run, args=(job_id, req), daemon=True, name=f"investigate-{job_id}").start()
    return {"job_id": job_id}


def _job(job_id: str) -> Dict[str, Any]:
    job = INVESTIGATIONS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Unknown investigation.")
    return job


@router.get("/api/investigate/{job_id}")
def api_investigate_status(job_id: str):
    job = _job(job_id)
    out = {k: v for k, v in job.items() if k not in ("cancel", "result")}
    if job["status"] == "done":
        out["result"] = job["result"]
    return out


@router.delete("/api/investigate/{job_id}", dependencies=[Depends(require_same_origin)])
def api_investigate_cancel(job_id: str):
    _job(job_id)["cancel"].set()
    return {"status": "cancelling"}


@router.get("/api/investigate/{job_id}/iocs.csv", response_class=PlainTextResponse)
def api_investigate_iocs(job_id: str):
    job = INVESTIGATIONS.get(job_id)
    if job is not None:
        if job["status"] != "done":
            raise HTTPException(status_code=409, detail="Investigation not finished yet.")
        result = job["result"]
    else:  # finished in an earlier server run: serve it from the history
        result = _stored(job_id)
    return PlainTextResponse(ioc_csv(result), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="infra-{result["seed"]}-iocs.csv"'})


# ------------------------------------------------------------------ history
def _stored(inv_id: str):
    try:
        return history.get(get_store().db, inv_id)
    except history.NotFound:
        raise HTTPException(status_code=404, detail="Unknown investigation.")


@router.get("/api/investigations")
def api_investigations(q: str = Query("", max_length=100), limit: int = Query(30, ge=1, le=100), skip: int = Query(0, ge=0)):
    db = get_store().db
    history.ensure_indexes(db)
    return history.list_items(db, q, limit, skip)


@router.get("/api/investigations/{inv_id}")
def api_investigation(inv_id: str):
    return _stored(inv_id)


@router.delete("/api/investigations/{inv_id}", dependencies=[Depends(require_same_origin)])
def api_investigation_delete(inv_id: str, request: Request):
    from core import scheduler_store as ss
    db = get_store().db
    try:
        doc = history.get(db, inv_id)
        n = history.delete(db, inv_id)
    except history.NotFound:
        raise HTTPException(status_code=404, detail="Unknown investigation.")
    ss.audit(db, request.client.host if request.client else "unknown", "investigation.delete", "investigation", inv_id, {"seed": doc.get("seed")})
    return {"deleted": n}
