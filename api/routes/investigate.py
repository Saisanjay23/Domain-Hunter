"""Infrastructure Investigator routes: one domain -> linked infrastructure, operator profile and predictions."""

import threading
import time
import uuid
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from api.deps import require_same_origin
from core.infra import InvestigationCancelled, investigate as core_investigate, ioc_csv

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
    job = _job(job_id)
    if job["status"] != "done":
        raise HTTPException(status_code=409, detail="Investigation not finished yet.")
    return PlainTextResponse(ioc_csv(job["result"]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="infra-{job["result"]["seed"]}-iocs.csv"'})
