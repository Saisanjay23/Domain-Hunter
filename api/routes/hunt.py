"""Impersonation hunt job routes and Dual-Engine Daily Threat Monitor (URLScan + WhoisXML)."""

from fastapi import APIRouter, Depends, HTTPException

from api.deps import app_attr, require_same_origin
from api.schemas import DailyIntelRequest, HuntRequest
from api.services.jobs import HUNT_JOBS, start_hunt
from core.daily_intel import run_daily_intel as core_run_daily_intel
from core.store import get_store

router = APIRouter()


@router.post("/api/hunt", dependencies=[Depends(require_same_origin)])
def api_hunt_start(req: HuntRequest):
    return {"job_id": start_hunt(req)}


@router.get("/api/hunt/{job_id}")
def api_hunt_status(job_id: str):
    jobs = app_attr("HUNT_JOBS", HUNT_JOBS)
    job = jobs.get(job_id)
    if not job:
        stored = get_store().get_hunt(job_id)
        if stored:
            get_store().decorate(stored, compute_new=False)
            return {
                "id": job_id, "target": stored["target"], "status": "done", "progress": 100,
                "stage": "done", "message": "Loaded from history", "stats": stored.get("stats", {}), "result": stored,
            }
        raise HTTPException(status_code=404, detail="Unknown hunt job.")
    out = {k: v for k, v in job.items() if k not in ("cancel", "result")}
    if job["status"] == "done":
        out["result"] = job["result"]
    return out


@router.delete("/api/hunt/{job_id}", dependencies=[Depends(require_same_origin)])
def api_hunt_cancel(job_id: str):
    jobs = app_attr("HUNT_JOBS", HUNT_JOBS)
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Unknown hunt job.")
    job["cancel"].set()
    return {"status": "cancelling"}


@router.post("/api/daily-intel")
def api_daily_intel(req: DailyIntelRequest):
    """
    Runs 100% free Multi-Engine Daily Threat Radar:
      - URLScan.io daily search (page.domain + page.title, excluding official domain)
      - Certificate Transparency logs (crt.sh + ctlogs.dev)
      - Free Daily NRD + OpenPhish + Phishing.Database feeds
      - Live typosquat DNS + HTTP title verification
      - Optional WhoisXML if a key is configured and requested
    """
    if not req.target or not req.target.strip():
        raise HTTPException(status_code=400, detail="Target domain is required.")
    try:
        runner = app_attr("run_daily_intel", core_run_daily_intel)
        return runner(
            target=req.target.strip(),
            brand_title=req.brand_title,
            extra_keywords=req.keywords,
            extra_allowlist=req.allowlist,
            lookback_hours=req.lookback_hours,
            include_urlscan=req.include_urlscan,
            include_ct=req.include_ct,
            include_feeds=req.include_feeds,
            include_dns=req.include_dns,
            include_whoisxml=req.include_whoisxml,
            with_typos=req.with_typos,
            timeout=req.timeout,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
