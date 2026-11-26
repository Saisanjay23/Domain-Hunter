"""Background hunt jobs, watchlist scheduling, and alert delivery."""

import os
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from api.deps import app_attr, safe_error
from api.schemas import HuntRequest
from api.services.image_inspector import api_icon
from core import alerts as alerts_mod
from core.hunter import HuntCancelled, hunt_for_export, run_hunt as core_run_hunt
from core.permutations import DEPTHS
from core.store import get_store

HUNT_JOBS: Dict[str, Dict[str, Any]] = {}
HUNT_LOCK = threading.Lock()
MAX_HUNT_JOBS = 20
MAX_RUNNING_HUNTS = 2

SCHEDULER_STATE: Dict[str, Any] = {"running": False}
SCHEDULER_TICK_SECONDS = 30


def hunt_api_result(result: Dict[str, Any]) -> Dict[str, Any]:
    out = hunt_for_export(result)
    out["brand"]["icons"] = [api_icon(i) for i in result["brand"]["icons"]]
    return out


def _finish_watch(watch_id: int, job_id: str, result: Optional[Dict[str, Any]], error: Optional[str] = None) -> None:
    """Records the outcome of a scheduled hunt and raises an alert (in-app and webhook) when warranted."""
    store = get_store()
    w = store.watch_get(watch_id, include_secret=True)
    if not w:
        return
    if error or result is None:
        store.watch_update(watch_id, last_run=time.time(), last_hunt=job_id, last_status=f"error: {error}")
        store.alert_add(w["brand"], "error", f"Scheduled hunt for {w['brand']} failed", error or "unknown error", job_id)
        return
    store.watch_update(watch_id, last_run=time.time(), last_hunt=job_id, last_status="ok")
    alerts_impl = app_attr("alerts_mod", alerts_mod)
    note = alerts_impl.compose(w["brand"], result, w["min_score"])
    if not note:
        return
    delivery = ""
    if note["notify"] and w.get("webhook_url"):
        ok, msg = alerts_impl.send_webhook(
            w["webhook_url"], note["title"], note["body"],
            {"brand": w["brand"], "domains": note["domains"], "hunt_id": job_id},
        )
        delivery = ("webhook: " if ok else "webhook failed: ") + msg
    store.alert_add(w["brand"], note["level"], note["title"], note["body"], job_id, delivery)


def _finish_watch_safe(*args: Any, **kwargs: Any) -> None:
    try:
        fn = app_attr("_finish_watch", _finish_watch)
        fn(*args, **kwargs)
    except Exception:
        pass


def _run_hunt_job(job_id: str, req: HuntRequest, watch_id: Optional[int] = None) -> None:
    jobs = app_attr("HUNT_JOBS", HUNT_JOBS)
    job = jobs[job_id]

    def progress(stage, pct, msg, stats):
        job.update(stage=stage, progress=pct, message=msg, stats=stats, updated=time.time())

    try:
        runner = app_attr("run_hunt", core_run_hunt)
        result = runner(
            req.target.strip(), depth=req.depth, use_ct=req.use_ct, verify=req.verify,
            use_rdap=req.use_rdap, use_intel=req.use_intel, use_feeds=req.use_feeds,
            extra_allowlist=req.allowlist, extra_keywords=req.keywords, timeout=req.timeout,
            max_verify=req.max_verify, progress=progress, cancel=job["cancel"],
        )
        api_result = hunt_api_result(result)
        api_result["hunt_id"] = job_id
        try:
            store = get_store()
            store.decorate(api_result, exclude_id=job_id)
            store.save_hunt(job_id, api_result, scheduled=watch_id is not None)
        except Exception as e:
            api_result.setdefault("errors", []).append(f"Could not save to history ({safe_error(e)})")
        job.update(status="done", progress=100, result=api_result, stats=api_result["stats"])
        if watch_id is not None:
            _finish_watch_safe(watch_id, job_id, api_result)
    except HuntCancelled:
        job.update(status="cancelled", message="Hunt cancelled")
        if watch_id is not None:
            _finish_watch_safe(watch_id, job_id, None, error="cancelled")
    except Exception as e:
        job.update(status="error", message=f"{e.__class__.__name__}: {e}")
        if watch_id is not None:
            _finish_watch_safe(watch_id, job_id, None, error=f"{e.__class__.__name__}: {e}")
    finally:
        job["finished"] = time.time()


def start_hunt(req: HuntRequest, watch_id: Optional[int] = None) -> str:
    """Validates and starts a background hunt."""
    if not req.target or not req.target.strip():
        raise HTTPException(status_code=400, detail="Target domain is required.")
    if req.depth not in DEPTHS:
        raise HTTPException(status_code=400, detail=f"depth must be one of {', '.join(DEPTHS)}")
    jobs = app_attr("HUNT_JOBS", HUNT_JOBS)
    with HUNT_LOCK:
        running = [j for j in jobs.values() if j["status"] == "running"]
        if len(running) >= MAX_RUNNING_HUNTS:
            raise HTTPException(status_code=429, detail="Two hunts are already running. Wait for one to finish or cancel it.")
        finished = sorted((j for j in jobs.values() if j["status"] != "running"), key=lambda j: j["created"])
        while len(jobs) >= MAX_HUNT_JOBS and finished:
            jobs.pop(finished.pop(0)["id"], None)
        job_id = uuid.uuid4().hex[:12]
        jobs[job_id] = {
            "id": job_id, "target": req.target.strip(), "status": "running", "stage": "queued",
            "progress": 0, "message": "Starting hunt...", "stats": {}, "result": None,
            "created": time.time(), "updated": time.time(), "cancel": threading.Event(),
            "scheduled": watch_id is not None,
        }
    threading.Thread(target=_run_hunt_job, args=(job_id, req, watch_id), daemon=True).start()
    return job_id


def _start_watch_hunt(w: Dict[str, Any]) -> str:
    req = HuntRequest(target=w["brand"], depth=w["depth"], allowlist=w.get("allowlist") or [])
    job_id = start_hunt(req, watch_id=w["id"])
    get_store().watch_update(w["id"], last_run=time.time(), last_hunt=job_id, last_status="running")
    return job_id


def scheduler_tick(now: Optional[float] = None) -> List[str]:
    """Starts a hunt for every enabled watch that is due. Claims each watch atomically."""
    now = now or time.time()
    store = get_store()
    started: List[str] = []
    starter = app_attr("_start_watch_hunt", _start_watch_hunt)
    for w in store.watch_list():
        if not w["enabled"]:
            continue
        due_before = now - w["interval_hours"] * 3600
        if w["last_run"] is not None and w["last_run"] > due_before:
            continue
        previous = (w["last_run"], w.get("last_status"))
        if not store.watch_claim(w["id"], due_before, now):
            continue
        try:
            starter(w)
            started.append(w["brand"])
        except Exception:
            store.watch_update(w["id"], last_run=previous[0], last_status=previous[1])
            break
    return started


def _scheduler_loop() -> None:
    while True:
        try:
            scheduler_tick()
        except Exception:
            pass
        time.sleep(SCHEDULER_TICK_SECONDS)


def start_scheduler() -> None:
    if SCHEDULER_STATE["running"] or os.environ.get("BRAND_HUNTER_SCHEDULER", "1") == "0":
        return
    SCHEDULER_STATE["running"] = True
    threading.Thread(target=_scheduler_loop, name="watchlist-scheduler", daemon=True).start()
