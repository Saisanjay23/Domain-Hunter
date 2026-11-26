"""
Scan Scheduler engine: runs scan batches on their schedules inside the server process, independent of any browser.

Every state change goes through MongoDB with atomic find_one_and_update claims, so several app instances can share
one database safely:

  tick()                        every TICK_SECONDS in a background thread
    recover()                   executions whose owner stopped heart-beating are handed back to the queue; their
                                running jobs are re-queued (after max_attempts interruptions a job is failed)
    schedule_due()              batches whose next_run_at has passed are leased, one execution is created per slot
                                (unique slot_key = at most once per slot), next_run_at is advanced; a slot missed by
                                more than the grace window follows the batch's missed-run policy (run once / skip)
    launch_queued()             queued executions are claimed (owner = this instance) and run in worker threads

  run_execution()               claims the execution's queued jobs up to `concurrency` at a time, heart-beats,
                                honours cancel requests, finishes the execution and sends notifications
  run_job()                     per-domain lease (no overlapping scans of one domain, even across batches),
                                run_hunt() with that domain's keywords only, timeout watchdog, save the hunt,
                                merge findings (lifecycle), retry with exponential back-off on failure

Graceful shutdown (app shutdown event) stops claiming, interrupts running scans and puts their jobs and
executions back in the queue without counting an attempt, so the next start resumes them.
"""

import logging
import os
import random
import socket
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional

from api.deps import app_attr, safe_error
from core import alerts as alerts_mod
from core import schedule as sched
from core import scheduler_store as ss
from core.hunter import HuntCancelled, run_hunt as core_run_hunt
from core.store import get_store

log = logging.getLogger("brand_hunter.scheduler")

TICK_SECONDS = 15
EXEC_POLL_SECONDS = 2.0
JOB_STAGGER_SECONDS = 2.0
LOCK_WAIT_SECONDS = 30
MISSED_GRACE_MIN = 15 * 60
MISSED_GRACE_MAX = 6 * 3600
RATE_LIMIT_WORDS = ("429", "rate limit", "rate-limit", "too many requests", "quota")


def _resolve(hosts: List[str]) -> Dict[str, Dict[str, Any]]:
    from core.discovery import resolve_domains
    return resolve_domains(hosts, concurrency=50, timeout=3.0)


class BatchScheduler:
    def __init__(self, owner: Optional[str] = None, poll_seconds: float = EXEC_POLL_SECONDS,
                 stagger_seconds: float = JOB_STAGGER_SECONDS, runner: Optional[Callable] = None,
                 resolver: Optional[Callable] = None, db_provider: Optional[Callable] = None) -> None:
        self.owner = owner or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"
        self.poll_seconds = poll_seconds
        self.stagger_seconds = stagger_seconds
        self.runner = runner
        self.resolver = resolver
        self._db_provider = db_provider
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._exec_threads: Dict[str, threading.Thread] = {}
        self._job_cancel: Dict[str, threading.Event] = {}
        self._lock = threading.Lock()
        self._indexed: set = set()
        self.state: Dict[str, Any] = {"running": False, "last_tick": None, "last_error": None, "started": None}

    # ------------------------------------------------------------------ plumbing
    def db(self):
        if self._db_provider is not None:
            db = self._db_provider()
        else:
            db = get_store().db
        key = (id(db.client), db.name)
        if key not in self._indexed:
            ss.ensure_indexes(db)
            self._indexed.add(key)
        return db

    def _runner(self) -> Callable:
        return self.runner or app_attr("run_hunt", core_run_hunt)

    def status(self) -> Dict[str, Any]:
        with self._lock:
            alive = [e for e, t in self._exec_threads.items() if t.is_alive()]
        return {**self.state, "owner": self.owner, "executions_here": alive}

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        if self.state["running"]:
            return
        self._stop.clear()
        self.state.update(running=True, started=time.time())
        self._thread = threading.Thread(target=self._loop, name="batch-scheduler", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 15.0) -> None:
        """Graceful shutdown: no new work, running scans are interrupted and re-queued for the next start."""
        self._stop.set()
        with self._lock:
            events = list(self._job_cancel.values())
            threads = list(self._exec_threads.values())
        for ev in events:
            ev.set()
        deadline = time.time() + timeout
        for t in threads:
            t.join(max(0.1, deadline - time.time()))
        self.state["running"] = False

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
                self.state["last_error"] = None
            except Exception as e:  # MongoDB down, etc.: keep the loop alive and report it
                self.state["last_error"] = safe_error(e)
                log.warning("scheduler tick failed: %s", self.state["last_error"])
            self._stop.wait(TICK_SECONDS)

    def tick(self, now: Optional[float] = None, run_inline: bool = False) -> Dict[str, Any]:
        now = now or time.time()
        db = self.db()
        settings = ss.get_settings(db)
        self.state["last_tick"] = now
        recovered = self.recover(db, now, settings)
        if not settings["enabled"]:
            return {"recovered": recovered, "scheduled": [], "launched": [], "disabled": True}
        scheduled = self.schedule_due(db, now)
        launched = self.launch_queued(db, now, settings, run_inline=run_inline)
        return {"recovered": recovered, "scheduled": scheduled, "launched": launched}

    # ------------------------------------------------------------------ recovery
    def recover(self, db, now: float, settings: Dict[str, Any]) -> List[str]:
        stale_before = now - settings["lease_seconds"]
        out = []
        for e in list(db.batch_executions.find({"status": "running", "heartbeat": {"$lt": stale_before}}, {"_id": 1})):
            claimed = db.batch_executions.find_one_and_update(
                {"_id": e["_id"], "status": "running", "heartbeat": {"$lt": stale_before}},
                {"$set": {"status": "queued", "owner": None, "heartbeat": now}})
            if not claimed:
                continue
            for j in db.scan_jobs.find({"execution_id": e["_id"], "status": "running"}, {"attempts": 1, "max_attempts": 1, "domain_id": 1}):
                if int(j.get("attempts") or 0) >= int(j.get("max_attempts") or 1):
                    db.scan_jobs.update_one({"_id": j["_id"], "status": "running"},
                                            {"$set": {"status": "failed", "finished": now, "owner": None,
                                                      "error": "interrupted (the server stopped during the scan) too many times"}})
                else:
                    db.scan_jobs.update_one({"_id": j["_id"], "status": "running"},
                                            {"$set": {"status": "queued", "owner": None, "next_attempt_at": now,
                                                      "message": "re-queued after an interrupted run"}})
                ss.release_lock(db, f"domain:{j['domain_id']}", j["_id"])
            out.append(e["_id"])
        for b in db.scan_batches.find({"active_execution_id": {"$ne": None}}, {"_id": 1}):
            ss._clear_stale_active(db, b["_id"])
        return out

    # ------------------------------------------------------------------ scheduling
    def schedule_due(self, db, now: float) -> List[Dict[str, Any]]:
        out = []
        for _ in range(50):
            b = db.scan_batches.find_one_and_update(
                {"status": "active", "deleting": {"$ne": True}, "next_run_at": {"$ne": None, "$lte": now}, "lease_until": {"$lt": now}},
                {"$set": {"lease_owner": self.owner, "lease_until": now + 60}}, sort=[("next_run_at", 1)])
            if not b:
                break
            slot = float(b["next_run_at"])
            spec = b.get("schedule") or {}
            nxt = sched.next_run(spec, now, anchor=slot)
            grace = min(MISSED_GRACE_MAX, max(MISSED_GRACE_MIN, sched.period_seconds(spec) * 0.25))
            outcome: Dict[str, Any] = {"batch_id": b["_id"], "slot": slot}
            if now - slot > grace and b.get("missed_policy") == "skip":
                outcome["result"] = "missed_skipped"
                ss.audit(db, "scheduler", "schedule.missed_skipped", "batch", b["_id"], {"slot": slot})
            else:
                try:
                    e = ss.create_execution(db, b, "schedule", slot=slot, now=now)
                    outcome.update(result="queued", execution_id=e["_id"], late_seconds=round(max(0.0, now - slot)))
                except ss.Conflict as c:
                    outcome["result"] = f"skipped: {c}"
                    ss.audit(db, "scheduler", "schedule.overlap_skipped", "batch", b["_id"], {"slot": slot, "reason": str(c)})
            db.scan_batches.update_one({"_id": b["_id"], "lease_owner": self.owner},
                                       {"$set": {"next_run_at": nxt, "lease_owner": None, "lease_until": 0, "last_slot": slot}})
            out.append(outcome)
        return out

    def launch_queued(self, db, now: float, settings: Dict[str, Any], run_inline: bool = False) -> List[str]:
        launched = []
        while not self._stop.is_set():      # a stopping instance never claims work (it just handed it back)
            with self._lock:
                alive = sum(t.is_alive() for t in self._exec_threads.values())
            if not run_inline and alive >= settings["max_parallel_executions"]:
                break
            e = db.batch_executions.find_one_and_update(
                {"status": "queued", "owner": None},
                {"$set": {"status": "running", "owner": self.owner, "heartbeat": now}}, sort=[("created", 1)])
            if not e:
                break
            db.batch_executions.update_one({"_id": e["_id"], "started": None}, {"$set": {"started": now}})
            launched.append(e["_id"])
            if run_inline:
                self.run_execution(e["_id"])
            else:
                t = threading.Thread(target=self.run_execution, args=(e["_id"],), name=f"exec-{e['_id']}", daemon=True)
                with self._lock:
                    self._exec_threads = {k: v for k, v in self._exec_threads.items() if v.is_alive()}
                    self._exec_threads[e["_id"]] = t
                t.start()
        return launched

    # ------------------------------------------------------------------ one execution
    def run_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        db = self.db()
        settings = ss.get_settings(db)
        lease = settings["lease_seconds"]
        futures: Dict[str, Future] = {}
        pool = ThreadPoolExecutor(max_workers=settings["concurrency"], thread_name_prefix=f"scan-{execution_id}")
        last_claim = 0.0
        final = None
        try:
            while True:
                now = time.time()
                e = db.batch_executions.find_one({"_id": execution_id})
                if not e or e.get("owner") != self.owner or e["status"] != "running":
                    break   # deleted, finished elsewhere, or taken over after we stalled
                db.batch_executions.update_one({"_id": execution_id, "owner": self.owner}, {"$set": {"heartbeat": now}})
                db.scan_jobs.update_many({"execution_id": execution_id, "status": "running", "owner": self.owner},
                                         {"$set": {"lease_until": now + lease}})
                for jid in [j for j, f in futures.items() if f.done()]:
                    futures.pop(jid)
                stop_jobs = set(futures) if e.get("cancel_requested") else {
                    j["_id"] for j in db.scan_jobs.find({"execution_id": execution_id, "status": "running", "cancel_requested": True}, {"_id": 1})}
                if stop_jobs:
                    with self._lock:
                        for jid in stop_jobs:
                            ev = self._job_cancel.get(jid)
                            if ev:
                                ev.set()
                if self._stop.is_set():
                    break
                while not e.get("cancel_requested") and len(futures) < settings["concurrency"] \
                        and time.time() - last_claim >= self.stagger_seconds:
                    job = db.scan_jobs.find_one_and_update(
                        {"execution_id": execution_id, "status": "queued", "next_attempt_at": {"$lte": time.time()}},
                        {"$set": {"status": "running", "owner": self.owner, "lease_until": time.time() + lease,
                                  "started": time.time(), "stage": "starting", "message": "Starting scan", "error": None},
                         "$inc": {"attempts": 1}}, sort=[("next_attempt_at", 1), ("created", 1)], return_document=True)
                    if not job:
                        break
                    last_claim = time.time()
                    ev = threading.Event()
                    with self._lock:
                        self._job_cancel[job["_id"]] = ev
                    futures[job["_id"]] = pool.submit(self.run_job, job, settings, ev)
                ss.refresh_execution_totals(db, execution_id, now)
                if not futures:
                    left = db.scan_jobs.count_documents({"execution_id": execution_id, "status": {"$in": ["queued", "running"]}})
                    if left == 0:
                        final = ss.finish_execution(db, execution_id)
                        self._notify(db, final)
                        break
                self._stop.wait(self.poll_seconds)
        finally:
            if self._stop.is_set():
                for ev in list(self._job_cancel.values()):
                    ev.set()
            pool.shutdown(wait=True)
            if final is None and self._stop.is_set():
                # graceful shutdown: hand the execution back to the queue for the next start (or another instance)
                db.scan_jobs.update_many({"execution_id": execution_id, "status": "running", "owner": self.owner},
                                         {"$set": {"status": "queued", "owner": None, "next_attempt_at": time.time()}})
                db.batch_executions.update_one({"_id": execution_id, "owner": self.owner, "status": "running"},
                                               {"$set": {"status": "queued", "owner": None}})
            with self._lock:
                self._exec_threads.pop(execution_id, None)
        return final

    # ------------------------------------------------------------------ one domain scan
    def run_job(self, job: Dict[str, Any], settings: Dict[str, Any], cancel: threading.Event) -> str:
        db = self.db()
        jid = job["_id"]
        lock = f"domain:{job['domain_id']}"
        timeout_s = settings["job_timeout"]
        timed_out = threading.Event()
        try:
            if not ss.acquire_lock(db, lock, jid, ttl=timeout_s + settings["lease_seconds"]):
                db.scan_jobs.update_one({"_id": jid, "owner": self.owner}, {
                    "$set": {"status": "queued", "owner": None, "next_attempt_at": time.time() + LOCK_WAIT_SECONDS,
                             "message": "Waiting: another scan of this domain is running"}, "$inc": {"attempts": -1}})
                return "waiting"
            domain = db.monitored_domains.find_one({"_id": job["domain_id"]})
            if not domain or domain.get("deleting"):
                db.scan_jobs.update_one({"_id": jid}, {"$set": {"status": "cancelled", "finished": time.time(), "owner": None,
                                                                "error": "the monitored domain was deleted"}})
                return "cancelled"
            timer = threading.Timer(timeout_s, lambda: (timed_out.set(), cancel.set()))
            timer.daemon = True
            timer.start()
            try:
                return self._scan(db, job, domain, cancel)
            except HuntCancelled:
                if timed_out.is_set():
                    return self._failed(db, job, settings, f"timed out after {timeout_s} s")
                if self._stop.is_set():
                    db.scan_jobs.update_one({"_id": jid}, {"$set": {"status": "queued", "owner": None, "next_attempt_at": time.time(),
                                                                    "message": "interrupted by shutdown; will resume"},
                                                           "$inc": {"attempts": -1}})
                    return "requeued"
                db.scan_jobs.update_one({"_id": jid}, {"$set": {"status": "cancelled", "finished": time.time(), "owner": None,
                                                                "error": "cancelled by user", "message": "Cancelled"}})
                return "cancelled"
            except Exception as ex:
                return self._failed(db, job, settings, safe_error(ex))
            finally:
                timer.cancel()
        finally:
            ss.release_lock(db, lock, jid)
            with self._lock:
                self._job_cancel.pop(jid, None)

    def _scan(self, db, job: Dict[str, Any], domain: Dict[str, Any], cancel: threading.Event) -> str:
        jid = job["_id"]
        last = {"t": 0.0}

        def progress(stage, pct, msg, _stats):
            if cancel.is_set():
                raise HuntCancelled()
            if time.time() - last["t"] >= 1.5:
                last["t"] = time.time()
                db.scan_jobs.update_one({"_id": jid}, {"$set": {"stage": stage, "progress": pct, "message": str(msg)[:200]}})

        result = self._runner()(domain["domain"], depth=job.get("depth") or "standard", extra_allowlist=list(domain.get("allowlist") or []),
                                extra_keywords=list(job.get("keywords_used") or []), progress=progress, cancel=cancel)
        if cancel.is_set():
            raise HuntCancelled()
        from api.services.jobs import hunt_api_result
        api_result = hunt_api_result(result)
        api_result["hunt_id"] = jid
        store = get_store()
        try:
            store.decorate(api_result, exclude_id=jid)
            store.save_hunt(jid, api_result, scheduled=True)
            db.hunts.update_one({"_id": jid}, {"$set": {"scheduled_batch": True, "domain_id": domain["_id"],
                                                        "batch_id": job.get("batch_id"), "execution_id": job.get("execution_id")}})
            hunt_id: Optional[str] = jid
        except Exception:
            hunt_id = None   # the findings below still keep the evidence summary
        counts = ss.apply_scan_results(db, domain, job, api_result.get("candidates") or [], hunt_id, resolver=self.resolver or _resolve)
        now = time.time()
        issues = len(result.get("source_issues") or [])
        msg = f"{counts['new']} new, {counts['updated'] + counts['reappeared']} changed, {counts['confirmed']} confirmed, {counts['potential']} potential"
        db.scan_jobs.update_one({"_id": jid}, {"$set": {"status": "completed", "finished": now, "owner": None, "hunt_id": hunt_id,
                                                        "counts": counts, "progress": 100, "stage": "done", "message": msg,
                                                        "source_issues": issues}})
        db.monitored_domains.update_one({"_id": domain["_id"]}, {"$set": {"last_scan_at": now, "last_success_at": now, "last_status": "ok",
                                                                          "last_job_id": jid, "last_execution_id": job.get("execution_id")}})
        return "completed"

    def _failed(self, db, job: Dict[str, Any], settings: Dict[str, Any], error: str) -> str:
        jid = job["_id"]
        now = time.time()
        attempts = int(job.get("attempts") or 1)
        e = db.batch_executions.find_one({"_id": job["execution_id"]}, {"cancel_requested": 1}) or {}
        db.monitored_domains.update_one({"_id": job["domain_id"]}, {"$set": {"last_scan_at": now, "last_status": f"error: {error[:200]}",
                                                                            "last_job_id": jid}})
        if attempts < int(job.get("max_attempts") or settings["max_attempts"]) and not e.get("cancel_requested") and not self._stop.is_set():
            delay = settings["retry_base_seconds"] * (2 ** (attempts - 1))
            if any(w in error.lower() for w in RATE_LIMIT_WORDS):
                delay *= 3
            delay = min(3600, delay) * random.uniform(0.9, 1.1)
            db.scan_jobs.update_one({"_id": jid}, {"$set": {"status": "queued", "owner": None, "next_attempt_at": now + delay,
                                                            "error": error[:500], "message": f"Attempt {attempts} failed; retrying in {int(delay)} s"}})
            return "retry"
        db.scan_jobs.update_one({"_id": jid}, {"$set": {"status": "failed", "finished": now, "owner": None, "error": error[:500],
                                                        "message": f"Failed after {attempts} attempt(s)"}})
        return "failed"

    # ------------------------------------------------------------------ notifications
    def _notify(self, db, e: Optional[Dict[str, Any]]) -> None:
        if not e:
            return
        b = db.scan_batches.find_one({"_id": e["batch_id"]})
        if not b:
            return
        notify = b.get("notify") or {}
        classes = ["confirmed"] if notify.get("min_classification") == "confirmed" else ["confirmed", "potential"]
        new = list(db.scan_observations.find({"execution_id": e["_id"], "change": "new", "classification": {"$in": classes}},
                                             {"host": 1, "score": 1, "classification": 1}).sort("score", -1).limit(15))
        messages = []
        if notify.get("on_new", True) and new:
            hosts = ", ".join(f"{o['host']} ({o['score']})" for o in new[:10])
            messages.append(("high" if any(o["classification"] == "confirmed" for o in new) else "warning",
                             f"{b['name']}: {len(new)}{'+' if len(new) == 15 else ''} new impersonation finding(s)", f"New: {hosts}",
                             [o["host"] for o in new]))
        if notify.get("on_failure", True) and e["status"] in ("failed", "partially_completed"):
            messages.append(("error", f"{b['name']}: run {e['status'].replace('_', ' ')}",
                             f"{e.get('failed', 0)} of {e.get('total', 0)} domain scans failed.", []))
        if not messages:
            return
        try:
            store = get_store()
        except Exception:
            return
        alerts_impl = app_attr("alerts_mod", alerts_mod)
        for level, title, body, hosts in messages:
            delivery = ""
            if notify.get("webhook_url"):
                ok, msg = alerts_impl.send_webhook(notify["webhook_url"], title, body,
                                                   {"batch": b["name"], "execution_id": e["_id"], "domains": hosts})
                delivery = ("webhook: " if ok else "webhook failed: ") + msg
            if notify.get("in_app", True) or delivery:
                try:
                    store.alert_add(b["name"], level, title, body, None, delivery)
                except Exception:
                    pass


ENGINE = BatchScheduler()


def start_batch_scheduler() -> None:
    if os.environ.get("BRAND_HUNTER_SCHEDULER", "1") == "0":
        return
    ENGINE.start()


def stop_batch_scheduler() -> None:
    if ENGINE.state["running"]:
        ENGINE.stop()
