"""
Scan Scheduler: input parsing, schedules, batches, the execution engine (claims, isolation, lifecycle, retries,
timeouts, cancel, recovery, multi-instance safety, shutdown) and the scheduler API.

The hunt engine itself is replaced by a deterministic fake runner here (its own behaviour is covered by the hunt
tests); every database operation runs against an isolated in-memory MongoDB (mongomock, see conftest.py).
"""
import base64
import io
import os
import threading
import time
import uuid
from datetime import datetime
from unittest import mock
from zoneinfo import ZoneInfo

import pytest

from api.services.batch_scheduler import BatchScheduler
from core import domain_input as di
from core import schedule as sched
from core import scheduler_store as ss
from core.hunter import HuntCancelled
from core.store import get_store


# ============================================================== helpers
def cand(host, score=60, cls="Potential Impersonation", verdict="suspicious", a=("203.0.113.5",), **kw):
    return {"domain": host, "score": score, "verdict": verdict, "classification": cls, "sources": ["ct"],
            "dns": {"a": list(a), "aaaa": [], "mx": [], "ns": []}, "dns_status": "resolves", "evidence": None, "rdap": None,
            "reasons": ["why"], "fuzzer": "combo", "matched_keyword": kw.pop("kw", None), **kw}


class FakeHunts:
    """Stands in for core.hunter.run_hunt: returns scripted candidates per brand and records every call."""

    def __init__(self):
        self.script = {}
        self.calls = []
        self.fail = {}

    def __call__(self, target, depth="standard", extra_allowlist=None, extra_keywords=None, progress=None, cancel=None, **kw):
        self.calls.append({"target": target, "keywords": list(extra_keywords or []), "allowlist": list(extra_allowlist or []), "depth": depth})
        if progress:
            progress("dns", 50, f"Resolving {target}", {})
        if self.fail.get(target):
            self.fail[target] -= 1
            raise RuntimeError(f"source error for {target}")
        cands = self.script.get(target, [])
        cands = cands() if callable(cands) else cands
        return {"target": target, "depth": depth, "brand": {"icons": [], "allowlist": [target]}, "stats": {"registered": len(cands)},
                "candidates": [dict(c) for c in cands], "queries": {}, "dorks": {}, "errors": [], "source_issues": []}


LIVE_URI = os.environ.get("BRAND_HUNTER_TEST_MONGO_URI")


@pytest.fixture
def db(isolated_store):
    """mongomock by default. With BRAND_HUNTER_TEST_MONGO_URI set, a real server and a throwaway bih_test_* database
    (dropped afterwards) so locks, unique/sparse indexes and bulk writes are proven against real MongoDB semantics."""
    live = None
    if LIVE_URI:
        from pymongo import MongoClient
        from core import store as store_mod
        from core.mongostore import MongoStore
        name = f"bih_test_{uuid.uuid4().hex[:8]}"
        live = MongoStore(MongoClient(LIVE_URI, serverSelectionTimeoutMS=4000), name)
        store_mod.set_store(live)
        d = live.db
    else:
        d = isolated_store.db
    ss.ensure_indexes(d)
    d.application_settings.update_one({"_id": "scheduler"}, {"$set": {"retry_base_seconds": 0, "max_attempts": 2}}, upsert=True)
    yield d
    if live is not None:
        live._client.drop_database(live.db_name)
        live.close()


@pytest.fixture
def hunts():
    return FakeHunts()


@pytest.fixture
def engine(hunts):
    return BatchScheduler(owner="test-a", poll_seconds=0.01, stagger_seconds=0, runner=hunts, resolver=lambda hosts: {})


def make_batch(db, name="Banks", domains=(("paypal.com", ["paypal", "venmo"]),), **kw):
    b = ss.create_batch(db, {"name": name, "schedule": kw.pop("schedule", {"frequency": "manual"}), **kw})
    ss.batch_add_entries(db, b["_id"], [{"domain": d, "keywords": k} for d, k in domains])
    return ss.get_batch(db, b["_id"])


def run_now(db, engine, batch, **kw):
    e = ss.create_execution(db, batch, "manual", **kw)
    engine.tick(run_inline=True)
    return db.batch_executions.find_one({"_id": e["_id"]})


def domain_id(db, host):
    return db.monitored_domains.find_one({"domain": host})["_id"]


# ============================================================== bulk input
class TestDomainInput:
    def test_normalisation_and_errors_are_reported_not_dropped(self):
        entries = di.parse_text("https://www.PayPal.com/signin?x=1\nlogin.microsoft.com:443\nnot a domain\n# comment\n\n"
                                "10.0.0.1\nintranet.local\nbücher.de, buch; bücher\nfoo\n")
        got = [(e["domain"], e["status"]) for e in entries]
        assert got == [("paypal.com", "valid"), ("login.microsoft.com", "valid"), (None, "invalid"), (None, "invalid"),
                       (None, "invalid"), ("xn--bcher-kva.de", "valid"), (None, "invalid")]
        assert entries[5]["keywords"] == ["buch", "bücher"]
        assert all(e["error"] for e in entries if e["status"] == "invalid")
        assert entries[2]["input"] == "not a domain" and entries[2]["line"] == 3

    def test_duplicates_are_flagged_and_their_keywords_merged(self):
        entries = di.parse_text("paypal.com, paypal\nPAYPAL.com, venmo\nwww.paypal.com\nnetflix.com")
        s = di.mark_duplicates(entries, existing={"netflix.com"})
        assert (s["valid"], s["duplicates"]) == (2, 2)
        assert entries[0]["keywords"] == ["paypal", "venmo"]
        assert entries[1]["error"] == "same domain as line 1"
        assert entries[3]["already_in_batch"] is True

    def test_csv_with_header_and_excel(self):
        csv_text = "Organization,Website,Keywords\nPayPal,https://paypal.com,paypal;venmo\nMS,microsoft.com,\n"
        e = di.parse_upload("list.csv", base64.b64encode(csv_text.encode()).decode())
        assert [(x["domain"], x["organization"], x["keywords"]) for x in e] == [("paypal.com", "PayPal", ["paypal", "venmo"]), ("microsoft.com", "MS", [])]
        import openpyxl
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.append(["domain", "keywords"])
        ws.append(["amazon.com", "amazon|aws"])
        ws.append(["bad domain", ""])
        buf = io.BytesIO()
        wb.save(buf)
        x = di.parse_upload("d.xlsx", base64.b64encode(buf.getvalue()).decode())
        assert [(r["domain"], r["status"]) for r in x] == [("amazon.com", "valid"), (None, "invalid")]
        assert x[0]["keywords"] == ["amazon", "aws"]

    def test_upload_limits_and_types(self):
        with pytest.raises(di.InputError):
            di.parse_upload("x.exe", base64.b64encode(b"paypal.com").decode())
        with pytest.raises(di.InputError):
            di.parse_upload("x.txt", base64.b64encode(b"a" * (di.MAX_UPLOAD_BYTES + 1)).decode())
        with pytest.raises(di.InputError):
            di.parse_upload("x.xlsx", base64.b64encode(b"not a zip").decode())
        with pytest.raises(di.InputError):
            di.parse_upload("x.txt", "%%%not-base64")

    def test_keyword_validation(self):
        kws, problems = di.clean_keywords(["PayPal", "pay pal", "<script>", "x" * 80, "paypal"])
        assert kws == ["paypal", "pay pal"]
        assert len(problems) == 2


# ============================================================== schedules
class TestSchedule:
    def test_daily_in_time_zone(self):
        spec = sched.validate({"frequency": "daily", "time": "02:30", "timezone": "Asia/Kolkata"})
        after = datetime(2026, 3, 1, 3, 0, tzinfo=ZoneInfo("Asia/Kolkata")).timestamp()
        nxt = datetime.fromtimestamp(sched.next_run(spec, after), ZoneInfo("Asia/Kolkata"))
        assert (nxt.day, nxt.hour, nxt.minute) == (2, 2, 30)

    def test_weekly_and_dst_gap(self):
        spec = sched.validate({"frequency": "weekly", "time": "09:00", "timezone": "Europe/Berlin", "weekdays": [3]})
        after = datetime(2026, 3, 2, 12, 0, tzinfo=ZoneInfo("Europe/Berlin")).timestamp()  # Monday
        nxt = datetime.fromtimestamp(sched.next_run(spec, after), ZoneInfo("Europe/Berlin"))
        assert (nxt.weekday(), nxt.hour) == (3, 9)
        gap = sched.validate({"frequency": "daily", "time": "02:30", "timezone": "America/New_York"})
        after = datetime(2026, 3, 7, 12, 0, tzinfo=ZoneInfo("America/New_York")).timestamp()
        nxt = sched.next_run(gap, after)          # 2026-03-08 02:30 does not exist locally
        local = datetime.fromtimestamp(nxt, ZoneInfo("America/New_York"))
        assert local.day == 8 and local.hour == 3   # runs right after the gap, once

    def test_interval_keeps_its_grid_after_missed_periods(self):
        spec = sched.validate({"frequency": "interval", "interval_hours": 6})
        assert sched.next_run(spec, 1000, anchor=1000) == 1000 + 6 * 3600
        assert sched.next_run(spec, 1000 + 20 * 3600, anchor=1000) == 1000 + 24 * 3600
        assert sched.next_run({"frequency": "manual"}, 1000) is None

    def test_validation(self):
        for bad in ({"frequency": "hourly"}, {"frequency": "daily", "time": "25:00"}, {"frequency": "daily", "timezone": "Mars/Base"},
                    {"frequency": "weekly", "weekdays": []}, {"frequency": "weekly", "weekdays": [9]},
                    {"frequency": "interval", "interval_hours": 0.1}):
            with pytest.raises(sched.ScheduleError):
                sched.validate(bad)


# ============================================================== batches & executions
class TestBatches:
    def test_create_unique_name_and_membership(self, db):
        b = make_batch(db, domains=(("paypal.com", ["paypal"]), ("microsoft.com", [])))
        assert ss.batch_public(db, b)["domain_count"] == 2
        with pytest.raises(ss.Conflict):
            ss.create_batch(db, {"name": "banks", "schedule": {"frequency": "manual"}})
        out = ss.batch_add_entries(db, b["_id"], [{"domain": "paypal.com"}, {"domain": "nope"}, {"domain": "netflix.com"}])
        assert (out["added"], out["already_in_batch"], len(out["errors"])) == (["netflix.com"], ["paypal.com"], 1)

    def test_domain_shared_by_two_batches_has_one_config(self, db):
        a = make_batch(db, "A", (("paypal.com", ["paypal"]),))
        b = make_batch(db, "B", (("paypal.com", ["venmo"]),))
        assert db.monitored_domains.count_documents({}) == 1
        assert db.monitored_domains.find_one()["keywords"] == ["paypal", "venmo"]
        assert ss.batch_domain_ids(db, a["_id"]) == ss.batch_domain_ids(db, b["_id"])

    def test_overlap_and_slot_idempotency(self, db):
        b = make_batch(db)
        ss.create_execution(db, b, "manual")
        with pytest.raises(ss.Conflict):
            ss.create_execution(db, b, "manual")                       # one active run per batch
        db.batch_executions.update_many({}, {"$set": {"status": "completed"}})
        db.scan_batches.update_one({"_id": b["_id"]}, {"$set": {"active_execution_id": None}})
        ss.create_execution(db, b, "schedule", slot=1000.0)
        db.batch_executions.update_many({}, {"$set": {"status": "completed"}})
        db.scan_batches.update_one({"_id": b["_id"]}, {"$set": {"active_execution_id": None}})
        with pytest.raises(ss.Conflict):
            ss.create_execution(db, b, "schedule", slot=1000.0)         # same slot never runs twice
        assert db.scan_batches.find_one({"_id": b["_id"]})["active_execution_id"] is None

    def test_paused_domain_is_skipped(self, db):
        b = make_batch(db, domains=(("paypal.com", []), ("microsoft.com", [])))
        ss.update_domain(db, domain_id(db, "microsoft.com"), {"status": "paused"})
        e = ss.create_execution(db, b, "manual")
        assert (e["total"], e["queued"], e["skipped"]) == (2, 1, 1)

    def test_webhook_secret_never_returned(self, db):
        b = ss.create_batch(db, {"name": "W", "schedule": {"frequency": "manual"}, "notify": {"webhook_url": "https://hooks.example/T0KEN1234567"}})
        pub = ss.batch_public(db, b)
        assert "T0KEN" not in repr(pub) and pub["notify"]["webhook"]["set"] is True


# ============================================================== engine
class TestEngine:
    def test_each_domain_is_scanned_with_its_own_keywords_and_results_stay_isolated(self, db, engine, hunts):
        hunts.script = {"paypal.com": [cand("paypal-login.example-host.com", 80, "Confirmed Impersonation", "phishing", kw="paypal"),
                                       cand("shared-bad.com", 50)],
                        "microsoft.com": [cand("shared-bad.com", 55), cand("micros0ft-sso.com", 70)]}
        b = make_batch(db, domains=(("paypal.com", ["paypal", "venmo"]), ("microsoft.com", ["outlook"])))
        e = run_now(db, engine, b)
        assert e["status"] == "completed" and (e["completed"], e["total"], e["new_findings"]) == (2, 2, 4)
        calls = {c["target"]: c["keywords"] for c in hunts.calls}
        assert calls == {"paypal.com": ["paypal", "venmo"], "microsoft.com": ["outlook"]}
        pp, ms = domain_id(db, "paypal.com"), domain_id(db, "microsoft.com")
        a = ss.list_findings(db, pp)["items"]
        m = ss.list_findings(db, ms)["items"]
        assert sorted(f["host"] for f in a) == ["paypal-login.example-host.com", "shared-bad.com"]
        assert sorted(f["host"] for f in m) == ["micros0ft-sso.com", "shared-bad.com"]
        shared = db.impersonation_findings.find({"host": "shared-bad.com"})
        assert sorted((f["domain_id"], f["score"]) for f in shared) == sorted([(pp, 50), (ms, 55)])   # two separate findings
        f = db.impersonation_findings.find_one({"domain_id": pp, "host": "paypal-login.example-host.com"})
        assert (f["classification"], f["original_domain"], f["last_batch_id"], f["keywords_used"]) == ("confirmed", "paypal.com", b["_id"], ["paypal", "venmo"])
        assert f["first_job_id"] == f["last_job_id"] and f["last_execution_id"] == e["_id"]
        job = db.scan_jobs.find_one({"_id": f["last_job_id"]})
        assert job["hunt_id"] == job["_id"] and get_store().get_hunt(job["_id"])["target"] == "paypal.com"   # full evidence saved
        assert db.hunts.find_one({"_id": job["_id"]})["scheduled_batch"] is True
        assert ss.list_findings(db, pp, view="confirmed")["total"] == 1

    def test_lifecycle_across_runs(self, db, engine, hunts):
        state = {"cands": [cand("a-paypal.com", 60), cand("b-paypal.com", 40), cand("c-paypal.com", 45)]}
        hunts.script = {"paypal.com": lambda: state["cands"]}
        gone = set()
        engine.resolver = lambda hosts: {h: {"status": "nxdomain" if h in gone else "timeout"} for h in hosts}
        b = make_batch(db)
        pp = domain_id(db, "paypal.com")
        run_now(db, engine, b)
        lc = lambda: {f["host"]: f["lifecycle"] for f in db.impersonation_findings.find({"domain_id": pp})}  # noqa: E731
        assert lc() == {"a-paypal.com": "new", "b-paypal.com": "new", "c-paypal.com": "new"}
        first = db.impersonation_findings.find_one({"host": "a-paypal.com"})["first_seen"]

        state["cands"] = [cand("a-paypal.com", 60), cand("b-paypal.com", 75)]     # c missing; its DNS times out
        run_now(db, engine, b)
        assert lc() == {"a-paypal.com": "seen", "b-paypal.com": "updated", "c-paypal.com": "new"}   # a missing host is not "gone"
        c = db.impersonation_findings.find_one({"host": "c-paypal.com"})
        assert c["missed_scans"] == 1
        a = db.impersonation_findings.find_one({"host": "a-paypal.com"})
        assert a["first_seen"] == first and a["last_seen"] > first

        gone.add("c-paypal.com")
        state["cands"] = [cand("a-paypal.com", 60), cand("b-paypal.com", 75)]
        run_now(db, engine, b)
        assert lc()["c-paypal.com"] == "unreachable"
        state["cands"] = [cand("a-paypal.com", 60), cand("b-paypal.com", 75), cand("c-paypal.com", 45)]
        e = run_now(db, engine, b)
        assert lc()["c-paypal.com"] == "reappeared" and e["updated_findings"] == 1
        hist = ss.finding_history(db, pp, f"{pp}:c-paypal.com")
        assert [h["change"] for h in hist] == ["reappeared", "unreachable", "new"]

    def test_benign_hosts_are_not_stored_unless_already_findings(self, db, engine, hunts):
        hunts.script = {"paypal.com": [cand("paypal-fan-blog.com", 5, "Benign/Unrelated", "live_unrelated")]}
        b = make_batch(db)
        run_now(db, engine, b)
        assert db.impersonation_findings.count_documents({}) == 0

    def test_retry_with_backoff_then_success_and_failure(self, db, engine, hunts):
        hunts.script = {"paypal.com": [cand("x-paypal.com")], "microsoft.com": [cand("y-microsoft.com")]}
        hunts.fail = {"paypal.com": 1, "microsoft.com": 5}
        b = make_batch(db, domains=(("paypal.com", []), ("microsoft.com", [])))
        e = run_now(db, engine, b)
        jobs = {j["domain"]: j for j in db.scan_jobs.find({"execution_id": e["_id"]})}
        assert (jobs["paypal.com"]["status"], jobs["paypal.com"]["attempts"]) == ("completed", 2)
        assert (jobs["microsoft.com"]["status"], jobs["microsoft.com"]["attempts"]) == ("failed", 2)
        assert "source error" in jobs["microsoft.com"]["error"]
        assert e["status"] == "partially_completed"
        assert db.monitored_domains.find_one({"domain": "microsoft.com"})["last_status"].startswith("error")
        alerts = get_store().alert_list()
        assert any("partially completed" in a["title"] for a in alerts) and any("new impersonation" in a["title"] for a in alerts)

        hunts.fail = {}
        db.scan_batches.update_one({"_id": b["_id"]}, {"$set": {"active_execution_id": None}})
        retry = ss.create_execution(db, ss.get_batch(db, b["_id"]), "retry", domain_ids=ss.failed_domain_ids(db, e["_id"]), retry_of=e["_id"])
        engine.tick(run_inline=True)
        r = db.batch_executions.find_one({"_id": retry["_id"]})
        assert (r["status"], r["total"], r["retry_of"]) == ("completed", 1, e["_id"])

    def test_backoff_delay_grows_and_rate_limits_wait_longer(self, db, engine):
        db.application_settings.update_one({"_id": "scheduler"}, {"$set": {"retry_base_seconds": 60, "max_attempts": 5}})
        b = make_batch(db)
        ex = ss.create_execution(db, b, "manual")
        job = db.scan_jobs.find_one({"execution_id": ex["_id"]})
        settings = ss.get_settings(db)
        t = time.time()
        engine._failed(db, {**job, "attempts": 1}, settings, "boom")
        d1 = db.scan_jobs.find_one({"_id": job["_id"]})["next_attempt_at"] - t
        engine._failed(db, {**job, "attempts": 3}, settings, "HTTP 429 Too Many Requests")
        d3 = db.scan_jobs.find_one({"_id": job["_id"]})["next_attempt_at"] - t
        assert 50 < d1 < 70 and 600 < d3 < 800     # 60 s, then 60*4*3 = 720 s

    def test_timeout_marks_the_job_failed(self, db, engine, hunts):
        db.application_settings.update_one({"_id": "scheduler"}, {"$set": {"job_timeout": 0.3, "max_attempts": 1}})

        def slow(target, cancel=None, **kw):
            cancel.wait(5)
            raise HuntCancelled()
        engine.runner = slow
        e = run_now(db, engine, make_batch(db))
        job = db.scan_jobs.find_one({"execution_id": e["_id"]})
        assert job["status"] == "failed" and "timed out" in job["error"] and e["status"] == "failed"

    def test_cancel_stops_running_and_queued_jobs(self, db, engine):
        started = threading.Event()

        def slow(target, cancel=None, **kw):
            started.set()
            cancel.wait(5)
            raise HuntCancelled()
        engine.runner = slow
        db.application_settings.update_one({"_id": "scheduler"}, {"$set": {"concurrency": 1}})
        b = make_batch(db, domains=(("paypal.com", []), ("microsoft.com", []), ("netflix.com", [])))
        ex = ss.create_execution(db, b, "manual")
        t = threading.Thread(target=engine.tick, kwargs={"run_inline": True})
        t.start()
        assert started.wait(5)
        ss.request_cancel(db, ex["_id"])
        t.join(10)
        e = db.batch_executions.find_one({"_id": ex["_id"]})
        assert e["status"] == "cancelled" and e["cancelled"] == 3
        assert db.scan_batches.find_one({"_id": b["_id"]})["active_execution_id"] is None
        assert db.scheduler_locks.count_documents({}) == 0

    def test_no_overlapping_scans_of_one_domain(self, db, engine, hunts):
        b = make_batch(db)
        pp = domain_id(db, "paypal.com")
        assert ss.acquire_lock(db, f"domain:{pp}", "jb_otherjob0000", ttl=600)    # another batch is scanning it
        ex = ss.create_execution(db, b, "manual")
        job = db.scan_jobs.find_one_and_update({"execution_id": ex["_id"]}, {"$set": {"status": "running", "owner": engine.owner}, "$inc": {"attempts": 1}}, return_document=True)
        assert engine.run_job(job, ss.get_settings(db), threading.Event()) == "waiting"
        j = db.scan_jobs.find_one({"_id": job["_id"]})
        assert (j["status"], j["attempts"]) == ("queued", 0) and j["next_attempt_at"] > time.time() + 10
        assert hunts.calls == []
        ss.release_lock(db, f"domain:{pp}", "jb_otherjob0000")

    def test_scheduled_slots_run_once_across_two_instances(self, db, hunts):
        hunts.script = {"paypal.com": [cand("x-paypal.com")]}
        b = make_batch(db, schedule={"frequency": "daily", "time": "02:00", "timezone": "UTC"})
        slot = time.time() - 30
        db.scan_batches.update_one({"_id": b["_id"]}, {"$set": {"next_run_at": slot}})
        one = BatchScheduler(owner="inst-1", poll_seconds=0.01, stagger_seconds=0, runner=hunts, resolver=lambda h: {})
        two = BatchScheduler(owner="inst-2", poll_seconds=0.01, stagger_seconds=0, runner=hunts, resolver=lambda h: {})
        r1 = one.schedule_due(db, time.time())
        r2 = two.schedule_due(db, time.time())
        assert [x["result"] for x in r1] == ["queued"] and r2 == []
        assert db.scan_batches.find_one({"_id": b["_id"]})["next_run_at"] > time.time()
        db.scan_batches.update_one({"_id": b["_id"]}, {"$set": {"next_run_at": slot}})       # a second instance racing the same slot
        assert "skipped" in two.schedule_due(db, time.time())[0]["result"]
        assert db.batch_executions.count_documents({"batch_id": b["_id"]}) == 1
        assert one.launch_queued(db, time.time(), ss.get_settings(db), run_inline=True) and \
            two.launch_queued(db, time.time(), ss.get_settings(db), run_inline=True) == []
        assert len(hunts.calls) == 1

    def test_missed_run_policies(self, db, engine):
        long_ago = time.time() - 3 * 86400
        skip = make_batch(db, "Skip", (("paypal.com", []),), schedule={"frequency": "daily", "time": "02:00", "timezone": "UTC"}, missed_policy="skip")
        once = make_batch(db, "Once", (("netflix.com", []),), schedule={"frequency": "daily", "time": "02:00", "timezone": "UTC"})
        db.scan_batches.update_many({}, {"$set": {"next_run_at": long_ago}})
        res = {r["batch_id"]: r["result"] for r in engine.schedule_due(db, time.time())}
        assert res == {skip["_id"]: "missed_skipped", once["_id"]: "queued"}
        assert db.batch_executions.count_documents({"batch_id": once["_id"]}) == 1          # one catch-up run, not three
        assert all(b["next_run_at"] > time.time() for b in db.scan_batches.find())

    def test_restart_recovery_requeues_interrupted_work(self, db, engine, hunts):
        hunts.script = {"paypal.com": [cand("x-paypal.com")]}
        b = make_batch(db, domains=(("paypal.com", []), ("microsoft.com", [])))
        ex = ss.create_execution(db, b, "manual")
        stale = time.time() - 3600
        db.batch_executions.update_one({"_id": ex["_id"]}, {"$set": {"status": "running", "owner": "dead-instance", "heartbeat": stale}})
        jobs = list(db.scan_jobs.find({"execution_id": ex["_id"]}))
        db.scan_jobs.update_one({"_id": jobs[0]["_id"]}, {"$set": {"status": "running", "owner": "dead-instance", "attempts": 1}})
        db.scan_jobs.update_one({"_id": jobs[1]["_id"]}, {"$set": {"status": "running", "owner": "dead-instance", "attempts": 2}})
        out = engine.tick(run_inline=True)
        assert out["recovered"] == [ex["_id"]] and out["launched"] == [ex["_id"]]
        e = db.batch_executions.find_one({"_id": ex["_id"]})
        statuses = sorted(j["status"] for j in db.scan_jobs.find({"execution_id": ex["_id"]}))
        assert statuses == ["completed", "failed"]            # the job already at max attempts is not retried forever
        assert e["status"] == "partially_completed" and e["owner"] == engine.owner

    def test_graceful_shutdown_requeues_without_counting_an_attempt(self, db, engine):
        def stopping(target, cancel=None, **kw):
            engine._stop.set()
            raise HuntCancelled()
        engine.runner = stopping
        b = make_batch(db)
        ex = ss.create_execution(db, b, "manual")
        engine.tick(run_inline=True)
        e = db.batch_executions.find_one({"_id": ex["_id"]})
        j = db.scan_jobs.find_one({"execution_id": ex["_id"]})
        assert (e["status"], e["owner"]) == ("queued", None)
        assert (j["status"], j["attempts"]) == ("queued", 0)

    def test_disabled_scheduler_does_nothing(self, db, engine):
        b = make_batch(db, schedule={"frequency": "interval", "interval_hours": 1})
        db.scan_batches.update_one({"_id": b["_id"]}, {"$set": {"next_run_at": time.time() - 10}})
        ss.update_settings(db, {"enabled": False})
        assert engine.tick(run_inline=True)["disabled"] is True
        assert db.batch_executions.count_documents({}) == 0


class TestDismissal:
    def test_dismissed_findings_stay_hidden_and_silent_until_confirmed(self, db, engine, hunts):
        state = {"c": [cand("fp-paypal.com", 50), cand("lead-paypal.com", 55)]}
        hunts.script = {"paypal.com": lambda: state["c"]}
        b = make_batch(db)
        run_now(db, engine, b)
        pp = domain_id(db, "paypal.com")
        assert ss.set_dismissed(db, pp, [f"{pp}:fp-paypal.com", "md_000000000000:x.com"], True, "partner site") == 1   # other domains ignored
        assert [f["host"] for f in ss.list_findings(db, pp)["items"]] == ["lead-paypal.com"]
        assert [f["host"] for f in ss.list_findings(db, pp, view="dismissed")["items"]] == ["fp-paypal.com"]
        assert ss.findings_counts(db, [pp])["dismissed"] == 1 and ss.findings_counts(db, [pp])["total"] == 1
        f = db.impersonation_findings.find_one({"_id": f"{pp}:fp-paypal.com"})
        assert f["dismissed_reason"] == "partner site"

        db.alerts.delete_many({})
        state["c"] = [cand("fp-paypal.com", 52), cand("lead-paypal.com", 55)]
        run_now(db, engine, b)                                                    # rescan: still dismissed
        assert db.impersonation_findings.find_one({"_id": f"{pp}:fp-paypal.com"})["dismissed"] is True

        state["c"] = [cand("fp-paypal.com", 90, "Confirmed Impersonation", "phishing"), cand("lead-paypal.com", 55)]
        e = run_now(db, engine, b)                                                 # now confirmed: back in review
        f = db.impersonation_findings.find_one({"_id": f"{pp}:fp-paypal.com"})
        assert f["dismissed"] is False and f.get("escalated_at")
        job = db.scan_jobs.find_one({"execution_id": e["_id"]})
        assert job["counts"].get("escalated") == 1

    def test_dismissed_new_findings_do_not_alert(self, db, engine, hunts):
        hunts.script = {"paypal.com": [cand("a-paypal.com", 60)]}
        b = make_batch(db)
        ex = ss.create_execution(db, b, "manual")
        engine.tick(run_inline=True)
        pp = domain_id(db, "paypal.com")
        db.alerts.delete_many({})
        ss.set_dismissed(db, pp, [f"{pp}:a-paypal.com"], True)
        engine._notify(db, db.batch_executions.find_one({"_id": ex["_id"]}))
        assert not any("new impersonation" in a["title"] for a in get_store().alert_list())


class TestCountersAndRetention:
    def test_stored_counters_always_match_a_live_count(self, db, engine, hunts):
        state = {"c": [cand(f"h{i}-paypal.com", 40 + i) for i in range(12)]}
        hunts.script = {"paypal.com": lambda: state["c"], "microsoft.com": [cand("m-1.com", 75, "Confirmed Impersonation", "phishing")]}
        b = make_batch(db, domains=(("paypal.com", []), ("microsoft.com", [])))
        ids = ss.batch_domain_ids(db, b["_id"])
        pp = domain_id(db, "paypal.com")

        def check():
            assert ss.findings_counts(db, ids) == ss._findings_counts_live(db, ids)
            for i in ids:
                assert ss.findings_counts(db, [i]) == ss._findings_counts_live(db, [i])
        run_now(db, engine, b)
        check()
        state["c"] = state["c"][3:] + [cand("new-paypal.com", 66)]
        state["c"][0] = cand("h3-paypal.com", 99, "Confirmed Impersonation", "phishing")
        run_now(db, engine, b)
        check()
        ss.set_dismissed(db, pp, [f"{pp}:h4-paypal.com", f"{pp}:h5-paypal.com"], True)
        check()
        ss.delete_findings(db, pp, [f"{pp}:h6-paypal.com"])
        check()
        ss.clear_domain_history(db, pp)
        check()
        assert db.monitored_domains.find_one({"_id": pp})["stats"]["observations"] == 0
        db.monitored_domains.update_many({}, {"$unset": {"stats": 1}})        # older data without counters
        check()

    def test_only_changes_are_recorded_and_retention_is_applied(self, db, engine, hunts):
        hunts.script = {"paypal.com": [cand("a-paypal.com", 60), cand("b-paypal.com", 61)]}
        b = make_batch(db)
        run_now(db, engine, b)
        run_now(db, engine, b)                                               # identical second scan
        pp = domain_id(db, "paypal.com")
        assert [o["change"] for o in db.scan_observations.find({"domain_id": pp})] == ["new", "new"]
        assert db.impersonation_findings.find_one({"_id": f"{pp}:a-paypal.com"})["lifecycle"] == "seen"
        o = db.scan_observations.find_one({"domain_id": pp})
        assert o["observed_dt"].year >= 2024                                  # the TTL field
        ttl = db.scan_observations.index_information()["observed_dt_ttl"]
        assert ttl["expireAfterSeconds"] == 365 * 86400
        ss.update_settings(db, {"observation_retention_days": 30})
        assert db.scan_observations.index_information()["observed_dt_ttl"]["expireAfterSeconds"] == 30 * 86400
        with pytest.raises(ss.DataError):
            ss.update_settings(db, {"observation_retention_days": 1})


class TestAtomicDeletes:
    def test_interrupted_delete_rolls_back_or_is_finished_by_the_engine(self, db, engine, hunts):
        hunts.script = {"paypal.com": [cand("x-paypal.com")], "netflix.com": [cand("y-netflix.com")]}
        b = make_batch(db, domains=(("paypal.com", []), ("netflix.com", [])))
        run_now(db, engine, b)
        pp, nf = domain_id(db, "paypal.com"), domain_id(db, "netflix.com")
        with mock.patch.object(ss, "refresh_execution_totals", side_effect=RuntimeError("process died mid-delete")):
            with pytest.raises(RuntimeError):
                ss.delete_domain(db, pp)
        if ss.supports_transactions(db):
            # one transaction: nothing was deleted, nothing is left half-done
            assert db.impersonation_findings.count_documents({"domain_id": pp}) == 1
            assert not db.monitored_domains.find_one({"_id": pp}).get("deleting")
            out = ss.delete_domain(db, pp)
            assert out["transaction"] is True
        else:
            # standalone: the target is hidden at once and the engine finishes the idempotent delete
            assert db.monitored_domains.find_one({"_id": pp})["deleting"] is True
            with pytest.raises(ss.NotFound):
                ss.get_domain(db, pp)
            assert pp not in [d["id"] for d in ss.data_summary(db)["domains"]]
            assert ss.finish_interrupted_deletes(db, older_than=-1) == [pp]
        assert db.monitored_domains.find_one({"_id": pp}) is None
        assert db.impersonation_findings.count_documents({"domain_id": pp}) == 0
        assert db.impersonation_findings.count_documents({"domain_id": nf}) == 1          # the other domain is untouched

    def test_conflict_inside_the_delete_changes_nothing(self, db, engine):
        b = make_batch(db)
        ss.create_execution(db, b, "manual")
        db.scan_jobs.update_many({}, {"$set": {"status": "running"}})
        with pytest.raises(ss.Conflict):
            ss.delete_domain(db, domain_id(db, "paypal.com"))
        assert not db.monitored_domains.find_one({"domain": "paypal.com"}).get("deleting")


# ============================================================== API
@pytest.fixture
def client(db, engine):
    from fastapi.testclient import TestClient
    import app as app_module
    with mock.patch("api.routes.scheduler.ENGINE", engine), \
            mock.patch.multiple(app_module, SETTINGS_ALLOWED_CLIENTS={"testclient"}, SETTINGS_ALLOWED_HOSTS={"testserver"}):
        yield TestClient(app_module.app)


class TestApi:
    def _create(self, client, name="Banks", domains=None):
        r = client.post("/api/scheduler/batches", json={
            "name": name, "description": "d", "schedule": {"frequency": "daily", "time": "03:15", "timezone": "Asia/Kolkata"},
            "domains": domains or [{"domain": "https://www.paypal.com/x", "keywords": ["paypal"]}, {"domain": "microsoft.com", "keywords": ["outlook"]}]})
        assert r.status_code == 200, r.text
        return r.json()

    def test_batch_crud_parse_and_run(self, client, db, engine, hunts):
        hunts.script = {"paypal.com": [cand("paypal-verify.com", 72)]}
        created = self._create(client)
        bid = created["batch"]["id"]
        assert created["import"]["added"] == ["paypal.com", "microsoft.com"]
        assert created["batch"]["schedule_text"] == "Daily at 03:15 (Asia/Kolkata)" and created["batch"]["next_run_at"] > time.time()
        p = client.post("/api/scheduler/parse", json={"text": "paypal.com\nnetflix.com\nbad entry", "batch_id": bid}).json()
        assert [e["status"] for e in p["entries"]] == ["valid", "valid", "invalid"] and p["entries"][0]["already_in_batch"]
        assert client.post("/api/scheduler/batches", json={"name": "banks"}).status_code == 409
        assert client.post("/api/scheduler/batches", json={"name": "x", "schedule": {"frequency": "daily", "time": "99:00"}}).status_code == 400
        assert client.patch(f"/api/scheduler/batches/{bid}", json={"description": "new"}).json()["batch"]["description"] == "new"
        for st, disp in (("paused", "Paused"), ("active", "Scheduled"), ("disabled", "Disabled")):
            assert client.post(f"/api/scheduler/batches/{bid}/status", json={"status": st}).json()["batch"]["display_status"] == disp
        assert client.post(f"/api/scheduler/batches/{bid}/run").status_code == 409             # disabled
        client.post(f"/api/scheduler/batches/{bid}/status", json={"status": "active"})
        ex = client.post(f"/api/scheduler/batches/{bid}/run").json()["execution"]
        assert client.post(f"/api/scheduler/batches/{bid}/run").status_code == 409             # already running
        engine.tick(run_inline=True)
        detail = client.get(f"/api/scheduler/executions/{ex['id']}").json()
        assert detail["execution"]["status"] == "completed" and len(detail["jobs"]) == 2
        batch = client.get(f"/api/scheduler/batches/{bid}").json()
        assert batch["batch"]["counts"]["new"] == 1 and {d["domain"] for d in batch["domains"]} == {"paypal.com", "microsoft.com"}
        dup = client.post(f"/api/scheduler/batches/{bid}/duplicate").json()["batch"]
        assert dup["name"] == "Banks (copy)" and dup["status"] == "paused" and dup["domain_count"] == 2
        ov = client.get("/api/scheduler/overview").json()
        assert ov["batches"] == 2 and ov["findings"]["total"] == 1 and ov["upcoming"][0]["batch_id"] == bid

    def test_domain_dashboard_is_isolated_server_side(self, client, db, engine, hunts):
        hunts.script = {"paypal.com": [cand("same.com", 60), cand("pp-only.com", 90, "Confirmed Impersonation", "phishing")],
                        "microsoft.com": [cand("same.com", 61)]}
        bid = self._create(client)["batch"]["id"]
        client.post(f"/api/scheduler/batches/{bid}/run")
        engine.tick(run_inline=True)
        pp, ms = domain_id(db, "paypal.com"), domain_id(db, "microsoft.com")
        a = client.get(f"/api/scheduler/domains/{pp}/findings").json()
        assert a["total"] == 2 and all(f["domain_id"] == pp for f in a["items"])
        assert client.get(f"/api/scheduler/domains/{ms}/findings?view=confirmed").json()["total"] == 0
        assert client.get(f"/api/scheduler/domains/{pp}/findings?q=only").json()["total"] == 1
        assert client.get(f"/api/scheduler/domains/{pp}/findings?q=.*").json()["total"] == 0     # regex characters are literal
        dash = client.get(f"/api/scheduler/domains/{pp}").json()
        assert dash["counts"]["confirmed"] == 1 and dash["batches"][0]["id"] == bid and dash["scans"] == 1
        # a finding id of another domain is refused through this domain's endpoints
        assert client.get(f"/api/scheduler/domains/{pp}/findings/history", params={"finding_id": f"{ms}:same.com"}).status_code == 404
        r = client.post(f"/api/data/domains/{pp}/findings/delete", json={"confirm": "paypal.com", "ids": [f"{ms}:same.com"]}).json()
        assert r["deleted"]["findings"] == 0 and db.impersonation_findings.count_documents({"domain_id": ms}) == 1
        assert client.get("/api/scheduler/domains/md_000000000000").status_code == 404
        assert client.get("/api/scheduler/domains/$where").status_code == 404
        assert client.patch(f"/api/scheduler/domains/{pp}", json={"keywords": ["paypal", "pp"]}).json()["domain"]["keywords"] == ["paypal", "pp"]
        csv_text = client.get(f"/api/scheduler/domains/{pp}/export?format=csv").text
        assert csv_text.splitlines()[0].startswith("host,classification") and "pp-only.com" in csv_text and "same.com" in csv_text
        assert client.get(f"/api/scheduler/domains/{pp}/export?format=json").json()["domain"] == "paypal.com"
        ex = client.post(f"/api/scheduler/domains/{pp}/run", json={}).json()["execution"]
        assert ex["total"] == 1 and ex["trigger"] == "manual_domain"

    def test_batch_export_dismiss_api_and_health(self, client, db, engine, hunts):
        hunts.script = {"paypal.com": [cand("p1.com", 60)], "microsoft.com": [cand("m1.com", 70)]}
        bid = self._create(client)["batch"]["id"]
        client.post(f"/api/scheduler/batches/{bid}/run")
        engine.tick(run_inline=True)
        text = client.get(f"/api/scheduler/batches/{bid}/export?format=csv").text
        assert "p1.com" in text and "m1.com" in text and text.splitlines()[0].endswith("dismissed")
        js = client.get(f"/api/scheduler/batches/{bid}/export?format=json").json()
        assert js["batch"] == "Banks" and {f["original_domain"] for f in js["findings"]} == {"paypal.com", "microsoft.com"}
        pp = domain_id(db, "paypal.com")
        assert client.post(f"/api/scheduler/domains/{pp}/findings/dismiss", json={"ids": [f"{pp}:p1.com"], "reason": "ok"}).json()["updated"] == 1
        assert "p1.com" not in client.get(f"/api/scheduler/batches/{bid}/export?format=csv").text
        assert "p1.com" in client.get(f"/api/scheduler/batches/{bid}/export?format=csv&view=dismissed").text
        r = client.get("/api/scheduler/health")
        assert r.status_code == 503 and r.json()["engine_running"] is False         # test engine is not started
        engine.state.update(running=True, last_tick=time.time())
        r = client.get("/api/scheduler/health")
        assert r.status_code == 200 and r.json()["healthy"] is True
        engine.state.update(last_tick=time.time() - 600)
        assert client.get("/api/scheduler/health").status_code == 503                # stalled engine
        engine.state.update(running=False)

    def test_export_neutralises_spreadsheet_formulas(self, client, db, engine, hunts):
        evil = cand("evil-paypal.com", 70)
        evil["evidence"] = {"title": "=HYPERLINK(\"http://x\")", "http": {"status": 200, "final_url": "https://evil-paypal.com/"}}
        hunts.script = {"paypal.com": [evil]}
        bid = self._create(client, domains=[{"domain": "paypal.com"}])["batch"]["id"]
        client.post(f"/api/scheduler/batches/{bid}/run")
        engine.tick(run_inline=True)
        text = client.get(f"/api/scheduler/domains/{domain_id(db, 'paypal.com')}/export").text
        assert "'=HYPERLINK" in text

    def test_scoped_deletes_with_confirmation_and_audit(self, client, db, engine, hunts):
        hunts.script = {"paypal.com": [cand("a.com", 60)], "microsoft.com": [cand("b.com", 60)]}
        bid = self._create(client)["batch"]["id"]
        other = self._create(client, "Other", [{"domain": "microsoft.com"}])["batch"]["id"]
        client.post(f"/api/scheduler/batches/{bid}/run")
        engine.tick(run_inline=True)
        get_store().save_hunt("manual1", {"target": "paypal.com", "depth": "quick", "stats": {}, "candidates": []})   # manual Brand Hunt history
        pp, ms = domain_id(db, "paypal.com"), domain_id(db, "microsoft.com")

        imp = client.get(f"/api/data/impact?type=domain&id={pp}").json()
        assert (imp["findings"], imp["scan_jobs"], imp["confirm_text"]) == (1, 1, "paypal.com")
        assert client.post(f"/api/data/domains/{pp}/delete", json={"confirm": "paypal"}).status_code == 400     # wrong name
        assert client.post(f"/api/data/domains/{pp}/delete", json={"confirm": "paypal.com"}, headers={"Origin": "https://evil.example"}).status_code == 403
        out = client.post(f"/api/data/domains/{pp}/delete", json={"confirm": "PayPal.com"}).json()["deleted"]
        assert (out["findings"], out["scan_jobs"], out["saved_hunts"], out["domain_record"]) == (1, 1, 1, 1)
        assert db.impersonation_findings.count_documents({"domain_id": ms}) == 1                   # other domain untouched
        assert get_store().get_hunt("manual1") is not None                                         # manual history kept
        assert db.monitored_domains.find_one({"_id": pp}) is None
        assert client.get(f"/api/scheduler/domains/{pp}").status_code == 404

        clr = client.post(f"/api/data/domains/{ms}/history/clear", json={"confirm": "microsoft.com"}).json()["deleted"]
        assert clr["scan_jobs"] == 1 and db.impersonation_findings.count_documents({"domain_id": ms}) == 1   # findings kept

        res = client.post(f"/api/data/batches/{bid}/delete", json={"confirm": "Banks", "delete_exclusive_domains": True}).json()["deleted"]
        assert res["batch_record"] == 1 and res["domains_deleted"] == []                                    # microsoft.com is still in "Other"
        assert db.monitored_domains.find_one({"_id": ms}) is not None
        res = client.post(f"/api/data/batches/{other}/delete", json={"confirm": "Other", "delete_exclusive_domains": True}).json()["deleted"]
        assert [d["id"] for d in res["domains_deleted"]] == [ms] and db.impersonation_findings.count_documents({}) == 0
        entries = client.get("/api/data/audit").json()["entries"]
        actions = [a["action"] for a in entries]
        deleted = next(a for a in entries if a["action"] == "domain.delete")
        assert deleted["details"]["domain"] == "paypal.com" and deleted["details"]["findings"] == 1   # the name survives in the audit
        for a in ("domain.delete", "domain.clear_history", "batch.delete", "batch.create"):
            assert a in actions

    def test_destructive_endpoints_are_local_only(self, client, db):
        bid = self._create(client)["batch"]["id"]
        import app as app_module
        with mock.patch.multiple(app_module, SETTINGS_ALLOWED_CLIENTS={"127.0.0.1"}):
            assert client.post(f"/api/data/batches/{bid}/delete", json={"confirm": "Banks"}).status_code == 403
            assert client.put("/api/scheduler/settings", json={"concurrency": 3}).status_code == 403
        assert client.put("/api/scheduler/settings", json={"concurrency": 99}).status_code == 400
        assert client.put("/api/scheduler/settings", json={"concurrency": 3}).json()["settings"]["concurrency"] == 3

    def test_refuses_to_delete_while_a_scan_runs(self, client, db):
        bid = self._create(client)["batch"]["id"]
        client.post(f"/api/scheduler/batches/{bid}/run")
        pp = domain_id(db, "paypal.com")
        db.scan_jobs.update_one({"domain_id": pp}, {"$set": {"status": "running"}})
        assert client.post(f"/api/data/batches/{bid}/delete", json={"confirm": "Banks"}).status_code == 409
        assert client.post(f"/api/data/domains/{pp}/delete", json={"confirm": "paypal.com"}).status_code == 409
        r = client.post(f"/api/data/domains/{pp}/delete", json={"confirm": "paypal.com", "cancel_active": True})
        assert r.status_code == 409 and db.scan_jobs.find_one({"domain_id": pp})["cancel_requested"] is True
