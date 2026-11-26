"""
Scheduler load / soak test against a real MongoDB, in a throwaway database that is dropped at the end.

Simulates N monitored domains (one batch) scanned R times ("days") with realistic churn between scans: a share of
lookalikes disappear, new ones appear, some change score, some go NXDOMAIN. The hunt engine is replaced by a
deterministic generator (this measures the scheduler + database layer, not internet sources).

    python tools/load_test.py --uri mongodb://127.0.0.1:27017 --domains 300 --findings 300 --runs 8 --concurrency 4

Reports: wall time per run, findings / observations growth, document sizes, and API latency of the busiest pages
(batch with all domains, domain findings page, overview, data summary) measured through the real FastAPI app.
"""

import argparse
import os
import random
import statistics
import sys
import time
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("BRAND_HUNTER_SCHEDULER", "0")
os.environ.setdefault("BRAND_HUNTER_RATE_LIMIT", "0")


def make_runner(n_findings: int, seed: int = 7):
    """Per brand, a stable pool of lookalikes; each call returns ~n_findings of them with churn."""
    state = {"run": 0}

    def runner(target, depth="standard", extra_allowlist=None, extra_keywords=None, progress=None, cancel=None, **kw):
        rnd = random.Random(f"{seed}:{target}:{state['run']}")
        label = target.split(".")[0]
        pool = [f"{label}-{w}{i}.example-{i % 13}.com" for i in range(int(n_findings * 1.3)) for w in ("login",)]
        present = rnd.sample(pool, n_findings)
        cands = []
        for host in present:
            base = random.Random(host).randint(20, 95)
            score = max(0, min(100, base + (rnd.randint(-8, 8) if rnd.random() < 0.15 else 0)))
            cls = "Confirmed Impersonation" if score >= 80 else "Potential Impersonation"
            cands.append({"domain": host, "score": score, "verdict": "phishing" if score >= 80 else "suspicious", "classification": cls,
                          "sources": ["ct"], "dns": {"a": ["203.0.113.%d" % (hash(host) % 250)], "aaaa": [], "mx": [], "ns": []},
                          "dns_status": "resolves", "evidence": None, "rdap": None, "reasons": ["load test"], "fuzzer": "combo",
                          "matched_keyword": label})
        if progress:
            progress("dns", 50, f"Resolving {target}", {})
        return {"target": target, "depth": depth, "brand": {"icons": [], "allowlist": [target]}, "stats": {"registered": len(cands)},
                "candidates": cands, "queries": {}, "dorks": {}, "errors": [], "source_issues": []}
    return runner, state


def timed(client, path, n=15):
    xs = []
    for _ in range(n):
        t = time.perf_counter()
        r = client.get(path)
        assert r.status_code == 200, (path, r.status_code, r.text[:200])
        xs.append((time.perf_counter() - t) * 1000)
    xs.sort()
    return statistics.median(xs), xs[int(len(xs) * 0.9) - 1]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--uri", default=os.environ.get("BRAND_HUNTER_TEST_MONGO_URI", "mongodb://127.0.0.1:27017"))
    ap.add_argument("--domains", type=int, default=300)
    ap.add_argument("--findings", type=int, default=300)
    ap.add_argument("--runs", type=int, default=6)
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--keep", action="store_true", help="keep the database for inspection")
    args = ap.parse_args()

    from pymongo import MongoClient
    from fastapi.testclient import TestClient

    import app as app_module
    from api.routes import scheduler as sched_routes
    from api.services.batch_scheduler import BatchScheduler
    from core import scheduler_store as ss
    from core import store as store_mod
    from core.mongostore import MongoStore

    name = f"bih_load_{uuid.uuid4().hex[:8]}"
    store = MongoStore(MongoClient(args.uri, serverSelectionTimeoutMS=5000), name)
    store_mod.set_store(store)
    db = store.db
    runner, state = make_runner(args.findings)
    engine = BatchScheduler(owner="load", poll_seconds=0.05, stagger_seconds=0, runner=runner, resolver=lambda hosts: {})
    sched_routes.ENGINE = engine
    print(f"database {name} on {args.uri.split('@')[-1]} | {args.domains} domains x ~{args.findings} findings x {args.runs} runs, "
          f"concurrency {args.concurrency}, transactions={ss.supports_transactions(db)}")
    try:
        ss.ensure_indexes(db)
        ss.update_settings(db, {"concurrency": args.concurrency, "max_attempts": 1})
        b = ss.create_batch(db, {"name": "Load test", "schedule": {"frequency": "manual"}})
        brands = [f"brand{i:04d}.com" for i in range(args.domains)]
        t = time.perf_counter()
        ss.batch_add_entries(db, b["_id"], [{"domain": d, "keywords": [d.split(".")[0]]} for d in brands])
        print(f"import of {args.domains} domains: {time.perf_counter() - t:.2f} s")
        for r in range(args.runs):
            state["run"] = r
            t = time.perf_counter()
            ex = ss.create_execution(db, ss.get_batch(db, b["_id"]), "manual")
            engine.tick(run_inline=True)
            e = db.batch_executions.find_one({"_id": ex["_id"]})
            dt = time.perf_counter() - t
            stats = db.command("collstats", "scan_observations")
            print(f"run {r + 1}: {e['status']} {e['completed']}/{e['total']} in {dt:6.1f} s ({e['total'] / dt:5.1f} domains/s) | "
                  f"findings {db.impersonation_findings.estimated_document_count():>7} | observations {db.scan_observations.estimated_document_count():>8} "
                  f"({stats.get('size', 0) / 1e6:6.1f} MB) | new {e['new_findings']} changed {e['updated_findings']}")
        c = TestClient(app_module.app)
        dom = db.monitored_domains.find_one({"domain": brands[0]})["_id"]
        for label, path in (("overview", "/api/scheduler/overview"), ("batches list", "/api/scheduler/batches"),
                            (f"batch detail ({args.domains} domains)", f"/api/scheduler/batches/{b['_id']}"),
                            ("domain dashboard", f"/api/scheduler/domains/{dom}"),
                            ("findings page 1", f"/api/scheduler/domains/{dom}/findings?view=all&page=1"),
                            ("findings, last page", f"/api/scheduler/domains/{dom}/findings?view=all&page=6"),
                            ("finding search", f"/api/scheduler/domains/{dom}/findings?q=login1"),
                            ("data summary", "/api/data/summary")):
            med, p90 = timed(c, path)
            print(f"  {label:32s} median {med:8.1f} ms   p90 {p90:8.1f} ms")
        sizes = {k: db.command("collstats", k).get("avgObjSize", 0) for k in ("impersonation_findings", "scan_observations", "scan_jobs")}
        print("avg document bytes:", {k: int(v) for k, v in sizes.items()})
    finally:
        if not args.keep:
            store._client.drop_database(name)
            print(f"dropped {name}")
        store_mod.set_store(None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
