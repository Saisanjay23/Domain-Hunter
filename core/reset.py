"""
"Reset all data": a verified backup of every application collection, then one scoped wipe.

Scope: only the collections this application owns, in its own database (never other databases on the server,
never other collections). Settings (API keys in .env, scheduler engine settings) are configuration, not data, and
are kept. The audit log keeps its history unless explicitly included, and the reset itself is always audited.

Backup: data/backups/reset-<timestamp>/<collection>.jsonl.gz (MongoDB Extended JSON, one document per line) plus
manifest.json with the per-collection counts; each file is read back and counted before anything is deleted.
Restore: core.reset.restore_backup(db, folder) (or `python -m core.reset restore <folder>`).
"""

import gzip
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

from bson import json_util

from . import config

DATA_COLLECTIONS = (
    # hunts and cases
    "hunts", "candidates", "triage", "watchlist", "alerts", "counters",
    # scan scheduler
    "organizations", "monitored_domains", "scan_batches", "batch_domain_memberships", "batch_executions", "scan_jobs",
    "impersonation_findings", "scan_observations", "scheduler_locks",
    # infrastructure investigator
    "infra_investigations",
    # remnants of retired features
    "migrations", "_bih_healthcheck",
)
AUDIT_COLLECTION = "audit_logs"
CONFIRM_TEXT = "DELETE ALL DATA"


class ResetError(RuntimeError):
    pass


def _targets(db, include_audit: bool) -> List[str]:
    existing = set(db.list_collection_names())
    names = [c for c in DATA_COLLECTIONS if c in existing]
    if include_audit and AUDIT_COLLECTION in existing:
        names.append(AUDIT_COLLECTION)
    return names


def preview(db, include_audit: bool = False) -> Dict[str, Any]:
    counts = {c: db[c].count_documents({}) for c in _targets(db, include_audit)}
    active = db.batch_executions.count_documents({"status": {"$in": ["queued", "running"]}}) if "batch_executions" in counts else 0
    return {"database": db.name, "collections": counts, "total": sum(counts.values()), "active_runs": active,
            "kept": ["API keys and settings (.env)", "scheduler engine settings", "phishing feed cache"]
            + ([] if include_audit else ["audit log (the reset itself is recorded)"]), "confirm_text": CONFIRM_TEXT}


def backup(db, include_audit: bool = True, root: Optional[str] = None) -> Dict[str, Any]:
    """Writes every collection to gzip JSON lines and verifies each file by reading it back."""
    root = root or os.path.join(config.PROJECT_ROOT, "data", "backups")
    folder = os.path.join(root, "reset-" + time.strftime("%Y%m%d-%H%M%S"))
    n = 1
    while os.path.exists(folder):
        n += 1
        folder = os.path.join(root, f"reset-{time.strftime('%Y%m%d-%H%M%S')}-{n}")
    os.makedirs(folder)
    manifest: Dict[str, Any] = {"database": db.name, "created": time.time(), "collections": {}}
    for name in _targets(db, include_audit):
        path = os.path.join(folder, f"{name}.jsonl.gz")
        written = 0
        with gzip.open(path, "wt", encoding="utf-8") as f:
            for doc in db[name].find({}):
                f.write(json_util.dumps(doc, json_options=json_util.CANONICAL_JSON_OPTIONS) + "\n")
                written += 1
        with gzip.open(path, "rt", encoding="utf-8") as f:
            read_back = sum(1 for line in f if line.strip())
        if read_back != written:
            raise ResetError(f"Backup of {name} could not be verified ({read_back} of {written} documents)")
        manifest["collections"][name] = written
    with open(os.path.join(folder, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return {"folder": folder, "collections": manifest["collections"], "total": sum(manifest["collections"].values())}


def reset_all(db, include_audit: bool = False, backup_root: Optional[str] = None, actor: str = "unknown") -> Dict[str, Any]:
    """Backup -> wipe (one transaction when the server supports it) -> audit entry. Refuses while a scan runs."""
    from .scheduler_store import audit, run_atomic
    if db.batch_executions.count_documents({"status": {"$in": ["queued", "running"]}}):
        raise ResetError("A scan batch is queued or running. Cancel it first (Scan Scheduler), then reset.")
    saved = backup(db, include_audit=True, root=backup_root)
    names = _targets(db, include_audit)

    def work(s):
        return {name: db[name].delete_many({}, session=s).deleted_count for name in names}
    deleted, txn = run_atomic(db, work)
    audit(db, actor, "data.reset_all", "database", db.name, {"deleted": deleted, "total": sum(deleted.values()),
                                                             "backup": saved["folder"], "transaction": txn})
    return {"deleted": deleted, "total": sum(deleted.values()), "backup": saved, "transaction": txn}


def restore_backup(db, folder: str) -> Dict[str, int]:
    """Re-inserts a reset backup (documents whose _id already exists are kept as they are)."""
    with open(os.path.join(folder, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    out = {}
    for name in manifest["collections"]:
        inserted = 0
        with gzip.open(os.path.join(folder, f"{name}.jsonl.gz"), "rt", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    doc = json_util.loads(line)
                    if db[name].find_one({"_id": doc["_id"]}, {"_id": 1}) is None:
                        db[name].insert_one(doc)
                        inserted += 1
        out[name] = inserted
    return out


if __name__ == "__main__":  # pragma: no cover - manual recovery tool
    if len(sys.argv) == 3 and sys.argv[1] == "restore":
        from .store import get_store
        print(json.dumps(restore_backup(get_store().db, sys.argv[2]), indent=2))
    else:
        print("usage: python -m core.reset restore <backup folder>")
