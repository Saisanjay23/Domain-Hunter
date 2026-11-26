"""
One-way import of the retired SQLite history (data/hunter.db) into MongoDB, plus a generic store-to-store copy.

MongoDB is the only runtime database. This module is the single place that still reads SQLite, and only to
import legacy files. The workflow is safe to repeat and never modifies or deletes the source:

  1. find      legacy_candidates() lists the SQLite files the app used to write (data/hunter.db, BRAND_HUNTER_DB).
  2. backup    backup_sqlite() takes a consistent copy (sqlite3 online-backup API) into data/backups/ and
               checks the copy's row counts match the original.
  3. copy      copy_store() upserts every record (idempotent, see below).
  4. validate  validate_counts() compares source counts with what is now in MongoDB.
  5. record    the run (source checksum, backup path, counts, validation) is written to `migrations`.

Idempotency of copy_store():
  hunts       upserted by id (candidates are rewritten with the hunt)
  triage      upserted by (brand, domain), original timestamps kept
  watchlist   brands already present in the destination are skipped
  alerts      skipped when an alert with the same (created, brand, title) already exists
"""

import hashlib
import json
import os
import sqlite3
import time
import zlib
from contextlib import closing
from typing import Any, Dict, List, Optional

from . import config
from .store import StoreBase, StoreError

LEGACY_TABLES = ("hunts", "hunt_candidates", "triage", "watchlist", "alerts")


def legacy_default_path() -> str:
    return os.environ.get("BRAND_HUNTER_DB") or os.path.join(config.PROJECT_ROOT, "data", "hunter.db")


def legacy_candidates() -> List[str]:
    """Existing SQLite files the old versions of the app could have written."""
    seen: List[str] = []
    for p in (legacy_default_path(), os.path.join(config.PROJECT_ROOT, "data", "hunter.db")):
        p = os.path.abspath(p)
        if p not in seen and os.path.isfile(p):
            seen.append(p)
    return seen


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _connect_ro(path: str) -> sqlite3.Connection:
    uri = "file:" + os.path.abspath(path).replace("\\", "/") + "?mode=ro"
    db = sqlite3.connect(uri, uri=True, check_same_thread=False, timeout=10)
    db.row_factory = sqlite3.Row
    return db


def sqlite_counts(path: str) -> Dict[str, int]:
    """Row counts of the legacy tables (missing tables count as 0)."""
    out: Dict[str, int] = {}
    with closing(_connect_ro(path)) as db:
        names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for t in LEGACY_TABLES:
            out[t] = int(db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]) if t in names else 0
    return out


def backup_sqlite(path: str, backup_dir: Optional[str] = None) -> Dict[str, Any]:
    """Consistent copy of the SQLite file (never overwrites an earlier backup). Verifies the copy's row counts."""
    backup_dir = backup_dir or os.path.join(config.PROJECT_ROOT, "data", "backups")
    os.makedirs(backup_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    base = os.path.splitext(os.path.basename(path))[0]
    dest = os.path.join(backup_dir, f"{base}-{stamp}.db")
    n = 1
    while os.path.exists(dest):
        n += 1
        dest = os.path.join(backup_dir, f"{base}-{stamp}-{n}.db")
    with closing(_connect_ro(path)) as src, closing(sqlite3.connect(dest)) as dst:
        src.backup(dst)
    original, copy = sqlite_counts(path), sqlite_counts(dest)
    if original != copy:
        raise RuntimeError(f"Backup verification failed: {original} != {copy}")
    return {"path": dest, "sha256": _sha256(dest), "counts": copy}


class LegacySQLiteReader:
    """Read-only view of a legacy SQLite file with the read methods copy_store() needs."""

    backend = "sqlite-legacy"

    def __init__(self, path: str) -> None:
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        self.path = path
        self._db = _connect_ro(path)
        self._tables = {r[0] for r in self._db.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> "LegacySQLiteReader":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _all(self, table: str, sql: str, params: tuple = ()) -> List[sqlite3.Row]:
        return self._db.execute(sql, params).fetchall() if table in self._tables else []

    def list_hunts(self, target: Optional[str] = None, limit: int = 1_000_000) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._all("hunts", "SELECT id,target,created,depth,scheduled FROM hunts ORDER BY created DESC LIMIT ?", (limit,))]

    def get_hunt(self, hunt_id: str) -> Optional[Dict[str, Any]]:
        rows = self._all("hunts", "SELECT result FROM hunts WHERE id=?", (hunt_id,))
        if not rows:
            return None
        return json.loads(zlib.decompress(rows[0]["result"]).decode("utf-8"))

    def triage_all(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._all("triage", "SELECT brand,domain,status,note,updated FROM triage")]

    def watch_list(self, include_secret: bool = False) -> List[Dict[str, Any]]:
        out = []
        for r in self._all("watchlist", "SELECT * FROM watchlist ORDER BY brand"):
            d = dict(r)
            d["enabled"] = bool(d.get("enabled"))
            al = d.get("allowlist") or ""
            d["allowlist"] = [x for x in al.split(",") if x]
            if not include_secret:
                d.pop("webhook_url", None)
            out.append(d)
        return out

    def alert_list(self, limit: int = 1_000_000) -> List[Dict[str, Any]]:
        return [dict(r) | {"read": bool(r["read"])} for r in self._all("alerts", "SELECT * FROM alerts ORDER BY created DESC LIMIT ?", (limit,))]


def _alert_key(a: Dict[str, Any]) -> tuple:
    return (round(float(a.get("created") or 0), 3), a.get("brand"), a.get("title"))


def copy_store(src: Any, dst: StoreBase) -> Dict[str, Any]:
    """Copies hunts, triage, watchlist and alerts. Safe to repeat (see the module docstring)."""
    counts: Dict[str, Any] = {"hunts": 0, "triage": 0, "watchlist": 0, "watchlist_skipped": 0, "alerts": 0, "alerts_skipped": 0}

    for h in src.list_hunts(limit=1_000_000):
        result = src.get_hunt(h["id"])
        if result:
            dst.save_hunt(h["id"], result, created=h["created"], scheduled=bool(h.get("scheduled")))
            counts["hunts"] += 1

    for t in src.triage_all():
        dst.triage_set(t["brand"], t["domain"], t["status"], t.get("note", ""), updated=t.get("updated"))
        counts["triage"] += 1

    existing = {w["brand"] for w in dst.watch_list()}
    for w in src.watch_list(include_secret=True):
        if w["brand"] in existing:
            counts["watchlist_skipped"] += 1
            continue
        try:
            wid = dst.watch_add(w["brand"], w["depth"], w["interval_hours"], w["min_score"], w.get("webhook_url", ""), w.get("allowlist", []))
        except StoreError:
            counts["watchlist_skipped"] += 1
            continue
        dst.watch_update(wid, enabled=w["enabled"], last_run=w.get("last_run"), last_hunt=w.get("last_hunt"), last_status=w.get("last_status"))
        counts["watchlist"] += 1

    have = {_alert_key(a) for a in dst.alert_list(1_000_000)}
    for a in reversed(src.alert_list(1_000_000)):
        if _alert_key(a) in have:
            counts["alerts_skipped"] += 1
            continue
        dst.alert_add(a["brand"], a["level"], a["title"], a["body"], a.get("hunt_id"), a.get("delivery", ""), created=a["created"], read=a["read"])
        have.add(_alert_key(a))
        counts["alerts"] += 1
    return counts


def validate_counts(reader: LegacySQLiteReader, dst: Any) -> Dict[str, Any]:
    """Every legacy record must now exist in MongoDB (by its natural key)."""
    db = dst.db
    hunt_ids = [h["id"] for h in reader.list_hunts()]
    missing_hunts = [i for i in hunt_ids if not db.hunts.find_one({"_id": i}, {"_id": 1})]
    cand_src = sum(len((reader.get_hunt(i) or {}).get("candidates") or []) for i in hunt_ids)
    cand_dst = db.candidates.count_documents({"hunt_id": {"$in": hunt_ids}}) if hunt_ids else 0
    tri = reader.triage_all()
    missing_tri = [t for t in tri if not db.triage.find_one({"brand": t["brand"], "domain": t["domain"]}, {"_id": 1})]
    brands = [w["brand"] for w in reader.watch_list()]
    missing_watch = [b for b in brands if not db.watchlist.find_one({"brand": b}, {"_id": 1})]
    have = {_alert_key(a) for a in dst.alert_list(1_000_000)}
    missing_alerts = [a for a in reader.alert_list() if _alert_key(a) not in have]
    ok = not (missing_hunts or missing_tri or missing_watch or missing_alerts) and cand_src == cand_dst
    return {"ok": ok, "hunts": {"source": len(hunt_ids), "missing": len(missing_hunts)},
            "candidates": {"source": cand_src, "destination": cand_dst},
            "triage": {"source": len(tri), "missing": len(missing_tri)},
            "watchlist": {"source": len(brands), "missing": len(missing_watch)},
            "alerts": {"source": len(reader.alert_list()), "missing": len(missing_alerts)}}


def migrate_sqlite(path: str, dst: Any, backup_dir: Optional[str] = None) -> Dict[str, Any]:
    """Backup -> copy -> validate -> record. The source file is opened read-only and never deleted."""
    if getattr(dst, "backend", None) != "mongodb":
        raise StoreError("The destination must be the MongoDB store")
    path = os.path.abspath(path)
    checksum = _sha256(path)
    backup = backup_sqlite(path, backup_dir)
    with LegacySQLiteReader(path) as reader:
        copied = copy_store(reader, dst)
        validation = validate_counts(reader, dst)
    report = {"source": path, "source_sha256": checksum, "backup": backup, "copied": copied, "validation": validation,
              "finished": time.time(), "source_deleted": False}
    dst.db.migrations.update_one({"_id": f"sqlite:{checksum}"},
                                 {"$set": {k: v for k, v in report.items()}, "$inc": {"runs": 1}}, upsert=True)
    return report


def migration_history(dst: Any) -> List[Dict[str, Any]]:
    return [{k: v for k, v in d.items() if k != "_id"} | {"id": d["_id"]} for d in dst.db.migrations.find({}).sort("finished", -1).limit(20)]
