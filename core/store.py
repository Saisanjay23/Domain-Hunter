"""
Persistent case store: hunt history, triage decisions, watchlist, alerts.

Two interchangeable backends behind one interface:

    SQLite   (default)   data/hunter.db, stdlib only            -> Store
    MongoDB  (optional)  set MONGODB_URI (and MONGODB_DB)       -> core.mongostore.MongoStore

get_store() picks the backend from the configuration on every call, so saving or removing a
connection string in the UI switches storage immediately. Existing data is not moved
automatically: use core.migrate.copy_store (the "Copy existing data" button).

Brand identity is the hunt's apex domain (e.g. "paypal.com"). Webhook URLs are secrets (Slack/Teams
URLs carry a token): they are stored but only a masked hint is ever returned to the browser.
"""

import json
import os
import sqlite3
import threading
import time
import zlib
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

from . import config

TRIAGE_STATUSES = ("open", "investigating", "confirmed", "takedown_sent", "taken_down", "false_positive")
PREVIEW_KEEP = 40          # candidates (by score) that keep their favicon preview in storage
MAX_NOTE = 1000
WATCH_FIELDS = {"depth", "interval_hours", "min_score", "webhook_url", "enabled", "last_run", "last_hunt", "last_status"}
UNAVAILABLE_RETRY_SECONDS = 15

SCHEMA = """
CREATE TABLE IF NOT EXISTS hunts (
    id TEXT PRIMARY KEY, target TEXT NOT NULL, created REAL NOT NULL, depth TEXT,
    high_risk INTEGER DEFAULT 0, suspicious INTEGER DEFAULT 0, registered INTEGER DEFAULT 0,
    new_count INTEGER DEFAULT 0, scheduled INTEGER DEFAULT 0, result BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hunts_target ON hunts(target, created);
CREATE TABLE IF NOT EXISTS hunt_candidates (
    hunt_id TEXT NOT NULL, domain TEXT NOT NULL, score INTEGER, verdict TEXT,
    PRIMARY KEY (hunt_id, domain)
);
CREATE INDEX IF NOT EXISTS idx_hc_domain ON hunt_candidates(domain);
CREATE TABLE IF NOT EXISTS triage (
    brand TEXT NOT NULL, domain TEXT NOT NULL, status TEXT NOT NULL, note TEXT DEFAULT '',
    updated REAL NOT NULL, PRIMARY KEY (brand, domain)
);
CREATE TABLE IF NOT EXISTS watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT, brand TEXT UNIQUE NOT NULL, depth TEXT DEFAULT 'standard',
    interval_hours INTEGER DEFAULT 24, min_score INTEGER DEFAULT 45, webhook_url TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1, allowlist TEXT DEFAULT '', last_run REAL, last_hunt TEXT, last_status TEXT,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, created REAL NOT NULL, brand TEXT, level TEXT, title TEXT,
    body TEXT, hunt_id TEXT, read INTEGER DEFAULT 0, delivery TEXT DEFAULT ''
);
"""


class StoreError(ValueError):
    """The request is invalid (duplicate brand, unknown status, bad webhook)."""


class StoreUnavailable(RuntimeError):
    """The configured storage backend cannot be reached."""


# ------------------------------------------------------------------ helpers shared by both backends
def default_path() -> str:
    return os.environ.get("BRAND_HUNTER_DB") or os.path.join(config.PROJECT_ROOT, "data", "hunter.db")


def _dumps(obj: Any) -> str:
    return json.dumps(obj, default=lambda o: sorted(o) if isinstance(o, (set, frozenset)) else str(o))


def trim_for_storage(result: Dict[str, Any]) -> Dict[str, Any]:
    """Drops bulky favicon previews except for the highest-scoring candidates."""
    cands = result.get("candidates") or []
    keep = {id(c) for c in sorted(cands, key=lambda c: -c.get("score", 0))[:PREVIEW_KEEP]}
    out = dict(result)
    trimmed = []
    for c in cands:
        ev = c.get("evidence")
        if ev and ev.get("preview") and id(c) not in keep:
            c = {**c, "evidence": {k: v for k, v in ev.items() if k != "preview"}}
        trimmed.append(c)
    out["candidates"] = trimmed
    return out


def mask_url(url: str) -> str:
    if not url:
        return ""
    p = urlparse(url)
    tail = url[-4:] if len(url) >= 12 else ""
    return f"{p.scheme}://{p.hostname}/…{tail}"


def validate_webhook(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname or len(url) > 2000:
        raise StoreError("The webhook must be an http(s) URL")
    return url


def check_triage(status: str, note: str) -> str:
    if status not in TRIAGE_STATUSES:
        raise StoreError(f"status must be one of {', '.join(TRIAGE_STATUSES)}")
    return (note or "").strip()[:MAX_NOTE]


class StoreBase:
    """Logic that does not depend on where the data lives."""

    backend = "base"

    # primitives each backend implements: triage_get, previous_domains, first_seen, ...

    def decorate(self, result: Dict[str, Any], exclude_id: Optional[str] = None, compute_new: bool = True) -> Dict[str, Any]:
        """Adds triage state, first-seen time and 'new since the previous hunt' flags to a result (in place)."""
        brand = result["target"]
        cands = result.get("candidates") or []
        now = time.time()
        tri = self.triage_get(brand)
        prev = self.previous_domains(brand, exclude_id) if compute_new else None
        seen = self.first_seen(brand, [c["domain"] for c in cands])
        new_total = new_risky = 0
        for c in cands:
            c["triage"] = tri.get(c["domain"]) or {"status": "open", "note": "", "updated": None}
            if compute_new:
                c["is_new"] = prev is not None and c["domain"] not in prev
                c["first_seen"] = seen.get(c["domain"], now)
                if c["is_new"]:
                    new_total += 1
                    new_risky += c.get("verdict") in ("phishing", "suspicious")
        if compute_new:
            result.setdefault("stats", {}).update(new_domains=new_total, new_risky=new_risky, has_previous=prev is not None)
        return result

    @staticmethod
    def watch_row(r: Dict[str, Any], include_secret: bool = False) -> Dict[str, Any]:
        d = {k: v for k, v in dict(r).items() if k != "_id"}
        url = d.pop("webhook_url", "") or ""
        d["webhook"] = {"set": bool(url), "hint": mask_url(url)}
        if include_secret:
            d["webhook_url"] = url
        d["enabled"] = bool(d["enabled"])
        al = d.get("allowlist") or ""
        d["allowlist"] = [x for x in al.split(",") if x] if isinstance(al, str) else list(al)
        interval = d["interval_hours"] * 3600
        d["next_run"] = (d["last_run"] + interval) if d.get("last_run") else None
        return d

    @staticmethod
    def clean_watch_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in fields.items():
            if k not in WATCH_FIELDS:
                continue
            if k == "webhook_url":
                v = validate_webhook(v)
            if k == "enabled":
                v = bool(v)
            out[k] = v
        return out


class Store(StoreBase):
    """SQLite backend."""

    backend = "sqlite"

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or default_path()
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        self._db.row_factory = sqlite3.Row
        # Default rollback journal: WAL side files misbehave in OneDrive-synced folders.
        self._db.execute("PRAGMA busy_timeout=8000")
        with self._lock:
            self._db.executescript(SCHEMA)
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _run(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._db.execute(sql, tuple(params))
            self._db.commit()
            return cur

    def _all(self, sql: str, params: Iterable[Any] = ()) -> List[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, tuple(params)).fetchall()

    def stats(self) -> Dict[str, Any]:
        n = lambda t: int(self._all(f"SELECT COUNT(*) AS n FROM {t}")[0]["n"])
        return {"hunts": n("hunts"), "triage": n("triage"), "watchlist": n("watchlist"), "alerts": n("alerts"), "location": self.path}

    # ------------------------------------------------------------------ hunts
    def save_hunt(self, hunt_id: str, result: Dict[str, Any], created: Optional[float] = None, scheduled: bool = False) -> None:
        created = created or time.time()
        stored = trim_for_storage(result)
        stored["hunt_id"], stored["created"] = hunt_id, created
        blob = zlib.compress(_dumps(stored).encode("utf-8"), 6)
        st = result.get("stats") or {}
        cands = result.get("candidates") or []
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO hunts(id,target,created,depth,high_risk,suspicious,registered,new_count,scheduled,result) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (hunt_id, result["target"], created, result.get("depth"), st.get("high_risk", 0), st.get("suspicious", 0),
                 st.get("registered", 0), st.get("new_domains", 0), int(scheduled), blob))
            self._db.execute("DELETE FROM hunt_candidates WHERE hunt_id=?", (hunt_id,))
            self._db.executemany("INSERT OR REPLACE INTO hunt_candidates VALUES (?,?,?,?)",
                                 [(hunt_id, c["domain"], c.get("score", 0), c.get("verdict")) for c in cands])
            self._db.commit()

    def list_hunts(self, target: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        sql = "SELECT id,target,created,depth,high_risk,suspicious,registered,new_count,scheduled FROM hunts"
        params: List[Any] = []
        if target:
            sql += " WHERE target=?"
            params.append(target)
        sql += " ORDER BY created DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self._all(sql, params)]

    def get_hunt(self, hunt_id: str) -> Optional[Dict[str, Any]]:
        rows = self._all("SELECT result FROM hunts WHERE id=?", (hunt_id,))
        if not rows:
            return None
        result = json.loads(zlib.decompress(rows[0]["result"]).decode("utf-8"))
        # Same order as the MongoDB backend: highest score first (a no-op for hunts, which are saved sorted)
        result["candidates"] = sorted(result.get("candidates") or [], key=lambda c: (-c.get("score", 0), c.get("domain", "")))
        return result

    def delete_hunt(self, hunt_id: str) -> bool:
        with self._lock:
            n = self._db.execute("DELETE FROM hunts WHERE id=?", (hunt_id,)).rowcount
            self._db.execute("DELETE FROM hunt_candidates WHERE hunt_id=?", (hunt_id,))
            self._db.commit()
        return bool(n)

    def previous_domains(self, target: str, exclude_id: Optional[str] = None) -> Optional[Set[str]]:
        """Domains seen in the most recent earlier hunt of this brand (None if this is the first hunt)."""
        rows = self._all("SELECT id FROM hunts WHERE target=? AND id != ? ORDER BY created DESC LIMIT 1", (target, exclude_id or ""))
        if not rows:
            return None
        return {r["domain"] for r in self._all("SELECT domain FROM hunt_candidates WHERE hunt_id=?", (rows[0]["id"],))}

    def first_seen(self, target: str, domains: List[str]) -> Dict[str, float]:
        out: Dict[str, float] = {}
        for i in range(0, len(domains), 400):
            chunk = domains[i:i + 400]
            q = ",".join("?" * len(chunk))
            for r in self._all(
                    f"SELECT hc.domain AS d, MIN(h.created) AS t FROM hunt_candidates hc JOIN hunts h ON h.id=hc.hunt_id "
                    f"WHERE h.target=? AND hc.domain IN ({q}) GROUP BY hc.domain", [target, *chunk]):
                out[r["d"]] = r["t"]
        return out

    # ------------------------------------------------------------------ triage
    def triage_get(self, brand: str) -> Dict[str, Dict[str, Any]]:
        return {r["domain"]: {"status": r["status"], "note": r["note"], "updated": r["updated"]}
                for r in self._all("SELECT domain,status,note,updated FROM triage WHERE brand=?", (brand,))}

    def triage_all(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._all("SELECT brand,domain,status,note,updated FROM triage")]

    def triage_set(self, brand: str, domain: str, status: str, note: str = "", updated: Optional[float] = None) -> Dict[str, Any]:
        note = check_triage(status, note)
        now = updated or time.time()
        if status == "open" and not note:
            self._run("DELETE FROM triage WHERE brand=? AND domain=?", (brand, domain))
        else:
            self._run("INSERT OR REPLACE INTO triage(brand,domain,status,note,updated) VALUES(?,?,?,?,?)", (brand, domain, status, note, now))
        return {"status": status, "note": note, "updated": now}

    # ------------------------------------------------------------------ watchlist
    def watch_list(self, include_secret: bool = False) -> List[Dict[str, Any]]:
        return [self.watch_row(dict(r), include_secret) for r in self._all("SELECT * FROM watchlist ORDER BY brand")]

    def watch_get(self, wid: int, include_secret: bool = False) -> Optional[Dict[str, Any]]:
        rows = self._all("SELECT * FROM watchlist WHERE id=?", (wid,))
        return self.watch_row(dict(rows[0]), include_secret) if rows else None

    def watch_add(self, brand: str, depth: str, interval_hours: int, min_score: int, webhook_url: str, allowlist: List[str]) -> int:
        webhook_url = validate_webhook(webhook_url)
        try:
            cur = self._run(
                "INSERT INTO watchlist(brand,depth,interval_hours,min_score,webhook_url,allowlist,created) VALUES(?,?,?,?,?,?,?)",
                (brand, depth, interval_hours, min_score, webhook_url, ",".join(allowlist), time.time()))
        except sqlite3.IntegrityError:
            raise StoreError(f"{brand} is already on the watchlist")
        return int(cur.lastrowid)

    def watch_update(self, wid: int, **fields: Any) -> None:
        clean = self.clean_watch_fields(fields)
        if not clean:
            return
        sets = [f"{k}=?" for k in clean]
        params = [int(v) if k == "enabled" else v for k, v in clean.items()]
        self._run(f"UPDATE watchlist SET {', '.join(sets)} WHERE id=?", [*params, wid])

    def watch_delete(self, wid: int) -> bool:
        return bool(self._run("DELETE FROM watchlist WHERE id=?", (wid,)).rowcount)

    def watch_claim(self, wid: int, due_before: float, now: Optional[float] = None) -> bool:
        """Atomically takes the right to start a due hunt (stops two scheduler instances running the same brand)."""
        cur = self._run("UPDATE watchlist SET last_run=?, last_status='running' WHERE id=? AND enabled=1 AND (last_run IS NULL OR last_run <= ?)",
                        (now or time.time(), wid, due_before))
        return cur.rowcount > 0

    # ------------------------------------------------------------------ alerts
    def alert_add(self, brand: str, level: str, title: str, body: str, hunt_id: Optional[str], delivery: str = "",
                  created: Optional[float] = None, read: bool = False) -> int:
        cur = self._run("INSERT INTO alerts(created,brand,level,title,body,hunt_id,delivery,read) VALUES(?,?,?,?,?,?,?,?)",
                        (created or time.time(), brand, level, title[:200], body[:4000], hunt_id, delivery, int(read)))
        return int(cur.lastrowid)

    def alert_list(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [dict(r) | {"read": bool(r["read"])} for r in self._all("SELECT * FROM alerts ORDER BY created DESC LIMIT ?", (limit,))]

    def alert_unread(self) -> int:
        return int(self._all("SELECT COUNT(*) AS n FROM alerts WHERE read=0")[0]["n"])

    def alert_mark_read(self, alert_id: Optional[int] = None) -> None:
        if alert_id is None:
            self._run("UPDATE alerts SET read=1")
        else:
            self._run("UPDATE alerts SET read=1 WHERE id=?", (alert_id,))


# ------------------------------------------------------------------ choosing the backend
_store: Optional[StoreBase] = None
_built: List[StoreBase] = []
_signature: Optional[Tuple] = None
_override: Optional[StoreBase] = None
_failure: Optional[Tuple[Tuple, float, str]] = None
_lock = threading.Lock()


def current_signature() -> Tuple:
    uri = config.get("MONGODB_URI")
    if uri:
        return ("mongodb", uri, config.get("MONGODB_DB"))
    return ("sqlite", default_path())


def _build(sig: Tuple) -> StoreBase:
    if sig[0] == "mongodb":
        from .mongostore import connect_mongo
        return connect_mongo(sig[1], sig[2])
    return Store(sig[1])


def get_store() -> StoreBase:
    """The active backend. Raises StoreUnavailable if MongoDB is configured but cannot be reached."""
    global _store, _signature, _failure
    with _lock:
        if _override is not None:
            return _override
        sig = current_signature()
        if _store is not None and _signature == sig:
            return _store
        if _failure and _failure[0] == sig and time.time() - _failure[1] < UNAVAILABLE_RETRY_SECONDS:
            raise StoreUnavailable(_failure[2])
        try:
            built = _build(sig)
        except StoreUnavailable as e:
            _failure = (sig, time.time(), str(e))
            raise
        _store, _signature, _failure = built, sig, None
        _built.append(built)
        return built


def close_all() -> None:
    """Closes every store get_store() has opened (tests, shutdown). The next get_store() reconnects."""
    global _store, _signature
    with _lock:
        for s in _built:
            try:
                s.close()
            except Exception:
                pass
        _built.clear()
        _store, _signature = None, None


def set_store(store: Optional[StoreBase]) -> None:
    """Pin the process-wide store (tests, or a specific database). None unpins it and forgets the cached backend."""
    global _store, _signature, _override, _failure
    with _lock:
        _override = store
        if store is None:
            _store, _signature, _failure = None, None, None
