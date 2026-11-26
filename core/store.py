"""
Persistent case store: hunt history, triage decisions, watchlist, alerts (plus, via core.scheduler_store,
scan batches, monitored domains and findings).

MongoDB is the only persistent database (core.mongostore.MongoStore). The connection comes from
MONGODB_URI / MONGODB_DB (Settings > Storage or .env); when MONGODB_URI is not set the local server
mongodb://127.0.0.1:27017 is used. get_store() re-reads the configuration on every call, so saving a new
connection string in the UI switches the connection immediately. If the server cannot be reached the
app reports StoreUnavailable; it never silently falls back to another database.

Data from the retired SQLite backend (data/hunter.db) can be imported with core.migrate
(Settings > Storage > "Import legacy SQLite file", or `python favicon_hash.py --migrate-history`).

Brand identity is the hunt's apex domain (e.g. "paypal.com"). Webhook URLs are secrets (Slack/Teams
URLs carry a token): they are stored but only a masked hint is ever returned to the browser.
"""

import json
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from . import config

TRIAGE_STATUSES = ("open", "investigating", "confirmed", "takedown_sent", "taken_down", "false_positive")
PREVIEW_KEEP = 40          # candidates (by score) that keep their favicon preview in storage
MAX_NOTE = 1000
WATCH_FIELDS = {"depth", "interval_hours", "min_score", "webhook_url", "enabled", "last_run", "last_hunt", "last_status"}
UNAVAILABLE_RETRY_SECONDS = 15

class StoreError(ValueError):
    """The request is invalid (duplicate brand, unknown status, bad webhook)."""


class StoreUnavailable(RuntimeError):
    """The configured storage backend cannot be reached."""


DEFAULT_MONGODB_URI = "mongodb://127.0.0.1:27017"


# ------------------------------------------------------------------ helpers
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


# ------------------------------------------------------------------ choosing the backend
_store: Optional[StoreBase] = None
_built: List[StoreBase] = []
_signature: Optional[Tuple] = None
_override: Optional[StoreBase] = None
_failure: Optional[Tuple[Tuple, float, str]] = None
_lock = threading.Lock()


def configured_uri() -> Tuple[str, bool]:
    """(connection string, explicitly configured?). Unset means the local default server."""
    uri = config.get("MONGODB_URI")
    return (uri, True) if uri else (DEFAULT_MONGODB_URI, False)


def current_signature() -> Tuple:
    return ("mongodb", configured_uri()[0], config.get("MONGODB_DB"))


def _build(sig: Tuple) -> StoreBase:
    from .mongostore import connect_mongo
    return connect_mongo(sig[1], sig[2])


def get_store() -> StoreBase:
    """The MongoDB store. Raises StoreUnavailable if the server cannot be reached."""
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
