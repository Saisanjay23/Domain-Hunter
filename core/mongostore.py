"""
MongoDB case store (the application's only persistent database).

Collections (database "brand_hunter" unless the URI or MONGODB_DB says otherwise):

    hunts        one document per hunt: summary counters + everything except the candidates
    candidates   one document per lookalike domain per hunt: queryable fields (domain, score, verdict,
                 target, created, ...) plus the full candidate in `data`. Keeping them separate means a
                 large hunt never nears the 16 MB document limit, and analysts can query them directly:
                     db.candidates.find({target: "paypal.com", verdict: "phishing"}).sort({score: -1})
    triage       one document per (brand, domain): status and analyst note
    watchlist    monitored brands (webhook URLs are stored here: protect the database accordingly)
    alerts       in-app alerts
    counters     integer ids for watchlist / alerts (the API uses integer ids)

The connection string holds credentials: every error message that leaves this module is redacted.
"""

import functools
import json
import time
from typing import Any, Dict, List, Optional, Set

from pymongo import ASCENDING, DESCENDING, MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError

from . import config
from .mongouri import DEFAULT_DB, describe_uri, redact, resolve_db_name  # noqa: F401  (re-exported)
from .store import (StoreBase, StoreError, StoreUnavailable, _dumps, check_triage, trim_for_storage, validate_webhook)

APPNAME = "brand-impersonation-hunter"
HEALTHCHECK_COLLECTION = "_bih_healthcheck"
INSERT_CHUNK = 500


# URI helpers live in core.mongouri (driver-free); re-exported here for convenience.


def _client(uri: str, timeout_ms: int) -> MongoClient:
    return MongoClient(uri, serverSelectionTimeoutMS=timeout_ms, connectTimeoutMS=timeout_ms, appname=APPNAME)


def check_connection(uri: str, db_name: Optional[str] = None, timeout_ms: int = 5000) -> Dict[str, Any]:
    """Pings the server and proves the database is writable (writes and removes one temporary document)."""
    client = None
    try:
        client = _client(uri, timeout_ms)
        client.admin.command("ping")
        version = None
        try:
            version = client.server_info().get("version")
        except PyMongoError:
            pass  # some restricted users may not run buildInfo; the write test below is what matters
        name = resolve_db_name(uri, db_name)
        probe = client[name][HEALTHCHECK_COLLECTION]
        probe.replace_one({"_id": "probe"}, {"_id": "probe", "at": time.time()}, upsert=True)
        probe.delete_one({"_id": "probe"})
        try:
            probe.drop()  # leave nothing behind (needs the dropCollection privilege; harmless if the user lacks it)
        except PyMongoError:
            pass
        return {"ok": True, "version": version, "db": name,
                "message": f"Connected{f' to MongoDB {version}' if version else ''}. Database '{name}' is writable."}
    except (PyMongoError, ValueError) as e:
        return {"ok": False, "message": redact(f"{e.__class__.__name__}: {e}", uri)[:400]}
    finally:
        if client is not None:
            client.close()


def connect_mongo(uri: str, db_name: Optional[str] = None, timeout_ms: int = 8000) -> "MongoStore":
    """Builds the store, or raises StoreUnavailable with a redacted message."""
    client = None
    try:
        client = _client(uri, timeout_ms)
        client.admin.command("ping")
        return MongoStore(client, resolve_db_name(uri, db_name))
    except (PyMongoError, ValueError) as e:
        if client is not None:
            client.close()
        raise StoreUnavailable(f"MongoDB is not reachable: {redact(f'{e.__class__.__name__}: {e}', uri)[:300]}") from None


# ------------------------------------------------------------------ document helpers
def _plain(obj: Any) -> Any:
    """JSON round-trip (sets, tuples and odd types become BSON-safe values) with Mongo-safe keys."""
    def keys(o: Any) -> Any:
        if isinstance(o, dict):
            return {(str(k).replace(".", "_").lstrip("$") or "_"): keys(v) for k, v in o.items()}
        if isinstance(o, list):
            return [keys(v) for v in o]
        return o
    return keys(json.loads(_dumps(obj)))


class MongoStore(StoreBase):
    backend = "mongodb"

    def __init__(self, client: MongoClient, db_name: str) -> None:
        self._client = client
        self.db_name = db_name
        self._db = client[db_name]
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        db = self._db
        db.hunts.create_index([("target", ASCENDING), ("created", DESCENDING)])
        db.candidates.create_index([("hunt_id", ASCENDING)])
        db.candidates.create_index([("target", ASCENDING), ("domain", ASCENDING)])
        db.candidates.create_index([("target", ASCENDING), ("verdict", ASCENDING), ("score", DESCENDING)])
        db.triage.create_index([("brand", ASCENDING)])
        db.watchlist.create_index([("brand", ASCENDING)], unique=True)
        db.alerts.create_index([("created", DESCENDING)])

    def close(self) -> None:
        self._client.close()

    @property
    def db(self):
        """The pymongo Database (used by the scheduler / data-management layer on the same connection)."""
        return self._db

    def _next_id(self, name: str) -> int:
        doc = self._db.counters.find_one_and_update({"_id": name}, {"$inc": {"seq": 1}}, upsert=True, return_document=ReturnDocument.AFTER)
        return int(doc["seq"])

    def stats(self) -> Dict[str, Any]:
        db = self._db
        return {"hunts": db.hunts.count_documents({}), "candidates": db.candidates.count_documents({}),
                "triage": db.triage.count_documents({}), "watchlist": db.watchlist.count_documents({}),
                "alerts": db.alerts.count_documents({}), "location": self.db_name}

    # ------------------------------------------------------------------ hunts
    def save_hunt(self, hunt_id: str, result: Dict[str, Any], created: Optional[float] = None, scheduled: bool = False) -> None:
        created = created or time.time()
        stored = trim_for_storage(result)
        stored["hunt_id"], stored["created"] = hunt_id, created
        cands = _plain(stored.pop("candidates", []))
        head = _plain(stored)
        st = result.get("stats") or {}
        target = result["target"]
        self._db.hunts.replace_one({"_id": hunt_id}, {
            "_id": hunt_id, "target": target, "created": created, "depth": result.get("depth"),
            "high_risk": st.get("high_risk", 0), "suspicious": st.get("suspicious", 0), "registered": st.get("registered", 0),
            "new_count": st.get("new_domains", 0), "scheduled": bool(scheduled), "candidate_count": len(cands), "result": head,
        }, upsert=True)
        self._db.candidates.delete_many({"hunt_id": hunt_id})
        docs = [{"_id": f"{hunt_id}:{c['domain']}", "hunt_id": hunt_id, "target": target, "domain": c["domain"],
                 "score": c.get("score", 0), "verdict": c.get("verdict"), "is_new": bool(c.get("is_new")),
                 "sources": c.get("sources", []), "created": created, "data": c} for c in cands]
        for i in range(0, len(docs), INSERT_CHUNK):
            self._db.candidates.insert_many(docs[i:i + INSERT_CHUNK], ordered=False)

    def list_hunts(self, target: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        cur = self._db.hunts.find({"target": target} if target else {}, {"result": 0}).sort("created", DESCENDING).limit(limit)
        return [{"id": d["_id"], "target": d["target"], "created": d["created"], "depth": d.get("depth"),
                 "high_risk": d.get("high_risk", 0), "suspicious": d.get("suspicious", 0), "registered": d.get("registered", 0),
                 "new_count": d.get("new_count", 0), "scheduled": int(bool(d.get("scheduled")))} for d in cur]

    def get_hunt(self, hunt_id: str) -> Optional[Dict[str, Any]]:
        doc = self._db.hunts.find_one({"_id": hunt_id})
        if not doc:
            return None
        result = doc["result"]
        cands = [r["data"] for r in self._db.candidates.find({"hunt_id": hunt_id})]
        cands.sort(key=lambda c: (-c.get("score", 0), c.get("domain", "")))
        result["candidates"] = cands
        return result

    def delete_hunt(self, hunt_id: str) -> bool:
        n = self._db.hunts.delete_one({"_id": hunt_id}).deleted_count
        self._db.candidates.delete_many({"hunt_id": hunt_id})
        return bool(n)

    def previous_domains(self, target: str, exclude_id: Optional[str] = None) -> Optional[Set[str]]:
        prev = self._db.hunts.find_one({"target": target, "_id": {"$ne": exclude_id or ""}}, {"_id": 1}, sort=[("created", DESCENDING)])
        if not prev:
            return None
        return set(self._db.candidates.distinct("domain", {"hunt_id": prev["_id"]}))

    def first_seen(self, target: str, domains: List[str]) -> Dict[str, float]:
        out: Dict[str, float] = {}
        for i in range(0, len(domains), 1000):
            pipeline = [{"$match": {"target": target, "domain": {"$in": domains[i:i + 1000]}}},
                        {"$group": {"_id": "$domain", "t": {"$min": "$created"}}}]
            for r in self._db.candidates.aggregate(pipeline):
                out[r["_id"]] = r["t"]
        return out

    # ------------------------------------------------------------------ triage
    @staticmethod
    def _tid(brand: str, domain: str) -> str:
        return f"{brand}|{domain}"

    def triage_get(self, brand: str) -> Dict[str, Dict[str, Any]]:
        return {d["domain"]: {"status": d["status"], "note": d.get("note", ""), "updated": d.get("updated")}
                for d in self._db.triage.find({"brand": brand})}

    def triage_all(self) -> List[Dict[str, Any]]:
        return [{"brand": d["brand"], "domain": d["domain"], "status": d["status"], "note": d.get("note", ""), "updated": d.get("updated")}
                for d in self._db.triage.find({})]

    def triage_set(self, brand: str, domain: str, status: str, note: str = "", updated: Optional[float] = None) -> Dict[str, Any]:
        note = check_triage(status, note)
        now = updated or time.time()
        if status == "open" and not note:
            self._db.triage.delete_one({"_id": self._tid(brand, domain)})
        else:
            self._db.triage.replace_one({"_id": self._tid(brand, domain)},
                                        {"_id": self._tid(brand, domain), "brand": brand, "domain": domain, "status": status,
                                         "note": note, "updated": now}, upsert=True)
        return {"status": status, "note": note, "updated": now}

    # ------------------------------------------------------------------ watchlist
    def watch_list(self, include_secret: bool = False) -> List[Dict[str, Any]]:
        return [self.watch_row(d, include_secret) for d in self._db.watchlist.find({}).sort("brand", ASCENDING)]

    def watch_get(self, wid: int, include_secret: bool = False) -> Optional[Dict[str, Any]]:
        d = self._db.watchlist.find_one({"_id": wid})
        return self.watch_row(d, include_secret) if d else None

    def watch_add(self, brand: str, depth: str, interval_hours: int, min_score: int, webhook_url: str, allowlist: List[str]) -> int:
        webhook_url = validate_webhook(webhook_url)
        wid = self._next_id("watchlist")
        try:
            self._db.watchlist.insert_one({
                "_id": wid, "id": wid, "brand": brand, "depth": depth, "interval_hours": interval_hours, "min_score": min_score,
                "webhook_url": webhook_url, "enabled": True, "allowlist": ",".join(allowlist), "last_run": None,
                "last_hunt": None, "last_status": None, "created": time.time()})
        except DuplicateKeyError:
            raise StoreError(f"{brand} is already on the watchlist")
        return wid

    def watch_update(self, wid: int, **fields: Any) -> None:
        clean = self.clean_watch_fields(fields)
        if clean:
            self._db.watchlist.update_one({"_id": wid}, {"$set": clean})

    def watch_delete(self, wid: int) -> bool:
        return self._db.watchlist.delete_one({"_id": wid}).deleted_count > 0

    def watch_claim(self, wid: int, due_before: float, now: Optional[float] = None) -> bool:
        """Atomic: with several app instances on one database, exactly one wins each due hunt."""
        res = self._db.watchlist.update_one(
            {"_id": wid, "enabled": True, "$or": [{"last_run": None}, {"last_run": {"$lte": due_before}}]},
            {"$set": {"last_run": now or time.time(), "last_status": "running"}})
        return res.modified_count > 0

    # ------------------------------------------------------------------ alerts
    def alert_add(self, brand: str, level: str, title: str, body: str, hunt_id: Optional[str], delivery: str = "",
                  created: Optional[float] = None, read: bool = False) -> int:
        aid = self._next_id("alerts")
        self._db.alerts.insert_one({"_id": aid, "id": aid, "created": created or time.time(), "brand": brand, "level": level,
                                    "title": title[:200], "body": body[:4000], "hunt_id": hunt_id, "read": bool(read), "delivery": delivery})
        return aid

    def alert_list(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [{"id": d["id"], "created": d["created"], "brand": d.get("brand"), "level": d.get("level"), "title": d.get("title"),
                 "body": d.get("body"), "hunt_id": d.get("hunt_id"), "read": bool(d.get("read")), "delivery": d.get("delivery", "")}
                for d in self._db.alerts.find({}).sort("created", DESCENDING).limit(limit)]

    def alert_unread(self) -> int:
        return int(self._db.alerts.count_documents({"read": False}))

    def alert_mark_read(self, alert_id: Optional[int] = None) -> None:
        self._db.alerts.update_many({} if alert_id is None else {"_id": alert_id}, {"$set": {"read": True}})


# Any driver error raised by a store method (network drop, auth, timeout) surfaces as StoreUnavailable with the
# connection string redacted, so callers (and the API's 503 handler) never need to import or know about pymongo.
def _guarded(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except PyMongoError as e:
            uri = config.get("MONGODB_URI")
            msg = f"{e.__class__.__name__}: {e}"
            raise StoreUnavailable(f"MongoDB error: {(redact(msg, uri) if uri else msg)[:300]}") from None
    return wrapper


for _name, _fn in list(vars(MongoStore).items()):
    if callable(_fn) and not _name.startswith("_") and not isinstance(_fn, (staticmethod, classmethod)):
        setattr(MongoStore, _name, _guarded(_fn))
