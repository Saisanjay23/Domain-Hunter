"""
MongoDB data layer of the Scan Scheduler and Data Management (same database as core.mongostore).

Collections (all scoped by explicit ids; nothing here ever runs an unscoped delete):

    organizations             {_id: org_*, name, name_key}
    monitored_domains         {_id: md_*, domain (unique), organization_id, keywords[], allowlist[], depth, status, ...}
    scan_batches              {_id: bt_*, name (unique, case-insensitive), schedule{}, status, next_run_at, notify{}, ...}
    batch_domain_memberships  {_id: "<batch_id>:<domain_id>", batch_id, domain_id}     (no unbounded arrays on batches)
    batch_executions          {_id: ex_*, batch_id, trigger, status, totals, slot_key (unique, scheduled runs only)}
    scan_jobs                 {_id: jb_*, execution_id, batch_id, domain_id, status, attempts, hunt_id, counts{}}
    impersonation_findings    {_id: "<domain_id>:<host>", unique (domain_id, host), lifecycle, classification, ...}
    scan_observations         {_id: "<job_id>:<host>", finding_id, domain_id, job_id, execution_id, batch_id, change}
    scheduler_locks           {_id: "domain:<domain_id>" | ..., owner, until}          (leases; expire on their own)
    application_settings      {_id: "scheduler", concurrency, job_timeout, max_attempts, ...}
    audit_logs                {_id: au_*, at, actor, action, target_type, target_id, details}

Isolation: a finding belongs to exactly one monitored domain (its _id starts with the domain id). The same hostname
found for two monitored domains is two separate findings, and every read/delete filters on domain_id server-side.
"""

import hashlib
import os
from datetime import datetime, timezone
import re
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple

from pymongo import ASCENDING, DESCENDING, ReturnDocument, UpdateOne
from pymongo.errors import DuplicateKeyError

from . import schedule as sched
from .domain_input import MAX_KEYWORDS, clean_keywords, clean_org, normalize_domain
from .store import mask_url, validate_webhook

ID_RE = re.compile(r"^(bt|md|ex|jb|org|au)_[0-9a-f]{12}$")
BATCH_STATUSES = ("active", "paused", "disabled")
DOMAIN_STATUSES = ("active", "paused")
EXEC_ACTIVE = ("queued", "running")
EXEC_FINAL = ("completed", "partially_completed", "failed", "cancelled", "interrupted")
JOB_FINAL = ("completed", "failed", "cancelled", "skipped")
LIFECYCLE_LABELS = {"new": "New", "seen": "Previously Discovered", "updated": "Updated", "reappeared": "Reappeared",
                    "unreachable": "Currently Unreachable"}
CLASS_KEYS = {"Confirmed Impersonation": "confirmed", "Potential Impersonation": "potential", "Inactive / Historical": "inactive",
              "Benign/Unrelated": "benign"}
DEPTHS = ("quick", "standard", "deep")
MISSED_POLICIES = ("run_once", "skip")
MAX_BATCH_DOMAINS = 1000
MAX_NAME = 120
MAX_DESCRIPTION = 1000
UNREACHABLE_CHECK_LIMIT = 300

SETTINGS_DEFAULTS = {
    "enabled": True,
    "concurrency": int(os.environ.get("SCHEDULER_CONCURRENCY", "2") or 2),
    "max_parallel_executions": 2,
    "job_timeout": int(os.environ.get("SCHEDULER_JOB_TIMEOUT", "900") or 900),
    "max_attempts": 3,
    "retry_base_seconds": 60,
    "lease_seconds": 120,
    "observation_retention_days": 365,
}
SETTINGS_LIMITS = {"observation_retention_days": (7, 3650), "concurrency": (1, 6), "max_parallel_executions": (1, 4), "job_timeout": (60, 3600),
                   "max_attempts": (1, 5), "retry_base_seconds": (10, 3600), "lease_seconds": (60, 900)}


class DataError(ValueError):
    """Invalid input (400)."""


class NotFound(LookupError):
    """Unknown id (404)."""


class Conflict(RuntimeError):
    """The request conflicts with the current state, e.g. a run is already active (409)."""


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def check_id(value: Any, prefix: str) -> str:
    """Ids from the API are validated before they reach a query (no operator injection, no type confusion)."""
    if not isinstance(value, str) or not ID_RE.match(value) or not value.startswith(prefix + "_"):
        raise NotFound(f"Unknown {prefix} id")
    return value


def _clean_text(value: Any, limit: int) -> str:
    return re.sub(r"[\x00-\x08\x0b-\x1f]", "", str(value or "")).strip()[:limit]


def _public(doc: Optional[Dict[str, Any]], id_key: str = "id") -> Optional[Dict[str, Any]]:
    if doc is None:
        return None
    d = dict(doc)
    d[id_key] = d.pop("_id")
    return d


# ====================================================================== indexes
def ensure_indexes(db) -> None:
    db.organizations.create_index([("name_key", ASCENDING)], unique=True)
    db.monitored_domains.create_index([("domain", ASCENDING)], unique=True)
    db.monitored_domains.create_index([("organization_id", ASCENDING)])
    db.batch_domain_memberships.create_index([("batch_id", ASCENDING), ("domain_id", ASCENDING)], unique=True)
    db.batch_domain_memberships.create_index([("domain_id", ASCENDING)])
    db.scan_batches.create_index([("name_key", ASCENDING)], unique=True)
    db.scan_batches.create_index([("status", ASCENDING), ("next_run_at", ASCENDING)])
    db.batch_executions.create_index([("batch_id", ASCENDING), ("created", DESCENDING)])
    db.batch_executions.create_index([("status", ASCENDING), ("heartbeat", ASCENDING)])
    db.batch_executions.create_index([("slot_key", ASCENDING)], unique=True, sparse=True)
    db.scan_jobs.create_index([("execution_id", ASCENDING), ("status", ASCENDING), ("next_attempt_at", ASCENDING)])
    db.scan_jobs.create_index([("domain_id", ASCENDING), ("created", DESCENDING)])
    db.scan_jobs.create_index([("batch_id", ASCENDING)])
    db.impersonation_findings.create_index([("domain_id", ASCENDING), ("host", ASCENDING)], unique=True)
    # The findings tables sort by (score desc, host asc) inside one domain / tab: these indexes return that order
    # directly (no in-memory SORT of every finding of the domain on each page). Measured in docs/SCHEDULER.md.
    by_score = [("score", DESCENDING), ("host", ASCENDING)]
    db.impersonation_findings.create_index([("domain_id", ASCENDING)] + by_score)
    db.impersonation_findings.create_index([("domain_id", ASCENDING), ("classification", ASCENDING)] + by_score)
    db.impersonation_findings.create_index([("domain_id", ASCENDING), ("lifecycle", ASCENDING)] + by_score)
    for superseded in ("domain_id_1_classification_1_score_-1", "domain_id_1_lifecycle_1"):   # prefixes of the ones above
        if superseded in db.impersonation_findings.index_information():
            db.impersonation_findings.drop_index(superseded)
    db.impersonation_findings.create_index([("domain_id", ASCENDING), ("last_seen", DESCENDING)])
    db.impersonation_findings.create_index([("host", ASCENDING)])
    db.scan_observations.create_index([("domain_id", ASCENDING), ("observed_at", DESCENDING)])
    db.scan_observations.create_index([("finding_id", ASCENDING), ("observed_at", DESCENDING)])
    db.scan_observations.create_index([("job_id", ASCENDING)])
    apply_retention(db)
    db.audit_logs.create_index([("at", DESCENDING)])
    db.audit_logs.create_index([("target_type", ASCENDING), ("target_id", ASCENDING)])


# ====================================================================== settings & audit
def get_settings(db) -> Dict[str, Any]:
    doc = db.application_settings.find_one({"_id": "scheduler"}) or {}
    out = dict(SETTINGS_DEFAULTS)
    out.update({k: v for k, v in doc.items() if k in SETTINGS_DEFAULTS})
    return out


def update_settings(db, values: Dict[str, Any]) -> Dict[str, Any]:
    clean: Dict[str, Any] = {}
    for k, v in (values or {}).items():
        if k not in SETTINGS_DEFAULTS or v is None:
            continue
        if k == "enabled":
            clean[k] = bool(v)
            continue
        try:
            n = int(v)
        except (TypeError, ValueError):
            raise DataError(f"{k} must be a whole number")
        lo, hi = SETTINGS_LIMITS[k]
        if not lo <= n <= hi:
            raise DataError(f"{k} must be between {lo} and {hi}")
        clean[k] = n
    if clean:
        db.application_settings.update_one({"_id": "scheduler"}, {"$set": {**clean, "updated": time.time()}}, upsert=True)
        if "observation_retention_days" in clean:
            apply_retention(db, clean["observation_retention_days"])
    return get_settings(db)


def apply_retention(db, days: Optional[int] = None) -> int:
    """TTL index on scan_observations.observed_dt: MongoDB removes observations older than `days` on its own."""
    days = int(days or get_settings(db)["observation_retention_days"])
    seconds = days * 86400
    info = db.scan_observations.index_information().get("observed_dt_ttl")
    if info is None:
        db.scan_observations.create_index([("observed_dt", ASCENDING)], name="observed_dt_ttl", expireAfterSeconds=seconds)
    elif int(info.get("expireAfterSeconds", -1)) != seconds:
        try:
            db.command("collMod", "scan_observations", index={"name": "observed_dt_ttl", "expireAfterSeconds": seconds})
        except Exception:  # servers / mocks without collMod: rebuild the index
            db.scan_observations.drop_index("observed_dt_ttl")
            db.scan_observations.create_index([("observed_dt", ASCENDING)], name="observed_dt_ttl", expireAfterSeconds=seconds)
    return days


def audit(db, actor: str, action: str, target_type: str, target_id: str, details: Optional[Dict[str, Any]] = None) -> str:
    aid = new_id("au")
    db.audit_logs.insert_one({"_id": aid, "at": time.time(), "actor": _clean_text(actor, 80), "action": action,
                              "target_type": target_type, "target_id": target_id, "details": details or {}})
    return aid


def audit_list(db, limit: int = 100, target_id: Optional[str] = None) -> List[Dict[str, Any]]:
    q = {"target_id": target_id} if target_id else {}
    return [_public(d) for d in db.audit_logs.find(q).sort("at", DESCENDING).limit(max(1, min(limit, 500)))]


# ====================================================================== locks (leases)
def acquire_lock(db, name: str, owner: str, ttl: float, now: Optional[float] = None) -> bool:
    """Atomic lease: succeeds if the lock is free, expired, or already ours."""
    now = now or time.time()
    try:
        db.scheduler_locks.update_one({"_id": name, "$or": [{"until": {"$lt": now}}, {"owner": owner}]},
                                      {"$set": {"owner": owner, "until": now + ttl, "at": now}}, upsert=True)
        return True
    except DuplicateKeyError:
        return False


def release_lock(db, name: str, owner: str) -> None:
    db.scheduler_locks.delete_one({"_id": name, "owner": owner})


# ====================================================================== organizations & monitored domains
def upsert_org(db, name: str) -> Optional[str]:
    name = clean_org(name)
    if not name:
        return None
    key = name.lower()
    for _ in range(2):
        try:
            doc = db.organizations.find_one_and_update(
                {"name_key": key}, {"$setOnInsert": {"_id": new_id("org"), "name": name, "name_key": key, "created": time.time()}},
                upsert=True, return_document=ReturnDocument.AFTER)
            return doc["_id"]
        except DuplicateKeyError:
            continue
    doc = db.organizations.find_one({"name_key": key})
    return doc["_id"] if doc else None


def _domain_public(d: Dict[str, Any]) -> Dict[str, Any]:
    out = _public(d)
    out.pop("deleting", None)
    return out


def get_domain(db, domain_id: str) -> Dict[str, Any]:
    d = db.monitored_domains.find_one({"_id": check_id(domain_id, "md"), "deleting": {"$ne": True}})
    if not d:
        raise NotFound("Monitored domain not found")
    return d


def get_or_create_domain(db, domain: str, organization: str = "", keywords: Optional[List[str]] = None,
                         depth: str = "standard") -> Tuple[Dict[str, Any], bool]:
    """Returns (domain doc, created). An existing domain gains any new keywords; nothing is overwritten."""
    host, err = normalize_domain(domain)
    if not host:
        raise DataError(f"{domain[:80]!r}: {err}")
    kws, _ = clean_keywords(keywords or [])
    now = time.time()
    existing = db.monitored_domains.find_one({"domain": host})
    if existing:
        if existing.get("deleting"):
            raise Conflict(f"{host} is being deleted; try again in a moment")
        merged = list(existing.get("keywords") or [])
        for k in kws:
            if k not in merged and len(merged) < MAX_KEYWORDS:
                merged.append(k)
        upd: Dict[str, Any] = {"keywords": merged, "updated": now}
        if organization and not existing.get("organization"):
            upd.update(organization=clean_org(organization), organization_id=upsert_org(db, organization))
        db.monitored_domains.update_one({"_id": existing["_id"]}, {"$set": upd})
        existing.update(upd)
        return existing, False
    doc = {"_id": new_id("md"), "domain": host, "organization": clean_org(organization),
           "organization_id": upsert_org(db, organization), "keywords": kws, "allowlist": [],
           "depth": depth if depth in DEPTHS else "standard", "status": "active", "created": now, "updated": now,
           "last_scan_at": None, "last_success_at": None, "last_status": None, "last_job_id": None}
    try:
        db.monitored_domains.insert_one(doc)
        return doc, True
    except DuplicateKeyError:  # created concurrently: use that one
        return get_or_create_domain(db, host, organization, kws, depth)


def update_domain(db, domain_id: str, values: Dict[str, Any]) -> Dict[str, Any]:
    d = get_domain(db, domain_id)
    upd: Dict[str, Any] = {}
    if "keywords" in values and values["keywords"] is not None:
        upd["keywords"], _ = clean_keywords(values["keywords"])
    if "allowlist" in values and values["allowlist"] is not None:
        allow = []
        for a in values["allowlist"] if isinstance(values["allowlist"], list) else str(values["allowlist"]).split(","):
            h, _ = normalize_domain(str(a))
            if h and h not in allow:
                allow.append(h)
        upd["allowlist"] = allow[:100]
    if values.get("organization") is not None:
        upd["organization"] = clean_org(values["organization"])
        upd["organization_id"] = upsert_org(db, upd["organization"])
    if values.get("depth") is not None:
        if values["depth"] not in DEPTHS:
            raise DataError(f"depth must be one of {', '.join(DEPTHS)}")
        upd["depth"] = values["depth"]
    if values.get("status") is not None:
        if values["status"] not in DOMAIN_STATUSES:
            raise DataError("status must be active or paused")
        upd["status"] = values["status"]
    if upd:
        upd["updated"] = time.time()
        db.monitored_domains.update_one({"_id": d["_id"]}, {"$set": upd})
        d.update(upd)
    return _domain_public(d)


def domain_batches(db, domain_id: str) -> List[Dict[str, Any]]:
    ids = [m["batch_id"] for m in db.batch_domain_memberships.find({"domain_id": domain_id}, {"batch_id": 1})]
    return [{"id": b["_id"], "name": b["name"], "status": b["status"]}
            for b in db.scan_batches.find({"_id": {"$in": ids}}, {"name": 1, "status": 1})] if ids else []


# ====================================================================== batches
def _batch_fields(values: Dict[str, Any], partial: bool) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if not partial or "name" in values:
        name = _clean_text(values.get("name"), MAX_NAME)
        if not name:
            raise DataError("The batch needs a name")
        out["name"], out["name_key"] = name, name.lower()
    if not partial or "description" in values:
        out["description"] = _clean_text(values.get("description"), MAX_DESCRIPTION)
    if not partial or "organization" in values:
        out["organization"] = clean_org(values.get("organization"))
    if not partial or "schedule" in values:
        try:
            out["schedule"] = sched.validate(values.get("schedule") or {})
        except sched.ScheduleError as e:
            raise DataError(str(e))
    if not partial or "depth" in values:
        depth = values.get("depth") or "standard"
        if depth not in DEPTHS:
            raise DataError(f"depth must be one of {', '.join(DEPTHS)}")
        out["depth"] = depth
    if not partial or "missed_policy" in values:
        mp = values.get("missed_policy") or "run_once"
        if mp not in MISSED_POLICIES:
            raise DataError("missed_policy must be run_once or skip")
        out["missed_policy"] = mp
    if not partial or "notify" in values:
        n = values.get("notify") or {}
        if not isinstance(n, dict):
            raise DataError("notify must be an object")
        notify = {"in_app": bool(n.get("in_app", True)), "on_new": bool(n.get("on_new", True)),
                  "on_failure": bool(n.get("on_failure", True)), "min_classification": n.get("min_classification") or "potential"}
        if notify["min_classification"] not in ("confirmed", "potential"):
            raise DataError("min_classification must be confirmed or potential")
        if "webhook_url" in n:
            try:
                notify["webhook_url"] = validate_webhook(n.get("webhook_url") or "")
            except ValueError as e:
                raise DataError(str(e))
        out["notify"] = notify
    return out


def batch_public(db, b: Dict[str, Any], with_counts: bool = True) -> Dict[str, Any]:
    out = _public(b)
    out.pop("name_key", None)
    out.pop("lease_owner", None)
    out.pop("lease_until", None)
    notify = dict(out.get("notify") or {})
    url = notify.pop("webhook_url", "") or ""
    notify["webhook"] = {"set": bool(url), "hint": mask_url(url)}
    out["notify"] = notify
    out["schedule_text"] = sched.describe(out.get("schedule") or {})
    if with_counts:
        domain_ids = batch_domain_ids(db, b["_id"])
        out["domain_count"] = len(domain_ids)
        out["counts"] = findings_counts(db, domain_ids)
        active = db.batch_executions.find_one({"batch_id": b["_id"], "status": {"$in": list(EXEC_ACTIVE)}}, sort=[("created", DESCENDING)])
        last = db.batch_executions.find_one({"batch_id": b["_id"], "status": {"$in": list(EXEC_FINAL)}}, sort=[("created", DESCENDING)])
        out["active_execution"] = execution_public(active) if active else None
        out["last_execution"] = execution_public(last) if last else None
        out["display_status"] = display_status(b, active, last)
    return out


def display_status(b: Dict[str, Any], active: Optional[Dict[str, Any]], last: Optional[Dict[str, Any]]) -> str:
    if active:
        return "Running" if active["status"] == "running" else "Queued"
    if b.get("status") == "paused":
        return "Paused"
    if b.get("status") == "disabled":
        return "Disabled"
    if b.get("next_run_at"):
        return "Scheduled"
    if last:
        return {"completed": "Completed", "partially_completed": "Partially Completed", "failed": "Failed",
                "cancelled": "Cancelled", "interrupted": "Failed"}.get(last["status"], "Completed")
    return "Manual"


def create_batch(db, values: Dict[str, Any], now: Optional[float] = None) -> Dict[str, Any]:
    now = now or time.time()
    fields = _batch_fields(values, partial=False)
    status = values.get("status") or "active"
    if status not in BATCH_STATUSES:
        raise DataError("status must be active, paused or disabled")
    doc = {"_id": new_id("bt"), **fields, "status": status, "created": now, "updated": now, "last_run_at": None,
           "last_status": None, "active_execution_id": None, "lease_owner": None, "lease_until": 0}
    doc["next_run_at"] = sched.next_run(doc["schedule"], now, anchor=now) if status == "active" else None
    try:
        db.scan_batches.insert_one(doc)
    except DuplicateKeyError:
        raise Conflict(f"A batch named '{fields['name']}' already exists")
    return doc


def get_batch(db, batch_id: str) -> Dict[str, Any]:
    b = db.scan_batches.find_one({"_id": check_id(batch_id, "bt"), "deleting": {"$ne": True}})
    if not b:
        raise NotFound("Batch not found")
    return b


def update_batch(db, batch_id: str, values: Dict[str, Any], now: Optional[float] = None) -> Dict[str, Any]:
    now = now or time.time()
    b = get_batch(db, batch_id)
    fields = _batch_fields(values, partial=True)
    if "notify" in fields and "webhook_url" not in fields["notify"]:
        fields["notify"]["webhook_url"] = (b.get("notify") or {}).get("webhook_url", "")
    if "status" in values and values["status"] is not None:
        if values["status"] not in BATCH_STATUSES:
            raise DataError("status must be active, paused or disabled")
        fields["status"] = values["status"]
    merged = {**b, **fields}
    if "schedule" in fields or "status" in fields:
        fields["next_run_at"] = (sched.next_run(merged["schedule"], now, anchor=b.get("last_run_at") or now)
                                 if merged["status"] == "active" else None)
    fields["updated"] = now
    try:
        db.scan_batches.update_one({"_id": b["_id"]}, {"$set": fields})
    except DuplicateKeyError:
        raise Conflict(f"A batch named '{fields.get('name')}' already exists")
    return {**b, **fields}


def set_batch_status(db, batch_id: str, status: str, now: Optional[float] = None) -> Dict[str, Any]:
    return update_batch(db, batch_id, {"status": status}, now)


def list_batches(db) -> List[Dict[str, Any]]:
    return [batch_public(db, b) for b in db.scan_batches.find({"deleting": {"$ne": True}}).sort("created", DESCENDING)]


def batch_domain_ids(db, batch_id: str) -> List[str]:
    return [m["domain_id"] for m in db.batch_domain_memberships.find({"batch_id": batch_id}, {"domain_id": 1}).sort("added", ASCENDING)]


def batch_add_entries(db, batch_id: str, entries: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Adds validated import entries ({domain, organization, keywords}) to a batch. Invalid ones are reported, not dropped."""
    b = get_batch(db, batch_id)
    current = set(batch_domain_ids(db, b["_id"]))
    added, existing, errors = [], [], []
    now = time.time()
    for e in entries:
        raw = (e or {}).get("domain") or ""
        try:
            doc, _ = get_or_create_domain(db, str(raw), (e or {}).get("organization") or b.get("organization") or "",
                                          (e or {}).get("keywords") or [], depth=b.get("depth") or "standard")
        except (DataError, Conflict) as ex:
            errors.append({"input": str(raw)[:200], "error": str(ex)})
            continue
        if doc["_id"] in current:
            existing.append(doc["domain"])
            continue
        if len(current) >= MAX_BATCH_DOMAINS:
            errors.append({"input": doc["domain"], "error": f"a batch holds at most {MAX_BATCH_DOMAINS} domains"})
            continue
        try:
            db.batch_domain_memberships.insert_one({"_id": f"{b['_id']}:{doc['_id']}", "batch_id": b["_id"], "domain_id": doc["_id"], "added": now})
        except DuplicateKeyError:
            existing.append(doc["domain"])
            continue
        current.add(doc["_id"])
        added.append(doc["domain"])
    db.scan_batches.update_one({"_id": b["_id"]}, {"$set": {"updated": now}})
    return {"added": added, "already_in_batch": existing, "errors": errors, "domain_count": len(current)}


def batch_domains(db, batch_id: str) -> List[Dict[str, Any]]:
    """Domains of a batch with their latest scan job and finding counts (one aggregate, no N+1 counts)."""
    ids = batch_domain_ids(db, batch_id)
    if not ids:
        return []
    docs = {d["_id"]: d for d in db.monitored_domains.find({"_id": {"$in": ids}, "deleting": {"$ne": True}})}
    counts = domain_stats(db, list(docs.values()))
    out = []
    for i in ids:
        d = docs.get(i)
        if not d:
            continue
        p = _domain_public(d)
        p["counts"] = counts.get(i)
        out.append(p)
    return out


def batch_remove_domains(db, batch_id: str, domain_ids: List[str]) -> int:
    b = get_batch(db, batch_id)
    ids = [check_id(i, "md") for i in domain_ids]
    if not ids:
        return 0
    return db.batch_domain_memberships.delete_many({"batch_id": b["_id"], "domain_id": {"$in": ids}}).deleted_count


def duplicate_batch(db, batch_id: str) -> Dict[str, Any]:
    b = get_batch(db, batch_id)
    base = f"{b['name']} (copy)"
    name, n = base, 2
    while db.scan_batches.find_one({"name_key": name.lower()}):
        name, n = f"{base} {n}", n + 1
    values = {k: b.get(k) for k in ("description", "organization", "schedule", "depth", "missed_policy", "notify")}
    values["name"] = name
    values["status"] = "paused"   # a copy never starts scanning by surprise
    copy = create_batch(db, values)
    db.scan_batches.update_one({"_id": copy["_id"]}, {"$set": {"notify": b.get("notify") or {}}})
    now = time.time()
    for i in batch_domain_ids(db, b["_id"]):
        try:
            db.batch_domain_memberships.insert_one({"_id": f"{copy['_id']}:{i}", "batch_id": copy["_id"], "domain_id": i, "added": now})
        except DuplicateKeyError:
            pass
    return db.scan_batches.find_one({"_id": copy["_id"]})


# ====================================================================== executions & jobs
def execution_public(e: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if e is None:
        return None
    out = _public(e)
    for k in ("owner", "slot_key"):
        out.pop(k, None)
    return out


def create_execution(db, batch: Dict[str, Any], trigger: str, domain_ids: Optional[List[str]] = None,
                     slot: Optional[float] = None, retry_of: Optional[str] = None, now: Optional[float] = None,
                     include_paused: bool = False) -> Dict[str, Any]:
    """
    Creates a queued execution and its per-domain jobs. Overlap protection: the batch's `active_execution_id`
    is claimed atomically, so two instances (or a double click) can never start two runs of one batch.
    Scheduled runs also carry a unique slot_key (batch + slot time) so a slot is executed at most once.
    """
    now = now or time.time()
    ex_id = new_id("ex")
    claimed = db.scan_batches.find_one_and_update(
        {"_id": batch["_id"], "$or": [{"active_execution_id": None}, {"active_execution_id": {"$exists": False}}]},
        {"$set": {"active_execution_id": ex_id}})
    if not claimed:
        _clear_stale_active(db, batch["_id"])
        claimed = db.scan_batches.find_one_and_update(
            {"_id": batch["_id"], "$or": [{"active_execution_id": None}, {"active_execution_id": {"$exists": False}}]},
            {"$set": {"active_execution_id": ex_id}})
        if not claimed:
            raise Conflict("This batch already has a run in progress")
    ids = domain_ids if domain_ids is not None else batch_domain_ids(db, batch["_id"])
    docs = {d["_id"]: d for d in db.monitored_domains.find({"_id": {"$in": ids}, "deleting": {"$ne": True}})} if ids else {}
    settings = get_settings(db)
    jobs = []
    for i in ids:
        d = docs.get(i)
        if not d:
            continue
        skip = d.get("status") == "paused" and not include_paused
        jobs.append({"_id": new_id("jb"), "execution_id": ex_id, "batch_id": batch["_id"], "domain_id": i, "domain": d["domain"],
                     "organization": d.get("organization") or "", "organization_id": d.get("organization_id"),
                     "keywords_used": list(d.get("keywords") or []), "depth": d.get("depth") or batch.get("depth") or "standard",
                     "status": "skipped" if skip else "queued", "error": "domain is paused" if skip else None,
                     "attempts": 0, "max_attempts": settings["max_attempts"], "next_attempt_at": now, "created": now,
                     "started": None, "finished": now if skip else None, "hunt_id": None, "counts": {}, "progress": 0,
                     "stage": None, "message": None, "owner": None, "lease_until": 0})
    queued = sum(j["status"] == "queued" for j in jobs)
    doc = {"_id": ex_id, "batch_id": batch["_id"], "batch_name": batch.get("name"), "trigger": trigger, "status": "queued",
           "scheduled_for": slot, "retry_of": retry_of, "created": now, "started": None, "finished": None, "heartbeat": now,
           "owner": None, "cancel_requested": False, "total": len(jobs), "queued": queued, "running": 0, "completed": 0,
           "failed": 0, "cancelled": 0, "skipped": len(jobs) - queued, "new_findings": 0, "updated_findings": 0,
           "current": [], "error": None}
    if slot is not None:
        doc["slot_key"] = f"{batch['_id']}:{int(slot)}"
    try:
        db.batch_executions.insert_one(doc)
    except DuplicateKeyError:
        db.scan_batches.update_one({"_id": batch["_id"], "active_execution_id": ex_id}, {"$set": {"active_execution_id": None}})
        raise Conflict("This scheduled slot has already been executed")
    if jobs:
        db.scan_jobs.insert_many(jobs)
    if not queued:
        finish_execution(db, ex_id, now)
    return db.batch_executions.find_one({"_id": ex_id})


def _clear_stale_active(db, batch_id: str) -> None:
    b = db.scan_batches.find_one({"_id": batch_id}, {"active_execution_id": 1})
    ex_id = (b or {}).get("active_execution_id")
    if not ex_id:
        return
    e = db.batch_executions.find_one({"_id": ex_id}, {"status": 1})
    if not e or e["status"] in EXEC_FINAL:
        db.scan_batches.update_one({"_id": batch_id, "active_execution_id": ex_id}, {"$set": {"active_execution_id": None}})


def get_execution(db, execution_id: str) -> Dict[str, Any]:
    e = db.batch_executions.find_one({"_id": check_id(execution_id, "ex")})
    if not e:
        raise NotFound("Execution not found")
    return e


def list_executions(db, batch_id: Optional[str] = None, limit: int = 50, skip: int = 0) -> List[Dict[str, Any]]:
    q = {"batch_id": check_id(batch_id, "bt")} if batch_id else {}
    cur = db.batch_executions.find(q).sort("created", DESCENDING).skip(max(0, skip)).limit(max(1, min(limit, 200)))
    return [execution_public(e) for e in cur]


def job_public(j: Dict[str, Any]) -> Dict[str, Any]:
    out = _public(j)
    out.pop("owner", None)
    return out


def execution_jobs(db, execution_id: str) -> List[Dict[str, Any]]:
    return [job_public(j) for j in db.scan_jobs.find({"execution_id": check_id(execution_id, "ex")}).sort("created", ASCENDING)]


def refresh_execution_totals(db, execution_id: str, now: Optional[float] = None, session=None) -> Dict[str, Any]:
    counts = {s: 0 for s in ("queued", "running", "completed", "failed", "cancelled", "skipped")}
    new = upd = 0
    current = []
    for j in db.scan_jobs.find({"execution_id": execution_id}, {"status": 1, "counts": 1, "domain": 1}, session=session):
        counts[j["status"]] = counts.get(j["status"], 0) + 1
        new += int((j.get("counts") or {}).get("new", 0))
        upd += int((j.get("counts") or {}).get("updated", 0)) + int((j.get("counts") or {}).get("reappeared", 0))
        if j["status"] == "running":
            current.append(j["domain"])
    fields = {**counts, "new_findings": new, "updated_findings": upd, "current": current[:10], "heartbeat": now or time.time()}
    db.batch_executions.update_one({"_id": execution_id}, {"$set": fields}, session=session)
    return fields


def finish_execution(db, execution_id: str, now: Optional[float] = None) -> Dict[str, Any]:
    now = now or time.time()
    t = refresh_execution_totals(db, execution_id, now)
    e = db.batch_executions.find_one({"_id": execution_id})
    if e["cancel_requested"]:
        status = "cancelled"
    elif t["failed"] == 0 and t["cancelled"] == 0:
        status = "completed"
    elif t["completed"] > 0:
        status = "partially_completed"
    else:
        status = "failed"
    db.batch_executions.update_one({"_id": execution_id}, {"$set": {"status": status, "finished": now, "current": []}})
    db.scan_batches.update_one({"_id": e["batch_id"]}, {"$set": {"last_run_at": e.get("started") or now, "last_status": status,
                                                                 "last_execution_id": execution_id}})
    db.scan_batches.update_one({"_id": e["batch_id"], "active_execution_id": execution_id}, {"$set": {"active_execution_id": None}})
    return db.batch_executions.find_one({"_id": execution_id})


def request_cancel(db, execution_id: str, now: Optional[float] = None) -> Dict[str, Any]:
    """Queued jobs are cancelled at once; running jobs stop at their next checkpoint (the engine watches the flag)."""
    now = now or time.time()
    e = get_execution(db, execution_id)
    if e["status"] not in EXEC_ACTIVE:
        raise Conflict(f"The run is already {e['status'].replace('_', ' ')}")
    db.batch_executions.update_one({"_id": e["_id"]}, {"$set": {"cancel_requested": True}})
    db.scan_jobs.update_many({"execution_id": e["_id"], "status": "queued"},
                             {"$set": {"status": "cancelled", "finished": now, "error": "cancelled by user"}})
    if not db.scan_jobs.find_one({"execution_id": e["_id"], "status": "running"}, {"_id": 1}):
        return finish_execution(db, e["_id"], now)
    refresh_execution_totals(db, e["_id"], now)
    return db.batch_executions.find_one({"_id": e["_id"]})


def failed_domain_ids(db, execution_id: str) -> List[str]:
    return [j["domain_id"] for j in db.scan_jobs.find({"execution_id": check_id(execution_id, "ex"),
                                                        "status": {"$in": ["failed", "cancelled"]}}, {"domain_id": 1})]


# ====================================================================== findings lifecycle
def _fingerprint(c: Dict[str, Any], cls: str) -> str:
    ev = c.get("evidence") or {}
    http = ev.get("http") or {}
    parts = [cls, c.get("verdict") or "", str(int(c.get("score") or 0)), c.get("dns_status") or "",
             ",".join(sorted((c.get("dns") or {}).get("a") or [])), str(http.get("status", "")), http.get("final_url", "") or "",
             (ev.get("title") or "")[:200]]
    return hashlib.sha1("|".join(parts).encode("utf-8", "replace")).hexdigest()


def _finding_fields(c: Dict[str, Any], cls: str) -> Dict[str, Any]:
    ev = c.get("evidence") or {}
    http = ev.get("http") or {}
    rd = c.get("rdap") or {}
    return {"classification": cls, "classification_label": c.get("classification"), "verdict": c.get("verdict"),
            "verdict_label": c.get("verdict_label"), "score": int(c.get("score") or 0),
            "registered_domain": c.get("registered_domain"), "matching_subdomain": c.get("matching_subdomain"),
            "matched_keyword": c.get("matched_keyword"), "matched_keywords": list(c.get("matched_keywords") or [])[:20],
            "matching_technique": c.get("matching_technique") or c.get("fuzzer"), "sources": list(c.get("sources") or [])[:20],
            "dns_status": c.get("dns_status"), "a": list((c.get("dns") or {}).get("a") or [])[:10],
            "http_status": http.get("status"), "final_url": (http.get("final_url") or "")[:500], "title": (ev.get("title") or "")[:300],
            "registrar": rd.get("registrar"), "created_at_registry": rd.get("created"),
            "reasons": list(c.get("reasons") or [])[:12], "corroboration": list(c.get("corroboration") or [])[:8],
            "unicode": c.get("unicode"), "defanged": c.get("defanged")}


def apply_scan_results(db, domain: Dict[str, Any], job: Dict[str, Any], candidates: List[Dict[str, Any]],
                       hunt_id: Optional[str], now: Optional[float] = None,
                       resolver=None) -> Dict[str, int]:
    """
    Merges one scan of one monitored domain into its findings.

      new          first time this host is found for this monitored domain
      seen         found before, evidence unchanged           ("Previously Discovered")
      updated      found before, evidence changed (score, classification, DNS, page)
      reappeared   found again after being missed / unreachable
      unreachable  not returned by this scan AND its DNS no longer resolves (NXDOMAIN). A host that is merely
                   missing from the results (a source failed, a feed rotated) keeps its state and gets missed_scans+1.

    Benign/unrelated candidates are only stored when the host is already a finding (so a downgrade is visible).
    """
    now = now or time.time()
    obs_dt = datetime.fromtimestamp(now, timezone.utc)
    did = domain["_id"]
    counts = {"candidates": len(candidates), "new": 0, "seen": 0, "updated": 0, "reappeared": 0, "unreachable": 0,
              "confirmed": 0, "potential": 0, "missed": 0}
    existing = {f["host"]: f for f in db.impersonation_findings.find(
        {"domain_id": did}, {"host": 1, "fingerprint": 1, "lifecycle": 1, "missed_scans": 1, "first_seen": 1, "dismissed": 1,
                             "classification": 1})}
    ops: List[Tuple[Dict[str, Any], Dict[str, Any], bool]] = []
    observations: List[Dict[str, Any]] = []
    seen_hosts = set()
    for c in candidates:
        host = (c.get("domain") or "").strip().lower()
        if not host or host in seen_hosts:
            continue
        cls = CLASS_KEYS.get(c.get("classification") or "", "potential" if c.get("verdict") in ("phishing", "suspicious") else "benign")
        prev = existing.get(host)
        if cls in ("benign", "inactive") and not prev:
            continue   # not stored unless already a finding (then the downgrade / takedown is visible as a change)
        seen_hosts.add(host)
        fp = _fingerprint(c, cls)
        if prev is None:
            change = "new"
        elif prev.get("lifecycle") == "unreachable" or int(prev.get("missed_scans") or 0) > 0:
            change = "reappeared"
        elif prev.get("fingerprint") != fp:
            change = "updated"
        else:
            change = "seen"
        counts[change] += 1
        if cls in ("confirmed", "potential"):
            counts[cls] += 1
        fields = {**_finding_fields(c, cls), "lifecycle": change, "fingerprint": fp, "last_seen": now, "missed_scans": 0,
                  "last_job_id": job["_id"], "last_execution_id": job.get("execution_id"), "last_batch_id": job.get("batch_id"),
                  "hunt_id": hunt_id, "original_domain": domain["domain"], "organization_id": domain.get("organization_id"),
                  "keywords_used": list(job.get("keywords_used") or [])}
        if change in ("new", "updated", "reappeared"):
            fields["last_changed"] = now
        insert_only = {"domain_id": did, "host": host, "first_seen": now, "first_job_id": job["_id"],
                       "first_execution_id": job.get("execution_id"), "first_batch_id": job.get("batch_id"), "under_review": False}
        if prev is not None and prev.get("dismissed") and cls == "confirmed" and prev.get("classification") != "confirmed":
            fields.update(dismissed=False, escalated_at=now)   # a dismissed lead that is now confirmed comes back
            counts["escalated"] = counts.get("escalated", 0) + 1
        elif prev is None:
            insert_only["dismissed"] = False
        ops.append(({"_id": f"{did}:{host}"}, {"$set": fields, "$setOnInsert": insert_only}, True))
        if change != "seen":   # unchanged re-sightings only move last_seen on the finding: no history row per scan
            observations.append({"_id": f"{job['_id']}:{host}", "finding_id": f"{did}:{host}", "domain_id": did, "host": host,
                                 "job_id": job["_id"], "execution_id": job.get("execution_id"), "batch_id": job.get("batch_id"),
                                 "observed_at": now, "observed_dt": obs_dt, "change": change, "classification": cls,
                                 "score": fields["score"], "verdict": fields["verdict"], "dns_status": fields["dns_status"],
                                 "sources": fields["sources"]})

    missing = [h for h in existing if h not in seen_hosts]
    counts["missed"] = len(missing)
    if missing:
        dns: Dict[str, Dict[str, Any]] = {}
        # Only the host's own DNS decides "unreachable": a source outage can make a host go
        # missing from the results, but never makes it NXDOMAIN. A DNS timeout leaves the state unchanged.
        if resolver is not None:
            try:
                dns = resolver(missing[:UNREACHABLE_CHECK_LIMIT]) or {}
            except Exception:
                dns = {}
        for host in missing:
            info = dns.get(host) or {}
            gone = info.get("status") == "nxdomain"
            upd: Dict[str, Any] = {"last_checked": now, "last_job_id": job["_id"]}
            if gone and existing[host].get("lifecycle") != "unreachable":
                upd.update(lifecycle="unreachable", last_changed=now, dns_status="nxdomain")
                counts["unreachable"] += 1
                observations.append({"_id": f"{job['_id']}:{host}", "finding_id": f"{did}:{host}", "domain_id": did, "host": host,
                                     "job_id": job["_id"], "execution_id": job.get("execution_id"), "batch_id": job.get("batch_id"),
                                     "observed_at": now, "observed_dt": obs_dt, "change": "unreachable", "classification": None, "score": None,
                                     "verdict": None, "dns_status": "nxdomain", "sources": []})
            ops.append(({"_id": f"{did}:{host}", "domain_id": did}, {"$set": upd, "$inc": {"missed_scans": 1}}, False))
    _bulk_update(db.impersonation_findings, ops)
    if observations:
        for i in range(0, len(observations), 500):
            try:
                db.scan_observations.insert_many(observations[i:i + 500], ordered=False)
            except Exception:  # a retried job re-inserting the same observation ids: keep the first copy
                for o in observations[i:i + 500]:
                    db.scan_observations.replace_one({"_id": o["_id"]}, o, upsert=True)
    refresh_domain_stats(db, did)
    return counts


def _bulk_update(coll, ops: List[Tuple[Dict[str, Any], Dict[str, Any], bool]]) -> None:
    """Unordered bulk upserts in chunks of 500 (one round trip per chunk on a real server)."""
    for i in range(0, len(ops), 500):
        chunk = ops[i:i + 500]
        try:
            coll.bulk_write([UpdateOne(f, u, upsert=up) for f, u, up in chunk], ordered=False)
        except TypeError:  # mongomock does not accept the newer pymongo UpdateOne signature: same writes, one by one
            for f, u, up in chunk:
                coll.update_one(f, u, upsert=up)


FINDING_SORTS = {"score": [("score", DESCENDING), ("host", ASCENDING)], "last_seen": [("last_seen", DESCENDING)],
                 "first_seen": [("first_seen", DESCENDING)], "host": [("host", ASCENDING)]}
FINDING_VIEWS = ("all", "new", "confirmed", "potential", "inactive", "benign", "changed", "unreachable", "review", "dismissed")


def findings_query(domain_id: str, view: str = "all", q: str = "", min_score: Optional[int] = None) -> Dict[str, Any]:
    query: Dict[str, Any] = {"domain_id": check_id(domain_id, "md")}
    if view not in FINDING_VIEWS:
        raise DataError(f"view must be one of {', '.join(FINDING_VIEWS)}")
    if view == "new":
        query["lifecycle"] = "new"
    elif view in ("confirmed", "potential", "inactive", "benign"):
        query["classification"] = view
    elif view == "changed":
        query["lifecycle"] = {"$in": ["updated", "reappeared"]}
    elif view == "unreachable":
        query["lifecycle"] = "unreachable"
    elif view == "review":
        query["under_review"] = True
    if view == "dismissed":
        query["dismissed"] = True
    else:
        query["dismissed"] = {"$ne": True}
    q = (q or "").strip().lower()[:100]
    if q:
        query["host"] = {"$regex": re.escape(q)}
    if min_score is not None:
        query["score"] = {"$gte": int(min_score)}
    return query


def list_findings(db, domain_id: str, view: str = "all", q: str = "", sort: str = "score", page: int = 1,
                  page_size: int = 50, min_score: Optional[int] = None) -> Dict[str, Any]:
    get_domain(db, domain_id)
    query = findings_query(domain_id, view, q, min_score)
    page_size = max(1, min(int(page_size or 50), 200))
    page = max(1, int(page or 1))
    total = db.impersonation_findings.count_documents(query)
    cur = db.impersonation_findings.find(query, {"fingerprint": 0}).sort(FINDING_SORTS.get(sort, FINDING_SORTS["score"])) \
        .skip((page - 1) * page_size).limit(page_size)
    items = []
    for f in cur:
        f = _public(f)
        f["lifecycle_label"] = LIFECYCLE_LABELS.get(f.get("lifecycle"), f.get("lifecycle"))
        items.append(f)
    return {"items": items, "total": total, "page": page, "page_size": page_size, "pages": max(1, -(-total // page_size))}


STAT_KEYS = ("total", "confirmed", "potential", "inactive", "benign", "new", "updated", "reappeared", "unreachable", "dismissed", "observations")


def _count_findings(db, match: Dict[str, Any], session=None) -> Dict[str, int]:
    out = {k: 0 for k in STAT_KEYS}
    out["dismissed"] = db.impersonation_findings.count_documents({**match, "dismissed": True}, session=session)
    for row in db.impersonation_findings.aggregate([{"$match": {**match, "dismissed": {"$ne": True}}},
                                                     {"$group": {"_id": {"c": "$classification", "l": "$lifecycle"}, "n": {"$sum": 1}}}],
                                                    session=session):
        n = row["n"]
        out["total"] += n
        c, lc = row["_id"].get("c"), row["_id"].get("l")
        if c in out:
            out[c] += n
        if lc in ("new", "updated", "reappeared", "unreachable"):
            out[lc] += n
    return out


def refresh_domain_stats(db, domain_id: str, session=None) -> Dict[str, int]:
    """Recomputes one domain's counters (indexed: only that domain's documents are read) and stores them on the
    monitored domain, so overview / batch / data pages sum a few hundred small documents instead of every finding.
    Called after every scan and every change to findings (dismiss, delete, clear)."""
    stats = _count_findings(db, {"domain_id": domain_id}, session)
    stats["observations"] = db.scan_observations.count_documents({"domain_id": domain_id}, session=session)
    stats["updated_at"] = time.time()
    db.monitored_domains.update_one({"_id": domain_id}, {"$set": {"stats": stats}}, session=session)
    return stats


def domain_stats(db, docs: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """Counters per domain document (computed and stored once for domains that have none yet)."""
    out = {}
    for d in docs:
        st = d.get("stats")
        if not st or any(k not in st for k in STAT_KEYS):
            st = refresh_domain_stats(db, d["_id"])
        out[d["_id"]] = {k: int(st.get(k, 0)) for k in STAT_KEYS}
    return out


def findings_counts(db, domain_ids: List[str]) -> Dict[str, int]:
    """Totals over domains, from the per-domain counters (O(domains), not O(findings))."""
    out = {k: 0 for k in STAT_KEYS if k != "observations"}
    if not domain_ids:
        return out
    docs = list(db.monitored_domains.find({"_id": {"$in": list(domain_ids)}}, {"stats": 1}))
    for st in domain_stats(db, docs).values():
        for k in out:
            out[k] += st[k]
    return out


def _findings_counts_live(db, domain_ids: List[str]) -> Dict[str, int]:
    """Exact aggregate over the findings themselves (tests use it to prove the counters are right)."""
    out = _count_findings(db, {"domain_id": {"$in": list(domain_ids)}})
    out.pop("observations", None)
    return out


def set_review(db, domain_id: str, finding_ids: List[str], under_review: bool) -> int:
    did = check_id(domain_id, "md")
    ids = [f for f in finding_ids if isinstance(f, str) and f.startswith(did + ":")]
    if not ids:
        return 0
    return db.impersonation_findings.update_many({"domain_id": did, "_id": {"$in": ids}}, {"$set": {"under_review": bool(under_review)}}).modified_count


def set_dismissed(db, domain_id: str, finding_ids: List[str], dismissed: bool, reason: str = "") -> int:
    """False-positive dismissal: hidden from the review views, counts and alerts, kept across rescans."""
    did = check_id(domain_id, "md")
    ids = [f for f in finding_ids if isinstance(f, str) and f.startswith(did + ":")]
    if not ids:
        return 0
    upd: Dict[str, Any] = {"dismissed": bool(dismissed)}
    if dismissed:
        upd.update(dismissed_at=time.time(), dismissed_reason=_clean_text(reason, 300))
    n = db.impersonation_findings.update_many({"domain_id": did, "_id": {"$in": ids}}, {"$set": upd}).modified_count
    refresh_domain_stats(db, did)
    return n


def batch_findings_query(db, batch_id: str, view: str = "all") -> Dict[str, Any]:
    """Findings of every domain in a batch (for the batch-wide export)."""
    b = get_batch(db, batch_id)
    ids = batch_domain_ids(db, b["_id"])
    q = findings_query("md_000000000000", view)          # same view rules as one domain...
    q["domain_id"] = {"$in": ids}                         # ...applied to all of the batch's domains
    return q


def finding_history(db, domain_id: str, finding_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    did = check_id(domain_id, "md")
    if not isinstance(finding_id, str) or not finding_id.startswith(did + ":"):
        raise NotFound("Finding not found")
    return [_public(o) for o in db.scan_observations.find({"domain_id": did, "finding_id": finding_id}).sort("observed_at", DESCENDING).limit(limit)]


def domain_jobs(db, domain_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    did = check_id(domain_id, "md")
    return [job_public(j) for j in db.scan_jobs.find({"domain_id": did}).sort("created", DESCENDING).limit(max(1, min(limit, 200)))]


def domain_observations(db, domain_id: str, limit: int = 200, skip: int = 0) -> List[Dict[str, Any]]:
    did = check_id(domain_id, "md")
    return [_public(o) for o in db.scan_observations.find({"domain_id": did}).sort("observed_at", DESCENDING).skip(max(0, skip)).limit(max(1, min(limit, 500)))]


def domain_dashboard(db, domain_id: str) -> Dict[str, Any]:
    d = get_domain(db, domain_id)
    out = _domain_public(d)
    out["counts"] = findings_counts(db, [d["_id"]])
    out["batches"] = domain_batches(db, d["_id"])
    out["scans"] = db.scan_jobs.count_documents({"domain_id": d["_id"]})
    out["observations"] = db.scan_observations.count_documents({"domain_id": d["_id"]})
    last = db.scan_jobs.find_one({"domain_id": d["_id"], "status": {"$in": list(JOB_FINAL)}}, sort=[("created", DESCENDING)])
    running = db.scan_jobs.find_one({"domain_id": d["_id"], "status": {"$in": ["queued", "running"]}}, sort=[("created", DESCENDING)])
    out["last_job"] = job_public(last) if last else None
    out["active_job"] = job_public(running) if running else None
    out["top_findings"] = list_findings(db, d["_id"], "all", page_size=5)["items"]
    return out


# ====================================================================== overview
def overview(db, now: Optional[float] = None) -> Dict[str, Any]:
    now = now or time.time()
    batches = list(db.scan_batches.find({"deleting": {"$ne": True}}, {"name": 1, "status": 1, "next_run_at": 1, "schedule": 1}))
    upcoming = sorted(({"batch_id": b["_id"], "name": b["name"], "at": b["next_run_at"], "schedule_text": sched.describe(b.get("schedule") or {})}
                       for b in batches if b.get("status") == "active" and b.get("next_run_at")), key=lambda x: x["at"])[:10]
    active = [execution_public(e) for e in db.batch_executions.find({"status": {"$in": list(EXEC_ACTIVE)}}).sort("created", ASCENDING)]
    day = now - 86400
    recent = list(db.batch_executions.find({"created": {"$gte": day}}, {"status": 1, "new_findings": 1}))
    return {"batches": len(batches), "active_batches": sum(b.get("status") == "active" for b in batches),
            "domains": db.monitored_domains.count_documents({"deleting": {"$ne": True}}),
            "findings": findings_counts(db, [d["_id"] for d in db.monitored_domains.find({}, {"_id": 1})]),
            "running": active, "upcoming": upcoming,
            "last_24h": {"runs": len(recent), "failed": sum(e["status"] == "failed" for e in recent),
                         "partial": sum(e["status"] == "partially_completed" for e in recent),
                         "new_findings": sum(int(e.get("new_findings") or 0) for e in recent)}}


# ====================================================================== data management: impact + scoped deletes
def domain_impact(db, domain_id: str) -> Dict[str, Any]:
    d = get_domain(db, domain_id)
    did = d["_id"]
    job_hunts = [j["hunt_id"] for j in db.scan_jobs.find({"domain_id": did, "hunt_id": {"$ne": None}}, {"hunt_id": 1})]
    active = db.scan_jobs.count_documents({"domain_id": did, "status": {"$in": ["queued", "running"]}})
    return {"type": "domain", "id": did, "name": d["domain"], "confirm_text": d["domain"],
            "findings": db.impersonation_findings.count_documents({"domain_id": did}),
            "observations": db.scan_observations.count_documents({"domain_id": did}),
            "scan_jobs": db.scan_jobs.count_documents({"domain_id": did}),
            "saved_hunts": len(job_hunts), "batches": domain_batches(db, did), "active_jobs": active,
            "shared": "Infrastructure investigations and manual Brand Hunt history are not owned by a monitored domain and are kept."}


def batch_impact(db, batch_id: str) -> Dict[str, Any]:
    b = get_batch(db, batch_id)
    ids = batch_domain_ids(db, b["_id"])
    exclusive = [i for i in ids if db.batch_domain_memberships.count_documents({"domain_id": i}) == 1]
    return {"type": "batch", "id": b["_id"], "name": b["name"], "confirm_text": b["name"],
            "domains": len(ids), "exclusive_domains": len(exclusive),
            "executions": db.batch_executions.count_documents({"batch_id": b["_id"]}),
            "scan_jobs": db.scan_jobs.count_documents({"batch_id": b["_id"]}),
            "active_executions": db.batch_executions.count_documents({"batch_id": b["_id"], "status": {"$in": list(EXEC_ACTIVE)}}),
            "findings_of_exclusive_domains": db.impersonation_findings.count_documents({"domain_id": {"$in": exclusive}}) if exclusive else 0}


def require_confirmation(expected: str, given: Optional[str]) -> None:
    if (given or "").strip().lower() != (expected or "").strip().lower():
        raise DataError(f"Type '{expected}' exactly to confirm")


# ---------------------------------------------------------------------- transactions
_TXN_SUPPORT: Dict[int, bool] = {}


def supports_transactions(db) -> bool:
    """True on a replica set or sharded cluster (multi-document transactions); False on a standalone server."""
    key = id(db.client)
    if key not in _TXN_SUPPORT:
        try:
            hello = db.client.admin.command("hello")
            _TXN_SUPPORT[key] = bool(hello.get("setName") or hello.get("msg") == "isdbgrid") \
                and hello.get("logicalSessionTimeoutMinutes") is not None
        except Exception:  # mongomock, old servers, restricted users
            _TXN_SUPPORT[key] = False
    return _TXN_SUPPORT[key]


def run_atomic(db, fn):
    """
    Runs fn(session) as ONE multi-document transaction when the server supports it: either everything is deleted
    or nothing is. On a standalone server fn(None) runs the recoverable workflow instead (the target is marked
    `deleting` first and its own document is removed last, every step is scoped and idempotent, so repeating an
    interrupted call finishes it). Returns (result, transactional).
    """
    if supports_transactions(db):
        with db.client.start_session() as session:
            # with_transaction retries the whole callback on transient errors: every step below is idempotent
            return session.with_transaction(lambda s: fn(s)), True
    return fn(None), False


def _delete_hunts(db, hunt_ids: List[str], session=None) -> int:
    """Saved hunts created by the scheduler only (`scheduled_batch`), never manual Brand Hunt history."""
    hunt_ids = [h for h in hunt_ids if h]
    if not hunt_ids:
        return 0
    owned = [h["_id"] for h in db.hunts.find({"_id": {"$in": hunt_ids}, "scheduled_batch": True}, {"_id": 1}, session=session)]
    if not owned:
        return 0
    n = db.hunts.delete_many({"_id": {"$in": owned}}, session=session).deleted_count
    db.candidates.delete_many({"hunt_id": {"$in": owned}}, session=session)
    return n


def delete_findings(db, domain_id: str, finding_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """Selected findings (ids must belong to the domain) or all findings of the domain, plus their observations."""
    did = get_domain(db, domain_id)["_id"]
    ids = None if finding_ids is None else [f for f in finding_ids if isinstance(f, str) and f.startswith(did + ":")]
    if ids is not None and not ids:
        return {"findings": 0, "observations": 0, "transaction": False}

    def work(s):
        if ids is None:
            obs = db.scan_observations.delete_many({"domain_id": did}, session=s).deleted_count
            return {"findings": db.impersonation_findings.delete_many({"domain_id": did}, session=s).deleted_count, "observations": obs}
        obs = db.scan_observations.delete_many({"domain_id": did, "finding_id": {"$in": ids}}, session=s).deleted_count
        return {"findings": db.impersonation_findings.delete_many({"domain_id": did, "_id": {"$in": ids}}, session=s).deleted_count,
                "observations": obs}
    out, txn = run_atomic(db, work)
    refresh_domain_stats(db, did)
    return {**out, "transaction": txn}


def clear_domain_history(db, domain_id: str) -> Dict[str, Any]:
    """Scan history (finished jobs, their saved hunts, observations). Current findings are kept."""
    did = get_domain(db, domain_id)["_id"]

    def work(s):
        if db.scan_jobs.find_one({"domain_id": did, "status": {"$in": ["queued", "running"]}}, {"_id": 1}, session=s):
            raise Conflict("A scan of this domain is queued or running. Cancel it first.")
        jobs = list(db.scan_jobs.find({"domain_id": did, "status": {"$in": list(JOB_FINAL)}}, {"hunt_id": 1}, session=s))
        hunts = _delete_hunts(db, [j.get("hunt_id") for j in jobs], s)
        obs = db.scan_observations.delete_many({"domain_id": did}, session=s).deleted_count
        n = db.scan_jobs.delete_many({"domain_id": did, "_id": {"$in": [j["_id"] for j in jobs]}}, session=s).deleted_count if jobs else 0
        return {"scan_jobs": n, "observations": obs, "saved_hunts": hunts}
    out, txn = run_atomic(db, work)
    refresh_domain_stats(db, did)
    return {**out, "transaction": txn}


def _delete_domain_work(db, did: str, s) -> Dict[str, Any]:
    if db.scan_jobs.find_one({"domain_id": did, "status": "running"}, {"_id": 1}, session=s):
        raise Conflict("A scan of this domain is running. Cancel it first.")
    db.monitored_domains.update_one({"_id": did}, {"$set": {"deleting": True, "deleting_since": time.time()}}, session=s)
    db.scan_jobs.update_many({"domain_id": did, "status": "queued"},
                             {"$set": {"status": "cancelled", "error": "domain deleted", "finished": time.time()}}, session=s)
    jobs = list(db.scan_jobs.find({"domain_id": did}, {"hunt_id": 1, "execution_id": 1}, session=s))
    out = {"findings": db.impersonation_findings.delete_many({"domain_id": did}, session=s).deleted_count,
           "observations": db.scan_observations.delete_many({"domain_id": did}, session=s).deleted_count,
           "saved_hunts": _delete_hunts(db, [j.get("hunt_id") for j in jobs], s),
           "scan_jobs": db.scan_jobs.delete_many({"domain_id": did}, session=s).deleted_count,
           "memberships": db.batch_domain_memberships.delete_many({"domain_id": did}, session=s).deleted_count}
    for ex in {j.get("execution_id") for j in jobs if j.get("execution_id")}:
        refresh_execution_totals(db, ex, session=s)
    db.scheduler_locks.delete_many({"_id": f"domain:{did}"}, session=s)
    out["domain_record"] = db.monitored_domains.delete_one({"_id": did}, session=s).deleted_count
    return out


def delete_domain(db, domain_id: str) -> Dict[str, Any]:
    """The monitored domain and everything it owns (findings, observations, jobs, scheduler-saved hunts, memberships)."""
    did = check_id(domain_id, "md")
    if not db.monitored_domains.find_one({"_id": did}, {"_id": 1}):
        raise NotFound("Monitored domain not found")
    out, txn = run_atomic(db, lambda s: _delete_domain_work(db, did, s))
    return {**out, "transaction": txn}


def _clear_executions_work(db, bid: str, s) -> Dict[str, int]:
    exs = [e["_id"] for e in db.batch_executions.find({"batch_id": bid}, {"_id": 1}, session=s)]
    jobs = list(db.scan_jobs.find({"batch_id": bid}, {"hunt_id": 1}, session=s))
    return {"saved_hunts": _delete_hunts(db, [j.get("hunt_id") for j in jobs], s),
            "scan_jobs": db.scan_jobs.delete_many({"batch_id": bid}, session=s).deleted_count,
            "executions": db.batch_executions.delete_many({"batch_id": bid, "_id": {"$in": exs}}, session=s).deleted_count if exs else 0}


def clear_batch_executions(db, batch_id: str) -> Dict[str, Any]:
    bid = get_batch(db, batch_id)["_id"]

    def work(s):
        if db.batch_executions.find_one({"batch_id": bid, "status": {"$in": list(EXEC_ACTIVE)}}, {"_id": 1}, session=s):
            raise Conflict("This batch has a run in progress. Cancel it first.")
        out = _clear_executions_work(db, bid, s)
        db.scan_batches.update_one({"_id": bid}, {"$set": {"last_status": None, "last_execution_id": None}}, session=s)
        return out
    out, txn = run_atomic(db, work)
    return {**out, "transaction": txn}


def delete_batch(db, batch_id: str, delete_exclusive_domains: bool = False) -> Dict[str, Any]:
    """Deletes the batch configuration, its memberships and run history. Domains stay unless they belong to no other
    batch AND delete_exclusive_domains is set (then they are deleted with everything they own, in the same transaction)."""
    bid = check_id(batch_id, "bt")
    if not db.scan_batches.find_one({"_id": bid}, {"_id": 1}):
        raise NotFound("Batch not found")

    def work(s):
        if db.batch_executions.find_one({"batch_id": bid, "status": {"$in": list(EXEC_ACTIVE)}}, {"_id": 1}, session=s):
            raise Conflict("This batch has a run in progress. Cancel it first.")
        db.scan_batches.update_one({"_id": bid}, {"$set": {"deleting": True, "deleting_since": time.time(), "status": "disabled",
                                                          "next_run_at": None}}, session=s)
        ids = [m["domain_id"] for m in db.batch_domain_memberships.find({"batch_id": bid}, {"domain_id": 1}, session=s)]
        exclusive = [i for i in ids if db.batch_domain_memberships.count_documents({"domain_id": i}, session=s) == 1]
        out: Dict[str, Any] = _clear_executions_work(db, bid, s)
        out["memberships"] = db.batch_domain_memberships.delete_many({"batch_id": bid}, session=s).deleted_count
        out["domains_deleted"] = []
        if delete_exclusive_domains:
            for i in exclusive:
                if db.monitored_domains.find_one({"_id": i}, {"_id": 1}, session=s):
                    out["domains_deleted"].append({"id": i, **_delete_domain_work(db, i, s)})
        out["batch_record"] = db.scan_batches.delete_one({"_id": bid}, session=s).deleted_count
        return out
    out, txn = run_atomic(db, work)
    return {**out, "transaction": txn}


def finish_interrupted_deletes(db, older_than: float = 60.0, now: Optional[float] = None) -> List[str]:
    """Standalone servers only: a delete that stopped half-way left its target marked `deleting` (hidden from the
    UI and the scheduler). Repeating the idempotent delete finishes it; the engine calls this on every tick."""
    cutoff = (now or time.time()) - older_than
    done = []
    for d in list(db.monitored_domains.find({"deleting": True, "deleting_since": {"$lt": cutoff}}, {"_id": 1})):
        try:
            delete_domain(db, d["_id"])
            done.append(d["_id"])
        except (NotFound, Conflict):
            continue
    for b in list(db.scan_batches.find({"deleting": True, "deleting_since": {"$lt": cutoff}}, {"_id": 1})):
        try:
            delete_batch(db, b["_id"])
            done.append(b["_id"])
        except (NotFound, Conflict):
            continue
    return done


def data_summary(db) -> Dict[str, Any]:
    """Per-domain and per-batch volumes for the Data Management page (aggregates, no per-row counting loops)."""
    def grouped(coll, key="domain_id"):
        return {r["_id"]: r["n"] for r in db[coll].aggregate([{"$group": {"_id": f"${key}", "n": {"$sum": 1}}}])}
    j, mem = grouped("scan_jobs"), grouped("batch_domain_memberships")
    docs = list(db.monitored_domains.find({"deleting": {"$ne": True}}).sort("domain", ASCENDING))
    st = domain_stats(db, docs)
    domains = [{"id": d["_id"], "domain": d["domain"], "organization": d.get("organization") or "", "status": d.get("status"),
                "findings": st[d["_id"]]["total"] + st[d["_id"]]["dismissed"], "observations": st[d["_id"]]["observations"],
                "scan_jobs": j.get(d["_id"], 0), "batches": mem.get(d["_id"], 0), "last_scan_at": d.get("last_scan_at")}
               for d in docs]
    ex, bj, bm = grouped("batch_executions", "batch_id"), grouped("scan_jobs", "batch_id"), grouped("batch_domain_memberships", "batch_id")
    batches = [{"id": b["_id"], "name": b["name"], "status": b.get("status"), "domains": bm.get(b["_id"], 0),
                "executions": ex.get(b["_id"], 0), "scan_jobs": bj.get(b["_id"], 0)}
               for b in db.scan_batches.find({"deleting": {"$ne": True}}).sort("name_key", ASCENDING)]
    totals = {c: db[c].estimated_document_count() for c in ("monitored_domains", "scan_batches", "batch_executions", "scan_jobs",
                                                             "impersonation_findings", "scan_observations", "audit_logs", "hunts", "candidates",
                                                             "infra_investigations", "alerts", "triage", "watchlist")}
    return {"domains": domains, "batches": batches, "totals": totals}
