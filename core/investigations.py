"""
Infrastructure Investigator history (MongoDB collection `infra_investigations`).

Every finished investigation is stored with a small summary (for the history list) and the full result (graph,
domains, operator dossier) so it can be reopened, exported or compared later without re-running it.

    {_id: <job id, 12 hex>, seed, seed_root, params{depth, max_domains, keywords}, created, finished,
     summary{mode, confidence, sophistication, domains, linked_high, linked_medium, linked_low, nodes, edges, elapsed_sec},
     result{...}, size_bytes, trimmed}
"""

import re
import time
from typing import Any, Dict, Optional

import bson
from pymongo import DESCENDING

MAX_DOC_BYTES = 12 * 1024 * 1024        # well below MongoDB's 16 MB document limit
ID_RE = re.compile(r"^[0-9a-f]{12}$")


class NotFound(LookupError):
    pass


def ensure_indexes(db) -> None:
    db.infra_investigations.create_index([("created", DESCENDING)])
    db.infra_investigations.create_index([("seed", 1), ("created", DESCENDING)])


def _plain(obj: Any) -> Any:
    """Mongo-safe keys (no dots / leading $) and JSON-safe values."""
    if isinstance(obj, dict):
        return {(str(k).replace(".", "_").lstrip("$") or "_"): _plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [_plain(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def _trim(result: Dict[str, Any]) -> Dict[str, Any]:
    """Drops embedded favicon previews (the largest part) if a huge investigation would not fit in one document."""
    out = dict(result)
    out["domains"] = [{**d, "favicon": {k: v for k, v in (d.get("favicon") or {}).items() if k not in ("preview", "data_uri")}}
                      if isinstance(d.get("favicon"), dict) else d for d in result.get("domains") or []]
    out["nodes"] = [{**n, "data": {k: v for k, v in (n.get("data") or {}).items() if k not in ("preview", "data_uri")}}
                    for n in result.get("nodes") or []]
    return out


def summarize(result: Dict[str, Any]) -> Dict[str, Any]:
    a = result.get("actor") or {}
    st = result.get("stats") or {}
    return {"mode": a.get("mode"), "confidence": a.get("confidence"), "sophistication": a.get("sophistication"),
            "domains": st.get("domains_profiled", len(result.get("domains") or [])), "linked_high": st.get("linked_high", 0),
            "linked_medium": st.get("linked_medium", 0), "linked_low": st.get("linked_low", 0), "nodes": st.get("nodes", 0),
            "edges": st.get("edges", 0), "elapsed_sec": st.get("elapsed_sec"), "summary": (a.get("summary") or "")[:400]}


def save(db, job_id: str, params: Dict[str, Any], result: Dict[str, Any], created: Optional[float] = None) -> Dict[str, Any]:
    if not ID_RE.match(job_id or ""):
        raise ValueError("bad investigation id")
    now = time.time()
    body = _plain(result)
    doc = {"_id": job_id, "seed": result.get("seed"), "seed_root": result.get("seed_root"), "params": _plain(params),
           "created": created or now, "finished": now, "summary": summarize(result), "result": body, "trimmed": False}
    size = len(bson.encode(doc))
    if size > MAX_DOC_BYTES:
        doc["result"], doc["trimmed"] = _plain(_trim(result)), True
        size = len(bson.encode(doc))
        if size > MAX_DOC_BYTES:
            doc["result"] = {k: v for k, v in doc["result"].items() if k not in ("nodes", "edges")}
    doc["size_bytes"] = size
    db.infra_investigations.replace_one({"_id": job_id}, doc, upsert=True)
    return {k: v for k, v in doc.items() if k != "result"}


def _public(d: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in d.items() if k not in ("_id", "result")}
    out["id"] = d["_id"]
    return out


def list_items(db, q: str = "", limit: int = 30, skip: int = 0) -> Dict[str, Any]:
    query: Dict[str, Any] = {}
    q = (q or "").strip().lower()[:100]
    if q:
        query["seed"] = {"$regex": re.escape(q)}
    total = db.infra_investigations.count_documents(query)
    cur = db.infra_investigations.find(query, {"result": 0}).sort("created", DESCENDING).skip(max(0, skip)).limit(max(1, min(limit, 100)))
    return {"items": [_public(d) for d in cur], "total": total}


def get(db, inv_id: str) -> Dict[str, Any]:
    if not isinstance(inv_id, str) or not ID_RE.match(inv_id):
        raise NotFound("Unknown investigation")
    d = db.infra_investigations.find_one({"_id": inv_id})
    if not d:
        raise NotFound("Unknown investigation")
    res = dict(d.get("result") or {})
    res["id"] = d["_id"]
    res["history"] = _public(d)
    return res


def delete(db, inv_id: str) -> int:
    if not isinstance(inv_id, str) or not ID_RE.match(inv_id):
        raise NotFound("Unknown investigation")
    return db.infra_investigations.delete_one({"_id": inv_id}).deleted_count


def previous_for(db, seed: str, before: float) -> Optional[Dict[str, Any]]:
    """The most recent earlier investigation of the same seed (for 'what changed since last time')."""
    d = db.infra_investigations.find_one({"seed": seed, "created": {"$lt": before}}, {"result.domains.domain": 1, "result.domains.link_confidence": 1,
                                                                                       "created": 1, "summary": 1},
                                         sort=[("created", DESCENDING)])
    return d


def diff_against_previous(db, result: Dict[str, Any], created: float) -> Optional[Dict[str, Any]]:
    prev = previous_for(db, result.get("seed"), created)
    if not prev:
        return None
    before = {d["domain"]: d.get("link_confidence") for d in ((prev.get("result") or {}).get("domains") or [])}
    now = {d["domain"]: d.get("link_confidence") for d in result.get("domains") or []}
    linked = ("seed", "high", "medium")
    return {"previous_id": prev["_id"], "previous_at": prev.get("created"),
            "new_domains": sorted(d for d in now if d not in before),
            "gone_domains": sorted(d for d in before if d not in now),
            "newly_linked": sorted(d for d, c in now.items() if c in linked and before.get(d) not in linked)}
