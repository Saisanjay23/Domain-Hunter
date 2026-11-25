"""
Copy case data between backends (SQLite -> MongoDB or back). Safe to run repeatedly:

  hunts       upserted by id
  triage      upserted by (brand, domain), original timestamps kept
  watchlist   brands already present in the destination are skipped (so a re-run never duplicates)
  alerts      copied only when the destination has none yet (alerts have no natural key)
"""

from typing import Any, Dict

from .store import StoreBase, StoreError


def copy_store(src: StoreBase, dst: StoreBase) -> Dict[str, Any]:
    counts: Dict[str, Any] = {"hunts": 0, "triage": 0, "watchlist": 0, "watchlist_skipped": 0, "alerts": 0, "alerts_skipped": False}

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

    if dst.alert_list(1):
        counts["alerts_skipped"] = True
    else:
        for a in reversed(src.alert_list(1_000_000)):
            dst.alert_add(a["brand"], a["level"], a["title"], a["body"], a.get("hunt_id"), a.get("delivery", ""), created=a["created"], read=a["read"])
            counts["alerts"] += 1
    return counts
