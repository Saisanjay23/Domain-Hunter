"""
Source activity log: every time an intelligence source is skipped, limited or fails during a hunt, radar, capture or
investigation, it is recorded here instead of being shown as a warning on the results screens. The API keys page
(Settings) shows the log, grouped per source, with what to do about it.

Kept in memory (last MAX_EVENTS) and mirrored to data/source_events.json so it survives a restart. Messages never
contain keys: SourceError texts are already key-free.
"""

import json
import os
import re
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, Iterable, Optional

from .config import PROJECT_ROOT

MAX_EVENTS = 300
STORE_FILE = os.path.join(PROJECT_ROOT, "data", "source_events.json")

_LOCK = threading.Lock()
_EVENTS: Deque[Dict[str, Any]] = deque(maxlen=MAX_EVENTS)
_LOADED = False

KINDS = {
    "plan": ("Plan does not include this search", "A free plan cannot run this query. It is skipped; nothing to do unless you upgrade."),
    "rate": ("Rate limited / daily quota reached", "Free quota used up for now. It resets automatically (usually within the hour or the next day)."),
    "challenge": ("Anti-bot challenge", "The service asked for a human check. It is skipped (never bypassed); other sources cover it."),
    "auth": ("Key rejected", "The saved key is invalid or expired. Replace or remove it on this page."),
    "overloaded": ("Service overloaded", "The free service was busy. The run continued with fallbacks; it usually works on the next run."),
    "network": ("Network error / timeout", "The service did not answer in time. Usually temporary."),
    "other": ("Error", "Unexpected answer from the service. Usually temporary."),
}

# Display name -> source id, so "FOFA 'Lookalike titles'" and "fofa" land in the same group.
_ALIASES = {
    "urlscan": "urlscan", "fofa": "fofa", "shodan": "shodan", "censys": "censys", "whoisxml": "whoisxml", "virustotal": "virustotal",
    "google lens": "serpapi", "serpapi": "serpapi", "google safe browsing": "safebrowsing", "safebrowsing": "safebrowsing",
    "otx": "otx", "alienvault": "otx", "hackertarget": "hackertarget", "duckduckgo": "duckduckgo", "bing": "bing",
    "wayback": "wayback", "crt.sh": "crt.sh", "ct search": "crt.sh", "ctlogs": "crt.sh", "openphish": "feeds", "phishing.database": "feeds",
    "phishing feeds": "feeds", "rdap": "rdap", "whois": "rdap", "team cymru": "asn", "ripestat": "asn", "dns": "dns",
    "page fetch": "page", "tls": "page", "verify": "page",
}


def classify(message: str) -> str:
    low = (message or "").lower()
    if "plan does not allow" in low or "820001" in low or "http 403" in low and "plan" in low or "membership" in low:
        return "plan"
    if "challenge" in low or "captcha" in low:
        return "challenge"
    if "429" in low or "rate limit" in low or "quota" in low or "daily free limit" in low or "paused" in low or "api count" in low:
        return "rate"
    if "401" in low or "key rejected" in low or "invalid key" in low:
        return "auth"
    if any(x in low for x in ("502", "503", "504", "overloaded")):
        return "overloaded"
    if any(x in low for x in ("timeout", "network error", "unreachable", "connection")):
        return "network"
    return "other"


def source_id(name: str) -> str:
    low = (name or "").lower()
    for alias, sid in _ALIASES.items():
        if low.startswith(alias) or f" {alias}" in f" {low}":
            return sid
    return re.sub(r"[^a-z0-9.]+", "", low.split(" ")[0]) or "other"


def _load() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    try:
        with open(STORE_FILE, encoding="utf-8") as f:
            for e in json.load(f)[-MAX_EVENTS:]:
                if isinstance(e, dict) and e.get("source"):
                    _EVENTS.append(e)
    except (OSError, ValueError):
        pass


def _save() -> None:
    try:
        os.makedirs(os.path.dirname(STORE_FILE), exist_ok=True)
        tmp = STORE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(list(_EVENTS), f)
        os.replace(tmp, STORE_FILE)
    except OSError:
        pass


def record(name: str, message: str, context: str, label: str = "", target: str = "") -> None:
    """One skipped / limited / failed source call. `name` may be a display name ("FOFA 'Lookalike titles'")."""
    if not message:
        return
    sid = source_id(name)
    event = {"source": sid, "name": name.split(" '")[0][:60], "label": (label or "")[:120], "message": str(message)[:300],
             "kind": classify(message), "context": context, "target": (target or "")[:120], "time": time.time()}
    with _LOCK:
        _load()
        _EVENTS.append(event)
        _save()


def record_many(items: Iterable[str], context: str, target: str = "") -> None:
    """Free-text "Source 'label': message" lines (the format runs have always used for their notes)."""
    for line in items or []:
        text = str(line)
        # "Source 'label': message"; labels may contain quotes themselves (Keyword 'gide': subdomain clones)
        m = re.match(r"^(?P<name>[^':]+?) '(?P<label>.*)': (?P<msg>.+)$", text, re.S)
        if m:
            record(m.group("name"), m.group("msg"), context, label=m.group("label"), target=target)
            continue
        name, _, message = text.partition(": ")
        record(name, message or text, context, target=target)


def summary(hours: float = 72) -> Dict[str, Any]:
    """Events of the last `hours`, newest first, plus the latest event per source with advice."""
    cutoff = time.time() - hours * 3600
    with _LOCK:
        _load()
        events = [e for e in _EVENTS if e.get("time", 0) >= cutoff]
    events.sort(key=lambda e: -e["time"])
    per: Dict[str, Dict[str, Any]] = {}
    for e in events:
        p = per.setdefault(e["source"], {"source": e["source"], "name": e["name"], "count": 0, "latest": e,
                                         "kinds": {}, "title": KINDS[e["kind"]][0], "advice": KINDS[e["kind"]][1]})
        p["count"] += 1
        p["kinds"][e["kind"]] = p["kinds"].get(e["kind"], 0) + 1
    return {"hours": hours, "events": events[:100], "sources": sorted(per.values(), key=lambda p: -p["latest"]["time"])}


def clear(source: Optional[str] = None) -> None:
    with _LOCK:
        _load()
        keep = [e for e in _EVENTS if source and e["source"] != source]
        _EVENTS.clear()
        _EVENTS.extend(keep)
        _save()


def _reset_for_tests(path: Optional[str] = None) -> None:
    global _LOADED, STORE_FILE
    with _LOCK:
        _EVENTS.clear()
        _LOADED = True
        if path:
            STORE_FILE = path
