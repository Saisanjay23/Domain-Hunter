"""
Free phishing feeds, matched against the brand (no API key needed):

  OpenPhish public feed        live phishing URLs, small (refreshed hourly)
  Phishing.Database (ACTIVE)   ~390k phishing domains from the community (refreshed daily)

Feeds are cached on disk (data/feeds). If a download fails the stale cache is used, and if
there is no cache the failure is reported instead of silently returning nothing.
"""

import os
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import requests

from . import config
from .domains import normalize_host, registrable_domain
from .pivots import FREE_HOSTING

CACHE_DIR = os.path.join(config.PROJECT_ROOT, "data", "feeds")
MAX_HITS_PER_FEED = 300
MIN_TOKEN_LEN = 4

FEEDS: Dict[str, Dict[str, Any]] = {
    "nrd_free": {
        "name": "Free Daily NRD", "kind": "domains", "ttl": 12 * 3600, "file": "nrd-1w.csv",
        "url": "https://raw.githubusercontent.com/shreshta-labs/newly-registered-domains/main/nrd-1w.csv",
    },
    "openphish": {
        "name": "OpenPhish", "kind": "urls", "ttl": 3600, "file": "openphish.txt",
        "url": "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
    },
    "phishingdb": {
        "name": "Phishing.Database", "kind": "domains", "ttl": 24 * 3600, "file": "phishing-domains-active.txt",
        "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    },
}

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; brand-protection-scanner/1.0)"}
_locks = {k: threading.Lock() for k in FEEDS}
_memory: Dict[str, Dict[str, Any]] = {}  # feed -> {"mtime": float, "lines": [str]}


def _path(feed: str) -> str:
    return os.path.join(CACHE_DIR, FEEDS[feed]["file"])


def _age(feed: str) -> Optional[float]:
    try:
        return time.time() - os.path.getmtime(_path(feed))
    except OSError:
        return None


def refresh(feed: str, force: bool = False) -> Dict[str, Any]:
    """Downloads the feed if the cache is missing or older than its TTL. Never raises."""
    meta = FEEDS[feed]
    with _locks[feed]:
        age = _age(feed)
        if not force and age is not None and age < meta["ttl"]:
            return {"ok": True, "downloaded": False, "age": age}
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=meta["file"] + ".", dir=CACHE_DIR)
            try:
                with requests.get(meta["url"], headers=HEADERS, timeout=(10, 90), stream=True) as r:
                    if r.status_code != 200:
                        raise requests.HTTPError(f"HTTP {r.status_code}")
                    with os.fdopen(fd, "wb") as f:
                        for chunk in r.iter_content(1 << 16):
                            f.write(chunk)
                os.replace(tmp, _path(feed))
            finally:
                if os.path.exists(tmp):
                    os.remove(tmp)
            return {"ok": True, "downloaded": True, "age": 0.0}
        except Exception as e:
            note = f"{meta['name']} download failed ({e.__class__.__name__})"
            if age is not None:
                return {"ok": True, "downloaded": False, "age": age, "warning": note + "; using the cached copy"}
            return {"ok": False, "error": note, "age": None}


def _lines(feed: str) -> List[str]:
    try:
        mtime = os.path.getmtime(_path(feed))
    except OSError:
        return []
    cached = _memory.get(feed)
    if cached and cached["mtime"] == mtime:
        return cached["lines"]
    with open(_path(feed), encoding="utf-8", errors="ignore") as f:
        lines = [ln.strip().lower() for ln in f if ln.strip() and not ln.startswith("#")]
    _memory[feed] = {"mtime": mtime, "lines": lines}
    return lines


# Words phishers put in front of a brand: "secureadani.com" targets adani, "madani.com" does not.
LURE_PREFIXES = {"secure", "login", "my", "www", "online", "app", "mobile", "official", "pay", "web", "get", "the", "new",
                 "portal", "verify", "account", "support", "help", "service", "update", "id", "go", "mail", "email", "sign", "signin"}


def token_matches(host: str, token: str) -> bool:
    """
    Does the hostname plausibly target the brand token? Long tokens (6+) match as a substring.
    Short ones must start a label, be a whole hyphen/dot-separated part, or follow a lure word,
    so "adani" matches adani-login.com, adanipower.in and secure-adani.com but not madani-tours.com
    or rahmadani.com.
    """
    host, token = host.lower(), token.lower().strip(".")
    if not token or token not in host:
        return False
    if len(token) >= 6:
        return True
    for label in host.split("."):
        if token not in label:
            continue
        if label.startswith(token) or token in label.split("-") or (len(token) >= 4 and "-" in token and f"-{token}-" in f"-{label}-"):
            return True
        if label.endswith(token) and label[: -len(token)].replace("-", "") in LURE_PREFIXES:
            return True
    return False


def host_matches(host: str, tokens: List[str]) -> bool:
    return any(token_matches(host, t) for t in tokens if len(t) >= MIN_TOKEN_LEN)


def _is_free_hosting(host: str) -> bool:
    return any(host == h or host.endswith("." + h) for h in FREE_HOSTING)


def _candidate_key(host: str, tokens: List[str]) -> str:
    reg = registrable_domain(host) or host
    return reg if host_matches(reg, tokens) else host


def match(tokens: List[str], allowlist: List[str], force_refresh: bool = False) -> Dict[str, Any]:
    """
    Returns {"hits": [{"host", "url", "feed", "feed_name", "via"}], "status": [...], "errors": [...]}.
    A hit's host is the candidate domain to track (the registrable domain when it carries the brand
    name, otherwise the exact host, e.g. a subdomain or a free-hosting page).
    """
    usable = [t for t in tokens if len(t) >= MIN_TOKEN_LEN]
    result: Dict[str, Any] = {"hits": [], "status": [], "errors": []}
    if not usable:
        result["errors"].append("Phishing feeds skipped: the brand name is too short to match reliably")
        return result

    needles = [t.lower().strip(".") for t in usable]
    seen: Set[str] = set()
    for feed, meta in FEEDS.items():
        info = refresh(feed, force=force_refresh)
        if info.get("warning"):
            result["errors"].append(info["warning"])
        if not info["ok"]:
            result["errors"].append(info["error"])
            result["status"].append({"feed": feed, "name": meta["name"], "count": 0, "error": info["error"]})
            continue

        hits: List[Dict[str, Any]] = []
        total = 0
        for line in _lines(feed):
            total += 1
            if not any(t in line for t in needles):  # cheap pre-filter: most of the ~400k lines never mention the brand
                continue
            if meta["kind"] == "urls":
                p = urlparse(line if "://" in line else f"//{line}")
                host, path = normalize_host(p.hostname or ""), (p.path or "").lower()
                if not host:
                    continue
                via = None
                if host_matches(host, usable):
                    via = "host"
                elif _is_free_hosting(host) and host_matches(path.replace("/", "."), usable):
                    via = "path"  # brand only in the URL path of a free-hosting page
                if not via:
                    continue
                key = host if via == "path" else _candidate_key(host, usable)
                url = line
            else:
                raw_dom = line.split(",", 1)[0].strip()
                if raw_dom in ("domain", "domain_name", "domains"):
                    continue
                host = normalize_host(raw_dom)
                if not host or "." not in host or not host_matches(host, usable):
                    continue
                key, url, via = _candidate_key(host, usable), None, "host"
            if (registrable_domain(key) or key) in allowlist:
                continue
            if (feed, key) in seen:
                continue
            seen.add((feed, key))
            hits.append({"host": key, "url": url, "feed": feed, "feed_name": meta["name"], "via": via})
        matched = len(hits)
        hits.sort(key=lambda h: (h["via"] != "host", len(h["host"])))  # closest to the brand name first
        hits = hits[:MAX_HITS_PER_FEED]
        age = _age(feed)
        result["hits"].extend(hits)
        result["status"].append({"feed": feed, "name": meta["name"], "count": len(hits), "matched": matched, "entries": total,
                                 "age_hours": round(age / 3600, 1) if age is not None else None, "error": None})
    return result


def feeds_status() -> List[Dict[str, Any]]:
    """Cache freshness for the UI (no network)."""
    out = []
    for feed, meta in FEEDS.items():
        age = _age(feed)
        out.append({"feed": feed, "name": meta["name"], "cached": age is not None,
                    "age_hours": round(age / 3600, 1) if age is not None else None})
    return out
