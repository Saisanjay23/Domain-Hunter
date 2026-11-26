"""
Source availability checks.

Free / keyless sources are probed with one cheap request each, in parallel, with a short timeout. Keyed sources
are NOT called (that would spend quota): their configuration state is reported, and the Settings page's Test
button checks the key itself. Results are cached for CACHE_TTL seconds.
"""

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

from . import config

UA = {"User-Agent": "Mozilla/5.0 (compatible; brand-protection-scanner/1.0)"}
TIMEOUT = 8
CACHE_TTL = 300.0

# id -> (display name, URL, what it is used for). Every probe asks about example.com only.
FREE_PROBES: Dict[str, Tuple[str, str, str]] = {
    "crt.sh": ("crt.sh (Certificate Transparency)", "https://crt.sh/?q=example.com&output=json&exclude=expired", "brand hostnames in TLS certificates"),
    "ctlogs": ("ctlogs.dev (CT fallback)", "https://ctlogs.dev/search?q=example.com&output=json", "CT fallback when crt.sh is overloaded"),
    "urlscan": ("URLScan.io (anonymous)", "https://urlscan.io/api/v1/search/?q=domain:example.com&size=1", "scanned pages, titles, subdomains"),
    "rdap": ("RDAP bootstrap (IANA)", "https://data.iana.org/rdap/dns.json", "registration date / registrar"),
    "bing": ("Bing RSS search", "https://www.bing.com/search?format=rss&q=example.com", "search-engine discovery"),
    "duckduckgo": ("DuckDuckGo HTML search", "https://html.duckduckgo.com/html/?q=example.com", "search-engine discovery"),
    "wayback": ("Wayback CDX", "https://web.archive.org/cdx/search/cdx?url=example.com&limit=1&output=json", "archived / free-hosting pages"),
    "otx": ("AlienVault OTX passive DNS", "https://otx.alienvault.com/api/v1/indicators/domain/example.com/general", "sibling hostnames under suspicious domains"),
    "openphish": ("OpenPhish feed", "https://openphish.com/feed.txt", "live phishing URLs"),
}

_cache: Dict[str, Any] = {"at": 0.0, "result": None}
_lock = threading.Lock()


def _probe(sid: str, name: str, url: str, purpose: str, getter: Callable[..., Any]) -> Dict[str, Any]:
    t0 = time.monotonic()
    out = {"id": sid, "name": name, "purpose": purpose, "keyless": True}
    try:
        # stream=True: only the status line and headers are needed, never the (possibly large) body
        resp = getter(url, headers=UA, timeout=TIMEOUT, stream=True)
        code = resp.status_code
        try:
            resp.close()
        except Exception:
            pass
        if code == 200:
            status, detail = "up", "responding"
        elif code == 202 and sid == "duckduckgo":
            status, detail = "challenged", "anti-bot challenge: skipped during hunts (never bypassed)"
        elif code == 429:
            status, detail = "rate_limited", "rate limited right now: hunts retry / fall back"
        elif code in (502, 503, 504):
            status, detail = "degraded", f"HTTP {code} (overloaded): hunts fall back where possible"
        else:
            status, detail = "down", f"HTTP {code}"
    except requests.RequestException as e:
        status, detail = "down", f"unreachable ({e.__class__.__name__})"
    out.update(status=status, ok=status == "up", detail=detail, ms=int((time.monotonic() - t0) * 1000))
    return out


def _dns_probe() -> Dict[str, Any]:
    t0 = time.monotonic()
    try:
        socket.getaddrinfo("example.com", 443)
        status, detail = "up", "resolver answering"
    except OSError as e:
        status, detail = "down", f"no DNS resolution ({e.__class__.__name__})"
    return {"id": "dns", "name": "DNS resolver", "purpose": "which candidates exist (A/AAAA/MX/NS)", "keyless": True,
            "status": status, "ok": status == "up", "detail": detail, "ms": int((time.monotonic() - t0) * 1000)}


def check_sources(force: bool = False, getter: Optional[Callable[..., Any]] = None) -> Dict[str, Any]:
    """{"checked_at", "cached", "free": [...probe results], "keyed": [...configuration state]}"""
    now = time.monotonic()
    with _lock:
        if not force and _cache["result"] is not None and now - _cache["at"] < CACHE_TTL:
            return {**_cache["result"], "cached": True}
    get = getter or requests.get
    with ThreadPoolExecutor(max_workers=len(FREE_PROBES) + 1, thread_name_prefix="src-health") as pool:
        futs = [pool.submit(_probe, sid, n, u, p, get) for sid, (n, u, p) in FREE_PROBES.items()]
        futs.append(pool.submit(_dns_probe))
        free: List[Dict[str, Any]] = [f.result() for f in futs]
    keyed = [
        {"id": s["id"], "name": s["name"], "status": "configured" if s["has_key"] else ("keyless" if s["enabled"] else "not_configured"),
         "key_count": s["key_count"], "detail": "use Test on this page to verify the key" if s["has_key"] else
         ("works without a key" if s["enabled"] else "optional: add a key to enable")}
        for s in config.sources_status()
    ]
    result = {"checked_at": int(time.time()), "free": free, "keyed": keyed,
              "summary": {"up": sum(1 for f in free if f["ok"]), "total": len(free)}}
    with _lock:
        _cache.update(at=now, result=result)
    return {**result, "cached": False}
