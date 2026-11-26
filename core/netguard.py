"""
SSRF guard for every page / favicon fetch made while inspecting suspected lookalike sites.

A lookalike domain is attacker-controlled: its DNS can point at 127.0.0.1, 10.x, 169.254.169.254 (cloud metadata) or
another internal address, and a redirect can send the crawler there too. PublicOnlyAdapter is mounted on the
crawler's requests.Session, so the check runs before *every* connection, including each redirect hop:
the hostname is resolved and the request is refused unless every address is a public unicast address.

Set BRAND_HUNTER_ALLOW_PRIVATE_FETCH=1 to inspect internal hosts on purpose (e.g. an intranet asset scan).
Known limit: the check and the connection resolve the name separately, so a DNS-rebinding server with a ~0 s TTL
could still race it; the window is milliseconds and the crawler only ever issues GET requests.
"""

import ipaddress
import os
import socket
import threading
import time
from typing import Dict, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

CACHE_SECONDS = 60
_cache: Dict[str, Tuple[float, bool, str]] = {}
_lock = threading.Lock()


class BlockedAddress(requests.exceptions.ConnectionError):
    """The destination resolves to a non-public address (treated like an unreachable host by callers)."""


def private_fetch_allowed() -> bool:
    return os.environ.get("BRAND_HUNTER_ALLOW_PRIVATE_FETCH", "").strip().lower() in ("1", "true", "yes", "on")


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
                or ip.is_unspecified or (ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10")))


def check_host(host: str) -> Tuple[bool, str]:
    """(allowed, reason). Cached for a minute per hostname."""
    host = (host or "").strip("[]").lower()
    if not host:
        return False, "no host"
    now = time.monotonic()
    with _lock:
        hit = _cache.get(host)
        if hit and now - hit[0] < CACHE_SECONDS:
            return hit[1], hit[2]
    try:
        ipaddress.ip_address(host)
        addrs = [host]
    except ValueError:
        try:
            addrs = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
        except (socket.gaierror, UnicodeError, OSError):
            return True, "unresolved"      # nothing to connect to; the request itself will fail normally
    bad = [a for a in addrs if not is_public_ip(a)]
    result = (False, f"{host} resolves to a non-public address ({bad[0]})") if bad else (True, "public")
    with _lock:
        if len(_cache) > 5000:
            _cache.clear()
        _cache[host] = (now, result[0], result[1])
    return result


class PublicOnlyAdapter(HTTPAdapter):
    def send(self, request, *args, **kwargs):
        if not private_fetch_allowed():
            ok, reason = check_host(urlparse(request.url).hostname or "")
            if not ok:
                raise BlockedAddress(f"Blocked request: {reason}", request=request)
        return super().send(request, *args, **kwargs)


def clear_cache() -> None:
    with _lock:
        _cache.clear()
