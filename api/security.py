"""
HTTP hardening applied to every request (registered in app.py):

  * request size limit      bodies above BRAND_HUNTER_MAX_BODY_MB (default 25 MB) are refused with 413
  * write rate limit        per client, sliding 60 s window, for POST/PUT/PATCH/DELETE under /api/:
                            BRAND_HUNTER_RATE_LIMIT per minute (default 120; 0 disables), and a stricter
                            budget for destructive /api/data/ calls (a quarter of it, at least 10)
  * security headers        nosniff, no framing, no referrer, minimal permissions; API responses are no-store
"""

import os
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple

from fastapi import Request
from fastapi.responses import JSONResponse

WINDOW = 60.0
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_hits: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
_lock = threading.Lock()


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _allow(client: str, bucket: str, limit: int, now: float) -> Tuple[bool, int]:
    with _lock:
        q = _hits[(client, bucket)]
        while q and now - q[0] > WINDOW:
            q.popleft()
        if len(q) >= limit:
            return False, max(1, int(WINDOW - (now - q[0])) + 1)
        q.append(now)
        if len(_hits) > 10000:  # bound memory: forget idle clients
            for k in [k for k, v in _hits.items() if not v or now - v[-1] > WINDOW]:
                _hits.pop(k, None)
        return True, 0


def reset() -> None:
    with _lock:
        _hits.clear()


async def security_middleware(request: Request, call_next):
    path = request.url.path
    max_body = _int_env("BRAND_HUNTER_MAX_BODY_MB", 25) * 1024 * 1024
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > max_body:
        return JSONResponse(status_code=413, content={"detail": f"Request body larger than {max_body // (1024 * 1024)} MB"})

    limit = _int_env("BRAND_HUNTER_RATE_LIMIT", 120)
    if limit > 0 and request.method in WRITE_METHODS and path.startswith("/api/"):
        client = request.client.host if request.client else "unknown"
        destructive = path.startswith("/api/data/")
        ok, retry = _allow(client, "data" if destructive else "write", max(10, limit // 4) if destructive else limit, time.monotonic())
        if not ok:
            return JSONResponse(status_code=429, content={"detail": f"Too many requests. Try again in {retry} s."},
                                headers={"Retry-After": str(retry)})

    response = await call_next(request)
    h = response.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    if path.startswith("/api/"):
        h.setdefault("Cache-Control", "no-store")
    return response
