"""
API-key rotation. Each source can have several keys (config: KEY=k1,k2,k3).

Failover order: the first healthy key is used until it hits a limit, then the next one takes
over. Failures are classified so a key is only sidelined for as long as makes sense:

    rate_limit   HTTP 429 / "too frequent"        cool down for Retry-After (default 60 s)
    quota        credits / searches used up        cool down 12 h (or until reset)
    forbidden    HTTP 403, plan doesn't allow it   cool down 30 min
    auth         HTTP 401, invalid key             disabled until the key list changes

Other errors (query syntax, network, 5xx) are not the key's fault and are raised immediately.
State is kept in memory per server process and never contains the key values.
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from . import config

COOLDOWNS = {"rate_limit": 60, "quota": 12 * 3600, "forbidden": 30 * 60}
ROTATE_KINDS = {"rate_limit", "quota", "forbidden", "auth"}
REASON_TEXT = {"rate_limit": "rate limited", "quota": "quota used up", "forbidden": "plan does not allow the query", "auth": "invalid key"}


class SourceError(Exception):
    """A platform call failed. kind tells the pool whether to try the next key."""

    def __init__(self, message: str, kind: str = "other", retry_after: Optional[float] = None):
        super().__init__(message)
        self.kind = kind
        self.retry_after = retry_after


@dataclass
class KeyState:
    uses: int = 0
    failures: int = 0
    cooldown_until: float = 0.0
    disabled: bool = False
    reason: Optional[str] = None
    last_used: Optional[float] = None
    last_error: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


class KeyPool:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: Dict[str, Dict[str, KeyState]] = {}

    @staticmethod
    def env_name(source: str) -> str:
        return config.SOURCES[source]["env"][0]

    def keys(self, source: str) -> List[str]:
        return config.get_list(self.env_name(source))

    def _st(self, source: str, kid: str) -> KeyState:
        return self._state.setdefault(source, {}).setdefault(kid, KeyState())

    def usable(self, source: str) -> List[str]:
        """Keys to try, in failover order, skipping disabled and cooling-down ones."""
        now = time.time()
        with self._lock:
            out = []
            for k in self.keys(source):
                st = self._st(source, config.key_id(k))
                if st.disabled or st.cooldown_until > now:
                    continue
                out.append(k)
            return out

    def next_available_in(self, source: str) -> Optional[int]:
        now = time.time()
        with self._lock:
            waits = [st.cooldown_until - now for k in self.keys(source)
                     for st in [self._st(source, config.key_id(k))] if not st.disabled and st.cooldown_until > now]
        return int(min(waits)) + 1 if waits else None

    def mark_success(self, source: str, key: str) -> None:
        with self._lock:
            st = self._st(source, config.key_id(key))
            st.uses += 1
            st.last_used = time.time()
            st.cooldown_until = 0.0
            st.disabled = False
            st.reason = None

    def mark_failure(self, source: str, key: str, err: SourceError) -> None:
        with self._lock:
            st = self._st(source, config.key_id(key))
            st.failures += 1
            st.last_used = time.time()
            st.last_error = str(err)[:160]
            st.reason = err.kind
            if err.kind == "auth":
                st.disabled = True
            else:
                wait = err.retry_after if (err.kind == "rate_limit" and err.retry_after) else COOLDOWNS.get(err.kind, 60)
                st.cooldown_until = time.time() + max(1.0, min(float(wait), 24 * 3600))

    def reset(self, source: Optional[str] = None, kid: Optional[str] = None) -> None:
        with self._lock:
            if source is None:
                self._state.clear()
            elif kid is None:
                self._state.pop(source, None)
            else:
                self._state.get(source, {}).pop(kid, None)

    def status(self, source: str) -> Dict[str, Dict[str, Any]]:
        """Per-key status for the UI, keyed by key id (no key values)."""
        now = time.time()
        out: Dict[str, Dict[str, Any]] = {}
        with self._lock:
            active_found = False
            for k in self.keys(source):
                kid = config.key_id(k)
                st = self._st(source, kid)
                cooling = st.cooldown_until > now
                if st.disabled:
                    state = "invalid"
                elif cooling:
                    state = "exhausted" if st.reason == "quota" else "cooling"
                elif not active_found:
                    state, active_found = "active", True
                else:
                    state = "standby"
                out[kid] = {
                    "state": state, "uses": st.uses, "failures": st.failures,
                    "reason": REASON_TEXT.get(st.reason or "", None) if (st.disabled or cooling) else None,
                    "available_in": int(st.cooldown_until - now) + 1 if cooling else None,
                    "last_used": st.last_used, "last_error": st.last_error,
                }
        return out


POOL = KeyPool()


def with_rotation(source: str, call: Callable[[str], Any], anonymous: Optional[Callable[[], Any]] = None, pool: KeyPool = POOL) -> Any:
    """
    Runs call(key) with the first healthy key; on a key-related failure marks that key and
    retries with the next one. `anonymous` (URLScan) is the last resort when no key works.
    """
    all_keys = pool.keys(source)
    if not all_keys:
        if anonymous:
            return anonymous()
        raise SourceError(f"{pool.env_name(source)} not set", kind="config")

    tried = 0
    last: Optional[SourceError] = None
    for key in pool.usable(source):
        tried += 1
        try:
            result = call(key)
        except SourceError as e:
            if e.kind not in ROTATE_KINDS:
                raise
            pool.mark_failure(source, key, e)
            last = e
            continue
        pool.mark_success(source, key)
        return result

    if anonymous:
        return anonymous()
    n = len(all_keys)
    if not tried:
        wait = pool.next_available_in(source)
        raise SourceError(f"all {n} key{'s' if n != 1 else ''} are paused" + (f"; next one available in {wait}s" if wait else " (invalid keys need replacing)"),
                          kind="exhausted")
    label = "key" if n == 1 else f"{n} keys"
    raise SourceError(f"{label} failed, last error: {last}", kind="exhausted")
