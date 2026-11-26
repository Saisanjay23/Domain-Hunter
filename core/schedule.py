"""
Schedule definitions and next-run computation for scan batches (time-zone aware, DST safe).

    {"frequency": "daily",    "time": "02:30", "timezone": "Asia/Kolkata"}
    {"frequency": "weekly",   "time": "09:00", "timezone": "Europe/Berlin", "weekdays": [0, 3]}   # Mon, Thu
    {"frequency": "interval", "interval_hours": 6}                                                 # every 6 h
    {"frequency": "manual"}                                                                        # Run now only

All instants are Unix timestamps (UTC). Local wall-clock times are resolved with zoneinfo; a time that does not
exist on a spring-forward day runs at the first valid instant after it, and an ambiguous fall-back time runs once
(the first occurrence).
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

FREQUENCIES = ("daily", "weekly", "interval", "manual")
MIN_INTERVAL_HOURS = 1
MAX_INTERVAL_HOURS = 24 * 30
_TIME = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
WEEKDAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


class ScheduleError(ValueError):
    pass


_TZ_CACHE: Optional[set] = None


def valid_timezones() -> set:
    global _TZ_CACHE
    if _TZ_CACHE is None:
        _TZ_CACHE = set(available_timezones()) | {"UTC"}
    return _TZ_CACHE


def validate(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Returns a clean schedule dict or raises ScheduleError."""
    spec = dict(spec or {})
    freq = spec.get("frequency") or "daily"
    if freq not in FREQUENCIES:
        raise ScheduleError(f"frequency must be one of {', '.join(FREQUENCIES)}")
    out: Dict[str, Any] = {"frequency": freq}
    tz = (spec.get("timezone") or "UTC").strip()
    if tz not in valid_timezones():
        raise ScheduleError(f"Unknown time zone '{tz[:60]}'")
    out["timezone"] = tz
    if freq in ("daily", "weekly"):
        t = (spec.get("time") or "02:00").strip()
        if not _TIME.match(t):
            raise ScheduleError("time must be HH:MM (24-hour)")
        out["time"] = t
    if freq == "weekly":
        days = spec.get("weekdays")
        if not isinstance(days, list) or not days:
            raise ScheduleError("Pick at least one weekday")
        try:
            clean = sorted({int(d) for d in days})
        except (TypeError, ValueError):
            raise ScheduleError("weekdays must be numbers 0 (Mon) to 6 (Sun)")
        if any(d < 0 or d > 6 for d in clean):
            raise ScheduleError("weekdays must be numbers 0 (Mon) to 6 (Sun)")
        out["weekdays"] = clean
    if freq == "interval":
        try:
            hours = float(spec.get("interval_hours") or 24)
        except (TypeError, ValueError):
            raise ScheduleError("interval_hours must be a number")
        if not MIN_INTERVAL_HOURS <= hours <= MAX_INTERVAL_HOURS:
            raise ScheduleError(f"interval_hours must be between {MIN_INTERVAL_HOURS} and {MAX_INTERVAL_HOURS}")
        out["interval_hours"] = hours
    return out


def _local_instant(day: datetime, hhmm: str, tz: ZoneInfo) -> float:
    h, m = (int(x) for x in hhmm.split(":"))
    local = datetime(day.year, day.month, day.day, h, m, tzinfo=tz, fold=0)
    # round-trip through UTC: a non-existent wall time (DST gap) maps to a real instant just after the gap
    return local.astimezone(timezone.utc).timestamp()


def next_run(spec: Dict[str, Any], after: float, anchor: Optional[float] = None) -> Optional[float]:
    """First run strictly after `after`. For interval schedules, `anchor` is the previous run (or creation time)."""
    freq = spec.get("frequency")
    if freq == "manual" or freq not in FREQUENCIES:
        return None
    if freq == "interval":
        step = float(spec.get("interval_hours") or 24) * 3600
        base = anchor if anchor is not None else after
        nxt = base + step
        if nxt <= after:  # missed several periods: next slot on the same grid
            nxt = base + step * (int((after - base) // step) + 1)
        return nxt
    try:
        tz = ZoneInfo(spec.get("timezone") or "UTC")
    except ZoneInfoNotFoundError:
        tz = ZoneInfo("UTC")
    start = datetime.fromtimestamp(after, tz)
    days = set(spec.get("weekdays") or range(7)) if freq == "weekly" else set(range(7))
    for offset in range(0, 15):
        day = (start + timedelta(days=offset)).date()
        if day.weekday() not in days:
            continue
        ts = _local_instant(datetime(day.year, day.month, day.day), spec.get("time") or "02:00", tz)
        if ts > after:
            return ts
    return None  # pragma: no cover - unreachable for valid specs


def period_seconds(spec: Dict[str, Any]) -> float:
    """Nominal distance between runs (used for the missed-run grace window)."""
    freq = spec.get("frequency")
    if freq == "interval":
        return float(spec.get("interval_hours") or 24) * 3600
    if freq == "weekly":
        return 7 * 86400 / max(1, len(spec.get("weekdays") or [0]))
    return 86400


def describe(spec: Dict[str, Any]) -> str:
    freq = spec.get("frequency")
    if freq == "manual":
        return "Manual (Run now only)"
    if freq == "interval":
        h = float(spec.get("interval_hours") or 24)
        return f"Every {int(h) if h == int(h) else h} h"
    tz = spec.get("timezone") or "UTC"
    if freq == "weekly":
        days = ", ".join(WEEKDAY_NAMES[d] for d in spec.get("weekdays") or [])
        return f"Weekly {days} at {spec.get('time')} ({tz})"
    return f"Daily at {spec.get('time')} ({tz})"
