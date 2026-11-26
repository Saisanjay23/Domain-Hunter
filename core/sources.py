"""
Threat-intel platform clients. Each search returns normalised hits:

    {"host": "adani-login.com" | None, "ip": "1.2.3.4" | None, "port": 443 | None,
     "url": str | None, "title": str, "time": str, "source": "urlscan", "extra": {...}}

Errors never include the request URL (Shodan / FOFA / SerpApi put the key in the query string).
"""

import base64
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import logging
import re
import threading
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import requests
from bs4 import BeautifulSoup

from . import config
from .domains import normalize_host
from .keypool import POOL, SourceError, with_rotation  # noqa: F401  (SourceError re-exported)

logger = logging.getLogger("hunt.sources")

UA = {"User-Agent": "Mozilla/5.0 (compatible; brand-protection-scanner/1.0)"}
TIMEOUT = 30


def _get(url: str, params: Dict[str, Any], headers: Optional[Dict[str, str]] = None, timeout: int = TIMEOUT) -> Any:
    try:
        resp = requests.get(url, params=params, headers={**UA, **(headers or {})}, timeout=timeout)
    except requests.RequestException as e:
        raise SourceError(f"network error ({e.__class__.__name__})") from None
    return _json(resp)


def _post(url: str, body: Dict[str, Any], headers: Dict[str, str], params: Optional[Dict[str, Any]] = None) -> Any:
    try:
        resp = requests.post(url, json=body, params=params, headers={**UA, **headers}, timeout=TIMEOUT)
    except requests.RequestException as e:
        raise SourceError(f"network error ({e.__class__.__name__})") from None
    return _json(resp)


def _retry_after(resp: requests.Response) -> Optional[float]:
    try:
        return float(resp.headers.get("Retry-After", ""))
    except (TypeError, ValueError):
        return None


def _error_text(resp: requests.Response) -> str:
    try:
        data = resp.json()
        msg = data.get("error") or data.get("message") or data.get("errmsg") or ""
        if isinstance(msg, dict):
            msg = msg.get("message", "")
        return str(msg)
    except Exception:
        return ""


RATE_WORDS = ("rate limit", "too many requests", "too many", "slow down", "per second", "try again in")
QUOTA_WORDS = ("run out of searches", "out of searches", "quota", "credits", "insufficient", "monthly", "plan limit")


def _json(resp: requests.Response) -> Any:
    code = resp.status_code
    if code == 401:
        raise SourceError("HTTP 401: key rejected", kind="auth")
    if code == 402:
        raise SourceError("HTTP 402: no credits left on this key", kind="quota")
    if code == 403:
        raise SourceError("HTTP 403: this key's plan does not allow the query", kind="forbidden")
    if code == 429:
        text = _error_text(resp).lower()
        # Rate-limit wording wins: "Rate limit reached" is a short pause, not an exhausted key.
        if any(w in text for w in QUOTA_WORDS) and not any(w in text for w in RATE_WORDS):
            raise SourceError("HTTP 429: quota used up on this key", kind="quota")
        raise SourceError("HTTP 429: rate limited", kind="rate_limit", retry_after=_retry_after(resp))
    if code >= 400:
        raise SourceError(f"HTTP {code}")
    try:
        return resp.json()
    except ValueError:
        raise SourceError("invalid JSON response") from None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _hit(source: str, host: Optional[str] = None, ip: Optional[str] = None, port: Any = None, url: Optional[str] = None,
         title: str = "", time: str = "", **extra) -> Dict[str, Any]:
    host = normalize_host(host) if host else None
    if host and _is_ip(host):
        ip, host = ip or host, None
    try:
        port = int(port) if port not in (None, "") else None
    except (TypeError, ValueError):
        port = None
    return {"host": host or None, "ip": ip or None, "port": port, "url": url, "title": (title or "")[:200],
            "time": time or "", "source": source, "extra": extra}


# ============================================================== URLScan
def urlscan_free_safe(query: str) -> str:
    """
    Free URLScan plans reject leading wildcards and `*.keyword` substring fields (HTTP 403 "plan does not allow").
    In free mode every query is rewritten to the prefix form they accept: page.domain.keyword:*x* -> page.domain:x*.
    """
    if not config.free_only():
        return query
    q = re.sub(r"\.keyword:\s*\*", ":", query)
    q = re.sub(r"\.keyword:", ":", q)
    return re.sub(r":\s*\*+(?=[A-Za-z0-9])", ":", q)


def urlscan_search(query: str, size: int = 100) -> List[Dict[str, Any]]:
    """URLScan search API. Works without a key (rate-limited)."""
    query = urlscan_free_safe(query)

    def call(key: Optional[str]):
        return _get("https://urlscan.io/api/v1/search/", {"q": query, "size": min(size, 100 if not key else 1000)},
                    headers={"API-Key": key} if key else None)

    data = with_rotation("urlscan", call, anonymous=lambda: call(None))
    hits = []
    for r in data.get("results", []) or []:
        page, task = r.get("page") or {}, r.get("task") or {}
        hits.append(_hit(
            "urlscan", host=page.get("domain") or task.get("domain"), ip=page.get("ip"), url=page.get("url") or task.get("url"),
            title=page.get("title", ""), time=task.get("time", ""), result=r.get("result"), screenshot=r.get("screenshot"),
            asn=page.get("asnname"), country=page.get("country"), domain_age_days=page.get("apexDomainAgeDays"),
            scan_source=task.get("source"),
        ))
    return hits


def urlscan_total(query: str) -> int:
    """How many URLScan scans match a query (the API reports the total; exact up to 10,000)."""
    def call(key: Optional[str]) -> int:
        data = _get("https://urlscan.io/api/v1/search/", {"q": query, "size": 1}, headers={"API-Key": key} if key else None)
        return int(data.get("total") or 0)

    return with_rotation("urlscan", call, anonymous=lambda: call(None))


# ============================================================== Shodan
def shodan_search(query: str, size: int = 100) -> List[Dict[str, Any]]:
    data = with_rotation("shodan", lambda key: _get("https://api.shodan.io/shodan/host/search",
                                                    {"key": key, "query": query, "minify": "true"}))
    hits = []
    for m in (data.get("matches") or [])[:size]:
        http = m.get("http") or {}
        hostnames = m.get("hostnames") or []
        hits.append(_hit("shodan", host=hostnames[0] if hostnames else None, ip=m.get("ip_str"), port=m.get("port"),
                         title=http.get("title") or "", time=m.get("timestamp", ""), org=m.get("org"),
                         all_hostnames=hostnames[:10], country=(m.get("location") or {}).get("country_code")))
    return hits


# ============================================================== FOFA
FOFA_FIELDS = ["host", "ip", "port", "domain", "title", "lastupdatetime"]

# FOFA errors are often in Chinese; translate by keyword (codes vary between API versions).
# Each hint also says whether the next key should be tried.
FOFA_ERROR_HINTS = (
    ("无效", "invalid key or account"),                       # 无效
    ("余额不足", "not enough F-points / credit"),     # 余额不足
    ("不足", "insufficient quota or F-points"),               # 不足
    ("权限", "your FOFA plan does not allow this query"),     # 权限
    ("频繁", "rate limited, try again later"),                # 频繁
    ("语法", "query syntax error"),                           # 语法
)


FOFA_ERROR_KINDS = {"invalid key or account": "auth", "not enough F-points / credit": "quota",
                    "insufficient quota or F-points": "quota", "your FOFA plan does not allow this query": "forbidden",
                    "rate limited, try again later": "rate_limit"}


def fofa_error_text(msg: str) -> str:
    code = re.match(r"\s*\[(-?\d+)\]", msg)
    for needle, text in FOFA_ERROR_HINTS:
        if needle in msg:
            return f"{text}" + (f" (code {code.group(1)})" if code else "")
    return msg[:120]


def fofa_error(msg: str) -> SourceError:
    text = fofa_error_text(msg)
    kind = next((k for t, k in FOFA_ERROR_KINDS.items() if text.startswith(t)), "other")
    return SourceError(f"FOFA: {text}", kind=kind)


_FOFA_PACE_LOCK = threading.Lock()
_LAST_FOFA_AT = 0.0


def fofa_search(query: str, size: int = 100) -> List[Dict[str, Any]]:
    def call(key: str):
        global _LAST_FOFA_AT
        # Pace free/personal FOFA keys so parallel hunt queries don't trigger per-second rate-limit cooldowns.
        with _FOFA_PACE_LOCK:
            wait = 1.05 - (time.monotonic() - _LAST_FOFA_AT)
            if wait > 0:
                time.sleep(wait)
            _LAST_FOFA_AT = time.monotonic()
        params = {"key": key, "qbase64": base64.b64encode(query.encode("utf-8")).decode("ascii"),
                  "fields": ",".join(FOFA_FIELDS), "size": size, "page": 1}
        email = config.get("FOFA_EMAIL")
        if email:
            params["email"] = email
        data = _get("https://fofa.info/api/v1/search/all", params)
        if data.get("error"):
            raise fofa_error(str(data.get("errmsg") or "query rejected"))
        return data

    data = with_rotation("fofa", call)
    hits = []
    for row in data.get("results", []) or []:
        rec = dict(zip(FOFA_FIELDS, row if isinstance(row, list) else [row]))
        raw_host = rec.get("host") or ""
        host = urlparse(raw_host if "://" in raw_host else f"//{raw_host}").hostname or rec.get("domain")
        hits.append(_hit("fofa", host=host, ip=rec.get("ip"), port=rec.get("port"), title=rec.get("title", ""),
                         time=rec.get("lastupdatetime", ""), url=raw_host if "://" in raw_host else None))
    return hits


# ============================================================== Censys Platform
def _walk(obj: Any, found: Dict[str, set]) -> None:
    """Collects hostnames / IPs / titles from any Censys resource shape."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                if k in ("hostname", "name") and "." in v and " " not in v:
                    found["hosts"].add(v)
                elif k == "ip":
                    found["ips"].add(v)
                elif k == "html_title" and v:
                    found["titles"].add(v)
            elif isinstance(v, list) and k in ("names", "dns_names"):
                found["hosts"].update(x for x in v if isinstance(x, str) and "." in x)
            else:
                _walk(v, found)
    elif isinstance(obj, list):
        for v in obj[:200]:
            _walk(v, found)


def censys_search(query: str, size: int = 100) -> List[Dict[str, Any]]:
    params = {}
    org = config.get("CENSYS_ORG_ID")
    if org:
        params["organization_id"] = org
    data = with_rotation("censys", lambda token: _post(
        "https://api.platform.censys.io/v3/global/search/query", {"query": query, "page_size": min(size, 100)},
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}, params=params))
    result = data.get("result") or {}
    hits = []
    for h in result.get("hits") or []:
        found = {"hosts": set(), "ips": set(), "titles": set()}
        _walk(h, found)
        title = next(iter(found["titles"]), "")
        ips = sorted(found["ips"])
        hosts = sorted(n.lstrip("*.").lower() for n in found["hosts"])
        if hosts:
            for n in hosts[:5]:
                hits.append(_hit("censys", host=n, ip=ips[0] if ips else None, title=title))
        elif ips:
            hits.append(_hit("censys", ip=ips[0], title=title))
    return hits


# ============================================================== Google Lens via SerpApi
def serpapi_lens(image_url: str, size: int = 60) -> List[Dict[str, Any]]:
    """Reverse image search of a public image URL. Returns pages showing a visually matching image."""
    def call(key: str):
        data = _get("https://serpapi.com/search.json", {"engine": "google_lens", "url": image_url, "api_key": key}, timeout=60)
        if data.get("error"):
            err = str(data["error"])
            kind = "quota" if any(w in err.lower() for w in QUOTA_WORDS) else ("auth" if "invalid api key" in err.lower() else "other")
            raise SourceError(f"SerpApi: {err[:120]}", kind=kind)
        return data

    data = with_rotation("serpapi", call)
    hits = []
    for section in ("exact_matches", "visual_matches"):
        for m in data.get(section) or []:
            link = m.get("link") or ""
            host = urlparse(link).hostname
            if host:
                hits.append(_hit("google-lens", host=host, url=link, title=m.get("title", ""),
                                 lens_section=section, image_source=m.get("source")))
            if len(hits) >= size:
                return hits
    return hits


# ============================================================== WhoisXML
WHOISXML_BRAND_ALERT_URL = "https://brand-alert.whoisxmlapi.com/api/v2"
WHOISXML_DISCOVERY_URL = "https://domains-subdomains-discovery.whoisxmlapi.com/api/v2"
WHOISXML_BALANCE_URL = "https://user.whoisxmlapi.com/user-service/account-balance"


def _whoisxml_since(days: int = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=max(1, min(14, int(days))))).strftime("%Y-%m-%d")


def _whoisxml_check_payload(data: Any) -> Any:
    """Translates WhoisXML JSON error shapes into classified SourceError without leaking keys."""
    if not isinstance(data, dict):
        return data
    err_obj = data.get("ErrorMessage")
    msg = ""
    code = data.get("code")
    if isinstance(err_obj, dict):
        msg = str(err_obj.get("msg") or "")
        code = code or err_obj.get("errorCode")
    elif data.get("messages"):
        msg = str(data["messages"])
    if msg:
        msg = re.sub(r"\bat_[A-Za-z0-9_-]{6,}\b", "[redacted]", msg)
        low = msg.lower()
        if any(w in low for w in ("apikey", "authenticate", "invalid key", "authorization", "missing api")):
            raise SourceError(f"WhoisXML: {msg[:120]}", kind="auth")
        if any(w in low for w in QUOTA_WORDS) or "balance" in low:
            raise SourceError(f"WhoisXML: {msg[:120]}", kind="quota")
        if "access" in low or "subscription" in low or "allowed" in low or code == 403:
            raise SourceError(f"WhoisXML: {msg[:120]}", kind="forbidden")
        if any(w in low for w in RATE_WORDS) or code == 429:
            raise SourceError(f"WhoisXML: {msg[:120]}", kind="rate_limit")
        raise SourceError(f"WhoisXML: {msg[:120]}")
    return data


def _whoisxml_post(url: str, body: Dict[str, Any]) -> Any:
    data = _post(url, body, {"Content-Type": "application/json", "Accept": "application/json"})
    return _whoisxml_check_payload(data)


def _whoisxml_parse_brand_hits(data: Dict[str, Any], default_date: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for item in data.get("domainsList") or []:
        if isinstance(item, dict):
            dom = item.get("domainName") or item.get("domain") or ""
            dt = str(item.get("date") or item.get("createdDate") or default_date or "")
            action = str(item.get("action") or "")
            registrar = item.get("registrar") or ""
        else:
            dom, dt, action, registrar = str(item or ""), default_date, "", ""
        if dom:
            hits.append(_hit(
                "whoisxml",
                host=dom,
                time=dt,
                action=action,
                registrar=registrar,
                endpoint="brand_alert",
            ))
    return hits


def _whoisxml_parse_discovery_hits(data: Dict[str, Any], default_date: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for item in data.get("domainsList") or []:
        if isinstance(item, dict):
            dom = item.get("domainName") or item.get("domain") or ""
            dt = str(item.get("date") or default_date or "")
        else:
            dom, dt = str(item or ""), default_date
        if dom:
            hits.append(_hit("whoisxml", host=dom, time=dt, endpoint="domain_discovery"))
    return hits


def _whoisxml_parse_spec(query: str) -> Dict[str, Any]:
    raw = (query or "").strip()
    if raw.startswith("{"):
        try:
            spec = json.loads(raw)
            if isinstance(spec, dict):
                return spec
        except ValueError:
            pass
    mode = "both"
    term = raw
    for prefix, m in (("brand_alert:", "brand_alert"), ("domain_discovery:", "domain_discovery")):
        if raw.lower().startswith(prefix):
            mode = m
            term = raw[len(prefix):].strip()
            break
    terms = [t.strip() for t in re.split(r"[,;\s]+", term) if t.strip() and not t.strip().startswith("since:")]
    since = _whoisxml_since(1)
    m_since = re.search(r"\bsince:(\d{4}-\d{2}-\d{2})\b", raw)
    if m_since:
        since = m_since.group(1)
    return {"mode": mode, "terms": terms[:3], "since_date": since, "with_typos": True, "exclude": []}


def _call_brand_alert(
    key: str,
    terms: List[str],
    since: str,
    with_typos: bool,
    excl: List[str],
    size: int,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    for term in terms:
        body: Dict[str, Any] = {
            "apiKey": key,
            "includeSearchTerms": [term],
            "sinceDate": since,
            "mode": "purchase",
            "withTypos": bool(with_typos),
            "punycode": True,
            "responseFormat": "json",
        }
        if excl:
            body["excludeSearchTerms"] = excl
        for h in _whoisxml_parse_brand_hits(_whoisxml_post(WHOISXML_BRAND_ALERT_URL, body), default_date=since):
            k = (h.get("host"), h["extra"].get("action"))
            if h.get("host") and k not in seen:
                seen.add(k)
                out.append(h)
            if len(out) >= size:
                return out
    return out


def _call_domain_discovery(
    key: str,
    terms: List[str],
    since: str,
    excl: List[str],
    size: int,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    for term in terms:
        dom_filter: Dict[str, Any] = {"include": [term]}
        if excl:
            dom_filter["exclude"] = excl
        body: Dict[str, Any] = {
            "apiKey": key,
            "domains": dom_filter,
            "sinceDate": since,
            "outputFormat": "JSON",
        }
        for h in _whoisxml_parse_discovery_hits(_whoisxml_post(WHOISXML_DISCOVERY_URL, body), default_date=since):
            if h.get("host") and h["host"] not in seen:
                seen.add(h["host"])
                out.append(h)
            if len(out) >= size:
                return out
    return out


def whoisxml_search(query: str, size: int = 500) -> List[Dict[str, Any]]:
    """
    Unified WhoisXML search entrypoint used by SEARCHERS and build_intel_plan.
    Runs Brand Alert v2 and/or Domains & Subdomains Discovery v2 using one key rotation pass
    so single-product subscriptions succeed even if the other endpoint returns 403/forbidden.
    """
    spec = _whoisxml_parse_spec(query)
    terms = [t for t in (spec.get("terms") or []) if t and len(str(t).strip()) >= 3][:3]
    if not terms:
        return []
    mode = spec.get("mode") or "both"
    since = spec.get("since_date") or _whoisxml_since(1)
    with_typos = bool(spec.get("with_typos", True))
    excl = [x for x in (spec.get("exclude") or []) if x][:4]

    def run_both(key: str) -> List[Dict[str, Any]]:
        endpoints = ("brand_alert", "domain_discovery") if mode == "both" else (mode,)
        hits: List[Dict[str, Any]] = []
        seen = set()
        last_err: Optional[SourceError] = None
        any_ok = False
        for ep in endpoints:
            try:
                batch = (
                    _call_brand_alert(key, terms, since, with_typos, excl, size)
                    if ep == "brand_alert"
                    else _call_domain_discovery(key, terms, since, excl, size)
                )
                any_ok = True
                for h in batch:
                    if h.get("host") and h["host"] not in seen:
                        seen.add(h["host"])
                        hits.append(h)
                    if len(hits) >= size:
                        return hits
            except SourceError as e:
                last_err = e
                if e.kind == "auth":
                    raise
        if not any_ok and last_err is not None:
            raise last_err
        return hits

    return with_rotation("whoisxml", run_both)


# ============================================================== VirusTotal (optional API key)
def _vt_hit_from_obj(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = item.get("type")
    attr = item.get("attributes") or {}
    item_id = item.get("id") or ""
    host = None
    url = None
    if kind == "domain":
        host = normalize_host(item_id)
        url = f"https://www.virustotal.com/gui/domain/{host}"
    elif kind == "url":
        raw_url = attr.get("url") or ""
        url = raw_url
        host = normalize_host(urlparse(raw_url).hostname or "")
    if not host:
        return None
    stats = attr.get("last_analysis_stats") or {}
    mal = int(stats.get("malicious") or 0)
    susp = int(stats.get("suspicious") or 0)
    title = attr.get("title") or (f"VT flagged ({mal} malicious, {susp} suspicious)" if (mal or susp) else "")
    ts = attr.get("creation_date") or attr.get("last_analysis_date") or ""
    if isinstance(ts, (int, float)) and ts > 0:
        ts = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
    return {
        "host": host, "ip": None, "port": None, "url": url,
        "title": str(title), "time": str(ts), "source": "virustotal",
        "malicious_votes": mal, "suspicious_votes": susp,
    }


def virustotal_search(query: str, size: int = 40) -> List[Dict[str, Any]]:
    """
    Search VirusTotal v3 (requires VIRUSTOTAL_API_KEY).
    Supports both explicit `domain:<root>` lookups (+ subdomains) and general keyword/domain searches.
    """
    q = (query or "").strip()
    if not q:
        return []

    def run(key: str) -> List[Dict[str, Any]]:
        hdrs = {"x-apikey": key, "Accept": "application/json"}
        hits: List[Dict[str, Any]] = []
        seen: set = set()
        if q.lower().startswith("domain:") and " " not in q:
            dom = normalize_host(q.split(":", 1)[1])
            if not dom:
                return []
            dom_data = _get(f"https://www.virustotal.com/api/v3/domains/{dom}", {}, headers=hdrs, timeout=TIMEOUT)
            obj = (dom_data or {}).get("data")
            if isinstance(obj, dict):
                h = _vt_hit_from_obj(obj)
                if h and h["host"] not in seen:
                    seen.add(h["host"])
                    hits.append(h)
            try:
                sub_data = _get(
                    f"https://www.virustotal.com/api/v3/domains/{dom}/subdomains",
                    {"limit": min(size, 40)}, headers=hdrs, timeout=TIMEOUT,
                )
                for sub_obj in (sub_data or {}).get("data") or []:
                    h = _vt_hit_from_obj(sub_obj)
                    if h and h["host"] not in seen:
                        seen.add(h["host"])
                        hits.append(h)
            except SourceError:
                pass
            return hits

        data = _get("https://www.virustotal.com/api/v3/search", {"query": q, "limit": min(size, 40)}, headers=hdrs, timeout=TIMEOUT)
        for obj in (data or {}).get("data") or []:
            h = _vt_hit_from_obj(obj)
            if h and h["host"] not in seen:
                seen.add(h["host"])
                hits.append(h)
        return hits

    return with_rotation("virustotal", run)


# ============================================================== Free Web Search & Archives
_FREE_CACHE_LOCK = threading.Lock()
_FREE_CACHE: Dict[Tuple[str, str], Tuple[float, Any]] = {}
_FREE_CACHE_TTL = 300.0


def _cache_get(bucket: str, key: str) -> Optional[Any]:
    now = time.monotonic()
    with _FREE_CACHE_LOCK:
        entry = _FREE_CACHE.get((bucket, key))
        if entry and now - entry[0] < _FREE_CACHE_TTL:
            return entry[1]
    return None


_FREE_CACHE_MAX = 5000


def _cache_set(bucket: str, key: str, value: Any) -> Any:
    with _FREE_CACHE_LOCK:
        _FREE_CACHE.pop((bucket, key), None)  # re-insert so the dict stays ordered oldest -> newest
        if len(_FREE_CACHE) >= _FREE_CACHE_MAX:
            # evict the oldest tenth instead of wiping everything: a 300-host Safe Browsing batch must not
            # flush the VirusTotal / OTX / search answers that are still fresh
            for k in list(_FREE_CACHE)[: _FREE_CACHE_MAX // 10]:
                del _FREE_CACHE[k]
        _FREE_CACHE[(bucket, key)] = (time.monotonic(), value)
    return value


def _extract_ddg_href(href: str) -> str:
    if not href:
        return ""
    if href.startswith("//"):
        href = "https:" + href
    parsed = urlparse(href)
    if "duckduckgo.com" in (parsed.netloc or "") and parsed.path.startswith("/l/"):
        qs = parse_qs(parsed.query)
        if qs.get("uddg"):
            return unquote(qs["uddg"][0])
    return href


def _has_challenge(resp: requests.Response) -> bool:
    if resp.status_code in (202, 403, 429):
        return True
    low = (resp.text or "")[:8000].lower()
    return any(m in low for m in ("anomaly-modal", "captcha", "verify you are human", "challenge-form"))


_BING_NOISE_HOSTS = {"bing.com", "msn.com"}


def _unwrap_bing_href(href: str) -> str:
    """Decode Bing `/ck/a` click-tracking redirect URLs back to their target URL."""
    link = (href or "").strip()
    if not link:
        return ""
    parsed = urlparse(link)
    host = normalize_host(parsed.hostname or "")
    if (host == "bing.com" or host.endswith(".bing.com")) and parsed.path.startswith("/ck/"):
        u = (parse_qs(parsed.query).get("u") or [""])[0]
        if u.startswith("a1") and len(u) > 2:
            raw = u[2:]
            try:
                decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "ignore").strip()
            except Exception:
                return ""
            if decoded.startswith(("http://", "https://")):
                return decoded
        return ""
    return link


def _bing_site_constraints(query: str) -> Tuple[set, set]:
    """
    Bing RSS often ignores `-site:` and `site:` operators when falling back to organic results.
    Return `(excluded_sites, required_sites)` so `bing_search` can enforce them client-side.
    """
    excluded = {
        s for s in (
            normalize_host(raw.strip("*."))
            for raw in re.findall(r"(?:^|[\s\(])-site:([^\s\)]+)", query, re.I)
        ) if s
    }
    q_pos = re.sub(r"(?:^|[\s\(])-site:[^\s\)]+", " ", query, flags=re.I)
    pos = {
        s for s in (
            normalize_host(raw.strip("*."))
            for raw in re.findall(r"(?<![-\w])site:([^\s\)]+)", q_pos, re.I)
        ) if s
    }
    if not pos:
        return excluded, set()

    def _strip_pure_site_group(m: re.Match) -> str:
        branches = [b.strip() for b in re.split(r"\s+OR\s+", m.group(1), flags=re.I) if b.strip()]
        if branches and all(re.match(r"^site:[^\s\)]+$", b, re.I) for b in branches):
            return " "
        return m.group(0)

    rem = re.sub(r"\(([^()]+)\)", _strip_pure_site_group, q_pos)
    rem = re.sub(r"(?<![-\w])site:[^\s\)]+", " ", rem, flags=re.I)
    return excluded, (set() if re.search(r"\bOR\b", rem) else pos)


def _host_matches_any(host: str, roots: set) -> bool:
    return any(host == r or host.endswith("." + r) for r in roots)


def bing_search(query: str, size: int = 30) -> List[Dict[str, Any]]:
    """
    Free automated web dork discovery via Bing's public XML RSS feed (no API key required).
    Enforces `-site:` exclusions and pure `site:` filters client-side because Bing RSS
    frequently ignores advanced operators.
    """
    q = (query or "").strip()
    if not q:
        return []
    cached = _cache_get("bing", q)
    if cached is not None:
        return cached
    try:
        resp = requests.get(
            "https://www.bing.com/search",
            params={"q": q, "format": "rss", "count": min(max(size, 10), 50)},
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"},
            timeout=15,
        )
    except requests.RequestException as e:
        raise SourceError(f"bing network error ({e.__class__.__name__})") from None
    if resp.status_code >= 400:
        raise SourceError(f"bing HTTP {resp.status_code}")

    excluded_sites, required_sites = _bing_site_constraints(q)
    hits: List[Dict[str, Any]] = []
    seen_hosts: set = set()
    try:
        root = ET.fromstring(resp.text)
        items = root.findall(".//item")
    except ET.ParseError:
        items = []

    for item in items:
        title = (item.findtext("title") or "").strip()
        link = _unwrap_bing_href(item.findtext("link") or "")
        if not link:
            continue
        host = normalize_host(urlparse(link).hostname or "")
        if not host or host in seen_hosts or _host_matches_any(host, _BING_NOISE_HOSTS):
            continue
        if excluded_sites and _host_matches_any(host, excluded_sites):
            continue
        if required_sites and not _host_matches_any(host, required_sites):
            continue
        seen_hosts.add(host)
        hits.append({"host": host, "ip": None, "port": None, "url": link, "title": title, "time": "", "source": "bing"})
        if len(hits) >= size:
            break
    return _cache_set("bing", q, hits)


def duckduckgo_search(query: str, size: int = 25) -> List[Dict[str, Any]]:
    """
    Free DuckDuckGo search discovery.
    Respects anti-bot challenges strictly (never bypasses CAPTCHA/anomaly gates); falls back cleanly
    to DuckDuckGo's public Instant Answer JSON API when HTML is rate/challenge gated.
    """
    q = (query or "").strip()
    if not q:
        return []
    cached = _cache_get("duckduckgo", q)
    if cached is not None:
        return cached

    hits: List[Dict[str, Any]] = []
    seen_hosts: set = set()
    browser_ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"}
    challenged = False
    try:
        resp = requests.get("https://html.duckduckgo.com/html/", params={"q": q}, headers=browser_ua, timeout=12)
        if _has_challenge(resp):
            challenged = True
        elif resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.select("a.result__a, a.result-link"):
                href = _extract_ddg_href(a.get("href") or "")
                host = normalize_host(urlparse(href).hostname or "")
                if not host or host in seen_hosts:
                    continue
                seen_hosts.add(host)
                hits.append({
                    "host": host, "ip": None, "port": None, "url": href,
                    "title": a.get_text(" ", strip=True), "time": "", "source": "duckduckgo",
                })
                if len(hits) >= size:
                    break
    except requests.RequestException:
        pass

    # Official zero-auth Instant Answer API as non-challenged entity supplement
    if not hits:
        try:
            ia = requests.get(
                "https://api.duckduckgo.com/",
                params={"q": q.split(" -site:")[0].strip(), "format": "json", "no_redirect": 1},
                headers=UA, timeout=10,
            )
            if ia.status_code == 200:
                data = ia.json()
                urls = [data.get("AbstractURL")]
                for bucket in (data.get("Results") or [], data.get("RelatedTopics") or []):
                    for item in bucket:
                        if isinstance(item, dict) and item.get("FirstURL"):
                            urls.append(item["FirstURL"])
                for u in urls:
                    if not u:
                        continue
                    host = normalize_host(urlparse(u).hostname or "")
                    if host and host not in seen_hosts and "duckduckgo.com" not in host:
                        seen_hosts.add(host)
                        hits.append({"host": host, "ip": None, "port": None, "url": u, "title": data.get("Heading") or "", "time": "", "source": "duckduckgo"})
        except Exception:
            pass

    if challenged and not hits:
        raise SourceError("DuckDuckGo HTML search challenged (skipping cleanly; Bing RSS / URLScan still active)", kind="rate")
    return _cache_set("duckduckgo", q, hits)


def wayback_search(query: str, size: int = 40) -> List[Dict[str, Any]]:
    """
    Free historical & free-hosting clone discovery via Internet Archive Wayback Machine CDX API.
    `query` should be a URL pattern like `*.workers.dev/*brand*` or `*brand*`.
    """
    pat = (query or "").strip()
    if not pat:
        return []
    cached = _cache_get("wayback", pat)
    if cached is not None:
        return cached
    try:
        resp = requests.get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": pat, "output": "json", "fl": "original,timestamp,statuscode", "collapse": "urlkey", "limit": min(size, 60)},
            headers=UA, timeout=15,
        )
    except requests.RequestException as e:
        raise SourceError(f"wayback network error ({e.__class__.__name__})") from None
    if resp.status_code >= 400:
        raise SourceError(f"wayback HTTP {resp.status_code}")
    try:
        rows = resp.json()
    except ValueError:
        rows = []

    hits: List[Dict[str, Any]] = []
    seen: set = set()
    for row in rows[1:] if isinstance(rows, list) and len(rows) > 1 else []:
        if not isinstance(row, list) or not row:
            continue
        orig = str(row[0] or "")
        ts = str(row[1] or "")[:8]
        host = normalize_host(urlparse(orig).hostname or "")
        if not host or host in seen:
            continue
        seen.add(host)
        date_fmt = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) == 8 else ts
        hits.append({"host": host, "ip": None, "port": None, "url": orig, "title": "", "time": date_fmt, "source": "wayback"})
    return _cache_set("wayback", pat, hits)


def hackertarget_reverse_ip(ip: str, limit: int = 40) -> List[str]:
    """
    Free reverse-IP lookup via HackerTarget (no key needed up to daily quota).
    Used for automatic Step-7 attacker cluster pivoting on shared infrastructure.
    """
    ip = (ip or "").strip()
    if not ip:
        return []
    cached = _cache_get("ht_revip", ip)
    if cached is not None:
        return cached
    try:
        resp = requests.get("https://api.hackertarget.com/reverseiplookup/", params={"q": ip}, headers=UA, timeout=10)
    except requests.RequestException as e:
        raise SourceError(f"hackertarget network error ({e.__class__.__name__})") from None
    if resp.status_code >= 400:
        raise SourceError(f"hackertarget HTTP {resp.status_code}")
    text = (resp.text or "").strip()
    if not text or any(err in text.lower() for err in ("error check", "api count exceeded", "no dns a records")):
        if "api count exceeded" in text.lower():
            raise SourceError("HackerTarget daily free limit reached", kind="rate")
        return _cache_set("ht_revip", ip, [])
    hosts: List[str] = []
    for line in text.splitlines():
        h = normalize_host(line.strip())
        if h and "." in h and h not in hosts:
            hosts.append(h)
        if len(hosts) >= limit:
            break
    return _cache_set("ht_revip", ip, hosts)


def hackertarget_shared_dns(nameserver: str, limit: int = 80) -> List[str]:
    """Domains using the same name server (HackerTarget free API, shares the reverse-IP daily quota)."""
    ns = normalize_host(nameserver)
    if not ns:
        return []
    cached = _cache_get("ht_shareddns", ns)
    if cached is not None:
        return cached
    try:
        resp = requests.get("https://api.hackertarget.com/findshareddns/", params={"q": ns}, headers=UA, timeout=12)
    except requests.RequestException as e:
        raise SourceError(f"hackertarget network error ({e.__class__.__name__})") from None
    if resp.status_code >= 400:
        raise SourceError(f"hackertarget HTTP {resp.status_code}")
    text = (resp.text or "").strip()
    if "api count exceeded" in text.lower():
        raise SourceError("HackerTarget daily free limit reached", kind="rate")
    if not text or text.lower().startswith(("error", "no records", "no results")):
        return _cache_set("ht_shareddns", ns, [])
    hosts: List[str] = []
    for line in text.splitlines():
        h = normalize_host(line.strip())
        if h and "." in h and h not in hosts:
            hosts.append(h)
        if len(hosts) >= limit:
            break
    return _cache_set("ht_shareddns", ns, hosts)


def virustotal_reputation(host: str) -> Optional[Dict[str, Any]]:
    """
    VirusTotal verdict for ONE host (GET /domains/{host}: available on the free API tier, unlike VT Intelligence
    search). Returns {"host", "malicious_votes", "suspicious_votes", "url", "categories"} or None when VT has
    never seen the host. Results are cached for the session window; rate limits / auth errors raise SourceError.
    """
    h = normalize_host(host)
    if not h or _is_ip(h) or not config.is_configured("virustotal"):
        return None
    cached = _cache_get("vt_rep", h)
    if cached is not None:
        return cached or None

    def run(key: str) -> Any:
        return _get(f"https://www.virustotal.com/api/v3/domains/{h}", {}, headers={"x-apikey": key, "Accept": "application/json"})

    try:
        data = with_rotation("virustotal", run)
    except SourceError as e:
        if str(e).startswith("HTTP 404"):
            _cache_set("vt_rep", h, {})  # unknown to VT: remember so it is not asked again
            return None
        raise
    obj = (data or {}).get("data")
    hit = _vt_hit_from_obj(obj) if isinstance(obj, dict) else None
    if not hit:
        _cache_set("vt_rep", h, {})
        return None
    cats = (obj.get("attributes") or {}).get("categories") or {}
    hit["categories"] = sorted({str(v) for v in cats.values()})[:6] if isinstance(cats, dict) else []
    return _cache_set("vt_rep", h, hit)


# ============================================================== Google Safe Browsing (optional key)
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_SB_THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
_SB_HOSTS_PER_CALL = 250  # two URLs (http + https) per host; the API takes 500 entries per request


def _sb_body(urls: List[str]) -> Dict[str, Any]:
    # Generic client id: the request must not identify the analyst or their organisation.
    return {"client": {"clientId": "brand-protection-scanner", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": _SB_THREATS, "platformTypes": ["ANY_PLATFORM"],
                           "threatEntryTypes": ["URL"], "threatEntries": [{"url": u} for u in urls]}}


def safebrowsing_lookup(hosts: List[str]) -> Dict[str, List[str]]:
    """
    {host: [threat types]} for the hosts Google Safe Browsing currently lists (Lookup API v4, batched: 250 hosts
    per request). Clean answers are cached too, so re-hunting the same brand costs nothing. Note Google's terms:
    the Lookup API is for non-commercial use; commercial deployments should use Google Web Risk instead.
    """
    if not config.is_configured("safebrowsing"):
        return {}
    todo: List[str] = []
    out: Dict[str, List[str]] = {}
    for h in dict.fromkeys(normalize_host(x) for x in hosts if x):
        if not h or _is_ip(h):
            continue
        cached = _cache_get("gsb", h)
        if cached is None:
            todo.append(h)
        elif cached:
            out[h] = cached
    for i in range(0, len(todo), _SB_HOSTS_PER_CALL):
        chunk = todo[i:i + _SB_HOSTS_PER_CALL]
        body = _sb_body([f"{scheme}://{h}/" for h in chunk for scheme in ("http", "https")])
        data = with_rotation("safebrowsing", lambda key: _post(SAFE_BROWSING_URL, body, {"Content-Type": "application/json"}, params={"key": key}))
        found: Dict[str, set] = {}
        for m in (data or {}).get("matches") or []:
            host = normalize_host(urlparse((m.get("threat") or {}).get("url") or "").hostname or "")
            if host:
                found.setdefault(host, set()).add(str(m.get("threatType") or "UNKNOWN"))
        for h in chunk:
            types = sorted(found.get(h, ()))
            _cache_set("gsb", h, types)
            if types:
                out[h] = types
    return out


# ============================================================== AlienVault OTX passive DNS (free; key optional)
def otx_passive_dns(domain: str, limit: int = 500) -> List[Dict[str, Any]]:
    """
    Hostnames passive DNS has seen under a domain: [{"hostname", "address", "record_type", "first", "last"}].
    Works anonymously (rate-limited); OTX_API_KEY raises the limits. Cached for the session window.
    """
    dom = normalize_host(domain)
    if not dom or "." not in dom:
        return []
    cached = _cache_get("otx_pdns", dom)
    if cached is not None:
        return cached

    def call(key: Optional[str]) -> Any:
        return _get(f"https://otx.alienvault.com/api/v1/indicators/domain/{dom}/passive_dns", {},
                    headers={"X-OTX-API-KEY": key} if key else None, timeout=20)

    data = with_rotation("otx", call, anonymous=lambda: call(None))
    rows: Dict[str, Dict[str, Any]] = {}
    for r in (data or {}).get("passive_dns") or []:
        host = normalize_host(str(r.get("hostname") or "").lstrip("*."))
        if not host or "." not in host or host in rows:
            continue
        rows[host] = {"hostname": host, "address": str(r.get("address") or ""), "record_type": str(r.get("record_type") or ""),
                      "first": str(r.get("first") or "")[:10], "last": str(r.get("last") or "")[:10]}
        if len(rows) >= limit:
            break
    return _cache_set("otx_pdns", dom, list(rows.values()))


SEARCHERS = {
    "urlscan": urlscan_search,
    "shodan": shodan_search,
    "fofa": fofa_search,
    "censys": censys_search,
    "whoisxml": whoisxml_search,
    "virustotal": virustotal_search,
    "bing": bing_search,
    "duckduckgo": duckduckgo_search,
    "wayback": wayback_search,
}


# ============================================================== key checks (settings page)
def _status_only(resp: requests.Response) -> Any:
    """Like _json, but also treats 400 (URLScan: malformed key) as a rejected key."""
    if resp.status_code == 400:
        raise SourceError("key rejected (invalid format)", kind="auth")
    return _json(resp)


def check_key(source: str, values: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Verifies credentials with the cheapest call each platform offers (account / quota
    endpoints that use no search credits; Censys has none, so it runs a 1-result search).
    `values` lets the UI test a key before saving it. Never echoes the key back.
    """
    values = values or {}

    def v(name: str) -> Optional[str]:
        return (values.get(name) or "").strip() or config.get(name)

    try:
        if source == "shodan":
            key = v("SHODAN_API_KEY")
            if not key:
                raise SourceError("no key entered")
            resp = requests.get("https://api.shodan.io/api-info", params={"key": key}, headers=UA, timeout=20)
            data = _json(resp)
            plan = data.get("plan") or "unknown plan"
            credits = data.get("query_credits")
            msg = f"Key accepted: {plan} plan" + (f", {credits} query credits left" if credits is not None else "")
            if credits == 0:
                msg += ". Favicon / title filters need query credits (paid membership)"
            return {"ok": True, "message": msg}

        if source == "fofa":
            key = v("FOFA_KEY")
            if not key:
                raise SourceError("no key entered")
            params = {"key": key}
            if v("FOFA_EMAIL"):
                params["email"] = v("FOFA_EMAIL")
            data = _status_only(requests.get("https://fofa.info/api/v1/info/my", params=params, headers=UA, timeout=20))
            if data.get("error"):
                raise fofa_error(str(data.get("errmsg") or "rejected"))
            level = data.get("vip_level")
            return {"ok": True, "message": "Key accepted" + (f": membership level {level}" if level is not None else "")}

        if source == "censys":
            token = v("CENSYS_PAT")
            if not token:
                raise SourceError("no token entered")
            params = {"organization_id": v("CENSYS_ORG_ID")} if v("CENSYS_ORG_ID") else None
            resp = requests.post("https://api.platform.censys.io/v3/global/search/query",
                                 json={"query": 'host.ip: "1.1.1.1"', "page_size": 1}, params=params,
                                 headers={**UA, "Authorization": f"Bearer {token}", "Accept": "application/json"}, timeout=30)
            _json(resp)
            return {"ok": True, "message": "Token accepted (the test used one search query)"}

        if source == "serpapi":
            key = v("SERPAPI_KEY")
            if not key:
                raise SourceError("no key entered")
            data = _json(requests.get("https://serpapi.com/account.json", params={"api_key": key}, headers=UA, timeout=20))
            if data.get("error"):
                raise SourceError(str(data["error"]).split(".")[0][:120])
            left = data.get("total_searches_left", data.get("plan_searches_left"))
            plan = data.get("plan_name")
            return {"ok": True, "message": "Key accepted" + (f": {plan}" if plan else "") + (f", {left} searches left" if left is not None else "")}

        if source == "urlscan":
            key = v("URLSCAN_API_KEY")
            if not key:
                # Anonymous search is allowed: check that URLScan answers at all.
                data = _json(requests.get("https://urlscan.io/api/v1/search/", params={"q": "domain:example.com", "size": 1}, headers=UA, timeout=20))
                return {"ok": True, "message": "No key: anonymous search works (rate-limited, 100 results per query)"}
            _status_only(requests.get("https://urlscan.io/user/quotas/", headers={**UA, "API-Key": key}, timeout=20))
            return {"ok": True, "message": "Key accepted"}

        if source == "whoisxml":
            key = v("WHOISXML_API_KEY")
            if not key:
                raise SourceError("no key entered")
            resp = requests.get(WHOISXML_BALANCE_URL, params={"apiKey": key, "outputFormat": "JSON"}, headers=UA, timeout=20)
            data = _whoisxml_check_payload(_json(resp))
            credits = None
            if isinstance(data, dict):
                if isinstance(data.get("credits"), (int, float)):
                    credits = int(data["credits"])
                elif isinstance(data.get("data"), list) and data["data"]:
                    total = sum(int(item.get("credits") or 0) for item in data["data"] if isinstance(item, dict))
                    credits = total
            msg = "Key accepted" + (f" ({credits:,} total product credits)" if credits is not None else "")
            return {"ok": True, "message": msg}

        if source == "virustotal":
            key = v("VIRUSTOTAL_API_KEY")
            if not key:
                raise SourceError("no key entered")
            resp = requests.get(
                "https://www.virustotal.com/api/v3/search",
                params={"query": "example.com", "limit": 1},
                headers={**UA, "x-apikey": key, "Accept": "application/json"},
                timeout=20,
            )
            _json(resp)
            return {"ok": True, "message": "Key accepted (VirusTotal API v3 ready)"}

        if source == "safebrowsing":
            key = v("GOOGLE_SAFE_BROWSING_KEY")
            if not key:
                raise SourceError("no key entered")
            _json(requests.post(SAFE_BROWSING_URL, json=_sb_body(["http://example.com/"]), params={"key": key},
                                headers={**UA, "Content-Type": "application/json"}, timeout=20))
            return {"ok": True, "message": "Key accepted (Safe Browsing Lookup API v4)"}

        if source == "otx":
            key = v("OTX_API_KEY")
            hdrs = {**UA, "X-OTX-API-KEY": key} if key else UA
            _json(requests.get("https://otx.alienvault.com/api/v1/indicators/domain/example.com/general", headers=hdrs, timeout=20))
            return {"ok": True, "message": "Key accepted" if key else "No key: anonymous passive-DNS lookups work (rate-limited)"}

        raise SourceError("unknown source")
    except SourceError as e:
        return {"ok": False, "message": str(e), "kind": e.kind}
    except requests.RequestException as e:
        return {"ok": False, "message": f"network error ({e.__class__.__name__})", "kind": "other"}
