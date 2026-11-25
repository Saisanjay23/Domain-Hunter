"""
Threat-intel platform clients. Each search returns normalised hits:

    {"host": "adani-login.com" | None, "ip": "1.2.3.4" | None, "port": 443 | None,
     "url": str | None, "title": str, "time": str, "source": "urlscan", "extra": {...}}

Errors never include the request URL (Shodan / FOFA / SerpApi put the key in the query string).
"""

import base64
import ipaddress
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

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
def urlscan_search(query: str, size: int = 100) -> List[Dict[str, Any]]:
    """URLScan search API. Works without a key (rate-limited)."""
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


def fofa_search(query: str, size: int = 100) -> List[Dict[str, Any]]:
    def call(key: str):
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


SEARCHERS = {
    "urlscan": urlscan_search,
    "shodan": shodan_search,
    "fofa": fofa_search,
    "censys": censys_search,
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

        raise SourceError("unknown source")
    except SourceError as e:
        return {"ok": False, "message": str(e), "kind": e.kind}
    except requests.RequestException as e:
        return {"ok": False, "message": f"network error ({e.__class__.__name__})", "kind": "other"}
