"""
Candidate discovery & enrichment sources (no API keys needed):

  resolve_domains()      fast async DNS (A / AAAA / MX / NS) with per-suffix wildcard detection
  crtsh_search()         Certificate Transparency hostnames containing a brand token (crt.sh)
  rdap_lookup()          registration date / registrar / abuse contact via the IANA RDAP bootstrap
  brand_allowlist()      the brand's own domains, taken from its TLS certificate SANs
"""

import asyncio
import logging
import random
import socket
import ssl
import string
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, Set

import requests

from .domains import normalize_host, registrable_domain

logger = logging.getLogger("hunt.discovery")

HTTP_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; brand-protection-scanner/1.0)", "Accept": "application/json"}

# Name servers of domain parking / aftermarket services.
PARKING_NS = (
    "sedoparking.com", "bodis.com", "parkingcrew.net", "above.com", "dan.com", "afternic.com",
    "hugedomains.com", "parklogic.com", "uniregistrymarket.link", "namebrightdns.com", "ztomy.com",
    "dsredirection.com", "trafficz.com", "fabulous.com", "voodoo.com", "parked.com", "domainparking.ru",
    "cashparking.com", "rookdns.com", "undeveloped.com", "brandbucket.com", "squadhelp.com", "atom.com",
    "smartname.com", "torresdns.com", "sav.com",
)


# ============================================================== DNS
def _make_resolver(nameservers: Optional[List[str]], timeout: float):
    import dns.asyncresolver

    try:
        resolver = dns.asyncresolver.Resolver(configure=not nameservers)
    except Exception:
        resolver = dns.asyncresolver.Resolver(configure=False)
        nameservers = nameservers or ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    if nameservers:
        resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    resolver.cache = None
    return resolver


async def _query(resolver, name: str, rtype: str):
    """Returns (status, values). status: ok | nxdomain | noanswer | timeout | error"""
    import dns.exception
    import dns.resolver

    try:
        ans = await resolver.resolve(name, rtype, raise_on_no_answer=False)
        if ans.rrset is None:
            return "noanswer", []
        vals = []
        for r in ans:
            if rtype == "MX":
                vals.append(str(r.exchange).rstrip(".").lower())
            elif rtype in ("NS", "CNAME"):
                vals.append(str(r.target).rstrip(".").lower())
            else:
                vals.append(r.to_text())
        return "ok", vals
    except dns.resolver.NXDOMAIN:
        return "nxdomain", []
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return "noanswer", []
    except dns.exception.Timeout:
        return "timeout", []
    except Exception:
        return "error", []


async def _resolve_one(resolver, name: str, sem: asyncio.Semaphore) -> Dict:
    async with sem:
        status, a = await _query(resolver, name, "A")
        if status == "timeout":
            status, a = await _query(resolver, name, "A")
        info = {"domain": name, "a": a, "aaaa": [], "mx": [], "ns": [], "status": status, "registered": False}
        if status == "nxdomain":
            return info
        if status in ("timeout", "error"):
            info["registered"] = None  # unknown
            return info
        apex = registrable_domain(name) or name
        tasks = [_query(resolver, name, "MX"), _query(resolver, apex, "NS")]
        if not a:
            tasks.append(_query(resolver, name, "AAAA"))
        results = await asyncio.gather(*tasks)
        info["mx"] = results[0][1]
        info["ns"] = results[1][1]
        if not a:
            info["aaaa"] = results[2][1]
        info["registered"] = bool(a or info["aaaa"] or info["mx"] or info["ns"])
        info["status"] = "resolves" if (a or info["aaaa"]) else ("registered" if info["registered"] else "noanswer")
        return info


def _random_label(n: int = 14) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


async def _resolve_all(
    names: List[str],
    concurrency: int,
    timeout: float,
    nameservers: Optional[List[str]],
    progress: Optional[Callable[[int, int], None]],
    cancel: Optional[threading.Event],
) -> Dict[str, Dict]:
    resolver = _make_resolver(nameservers, timeout)
    sem = asyncio.Semaphore(concurrency)

    # Wildcard detection: a random label under each suffix should NOT resolve.
    suffixes = sorted({n.split(".", 1)[1] for n in names if "." in n})
    wildcard_ips: Dict[str, Set[str]] = {}

    async def probe(sfx: str):
        st, ips = await _query(resolver, f"{_random_label()}.{sfx}", "A")
        if st == "ok" and ips:
            wildcard_ips[sfx] = set(ips)

    await asyncio.gather(*(probe(s) for s in suffixes))

    results: Dict[str, Dict] = {}
    done = 0
    tasks = [asyncio.ensure_future(_resolve_one(resolver, n, sem)) for n in names]
    try:
        for fut in asyncio.as_completed(tasks):
            info = await fut
            sfx = info["domain"].split(".", 1)[1] if "." in info["domain"] else ""
            if sfx in wildcard_ips and info["a"] and set(info["a"]) <= wildcard_ips[sfx] and not info["mx"]:
                info.update(status="wildcard", registered=False)
            results[info["domain"]] = info
            done += 1
            if progress and (done % 50 == 0 or done == len(names)):
                progress(done, len(names))
            if cancel is not None and cancel.is_set():
                break
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
    return results


def resolve_domains(
    names: Iterable[str],
    concurrency: int = 150,
    timeout: float = 2.5,
    nameservers: Optional[List[str]] = None,
    progress: Optional[Callable[[int, int], None]] = None,
    cancel: Optional[threading.Event] = None,
) -> Dict[str, Dict]:
    """
    Resolves many hostnames concurrently. Returns {name: info} where info has
    a / aaaa / mx / ns lists, status (resolves | registered | nxdomain | wildcard | timeout | ...)
    and registered (True / False / None when unknown).
    Safe to call from a worker thread (runs its own event loop).
    """
    names = list(dict.fromkeys(normalize_host(n) for n in names if n))
    if not names:
        return {}
    try:
        return asyncio.run(_resolve_all(names, concurrency, timeout, nameservers, progress, cancel))
    except Exception as e:  # pragma: no cover - environment specific (no DNS at all)
        logger.warning(f"Async DNS failed ({e}); falling back to getaddrinfo")
        return _resolve_fallback(names, progress)


def _resolve_fallback(names: List[str], progress=None) -> Dict[str, Dict]:
    from concurrent.futures import ThreadPoolExecutor

    def one(n):
        try:
            ips = sorted({ai[4][0] for ai in socket.getaddrinfo(n, None)})
            return {"domain": n, "a": ips, "aaaa": [], "mx": [], "ns": [], "status": "resolves", "registered": True}
        except socket.gaierror:
            return {"domain": n, "a": [], "aaaa": [], "mx": [], "ns": [], "status": "nxdomain", "registered": False}

    out = {}
    with ThreadPoolExecutor(64) as pool:
        for i, info in enumerate(pool.map(one, names), 1):
            out[info["domain"]] = info
            if progress and (i % 50 == 0 or i == len(names)):
                progress(i, len(names))
    return out


def is_parked_ns(ns_list: List[str]) -> bool:
    return any(ns.endswith(p) or f".{p}" in ns for ns in ns_list for p in PARKING_NS)


# ============================================================== Certificate Transparency
def crtsh_search(token: str, timeout: int = 45, retries: int = 2, max_hosts: int = 1500) -> Dict:
    """
    Hostnames in CT logs whose certificate identity contains the token (crt.sh %token%).
    Returns {"hosts": {host: {"first_seen", "last_seen", "issuer", "certs"}}, "error": str|None}.
    """
    token = (token or "").strip().lower()
    if len(token) < 3:
        return {"hosts": {}, "error": "token too short for CT search"}
    url = "https://crt.sh/"
    # Full history first; the lighter "exclude=expired" variant often succeeds when crt.sh is overloaded.
    variants = [{"q": f"%{token}%", "output": "json"}, {"q": f"%{token}%", "output": "json", "exclude": "expired"}]
    last_err = None
    for attempt in range(retries + 1):
        params = variants[min(attempt, len(variants) - 1)]
        try:
            resp = requests.get(url, params=params, headers=HTTP_HEADERS, timeout=timeout)
            if resp.status_code == 200:
                rows = resp.json()
                break
            last_err = f"crt.sh HTTP {resp.status_code}"
        except ValueError:
            last_err = "crt.sh returned invalid JSON"
        except requests.RequestException as e:
            last_err = f"crt.sh unreachable: {e.__class__.__name__}"
        if attempt < retries:
            time.sleep(3 * (attempt + 1))
    else:
        return {"hosts": {}, "error": f"{last_err} (crt.sh is often overloaded; re-run later for CT results)"}

    hosts: Dict[str, Dict] = {}
    for row in rows:
        names = set()
        for field in ("name_value", "common_name"):
            for n in str(row.get(field) or "").split("\n"):
                n = n.strip().lower().lstrip("*.").rstrip(".")
                if n and "@" not in n and " " not in n and "." in n:
                    names.add(n)
        nb = (row.get("not_before") or "")[:10]
        issuer = row.get("issuer_name") or ""
        org = ""
        for part in issuer.split(","):
            part = part.strip()
            if part.startswith("O="):
                org = part[2:].strip('"')
        for n in names:
            if token not in n.replace("-", "") and token not in n:
                continue
            h = hosts.setdefault(n, {"first_seen": nb, "last_seen": nb, "issuer": org, "certs": 0})
            h["certs"] += 1
            if nb and (not h["first_seen"] or nb < h["first_seen"]):
                h["first_seen"] = nb
            if nb and nb > h["last_seen"]:
                h["last_seen"] = nb
                h["issuer"] = org or h["issuer"]
    if len(hosts) > max_hosts:
        keep = sorted(hosts.items(), key=lambda kv: kv[1]["last_seen"], reverse=True)[:max_hosts]
        hosts = dict(keep)
    return {"hosts": hosts, "error": None}


# ============================================================== RDAP
_BOOTSTRAP: Dict[str, str] = {}
_BOOTSTRAP_LOCK = threading.Lock()


def _rdap_base(tld: str) -> Optional[str]:
    with _BOOTSTRAP_LOCK:
        if not _BOOTSTRAP:
            try:
                data = requests.get("https://data.iana.org/rdap/dns.json", headers=HTTP_HEADERS, timeout=15).json()
                for tlds, urls in data.get("services", []):
                    base = next((u for u in urls if u.startswith("https")), urls[0] if urls else None)
                    for t in tlds:
                        _BOOTSTRAP[t.lower()] = base
                _BOOTSTRAP["__loaded__"] = "1"
            except Exception as e:
                logger.debug(f"RDAP bootstrap failed: {e}")
                _BOOTSTRAP["__loaded__"] = "0"
    return _BOOTSTRAP.get(tld.lower())


def _vcard_value(entity: Dict, key: str) -> Optional[str]:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) > 1:
        for item in vcard[1]:
            if isinstance(item, list) and item and item[0] == key and len(item) > 3:
                return str(item[3])
    return None


def rdap_lookup(domain: str, timeout: int = 10) -> Optional[Dict]:
    """Registration date, registrar and abuse e-mail for a registrable domain (None if unavailable)."""
    domain = registrable_domain(domain) or domain
    tld = domain.rsplit(".", 1)[-1]
    base = _rdap_base(tld)
    if not base:
        return None
    try:
        resp = requests.get(f"{base.rstrip('/')}/domain/{domain}", headers={**HTTP_HEADERS, "Accept": "application/rdap+json"}, timeout=timeout)
        if resp.status_code != 200:
            return None
        data = resp.json()
    except Exception:
        return None

    out: Dict = {"created": None, "expires": None, "updated": None, "registrar": None, "abuse_email": None, "age_days": None}
    for ev in data.get("events", []) or []:
        action, date = ev.get("eventAction"), ev.get("eventDate")
        if action == "registration":
            out["created"] = date
        elif action == "expiration":
            out["expires"] = date
        elif action == "last changed":
            out["updated"] = date

    def walk(entities):
        for ent in entities or []:
            roles = ent.get("roles") or []
            if "registrar" in roles and not out["registrar"]:
                out["registrar"] = _vcard_value(ent, "fn")
            if "abuse" in roles and not out["abuse_email"]:
                out["abuse_email"] = _vcard_value(ent, "email")
            walk(ent.get("entities"))

    walk(data.get("entities"))
    if out["created"]:
        try:
            created = datetime.fromisoformat(out["created"].replace("Z", "+00:00"))
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            out["age_days"] = max(0, (datetime.now(timezone.utc) - created).days)
        except ValueError:
            pass
    return out


# ============================================================== Brand allowlist
def cert_san_domains(host: str, port: int = 443, timeout: int = 8) -> List[str]:
    """DNS names in the TLS certificate presented by host (unverified fetch)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except Exception:
        return []
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return [n.lower().lstrip("*.") for n in san.get_values_for_type(x509.DNSName)]
    except Exception:
        return []


# Shared-hosting / CDN suffixes that must never be allowlisted as "the brand".
_NEVER_ALLOW = {"cloudflaressl.com", "cloudflare.com", "akamaiedge.net", "azurewebsites.net", "herokuapp.com", "wpengine.com"}


def brand_allowlist(domain: str, extra: Optional[Iterable[str]] = None, final_url_host: Optional[str] = None) -> List[str]:
    """
    The brand's own registrable domains: input domain, post-redirect host, certificate SANs
    of the apex and www host, plus anything the analyst adds.
    """
    allow: List[str] = []

    def add(h: Optional[str]):
        r = registrable_domain(h or "")
        if r and r not in allow and r not in _NEVER_ALLOW:
            allow.append(r)

    add(domain)
    add(final_url_host)
    apex = registrable_domain(domain) or domain
    for host in dict.fromkeys([final_url_host or apex, apex, f"www.{apex}"]):
        for name in cert_san_domains(host):
            add(name)
    for e in extra or []:
        add(normalize_host(e))
    return allow
