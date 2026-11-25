"""
Candidate verification & explainable risk scoring.

verify_candidate() visits a candidate host once (homepage + up to 4 small images, no JS,
never submits anything) and records evidence. score_candidate() turns that evidence into a
0-100 score, a verdict and a list of human-readable reasons.
"""

import base64
import difflib
import re
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import imagehash
import requests
from bs4 import BeautifulSoup

from .crawler import FaviconCrawler, FetchResult, decode_data_uri
from .discovery import is_parked_ns
from .domains import registrable_domain
from .hasher import analyze_icon_bytes, is_image_bytes, sniff_image_format

MAX_PAGE_BYTES = 1_500_000
MAX_IMG_BYTES = 1_000_000
MAX_PREVIEW_BYTES = 96 * 1024

ANALYTICS_RE = re.compile(r"\b(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{8,12}|GTM-[A-Z0-9]{5,9}|AW-\d{8,12})\b")
WORD_RE = re.compile(r"[a-zÀ-ɏЀ-ӿ]{4,}")

PARKING_HOSTS = (
    "sedo.com", "dan.com", "afternic.com", "hugedomains.com", "bodis.com", "parkingcrew.net", "above.com",
    "undeveloped.com", "atom.com", "squadhelp.com", "brandbucket.com", "sav.com", "godaddy.com", "domainmarket.com",
    "namecheap.com", "buydomains.com", "uniregistry.com", "efty.com", "spaceship.com", "porkbun.com", "dynadot.com",
)
PARKING_TEXT = re.compile(
    r"(this domain (name )?(is|may be) for sale|buy this domain|domain is for sale|make an offer|"
    r"is parked free|domain parking|parked domain|this domain has been registered|"
    r"inquire about this domain|get this domain|the domain .{0,60} is for sale|domain names? for sale|"
    r"parking page|resources and information\.?</title>|related searches|sponsored listings|"
    r"window\.park|/park\.js|parkingcrew|bodis\.com|sedoparking|domain-for-sale)",
    re.I,
)
DEFAULT_PAGE_TEXT = re.compile(
    r"(apache2? (ubuntu |debian )?default page|welcome to nginx|it works!|iis windows server|"
    r"index of /|future home of something quite cool|website coming soon|under construction|"
    r"account (has been )?suspended|this site can.t be reached|default web site page|plesk|cpanel)",
    re.I,
)

TYPO_FUZZERS = {"omission", "repetition", "transposition", "replacement", "insertion", "bitsquatting",
                "vowel-swap", "hyphenation", "addition", "various"}
LURE_WORDS = {"login", "secure", "verify", "account", "signin", "auth", "kyc", "wallet", "update", "pay",
              "payment", "billing", "refund", "claim", "support", "help", "portal", "client", "customer", "id", "access"}

VERDICTS = {
    "phishing": "High risk: likely impersonation",
    "suspicious": "Suspicious",
    "parked": "Parked / for sale",
    "redirect_brand": "Redirects to brand",
    "brand_owned": "Likely brand-owned",
    "no_website": "Registered, no website",
    "unreachable": "Resolves, web unreachable",
    "live_unrelated": "Live, no brand content",
    "offline": "Seen in threat intel, now offline",
}

SOURCE_NAMES = {"openphish": "OpenPhish", "phishingdb": "Phishing.Database", "urlscan": "URLScan", "shodan": "Shodan", "fofa": "FOFA", "censys": "Censys", "serpapi": "Google Lens",
                "google-lens": "Google Lens", "crt.sh": "crt.sh"}


# ------------------------------------------------------------------ helpers
def _informative_phash(ph: Optional[str]) -> bool:
    """Blank / single-colour images all hash alike; ignore them for visual matching."""
    if not ph:
        return False
    try:
        bits = bin(int(ph, 16)).count("1")
    except ValueError:
        return False
    return 8 <= bits <= 56


def phash_distance(a: Optional[str], b: Optional[str]) -> Optional[int]:
    if not (_informative_phash(a) and _informative_phash(b)):
        return None
    try:
        return int(imagehash.hex_to_hash(a) - imagehash.hex_to_hash(b))
    except Exception:
        return None


def page_words(soup: BeautifulSoup) -> Set[str]:
    for t in soup(["script", "style", "noscript"]):
        t.decompose()
    text = soup.get_text(" ", strip=True).lower()
    return set(WORD_RE.findall(text)[:3000])


def jaccard(a: Set[str], b: Set[str]) -> float:
    if not a or not b:
        return 0.0
    return round(len(a & b) / len(a | b), 3)


def title_of(soup: Optional[BeautifulSoup]) -> str:
    if soup is None or soup.title is None:
        return ""
    return re.sub(r"\s+", " ", soup.title.get_text(" ", strip=True))[:200]


def _squash(s: str) -> str:
    return re.sub(r"[^a-z0-9À-ɏЀ-ӿ]", "", s.lower())


def preview_data_uri(content: bytes) -> Optional[str]:
    if not content or len(content) > MAX_PREVIEW_BYTES:
        return None
    fmt = sniff_image_format(content)
    mime = {"ICO": "image/x-icon", "CUR": "image/x-icon", "PNG": "image/png", "GIF": "image/gif", "JPEG": "image/jpeg",
            "BMP": "image/bmp", "WEBP": "image/webp", "SVG": "image/svg+xml", "AVIF": "image/avif"}.get(fmt or "")
    if not mime:
        return None
    return f"data:{mime};base64,{base64.b64encode(content).decode('ascii')}"


def defang(host: str) -> str:
    return host.replace(".", "[.]")


def cert_info(host: str, timeout: int = 5) -> Optional[Dict[str, str]]:
    """Subject organisation / CN and issuer organisation of the certificate served by host."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        cert = x509.load_der_x509_certificate(der)

        def attr(name, oid):
            vals = name.get_attributes_for_oid(oid)
            return vals[0].value if vals else ""

        return {
            "subject_org": attr(cert.subject, NameOID.ORGANIZATION_NAME),
            "subject_cn": attr(cert.subject, NameOID.COMMON_NAME),
            "issuer_org": attr(cert.issuer, NameOID.ORGANIZATION_NAME),
            "not_before": cert.not_valid_before_utc.date().isoformat(),
        }
    except Exception:
        return None


# ------------------------------------------------------------------ brand profile
def build_brand_profile(
    domain: str,
    icons: List[Dict[str, Any]],
    soup: Optional[BeautifulSoup],
    allowlist: List[str],
    tokens: List[str],
) -> Dict[str, Any]:
    """Everything a candidate is compared against."""
    raw_html = str(soup) if soup is not None else ""
    title = title_of(soup)
    cert = cert_info(domain) or cert_info(f"www.{domain}") or {}
    words = page_words(BeautifulSoup(raw_html, "html.parser")) if raw_html else set()
    return {
        "domain": domain,
        "title": title,
        "tokens": [t for t in tokens if len(t) >= 3],
        "allowlist": allowlist,
        "favicon_mmh3": {i["mmh3"] for i in icons if i.get("kind") != "logo" and i.get("mmh3") is not None},
        "favicon_sha256": {i["sha256"] for i in icons if i.get("kind") != "logo" and i.get("sha256")},
        "any_sha256": {i["sha256"] for i in icons if i.get("sha256")},
        "phashes": [(i["phash"], i.get("kind", "favicon")) for i in icons if _informative_phash(i.get("phash"))],
        "analytics": set(ANALYTICS_RE.findall(raw_html)),
        "words": words,
        "cert_org": (cert.get("subject_org") or "").strip(),
    }


# ------------------------------------------------------------------ verification
SITE_BUDGET = 20.0  # seconds of wall time one candidate may take in total (measured p95 is ~12 s, a slow-drip server ~48 s)


def _fetch(crawler: FaviconCrawler, url: str, max_bytes: int, timeout: int, deadline: Optional[float] = None):
    """GET up to max_bytes. A deadline (time.monotonic) bounds connect, first byte and the body read, so a server that
    trickles data cannot hold a worker; whatever arrived by then is returned."""
    left = None if deadline is None else deadline - time.monotonic()
    if left is not None and left <= 0.5:
        return None
    connect, read = (4, timeout) if left is None else (min(4, left), min(timeout, left))
    try:
        with crawler.session.get(url, timeout=(connect, read), verify=False, allow_redirects=True, stream=True) as resp:
            chunks, total = [], 0
            for chunk in resp.iter_content(65536):
                chunks.append(chunk)
                total += len(chunk)
                if total >= max_bytes or (deadline is not None and time.monotonic() > deadline):
                    break
            return resp.status_code, resp.url, {k.lower(): v for k, v in resp.headers.items()}, b"".join(chunks)[:max_bytes], [r.url for r in resp.history]
    except requests.RequestException:
        return None


def _fetch_image(crawler: FaviconCrawler, url: str, timeout: int, deadline: Optional[float] = None) -> Optional[bytes]:
    if url.lower().startswith("data:"):
        return decode_data_uri(url)
    res = _fetch(crawler, url, MAX_IMG_BYTES, timeout, deadline)
    if not res or res[0] != 200 or not is_image_bytes(res[3]):
        return None
    return res[3]


def _in_allowlist(host: str, allowlist: List[str]) -> bool:
    r = registrable_domain(host or "")
    return bool(r and r in allowlist)


def verify_candidate(host: str, dns_info: Dict[str, Any], brand: Dict[str, Any], crawler: FaviconCrawler, timeout: int = 8,
                     budget: float = SITE_BUDGET) -> Dict[str, Any]:
    """Visits a live candidate and collects brand-impersonation evidence, spending at most ~`budget` seconds on it."""
    deadline = time.monotonic() + budget
    ev: Dict[str, Any] = {"http": None, "favicon": None, "visual_distance": None, "visual_match_kind": None,
                          "brand_resources": 0, "brand_links": 0, "shared_analytics": [], "password_form": False,
                          "forms": 0, "title": "", "brand_in_title": False, "title_similarity": 0.0,
                          "text_similarity": 0.0, "parked": False, "parked_reason": None, "default_page": False,
                          "redirect_brand": False, "cert": None, "cert_org_match": False, "preview": None}

    if dns_info.get("ns") and is_parked_ns(dns_info["ns"]):
        ev.update(parked=True, parked_reason="parking name servers")

    res = None
    for scheme in ("https", "http"):
        res = _fetch(crawler, f"{scheme}://{host}/", MAX_PAGE_BYTES, timeout, deadline)
        if res is not None:
            break
    if res is None:
        return ev

    status, final_url, headers, content, history = res
    final_host = (urlparse(final_url).hostname or "").lower()
    ev["http"] = {"status": status, "final_url": final_url, "final_host": final_host,
                  "redirects": len(history), "server": headers.get("server", "")[:60]}

    if final_host != host and _in_allowlist(final_host, brand["allowlist"]):
        ev["redirect_brand"] = True
    if any(final_host == p or final_host.endswith("." + p) for p in PARKING_HOSTS) and final_host != host:
        ev.update(parked=True, parked_reason=f"redirects to {final_host}")

    ctype = headers.get("content-type", "").lower()
    if "html" not in ctype and not content[:512].lstrip().lower().startswith((b"<!doctype", b"<html", b"<head")):
        return ev

    soup = FaviconCrawler._parse_html(FetchResult(url=final_url, status=status, headers=headers, content=content))
    raw = content.decode("utf-8", errors="ignore")
    base = FaviconCrawler._effective_base(soup, final_url)

    # Meta-refresh / JS redirect to the brand
    refresh = FaviconCrawler._meta_refresh_target(soup, base)
    if refresh and _in_allowlist(urlparse(refresh).hostname or "", brand["allowlist"]):
        ev["redirect_brand"] = True

    title = title_of(soup)
    ev["title"] = title
    # Strip the candidate's own name first: parked pages titled "adanii.com" are not brand content.
    own = {host, host.split(".")[0], registrable_domain(host) or host, final_host, final_host.split(".")[0]}
    clean_title = title.lower()
    for name in sorted(own, key=len, reverse=True):
        if name:
            clean_title = clean_title.replace(name.lower(), " ")
    sq_title = _squash(clean_title)
    ev["brand_in_title"] = any(_squash(t) and _squash(t) in sq_title for t in brand["tokens"])
    if brand["title"] and title:
        ev["title_similarity"] = round(difflib.SequenceMatcher(None, brand["title"].lower(), title.lower()).ratio(), 2)

    if PARKING_TEXT.search(raw[:200000]):
        ev.update(parked=True, parked_reason=ev["parked_reason"] or "for-sale / parking page text")
    if len(raw) < 60000 and DEFAULT_PAGE_TEXT.search(raw):
        ev["default_page"] = True

    ev["password_form"] = bool(soup.find("input", attrs={"type": re.compile(r"^password$", re.I)}))
    ev["forms"] = len(soup.find_all("form"))
    ev["shared_analytics"] = sorted(set(ANALYTICS_RE.findall(raw)) & brand["analytics"])

    # Resources hot-linked from the brand's own domains (images, scripts, css, icons)
    for tag, attr in (("img", "src"), ("script", "src"), ("link", "href"), ("source", "src"), ("iframe", "src")):
        for el in soup.find_all(tag):
            val = (el.get(attr) or "").strip()
            if val.startswith(("http://", "https://", "//")) and _in_allowlist(urlparse(urljoin(base, val)).hostname or "", brand["allowlist"]):
                ev["brand_resources"] += 1
    for a in soup.find_all("a", href=True):
        h = urlparse(urljoin(base, a["href"])).hostname or ""
        if h and _in_allowlist(h, brand["allowlist"]):
            ev["brand_links"] += 1

    # Favicon + logo comparison
    icon_cands, _ = crawler.extract_html_icon_candidates(soup, final_url)
    favs = [c["url"] for c in sorted(icon_cands, key=lambda c: -c.get("priority", 0)) if c.get("kind") == "favicon"][:2]
    root_ico = f"{urlparse(final_url).scheme}://{urlparse(final_url).netloc}/favicon.ico"
    if root_ico not in favs:
        favs.append(root_ico)
    logos = [u for u, _ in FaviconCrawler._logo_candidates(soup, base)][:2]

    best: Tuple[Optional[int], Optional[str]] = (None, None)
    for kind, urls in (("favicon", favs[:3]), ("logo", logos)):
        for u in urls:
            data = _fetch_image(crawler, u, timeout, deadline)
            if not data:
                continue
            a = analyze_icon_bytes(data)
            if kind == "favicon" and ev["favicon"] is None:
                ev["favicon"] = {"url": u if not u.startswith("data:") else "data: URI", "mmh3": a["mmh3"], "sha256": a["sha256"],
                                 "phash": a["phash"], "exact_match": a["mmh3"] in brand["favicon_mmh3"] or a["sha256"] in brand["favicon_sha256"]}
                ev["preview"] = preview_data_uri(data)
            if a["sha256"] in brand["any_sha256"]:
                best = (0, f"{kind} identical to brand asset")
            for ph, bkind in brand["phashes"]:
                d = phash_distance(a["phash"], ph)
                if d is not None and (best[0] is None or d < best[0]):
                    best = (d, f"{kind} vs brand {bkind}")
            if ev["preview"] is None and kind == "logo":
                ev["preview"] = preview_data_uri(data)
    ev["visual_distance"], ev["visual_match_kind"] = best
    ev["text_similarity"] = jaccard(page_words(soup), brand["words"])  # last: strips <script> from soup

    if final_url.startswith("https://") and deadline - time.monotonic() > 1:
        ev["cert"] = cert_info(final_host, timeout=min(5, deadline - time.monotonic()))
        org = (ev["cert"] or {}).get("subject_org", "").strip().lower()
        ev["cert_org_match"] = bool(org and brand.get("cert_org") and org == brand["cert_org"].lower())

    return ev


# ------------------------------------------------------------------ scoring
def score_candidate(cand: Dict[str, Any], brand: Optional[Dict[str, Any]] = None) -> Tuple[int, str, List[str]]:
    """
    Explainable 0-100 risk score. cand holds: fuzzer, sources, dns, evidence (may be None), rdap (may be None).
    Returns (score, verdict_key, reasons).
    """
    reasons: List[Tuple[int, str]] = []

    def add(points: int, text: str):
        reasons.append((points, text))

    fuzzer = cand.get("fuzzer") or ""
    dns = cand.get("dns") or {}
    ev = cand.get("evidence") or {}
    rdap = cand.get("rdap") or {}
    domain = cand.get("domain", "")

    # ---- domain-level signals
    if fuzzer in ("homoglyph", "idn-homoglyph"):
        add(12, "visual lookalike of the brand name (homoglyph)")
    elif fuzzer == "combosquat":
        label = domain.split(".")[0]
        if any(w in label.split("-") or label.startswith(w) or label.endswith(w) for w in LURE_WORDS):
            add(12, "brand + phishing lure word")
        else:
            add(7, "brand name combined with another word")
    elif fuzzer in TYPO_FUZZERS:
        add(6, f"typo of the brand name ({fuzzer})")
    elif fuzzer == "tld-swap":
        add(6, "brand name on another TLD")
    if "crt.sh" in (cand.get("sources") or []):
        add(5, "brand name in a recent TLS certificate (CT log)")

    if dns.get("mx"):
        add(8, "has mail servers (can send/receive phishing e-mail)")
    age = rdap.get("age_days")
    if age is not None:
        if age <= 30:
            add(18, f"registered {age} days ago")
        elif age <= 90:
            add(12, f"registered {age} days ago")
        elif age <= 365:
            add(5, f"registered {age} days ago")
        # A brand-new lookalike that already has mail or web infrastructure is the classic
        # pre-campaign pattern, even before any brand content goes live.
        lookalike = fuzzer in TYPO_FUZZERS or fuzzer in ("homoglyph", "idn-homoglyph", "combosquat", "brand-subdomain", "ct-hostname")
        if age <= 30 and lookalike and (dns.get("mx") or dns.get("a") or dns.get("aaaa")):
            add(10, "new lookalike with live mail/web setup (watch for a campaign)")

    # ---- content signals
    fav = ev.get("favicon") or {}
    if fav.get("exact_match"):
        add(40, "favicon is byte-identical to the brand favicon")
    vd = ev.get("visual_distance")
    if vd is not None and not fav.get("exact_match"):
        if vd <= 6:
            add(32, f"{ev.get('visual_match_kind') or 'image'} visually matches the brand (pHash distance {vd})")
        elif vd <= 10:
            add(15, f"{ev.get('visual_match_kind') or 'image'} resembles the brand (pHash distance {vd})")
    if ev.get("shared_analytics"):
        add(30, f"same analytics ID as the brand ({', '.join(ev['shared_analytics'][:2])}): cloned site")
    if ev.get("brand_resources"):
        add(20, f"loads {ev['brand_resources']} resource(s) directly from the brand's servers")
    strong_intel = any(i.get("match") in ("favicon_hash", "asset_hash", "analytics", "hosting", "feed") for i in cand.get("intel") or [])
    brand_content = bool(fav.get("exact_match") or (vd is not None and vd <= 10) or ev.get("brand_resources")
                         or ev.get("brand_in_title") or ev.get("shared_analytics") or strong_intel)
    if ev.get("password_form"):
        add(15 if brand_content else 5, "page asks for a password")
    if ev.get("brand_in_title"):
        add(15, f"brand name in page title “{(ev.get('title') or '')[:60]}”")
    if (ev.get("title_similarity") or 0) >= 0.85:
        add(10, f"title {int(ev['title_similarity'] * 100)}% identical to the brand's")
    ts = ev.get("text_similarity") or 0
    if ts >= 0.5:
        add(20, f"page text {int(ts * 100)}% similar to the brand homepage")
    elif ts >= 0.3:
        add(10, f"page text {int(ts * 100)}% similar to the brand homepage")

    # ---- threat-intel platform matches
    intel = cand.get("intel") or []
    matches = {i.get("match") for i in intel}

    def srcs(m: str) -> str:
        return ", ".join(sorted({SOURCE_NAMES.get(i.get("source"), i.get("source")) for i in intel if i.get("match") == m}))

    if "feed" in matches:
        add(45, f"listed in active phishing feeds ({srcs('feed')})")
    if "favicon_hash" in matches:
        add(35, f"served the brand's favicon ({srcs('favicon_hash')} favicon-hash search)")
    if "asset_hash" in matches:
        add(30, "loaded the brand's own favicon / logo images (URLScan resource-hash match)")
    if "code_hash" in matches:
        add(10, "loaded JS/CSS files that are rare outside the brand's site (weak signal: shared code can match)")
    if "analytics" in matches:
        add(30, f"page source contains the brand's analytics ID ({srcs('analytics')})")
    if "hosting" in matches:
        add(14, "brand page on a free hosting / site-builder platform (URLScan)")
    if "lens" in matches:
        add(8, "the brand logo appears on this site (Google Lens)")
    if "dork" in matches:
        add(4, f"found by {srcs('dork')} impersonation search")

    score = min(100, sum(p for p, _ in reasons))
    texts = [t for _, t in sorted(reasons, key=lambda r: -r[0])]

    # ---- verdict
    live = bool(ev.get("http"))
    resolves = bool(dns.get("a") or dns.get("aaaa"))
    if ev.get("cert_org_match"):
        texts.insert(0, "TLS certificate issued to the brand's own organisation")
        return min(score, 10), "brand_owned", texts
    if ev.get("redirect_brand"):
        texts.insert(0, "redirects to the brand's official site (often a defensive registration)")
        return min(score, 15), "redirect_brand", texts
    if intel and cand.get("dns_status") in ("nxdomain", "wildcard"):
        texts.insert(0, "no longer resolves: seen by threat-intel platforms, now offline")
        return min(score, 60), "offline", texts
    if score >= 70:
        return score, "phishing", texts
    if ev.get("parked") and score < 70:
        texts.insert(0, f"parked / for sale ({ev.get('parked_reason')})")
        return min(score, 40), "parked", texts
    if score >= 45:
        return score, "suspicious", texts
    if not resolves:
        return min(score, 40), "no_website", texts
    if not live:
        return score, "unreachable", texts
    return score, "live_unrelated", texts
