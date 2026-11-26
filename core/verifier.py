"""
Candidate verification & explainable risk scoring.

verify_candidate() visits a candidate host once (homepage + up to 4 small images, no JS,
never submits anything) and records evidence. score_candidate() turns that evidence into a
0-100 score, a verdict and a list of human-readable reasons.
"""

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

from .crawler import ANALYTICS_RE, FaviconCrawler, FetchResult, decode_data_uri
from .discovery import is_parked_ns
from .domain_matcher import corroborating_evidence, evaluate_domain_match
from .domains import defang, registrable_domain  # noqa: F401
from .hasher import analyze_icon_bytes, is_image_bytes, make_preview_data_uri
from .scoring import get_lure_words, get_weights

MAX_PAGE_BYTES = 1_500_000
MAX_IMG_BYTES = 1_000_000
MAX_PREVIEW_BYTES = 96 * 1024

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

SOURCE_NAMES = {
    "openphish": "OpenPhish", "phishingdb": "Phishing.Database", "nrd_free": "Free Daily NRD",
    "urlscan": "URLScan", "whoisxml": "WhoisXML", "shodan": "Shodan", "fofa": "FOFA",
    "censys": "Censys", "serpapi": "Google Lens", "google-lens": "Google Lens",
    "crt.sh": "crt.sh", "virustotal": "VirusTotal", "bing": "Bing",
    "duckduckgo": "DuckDuckGo", "wayback": "Wayback", "hackertarget": "HackerTarget",
    "safebrowsing": "Google Safe Browsing", "otx": "AlienVault OTX",
}


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
    return make_preview_data_uri(content, max_bytes=MAX_PREVIEW_BYTES)


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

        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except Exception:
            san = []
        return {
            "san": [n.lower().lstrip("*.") for n in san][:60],
            "san_count": len(san),
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


# Shared multi-tenant certificates list unrelated customers together; they prove nothing about ownership.
_SHARED_CERT_CN = ("cloudflaressl.com", "sni.cloudflaressl.com", "incapsula.com", "edgekey.net", "akamaized.net")
MAX_OWNER_SANS = 25


def cert_covers_brand(cert: Optional[Dict[str, Any]], allowlist: List[str]) -> bool:
    """
    True when the candidate's own TLS certificate also lists one of the brand's domains. A CA only issues that to
    whoever controls both names, so it is evidence of common ownership, unless the certificate is a shared
    multi-tenant one (CDN "sni" certificates bundling many unrelated customers).
    """
    if not cert or not allowlist:
        return False
    sans = cert.get("san") or []
    cn = (cert.get("subject_cn") or "").lower()
    if not sans or (cert.get("san_count") or len(sans)) > MAX_OWNER_SANS or cn.endswith(_SHARED_CERT_CN):
        return False
    return any(_in_allowlist(n, allowlist) for n in sans)


def ownership_evidence(cand: Dict[str, Any], allowlist: Optional[List[str]]) -> List[str]:
    """
    Verifiable signs that the brand itself operates the candidate (official regional site, subsidiary, defensive
    registration): its DNS is served by the brand's own name servers, its mail goes to the brand's mail servers,
    or its TLS certificate also covers the brand's domain. Self-declared WHOIS/RDAP registrant data is NOT used:
    anyone can type a company name into a registration form.
    """
    allow = list(allowlist or [])
    if not allow:
        return []
    out: List[str] = []
    dns = cand.get("dns") or {}
    ev = cand.get("evidence") or {}
    ns = [n for n in dns.get("ns") or [] if _in_allowlist(n, allow)]
    if ns:
        out.append(f"DNS is served by the brand's own name servers ({ns[0]})")
    mx = [m for m in dns.get("mx") or [] if _in_allowlist(m, allow)]
    if mx:
        out.append(f"mail is handled by the brand's own mail servers ({mx[0]})")
    if ev.get("cert_covers_brand"):
        out.append("TLS certificate also covers the brand's own domain (same certificate owner)")
    return out


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
        ev["cert_covers_brand"] = cert_covers_brand(ev["cert"], brand["allowlist"])

    return ev


# ------------------------------------------------------------------ scoring
def score_candidate(cand: Dict[str, Any], brand: Optional[Dict[str, Any]] = None) -> Tuple[int, str, List[str]]:
    """
    Explainable 0-100 risk score. cand holds: fuzzer, sources, dns, evidence (may be None), rdap (may be None).
    Returns (score, verdict_key, reasons). See score_candidate_detailed() for the structured breakdown.
    """
    d = score_candidate_detailed(cand, brand)
    return d["score"], d["verdict"], d["reasons"]


def score_candidate_detailed(cand: Dict[str, Any], brand: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Same scoring as score_candidate(), returning everything an analyst needs to audit it:
      score, verdict, reasons (human text), breakdown ([{signal, points, reason}] that sums to the score),
      corroboration (independent non-name evidence), capped (True when the score was held below "High risk"
      because nothing but the domain name / registration data supports it).
    Point values come from core.scoring (tunable through THREAT_SCORE_WEIGHTS).
    """
    W, T = get_weights()
    items: List[Dict[str, Any]] = []

    def add(signal: str, text: str, points: Optional[int] = None) -> None:
        items.append({"signal": signal, "points": W.get(signal, 0) if points is None else points, "reason": text})

    fuzzer = cand.get("fuzzer") or ""
    dns = cand.get("dns") or {}
    ev = cand.get("evidence") or {}
    rdap = cand.get("rdap") or {}
    domain = cand.get("domain", "")
    intel = cand.get("intel") or []

    mm = cand.get("match_meta")
    if mm is None and brand and brand.get("domain"):
        mm = evaluate_domain_match(
            domain,
            brand["domain"],
            keywords=brand.get("raw_keywords") or brand.get("tokens") or [],
            allowlist=brand.get("allowlist") or [],
            evidence=ev,
            intel=intel,
        )

    fav = ev.get("favicon") or {}
    vd = ev.get("visual_distance")
    strong_intel = any(i.get("match") in ("favicon_hash", "asset_hash", "analytics", "hosting", "feed", "daily_title", "subdomain_spoof") for i in intel)
    brand_content = bool(fav.get("exact_match") or (vd is not None and vd <= 10) or ev.get("brand_resources")
                         or ev.get("brand_in_title") or ev.get("shared_analytics") or strong_intel)

    benign_collision = bool(mm and mm.get("is_benign_collision") and not brand_content)

    # ---- domain-level signals
    if benign_collision:
        add("name", "name matches a common dictionary word with no impersonation signals", 0)
    elif fuzzer in ("homoglyph", "idn-homoglyph"):
        add("homoglyph", "visual lookalike of the brand name (homoglyph)")
    elif fuzzer == "combosquat":
        label = domain.split(".")[0]
        if any(w in label.split("-") or label.startswith(w) or label.endswith(w) for w in get_lure_words()):
            add("combosquat_lure", "brand + phishing lure word")
        else:
            add("combosquat", "brand name combined with another word")
    elif fuzzer in TYPO_FUZZERS:
        add("typo", f"typo of the brand name ({fuzzer})")
    elif fuzzer == "tld-swap":
        add("tld_swap", "brand name on another TLD")

    if not benign_collision and mm:
        tech_key = mm.get("technique_key") or ""
        kw_used = mm.get("matched_keyword") or "brand"
        sim = mm.get("similarity_percent") or 0.0
        weak_kw = mm.get("keyword_strength") == "weak"
        if mm.get("is_subdomain_impersonation") and not mm.get("is_own_domain"):
            where = f"brand keyword '{kw_used}' impersonated inside subdomain '{mm.get('matching_subdomain') or mm.get('subdomain')}' of external domain '{mm.get('registered_domain')}'"
            if weak_kw:
                add("subdomain_impersonation_weak", where + " (very short abbreviation: weak on its own)")
            else:
                add("subdomain_impersonation", where)
        elif mm.get("mixed_script") and not mm.get("is_own_domain") and fuzzer not in ("homoglyph", "idn-homoglyph"):
            add("mixed_script_idn", f"mixed-script IDN homograph ({'/'.join(mm.get('scripts') or ['Unicode'])}) visually mimics '{kw_used}' ({sim:.0f}% similarity)")
        elif tech_key == "homograph_idn" and fuzzer not in ("homoglyph", "idn-homoglyph"):
            add("idn_lookalike", f"IDN lookalike matches '{kw_used}' ({sim:.0f}% similarity)")
        elif tech_key not in ("none", "content_infrastructure", "benign_collision", "subdomain_impersonation") and fuzzer.startswith(("intel-", "ct-", "feed-", "keyword-")):
            strong_name = tech_key in ("exact_brand_match", "combosquat", "keyword_cooccurrence", "homograph_ascii")
            add("name_match_strong" if strong_name else "name_match",
                f"{mm.get('matching_technique')} matching keyword '{kw_used}' ({sim:.0f}% similarity)")

    ctx = (mm or {}).get("context_keywords") or []
    if ctx and not benign_collision and not any(i["signal"] == "combosquat_lure" for i in items):
        add("brand_lure_context", f"brand combined with malicious-context word(s): {', '.join(ctx[:3])}")

    if "crt.sh" in (cand.get("sources") or []):
        add("ct_certificate", "brand name in a recent TLS certificate (CT log)")

    if dns.get("mx") and not benign_collision:
        add("mx_records", "has mail servers (can send/receive phishing e-mail)")
    age = rdap.get("age_days")
    if age is not None and not benign_collision:
        if age <= 30:
            add("age_30", f"registered {age} days ago")
        elif age <= 90:
            add("age_90", f"registered {age} days ago")
        elif age <= 365:
            add("age_365", f"registered {age} days ago")
        # A brand-new lookalike that already has mail or web infrastructure is the classic
        # pre-campaign pattern, even before any brand content goes live.
        lookalike = fuzzer in TYPO_FUZZERS or fuzzer in ("homoglyph", "idn-homoglyph", "combosquat", "brand-subdomain", "ct-hostname", "keyword-exact")
        if age <= 30 and lookalike and (dns.get("mx") or dns.get("a") or dns.get("aaaa")):
            add("new_lookalike_live", "new lookalike with live mail/web setup (watch for a campaign)")

    # ---- content signals
    if fav.get("exact_match"):
        add("favicon_exact", "favicon is byte-identical to the brand favicon")
    if vd is not None and not fav.get("exact_match"):
        if vd <= 6:
            add("visual_match", f"{ev.get('visual_match_kind') or 'image'} visually matches the brand (pHash distance {vd})")
        elif vd <= 10:
            add("visual_resembles", f"{ev.get('visual_match_kind') or 'image'} resembles the brand (pHash distance {vd})")
    if ev.get("shared_analytics"):
        add("shared_analytics", f"same analytics ID as the brand ({', '.join(ev['shared_analytics'][:2])}): cloned site")
    if ev.get("brand_resources"):
        add("brand_resources", f"loads {ev['brand_resources']} resource(s) directly from the brand's servers")
    if ev.get("password_form"):
        add("password_form_brand" if brand_content else "password_form", "page asks for a password")
    if ev.get("brand_in_title"):
        add("brand_in_title", f"brand name in page title “{(ev.get('title') or '')[:60]}”")
    if (ev.get("title_similarity") or 0) >= 0.85:
        add("title_similarity", f"title {int(ev['title_similarity'] * 100)}% identical to the brand's")
    ts = ev.get("text_similarity") or 0
    if ts >= 0.5:
        add("text_similarity_high", f"page text {int(ts * 100)}% similar to the brand homepage")
    elif ts >= 0.3:
        add("text_similarity_mid", f"page text {int(ts * 100)}% similar to the brand homepage")

    # ---- threat-intel platform matches
    matches = {i.get("match") for i in intel}

    def srcs(m: str) -> str:
        return ", ".join(sorted({SOURCE_NAMES.get(i.get("source"), i.get("source")) for i in intel if i.get("match") == m}))

    if "feed" in matches:
        add("feed", f"listed in active phishing feeds ({srcs('feed')})")
    if "safe_browsing" in matches:
        sb = next((i.get("title") for i in intel if i.get("match") == "safe_browsing" and i.get("title")), "")
        add("safe_browsing", "listed by Google Safe Browsing" + (f" ({sb})" if sb else ""))
    vt_mal = max((int(i.get("malicious_votes") or 0) for i in intel if i.get("source") == "virustotal"), default=0)
    if vt_mal >= 3:
        add("vt_malicious", f"VirusTotal flagged malicious by {vt_mal} security vendor(s)")
    elif vt_mal > 0:
        add("vt_suspicious", f"VirusTotal: {vt_mal} security vendor(s) flag it (low confidence on its own)")
    if "favicon_hash" in matches:
        add("favicon_hash", f"served the brand's favicon ({srcs('favicon_hash')} favicon-hash search)")
    if "asset_hash" in matches:
        add("asset_hash", "loaded the brand's own favicon / logo images (URLScan resource-hash match)")
    if "code_hash" in matches:
        add("code_hash", "loaded JS/CSS files that are rare outside the brand's site (weak signal: shared code can match)")
    if "analytics" in matches:
        add("analytics", f"page source contains the brand's analytics ID ({srcs('analytics')})")
    if "daily_title" in matches:
        add("daily_title", "brand title matched in URLScan.io daily scan")
    if "whoisxml_brand" in matches:
        add("whoisxml_brand", "flagged by WhoisXML Brand Alert (newly registered / updated lookalike)")
    if "subdomain_spoof" in matches:
        add("subdomain_spoof", "brand subdomain impersonation matched in URLScan.io (keyword.*)")
    if "hosting" in matches:
        add("hosting", "brand page on a free hosting / site-builder platform (URLScan)")
    if "whoisxml_discovery" in matches:
        add("whoisxml_discovery", "discovered in WhoisXML Domains & Subdomains index")
    if "lens" in matches:
        add("lens", "the brand logo appears on this site (Google Lens)")
    if "daily_domain" in matches:
        add("daily_domain", "domain keyword matched in URLScan.io daily scan")
    if "dork" in matches:
        add("dork", f"found by {srcs('dork')} impersonation search")

    raw_total = sum(i["points"] for i in items)
    score = min(100, raw_total)
    corroboration = corroborating_evidence(cand)

    # A high score built only from the domain name and registration data is a lead, not proof. Hold it below
    # "High risk" until page content or threat-intel independently supports it.
    capped = False
    if score >= T["phishing"] and not corroboration:
        capped = True
        new_score = min(score, T["uncorroborated_cap"])
        if new_score < score:
            items.append({"signal": "uncorroborated_cap", "points": new_score - score,
                          "reason": f"capped at {new_score}: only the domain name and registration data support this; "
                                    "no page-content or threat-intel evidence yet"})
            score = new_score

    positive = [i for i in items if i["points"] > 0]
    texts = [i["reason"] for i in sorted(positive, key=lambda i: -i["points"])]
    if capped:
        texts.append(items[-1]["reason"] if items[-1]["signal"] == "uncorroborated_cap" else "no independent corroboration yet")

    def result(final_score: int, verdict: str, note: Optional[str] = None, cap: Optional[int] = None) -> Dict[str, Any]:
        if cap is not None and final_score > cap:
            items.append({"signal": "verdict_cap", "points": cap - final_score,
                          "reason": note or f"score limited to {cap} by verdict"})
            final_score = cap
        reasons = list(texts)
        if note:
            reasons.insert(0, note)
        return {"score": final_score, "verdict": verdict, "reasons": reasons,
                "breakdown": [dict(i) for i in items if i["points"] != 0],
                "corroboration": corroboration, "capped": capped, "raw_total": raw_total}

    # ---- verdict
    live = bool(ev.get("http"))
    resolves = bool(dns.get("a") or dns.get("aaaa"))
    if ev.get("cert_org_match"):
        return result(score, "brand_owned", "TLS certificate issued to the brand's own organisation", cap=10)
    owned = ownership_evidence(cand, (brand or {}).get("allowlist") or cand.get("brand_allowlist"))
    if owned:
        r = result(score, "brand_owned", "likely operated by the brand: " + "; ".join(owned), cap=10)
        r["ownership"] = owned
        return r
    if ev.get("redirect_brand"):
        return result(score, "redirect_brand", "redirects to the brand's official site (often a defensive registration)", cap=15)
    if intel and cand.get("dns_status") in ("nxdomain", "wildcard"):
        return result(score, "offline", "no longer resolves: seen by threat-intel platforms, now offline", cap=60)
    if benign_collision:
        return result(min(score, 20), "live_unrelated" if resolves else "no_website")
    if score >= T["phishing"]:
        return result(score, "phishing")
    if ev.get("parked") and score < T["phishing"]:
        return result(score, "parked", f"parked / for sale ({ev.get('parked_reason')})", cap=40)
    if score >= T["suspicious"]:
        return result(score, "suspicious")
    if mm and not mm.get("is_own_domain") and (mm.get("is_subdomain_impersonation") or mm.get("mixed_script")):
        if resolves:
            return result(score, "suspicious")
        return result(score, "no_website", cap=40)
    if not resolves:
        return result(score, "no_website", cap=40)
    if not live:
        return result(score, "unreachable")
    return result(score, "live_unrelated")
