"""
Infrastructure Investigator: one domain (phishing or legitimate) -> the infrastructure and operation behind it.

    1. Fingerprint   DNS, RDAP/WHOIS (public registrant data only), IP owner + ASN, TLS certificate, and one safe
                     page fetch for the phishing-kit "DNA" (title, favicon, analytics IDs, Telegram exfil bots,
                     crypto wallets, contact e-mails, form-post targets, download lures, HTML structure)
    2. Pivot         every fingerprint is searched for other domains: certificate SANs, crt.sh, passive DNS (OTX),
                     same IP (HackerTarget, URLScan), same favicon / exact title (URLScan), uncommon shared name servers
    3. Link          domains are tied to the seed's operator by the STRENGTH of what they share: a Telegram bot,
                     wallet, analytics ID or certificate is strong; a mass-hosting IP is weak. Confidence is the
                     strongest chain of evidence back to the seed, so an unlucky IP neighbour is never "the actor".
    4. Profile       intent, targets, infrastructure habits, MITRE ATT&CK techniques, timeline, and projections:
                     the next domains the naming pattern predicts, checked live in DNS.

Everything is free (no API key needed). Pages are fetched once, without JavaScript, and nothing is ever submitted.
Who is behind it is reported only from PUBLIC data (published registrant fields, hosting/abuse contacts, handles the
kit itself exposes); identifying a person beyond that needs registrar / law-enforcement process.
"""

from __future__ import annotations

import re
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests

from . import config, source_events
from .crawler import ANALYTICS_RE, FaviconCrawler, FetchResult
from .discovery import crtsh_search, is_parked_ns, registration_lookup, resolve_domains
from .domain_matcher import evaluate_domain_match
from .domains import normalize_host, registrable_domain, split_host
from .hasher import analyze_icon_bytes
from .keypool import SourceError
from .scoring import get_lure_words
from .sources import hackertarget_reverse_ip, hackertarget_shared_dns, otx_passive_dns, urlscan_search
from .takedown import ip_abuse
from .verifier import _fetch, _fetch_image, cert_info

ProgressFn = Callable[[str, float, str], None]

MAX_PAGE_BYTES = 800_000
SITE_BUDGET = 14.0
MASS_HOSTING_COHOSTS = 10          # an IP serving more domains than this is shared hosting: weak evidence
GENERIC_HASH_HITS = 60             # a favicon/title found on more pages than this is generic: not evidence
POPULAR_NS_DOMAINS = 25            # a name server shared by more domains than this is a provider's, not the operator's

STRENGTH = {"strong": 3, "medium": 2, "weak": 1}

# Name servers / hosting so common that sharing them says nothing about who operates a domain.
MAINSTREAM_NS = ("cloudflare.com", "domaincontrol.com", "registrar-servers.com", "awsdns", "azure-dns", "googledomains.com",
                 "nsone.net", "dnsmadeeasy.com", "ultradns", "akam.net", "hostinger", "namecheaphosting.com", "porkbun.com",
                 "name.com", "dynadot.com", "gandi.net", "ovh.net", "hetzner.com", "digitalocean.com", "linode.com",
                 "wixdns.net", "squarespacedns.com", "bluehost.com", "hostgator.com", "dreamhost.com", "dnsowl.com",
                 "parkingcrew.net", "sedoparking.com", "bodis.com", "above.com", "afternic.com", "google.com", "yandex.net",
                 "ns.cloudflare.com", "worldnic.com", "networksolutions.com", "godaddy.com", "1and1", "ionos",
                 "your-server.de", "second-ns.de", "second-ns.com", "hetzner", "contabo", "vultr", "ui-dns", "dns-parking",
                 "nic.ru", "reg.ru", "timeweb", "beget", "selectel", "netcup", "strato", "one.com", "rackspace")
FREE_HOSTING = ("workers.dev", "pages.dev", "vercel.app", "netlify.app", "github.io", "glitch.me", "web.app", "firebaseapp.com",
                "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com", "herokuapp.com", "onrender.com", "repl.co",
                "ngrok-free.app", "ngrok.io", "trycloudflare.com", "surge.sh", "r2.dev", "azurewebsites.net", "square.site")
KNOWN_BRANDS = (
    "paypal", "microsoft", "office365", "office", "outlook", "onedrive", "sharepoint", "azure", "apple", "icloud", "amazon",
    "netflix", "google", "gmail", "facebook", "instagram", "whatsapp", "meta", "linkedin", "dhl", "fedex", "ups", "usps",
    "dpd", "royalmail", "chase", "wellsfargo", "bankofamerica", "citi", "hsbc", "barclays", "santander", "binance",
    "coinbase", "metamask", "trustwallet", "ledger", "kraken", "adobe", "docusign", "dropbox", "steam", "roblox", "discord",
    "telegram", "ebay", "walmart", "costco", "spotify", "airbnb", "booking", "irs", "hmrc", "att", "verizon", "tmobile",
    "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "upi", "aadhaar", "zoom", "okta", "salesforce", "yahoo", "aol",
)
GENERIC_TOKENS = {"www", "com", "net", "org", "online", "site", "app", "web", "info", "home", "page", "group", "global",
                  "official", "the", "and", "new", "my", "secure2", "index", "mail", "server", "host", "cloud",
                  "api", "cdn", "static", "dev", "test", "prod", "eu", "us", "uk", "in"}

# Phishing-kit artefacts (all from the page the site itself serves).
TELEGRAM_BOT_RE = re.compile(r"(?:api\.telegram\.org/)?bot(\d{8,11}):([A-Za-z0-9_-]{30,40})")
TELEGRAM_CHAT_RE = re.compile(r"chat_?id[\"']?\s*[:=]\s*[\"']?(-?\d{6,15})", re.I)
TELEGRAM_HANDLE_RE = re.compile(r"(?:https?://)?t\.me/([A-Za-z0-9_]{5,32})\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{2,64}@[A-Za-z0-9.-]{2,190}\.[A-Za-z]{2,24}\b")
BTC_RE = re.compile(r"\b(bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
TRON_RE = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
FB_PIXEL_RE = re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]")
YANDEX_RE = re.compile(r"\bym\(\s*(\d{6,12})\s*,")
DOWNLOAD_RE = re.compile(r"\.(exe|msi|scr|apk|zip|rar|7z|iso|img|js|vbs|hta|lnk|dmg|pkg)(\?|$)", re.I)
CARD_FIELD_RE = re.compile(r"(card.?number|cc.?num|cardnum|cvv|cvc|expir|exp.?date|ccexp)", re.I)
SEED_PHRASE_RE = re.compile(r"(seed phrase|recovery phrase|secret recovery|mnemonic|12.word|24.word|private key)", re.I)
WEB3_RE = re.compile(r"(web3|ethers\.min\.js|walletconnect|connect wallet|metamask)", re.I)
SUPPORT_SCAM_RE = re.compile(r"(call (?:us|now|microsoft|support)|toll.free|your computer (?:is|has been) (?:infected|blocked)|technical support)", re.I)
INVEST_RE = re.compile(r"(guaranteed (?:profit|return)|double your|investment plan|trading bot|daily profit|roi\b)", re.I)
JOB_RE = re.compile(r"(job offer|work from home|recruit|hiring now|remote job|task.based)", re.I)

IMAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico")
_ASN_CACHE: Dict[str, Optional[Dict[str, Any]]] = {}
_ASN_LOCK = threading.Lock()


class InvestigationCancelled(Exception):
    pass


# ============================================================== free helpers
def asn_lookup(ip: str, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    """
    ASN, prefix, country and AS name of an IPv4 address (cached). Team Cymru's free DNS service first, asked
    through public resolvers with short timeouts; RIPEstat (free, no key) when DNS does not answer.
    """
    with _ASN_LOCK:
        if ip in _ASN_CACHE:
            return _ASN_CACHE[ip]
    out = _asn_cymru(ip, timeout) or _asn_ripestat(ip)
    with _ASN_LOCK:
        _ASN_CACHE[ip] = out
    return out


def _asn_ripestat(ip: str) -> Optional[Dict[str, Any]]:
    import requests

    try:
        data = requests.get("https://stat.ripe.net/data/network-info/data.json", params={"resource": ip}, timeout=6).json().get("data") or {}
        asns = data.get("asns") or []
        if not asns:
            return None
        out = {"asn": f"AS{asns[0]}", "prefix": data.get("prefix") or "", "country": "", "as_name": ""}
        try:
            ov = requests.get("https://stat.ripe.net/data/as-overview/data.json", params={"resource": out["asn"]}, timeout=4).json().get("data") or {}
            out["as_name"] = ov.get("holder") or ""
        except Exception:
            pass
        return out
    except Exception:
        return None


def _asn_cymru(ip: str, timeout: float) -> Optional[Dict[str, Any]]:
    out = None
    try:
        import dns.resolver

        parts = ip.split(".")
        if len(parts) == 4:
            res = dns.resolver.Resolver(configure=False)
            res.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
            res.timeout = 1.5
            res.lifetime = timeout
            txt = str(res.resolve(".".join(reversed(parts)) + ".origin.asn.cymru.com", "TXT")[0]).strip('"')
            asn, prefix, cc = [p.strip() for p in txt.split("|")[:3]]
            asn = asn.split()[0]
            name = ""
            try:
                name = str(res.resolve(f"AS{asn}.asn.cymru.com", "TXT")[0]).strip('"').split("|")[-1].strip()
            except Exception:
                pass
            out = {"asn": f"AS{asn}", "prefix": prefix, "country": cc, "as_name": name}
    except Exception:
        out = None
    return out


def _parse_html(content: bytes, url: str, status: int, headers: Dict[str, str]):
    return FaviconCrawler._parse_html(FetchResult(url=url, status=status, headers=headers, content=content))


def _structure_shingles(soup) -> Set[str]:
    """Phishing kits are copied wholesale: the tag/class skeleton survives text and brand changes."""
    seq = []
    for el in (soup.body or soup).find_all(True, limit=600):
        cls = ".".join(sorted(el.get("class") or [])[:2])
        seq.append(f"{el.name}{'.' + cls if cls else ''}")
    return {"|".join(seq[i:i + 4]) for i in range(max(0, len(seq) - 3))}


def fetch_page(host: str, crawler: FaviconCrawler, timeout: int = 8, budget: float = SITE_BUDGET) -> Optional[Dict[str, Any]]:
    """
    One safe visit (no JavaScript, nothing submitted, size-capped, time-boxed) that extracts the kit "DNA".
    Returns None when the site does not answer over HTTPS or HTTP.
    """
    deadline = time.monotonic() + budget
    res = None
    for scheme in ("https", "http"):
        res = _fetch(crawler, f"{scheme}://{host}/", MAX_PAGE_BYTES, timeout, deadline)
        if res is not None:
            break
    if res is None:
        return None
    status, final_url, headers, content, history = res
    return analyze_html(content, final_url, status, headers, history=history, host=host, crawler=crawler, timeout=timeout, deadline=deadline)


CHALLENGE_TITLE_RE = re.compile(r"(attention required|just a moment|checking your browser|ddos protection|verify you are human|"
                                r"security check|one more step|are you a robot|access denied|captcha|bot verification)", re.I)
CHALLENGE_MARKERS = ("cf-chl", "challenge-platform", "__cf_chl", "cf_chl_opt", "hcaptcha.com", "g-recaptcha", "challenges.cloudflare.com",
                     "turnstile", "sgcaptcha", "ddos-guard")


def detect_challenge(title: str, raw: str, text: str, headers: Dict[str, str]) -> Optional[str]:
    """
    A bot-protection interstitial is not the site's content. Returns what blocked us, or None. Treating a challenge
    page as "inspected, nothing malicious" would turn every Cloudflare-fronted phishing site into a false all-clear.
    """
    low = raw[:20000].lower()
    if CHALLENGE_TITLE_RE.search(title or "") or (any(m in low for m in CHALLENGE_MARKERS) and len(text) < 4000):
        server = (headers.get("server") or "").lower()
        if "cloudflare" in server or "cloudflare" in low or "cf-chl" in low:
            return "Cloudflare bot protection"
        if "ddos-guard" in low or "ddos-guard" in server:
            return "DDoS-Guard bot protection"
        return "bot protection / CAPTCHA"
    return None


def analyze_html(content: bytes, final_url: str, status: Optional[int], headers: Dict[str, str], history: Optional[List[str]] = None,
                 host: str = "", crawler: Optional[FaviconCrawler] = None, timeout: int = 8, deadline: Optional[float] = None) -> Dict[str, Any]:
    """Kit "DNA" of one HTML document (a live fetch or a stored scan snapshot)."""
    host = host or (urlparse(final_url).hostname or "")
    page: Dict[str, Any] = {"status": status, "final_url": final_url, "final_host": (urlparse(final_url).hostname or "").lower(),
                            "redirects": (history or [])[:6], "server": (headers.get("server") or "")[:60], "title": "",
                            "artifacts": {}, "signals": {}, "favicon": None, "shingles": set()}
    ctype = (headers.get("content-type") or "").lower()
    if "html" not in ctype and not content[:512].lstrip().lower().startswith((b"<!doctype", b"<html", b"<head")):
        return page
    soup = _parse_html(content, final_url, status or 200, headers)
    raw = content.decode("utf-8", errors="ignore")
    text = soup.get_text(" ", strip=True)[:60000]
    page["title"] = re.sub(r"\s+", " ", soup.title.get_text(" ", strip=True))[:160] if soup.title else ""
    blocked = detect_challenge(page["title"], raw, text, headers)
    if blocked:
        page.update(blocked=blocked, challenge_title=page["title"], title="")
        return page
    gen = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
    page["generator"] = (gen.get("content") or "")[:80] if gen else ""
    page["shingles"] = _structure_shingles(soup)

    own = registrable_domain(page["final_host"] or host) or host
    forms = []
    for f in soup.find_all("form")[:12]:
        action = urljoin(final_url, (f.get("action") or "").strip()) if f.get("action") else final_url
        ahost = (urlparse(action).hostname or "").lower()
        fields = " ".join(f"{i.get('name', '')} {i.get('id', '')} {i.get('placeholder', '')} {i.get('type', '')}" for i in f.find_all(["input", "select"]))
        forms.append({"action_host": ahost, "external": bool(ahost and registrable_domain(ahost) != own),
                      "password": "password" in fields.lower(), "card": bool(CARD_FIELD_RE.search(fields)),
                      "method": (f.get("method") or "get").lower()})
    page["forms"] = forms

    script_hosts, downloads = set(), set()
    for el in soup.find_all(["script", "a", "link", "iframe"], limit=800):
        ref = el.get("src") or el.get("href") or ""
        if not ref or ref.startswith(("#", "javascript:", "mailto:", "data:")):
            continue
        absu = urljoin(final_url, ref)
        h = (urlparse(absu).hostname or "").lower()
        if el.name in ("script", "iframe") and h and registrable_domain(h) != own:
            script_hosts.add(h)
        if el.name == "a" and DOWNLOAD_RE.search(urlparse(absu).path or ""):
            downloads.add(absu[:200])

    bots = {f"{m.group(1)}:{m.group(2)[:4]}…{m.group(2)[-3:]}" for m in TELEGRAM_BOT_RE.finditer(raw)}  # never keep a usable token
    emails = {e.lower() for e in EMAIL_RE.findall(raw) if not e.lower().endswith(IMAGE_EXT) and "example." not in e.lower()
              and not e.lower().split("@")[1].startswith(("sentry", "wixpress", "w3.org"))}
    art = {
        "analytics": sorted(set(ANALYTICS_RE.findall(raw)) | {f"fb:{x}" for x in FB_PIXEL_RE.findall(raw)} | {f"ym:{x}" for x in YANDEX_RE.findall(raw)}),
        "telegram_bots": sorted(bots),
        "telegram_chats": sorted(set(TELEGRAM_CHAT_RE.findall(raw)))[:5],
        "telegram_handles": sorted({h.lower() for h in TELEGRAM_HANDLE_RE.findall(raw)} - {"share", "joinchat", "s", "addstickers"})[:8],
        "wallets": sorted(set(BTC_RE.findall(raw) if ("bitcoin" in raw.lower() or "btc" in raw.lower()) else []) | set(ETH_RE.findall(raw)) |
                          set(TRON_RE.findall(raw) if "usdt" in raw.lower() or "tron" in raw.lower() else []))[:10],
        "emails": sorted(emails)[:10],
        "exfil_hosts": sorted({f["action_host"] for f in forms if f["external"] and f["action_host"]}),
        "script_hosts": sorted(script_hosts)[:25],
        "downloads": sorted(downloads)[:10],
    }
    page["artifacts"] = {k: v for k, v in art.items() if v}
    page["signals"] = {
        "password_form": any(f["password"] for f in forms),
        "card_form": any(f["card"] for f in forms) or bool(CARD_FIELD_RE.search(text[:20000]) and "payment" in text.lower()),
        "seed_phrase": bool(SEED_PHRASE_RE.search(text)),
        "web3": bool(WEB3_RE.search(raw)),
        "support_scam": bool(SUPPORT_SCAM_RE.search(text)),
        "investment": bool(INVEST_RE.search(text)),
        "job": bool(JOB_RE.search(text)),
        "downloads": bool(downloads),
        "telegram_exfil": bool(bots),
    }

    # favicon (declared icon first, /favicon.ico fallback); never fetched for stored snapshots
    icon = soup.find("link", rel=lambda r: r and "icon" in " ".join(r).lower())
    if crawler is None:
        return page
    for u in ([urljoin(final_url, icon["href"])] if icon and icon.get("href") else []) + [f"{urlparse(final_url).scheme}://{urlparse(final_url).netloc}/favicon.ico"]:
        data = _fetch_image(crawler, u, timeout, deadline)
        if data:
            a = analyze_icon_bytes(data)
            page["favicon"] = {"mmh3": a.get("mmh3"), "sha256": a.get("sha256")}
            break
    return page


def urlscan_snapshot(host: str) -> Optional[Dict[str, Any]]:
    """
    The newest public URLScan scan of a host, for when the live page is hidden behind bot protection or offline.
    Always: title, URL, IP and date from the (free) search API. With a free URLScan key: the scanned page itself,
    run through the same kit analysis.
    """
    hits = [h for h in urlscan_search(f'page.domain:"{host}"', size=10) if h.get("host") == host]
    if not hits:
        return None
    h = sorted(hits, key=lambda x: x.get("time") or "", reverse=True)[0]
    result_api = (h.get("extra") or {}).get("result") or ""
    uuid = result_api.rstrip("/").rsplit("/", 1)[-1] if "/result/" in result_api else ""
    meta = {"via": "urlscan", "observed": (h.get("time") or "")[:10], "scan_url": f"https://urlscan.io/result/{uuid}/" if uuid else None,
            "snapshot_ip": h.get("ip")}
    key = config.get("URLSCAN_API_KEY")
    if key and uuid:
        try:
            r = requests.get(f"https://urlscan.io/dom/{uuid}/", headers={"API-Key": key}, timeout=20)
            if r.status_code == 200 and r.content:
                page = analyze_html(r.content[:MAX_PAGE_BYTES], h.get("url") or f"https://{host}/", 200, {"content-type": "text/html"}, host=host)
                page.update(meta)
                return page
        except requests.RequestException:
            pass
    return {"status": None, "final_url": h.get("url"), "final_host": host, "title": (h.get("title") or "")[:160], "redirects": [],
            "server": "", "forms": [], "artifacts": {}, "signals": {}, "favicon": None, "shingles": set(), "partial": True, **meta}


def brand_in_title(title: str, terms: Iterable[str]) -> Optional[str]:
    """The brand term a page title names (punctuation-insensitive: 'Giesecke+Devrient' contains 'giesecke')."""
    flat = re.sub(r"[^a-z0-9]", "", (title or "").lower())
    return next((t for t in terms if len(t) >= 4 and t in flat), None)


# ============================================================== intent & naming
INTENTS = {
    "credential_theft": "Credential harvesting",
    "card_fraud": "Payment-card fraud",
    "crypto_fraud": "Crypto theft / wallet drainer",
    "malware": "Malware delivery",
    "support_scam": "Tech-support scam",
    "investment_scam": "Investment scam",
    "job_scam": "Recruitment scam",
    "impersonation": "Brand impersonation page",
    "staged": "Staged / not yet active",
}


def classify_intent(dom: Dict[str, Any]) -> List[Dict[str, str]]:
    """What a site is built to do, from what its page actually contains (each with the evidence)."""
    page = dom.get("page") or {}
    s = page.get("signals") or {}
    art = page.get("artifacts") or {}
    age = (dom.get("rdap") or {}).get("age_days")
    # Login, checkout and download pages are normal on established sites. They only count as hostile on young
    # domains (or unknown age) or when the kit's own artefacts (exfil host, Telegram bot) are present.
    young = age is None or age <= 365
    kit = bool(art.get("exfil_hosts") or s.get("telegram_exfil"))
    out = []
    if s.get("password_form") and (young or kit):
        out.append(("credential_theft", "page has a password form" + (f" posting to {art['exfil_hosts'][0]}" if art.get("exfil_hosts") else "")
                    + ("" if kit else f" on a {age}-day-old domain" if age is not None else " (domain age unknown)")))
    if s.get("telegram_exfil"):
        out.append(("credential_theft", "kit sends captured data to a Telegram bot"))
    if s.get("card_form") and (young or kit):
        out.append(("card_fraud", "page asks for card number / CVV / expiry"))
    if s.get("seed_phrase"):
        out.append(("crypto_fraud", "asks for a wallet seed phrase / recovery phrase"))
    elif art.get("wallets") and (young or kit or s.get("web3")):
        out.append(("crypto_fraud", f"crypto wallet address on the page ({art['wallets'][0][:12]}…)"))
    if s.get("downloads") and (young or kit):
        out.append(("malware", f"offers executable / archive downloads ({urlparse(art['downloads'][0]).path.rsplit('/', 1)[-1][:40]})"))
    nm = dom.get("name_match")
    named = brand_in_title(page.get("title") or "", dom.get("brand_terms") or [])
    if nm and named:
        via = f" (URLScan scan {page.get('observed')})" if page.get("via") == "urlscan" else ""
        out.append(("impersonation", f"page titled “{page.get('title')}”{via} names '{named}' while hosted on {dom.get('root')}, "
                                     f"which is not the brand's domain ({nm['technique'].replace('_', ' ')} of '{nm['keyword']}')"))
    if s.get("support_scam"):
        out.append(("support_scam", "'call support' / infected-computer wording"))
    if s.get("investment"):
        out.append(("investment_scam", "guaranteed-profit / investment-plan wording"))
    if s.get("job"):
        out.append(("job_scam", "job-offer / work-from-home wording"))
    if not out and dom.get("dns_status") in ("resolves", "registered") and not page:
        out.append(("staged", "registered and resolving but no web content yet"))
    seen, res = set(), []
    for k, why in out:
        if k not in seen:
            seen.add(k)
            res.append({"intent": k, "label": INTENTS[k], "evidence": why})
    return res


def brand_phrases(host: str) -> List[str]:
    """
    The name a hostname impersonates: its subdomain labels when it has any (gi-de.attacker.tech -> gi-de), otherwise
    its registered label (gi-de-wallet.top -> gi-de), with lure / generic words and numbers removed.
    """
    sub, sld, _ = split_host(host)
    lures = set(get_lure_words())
    out = []
    for label in ([x for x in sub.split(".") if x] if sub else [sld]):
        phrase = "-".join(p for p in label.lower().split("-") if p and p not in lures and p not in GENERIC_TOKENS and not p.isdigit())
        if len(phrase.replace("-", "")) >= 4 and phrase not in out:
            out.append(phrase)
    return out


def name_tokens(host: str) -> List[str]:
    """Words of a hostname (TLD excluded): login.paypal-secure.xyz -> [login, paypal, secure]."""
    sub, sld, _ = split_host(host)
    toks = re.split(r"[-._]|\d+", f"{sub}.{sld}".lower())
    return [t for t in toks if len(t) >= 2]


# ============================================================== the investigation
def _node_id(kind: str, value: str) -> str:
    return f"{kind}:{value}"


class _Graph:
    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self.pivoted: Set[Tuple[str, str]] = set()

    def node(self, kind: str, value: str, label: Optional[str] = None, **data: Any) -> str:
        nid = _node_id(kind, value)
        n = self.nodes.setdefault(nid, {"id": nid, "type": kind, "label": label or value, "data": {}})
        n["data"].update({k: v for k, v in data.items() if v not in (None, "", [], {})})
        return nid

    def edge(self, a: str, b: str, relation: str, strength: str, evidence: str, source: str) -> None:
        if a == b:
            return
        key = (min(a, b), max(a, b), relation)
        e = self.edges.get(key)
        if e is None or STRENGTH[strength] > STRENGTH[e["strength"]]:
            self.edges[key] = {"source": a, "target": b, "relation": relation, "strength": strength,
                               "evidence": evidence[:200], "via": source}


def investigate(
    target: str,
    depth: int = 2,
    max_domains: int = 30,
    keywords: Optional[List[str]] = None,
    timeout: int = 8,
    workers: int = 8,
    progress: Optional[ProgressFn] = None,
    cancel: Optional[threading.Event] = None,
) -> Dict[str, Any]:
    t0 = time.time()
    seed = normalize_host(target)
    if not seed or "." not in seed:
        raise ValueError("Give a domain, hostname or URL")
    seed_root = registrable_domain(seed) or seed
    keywords = [k.strip() for k in (keywords or []) if k and k.strip()]
    depth = max(1, min(int(depth), 3))
    max_domains = max(5, min(int(max_domains), 80))
    g = _Graph()
    errors: List[str] = []
    sources_used: Counter = Counter()
    domains: Dict[str, Dict[str, Any]] = {}
    queue: List[Tuple[str, int, str]] = [(seed, 0, "seed")]
    queued: Set[str] = {seed}
    crawler = FaviconCrawler(timeout=timeout, include_logos=False, probe_subdomains=False, max_workers=workers)
    lure_set = set(get_lure_words())
    seed_tokens = {t for t in name_tokens(seed) if len(t) >= 4 and t not in GENERIC_TOKENS and t not in lure_set}
    seed_phrases = [p for p in brand_phrases(seed) if p not in KNOWN_BRANDS]
    brand_terms = list(dict.fromkeys([re.sub(r"[^a-z0-9]", "", k.lower()) for k in keywords] + [p.replace("-", "") for p in seed_phrases]))
    brand_labels = {re.sub(r"[^a-z0-9]", "", k.split(".")[0].lower()) for k in keywords} | {p.replace("-", "") for p in seed_phrases}

    def name_match(host: str) -> Optional[Dict[str, str]]:
        """Does this hostname imitate a brand keyword on a domain the brand does not own?"""
        refs = ([(brand_ref, keywords)] if keywords else []) + [(f"{p}.com", [p]) for p in seed_phrases[:3]]
        for ref, kws in refs:
            m = evaluate_domain_match(host, ref, keywords=kws)
            if not m["is_own_domain"] and m["technique_key"] not in ("none", "benign_collision", "content_infrastructure"):
                return {"keyword": m["matched_keyword"], "technique": m["technique_key"], "where": m["matched_in"]}
        return None

    def is_brand_original(host: str) -> bool:
        """The impersonated brand's own site (gi-de.com for gi-de.astrobale-core.tech): the victim, never the actor."""
        root = registrable_domain(host) or host
        if root == seed_root:
            return False
        label = re.sub(r"[^a-z0-9]", "", split_host(root)[1].lower())
        return bool(label) and label in brand_labels and not split_host(host)[0].replace("www", "")
    brand_ref = next((k for k in keywords if "." in k), f"{re.sub(r'[^a-z0-9-]', '', keywords[0].lower()) or 'brand'}.com" if keywords else "")

    def report(stage: str, pct: float, msg: str) -> None:
        if cancel is not None and cancel.is_set():
            raise InvestigationCancelled()
        if progress:
            progress(stage, round(pct, 1), msg)

    def interesting(host: str) -> bool:
        """Expand a weakly linked neighbour only when its NAME looks related (brand keyword or seed naming token)."""
        for ref, kws in ([(brand_ref, keywords)] if keywords else []) + [(f"{p}.com", [p]) for p in seed_phrases[:3]]:
            m = evaluate_domain_match(host, ref, keywords=kws)
            if m["technique_key"] not in ("none", "benign_collision", "content_infrastructure"):
                return True
        toks = set(name_tokens(host))
        return bool(toks & seed_tokens) or bool(toks & set(KNOWN_BRANDS) & set(name_tokens(seed)))

    def enqueue(host: str, d: int, why: str, force: bool = False) -> None:
        host = normalize_host(host).lstrip("*.")
        if not host or "." not in host or host in queued or len(queued) >= max_domains * 4:
            return
        if name_match(seed) and is_brand_original(host):
            return  # the victim brand's own site is shown, never investigated as part of the operation
        if not force and not interesting(host):
            return
        queued.add(host)
        queue.append((host, d, why))

    tripped: Set[str] = set()

    def safe(name: str, fn: Callable[[], Any], default: Any) -> Any:
        """Calls a source; after it rate-limits / runs out of quota it is skipped for the rest of the run."""
        if name in tripped:
            return default
        try:
            out = fn()
            sources_used[name] += 1
            return out
        except SourceError as e:
            if getattr(e, "kind", "") in ("rate_limit", "rate", "quota", "exhausted", "auth") or "429" in str(e):
                tripped.add(name)
                errors.append(f"{name}: {e} (skipped for the rest of this investigation)")
            else:
                errors.append(f"{name}: {e}")
        except Exception as e:  # never let one source end the investigation
            errors.append(f"{name}: {e.__class__.__name__}")
        return default

    report("fingerprint", 2, f"Fingerprinting {seed}")
    level = 0
    while queue and level <= depth:
        batch = [q for q in queue if q[1] == level and q[0] not in domains][: max(0, max_domains - len(domains))]
        queue = [q for q in queue if q[1] != level]
        if not batch:
            level += 1
            continue
        hosts = [h for h, _, _ in batch]
        dns = safe("DNS", lambda: resolve_domains(hosts, timeout=2.5), {})
        report("fingerprint", 5 + 60 * len(domains) / max_domains, f"Level {level}: fingerprinting {len(hosts)} domain(s)")

        def profile(item):
            host, d, why = item
            info = dns.get(host) or {}
            dom = {"domain": host, "root": registrable_domain(host) or host, "depth": d, "discovered_via": why,
                   "dns": {k: info.get(k, []) for k in ("a", "aaaa", "mx", "ns")}, "dns_status": info.get("status", "unknown"),
                   "name_tokens": name_tokens(host)}
            dom["rdap"] = safe("RDAP/WHOIS", lambda: registration_lookup(dom["root"]), None)
            ip = (dom["dns"]["a"] or [None])[0]
            if ip:
                dom["ip_owner"] = safe("IP RDAP", lambda: ip_abuse(ip), None)
                dom["asn"] = safe("Team Cymru ASN", lambda: asn_lookup(ip), None)
            if info.get("a") or info.get("aaaa"):
                dom["page"] = safe("page fetch", lambda: fetch_page(host, crawler, timeout), None)
                if dom.get("page") and (dom["page"].get("final_url") or "").startswith("https"):
                    dom["cert"] = safe("TLS certificate", lambda: cert_info(dom["page"].get("final_host") or host), None)
            live = dom.get("page")
            if (not live or live.get("blocked")) and (host == seed or d <= 1):
                # hidden behind bot protection or not answering: use the newest public scan instead
                snap = safe("URLScan snapshot", lambda: urlscan_snapshot(host), None)
                if snap:
                    dom["live_page"] = live
                    dom["page"] = snap
            return dom

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="infra") as pool:
            futs = [pool.submit(profile, it) for it in batch]
            for f in as_completed(futs):
                dom = f.result()
                domains[dom["domain"]] = dom
                report("fingerprint", 5 + 60 * len(domains) / max_domains, f"Fingerprinted {dom['domain']}")
        for host in hosts:
            _attach(g, domains[host], seed)

        if level < depth:
            report("pivot", 5 + 60 * len(domains) / max_domains, f"Level {level}: pivoting from {len(hosts)} domain(s)")
            for host in hosts:
                _pivot(g, domains[host], level, enqueue, safe, seed, related=interesting)
        level += 1

    report("link", 70, "Linking shared artefacts across domains")
    _cross_link(g, domains)
    _weaken_crowded_hubs(g)
    confidence = _confidence(g, seed)
    for d in domains.values():
        c = confidence.get(_node_id("domain", d["domain"]))
        d["link_confidence"] = c["level"] if c else "unlinked"
        d["link_path"] = c["path"] if c else []
        d["name_match"] = name_match(d["domain"])
        d["brand_terms"] = brand_terms
        d["intent"] = classify_intent(d)
    seed_impersonates = bool(name_match(seed))
    originals = sorted(n["label"] for n in g.nodes.values() if n["type"] == "domain" and seed_impersonates and is_brand_original(n["label"]))
    for nid, n in g.nodes.items():
        if n["type"] == "domain":
            c = confidence.get(nid)
            n["data"]["confidence"] = c["level"] if c else "unlinked"
            n["data"]["profiled"] = n["label"] in domains
            if n["label"] in originals:
                n["data"]["role"] = "impersonated brand"
            if n["label"] in domains and (domains[n["label"]].get("page") or {}).get("title"):
                n["data"]["title"] = domains[n["label"]]["page"]["title"]

    report("profile", 80, "Building the operator profile")
    clones = _clones(g, domains, seed)
    seed_dom = domains.get(seed) or {}
    seed_blocked = (seed_dom.get("live_page") or seed_dom.get("page") or {}).get("blocked")
    seed_legit = not any(i["intent"] != "staged" for i in seed_dom.get("intent") or []) and not seed_impersonates and \
        not seed_blocked and ((seed_dom.get("rdap") or {}).get("age_days") or 0) > 365
    clone_hosts = {c["domain"] for c in clones}
    cluster = [d for d in domains.values() if d["link_confidence"] in ("seed", "high", "medium")
               and not (seed_legit and d["domain"] in clone_hosts)      # a legitimate site's copy-cats are a different actor
               and d["domain"] not in originals]                       # the impersonated brand is the victim
    actor = _profile_actor(cluster, seed, keywords)
    actor["clones"] = [] if originals else clones
    actor["impersonated_originals"] = originals
    snap = seed_dom.get("page") if (seed_dom.get("page") or {}).get("via") == "urlscan" else None
    if actor["mode"] != "malicious":
        if seed_impersonates:
            actor["mode"] = "suspicious"
        elif actor["mode"] == "legitimate" and not seed_legit:
            actor["mode"] = "unclear"
    nm = name_match(seed) or {}
    if actor["mode"] in ("malicious", "suspicious") and nm:
        where = "subdomain" if nm.get("where") == "subdomain" else "domain name"
        parts = [f"{seed} imitates '{nm['keyword']}' in its {where} on {seed_root}, a domain the brand does not own."]
        if seed_blocked:
            parts.append(f"The live page is hidden behind {seed_blocked}, so it could not be inspected directly.")
        if snap and snap.get("title"):
            parts.append(f"URLScan's public scan of {snap.get('observed')} shows the page titled “{snap['title']}”.")
        if originals:
            parts.append(f"Impersonated original: {', '.join(originals[:2])}.")
        if len(cluster) > 1:
            parts.append(f"{len(cluster)} domain(s) share its infrastructure.")
        purpose = [i for i in actor["intent"] if i["intent"] not in ("impersonation", "staged")]
        actor["purpose_confirmed"] = bool(purpose)
        if actor["mode"] == "malicious" and purpose:
            parts.append(f"Verdict: brand impersonation used for {purpose[0]['label'].lower()}.")
        elif actor["mode"] == "malicious":
            parts.append("Verdict: brand impersonation (the page carries the brand's name). Its purpose (credential theft, fraud, "
                         "or e.g. an unauthorised staging copy) is not confirmed: no form or kit was observed. Review the scan in a sandbox.")
        else:
            parts.append("Verdict: suspected impersonation, content not confirmed: check it in a sandboxed browser.")
        actor["summary"] = " ".join(parts)
    elif seed_blocked and actor["mode"] == "unclear":
        actor["summary"] = f"{seed} hides its content behind {seed_blocked}; no verdict on intent without a snapshot. " + actor["summary"]
    if actor["mode"] == "legitimate":
        actor["summary"] = (f"No malicious behaviour was observed on {seed} or the {max(0, len(cluster) - 1)} domain(s) sharing its "
                            f"infrastructure: this looks like a legitimate organisation's estate (same certificate, servers or name servers). "
                            + (f"{len(actor['clones'])} other site(s) copy its page title / favicon / layout and should be reviewed as possible impersonation."
                               if actor["clones"] else "No copies of its pages were found on other infrastructure."))
    report("predict", 88, "Checking predicted next domains in DNS")
    actor["predictions"]["next_domains"] = _predict_domains(cluster, actor, set(domains) | {n["label"] for n in g.nodes.values() if n["type"] == "domain"}, safe)

    source_events.record_many(errors, "Infrastructure", target=seed)
    report("done", 100, "Investigation complete")
    out_domains = []
    for d in sorted(domains.values(), key=lambda d: (-{"seed": 5, "high": 4, "medium": 3, "low": 2, "unlinked": 1}[d["link_confidence"]], d["domain"])):
        page = d.get("page") or {}
        out_domains.append({
            "domain": d["domain"], "root": d["root"], "depth": d["depth"], "discovered_via": d["discovered_via"],
            "link_confidence": d["link_confidence"], "link_path": d["link_path"], "dns": d["dns"], "dns_status": d["dns_status"],
            "rdap": d.get("rdap"), "ip_owner": d.get("ip_owner"), "asn": d.get("asn"), "cert": d.get("cert"),
            "title": page.get("title", ""), "http_status": page.get("status"), "final_url": page.get("final_url"),
            "blocked": (d.get("live_page") or {}).get("blocked") or page.get("blocked"),
            "page_via": page.get("via"), "observed": page.get("observed"), "scan_url": page.get("scan_url"),
            "name_match": d.get("name_match"),
            "server": page.get("server", ""), "artifacts": page.get("artifacts", {}), "signals": page.get("signals", {}),
            "favicon": page.get("favicon"), "intent": d["intent"],
        })
    return {
        "seed": seed, "seed_root": seed_root, "depth": depth, "keywords": keywords,
        "nodes": list(g.nodes.values()), "edges": list(g.edges.values()), "domains": out_domains, "actor": actor,
        "stats": {
            "domains_profiled": len(domains), "nodes": len(g.nodes), "edges": len(g.edges),
            "linked_high": sum(1 for d in domains.values() if d["link_confidence"] == "high"),
            "linked_medium": sum(1 for d in domains.values() if d["link_confidence"] == "medium"),
            "linked_low": sum(1 for d in domains.values() if d["link_confidence"] == "low"),
            "elapsed_sec": round(time.time() - t0, 1),
        },
        "sources": [{"source": k, "calls": v} for k, v in sources_used.most_common()],
        "errors": errors[:40],
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "disclaimer": ("Links and the operator profile are evidence-based assessments, not proof of identity. "
                       "Who is behind the infrastructure is shown only from public data."),
    }


def _attach(g: _Graph, dom: Dict[str, Any], seed: str) -> None:
    """Infrastructure nodes for one fingerprinted domain."""
    host = dom["domain"]
    page = dom.get("page") or {}
    rd = dom.get("rdap") or {}
    dn = g.node("domain", host, title=page.get("title"), status=dom["dns_status"], seed=host == seed,
                created=(rd.get("created") or "")[:10], intent=[i["label"] for i in classify_intent(dom)])
    for i, ip in enumerate(dom["dns"].get("a", [])[:4]):
        owner = (dom.get("ip_owner") or {}) if i == 0 else {}
        ipn = g.node("ip", ip, org=owner.get("org") or owner.get("network"), country=owner.get("country"))
        g.edge(dn, ipn, "resolves to", "medium", f"{host} resolves to {ip}", "DNS")
        if i == 0 and dom.get("asn"):
            asn = dom["asn"]
            an = g.node("asn", asn["asn"], label=f"{asn['asn']} {asn.get('as_name', '')[:28]}".strip(), country=asn.get("country"))
            g.edge(ipn, an, "announced by", "weak", f"{ip} is announced by {asn['asn']}", "Team Cymru")
    for ns in dom["dns"].get("ns", [])[:4]:
        mainstream = any(m in ns for m in MAINSTREAM_NS) or is_parked_ns([ns])
        nn = g.node("ns", ns, mainstream=mainstream)
        g.edge(dn, nn, "name server", "weak" if mainstream else "medium", f"{host} uses name server {ns}", "DNS")
    if rd.get("registrar"):
        g.edge(dn, g.node("registrar", rd["registrar"]), "registered via", "weak", f"registrar {rd['registrar']}", "RDAP")
    reg = rd.get("registrant") or {}
    if reg and not reg.get("redacted"):
        who = reg.get("email") or reg.get("org") or reg.get("name")
        if who:
            g.edge(dn, g.node("registrant", who.lower(), label=who, country=reg.get("country")), "registered by", "strong",
                   f"public registrant: {who}", "RDAP")
    cert = dom.get("cert") or {}
    sans = cert.get("san") or []
    if sans and (cert.get("san_count") or len(sans)) <= 25 and not (cert.get("subject_cn") or "").endswith("cloudflaressl.com"):
        cn = g.node("cert", f"{cert.get('subject_cn') or host}|{cert.get('not_before', '')}", label=f"TLS {cert.get('subject_cn') or host}",
                    issuer=cert.get("issuer_org"), not_before=cert.get("not_before"), sans=len(sans))
        g.edge(dn, cn, "serves certificate", "strong", f"certificate for {', '.join(sans[:3])}", "TLS")
    fav = page.get("favicon") or {}
    if fav.get("sha256"):
        g.edge(dn, g.node("favicon", fav["sha256"], label=f"favicon {fav.get('mmh3')}", mmh3=fav.get("mmh3")),
               "same favicon", "medium", f"favicon mmh3 {fav.get('mmh3')}", "page")
    art = page.get("artifacts") or {}
    # Actor-specific artefacts (exfil bot, chat id, wallet, collection host) are strong. Analytics IDs, Telegram
    # handles and e-mails are medium: a cloned page often carries the impersonated BRAND's own values.
    for kind, rel, strength in (("analytics", "analytics ID", "medium"), ("telegram_bots", "Telegram exfil bot", "strong"),
                                ("telegram_handles", "Telegram handle", "medium"), ("wallets", "crypto wallet", "strong"),
                                ("emails", "contact e-mail", "medium"), ("exfil_hosts", "posts data to", "strong"),
                                ("telegram_chats", "Telegram chat id", "strong")):
        for v in art.get(kind, [])[:6]:
            g.edge(dn, g.node(kind.rstrip("s") if kind != "analytics" else "analytics", v), rel, strength, f"{rel}: {v}", "page")


def _pivot(g: _Graph, dom: Dict[str, Any], level: int, enqueue: Callable[..., None], safe: Callable[..., Any], seed: str,
           related: Callable[[str], bool] = lambda h: True) -> None:
    """Search every fingerprint for other domains; strong pivots are always expanded, weak ones only if the name fits."""
    host, root = dom["domain"], dom["root"]

    def first(kind: str, value: str) -> bool:
        """Each root / IP / name server / favicon / title is searched once per investigation, however many domains share it."""
        key = (kind, value)
        if key in g.pivoted:
            return False
        g.pivoted.add(key)
        return True
    dn = _node_id("domain", host)
    nxt = level + 1
    shared_root = any(root.endswith(f) or root == f for f in FREE_HOSTING)

    # certificate SANs: issued together = same owner
    cert = dom.get("cert") or {}
    if cert.get("san") and (cert.get("san_count") or 0) <= 25:
        for name in cert["san"]:
            if registrable_domain(name) != root or name != host:
                h = normalize_host(name)
                if h and h != host:
                    g.edge(dn, g.node("domain", h), "same TLS certificate", "strong", f"{host} and {h} share one certificate", "TLS")
                    enqueue(h, nxt, f"SAN of {host}'s certificate", force=True)

    # siblings under the same registered domain (attacker-owned roots only)
    if not shared_root and first("root", root):
        ct = safe("crt.sh", lambda: crtsh_search(root, max_hosts=200), {"hosts": {}})
        for h, meta in list((ct or {}).get("hosts", {}).items())[:40]:
            if registrable_domain(h) == root and h != host:
                g.edge(dn, g.node("domain", h, first_seen=meta.get("first_seen")), "same registered domain", "strong",
                       f"both under {root} (certificate {meta.get('first_seen', '')})", "crt.sh")
                enqueue(h, nxt, f"sibling under {root} (crt.sh)", force=True)
        rows = safe("OTX passive DNS", lambda: otx_passive_dns(root, limit=150), [])
        for r in (rows or [])[:60]:
            h = r["hostname"]
            if registrable_domain(h) == root and h != host:
                g.edge(dn, g.node("domain", h), "same registered domain", "strong", f"both under {root} (passive DNS)", "OTX")
                enqueue(h, nxt, f"sibling under {root} (passive DNS)", force=True)
            if r.get("record_type") == "A" and r.get("address") and re.match(r"^\d+\.\d+\.\d+\.\d+$", r["address"]):
                src = dn if h == host else g.node("domain", h)
                g.edge(src, g.node("ip", r["address"]), "historically resolved to", "weak",
                       f"{h} -> {r['address']} ({r.get('last', '')})", "OTX")

    # same IP
    for ip in dom["dns"].get("a", [])[:2]:
        if not first("ip", ip):
            continue
        co = safe("HackerTarget reverse IP", lambda: hackertarget_reverse_ip(ip, limit=120), []) or []
        us = safe("URLScan", lambda: urlscan_search(f'ip:"{ip}"', size=60), []) or []
        hosts = list(dict.fromkeys(co + [h["host"] for h in us if h.get("host")]))
        # Free sources return capped samples: a full page of results means "many", whatever the unique count.
        sampled = len(us) >= 60 or len(co) >= 120
        cohosted = max(len(hosts), MASS_HOSTING_COHOSTS + 1) if sampled else len(hosts)
        strength = "weak" if cohosted > MASS_HOSTING_COHOSTS else "medium"
        g.nodes.get(_node_id("ip", ip), {}).get("data", {}).update(cohosted=cohosted)
        for h in hosts[:30]:
            if h == host:
                continue
            # On shared hosting only name-related neighbours become nodes; the rest is just the count on the IP node.
            if strength == "weak" and not related(h):
                continue
            g.edge(g.node("domain", h), _node_id("ip", ip), "resolves to", strength,
                   f"co-hosted on {ip} ({len(hosts)} domains there)", "reverse IP")
            enqueue(h, nxt, f"co-hosted on {ip}", force=strength == "medium" and not shared_root)

    page = dom.get("page") or {}
    fav = page.get("favicon") or {}
    if fav.get("sha256") and first("favicon", fav["sha256"]):
        hits = safe("URLScan", lambda: urlscan_search(f"hash:{fav['sha256']}", size=100), []) or []
        hosts = {h["host"] for h in hits if h.get("host")} - {host}
        if 0 < len(hosts) <= GENERIC_HASH_HITS:
            fn = _node_id("favicon", fav["sha256"])
            for h in list(hosts)[:40]:
                g.edge(g.node("domain", h), fn, "same favicon", "medium", f"serves the same favicon ({fav.get('mmh3')})", "URLScan")
                enqueue(h, nxt, f"same favicon as {host}")
    title = (page.get("title") or "").strip()
    if len(title) >= 10 and '"' not in title and first("title", title.lower()):
        hits = safe("URLScan", lambda: urlscan_search(f'page.title:"{title}"', size=100), []) or []
        hosts = {h["host"] for h in hits if h.get("host")} - {host}
        if 0 < len(hosts) <= GENERIC_HASH_HITS:
            tn = g.node("title", title.lower()[:120], label=f"“{title[:40]}”")
            g.edge(dn, tn, "page title", "medium", title, "page")
            for h in list(hosts)[:30]:
                g.edge(g.node("domain", h), tn, "page title", "medium", f"identical title “{title[:60]}”", "URLScan")
                enqueue(h, nxt, f"same page title as {host}")
    for ns in dom["dns"].get("ns", [])[:2]:
        if any(m in ns for m in MAINSTREAM_NS) or is_parked_ns([ns]) or not first("ns", ns):
            continue
        shared = safe("HackerTarget shared DNS", lambda: hackertarget_shared_dns(ns, limit=400), []) or []
        popular = len(shared) > POPULAR_NS_DOMAINS
        g.nodes.get(_node_id("ns", ns), {}).get("data", {}).update(shared_by=len(shared), mainstream=popular or None)
        for h in shared[:60]:
            if h == host or (popular and not related(h)):
                continue  # a provider's name server: only name-related neighbours are worth a node
            g.edge(g.node("domain", h), _node_id("ns", ns), "name server", "weak" if popular else "medium",
                   f"also uses name server {ns} ({len(shared)} domains on it)", "HackerTarget")
            enqueue(h, nxt, f"shares name server {ns}", force=not popular and len(shared) <= 20)


def _cross_link(g: _Graph, domains: Dict[str, Dict[str, Any]]) -> None:
    """Kit similarity: pages built from the same HTML skeleton are the same kit (and often the same operator)."""
    items = [(h, (d.get("page") or {}).get("shingles") or set()) for h, d in domains.items()]
    items = [(h, s) for h, s in items if len(s) >= 25]
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            a, sa = items[i]
            b, sb = items[j]
            sim = len(sa & sb) / max(1, len(sa | sb))
            if sim >= 0.8:
                g.edge(_node_id("domain", a), _node_id("domain", b), "same phishing kit", "strong" if sim >= 0.9 else "medium",
                       f"{int(sim * 100)}% identical page structure", "page")
    for d in domains.values():
        (d.get("page") or {}).pop("shingles", None)


def _weaken_crowded_hubs(g: _Graph) -> None:
    """Every edge into a crowded hub (mass-hosting IP) is weak evidence, whichever pivot created it."""
    for e in g.edges.values():
        for end in (e["source"], e["target"]):
            n = g.nodes.get(end) or {}
            crowded = (n.get("type") == "ip" and (n.get("data", {}).get("cohosted") or 0) > MASS_HOSTING_COHOSTS) or                 (n.get("type") == "ns" and (n.get("data", {}).get("shared_by") or 0) > POPULAR_NS_DOMAINS)
            if crowded and e["strength"] != "weak":
                e["strength"] = "weak"
                e["evidence"] = (e["evidence"] + " (shared infrastructure: weak evidence)")[:200]


def _confidence(g: _Graph, seed: str) -> Dict[str, Dict[str, Any]]:
    """
    Widest-path confidence from the seed: a domain is as strongly linked as the WEAKEST hop on its STRONGEST chain.
    Weak hops (mass hosting, mainstream DNS, registrar) can never make a domain more than 'low'.
    """
    adj: Dict[str, List[Tuple[str, int, Dict[str, Any]]]] = {}
    for e in g.edges.values():
        w = STRENGTH[e["strength"]]
        adj.setdefault(e["source"], []).append((e["target"], w, e))
        adj.setdefault(e["target"], []).append((e["source"], w, e))
    start = _node_id("domain", seed)
    best: Dict[str, Tuple[int, int, List[str]]] = {start: (9, 0, [])}
    frontier = [start]
    while frontier:
        frontier.sort(key=lambda n: (-best[n][0], best[n][1]))
        cur = frontier.pop(0)
        cw, hops, path = best[cur]
        if hops >= 6:
            continue
        for nb, w, e in adj.get(cur, []):
            node = g.nodes.get(nb) or {}
            # generic hubs carry no attribution: don't walk THROUGH them
            if node.get("type") in ("registrar", "asn") or (node.get("type") == "ns" and node.get("data", {}).get("mainstream")):
                continue
            nw = min(cw, w)
            step = e["evidence"] if e["evidence"].lower().startswith(e["relation"].lower()) else f"{e['relation']}: {e['evidence']}"
            cand = (nw, hops + 1, path + [step])
            if nb not in best or (cand[0], -cand[1]) > (best[nb][0], -best[nb][1]):
                best[nb] = cand
                frontier.append(nb)
    names = {9: "seed", 3: "high", 2: "medium", 1: "low"}
    return {n: {"level": names[w], "path": p[:4]} for n, (w, _, p) in best.items() if n.startswith("domain:")}


CLONE_RELATIONS = {"page title", "same favicon", "same phishing kit"}


def _clones(g: _Graph, domains: Dict[str, Dict[str, Any]], seed: str) -> List[Dict[str, Any]]:
    """
    Sites that copy the seed's page (identical title, favicon or HTML skeleton) from a DIFFERENT registered domain
    that shares none of its certificate. For a legitimate seed these are the impersonators.
    """
    seed_root = registrable_domain(seed) or seed
    seed_ids = {_node_id("domain", seed)}
    hub_ids = set()
    for e in g.edges.values():
        if e["relation"] in CLONE_RELATIONS and (e["source"] in seed_ids or e["target"] in seed_ids):
            hub_ids.add(e["target"] if e["source"] in seed_ids else e["source"])
    owned_cert = {e["target"] if e["source"] in seed_ids else e["source"] for e in g.edges.values()
                  if e["relation"] in ("same TLS certificate", "serves certificate") and (e["source"] in seed_ids or e["target"] in seed_ids)}
    out: Dict[str, Dict[str, Any]] = {}
    for e in g.edges.values():
        if e["relation"] not in CLONE_RELATIONS:
            continue
        for a, b in ((e["source"], e["target"]), (e["target"], e["source"])):
            if (a in hub_ids or a in seed_ids) and b.startswith("domain:") and b not in seed_ids and b not in owned_cert:
                host = b.split(":", 1)[1]
                if (registrable_domain(host) or host) == seed_root:
                    continue
                d = domains.get(host) or {}
                rec = out.setdefault(host, {"domain": host, "root": registrable_domain(host) or host, "evidence": [],
                                            "live": bool((d.get("page") or {}).get("status")), "profiled": host in domains})
                if e["evidence"] not in rec["evidence"]:
                    rec["evidence"].append(e["evidence"])
    return sorted(out.values(), key=lambda r: (not r["live"], r["domain"]))[:40]


def _top(counter: Counter, n: int = 4) -> List[Dict[str, Any]]:
    return [{"value": k, "count": v} for k, v in counter.most_common(n) if k]


def _profile_actor(cluster: List[Dict[str, Any]], seed: str, keywords: List[str]) -> Dict[str, Any]:
    """Evidence-based operator profile of the linked cluster (seed + high/medium links)."""
    lures = set(get_lure_words())
    tlds, registrars, asns, countries, issuers, hosting = Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
    tokens, brands, intents = Counter(), Counter(), Counter()
    intent_evidence: Dict[str, List[str]] = {}
    registrants, emails, tg, wallets, exfil, abuse = [], set(), set(), set(), set(), set()
    created, timeline = [], []
    patterns = Counter()
    subdomain_style = free_hosting = cloudflare = fresh = 0
    attacker_roots = {registrable_domain(d["domain"]) for d in cluster if split_host(d["domain"])[0]}
    for d in cluster:
        host, rd = d["domain"], d.get("rdap") or {}
        _, sld, tld = split_host(host)
        tlds[tld] += 1
        if rd.get("registrar"):
            registrars[rd["registrar"]] += 1
        if rd.get("abuse_email"):
            abuse.add(rd["abuse_email"])
        reg = rd.get("registrant") or {}
        if reg and not reg.get("redacted"):
            registrants.append({k: reg.get(k) for k in ("name", "org", "email", "country") if reg.get(k)} | {"domain": host})
        if (d.get("asn") or {}).get("asn"):
            asns[f"{d['asn']['asn']} {d['asn'].get('as_name', '')}".strip()] += 1
            countries[d["asn"].get("country") or ""] += 1
        owner = d.get("ip_owner") or {}
        if owner.get("abuse_email"):
            abuse.add(owner["abuse_email"])
        if owner.get("org") or owner.get("network"):
            hosting[owner.get("org") or owner.get("network")] += 1
        if (d.get("cert") or {}).get("issuer_org"):
            issuers[d["cert"]["issuer_org"]] += 1
        if any(registrable_domain(host) == f or host.endswith("." + f) for f in FREE_HOSTING):
            free_hosting += 1
        if any("cloudflare" in ns for ns in d["dns"].get("ns", [])) or "cloudflare" in str(owner.get("org") or owner.get("network") or "").lower():
            cloudflare += 1
        if split_host(host)[0] and (registrable_domain(host) or "") != seed:
            subdomain_style += 1
        for t in name_tokens(host):
            if t in KNOWN_BRANDS:
                brands[t] += 1
        # The impersonated name sits in the subdomain labels when there are any (gi-de.attacker.tech), otherwise in
        # the registered label (gi-de-wallet.top). The attacker's own root label is never a "target".
        if host in attacker_roots:
            continue  # astrobale-core.tech is where the attacker hosts brand subdomains, not a brand it targets
        for phrase in brand_phrases(host):
            if phrase not in KNOWN_BRANDS:
                tokens[phrase] += 1
        shape = "-".join("{lure}" if t in lures else ("{brand}" if (t in KNOWN_BRANDS or t in tokens) else "{word}") for t in re.split(r"[-.]", sld) if t)
        patterns[shape or "{word}"] += 1
        art = (d.get("page") or {}).get("artifacts") or d.get("artifacts") or {}
        emails.update(art.get("emails", []))
        tg.update(art.get("telegram_bots", []) + [f"@{h}" for h in art.get("telegram_handles", [])])
        wallets.update(art.get("wallets", []))
        exfil.update(art.get("exfil_hosts", []))
        for i in d.get("intent") or []:
            intents[i["intent"]] += 1
            intent_evidence.setdefault(i["intent"], []).append(f"{host}: {i['evidence']}")
        if rd.get("created"):
            created.append(rd["created"][:10])
            timeline.append({"date": rd["created"][:10], "event": f"{host} registered", "domain": host})
            if (rd.get("age_days") or 9999) <= 30:
                fresh += 1
        if (d.get("cert") or {}).get("not_before"):
            timeline.append({"date": d["cert"]["not_before"][:10], "event": f"TLS certificate issued for {host}", "domain": host})
    known_flat = {re.sub(r"[^a-z0-9]", "", t) for t in list(tokens) + list(brands)}
    for b in keywords:  # analyst-supplied targets are always listed (once, in their own spelling)
        kw = re.sub(r"[^a-z0-9-]", "", b.lower().replace("+", "-")).strip("-")
        if kw and re.sub(r"[^a-z0-9]", "", kw) not in known_flat:
            brands[kw] += 0
            known_flat.add(re.sub(r"[^a-z0-9]", "", kw))
    n = max(1, len(cluster))
    target_list = [{"value": k, "count": v} for k, v in brands.most_common(6) if v > 0] + \
                  [{"value": k, "count": v, "inferred": True} for k, v in tokens.most_common(4) if v >= 2 or len(cluster) <= 2] + \
                  [{"value": k, "count": 0, "analyst": True} for k, v in brands.items() if v == 0]
    intent_list = [{"intent": k, "label": INTENTS[k], "domains": v, "share": round(v / n, 2), "evidence": intent_evidence[k][:4]}
                   for k, v in intents.most_common()]
    style = []
    if fresh:
        style.append(f"Uses freshly registered domains ({fresh} of {len(cluster)} registered within 30 days of discovery)")
    if subdomain_style:
        style.append(f"Puts the brand in subdomains of its own domains ({subdomain_style} hostnames)")
    if free_hosting:
        style.append(f"Abuses free hosting / serverless platforms ({free_hosting} sites)")
    if cloudflare:
        style.append(f"Hides origin servers behind Cloudflare ({cloudflare} domains)")
    if tg:
        style.append("Phishing kit exfiltrates victims' data to Telegram (typical of commodity kits sold on Telegram)")
    if exfil:
        style.append(f"Forms post captured data to separate collection hosts ({', '.join(sorted(exfil)[:2])})")
    if patterns:
        style.append(f"Naming pattern: {patterns.most_common(1)[0][0]} (e.g. {cluster[0]['domain']})")
    if issuers:
        style.append(f"Certificates from {issuers.most_common(1)[0][0]}")
    attack = [{"id": "T1583.001", "name": "Acquire Infrastructure: Domains", "evidence": f"{len(cluster)} linked domains"}]
    if any(i["intent"] in ("credential_theft", "card_fraud", "crypto_fraud") for i in intent_list):
        attack.append({"id": "T1566.002", "name": "Phishing: Spearphishing Link", "evidence": "credential / payment collection pages"})
        attack.append({"id": "T1656", "name": "Impersonation", "evidence": f"targets {', '.join(t['value'] for t in target_list[:3]) or 'a brand'}"})
    if issuers:
        attack.append({"id": "T1588.004", "name": "Obtain Capabilities: Digital Certificates", "evidence": f"{sum(issuers.values())} TLS certificates"})
    if free_hosting:
        attack.append({"id": "T1583.006", "name": "Acquire Infrastructure: Web Services", "evidence": f"{free_hosting} free-hosting sites"})
    if intents.get("malware"):
        attack.append({"id": "T1608.001", "name": "Stage Capabilities: Upload Malware", "evidence": "download lures on the pages"})
    if tg:
        attack.append({"id": "T1567", "name": "Exfiltration Over Web Service", "evidence": "Telegram bot API in the kit"})
    if cloudflare:
        attack.append({"id": "T1090.004", "name": "Proxy: Domain Fronting / CDN", "evidence": "origin behind Cloudflare"})
    linked = len(cluster)
    sophistication = min(100, 10 * min(linked, 5) + 10 * min(len(asns), 3) + (15 if tg or exfil else 0) + (10 if cloudflare else 0)
                         + (10 if free_hosting else 0) + (10 if subdomain_style else 0))
    live = sum(1 for d in cluster if (d.get("page") or {}).get("status"))
    status = ("Active campaign: linked sites are live now" if live and fresh else
              "Staged infrastructure: registered but mostly not serving content yet" if not live else
              "Established infrastructure: live, not newly registered")
    top_intent = intent_list[0]["label"] if intent_list else "unclear (no content collected)"
    targets_txt = ", ".join(t["value"] for t in target_list[:3]) or "no specific brand identified"
    malicious = any(i["intent"] != "staged" for i in intent_list)
    fetched = sum(1 for d in cluster if d.get("page") and not d["page"].get("blocked") and not d["page"].get("partial"))
    mode = "malicious" if malicious else ("legitimate" if fetched else "unclear")
    if not intent_list:
        top_intent = "no malicious behaviour seen on the pages" if fetched else "unclear (no page content could be collected)"
    summary = (f"{linked} domain(s) are linked to {seed} by shared infrastructure or phishing-kit artefacts. "
               f"Most likely purpose: {top_intent.lower()}. Targets: {targets_txt}. {status}.")
    return {
        "mode": mode,
        "summary": summary,
        "status": status,
        "confidence": "high" if any(d["link_confidence"] == "high" for d in cluster) else ("medium" if linked > 1 else "single domain"),
        "sophistication": sophistication,
        "cluster_size": linked,
        "intent": intent_list,
        "targets": target_list,
        "attribution": {
            "public_registrants": registrants[:10],
            "contact_emails": sorted(emails)[:10],
            "telegram": sorted(tg)[:10],
            "wallets": sorted(wallets)[:10],
            "exfil_hosts": sorted(exfil)[:10],
            "abuse_contacts": sorted(abuse)[:10],
            "note": ("Registrant data is shown only when the registry publishes it; most registrations are privacy-protected. "
                     "Telegram bot secrets are masked: report bots to abuse@telegram.org rather than using them."),
        },
        "infrastructure": {"tlds": _top(tlds), "registrars": _top(registrars), "asns": _top(asns), "hosting": _top(hosting),
                           "countries": _top(countries), "cert_issuers": _top(issuers)},
        "style": style,
        "attack": attack,
        "timeline": sorted(timeline, key=lambda t: t["date"])[-30:],
        "predictions": {
            "likely_tlds": [t["value"] for t in _top(tlds, 3)],
            "likely_registrars": [r["value"] for r in _top(registrars, 2)],
            "likely_hosting": [h["value"] for h in _top(asns, 2)],
            "outlook": _outlook(intent_list, target_list, fresh, live, linked),
            "next_domains": [],
        },
    }


def _outlook(intents: List[Dict[str, Any]], targets: List[Dict[str, Any]], fresh: int, live: int, linked: int) -> List[str]:
    out = []
    if fresh:
        out.append("Fresh registrations: expect new lookalike domains within days, following the same naming pattern.")
    if intents and intents[0]["intent"] == "staged":
        out.append("Domains are registered but dark: activation (phishing e-mail / SMS wave) typically follows within 1-3 weeks.")
    if any(i["intent"] == "credential_theft" for i in intents):
        out.append("Harvested credentials are typically tested quickly: watch for account-takeover attempts on the targeted brand's portals.")
    if any(i["intent"] in ("card_fraud", "crypto_fraud") for i in intents):
        out.append("Expect monetisation through card testing / wallet draining shortly after each wave.")
    if targets:
        out.append(f"Likely to keep targeting {targets[0]['value']} and to reuse the same kit for further brands.")
    if linked >= 5:
        out.append("Multi-domain operation: taking down a single domain will not stop it; report the registrar / hosting cluster together.")
    return out


def _predict_domains(cluster: List[Dict[str, Any]], actor: Dict[str, Any], known: Set[str], safe: Callable[..., Any]) -> List[Dict[str, Any]]:
    """Domains the observed naming pattern predicts (brand x lure word x preferred TLDs), checked in DNS now."""
    targets = [t["value"] for t in actor["targets"][:3] if t["value"]]
    if not targets:
        return []
    observed_lures = Counter(t for d in cluster for t in name_tokens(d["domain"]) if t in set(get_lure_words()))
    lures = [w for w, _ in observed_lures.most_common(4)] + [w for w in ("login", "secure", "verify", "support", "account") if w not in observed_lures]
    tlds = actor["predictions"]["likely_tlds"][:3] or ["com"]
    names: List[str] = []
    for b in targets[:2]:
        for w in lures[:6]:
            for tld in tlds:
                for name in (f"{b}-{w}.{tld}", f"{w}-{b}.{tld}"):
                    if name not in known and name not in names:
                        names.append(name)
    names = names[:48]
    dns = safe("DNS (predictions)", lambda: resolve_domains(names, timeout=2.0), {}) or {}
    out = []
    for nme in names:
        info = dns.get(nme) or {}
        state = "registered" if info.get("registered") else ("available" if info.get("status") == "nxdomain" else "unknown")
        out.append({"domain": nme, "state": state, "resolves": bool(info.get("a") or info.get("aaaa")),
                    "note": "already registered: watch / pre-emptive takedown" if state == "registered" else "not registered yet: candidate for defensive registration"})
    out.sort(key=lambda r: (r["state"] != "registered", not r["resolves"], r["domain"]))
    return out[:24]


def iter_iocs(result: Dict[str, Any]) -> Iterable[Dict[str, str]]:
    """Flat IOC list (linked domains, IPs, artefacts) for export."""
    for d in result.get("domains", []):
        if d["link_confidence"] in ("seed", "high", "medium"):
            yield {"type": "domain", "value": d["domain"], "confidence": d["link_confidence"]}
            for ip in d["dns"].get("a", []):
                yield {"type": "ipv4", "value": ip, "confidence": d["link_confidence"]}
            for k, vals in (d.get("artifacts") or {}).items():
                if k in ("analytics", "telegram_bots", "wallets", "emails", "exfil_hosts", "telegram_handles"):
                    for v in vals:
                        yield {"type": k, "value": v, "confidence": d["link_confidence"]}


def ioc_csv(result: Dict[str, Any]) -> str:
    rows = ["type,value,confidence"] + [f"{r['type']},{r['value'].replace(',', ' ')},{r['confidence']}" for r in iter_iocs(result)]
    return "\n".join(dict.fromkeys(rows)) + "\n"

