"""
Pivots beyond the favicon:

  extract_asset_pivots()  brand-unique JS / CSS file hashes + analytics IDs from the homepage
  pivot_queries()         platform queries for those pivots (cloned kits keep them)
  search_engine_dorks()   Google / Bing / DuckDuckGo / Yandex dorks: impersonation pages, free hosting,
                          social, app stores, fake recruitment / helplines, paste & code leaks
  build_intel_plan()      the queries the hunt runs automatically on each configured platform
"""

import re
import urllib.parse
from typing import Any, Dict, List, Optional

from bs4 import BeautifulSoup

from . import config
from .domains import registrable_domain
from .hasher import sha256_hash
from .platforms import build_search_url

MAX_ASSETS = 6
MAX_ASSET_BYTES = 3 * 1024 * 1024

# Third-party / framework files are identical on millions of sites: never pivot on them.
GENERIC_ASSET_RE = re.compile(
    r"(jquery|bootstrap|react|vue|angular|lodash|polyfill|modernizr|gtag|gtm\.js|analytics|recaptcha|wp-includes|"
    r"wp-emoji|font-?awesome|swiper|slick|owl\.carousel|select2|moment|axios|underscore|popper|aos\.|gsap|"
    r"cookie|onetrust|hotjar|clarity|tag-?manager|chunk-vendors|vendor|runtime|webpack|cdn-cgi|"
    r"captcha|datadog|sentry|newrelic|nr-loader|segment|optimizely|launch-|satellite|adobe|akamai|tealium|"
    r"utag|qualtrics|zendesk|intercom|hubspot|osano|trustarc|consent)",
    re.I,
)
ANALYTICS_RE = re.compile(r"\b(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{8,12}|GTM-[A-Z0-9]{5,9}|AW-\d{8,12})\b")

FREE_HOSTING = [
    "pages.dev", "workers.dev", "r2.dev", "netlify.app", "vercel.app", "web.app", "firebaseapp.com", "github.io",
    "gitlab.io", "herokuapp.com", "onrender.com", "glitch.me", "replit.app", "repl.co", "blogspot.com",
    "wordpress.com", "wixsite.com", "weebly.com", "webflow.io", "square.site", "godaddysites.com", "framer.app",
    "carrd.co", "notion.site", "myshopify.com", "000webhostapp.com", "ngrok-free.app", "ngrok.io", "azurewebsites.net",
    "web.core.windows.net", "s3.amazonaws.com", "ipfs.io", "dweb.link", "surge.sh", "fly.dev", "translate.goog",
    "trycloudflare.com", "canva.site", "duckdns.org", "ddns.net",
]
SOCIAL = ["facebook.com", "instagram.com", "x.com", "twitter.com", "t.me", "linkedin.com", "youtube.com", "tiktok.com", "whatsapp.com"]
APP_STORES = ["play.google.com", "apps.apple.com", "apkpure.com", "apkcombo.com", "uptodown.com", "apkmirror.com"]
PASTE_SITES = ["pastebin.com", "paste.ee", "justpaste.it", "rentry.co", "ghostbin.site", "controlc.com"]

ENGINES = {
    "google": "https://www.google.com/search?q={}",
    "bing": "https://www.bing.com/search?q={}",
    "duckduckgo": "https://duckduckgo.com/?q={}",
    "yandex": "https://yandex.com/search/?text={}",
}


# ------------------------------------------------------------------ brand pivots
def extract_asset_pivots(soup: Optional[BeautifulSoup], page_url: str, allowlist: List[str], crawler, max_assets: int = MAX_ASSETS) -> Dict[str, Any]:
    """SHA-256 of the brand's own (non-library) JS / CSS files, plus analytics IDs in the HTML."""
    out: Dict[str, Any] = {"analytics": [], "assets": []}
    if soup is None:
        return out
    out["analytics"] = sorted(set(ANALYTICS_RE.findall(str(soup))))
    urls: List[str] = []
    for tag, attr, kind in (("script", "src", "js"), ("link", "href", "css")):
        for el in soup.find_all(tag):
            if tag == "link" and "stylesheet" not in [r.lower() for r in (el.get("rel") or [])]:
                continue
            val = (el.get(attr) or "").strip()
            if not val or val.startswith("data:"):
                continue
            absu = urllib.parse.urljoin(page_url, val)
            host = urllib.parse.urlparse(absu).hostname or ""
            if registrable_domain(host) not in allowlist or GENERIC_ASSET_RE.search(absu):
                continue
            if absu not in urls:
                urls.append(absu)
    for u in urls[: max_assets * 2]:
        if len(out["assets"]) >= max_assets:
            break
        res = crawler._safe_get(u, max_bytes=MAX_ASSET_BYTES)
        if res is None or res.status != 200 or len(res.content) < 512 or len(res.content) >= MAX_ASSET_BYTES:
            continue  # tiny files are often shared stubs; truncated files would hash wrong
        if res.looks_like_html():
            continue
        out["assets"].append({"url": u, "sha256": sha256_hash(res.content), "size": len(res.content),
                              "type": "css" if u.split("?")[0].endswith(".css") else "js"})
    return out


def _q(v: str) -> str:
    return '"' + v.replace('"', '\\"') + '"'


def _urlscan_exclude(allowlist: List[str]) -> str:
    own = allowlist[:10]
    if not own:
        return ""
    return " AND NOT page.apexDomain:" + (f"({' OR '.join(own)})" if len(own) > 1 else own[0])


def pivot_queries(pivots: Dict[str, Any], allowlist: List[str]) -> List[Dict[str, str]]:
    """Copy-ready queries for the analytics IDs and asset hashes (with search links)."""
    out: List[Dict[str, str]] = []
    legit = allowlist[0] if allowlist else ""

    def add(platform, label, query):
        out.append({"platform": platform, "label": label, "query": query, "url": build_search_url(platform, query)})

    for gid in pivots.get("analytics", [])[:4]:
        add("fofa", f"Analytics {gid}", f'body={_q(gid)}' + "".join(f' && domain!="{d}"' for d in allowlist[:5]))
        add("shodan", f"Analytics {gid}", f"http.html:{_q(gid)}" + (f" -hostname:{legit}" if legit else ""))
        add("urlscan", f"Analytics {gid} (Pro: page text)", f"text.content:{_q(gid)}" + _urlscan_exclude(allowlist))
    hashes = [a["sha256"] for a in pivots.get("assets", [])]
    if hashes:
        q = ("hash:" + hashes[0]) if len(hashes) == 1 else "hash:(" + " OR ".join(hashes) + ")"
        add("urlscan", f"Brand JS/CSS files ({len(hashes)})", q + _urlscan_exclude(allowlist))
    return out


# ------------------------------------------------------------------ search engine dorks
def _sites(sites: List[str]) -> str:
    return "(" + " OR ".join(f"site:{s}" for s in sites) + ")"


def _chunks(items: List[str], n: int) -> List[List[str]]:
    return [items[i:i + n] for i in range(0, len(items), n)]


def search_engine_dorks(domain: str, brand: str, tokens: List[str]) -> List[Dict[str, Any]]:
    """Grouped search-engine dorks; each has a ready link per engine (opened by the analyst, never scraped)."""
    b = _q(brand)
    not_own = f"-site:{domain}"
    tok = next((t for t in tokens if len(t) >= 4), brand.lower())
    groups: Dict[str, List[str]] = {
        "Impersonation pages": [
            f"intitle:{b} {not_own}",
            f"{b} (login OR \"sign in\" OR verify OR kyc OR password) {not_own}",
            f"inurl:{tok} (login OR signin OR secure OR verify) {not_own}",
            f"\"{domain}\" {not_own} -site:linkedin.com -site:wikipedia.org",
        ],
        "Free hosting & site builders": [f"{b} {_sites(c)}" for c in _chunks(FREE_HOSTING, 9)],
        "Fake recruitment & helplines": [
            f"{b} (\"offer letter\" OR \"job offer\" OR recruitment OR \"registration fee\") {not_own}",
            f"{b} (\"customer care number\" OR helpline OR \"toll free\" OR refund) {not_own}",
            f"{b} (investment OR \"guaranteed returns\" OR trading OR crypto) {not_own}",
        ],
        "Social & messaging": [f"{b} {_sites(SOCIAL)}"],
        "Mobile apps": [f"{b} {_sites(APP_STORES)}"],
        "Paste & code leaks": [
            f"\"{domain}\" {_sites(PASTE_SITES)}",
            f"\"{domain}\" site:github.com (password OR secret OR token OR apikey)",
            f"\"@{domain}\" (password OR passwd) (filetype:txt OR filetype:csv OR filetype:xlsx OR filetype:sql)",
        ],
    }
    out = []
    for group, queries in groups.items():
        for q in queries:
            out.append({"group": group, "query": q,
                        "links": {e: tpl.format(urllib.parse.quote_plus(q)) for e, tpl in ENGINES.items()}})
    return out


# ------------------------------------------------------------------ automatic intel plan
def build_intel_plan(
    combined_hash_queries: Dict[str, str],
    icons: List[Dict[str, Any]],
    pivots: Dict[str, Any],
    dorks: Dict[str, Dict[str, str]],
    allowlist: List[str],
    brand: str,
    tokens: List[str],
) -> List[Dict[str, str]]:
    """
    Queries to run automatically: {"source", "match", "label", "query"}.
    match = favicon_hash | asset_hash | analytics | dork | hosting
    """
    plan: List[Dict[str, str]] = []
    legit = allowlist[0] if allowlist else ""
    excl_u = _urlscan_exclude(allowlist)

    def add(source, match, label, query):
        if query:
            plan.append({"source": source, "match": match, "label": label, "query": query})

    # URLScan indexes the hash of every response a scanned page loads. Images (favicon, logo) are brand-specific
    # by nature: a strong signal. JS/CSS files are queried separately and score weakly, because themes and
    # plugins (WordPress, Wix, ...) ship the same files to thousands of unrelated sites.
    def hash_query(hashes):
        return ("hash:" + hashes[0]) if len(hashes) == 1 else "hash:(" + " OR ".join(hashes) + ")"

    image_hashes = list(dict.fromkeys(i["sha256"] for i in icons if i.get("sha256") and i.get("kind") != "subdomain"))[:25]
    if image_hashes:
        add("urlscan", "asset_hash", "Pages loading the brand's favicon / logo images", hash_query(image_hashes) + excl_u)
    code_hashes = list(dict.fromkeys(a["sha256"] for a in pivots.get("assets", []) if a["sha256"] not in image_hashes))[:25]
    if code_hashes:
        add("urlscan", "code_hash", "Pages loading the brand's rare JS/CSS files", hash_query(code_hashes) + excl_u)
    add("urlscan", "dork", "Lookalike domains", (dorks.get("urlscan") or {}).get("domain_wildcard"))
    add("urlscan", "dork", "Domain / URL token match", (dorks.get("urlscan") or {}).get("url_prefix"))
    if config.get("URLSCAN_API_KEY"):
        add("urlscan", "dork", "All domains containing brand (key)", (dorks.get("urlscan") or {}).get("all_domains"))
    add("urlscan", "dork", "Brand in page title", (dorks.get("urlscan") or {}).get("title_spoof"))
    hosting = " OR ".join(f"page.domain:{h}" for h in FREE_HOSTING[:20])
    brand_terms = " OR ".join([f"page.title:{_q(brand)}"] + [f"page.domain:{t}*" for t in tokens[:3]])
    add("urlscan", "hosting", "Brand on free hosting / site builders", f"({hosting}) AND ({brand_terms})")

    # Favicon-hash engines
    if combined_hash_queries.get("shodan"):
        add("shodan", "favicon_hash", "Servers serving the brand favicon",
            combined_hash_queries["shodan"] + (f" -hostname:{legit}" if legit else ""))
    if combined_hash_queries.get("fofa"):
        add("fofa", "favicon_hash", "Servers serving the brand favicon",
            combined_hash_queries["fofa"] + "".join(f' && domain!="{d}"' for d in allowlist[:5]))
    if combined_hash_queries.get("censys"):
        add("censys", "favicon_hash", "Hosts serving the brand favicon", combined_hash_queries["censys"])

    # Title / host / cert dorks
    add("shodan", "dork", "Brand in page title", (dorks.get("shodan") or {}).get("title_spoof"))
    add("shodan", "dork", "Lookalike TLS certificate CN", (dorks.get("shodan") or {}).get("cert_wildcard"))
    add("fofa", "dork", "Lookalike titles / hosts / certs", (dorks.get("fofa") or {}).get("master"))
    censys_dork = (dorks.get("censys") or {}).get("master") or (dorks.get("censys") or {}).get("title_spoof")
    add("censys", "dork", "Lookalike titles / hosts / certs", censys_dork)

    # Analytics-ID pivots (cloned kits keep the brand's tracking code)
    for gid in pivots.get("analytics", [])[:2]:
        add("shodan", "analytics", f"HTML contains {gid}", f"http.html:{_q(gid)}" + (f" -hostname:{legit}" if legit else ""))
        add("fofa", "analytics", f"Body contains {gid}", f"body={_q(gid)}" + "".join(f' && domain!="{d}"' for d in allowlist[:5]))
    return plan


def lens_image_urls(icons: List[Dict[str, Any]], limit: int = 2) -> List[str]:
    """Public brand images worth a reverse search: biggest logos first, then the biggest raster favicon."""
    def area(i):
        try:
            w, h = (i.get("dimensions") or "0x0").split("x")
            return int(w) * int(h)
        except ValueError:
            return 0

    cands = [i for i in icons if str(i.get("url", "")).startswith("http") and (i.get("format") or "").upper() not in ("SVG", "ICO")]
    logos = sorted((i for i in cands if i.get("kind") == "logo"), key=area, reverse=True)
    favs = sorted((i for i in cands if i.get("kind") != "logo" and area(i) >= 96 * 96), key=area, reverse=True)
    urls = [i.get("final_url") or i["url"] for i in logos[:limit] + favs[:1]]
    return list(dict.fromkeys(urls))[:limit]


# ------------------------------------------------------------------ shared-code filter
SHARED_ASSET_THRESHOLD = 200   # URLScan pages loading a file; above this it is shared code, not brand-specific


def drop_shared_assets(pivots: Dict[str, Any], count_fn, threshold: int = SHARED_ASSET_THRESHOLD) -> Dict[str, Any]:
    """
    Keeps only JS/CSS files that are rare on the web. Plugin and theme files (WordPress core, Contact Form 7,
    WPML, ...) are loaded by thousands of unrelated sites and would turn every such site into a "lookalike",
    often from renamed paths (/apps/, /my_includes/) that no path pattern can recognise. count_fn(sha256) returns
    how many scanned pages load the file. Unknown counts are treated as shared (fail closed: no junk candidates).
    """
    from concurrent.futures import ThreadPoolExecutor

    assets = pivots.get("assets", [])

    def count(a):
        try:
            return count_fn(a["sha256"])
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=3) as pool:
        counts = list(pool.map(count, assets))
    kept = [{**a, "seen_on": n} for a, n in zip(assets, counts) if n is not None and n <= threshold]
    return {**pivots, "assets": kept, "dropped_shared": len(assets) - len(kept)}
