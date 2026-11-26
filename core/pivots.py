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
from .crawler import ANALYTICS_RE
from .domains import registrable_domain
from .dorks import FREE_HOSTING, ENGINES, APP_STORES, PASTE_SITES, SOCIAL, build_urlscan_daily_queries, build_whoisxml_daily_spec
from .hasher import sha256_hash
from .platforms import build_search_url, quote_term, urlscan_exclude_clause

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


def pivot_queries(pivots: Dict[str, Any], allowlist: List[str]) -> List[Dict[str, str]]:
    """Copy-ready queries for the analytics IDs and asset hashes (with search links)."""
    out: List[Dict[str, str]] = []
    legit = allowlist[0] if allowlist else ""
    excl_u = urlscan_exclude_clause(allowlist)

    def add(platform, label, query):
        out.append({"platform": platform, "label": label, "query": query, "url": build_search_url(platform, query)})

    for gid in pivots.get("analytics", [])[:4]:
        add("fofa", f"Analytics {gid}", f'body={quote_term(gid)}' + "".join(f' && domain!="{d}"' for d in allowlist[:5]))
        add("shodan", f"Analytics {gid}", f"http.html:{quote_term(gid)}" + (f" -hostname:{legit}" if legit else ""))
        add("urlscan", f"Analytics {gid} (Pro: page text)", f"text.content:{quote_term(gid)}" + excl_u)
        out.append({
            "platform": "publicwww", "label": f"PublicWWW source match ({gid})",
            "query": f'"{gid}"', "url": f"https://publicwww.com/web/{urllib.parse.quote(f'\"{gid}\"')}/",
        })
    hashes = [a["sha256"] for a in pivots.get("assets", [])]
    if hashes:
        q = ("hash:" + hashes[0]) if len(hashes) == 1 else "hash:(" + " OR ".join(hashes) + ")"
        add("urlscan", f"Brand JS/CSS files ({len(hashes)})", q + excl_u)
    return out


# ------------------------------------------------------------------ search engine dorks
def _sites(sites: List[str]) -> str:
    return "(" + " OR ".join(f"site:{s}" for s in sites) + ")"


def _chunks(items: List[str], n: int) -> List[List[str]]:
    return [items[i:i + n] for i in range(0, len(items), n)]


def search_engine_dorks(domain: str, brand: str, tokens: List[str]) -> List[Dict[str, Any]]:
    """Grouped search-engine dorks; each has a ready link per engine (opened by the analyst, never scraped)."""
    b = quote_term(brand)
    not_own = f"-site:{domain}"
    tok = next((t for t in tokens if len(t) >= 4), brand.lower())
    groups: Dict[str, List[str]] = {
        "Impersonation pages": [
            f"intitle:{b} {not_own}",
            f"{b} (login OR \"sign in\" OR verify OR kyc OR password) {not_own}",
            f"inurl:{tok} (login OR signin OR secure OR verify) {not_own}",
            f"\"{domain}\" {not_own} -site:linkedin.com -site:wikipedia.org",
        ],
        "Free hosting & site builders": [
            f"{b} (site:workers.dev OR site:web.app OR site:vercel.app OR site:pages.dev OR site:netlify.app)",
            *[f"{b} {_sites(c)}" for c in _chunks(FREE_HOSTING, 9)],
        ],
        "Subdomain & Login Dorks": [
            f"inurl:{tok} (inurl:login OR inurl:sso OR inurl:portal) {not_own}",
            f"site:{tok}.* {not_own}",
        ],
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
    brand_titles: Optional[List[str]] = None,
) -> List[Dict[str, str]]:
    """
    Queries to run automatically: {"source", "match", "label", "query"}.
    match = favicon_hash | asset_hash | analytics | dork | hosting | daily_domain | daily_title | whoisxml_brand | whoisxml_discovery
    """
    plan: List[Dict[str, str]] = []
    legit = allowlist[0] if allowlist else ""
    excl_u = urlscan_exclude_clause(allowlist)

    def add(source, match, label, query, fallback=None):
        """fallback: a cheaper query to run when the platform plan rejects this one (see hunter.run_intel)."""
        if config.is_paid(source) and config.free_only():
            return  # free mode: paid platforms are never queried
        if query:
            plan.append({"source": source, "match": match, "label": label, "query": query, **({"fallback": fallback} if fallback else {})})

    def hash_query(hashes):
        return ("hash:" + hashes[0]) if len(hashes) == 1 else "hash:(" + " OR ".join(hashes) + ")"

    image_hashes = list(dict.fromkeys(i["sha256"] for i in icons if i.get("sha256") and i.get("kind") != "subdomain"))[:25]
    if image_hashes:
        add("urlscan", "asset_hash", "Pages loading the brand's favicon / logo images", hash_query(image_hashes) + excl_u)
    code_hashes = list(dict.fromkeys(a["sha256"] for a in pivots.get("assets", []) if a["sha256"] not in image_hashes))[:25]
    if code_hashes:
        add("urlscan", "code_hash", "Pages loading the brand's rare JS/CSS files", hash_query(code_hashes) + excl_u)

    has_urlscan_key = bool(config.get("URLSCAN_API_KEY"))
    titles_for_daily = brand_titles or [brand]
    daily_us = build_urlscan_daily_queries(tokens, titles_for_daily, allowlist, hours=24, has_key=has_urlscan_key)
    add("urlscan", "daily_domain", "Daily scan (24h): page.domain keyword match", daily_us.get("domain_query"))
    add("urlscan", "daily_title", "Daily scan (24h): page.title brand-title match", daily_us.get("title_query"))

    add("urlscan", "dork", "Lookalike domains", (dorks.get("urlscan") or {}).get("domain_wildcard"))
    add("urlscan", "subdomain_spoof", "Subdomain impersonations (keyword.*)", (dorks.get("urlscan") or {}).get("subdomain_spoof"))
    # Evaluate additional analyst tokens independently for subdomain & domain-wildcard coverage
    seen_urlscan_sub = {(dorks.get("urlscan") or {}).get("subdomain_spoof")}
    for tok in tokens[1:9]:  # every analyst keyword, not just the first few forms
        t = (tok or "").strip().lower()
        if len(t) >= 4:
            sub_q = f"page.domain:{t}*{excl_u}"  # prefix match only: a leading wildcard needs a higher URLScan plan
            if sub_q not in seen_urlscan_sub:
                seen_urlscan_sub.add(sub_q)
                add("urlscan", "subdomain_spoof", f"Keyword '{tok}': subdomain & host clones", sub_q)

    add("urlscan", "dork", "Domain / URL token match", (dorks.get("urlscan") or {}).get("url_prefix"))
    if has_urlscan_key and not config.free_only():  # substring search needs a paid URLScan plan
        add("urlscan", "dork", "All domains containing brand (key)", (dorks.get("urlscan") or {}).get("all_domains"))
    add("urlscan", "dork", "Brand in page title", (dorks.get("urlscan") or {}).get("title_spoof"))
    hosting = " OR ".join(f"page.domain:{h}" for h in FREE_HOSTING[:20])
    brand_terms = " OR ".join([f"page.title:{quote_term(brand)}"] + [f"page.domain:{t}*" for t in tokens[:6]])
    add("urlscan", "hosting", "Brand on free hosting / site builders", f"({hosting}) AND ({brand_terms})")

    # Free Search-Engine & Archive Dork Automation (Bing RSS, DuckDuckGo, Wayback CDX)
    not_own = " ".join(f"-site:{d}" for d in allowlist[:4])
    b_toks = [t for t in tokens if len(t) >= 4][:5] or [brand]
    if b_toks:
        # Prefer a concrete non-hyphenated brand title/token so Bing doesn't split "gi-de" into "gi" ("GI Tag").
        bing_brand = (
            next((t for t in (brand_titles or []) if "-" not in t and len(t) >= 4), "")
            or next((t for t in b_toks if "-" not in t and len(t) >= 5), "")
            or (brand_titles[0] if brand_titles else brand)
        )
        bing_title = f'intitle:"{bing_brand}" {not_own}'.strip()
        add("bing", "dork", f"Bing web search: cloned title for {bing_brand}", bing_title)
        clean_tok = next((t for t in b_toks if "-" not in t and len(t) >= 5), "") or next((t for t in b_toks if "-" not in t), b_toks[0])
        hosting_sites = " OR ".join(f"site:{h}" for h in ("workers.dev", "vercel.app", "pages.dev", "netlify.app", "web.app"))
        bing_sub = f'"{clean_tok}" ({hosting_sites}) {not_own}'.strip()
        add("bing", "dork", f"Bing web search: {clean_tok} on free hosting platforms", bing_sub)
        ddg_q = f'("{brand}" OR {" OR ".join(f"inurl:{t}" for t in b_toks[:3])}) {not_own}'.strip()
        add("duckduckgo", "dork", f"DuckDuckGo search: {b_toks[0]} mentions outside official site", ddg_q)
    for tok in b_toks[:3]:
        add("wayback", "hosting", f"Wayback CDX: workers.dev pages containing '{tok}'", f"*.workers.dev/*{tok}*")

    # Optional VirusTotal discovery (runs automatically when VIRUSTOTAL_API_KEY is configured)
    if config.is_enabled("virustotal"):
        for tok in b_toks[:4]:
            add("virustotal", "dork", f"VirusTotal search for '{tok}'", tok)

    # Optional WhoisXML engine (only scheduled when a key is configured)
    if config.is_enabled("whoisxml"):
        add("whoisxml", "whoisxml_brand", "Daily newly registered / updated lookalikes & typos (Brand Alert)",
            build_whoisxml_daily_spec(tokens, allowlist, since_days=1, with_typos=True, mode="brand_alert"))
        add("whoisxml", "whoisxml_discovery", "Newly discovered domains containing brand keyword",
            build_whoisxml_daily_spec(tokens, allowlist, since_days=1, with_typos=False, mode="domain_discovery"))

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
    add("fofa", "dork", "Lookalike titles / hosts / certs", (dorks.get("fofa") or {}).get("master"),
        fallback=(dorks.get("fofa") or {}).get("domain_wildcard"))
    censys_dork = (dorks.get("censys") or {}).get("master") or (dorks.get("censys") or {}).get("title_spoof")
    add("censys", "dork", "Lookalike titles / hosts / certs", censys_dork)

    # Analytics-ID pivots (cloned kits keep the brand's tracking code)
    for gid in pivots.get("analytics", [])[:2]:
        add("shodan", "analytics", f"HTML contains {gid}", f"http.html:{quote_term(gid)}" + (f" -hostname:{legit}" if legit else ""))
        add("fofa", "analytics", f"Body contains {gid}", f"body={quote_term(gid)}" + "".join(f' && domain!="{d}"' for d in allowlist[:5]))
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
