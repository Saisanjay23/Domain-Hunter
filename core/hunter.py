"""
One-shot impersonation hunt:  brand domain  ->  ranked list of impersonating domains.

  1. Fingerprint   favicons / logos / title / analytics IDs / cert org / allowlist of own domains
  2. Generate      typosquat, homoglyph, combosquat and TLD-swap permutations
  3. CT logs       hostnames containing the brand in crt.sh
  4. DNS           which candidates exist (A / AAAA / MX / NS, wildcard aware)
  5. Verify        visit live candidates and compare them with the brand
  6. RDAP          registration age / registrar / abuse contact
  7. Score         explainable 0-100 risk score + verdict

Also returns the favicon-hash queries and impersonation dorks for manual pivoting.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

import re

from . import config, feeds
from .crawler import FaviconCrawler
from .discovery import brand_allowlist, crtsh_search, rdap_lookup, registration_lookup, resolve_domains
from .domain_matcher import classify_candidate, evaluate_domain_match, expand_analyst_keywords, keyword_search_tokens
from .pivots import FREE_HOSTING, build_intel_plan, drop_shared_assets, extract_asset_pivots, lens_image_urls, pivot_queries, search_engine_dorks
from .sources import (SEARCHERS, SourceError, hackertarget_reverse_ip, otx_passive_dns, safebrowsing_lookup, serpapi_lens,
                      urlscan_search, urlscan_total, virustotal_reputation)
from .domains import normalize_host, registrable_domain, split_host
from .dorks import extract_brand_titles
from .exporter import clean_icon_dict_for_export
from .impersonation import decompose_keyword, generate_keyword_dorks
from .keypool import POOL
from . import source_events
from .permutations import generate_permutations, permutation_stats
from .platforms import urlscan_exclude_clause
from .query_gen import generate_search_queries
from .verifier import SOURCE_NAMES, VERDICTS, build_brand_profile, defang, score_candidate, score_candidate_detailed, verify_candidate

_ORIGINAL_RDAP_LOOKUP = rdap_lookup
_FREE_BUILTINS = {"bing", "duckduckgo", "wayback"}
_SHARED_HOSTING_ROOTS = set(FREE_HOSTING) | {"github.io", "gitlab.io", "bitbucket.io", "azurewebsites.net"}

ProgressFn = Callable[[str, float, str, Dict[str, Any]], None]

MAX_RDAP = 250
LATE_RDAP = 60      # extra lookups for domains inspection revealed as risky
RDAP_WORKERS = 8
VT_ENRICH_MAX = 12     # VirusTotal's free tier allows 4 lookups/min: only the most suspicious candidates are checked
VT_ENRICH_BUDGET_S = 40
STRONG_INTEL = {"favicon_hash", "asset_hash", "analytics", "hosting", "feed", "daily_domain", "daily_title", "subdomain_spoof", "whoisxml_brand", "whoisxml_discovery"}

# Reverse image search and web search dorks often return big legitimate reference, WHOIS, review, or social
# platforms; never turn those into impersonation candidates.
LENS_IGNORE = {
    "wikipedia.org", "wikimedia.org", "wikiwand.com", "wikidata.org",
    "linkedin.com", "facebook.com", "instagram.com", "x.com", "twitter.com",
    "youtube.com", "tiktok.com", "pinterest.com", "reddit.com", "quora.com", "zhihu.com",
    "google.com", "bing.com", "duckduckgo.com", "yandex.com", "baidu.com", "msn.com",
    "amazon.com", "crunchbase.com", "bloomberg.com", "reuters.com", "forbes.com",
    "indiatimes.com", "economictimes.com", "india.com",
    "glassdoor.com", "indeed.com", "ambitionbox.com", "zoominfo.com", "tracxn.com",
    "seeklogo.com", "logo.wine", "brandfetch.com", "worldvectorlogo.com", "1000logos.net",
    "whois.com", "who.is", "scamadviser.com", "scam-detector.com", "trustpilot.com", "sitejabber.com",
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com", "stackexchange.com",
    "medium.com", "substack.com", "whatsapp.com", "wa.me", "t.me", "meta.com",
    "virustotal.com", "urlscan.io", "crt.sh", "archive.org",
}


class HuntCancelled(Exception):
    pass


def _plan_forbidden(err: Exception) -> bool:
    """The platform understood the query but this account's plan does not include it (HTTP 403 / FOFA 820001)."""
    return getattr(err, "kind", "") == "forbidden" or "plan does not allow" in str(err).lower()


def _is_skip(message: str) -> bool:
    """Outcomes that are expected and not the analyst's problem: plan limits and anti-bot challenges."""
    low = (message or "").lower()
    return "plan does not allow" in low or "challenged" in low or "no api key configured" in low


def _cheaper_query(job: Dict[str, str]) -> Optional[str]:
    """What to try when a plan rejects the query: the planner's explicit fallback, or the query minus leading wildcards."""
    if job.get("fallback"):
        return job["fallback"]
    q = job.get("query") or ""
    stripped = re.sub(r"(:)\*+", r"\1", q)  # page.domain:*x* -> page.domain:x*
    return stripped if stripped != q else None


def _enrich_safebrowsing(registered: List[Dict[str, Any]], errors: List[str]) -> int:
    """One batched Google Safe Browsing check for every plausible candidate; listed hosts get a 'safe_browsing' intel ref."""
    todo = [c for c in registered if not (c.get("match_meta") or {}).get("is_benign_collision")][:1000]
    try:
        listed = safebrowsing_lookup([c["domain"] for c in todo])
    except SourceError as e:
        errors.append(f"Google Safe Browsing: {e}")
        return 0
    for c in todo:
        types = listed.get(c["domain"])
        if types:
            c.setdefault("intel", []).append({"source": "safebrowsing", "match": "safe_browsing", "label": "Google Safe Browsing",
                                              "title": ", ".join(t.replace("_", " ").lower() for t in types), "url": None, "time": ""})
            if "safebrowsing" not in c["sources"]:
                c["sources"].append("safebrowsing")
    return len(todo)


def _enrich_virustotal(registered: List[Dict[str, Any]], errors: List[str], report: Callable[[str, float, str], None]) -> int:
    """
    Adds VirusTotal's verdict for the most suspicious candidates that no other VT query covered. Sequential and
    time-boxed on purpose (free tier: 4 requests/minute); stops at the first rate-limit / quota / auth error and
    reports it instead of failing the hunt. Only vendor flags are recorded: "VT has no detections" is not evidence
    of innocence, so a clean answer adds nothing.
    """
    def interesting(c: Dict[str, Any]) -> bool:
        mm = c.get("match_meta") or {}
        named = mm.get("technique_key") not in (None, "none", "benign_collision", "content_infrastructure")
        return (c.get("score", 0) >= 25 or named) and not mm.get("is_benign_collision")

    todo = [c for c in sorted(registered, key=lambda c: -c.get("score", 0))
            if interesting(c) and not any(i.get("source") == "virustotal" for i in c.get("intel") or [])][:VT_ENRICH_MAX]
    deadline = time.monotonic() + VT_ENRICH_BUDGET_S
    checked = 0
    for i, c in enumerate(todo):
        if time.monotonic() > deadline:
            break
        report("intel", 88 + 2 * i / max(1, len(todo)), f"VirusTotal reputation: {c['domain']}")
        try:
            hit = virustotal_reputation(c["domain"])
        except SourceError as e:
            errors.append(f"VirusTotal reputation: {e}")
            break
        except Exception as e:  # pragma: no cover - defensive
            errors.append(f"VirusTotal reputation: {e.__class__.__name__}")
            break
        checked += 1
        if hit and (hit.get("malicious_votes") or hit.get("suspicious_votes")):
            c.setdefault("intel", []).append({
                "source": "virustotal", "match": "reputation", "label": "VirusTotal domain reputation",
                "title": hit.get("title", ""), "url": hit.get("url"), "time": "",
                "malicious_votes": int(hit.get("malicious_votes") or 0),
            })
            if "virustotal" not in c["sources"]:
                c["sources"].append("virustotal")
    return checked


def _token_in(host: str, tokens: List[str]) -> bool:
    flat = host.replace("-", "")
    return any(t in host or t.replace("-", "") in flat for t in tokens)


def _hit_mentions_brand(
    hit: Dict[str, Any],
    apex: str,
    tokens: List[str],
    brand_titles: List[str],
) -> bool:
    """Return True when a search hit's title or URL explicitly names a non-ambiguous brand identifier."""
    hay = f"{hit.get('title') or ''} {hit.get('url') or ''}".lower()
    if not hay.strip():
        return False
    if apex and apex.lower() in hay:
        return True
    for bt in brand_titles:
        low = (bt or "").strip().lower()
        if len(low) >= 5 and low in hay:
            return True
    for tok in tokens:
        t = (tok or "").strip().lower()
        # Require >= 5 chars when hyphenated so "gi-de" cannot match bare "gi" inside "GI Tag".
        if len(t) >= (5 if "-" in t else 4) and re.search(rf"(?<![a-z0-9]){re.escape(t)}(?![a-z0-9])", hay):
            return True
    return False


def _is_shared_hosting(host: str) -> bool:
    h = normalize_host(host)
    return any(h == root or h.endswith("." + root) for root in _SHARED_HOSTING_ROOTS)


def _is_search_dork_false_positive(
    hit: Dict[str, Any],
    mm: Dict[str, Any],
    host: str,
    apex: str,
    tokens: List[str],
    brand_titles: List[str],
) -> bool:
    """Filter out unrelated blogs, news, directories, and fallback pages returned by search-engine RSS/HTML."""
    if mm.get("is_own_domain") or mm.get("is_benign_collision"):
        return True
    src = hit.get("source")
    tech = mm.get("technique_key")
    if tech == "none":
        if _is_shared_hosting(host):
            return not (src == "wayback" or _hit_mentions_brand(hit, apex, tokens, brand_titles))
        return True
    if mm.get("keyword_strength") == "weak" and tech not in ("exact_brand_match",):
        return not (mm.get("context_keywords") or _hit_mentions_brand(hit, apex, tokens, brand_titles))
    return False


def run_intel(plan: List[Dict[str, str]], lens_urls: List[str], cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Runs the intel plan on built-in free engines + every configured platform in parallel."""
    jobs = [p for p in plan if p["source"] in _FREE_BUILTINS or config.is_enabled(p["source"])]
    # paid sources switched off by free mode are simply not part of the run (no "skipped" noise)
    skipped = [p for p in plan if p["source"] not in _FREE_BUILTINS and not config.is_enabled(p["source"])
               and not (config.is_paid(p["source"]) and config.free_only())]
    if config.is_enabled("serpapi"):
        jobs += [{"source": "serpapi", "match": "lens", "label": "Google Lens: brand logo", "query": u} for u in lens_urls]
    elif lens_urls and not config.free_only():
        skipped.append({"source": "serpapi", "match": "lens", "label": "Google Lens: brand logo", "query": lens_urls[0]})

    hits: List[Dict[str, Any]] = []
    status: List[Dict[str, Any]] = [{**p, "count": 0, "error": "no API key configured", "ran": False} for p in skipped]

    def one(job):
        fn = serpapi_lens if job["source"] == "serpapi" else SEARCHERS[job["source"]]
        try:
            return fn(job["query"])
        except SourceError as e:
            retry = _cheaper_query(job) if _plan_forbidden(e) else None
            if not retry:
                raise
            if job["source"] == "fofa":
                POOL.reset("fofa")  # the rejected query paused the key; the cheaper one may well be allowed
            return fn(retry)

    with ThreadPoolExecutor(max_workers=6) as pool:
        futs = {pool.submit(one, j): j for j in jobs}
        for fut in as_completed(futs):
            job = futs[fut]
            entry = {**job, "count": 0, "error": None, "ran": True}
            try:
                res = fut.result()
                entry["count"] = len(res)
                for h in res:
                    hits.append({**h, "match": job["match"], "label": job["label"]})
            except SourceError as e:
                entry["error"] = str(e)
                entry["skipped"] = _is_skip(entry["error"])
            except Exception as e:  # pragma: no cover - defensive
                entry["error"] = e.__class__.__name__
            status.append(entry)
            if cancel is not None and cancel.is_set():
                break
    return {"hits": hits, "status": status}


_ORIGINAL_RUN_INTEL = run_intel


def run_hunt(
    target: str,
    depth: str = "standard",
    use_ct: bool = True,
    verify: bool = True,
    use_rdap: bool = True,
    use_intel: bool = True,
    use_feeds: bool = True,
    extra_allowlist: Optional[List[str]] = None,
    extra_keywords: Optional[List[str]] = None,
    timeout: int = 8,
    max_verify: int = 400,
    workers: int = 24,
    dns_servers: Optional[List[str]] = None,
    progress: Optional[ProgressFn] = None,
    cancel: Optional[threading.Event] = None,
) -> Dict[str, Any]:
    t0 = time.time()
    stats: Dict[str, Any] = {}
    errors: List[str] = []

    def report(stage: str, pct: float, msg: str):
        if cancel is not None and cancel.is_set():
            raise HuntCancelled()
        if progress:
            progress(stage, round(pct, 1), msg, dict(stats))

    # ------------------------------------------------------------ 1. fingerprint
    crawler = FaviconCrawler(timeout=timeout + 2, include_logos=True, probe_subdomains=False, max_workers=workers)
    domain, _ = crawler.normalize_target(target)
    domain = normalize_host(domain)
    apex = registrable_domain(domain) or domain
    report("fingerprint", 2, f"Fingerprinting {apex}: favicons, logos, title, certificate")

    scan = crawler.scan(apex)
    icons = scan["icons"]
    soup = getattr(crawler, "last_soup", None)
    final_host = normalize_host(scan.get("resolved_url") or "")
    allowlist = brand_allowlist(apex, extra=extra_allowlist, final_url_host=final_host)
    dec = decompose_keyword(apex)
    _, label, _ = split_host(apex)
    raw_keywords = [k.strip() for k in (extra_keywords or []) if k and k.strip()]
    kw_specs = expand_analyst_keywords(apex, raw_keywords)
    expanded_toks = [f for sp in kw_specs for f in sp["forms"] if len(f.replace("-", "")) >= 4]
    extra_toks = [k.lower() for k in raw_keywords if len(k.replace("+", "").replace("&", "").strip()) >= 4]
    kw_tokens = keyword_search_tokens(kw_specs, min_len=4, limit=12)  # one token per analyst keyword first
    tokens = list(dict.fromkeys([label] + kw_tokens + [t for t in dec["tokens"] if len(t) >= 4] + expanded_toks + extra_toks))
    brand_titles = extract_brand_titles(apex, soup=soup)
    brand = build_brand_profile(apex, icons, soup, allowlist, tokens)
    brand["raw_keywords"] = raw_keywords
    pivots = extract_asset_pivots(soup, scan.get("resolved_url") or f"https://{apex}/", allowlist, crawler)
    if use_intel and pivots["assets"]:
        report("fingerprint", 9, "Checking which brand JS/CSS files are rare enough to search for")
        excl = urlscan_exclude_clause(allowlist)
        pivots = drop_shared_assets(pivots, lambda sha: urlscan_total(f"hash:{sha}{excl}"))
    stats.update(brand_icons=len(icons), allowlist=len(allowlist), brand_assets=len(pivots["assets"]),
                 brand_assets_shared=pivots.get("dropped_shared", 0))
    report("fingerprint", 10, f"Brand fingerprint ready: {len(icons)} icon(s), {len(allowlist)} own domain(s)")

    # ------------------------------------------------------------ 2. generate
    perms = generate_permutations(apex, depth=depth, extra_keywords=extra_keywords)
    candidates: Dict[str, Dict[str, Any]] = {}
    for p in perms:
        candidates[p["domain"]] = {"domain": p["domain"], "unicode": p["unicode"], "fuzzer": p["fuzzer"],
                                   "sources": ["permutation"], "ct": None}
    stats.update(generated=len(perms), permutation_types=permutation_stats(perms))
    report("generate", 12, f"Generated {len(perms)} lookalike permutations")

    # ------------------------------------------------------------ 3. CT logs, phishing feeds and threat intel
    # The three sources are independent network calls: start them together and merge the results in a fixed
    # order below, so the hunt waits for the slowest one instead of the sum of all three.
    queries = generate_search_queries(icons)
    dorks_all = generate_keyword_dorks(apex)
    dorks = {p: dorks_all[p] for p in ("fofa", "censys", "urlscan", "shodan")}
    plan = build_intel_plan(queries.get("combined", {}), icons, pivots, dorks, allowlist, label, tokens, brand_titles=brand_titles)
    ct_limit = min(10, max(5, len(kw_specs) + 1))  # a hunt with 6 keywords must search all 6, not the first 5 forms
    ct_tokens = ([t for t in tokens if len(t) >= 4] or [label])[:ct_limit]

    def _ct_all():
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="hunt-ct") as ex:  # crt.sh throttles harder than 2 in parallel
            return list(ex.map(lambda tok: (tok, crtsh_search(tok)), ct_tokens))

    prefetch = ThreadPoolExecutor(max_workers=3, thread_name_prefix="hunt-prefetch")
    ct_future = prefetch.submit(_ct_all) if use_ct else None
    feeds_future = prefetch.submit(feeds.match, tokens, allowlist) if use_feeds else None
    intel_future = prefetch.submit(run_intel, plan, lens_image_urls(icons), cancel) if use_intel else None
    prefetch.shutdown(wait=False)  # lets the workers finish and exit; results are collected below

    ct_hosts_total = 0
    if use_ct:
        report("ct", 12, "Searching Certificate Transparency logs")
        for i, (tok, res) in enumerate(ct_future.result()):
            report("ct", 12 + 8 * (i + 1) / max(1, len(ct_tokens)), f"Certificate Transparency results for “{tok}”")
            if res["error"]:
                errors.append(f"CT search for '{tok}': {res['error']}")
            for host, meta in res["hosts"].items():
                reg = registrable_domain(host) or host
                if reg in allowlist:
                    continue
                ct_hosts_total += 1
                mm_ct = evaluate_domain_match(host, apex, keywords=raw_keywords, allowlist=allowlist)
                # Brand only in subdomain (e.g. gi-de.astrobale-core.tech) -> always preserve full FQDN!
                key = host if (mm_ct["is_subdomain_impersonation"] or not _token_in(reg, tokens)) else reg
                c = candidates.get(key)
                if c is None:
                    fuzzer_kind = "brand-subdomain" if mm_ct["is_subdomain_impersonation"] or key != reg else "ct-hostname"
                    c = candidates[key] = {"domain": key, "unicode": mm_ct.get("unicode", ""), "fuzzer": fuzzer_kind,
                                           "sources": [], "ct": {"hosts": [], "first_seen": meta["first_seen"],
                                                                "last_seen": meta["last_seen"], "issuer": meta["issuer"]}}
                if "crt.sh" not in c["sources"]:
                    c["sources"].append("crt.sh")
                if c["ct"] is None:
                    c["ct"] = {"hosts": [], "first_seen": meta["first_seen"], "last_seen": meta["last_seen"], "issuer": meta["issuer"]}
                if host not in c["ct"]["hosts"] and len(c["ct"]["hosts"]) < 25:
                    c["ct"]["hosts"].append(host)
                if meta["last_seen"] > (c["ct"]["last_seen"] or ""):
                    c["ct"]["last_seen"], c["ct"]["issuer"] = meta["last_seen"], meta["issuer"]
    stats.update(ct_hosts=ct_hosts_total, candidates=len(candidates))
    report("ct", 20, f"{ct_hosts_total} CT hostnames, {len(candidates)} unique candidates")

    # ------------------------------------------------------------ 3b. phishing feeds (OpenPhish, Phishing.Database)
    feed_status: List[Dict[str, Any]] = []
    if use_feeds:
        report("feeds", 20.5, "Checking phishing feeds (OpenPhish, Phishing.Database)")
        fm = feeds_future.result()
        errors.extend(fm["errors"])
        feed_status = fm["status"]
        feed_added = 0
        for h in fm["hits"]:
            key = h["host"]
            c = candidates.get(key)
            if c is None:
                c = candidates[key] = {"domain": key, "unicode": "", "fuzzer": "feed-listed", "sources": [], "ct": None}
                feed_added += 1
            if h["feed"] not in c["sources"]:
                c["sources"].append(h["feed"])
            ref = {"source": h["feed"], "match": "feed", "label": f"Listed in {h['feed_name']}", "title": "", "url": h["url"], "time": ""}
            c.setdefault("intel", [])
            if ref not in c["intel"]:
                c["intel"].append(ref)
        stats.update(feed_hits=len(fm["hits"]), feed_new=feed_added, candidates=len(candidates))
        report("feeds", 21, f"Phishing feeds: {len(fm['hits'])} listed lookalikes, {feed_added} new candidates")

    # ------------------------------------------------------------ 4. threat-intel platforms
    intel: Dict[str, Any] = {"hits": [], "status": []}
    infrastructure: Dict[str, Dict[str, Any]] = {}
    if use_intel:
        active_names = [config.SOURCES[s]["name"] for s in ("whoisxml", "shodan", "fofa", "censys", "serpapi", "virustotal") if config.is_enabled(s)]
        report("intel", 21, "Querying threat-intel platforms (URLScan, Bing, DDG, Wayback" + ("".join(f", {n}" for n in active_names)) + ")")
        intel = intel_future.result()
        added = 0
        for h in intel["hits"]:
            host = h.get("host")
            ref = {k: h.get(k) for k in ("source", "match", "label", "title", "url", "time", "malicious_votes") if h.get(k) is not None}
            if not host:
                if h.get("ip") and h["match"] in ("favicon_hash", "analytics", "asset_hash"):
                    key = f"{h['ip']}:{h.get('port') or ''}"
                    infra = infrastructure.setdefault(key, {"ip": h["ip"], "port": h.get("port"), "title": h.get("title", ""),
                                                            "org": h["extra"].get("org") or h["extra"].get("asn"),
                                                            "country": h["extra"].get("country"), "matches": []})
                    if ref not in infra["matches"]:
                        infra["matches"].append(ref)
                continue
            reg = registrable_domain(host) or host
            if reg in allowlist or (h["match"] in ("lens", "dork") and reg in LENS_IGNORE):
                continue
            mm_in = evaluate_domain_match(host, apex, keywords=raw_keywords, allowlist=allowlist)
            # Subdomain spoofs keep full host; web search dork hits stay strictly tied to matching hosts or strong signals
            if mm_in["is_subdomain_impersonation"] or (not _token_in(reg, tokens) and h["match"] != "lens"):
                key = host
            else:
                key = reg
            if h.get("source") in ("bing", "duckduckgo", "wayback") and _is_search_dork_false_positive(h, mm_in, host, apex, tokens, brand_titles):
                continue
            c = candidates.get(key)
            if c is None:
                fuzzer_name = "brand-subdomain" if mm_in["is_subdomain_impersonation"] else f"intel-{h['match']}"
                c = candidates[key] = {"domain": key, "unicode": mm_in.get("unicode", ""), "fuzzer": fuzzer_name,
                                       "sources": [], "ct": None}
                added += 1
            src = h["source"]
            if src not in c["sources"]:
                c["sources"].append(src)
            c.setdefault("intel", [])
            if ref not in c["intel"] and len(c["intel"]) < 12:
                c["intel"].append(ref)
        ran = [s for s in intel["status"] if s["ran"]]
        stats.update(intel_queries=len(ran), intel_hits=len(intel["hits"]), intel_new=added,
                     infrastructure=len(infrastructure), candidates=len(candidates))
        failed = [s for s in ran if s["error"] and not s.get("skipped")]
        # Plan limits and anti-bot challenges are visible in the query status table, not as hunt warnings.
        stats["intel_skipped"] = sum(1 for s in ran if s["error"] and s.get("skipped"))
        for s in failed:
            src_name = (config.SOURCES.get(s["source"]) or {}).get("name") or SOURCE_NAMES.get(s["source"], s["source"])
            errors.append(f"{src_name} '{s['label']}': {s['error']}")
        report("intel", 30, f"Threat intel: {len(intel['hits'])} hits from {len(ran)} queries, {added} new candidates")

    # ------------------------------------------------------------ 5. DNS
    def dns_progress(done: int, total: int):
        stats["dns_checked"] = done
        report("dns", 30 + 25 * done / max(1, total), f"DNS: checked {done}/{total} candidates")

    dns = resolve_domains(list(candidates), progress=dns_progress, cancel=cancel, nameservers=dns_servers)
    registered = []
    for name, c in candidates.items():
        info = dns.get(name) or {}
        c["dns"] = {k: info.get(k, []) for k in ("a", "aaaa", "mx", "ns")}
        c["dns_status"] = info.get("status", "unknown")
        strong_intel = any(i["match"] in STRONG_INTEL for i in c.get("intel") or [])
        if info.get("registered") or strong_intel:  # intel-confirmed kits stay listed even once taken down
            registered.append(c)
    live = [c for c in registered if c["dns"]["a"] or c["dns"]["aaaa"]]
    stats.update(registered=len(registered), live=len(live), dns_unknown=sum(1 for i in dns.values() if i.get("registered") is None))
    report("dns", 55, f"{len(registered)} registered, {len(live)} with a web address")

    # ------------------------------------------------------------ 6. verify (registration lookups run alongside)
    rdap_fn = registration_lookup if rdap_lookup is _ORIGINAL_RDAP_LOOKUP else rdap_lookup
    for c in registered:
        c["evidence"], c["rdap"] = None, None
        c["match_meta"] = evaluate_domain_match(
            c["domain"], apex, keywords=raw_keywords, allowlist=allowlist, intel=c.get("intel")
        )
        c["score"], c["verdict"], c["reasons"] = score_candidate(c, brand)  # preliminary (domain-level only)

    # RDAP + WHOIS fallback only needs the registrable domain, so start alongside verification
    by_reg: Dict[str, List[Dict[str, Any]]] = {}
    rdap_pool: Optional[ThreadPoolExecutor] = None
    rdap_futs: Dict[Any, str] = {}
    requested: set = set()
    if use_rdap and registered:
        for c in sorted(registered, key=lambda c: -c["score"]):
            by_reg.setdefault(registrable_domain(c["domain"]) or c["domain"], []).append(c)
        requested = set(list(by_reg)[:MAX_RDAP])
        rdap_pool = ThreadPoolExecutor(max_workers=RDAP_WORKERS, thread_name_prefix="hunt-rdap")
        rdap_futs = {rdap_pool.submit(rdap_fn, r): r for r in requested}

    if verify and live:
        to_verify = sorted(live, key=lambda c: (-bool(c.get("intel")), -("crt.sh" in c["sources"]), -c["score"]))[:max_verify]
        stats["verify_total"] = len(to_verify)
        done = 0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(verify_candidate, c["domain"], {**c["dns"]}, brand, crawler, timeout): c for c in to_verify}
            try:
                for fut in as_completed(futs):
                    c = futs[fut]
                    try:
                        c["evidence"] = fut.result()
                    except Exception as e:  # never let one hostile site kill the hunt
                        errors.append(f"verify {c['domain']}: {e.__class__.__name__}")
                    done += 1
                    stats["verified"] = done
                    if done % 5 == 0 or done == len(to_verify):
                        report("verify", 55 + 33 * done / len(to_verify), f"Inspecting live sites: {done}/{len(to_verify)}")
            except HuntCancelled:
                for f in futs:
                    f.cancel()
                if rdap_pool is not None:
                    rdap_pool.shutdown(wait=False, cancel_futures=True)
                raise

    # ------------------------------------------------------------ 6b. VirusTotal reputation (optional key, live hunts only)
    if use_intel and run_intel is _ORIGINAL_RUN_INTEL and registered and config.is_enabled("virustotal"):
        stats["vt_checked"] = _enrich_virustotal(registered, errors, report)
    if use_intel and run_intel is _ORIGINAL_RUN_INTEL and registered and config.is_enabled("safebrowsing"):
        report("intel", 90, "Google Safe Browsing check")
        stats["safebrowsing_checked"] = _enrich_safebrowsing(registered, errors)

    # ------------------------------------------------------------ 7. RDAP (collect)
    if rdap_pool is not None:
        for c in registered:
            c["score"], c["verdict"], c["reasons"] = score_candidate(c, brand)
        # Anything inspection revealed as risky that the preliminary ordering left out (large hunts) is looked up now.
        for reg, group in by_reg.items():
            if reg not in requested and len(requested) < MAX_RDAP + LATE_RDAP and max(c["score"] for c in group) >= 45:
                requested.add(reg)
                rdap_futs[rdap_pool.submit(rdap_lookup, reg)] = reg
        done = 0
        try:
            for fut in as_completed(rdap_futs):
                info = None
                try:
                    info = fut.result()
                except Exception:
                    pass
                for c in by_reg[rdap_futs[fut]]:
                    c["rdap"] = info
                done += 1
                if done % 10 == 0 or done == len(rdap_futs):
                    report("rdap", 88 + 9 * done / len(rdap_futs), f"Registration data: {done}/{len(rdap_futs)}")
        except HuntCancelled:
            rdap_pool.shutdown(wait=False, cancel_futures=True)
            raise
        rdap_pool.shutdown(wait=False)

    # ------------------------------------------------------------ 7b. Step-7 Automatic 2nd-Hop Pivots (live hunts only)
    auto_pivots: List[Dict[str, Any]] = []
    if use_intel and run_intel is _ORIGINAL_RUN_INTEL and registered:
        pivot_roots: List[str] = []
        pivot_ips: List[str] = []
        for c in sorted(registered, key=lambda x: -x["score"]):
            mm_p = c.get("match_meta") or {}
            root_p = mm_p.get("registered_domain") or registrable_domain(c["domain"]) or ""
            if root_p and root_p not in allowlist and root_p not in _SHARED_HOSTING_ROOTS and (mm_p.get("is_subdomain_impersonation") or c["score"] >= 55):
                if root_p not in pivot_roots:
                    pivot_roots.append(root_p)
            for ip in (c.get("dns") or {}).get("a") or []:
                if ip and ip not in pivot_ips and c["score"] >= 55:
                    pivot_ips.append(ip)
            if len(pivot_roots) >= 2 and len(pivot_ips) >= 2:
                break
        for root_p in pivot_roots[:2]:
            try:
                us_hits = urlscan_search(f"domain:{root_p}", size=15)
                auto_pivots.append({"type": "urlscan_root", "target": root_p, "count": len(us_hits)})
            except Exception:
                pass
        # Passive DNS (OTX): attackers often run several brand subdomains under one registered domain;
        # CT only shows the ones that got their own certificate.
        known = set(candidates) | {c["domain"] for c in registered}
        pdns_new: Dict[str, str] = {}
        for root_p in pivot_roots[:3]:
            try:
                rows = otx_passive_dns(root_p, limit=300)
            except SourceError as e:
                errors.append(f"OTX passive DNS for {root_p}: {e}")
                break
            matched = 0
            for row in rows:
                h = row["hostname"]
                if h in known or h in pdns_new:
                    continue
                cm = evaluate_domain_match(h, apex, keywords=raw_keywords, allowlist=allowlist)
                if cm["technique_key"] not in ("none", "benign_collision", "content_infrastructure") and not cm["is_own_domain"]:
                    pdns_new[h] = root_p
                    matched += 1
            auto_pivots.append({"type": "passive_dns", "target": root_p, "count": len(rows), "new_matches": matched})
        if pdns_new:
            pdns_dns = resolve_domains(list(pdns_new)[:200], nameservers=dns_servers)
            for h, root_p in list(pdns_new.items())[:200]:
                info = pdns_dns.get(h) or {}
                registered.append({
                    "domain": h, "unicode": "", "fuzzer": "intel-pivot", "sources": ["otx"], "ct": None,
                    "dns": {k: info.get(k, []) for k in ("a", "aaaa", "mx", "ns")}, "dns_status": info.get("status", "unknown"),
                    "evidence": None, "rdap": None,
                    "intel": [{"source": "otx", "match": "passive_dns", "label": f"Passive DNS under {root_p}", "title": "", "url": None, "time": ""}],
                })
            stats["passive_dns_new"] = len(pdns_new)
        for ip in pivot_ips[:2]:
            try:
                co = [h for h in hackertarget_reverse_ip(ip, limit=25) if registrable_domain(h) not in allowlist]
                if co:
                    auto_pivots.append({"type": "reverse_ip", "target": ip, "count": len(co), "domains": co[:10]})
                    for chost in co[:15]:
                        cm = evaluate_domain_match(chost, apex, keywords=raw_keywords, allowlist=allowlist)
                        if cm["technique_key"] not in ("none", "benign_collision") and chost not in candidates:
                            registered.append({
                                "domain": chost, "unicode": cm.get("unicode", ""), "fuzzer": "intel-pivot",
                                "sources": ["hackertarget"], "ct": None, "dns": {"a": [ip], "aaaa": [], "mx": [], "ns": []},
                                "dns_status": "resolves", "evidence": None, "rdap": None,
                                "intel": [{"source": "hackertarget", "match": "pivot", "label": f"Co-hosted on {ip}", "title": "", "url": None, "time": ""}],
                            })
            except Exception:
                pass
        if auto_pivots:
            pivots["auto_pivots"] = auto_pivots

    # ------------------------------------------------------------ 8. score
    report("score", 98, "Scoring and ranking")
    for c in registered:
        mm = evaluate_domain_match(
            c["domain"], apex, keywords=raw_keywords, allowlist=allowlist,
            evidence=c.get("evidence"), intel=c.get("intel"),
        )
        c["match_meta"] = mm
        if mm.get("unicode") and not c.get("unicode"):
            c["unicode"] = mm["unicode"]
        d = score_candidate_detailed(c, brand)
        c["score"], c["verdict"], c["reasons"] = d["score"], d["verdict"], d["reasons"]
        c["score_breakdown"], c["corroboration"], c["score_capped"] = d["breakdown"], d["corroboration"], d["capped"]
        c["ownership"] = d.get("ownership", [])
        c["verdict_label"] = VERDICTS[c["verdict"]]
        c["classification"] = classify_candidate(c, c["score"], c["verdict"])
        c["registered_domain"] = mm["registered_domain"]
        c["matching_subdomain"] = mm["matching_subdomain"]
        c["original_domain"] = apex
        c["matched_keyword"] = mm["matched_keyword"]
        c["matched_keywords"] = mm["matched_keywords"]
        c["matching_technique"] = mm["matching_technique"]
        c["similarity_percent"] = mm["similarity_percent"]
        c["defanged"] = defang(c["domain"])
    registered.sort(key=lambda c: (-c["score"], c["domain"]))

    by_verdict: Dict[str, int] = {}
    by_classification: Dict[str, int] = {}
    for c in registered:
        by_verdict[c["verdict"]] = by_verdict.get(c["verdict"], 0) + 1
        by_classification[c["classification"]] = by_classification.get(c["classification"], 0) + 1
    stats.update(
        by_verdict=by_verdict,
        by_classification=by_classification,
        high_risk=by_verdict.get("phishing", 0),
        suspicious=by_verdict.get("suspicious", 0),
        confirmed_impersonation=by_classification.get("Confirmed Impersonation", 0),
        potential_impersonation=by_classification.get("Potential Impersonation", 0),
        inactive_historical=by_classification.get("Inactive / Historical", 0),
        subdomain_impersonations=sum(1 for c in registered if (c.get("match_meta") or {}).get("is_subdomain_impersonation")),
        elapsed_sec=round(time.time() - t0, 1),
    )

    result = {
        "target": apex,
        "depth": depth,
        "brand": {
            "domain": apex,
            "resolved_url": scan.get("resolved_url"),
            "reachable": scan.get("reachable"),
            "title": brand["title"],
            "brand_titles": brand_titles,
            "tokens": tokens,
            "allowlist": allowlist,
            "analytics_ids": sorted(brand["analytics"]),
            "cert_org": brand["cert_org"],
            "icons": icons,  # raw (has _raw_bytes); API / exporters clean it
        },
        "stats": stats,
        "candidates": registered,
        "queries": queries,
        "dorks": dorks,
        "pivots": pivots,
        "pivot_queries": pivot_queries(pivots, allowlist),
        "search_dorks": search_engine_dorks(apex, label, tokens),
        "intel": {"status": intel["status"], "plan": plan},
        "feeds": feed_status,
        "infrastructure": sorted(infrastructure.values(), key=lambda i: -len(i["matches"])),
        "sources": config.sources_status(),
        # Source problems (plan limits, quotas, anti-bot challenges, outages) belong to Settings > API keys, not to the
        # results screen: they are logged there and kept here only for API consumers.
        "errors": [],
        "source_issues": errors,
    }
    source_events.record_many(errors, "Brand Hunt", target=apex)
    report("done", 100, f"Done: {stats['high_risk']} high-risk, {stats['suspicious']} suspicious, {len(registered)} registered lookalikes")
    return result


def hunt_for_export(result: Dict[str, Any]) -> Dict[str, Any]:
    """JSON-safe copy of a hunt result (no raw bytes)."""
    out = dict(result)
    out["brand"] = dict(result["brand"])
    out["brand"]["icons"] = [clean_icon_dict_for_export(i) for i in result["brand"]["icons"]]
    return out


HUNT_CSV_FIELDS = ["score", "classification", "verdict", "domain", "registered_domain", "matching_subdomain",
                   "original_domain", "matched_keyword", "matching_technique", "similarity_percent", "unicode",
                   "defanged", "fuzzer", "sources", "dns_status", "a", "mx", "ns", "created", "age_days", "registrar",
                   "abuse_email", "http_status", "final_url", "title", "favicon_exact", "visual_distance",
                   "password_form", "brand_resources", "shared_analytics", "ct_first_seen", "ct_hosts", "intel", "reasons",
                   "matched_keywords", "corroboration", "score_breakdown"]


def hunt_csv_rows(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for c in result["candidates"]:
        ev = c.get("evidence") or {}
        rd = c.get("rdap") or {}
        http = ev.get("http") or {}
        rows.append({
            "score": c["score"],
            "classification": c.get("classification") or classify_candidate(c, c["score"], c["verdict"]),
            "verdict": c.get("verdict_label", c["verdict"]),
            "domain": c["domain"],
            "registered_domain": c.get("registered_domain", ""),
            "matching_subdomain": c.get("matching_subdomain", ""),
            "original_domain": c.get("original_domain", result.get("target", "")),
            "matched_keyword": c.get("matched_keyword", ""),
            "matching_technique": c.get("matching_technique", c.get("fuzzer", "")),
            "similarity_percent": c.get("similarity_percent", ""),
            "unicode": c.get("unicode", ""), "defanged": c.get("defanged", ""), "fuzzer": c["fuzzer"],
            "sources": ";".join(c["sources"]), "dns_status": c.get("dns_status", ""),
            "a": ";".join(c["dns"]["a"]), "mx": ";".join(c["dns"]["mx"]),
            "ns": ";".join(c["dns"]["ns"]), "created": rd.get("created") or "", "age_days": rd.get("age_days") if rd.get("age_days") is not None else "",
            "registrar": rd.get("registrar") or "", "abuse_email": rd.get("abuse_email") or "",
            "http_status": http.get("status", ""), "final_url": http.get("final_url", ""), "title": ev.get("title", ""),
            "favicon_exact": bool((ev.get("favicon") or {}).get("exact_match")),
            "visual_distance": ev.get("visual_distance") if ev.get("visual_distance") is not None else "",
            "password_form": ev.get("password_form", ""), "brand_resources": ev.get("brand_resources", ""),
            "shared_analytics": ";".join(ev.get("shared_analytics") or []),
            "ct_first_seen": (c.get("ct") or {}).get("first_seen", ""), "ct_hosts": ";".join((c.get("ct") or {}).get("hosts", [])[:10]),
            "intel": ";".join(sorted({f"{i['source']}:{i['match']}" for i in c.get("intel") or []})),
            "reasons": " | ".join(c.get("reasons") or []),
            "matched_keywords": ";".join(c.get("matched_keywords") or []),
            "corroboration": " | ".join(c.get("corroboration") or []),
            "score_breakdown": "; ".join(f"{b['signal']}:{b['points']:+d}" for b in c.get("score_breakdown") or []),
        })
    return rows
