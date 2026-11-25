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

from . import config, feeds
from .crawler import FaviconCrawler
from .discovery import brand_allowlist, crtsh_search, rdap_lookup, resolve_domains
from .pivots import build_intel_plan, drop_shared_assets, extract_asset_pivots, lens_image_urls, pivot_queries, search_engine_dorks
from .sources import SEARCHERS, SourceError, serpapi_lens, urlscan_total
from .domains import normalize_host, registrable_domain, split_host
from .exporter import clean_icon_dict_for_export
from .impersonation import decompose_keyword, generate_keyword_dorks
from .permutations import generate_permutations, permutation_stats
from .query_gen import generate_search_queries
from .verifier import VERDICTS, build_brand_profile, defang, score_candidate, verify_candidate

ProgressFn = Callable[[str, float, str, Dict[str, Any]], None]

MAX_RDAP = 250
LATE_RDAP = 60      # extra lookups for domains inspection revealed as risky
RDAP_WORKERS = 8
STRONG_INTEL = {"favicon_hash", "asset_hash", "analytics", "hosting", "feed"}

# Reverse image search mostly returns big legitimate platforms; never turn those into candidates.
LENS_IGNORE = {
    "wikipedia.org", "wikimedia.org", "linkedin.com", "facebook.com", "instagram.com", "x.com", "twitter.com",
    "youtube.com", "google.com", "pinterest.com", "reddit.com", "amazon.com", "crunchbase.com", "bloomberg.com",
    "reuters.com", "glassdoor.com", "indeed.com", "ambitionbox.com", "seeklogo.com", "logo.wine", "brandfetch.com",
    "worldvectorlogo.com", "1000logos.net", "wikidata.org", "zoominfo.com", "tracxn.com", "economictimes.com",
}


class HuntCancelled(Exception):
    pass


def _token_in(host: str, tokens: List[str]) -> bool:
    flat = host.replace("-", "")
    return any(t in host or t.replace("-", "") in flat for t in tokens)


def run_intel(plan: List[Dict[str, str]], lens_urls: List[str], cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Runs the intel plan on every configured platform in parallel. Returns {"hits": [...], "status": [...]}."""
    jobs = [p for p in plan if config.is_configured(p["source"])]
    skipped = [p for p in plan if not config.is_configured(p["source"])]
    if config.is_configured("serpapi"):
        jobs += [{"source": "serpapi", "match": "lens", "label": "Google Lens: brand logo", "query": u} for u in lens_urls]
    elif lens_urls:
        skipped.append({"source": "serpapi", "match": "lens", "label": "Google Lens: brand logo", "query": lens_urls[0]})

    hits: List[Dict[str, Any]] = []
    status: List[Dict[str, Any]] = [{**p, "count": 0, "error": "no API key configured", "ran": False} for p in skipped]

    def one(job):
        fn = serpapi_lens if job["source"] == "serpapi" else SEARCHERS[job["source"]]
        return fn(job["query"])

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
            except Exception as e:  # pragma: no cover - defensive
                entry["error"] = e.__class__.__name__
            status.append(entry)
            if cancel is not None and cancel.is_set():
                break
    return {"hits": hits, "status": status}


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
    tokens = list(dict.fromkeys([label] + [t for t in dec["tokens"] if len(t) >= 4]))
    brand = build_brand_profile(apex, icons, soup, allowlist, tokens)
    pivots = extract_asset_pivots(soup, scan.get("resolved_url") or f"https://{apex}/", allowlist, crawler)
    if use_intel and pivots["assets"]:
        report("fingerprint", 9, "Checking which brand JS/CSS files are rare enough to search for")
        excl = " AND NOT page.apexDomain:" + (allowlist[0] if len(allowlist) == 1 else f"({' OR '.join(allowlist[:10])})") if allowlist else ""
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
    plan = build_intel_plan(queries.get("combined", {}), icons, pivots, dorks, allowlist, label, tokens)
    ct_tokens = ([t for t in tokens if len(t) >= 4] or [label])[:3]
    prefetch = ThreadPoolExecutor(max_workers=3, thread_name_prefix="hunt-prefetch")
    ct_future = prefetch.submit(lambda: [(tok, crtsh_search(tok)) for tok in ct_tokens]) if use_ct else None
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
                if registrable_domain(host) in allowlist:
                    continue
                ct_hosts_total += 1
                reg = registrable_domain(host) or host
                key = reg if _token_in(reg, tokens) else host  # brand only in subdomain -> track the host itself
                c = candidates.get(key)
                if c is None:
                    c = candidates[key] = {"domain": key, "unicode": "", "fuzzer": "ct-hostname" if key == reg else "brand-subdomain",
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
        report("intel", 21, "Querying threat-intel platforms (URLScan" + "".join(
            f", {config.SOURCES[s]['name']}" for s in ("shodan", "fofa", "censys", "serpapi") if config.is_configured(s)) + ")")
        intel = intel_future.result()
        added = 0
        for h in intel["hits"]:
            host = h.get("host")
            ref = {k: h.get(k) for k in ("source", "match", "label", "title", "url", "time")}
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
            if reg in allowlist or (h["match"] == "lens" and reg in LENS_IGNORE):
                continue
            key = reg if (_token_in(reg, tokens) or h["match"] == "lens") else host
            c = candidates.get(key)
            if c is None:
                c = candidates[key] = {"domain": key, "unicode": "", "fuzzer": f"intel-{h['match']}",
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
        failed = [s for s in ran if s["error"]]
        for s in failed:
            errors.append(f"{config.SOURCES[s['source']]['name']} '{s['label']}': {s['error']}")
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
    for c in registered:
        c["evidence"], c["rdap"] = None, None
        c["score"], c["verdict"], c["reasons"] = score_candidate(c, brand)  # preliminary (domain-level only)

    # RDAP only needs the registrable domain, so it does not have to wait for site inspection: start it now,
    # ordered by the preliminary score, and collect it in stage 7.
    by_reg: Dict[str, List[Dict[str, Any]]] = {}
    rdap_pool: Optional[ThreadPoolExecutor] = None
    rdap_futs: Dict[Any, str] = {}
    requested: set = set()
    if use_rdap and registered:
        for c in sorted(registered, key=lambda c: -c["score"]):
            by_reg.setdefault(registrable_domain(c["domain"]) or c["domain"], []).append(c)
        requested = set(list(by_reg)[:MAX_RDAP])
        rdap_pool = ThreadPoolExecutor(max_workers=RDAP_WORKERS, thread_name_prefix="hunt-rdap")
        rdap_futs = {rdap_pool.submit(rdap_lookup, r): r for r in requested}

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

    # ------------------------------------------------------------ 8. score
    report("score", 98, "Scoring and ranking")
    for c in registered:
        c["score"], c["verdict"], c["reasons"] = score_candidate(c, brand)
        c["verdict_label"] = VERDICTS[c["verdict"]]
        c["defanged"] = defang(c["domain"])
    registered.sort(key=lambda c: (-c["score"], c["domain"]))

    by_verdict: Dict[str, int] = {}
    for c in registered:
        by_verdict[c["verdict"]] = by_verdict.get(c["verdict"], 0) + 1
    stats.update(by_verdict=by_verdict, high_risk=by_verdict.get("phishing", 0), suspicious=by_verdict.get("suspicious", 0),
                 elapsed_sec=round(time.time() - t0, 1))

    result = {
        "target": apex,
        "depth": depth,
        "brand": {
            "domain": apex,
            "resolved_url": scan.get("resolved_url"),
            "reachable": scan.get("reachable"),
            "title": brand["title"],
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
        "errors": errors,
    }
    report("done", 100, f"Done: {stats['high_risk']} high-risk, {stats['suspicious']} suspicious, {len(registered)} registered lookalikes")
    return result


def hunt_for_export(result: Dict[str, Any]) -> Dict[str, Any]:
    """JSON-safe copy of a hunt result (no raw bytes)."""
    out = dict(result)
    out["brand"] = dict(result["brand"])
    out["brand"]["icons"] = [clean_icon_dict_for_export(i) for i in result["brand"]["icons"]]
    return out


HUNT_CSV_FIELDS = ["score", "verdict", "domain", "unicode", "defanged", "fuzzer", "sources", "a", "mx", "ns",
                   "created", "age_days", "registrar", "abuse_email", "http_status", "final_url", "title",
                   "favicon_exact", "visual_distance", "password_form", "brand_resources", "shared_analytics",
                   "ct_first_seen", "ct_hosts", "intel", "reasons"]


def hunt_csv_rows(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for c in result["candidates"]:
        ev = c.get("evidence") or {}
        rd = c.get("rdap") or {}
        http = ev.get("http") or {}
        rows.append({
            "score": c["score"], "verdict": c.get("verdict_label", c["verdict"]), "domain": c["domain"],
            "unicode": c.get("unicode", ""), "defanged": c.get("defanged", ""), "fuzzer": c["fuzzer"],
            "sources": ";".join(c["sources"]), "a": ";".join(c["dns"]["a"]), "mx": ";".join(c["dns"]["mx"]),
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
        })
    return rows
