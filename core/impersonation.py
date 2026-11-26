"""
Live multi-vector domain capture orchestrator.
Keyword decomposition and OSINT dork builders live in core/dorks.py and are
re-exported here for backward compatibility.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from . import config, feeds
from .discovery import crtsh_search, resolve_domains
from .domains import normalize_host, registrable_domain
from .dorks import (  # noqa: F401
    CLOUD_ABUSE_DOMAINS,
    MIN_ABBREV_TOKEN_LEN,
    MIN_TOKEN_LEN,
    build_urlscan_daily_queries,
    build_whoisxml_daily_spec,
    decompose_keyword,
    extract_brand_titles,
    generate_impersonation_recon_suite,
    generate_keyword_dorks,
    sanitize_keywords,
)
from .keypool import POOL
from . import source_events
from .permutations import generate_permutations
from .platforms import (  # noqa: F401
    build_censys_search_url,
    build_crtsh_search_url,
    build_fofa_search_url,
    build_shodan_search_url,
    build_urlscan_search_url,
    urlscan_exclude_clause,
)
from .sources import SEARCHERS, SourceError

__all__ = [
    "sanitize_keywords",
    "decompose_keyword",
    "extract_brand_titles",
    "generate_keyword_dorks",
    "generate_impersonation_recon_suite",
    "capture_domains_from_keywords",
    "build_fofa_search_url",
    "build_censys_search_url",
    "build_urlscan_search_url",
    "build_shodan_search_url",
    "build_crtsh_search_url",
]


def _host_matches_terms(host: str, terms: List[str], coocc: List[List[str]], puny_skels: Optional[List[str]] = None) -> bool:
    h = host.lower()
    flat = h.replace("-", "")
    for t in terms:
        tl = t.lower()
        if tl in h or tl.replace("-", "") in flat:
            return True
    for g in coocc:
        if all(w.lower() in h for w in g):
            return True
    if puny_skels and "xn--" in h:
        if any(sk.lower() in h for sk in puny_skels):
            return True
    return False


def capture_domains_from_keywords(
    raw_input: str,
    include_variants: bool = False,
    use_ct: bool = True,
    use_intel: bool = True,
    use_feeds: bool = True,
    use_dns: bool = False,
    max_ct_tokens: int = 4,
) -> Dict[str, Any]:
    """
    Executes multi-vector dorks across Certificate Transparency (crt.sh),
    URLScan (including daily domain & title scans), WhoisXML, FOFA, Censys,
    Shodan, phishing feeds, and optional live DNS lookalike probing.
    """
    suite = generate_impersonation_recon_suite(raw_input, include_variants=include_variants)
    if not suite["total_keywords"]:
        return {
            "total_keywords": 0, "total_domains": 0, "total_apex_domains": 0,
            "domains": [], "apex_domains": [], "source_status": [], "suite": suite,
        }

    legit = set(suite["legit_domains"])
    terms = suite["all_substring_terms"]
    titles = suite.get("all_titles") or []
    puny_skels = suite.get("all_punycode_skeletons") or []
    coocc = [g for it in suite["items"] for g in it["decomposition"]["cooccurrence_groups"]]
    mq = suite["master_queries"]

    captured: Dict[str, Dict[str, Any]] = {}
    status: List[Dict[str, Any]] = []

    def record_host(
        host: Optional[str], source: str, title: str = "", url: Optional[str] = None,
        ip: Optional[str] = None, time_str: str = "",
    ) -> bool:
        if not host:
            return False
        h = normalize_host(host).lstrip("*.")
        if not h or "." not in h or " " in h:
            return False
        apex = registrable_domain(h) or h
        if apex in legit or h in legit:
            return False
        entry = captured.get(h)
        if entry is None:
            entry = captured[h] = {
                "domain": h, "apex_domain": apex, "sources": [],
                "title": "", "url": None, "ip": None, "last_seen": "",
            }
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if title and not entry["title"]:
            entry["title"] = title[:160]
        if url and not entry["url"]:
            entry["url"] = url
        if ip and not entry["ip"]:
            entry["ip"] = ip
        if time_str and time_str > entry["last_seen"]:
            entry["last_seen"] = time_str
        return True

    tasks: List[Tuple[str, str, Any]] = []

    if use_ct:
        ct_terms = [t for t in terms if len(t) >= MIN_ABBREV_TOKEN_LEN][:max_ct_tokens]
        for tok in ct_terms:
            tasks.append(("crt.sh", f"%{tok}%", lambda t=tok: ("ct", crtsh_search(t, timeout=18, retries=1))))
            tasks.append(("crt.sh (Subdomains)", f"{tok}.%", lambda t=tok: ("ct", crtsh_search(f"{t}.", timeout=15, retries=1))))

    if use_intel:
        has_urlscan_key = bool(config.get("URLSCAN_API_KEY"))
        us_size = 500 if has_urlscan_key else 100
        us_dom_q = mq["urlscan"]["all_domains_query"] if has_urlscan_key and not config.free_only() else mq["urlscan"]["domain_query"]
        us_sub_q = mq["urlscan"]["subdomain_query"]
        us_excl = urlscan_exclude_clause(list(legit))
        us_url_q = (
            "("
            + " OR ".join(f"page.url:{t}*" for t in terms)
            + " OR " + " OR ".join(f"task.url:{t}*" for t in terms)
            + " OR " + " OR ".join(f"filename:{t}*" for t in terms)
            + ")" + us_excl
        )
        daily_us = build_urlscan_daily_queries(terms, titles, list(legit), hours=24, has_key=has_urlscan_key)
        tasks.append(("URLScan (Domains)", us_dom_q, lambda q=us_dom_q: ("hits", SEARCHERS["urlscan"](q, size=us_size))))
        tasks.append(("URLScan (Subdomains · keyword.*)", us_sub_q, lambda q=us_sub_q: ("hits", SEARCHERS["urlscan"](q, size=us_size))))
        tasks.append(("URLScan (Daily Domain+Title)", daily_us["combined_query"], lambda q=daily_us["combined_query"]: ("hits", SEARCHERS["urlscan"](q, size=us_size))))
        tasks.append(("URLScan (URLs & Kits)", us_url_q, lambda q=us_url_q: ("hits", SEARCHERS["urlscan"](q, size=us_size))))
        tasks.append(("URLScan (Free Hosting)", mq["urlscan"]["free_hosting_query"], lambda q=mq["urlscan"]["free_hosting_query"]: ("hits", SEARCHERS["urlscan"](q, size=us_size))))
        tasks.append(("URLScan (IDN Punycode)", mq["urlscan"]["idn_query"], lambda q=mq["urlscan"]["idn_query"]: ("hits", SEARCHERS["urlscan"](q, size=us_size))))

        if config.is_enabled("whoisxml") and "whoisxml" in SEARCHERS:
            wx_spec = mq["whoisxml"]["spec"]
            tasks.append(("WhoisXML (Brand Alert + Discovery)", ", ".join(mq["whoisxml"]["terms"]), lambda s=wx_spec: ("hits", SEARCHERS["whoisxml"](s, size=500))))

        def _is_plan_forbidden(err: SourceError) -> bool:
            msg = str(err).lower()
            return err.kind == "forbidden" or "does not allow" in msg or "forbidden" in msg

        if config.is_enabled("fofa"):
            def run_fofa():
                try:
                    return ("hits", SEARCHERS["fofa"](mq["fofa"]["exhaustive_query"], size=500))
                except SourceError as e:
                    if _is_plan_forbidden(e):
                        POOL.reset("fofa")
                        return ("hits", SEARCHERS["fofa"](mq["fofa"]["query"], size=500))
                    raise
            tasks.append(("FOFA", mq["fofa"]["exhaustive_query"], run_fofa))

        if config.is_enabled("censys"):
            def run_censys():
                try:
                    return ("hits", SEARCHERS["censys"](mq["censys"]["exhaustive_query"], size=100))
                except SourceError as e:
                    if _is_plan_forbidden(e):
                        POOL.reset("censys")
                        return ("hits", SEARCHERS["censys"](mq["censys"]["query"], size=100))
                    raise
            tasks.append(("Censys", mq["censys"]["exhaustive_query"], run_censys))

        if config.is_enabled("shodan"):
            tasks.append(("Shodan (Cert CN)", mq["shodan"]["query"], lambda q=mq["shodan"]["query"]: ("hits", SEARCHERS["shodan"](q, size=100))))
            tasks.append(("Shodan (Hostname)", mq["shodan"]["hostname_query"], lambda q=mq["shodan"]["hostname_query"]: ("hits", SEARCHERS["shodan"](q, size=100))))
    else:
        status.append({"source": "URLScan", "query": "", "count": 0, "error": "disabled", "ran": False})

    for src_id, name in (("whoisxml", "WhoisXML"), ("fofa", "FOFA"), ("censys", "Censys"), ("shodan", "Shodan")):
        if use_intel and not config.is_enabled(src_id) and not config.free_only():
            status.append({"source": name, "query": "", "count": 0, "error": "no API key configured", "ran": False})

    if use_feeds:
        feed_tokens = [t for t in terms if len(t) >= MIN_ABBREV_TOKEN_LEN]
        tasks.append(("Phishing feeds", ", ".join(feed_tokens), lambda ft=feed_tokens: ("feed", feeds.match(ft, list(legit)))))

    if use_dns:
        def run_dns_probe():
            seed_domains = [it["decomposition"]["legit_domain"] for it in suite["items"] if it["decomposition"]["legit_domain"]]
            if not seed_domains:
                seed_domains = [f"{t}.com" for t in suite["all_tokens"][:2] if len(t) >= 4 and "-" not in t]
            cand_names = list(seed_domains)
            for sd in seed_domains[:2]:
                cand_names.extend(p["domain"] for p in generate_permutations(sd, depth="quick", max_results=220))
            resolved = resolve_domains(cand_names[:350], concurrency=120, timeout=1.5)
            return ("dns", [info for info in resolved.values() if info.get("registered")])

        tasks.append(("Live DNS lookalikes", ", ".join(suite["all_tokens"][:2]), run_dns_probe))

    with ThreadPoolExecutor(max_workers=6) as pool:
        futs = {pool.submit(fn): (src, q) for src, q, fn in tasks}
        for fut in as_completed(futs):
            src, q = futs[fut]
            rec = {"source": src, "query": q, "count": 0, "error": None, "ran": True}
            try:
                kind, payload = fut.result()
                added = 0
                if kind == "ct":
                    if payload.get("error"):
                        rec["error"] = payload["error"]
                    for host, meta in (payload.get("hosts") or {}).items():
                        if _host_matches_terms(host, terms, coocc, puny_skels):
                            if record_host(host, "crt.sh", time_str=meta.get("last_seen", "")):
                                added += 1
                elif kind == "feed":
                    if payload.get("errors"):
                        rec["error"] = "; ".join(payload["errors"])
                    for h in payload.get("hits") or []:
                        if record_host(h.get("host"), h.get("feed_name") or "feed", url=h.get("url")):
                            added += 1
                elif kind == "dns":
                    for info in payload or []:
                        ips = info.get("a") or info.get("aaaa") or []
                        if record_host(info.get("domain"), "dns-probe", ip=ips[0] if ips else None):
                            added += 1
                elif kind == "hits":
                    tag = "urlscan" if src.startswith("URLScan") else ("whoisxml" if src.startswith("WhoisXML") else src.split(" ")[0].lower())
                    for h in payload or []:
                        if record_host(h.get("host"), tag, title=h.get("title", ""), url=h.get("url"), ip=h.get("ip"), time_str=h.get("time", "")):
                            added += 1
                rec["count"] = added
            except SourceError as e:
                rec["error"] = str(e)
            except Exception as e:
                rec["error"] = str(e)
            status.append(rec)

    for rec in status:
        if rec.get("ran") and rec.get("error"):
            source_events.record(rec["source"], rec["error"], "Dorks & Capture", label=rec.get("query", "")[:80], target=raw_input[:80])
    domains = sorted(
        captured.values(),
        key=lambda d: (-len(d["sources"]), -(1 if _host_matches_terms(d["domain"], terms, coocc, puny_skels) else 0), d["domain"]),
    )
    apex_domains = list(dict.fromkeys(d["apex_domain"] for d in domains))
    return {
        "total_keywords": suite["total_keywords"], "total_domains": len(domains), "total_apex_domains": len(apex_domains),
        "domains": domains, "apex_domains": apex_domains, "source_status": status, "suite": suite,
    }
