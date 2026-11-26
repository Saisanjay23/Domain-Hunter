"""
Offline bulk evaluation: run a list of candidate hostnames through the impersonation matcher, scorer and
classifier without any network access (unless DNS resolution is requested).

Used by POST /api/impersonation/evaluate and by the quality tests. It reuses exactly the engine the hunt uses
(core.domain_matcher + core.verifier scoring), so a domain scores the same here as in a hunt that found it.
Without DNS/page evidence only the name-level signals can fire, so a candidate here is at most
"Potential Impersonation": confirming it needs the evidence a hunt collects.
"""

from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

from .domain_matcher import _allow_set, classify_candidate, evaluate_domain_match
from .domains import normalize_host
from .verifier import VERDICTS, score_candidate_detailed

MAX_DOMAINS = 100_000

Item = Union[str, Dict[str, Any]]


def _norm(item: Item) -> Optional[Dict[str, Any]]:
    """Accepts 'host', or {'domain': host, 'source': 'urlscan'}; returns {'host', 'source'} or None if unusable."""
    if isinstance(item, dict):
        raw, source = item.get("domain") or item.get("host") or "", str(item.get("source") or "input")
    else:
        raw, source = str(item or ""), "input"
    host = normalize_host(raw.strip().lstrip("*.")) if raw else ""
    if not host or "." not in host or " " in host:
        return None
    return {"host": host, "source": source}


def evaluate_domains(
    original_domain: str,
    keywords: Optional[Sequence[str]] = None,
    domains: Iterable[Item] = (),
    allowlist: Optional[Sequence[str]] = None,
    include_benign: bool = False,
    dns: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Returns {"summary": {...}, "results": [...]} with results ranked by threat score.

    Every input is normalised and de-duplicated (sources of duplicates are merged, never lost). Benign /
    unrelated hosts and the brand's own domains are counted but only listed when include_benign=True.
    `dns` optionally maps host -> {"a","aaaa","mx","ns","status"} when the caller already resolved them.
    """
    keywords = [k for k in (keywords or []) if isinstance(k, str) and k.strip()]
    merged: Dict[str, Dict[str, Any]] = {}
    invalid = duplicates = 0
    for item in domains:
        n = _norm(item)
        if n is None:
            invalid += 1
            continue
        if n["host"] in merged:
            duplicates += 1
            if n["source"] not in merged[n["host"]]["sources"]:
                merged[n["host"]]["sources"].append(n["source"])
            continue
        if len(merged) >= MAX_DOMAINS:
            break
        merged[n["host"]] = {"host": n["host"], "sources": [n["source"]]}

    brand_ctx = {"allowlist": list(_allow_set(original_domain, allowlist)[1])}  # for NS/MX ownership evidence
    results: List[Dict[str, Any]] = []
    by_class: Dict[str, int] = {}
    own = 0
    for host, rec in merged.items():
        mm = evaluate_domain_match(host, original_domain, keywords=keywords, allowlist=allowlist or [])
        if mm["is_own_domain"]:
            own += 1
            continue
        info = (dns or {}).get(host) or {}
        cand = {
            "domain": host, "fuzzer": "keyword-list", "sources": rec["sources"], "match_meta": mm,
            "dns": {k: info.get(k, []) for k in ("a", "aaaa", "mx", "ns")}, "dns_status": info.get("status", "unknown"),
            "evidence": None, "rdap": None,
        }
        d = score_candidate_detailed(cand, brand_ctx)
        cand.update(score=d["score"], verdict=d["verdict"], corroboration=d["corroboration"])
        cls = classify_candidate(cand, d["score"], d["verdict"])
        by_class[cls] = by_class.get(cls, 0) + 1
        if cls == "Benign/Unrelated" and not include_benign:
            continue
        results.append({
            "domain": host,
            "registered_domain": mm["registered_domain"],
            "matching_subdomain": mm["matching_subdomain"],
            "original_domain": mm["original_domain"],
            "matched_keyword": mm["matched_keyword"],
            "matched_keywords": mm["matched_keywords"],
            "keyword_strength": mm["keyword_strength"],
            "matching_technique": mm["matching_technique"],
            "technique_key": mm["technique_key"],
            "similarity_percent": mm["similarity_percent"],
            "matched_in": mm["matched_in"],
            "unicode": mm["unicode"],
            "classification": cls,
            "score": d["score"],
            "verdict": d["verdict"],
            "verdict_label": VERDICTS[d["verdict"]],
            "reasons": d["reasons"],
            "score_breakdown": d["breakdown"],
            "corroboration": d["corroboration"],
            "match_reasons": mm["match_reasons"],
            "context_keywords": mm["context_keywords"],
            "ownership": d.get("ownership", []),
            "sources": rec["sources"],
            "dns_status": cand["dns_status"],
        })
    results.sort(key=lambda r: (-r["score"], -r["similarity_percent"], r["domain"]))
    return {
        "summary": {
            "received": len(merged) + duplicates + invalid, "unique": len(merged), "duplicates": duplicates,
            "invalid": invalid, "own_domains": own, "by_classification": by_class, "listed": len(results),
        },
        "results": results,
    }
