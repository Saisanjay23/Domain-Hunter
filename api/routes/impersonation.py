"""Keyword dork generator, live multi-source domain capture, and offline bulk impersonation analysis routes."""

from fastapi import APIRouter, Depends, HTTPException

from api.deps import app_attr, require_same_origin
from api.schemas import DomainEvaluateRequest, ImpersonationCaptureRequest, ImpersonationDorksRequest
from core.bulk import evaluate_domains
from core.discovery import resolve_domains
from core.impersonation import (
    capture_domains_from_keywords as core_capture,
    generate_impersonation_recon_suite,
)
from core.scoring import get_lure_words, get_weights

router = APIRouter()


@router.post("/api/impersonation-dorks")
def api_impersonation_dorks(req: ImpersonationDorksRequest):
    if not req.keywords or not req.keywords.strip():
        raise HTTPException(status_code=400, detail="No keywords provided.")
    try:
        return generate_impersonation_recon_suite(req.keywords, include_variants=req.include_variants)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/impersonation-dorks/capture")
def api_impersonation_capture(req: ImpersonationCaptureRequest):
    if not req.keywords or not req.keywords.strip():
        raise HTTPException(status_code=400, detail="No keywords provided.")
    try:
        capturer = app_attr("capture_domains_from_keywords", core_capture)
        return capturer(
            req.keywords,
            include_variants=req.include_variants,
            use_ct=req.use_ct,
            use_intel=req.use_intel,
            use_feeds=req.use_feeds,
            use_dns=req.use_dns,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/impersonation/evaluate", dependencies=[Depends(require_same_origin)])
def api_impersonation_evaluate(req: DomainEvaluateRequest):
    """
    Score a list of hostnames against a brand (original domain + analyst keywords): subdomain, typosquat,
    homograph/IDN and multi-keyword matching, threat score, classification and the reasons for each.
    Offline by default; with `resolve=true` the hosts are looked up in DNS first (at most 2,000 of them).
    """
    if not req.original_domain.strip():
        raise HTTPException(status_code=400, detail="original_domain is required.")
    if not req.domains:
        raise HTTPException(status_code=400, detail="No domains provided.")
    try:
        dns = None
        if req.resolve:
            dns = resolve_domains(req.domains[:2000], concurrency=120, timeout=2.0)
        return evaluate_domains(
            req.original_domain.strip(), keywords=req.keywords, domains=req.domains,
            allowlist=req.allowlist, include_benign=req.include_benign, dns=dns,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/scoring-weights")
def api_scoring_weights():
    """The effective threat-score weights and thresholds (defaults plus THREAT_SCORE_WEIGHTS overrides)."""
    weights, thresholds = get_weights()
    return {"weights": weights, "thresholds": thresholds, "lure_keywords": list(get_lure_words()),
            "note": "Override with THREAT_SCORE_WEIGHTS (JSON) and LURE_KEYWORDS (comma list; '-word' removes) in .env."}
