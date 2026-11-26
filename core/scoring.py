"""
Threat-score weights and thresholds (the 0-100 score is a sum of independent signals).

Every signal's points live here so analysts can tune the model without touching code. Override any of them
with the THREAT_SCORE_WEIGHTS variable (environment or .env), a JSON object:

    THREAT_SCORE_WEIGHTS={"age_30": 25, "feed": 50, "thresholds": {"phishing": 75, "suspicious": 40}}

Unknown keys and values outside 0-100 are ignored (and logged), so a typo can never break a hunt.
"""

import json
import logging
from typing import Any, Dict, Tuple

from . import config

logger = logging.getLogger(__name__)

DEFAULT_WEIGHTS: Dict[str, int] = {
    # --- name analysis
    "subdomain_impersonation": 32,       # brand keyword inside a subdomain of someone else's registered domain
    "subdomain_impersonation_weak": 12,  # same, but the keyword is a <=3 character abbreviation (gd, g-d)
    "mixed_script_idn": 28,              # Cyrillic/Greek/... letters mimicking the brand
    "idn_lookalike": 20,
    "homoglyph": 12,                     # generated homoglyph permutation
    "combosquat_lure": 12,               # generated permutation: brand + login/secure/verify...
    "brand_lure_context": 12,            # any discovered host: brand + a lure word (see LURE_KEYWORDS)
    "combosquat": 7,
    "typo": 6,
    "tld_swap": 6,
    "name_match_strong": 12,             # exact / combo / co-occurrence found by discovery
    "name_match": 8,                     # typo-class match found by discovery
    # --- infrastructure & registration
    "ct_certificate": 5,
    "mx_records": 8,
    "age_30": 18,
    "age_90": 12,
    "age_365": 5,
    "new_lookalike_live": 10,
    # --- page content
    "favicon_exact": 40,
    "visual_match": 32,
    "visual_resembles": 15,
    "shared_analytics": 30,
    "brand_resources": 20,
    "password_form_brand": 15,
    "password_form": 5,
    "brand_in_title": 15,
    "title_similarity": 10,
    "text_similarity_high": 20,
    "text_similarity_mid": 10,
    # --- threat-intel platforms
    "feed": 45,
    "safe_browsing": 45,                 # Google Safe Browsing lists the host
    "vt_malicious": 35,                  # >= 3 vendors
    "vt_suspicious": 15,                 # 1-2 vendors
    "favicon_hash": 35,
    "asset_hash": 30,
    "code_hash": 10,
    "analytics": 30,
    "daily_title": 16,
    "whoisxml_brand": 14,
    "subdomain_spoof": 14,
    "hosting": 14,
    "whoisxml_discovery": 10,
    "lens": 8,
    "daily_domain": 6,
    "dork": 4,
}

DEFAULT_THRESHOLDS: Dict[str, int] = {
    "phishing": 70,      # score at/above which a candidate is "High risk" (still needs corroboration)
    "suspicious": 45,
    "uncorroborated_cap": 69,  # ceiling for candidates whose evidence is only the name / registration data
}

# "Brand + malicious context" words: a brand match next to one of these gets priority (brand_lure_context).
# Configure with LURE_KEYWORDS (comma-separated): plain words are added, "-word" removes a default, e.g.
#   LURE_KEYWORDS=invoice,crypto,-help
DEFAULT_LURE_WORDS: Tuple[str, ...] = (
    "login", "logon", "signin", "sign-in", "secure", "security", "verify", "verification", "validate", "confirm",
    "account", "accounts", "auth", "authentication", "sso", "mfa", "otp", "password", "reset", "recovery", "unlock",
    "update", "support", "helpdesk", "help", "service", "portal", "client", "customer", "access",
    "bank", "banking", "wallet", "pay", "payment", "payments", "billing", "invoice", "refund", "claim", "kyc",
)

_cache: Tuple[str, Dict[str, int], Dict[str, int]] = ("", dict(DEFAULT_WEIGHTS), dict(DEFAULT_THRESHOLDS))
_lure_cache: Tuple[str, Tuple[str, ...]] = ("", DEFAULT_LURE_WORDS)


def get_lure_words() -> Tuple[str, ...]:
    """Effective lure words: defaults, plus LURE_KEYWORDS additions, minus its "-word" removals."""
    global _lure_cache
    raw = config._raw("LURE_KEYWORDS")
    if raw == _lure_cache[0]:
        return _lure_cache[1]
    words = list(DEFAULT_LURE_WORDS)
    for item in raw.split(","):
        w = item.strip().lower()
        if w.startswith("-"):
            w = w[1:].strip()
            if w in words:
                words.remove(w)
        elif w and w.replace("-", "").isalnum() and len(w) <= 40 and w not in words:
            words.append(w)
    _lure_cache = (raw, tuple(words))
    return _lure_cache[1]


def _valid(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v <= 100


def get_weights() -> Tuple[Dict[str, int], Dict[str, int]]:
    """Effective (weights, thresholds): defaults plus any valid THREAT_SCORE_WEIGHTS overrides."""
    global _cache
    raw = config._raw("THREAT_SCORE_WEIGHTS")
    if raw == _cache[0]:
        return _cache[1], _cache[2]
    weights, thresholds = dict(DEFAULT_WEIGHTS), dict(DEFAULT_THRESHOLDS)
    if raw:
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("must be a JSON object")
            for k, v in data.items():
                if k == "thresholds" and isinstance(v, dict):
                    for tk, tv in v.items():
                        if tk in thresholds and _valid(tv):
                            thresholds[tk] = int(tv)
                        else:
                            logger.warning("THREAT_SCORE_WEIGHTS: ignored threshold %r", tk)
                elif k in weights and _valid(v):
                    weights[k] = int(v)
                else:
                    logger.warning("THREAT_SCORE_WEIGHTS: ignored %r", k)
        except (ValueError, TypeError) as e:
            logger.warning("THREAT_SCORE_WEIGHTS is not valid JSON (%s); using defaults", e)
            weights, thresholds = dict(DEFAULT_WEIGHTS), dict(DEFAULT_THRESHOLDS)
    _cache = (raw, weights, thresholds)
    return weights, thresholds
