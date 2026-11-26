"""
Unified domain, subdomain, typosquatting, IDN/homograph, and multi-keyword impersonation matcher.

Analyses complete hostnames (subdomains + second-level domain + PSL root domain + TLD),
expands analyst keywords independently, detects mixed-script/Cyrillic/Punycode homographs,
computes Damerau-Levenshtein similarity scores, suppresses common dictionary-word false
positives, and classifies every candidate with explainable match metadata.
"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .domains import normalize_host, registrable_domain, split_host
from .permutations import ASCII_GLYPHS, QWERTY, UNICODE_GLYPHS
from .scoring import get_lure_words

# Expanded confusable map combining Cyrillic, Greek, extended Latin, and visual ASCII tricks.
CONFUSABLE_CHARS: Dict[str, str] = {
    # Cyrillic lowercase
    "\u0430": "a", "\u0432": "b", "\u0441": "c", "\u0435": "e", "\u0451": "e",
    "\u043d": "h", "\u0456": "i", "\u0457": "i", "\u0458": "j", "\u043a": "k",
    "\u043c": "m", "\u043e": "o", "\u0440": "p", "\u0455": "s", "\u0442": "t",
    "\u0443": "y", "\u0445": "x", "\u0501": "d", "\u051b": "q", "\u04bb": "h",
    "\u04cf": "l", "\u0461": "w", "\u0261": "g", "\u0131": "i",
    # Cyrillic uppercase
    "\u0410": "a", "\u0412": "b", "\u0421": "c", "\u0415": "e", "\u041d": "h",
    "\u0406": "i", "\u041a": "k", "\u041c": "m", "\u041e": "o", "\u0420": "p",
    "\u0405": "s", "\u0422": "t", "\u0423": "y", "\u0425": "x",
    # Greek
    "\u03b1": "a", "\u03b2": "b", "\u03b5": "e", "\u03b9": "i", "\u03ba": "k",
    "\u03bd": "v", "\u03bf": "o", "\u03c1": "p", "\u03c4": "t", "\u03c5": "u",
    "\u03c7": "x",
    # Latin lookalikes not resolved purely by NFKD
    "\u00f8": "o", "\u0142": "l", "\u0111": "d", "\u0127": "h", "\u0167": "t",
    "\u00df": "ss", "\u00e6": "ae", "\u0153": "oe",
    # Fullwidth / digit visual homoglyphs for domain skeleton normalization
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
}
# Include reverse mapping from core.permutations.UNICODE_GLYPHS
for _ascii_ch, _glyphs in UNICODE_GLYPHS.items():
    for _g in _glyphs:
        CONFUSABLE_CHARS.setdefault(_g, _ascii_ch)

_MULTI_GLYPHS: Tuple[Tuple[str, str], ...] = (
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("ii", "u"),
)

# Words/subdomains commonly used as infrastructure prefixes rather than brand identity.
_INFRA_SUBDOMAIN_LABELS = {
    "www", "mail", "webmail", "smtp", "imap", "pop", "mx", "ns", "ns1", "ns2",
    "cdn", "static", "assets", "img", "api", "app", "portal", "login", "signin",
    "sso", "auth", "verify", "secure", "account", "accounts", "support", "help",
    "docs", "blog", "shop", "store", "dev", "staging", "test", "beta", "admin",
    "panel", "cpanel", "autodiscover", "m", "mobile",
}

# Common harmless English dictionary words that accidentally start with short 3-4 letter stems (like "gide").
_BENIGN_WORD_COLLISIONS = {
    "gideon", "gideons", "gideonsjeweler", "guided", "guides", "guide", "guiding",
    "guidebook", "guideline", "guidelines", "gider", "goods", "good", "google",
    "gdpr", "gdr", "gdansk",
}

_STOP_KEYWORDS = {
    "the", "and", "for", "of", "in", "on", "at", "by", "to", "a", "an",
    "com", "net", "org", "co", "io", "www", "http", "https", "official",
    "inc", "ltd", "llc", "gmbh", "corp", "group", "limited", "private",
}


def decode_idna_label(label: str) -> str:
    """Decode an ASCII ACE (`xn--`) label into Unicode when valid, otherwise return as-is."""
    low = (label or "").strip().lower()
    if not low.startswith("xn--"):
        return low
    try:
        return low.encode("ascii").decode("idna")
    except Exception:
        return low


def decode_idna_host(hostname: str) -> str:
    """Decode every `xn--` label in a hostname to readable Unicode."""
    parts = [p for p in (hostname or "").strip().lower().rstrip(".").split(".") if p]
    if not parts:
        return ""
    return ".".join(decode_idna_label(p) for p in parts)


def _char_script(ch: str) -> Optional[str]:
    if not ch.isalpha():
        return None
    if ord(ch) < 128:
        return "Latin"
    try:
        name = unicodedata.name(ch, "")
    except ValueError:
        return "Other"
    if "CYRILLIC" in name:
        return "Cyrillic"
    if "GREEK" in name:
        return "Greek"
    if "LATIN" in name:
        return "Latin"
    if "ARMENIAN" in name:
        return "Armenian"
    if "CHEROKEE" in name:
        return "Cherokee"
    return name.split(" ", 1)[0] if name else "Other"


@lru_cache(maxsize=262144)
def skeletonize(text: str, collapse_digits: bool = True) -> str:
    """Reduce Unicode/diacritic/homoglyph lookalike text to a canonical ASCII skeleton."""
    raw = unicodedata.normalize("NFKC", text or "").lower()
    out: List[str] = []
    for ch in raw:
        if ch in CONFUSABLE_CHARS:
            mapped = CONFUSABLE_CHARS[ch]
            if not collapse_digits and ch.isdigit():
                out.append(ch)
            else:
                out.append(mapped)
            continue
        decomposed = unicodedata.normalize("NFKD", ch)
        stripped = "".join(c for c in decomposed if unicodedata.category(c) != "Mn")
        if stripped and all(ord(c) < 128 for c in stripped):
            out.append(stripped)
        elif ord(ch) < 128:
            out.append(ch)
    s = "".join(out)
    for seq, repl in _MULTI_GLYPHS:
        if seq in s:
            s = s.replace(seq, repl)
    return re.sub(r"[^a-z0-9-]+", "", s)


def inspect_idn(hostname: str) -> Dict[str, Any]:
    """Inspect a hostname for IDN/Punycode encoding, Unicode scripts, and skeleton form."""
    ascii_host = normalize_host(hostname)
    unicode_host = decode_idna_host(ascii_host)
    is_idn = ("xn--" in ascii_host) or any(ord(c) > 127 for c in (hostname or "").strip())
    scripts = sorted({sc for sc in (_char_script(c) for c in unicode_host) if sc})
    non_latin = any(s != "Latin" for s in scripts)
    mixed_script = len(scripts) > 1 or non_latin
    labels = [p for p in unicode_host.split(".") if p]
    skeleton_labels = [skeletonize(lbl) for lbl in labels]
    return {
        "ascii_host": ascii_host,
        "unicode_host": unicode_host if is_idn and unicode_host != ascii_host else (hostname.lower() if any(ord(c) > 127 for c in (hostname or "")) else ""),
        "is_idn": is_idn,
        "scripts": scripts,
        "mixed_script": mixed_script,
        "skeleton_host": ".".join(skeleton_labels),
        "skeleton_labels": skeleton_labels,
    }


def parse_domain_parts(hostname: str) -> Dict[str, Any]:
    """Decompose a hostname using the offline Public Suffix List into subdomain, SLD, root, and TLD."""
    fqdn = normalize_host(hostname)
    sub, sld, tld = split_host(fqdn)
    reg = registrable_domain(fqdn) or (f"{sld}.{tld}".strip(".") if tld else fqdn)
    sub_labels = [p for p in sub.split(".") if p] if sub else []
    return {
        "fqdn": fqdn,
        "registered_domain": reg,
        "subdomain": sub,
        "subdomain_labels": sub_labels,
        "sld": sld,
        "tld": tld,
    }


try:  # C-accelerated optimal string alignment when RapidFuzz is installed (same results as the fallback below)
    from rapidfuzz.distance import OSA as _RF_OSA
except ImportError:  # pragma: no cover - depends on the environment
    _RF_OSA = None


def damerau_levenshtein(a: str, b: str) -> int:
    """Compute optimal string alignment (Damerau-Levenshtein) distance treating adjacent swaps as cost 1."""
    if a == b:
        return 0
    if _RF_OSA is not None:
        return int(_RF_OSA.distance(a, b))
    return _osa_python(a, b)


def _osa_python(a: str, b: str) -> int:
    """Pure-Python optimal string alignment distance (fallback when RapidFuzz is not installed)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            best = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                best = min(best, d[i - 2][j - 2] + 1)
            d[i][j] = best
    return d[la][lb]


SHORT_STEM_MAX = 5  # brand forms this short need stricter typo rules (see _classify_typo)


def _is_transposition(a: str, b: str) -> bool:
    """True when a and b are equal length and differ only by one swap of adjacent characters."""
    if len(a) != len(b) or a == b:
        return False
    diffs = [i for i in range(len(a)) if a[i] != b[i]]
    return len(diffs) == 2 and diffs[1] == diffs[0] + 1 and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]


def _classify_typo(candidate_label: str, target_form: str, *, is_idn: bool = False, mixed_script: bool = False) -> Tuple[Optional[str], float]:
    """
    Compare a single domain label (or skeleton) against a keyword form.
    Returns (technique_key, similarity_percent) or (None, similarity_percent) when unrelated.
    """
    a = re.sub(r"[^a-z0-9-]", "", (candidate_label or "").lower())
    b = re.sub(r"[^a-z0-9-]", "", (target_form or "").lower())
    if not a or not b:
        return None, 0.0

    sk_a = skeletonize(candidate_label)
    sk_b = skeletonize(target_form)

    if a == b:
        if is_idn or mixed_script:
            return "homograph_idn", 99.0
        return "exact_brand_match", 100.0

    # Pure skeleton equivalence (e.g. Cyrillic o,rn->m, 0->o, 1->l, accented chars)
    if sk_a and sk_b and sk_a == sk_b:
        if is_idn or mixed_script or any(c.isdigit() for c in a) != any(c.isdigit() for c in b):
            return "homograph_idn", 97.0
        if a.replace("-", "") == b.replace("-", ""):
            return "hyphen_variation", 96.0
        return "homograph_ascii", 95.0

    # Hyphen-stripped equality (gi-de vs gide or vice versa)
    a_flat = a.replace("-", "")
    b_flat = b.replace("-", "")
    if a_flat == b_flat:
        return "hyphen_variation", 96.0

    # Combo-squatting when candidate contains the whole keyword form with hyphen/affix boundaries
    if len(b) >= 4:
        parts = [p for p in re.split(r"[-.]", a) if p]
        if b in parts or b_flat in parts:
            sim = round(max(78.0, (len(b_flat) / max(len(a_flat), 1)) * 100.0), 1)
            return "combosquat", min(95.0, sim)
        # brand on a hyphen boundary (gi-de-x, x-gi-de, a-gi-de-b) is a combo even with a 1-letter affix
        boundary = a.startswith(b + "-") or a.endswith("-" + b) or f"-{b}-" in a
        if (b in a or (len(b_flat) >= 5 and b_flat in a_flat)) and (len(a_flat) > len(b_flat) + 1 or boundary):
            ratio = len(b_flat) / max(len(a_flat), 1)
            sim = round(max(74.0, ratio * 100.0), 1)
            return "combosquat", min(94.0, sim)

    # Check edit distance on normalized flat strings (protect short <=3 tokens from random 1-edit matches)
    if len(b_flat) < 4:
        return None, 0.0

    # Edit budget: one edit up to 9 characters, two beyond. Two edits on an 8-letter name (75% similar)
    # matches ordinary words (deviant/devrient), so it is not allowed.
    max_edits = 1 if len(b_flat) <= 9 else 2
    if abs(len(a_flat) - len(b_flat)) > max_edits:
        return None, 0.0  # cheap exit: no need to compute the distance

    dist = damerau_levenshtein(a_flat, b_flat)
    sk_dist = damerau_levenshtein(sk_a.replace("-", ""), sk_b.replace("-", "")) if sk_a and sk_b else dist
    use_sk = sk_dist < dist
    best_dist = min(dist, sk_dist)
    max_len = max(len(a_flat), len(b_flat), 1)
    sim = round(max(0.0, (1.0 - best_dist / max_len) * 100.0), 1)

    if best_dist > max_edits:
        return None, sim

    if use_sk and (is_idn or mixed_script):
        return "homograph_idn", max(sim, 88.0)

    # Short stems (gi-de -> "gide") sit one edit away from ordinary words (wide, side, hide, glide).
    # Hyphenated brand: the candidate must keep the hyphen in place (gi-do, gi-d, gi-ded).
    # Unhyphenated stem of <=4 characters: a plain substitution is never evidence on its own.
    if len(b_flat) <= SHORT_STEM_MAX and not use_sk:
        if "-" in b:
            if damerau_levenshtein(a, b) > 1:
                return None, sim
        elif len(b_flat) <= 4 and len(a_flat) == len(b_flat) and not _is_transposition(a_flat, b_flat):
            return None, sim

    # Identify fine-grained typo mechanism
    if len(a_flat) == len(b_flat):
        # Adjacent swap?
        diffs = [i for i in range(len(a_flat)) if a_flat[i] != b_flat[i]]
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1 and a_flat[diffs[0]] == b_flat[diffs[1]] and a_flat[diffs[1]] == b_flat[diffs[0]]:
            return "typosquat_transposition", sim
        if len(diffs) == 1:
            ca, cb = b_flat[diffs[0]], a_flat[diffs[0]]
            if cb in QWERTY.get(ca, ""):
                return "typosquat_keyboard", sim
            if cb in ASCII_GLYPHS.get(ca, ()):
                return "homograph_ascii", sim
        return "typosquat_substitution", sim

    if len(a_flat) == len(b_flat) + 1:
        for i in range(len(a_flat)):
            if a_flat[:i] + a_flat[i + 1:] == b_flat:
                if (i > 0 and a_flat[i] == a_flat[i - 1]) or (i < len(a_flat) - 1 and a_flat[i] == a_flat[i + 1]):
                    return "typosquat_repetition", sim
                return "typosquat_insertion", sim
        return "typosquat_insertion", sim

    if len(a_flat) + 1 == len(b_flat):
        return "typosquat_omission", sim

    return "typosquat_substitution", sim


def expand_analyst_keywords(
    original_domain: str,
    keywords: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Cached keyword expansion (see `_expand_uncached`). Returns fresh dicts; treat the sets/lists as read-only."""
    cached = _expand_cached(original_domain or "", tuple(k for k in (keywords or ()) if isinstance(k, str)))
    return [dict(s) for s in cached]


@lru_cache(maxsize=256)
def _expand_cached(original_domain: str, keywords: Tuple[str, ...]) -> Tuple[Dict[str, Any], ...]:
    return tuple(_expand_uncached(original_domain, keywords))


def keyword_search_tokens(specs: Sequence[Dict[str, Any]], min_len: int = 4, limit: int = 12) -> List[str]:
    """
    Search tokens for discovery sources, ordered so that EVERY analyst keyword is represented before any
    keyword gets a second token (round-robin over keywords, most specific form first). A plain "first N
    tokens" cut would let the forms of the first keyword crowd out the later keywords.
    """
    per_spec: List[List[str]] = []
    for sp in specs:
        forms = [f for f in sp.get("forms") or [] if len(f.replace("-", "")) >= min_len]
        flat = [f.replace("-", "") for f in forms]
        # distinct tokens, the analyst's own spelling first
        ordered = list(dict.fromkeys(forms + flat))
        if ordered:
            per_spec.append(ordered)
    out: List[str] = []
    depth = 0
    while len(out) < limit and any(depth < len(p) for p in per_spec):
        for p in per_spec:
            if depth < len(p) and p[depth] not in out:
                out.append(p[depth])
                if len(out) >= limit:
                    break
        depth += 1
    return out


def _expand_uncached(
    original_domain: str,
    keywords: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Independently normalize and expand the target domain label plus every analyst keyword.

    Preserves exact attribution back to the original keyword (e.g. `G+D`, `Giesecke+Devrient`,
    `gi-de`) while flagging very short forms (`<=3` chars) as strict-boundary-only so common
    domains like `good.com` do not cause noisy substring matches.
    """
    apex = registrable_domain(normalize_host(original_domain)) or normalize_host(original_domain)
    _, domain_label, _ = split_host(apex)
    raw_inputs: List[Tuple[str, bool]] = []
    if domain_label:
        raw_inputs.append((domain_label, True))
    for kw in keywords or []:
        cleaned = (kw or "").strip()
        if cleaned:
            raw_inputs.append((cleaned, False))

    specs: List[Dict[str, Any]] = []
    seen_raw: set = set()
    for raw, from_domain in raw_inputs:
        key_id = raw.lower()
        if key_id in seen_raw or key_id in _STOP_KEYWORDS:
            continue
        seen_raw.add(key_id)

        # Extract domain stem if analyst passed a keyword like `gi-de.com`
        work = raw
        if "." in raw and " " not in raw and "+" not in raw and "&" not in raw:
            norm = normalize_host(raw)
            _, lbl, sfx = split_host(norm)
            if lbl and sfx:
                work = lbl

        low = work.lower().strip()
        forms: List[str] = []
        strict_forms: set = set()

        def add_form(val: str, strict: bool = False) -> None:
            v = re.sub(r"[^a-z0-9-]+", "", (val or "").lower()).strip("-")
            if not v or len(v) < 2 or v in _STOP_KEYWORDS:
                return
            if v not in forms:
                forms.append(v)
            if strict or len(v.replace("-", "")) <= 3:
                strict_forms.add(v)

        if "+" in low or "&" in low:
            # Handle marks like "G+D", "G&D", "Giesecke+Devrient"
            parts = [re.sub(r"[^a-z0-9-]", "", p.lower()) for p in re.split(r"[+&/\s]+", low) if p.strip()]
            joined = "".join(parts)
            hyphened = "-".join(p for p in parts if p)
            n_repl = re.sub(r"[+&]", "n", low)
            n_repl = re.sub(r"[^a-z0-9-]", "", n_repl)
            and_repl = re.sub(r"[^a-z0-9-]", "", re.sub(r"[+&]", "and", low))
            is_short = len(joined) <= 3
            add_form(hyphened, strict=is_short)
            add_form(joined, strict=is_short)
            # "n"/"and" spellings only make sense for real words (Giesecke+Devrient -> gieseckeanddevrient).
            # For "G+D" they would invent 'gnd' / 'gandd' and match unrelated words.
            if len(joined) >= 5:
                add_form(n_repl, strict=False)
                add_form(and_repl, strict=False)
            co_terms = [p for p in parts if len(p) >= 4]
        else:
            split_words = [w for w in re.split(r"[\s_/]+", low) if w]
            if len(split_words) > 1:
                add_form("-".join(split_words), strict=False)
                add_form("".join(split_words), strict=False)
                for w in split_words:
                    if len(w) >= 4 and w not in _STOP_KEYWORDS:
                        add_form(w, strict=False)
                co_terms = [w for w in split_words if len(w) >= 4]
            else:
                add_form(low, strict=len(low.replace("-", "")) <= 3)
                co_terms = []

        if forms or co_terms:
            specs.append({
                "raw": raw,
                "from_domain": from_domain,
                "forms": forms,
                "strict_forms": strict_forms,
                "co_terms": co_terms,
                "phrase": re.sub(r"\s+", " ", raw.lower()).strip(),
            })

    return specs


def is_benign_word_collision(
    hostname: str,
    matched_label: str,
    keyword_spec: Optional[Dict[str, Any]],
    evidence: Optional[Dict[str, Any]] = None,
    intel: Optional[List[Dict[str, Any]]] = None,
) -> bool:
    """
    Detect harmless dictionary-word collisions (e.g. `gideon`, `guided`, `goods`, `gdpr`)
    when there is no brand evidence supporting impersonation.
    """
    ev = evidence or {}
    has_strong_signal = bool(
        (ev.get("favicon") or {}).get("exact_match")
        or (ev.get("visual_distance") is not None and ev["visual_distance"] <= 6)
        or ev.get("shared_analytics")
        or ev.get("brand_in_title")
        or ev.get("brand_resources")
        or any((i.get("match") in {"feed", "openphish_feed", "phishingdb_feed", "favicon_hash", "asset_hash", "analytics", "daily_title"}) for i in (intel or []))
    )
    if has_strong_signal:
        return False

    lbl = (matched_label or "").lower().strip()
    parts = [p for p in re.split(r"[-.]", lbl) if p]
    # Direct hit against known common unrelated dictionary words
    if any(p in _BENIGN_WORD_COLLISIONS for p in parts) or lbl in _BENIGN_WORD_COLLISIONS:
        return True

    if keyword_spec:
        forms = keyword_spec.get("forms") or []
        strict_forms = keyword_spec.get("strict_forms") or set()
        # A keyword counts as present when ANY of its forms (g-d / gd / gnd for "G+D") equals the label or one
        # of its hyphen-separated parts. Judging each form separately flagged "gd" as unrelated because it is
        # not spelled "g-d".
        present = any(f == lbl or f.replace("-", "") == lbl or f in parts or f.replace("-", "") in parts for f in forms)
        # brand glued to a lure word (gidewallet, logingide) is deliberate, not a dictionary word like "gideon"
        lures = get_lure_words()
        flat_lbl = lbl.replace("-", "").replace(".", "")
        if not present and any(len(f.replace("-", "")) >= 4 and flat_lbl in _glued(f.replace("-", ""), lures) for f in forms):
            present = True
        if strict_forms and not present:
            return True  # 'gd' only counts on an exact segment, never inside a longer word
        # Short hyphenated stem like "gi-de": "gideon" / "guided" has no hyphen and only starts with "gide"
        if not present and "-" not in lbl and "-" in (keyword_spec.get("raw") or "").lower():
            for f in forms:
                f_flat = f.replace("-", "")
                if len(f_flat) <= 4 and any(p.startswith(f_flat) and len(p) > len(f_flat) for p in parts):
                    return True
    return False


_TECHNIQUE_LABELS: Dict[str, str] = {
    "subdomain_impersonation": "Subdomain Impersonation",
    "homograph_idn": "Homograph / IDN Spoofing",
    "homograph_ascii": "Visual Homoglyph Substitution",
    "exact_brand_match": "Exact Brand Match",
    "hyphen_variation": "Hyphenation Variant",
    "combosquat": "Brand Keyword + Lure Combo",
    "typosquat_transposition": "Typosquatting (Transposition)",
    "typosquat_omission": "Typosquatting (Character Deletion)",
    "typosquat_insertion": "Typosquatting (Character Addition)",
    "typosquat_repetition": "Typosquatting (Character Repetition)",
    "typosquat_keyboard": "Typosquatting (Keyboard Neighbor)",
    "typosquat_substitution": "Typosquatting (Character Substitution)",
    "keyword_cooccurrence": "Multi-Word Brand Match",
    "content_infrastructure": "Content / Infrastructure Overlap",
    "benign_collision": "Unrelated Common Word",
    "none": "No Direct Name Match",
}


@lru_cache(maxsize=131072)
def _parse_cached(hostname: str) -> Dict[str, Any]:
    return parse_domain_parts(hostname)


@lru_cache(maxsize=131072)
def _idn_cached(fqdn: str) -> Dict[str, Any]:
    return inspect_idn(fqdn)


def _allow_set(original_domain: str, allowlist: Optional[Iterable[str]]) -> Tuple[str, Tuple[str, ...]]:
    orig_apex = registrable_domain(normalize_host(original_domain)) or normalize_host(original_domain)
    allow = {registrable_domain(normalize_host(a)) or normalize_host(a) for a in (allowlist or []) if a}
    if orig_apex:
        allow.add(orig_apex)
    return orig_apex, tuple(sorted(allow))


@lru_cache(maxsize=4096)
def _glued(form_flat: str, lures: Tuple[str, ...]) -> frozenset:
    """Brand stem glued to a lure word with no separator: gidewallet, logingide, giesecke-login -> gieseckelogin."""
    out = set()
    for w in lures:
        wf = w.replace("-", "")
        if wf and wf != form_flat:
            out.add(form_flat + wf)
            out.add(wf + form_flat)
    return frozenset(out)


def lure_context(labels: Sequence[str], forms: Sequence[str], lures: Sequence[str]) -> List[str]:
    """
    Lure words standing next to the brand in a hostname's labels (TLD excluded): login.gi-de.evil.com -> [login],
    gi-de-verification.org -> [verification], gidewallet.com -> [wallet]. Lure words equal to a brand form are ignored.
    """
    flats = [f.replace("-", "") for f in forms if len(f.replace("-", "")) >= 2]
    found: List[str] = []
    for lbl in labels:
        padded = f"-{lbl}-"
        flat = lbl.replace("-", "")
        for w in lures:
            if w in forms or w in found:
                continue
            if f"-{w}-" in padded:
                found.append(w)
                continue
            wf = w.replace("-", "")
            if any(flat in (f + wf, wf + f) for f in flats):
                found.append(w)
    return found


@lru_cache(maxsize=65536)
def _match_core(hostname: str, original_domain: str, keywords: Tuple[str, ...], allow: Tuple[str, ...],
                lures: Tuple[str, ...] = ()) -> Dict[str, Any]:
    """
    Evidence-independent part of the match (the expensive part), cached per host/brand/keyword-set.
    Callers must treat the returned dict as read-only.
    """
    parts = _parse_cached(hostname)
    fqdn, reg, sub, sld = parts["fqdn"], parts["registered_domain"], parts["subdomain"], parts["sld"]
    sub_labels = parts["subdomain_labels"]
    orig_apex = registrable_domain(normalize_host(original_domain)) or normalize_host(original_domain)
    idn_info = _idn_cached(fqdn)
    specs = expand_analyst_keywords(orig_apex, keywords=keywords)
    is_own = bool(reg and reg in allow)

    best: Optional[Tuple[int, float, int, str, str, str, str, Dict[str, Any]]] = None
    per_keyword: Dict[str, Dict[str, Any]] = {}

    def consider(tier: int, technique: str, sim: float, matched_in: str, matched_label: str, spec: Dict[str, Any], weak: bool) -> None:
        nonlocal best
        sim = round(sim, 1)
        rank = (tier, sim, 0 if weak else 1)
        rec = per_keyword.get(spec["raw"])
        if rec is None or rank > rec["_rank"]:
            per_keyword[spec["raw"]] = {"keyword": spec["raw"], "technique_key": technique, "similarity_percent": sim,
                                        "matched_in": matched_in, "matched_label": matched_label,
                                        "keyword_strength": "weak" if weak else "strong", "_rank": rank}
        if best is None or rank > best[:3]:
            best = (tier, sim, 0 if weak else 1, matched_in, technique, spec["raw"], matched_label, spec)

    sub_unicode_labels = [decode_idna_label(lbl) for lbl in sub_labels]
    sld_unicode = decode_idna_label(sld)
    idn, mixed = idn_info["is_idn"], idn_info["mixed_script"]

    for spec in specs:
        for form in spec["forms"]:
            is_strict = form in spec["strict_forms"]
            # 1) the registered domain's own label
            if is_strict:
                sld_segments = [p for p in sld_unicode.split("-") if p]
                if sld_unicode == form or form in sld_segments:
                    t = "homograph_idn" if (idn and mixed) else ("exact_brand_match" if sld_unicode == form else "combosquat")
                    sim = 100.0 if sld_unicode == form else round(max(78.0, len(form) / max(len(sld_unicode), 1) * 100.0), 1)
                    consider(4 if t == "homograph_idn" else 3, t, sim, "sld", sld_unicode, spec, True)
            else:
                tech, sim = _classify_typo(sld_unicode, form, is_idn=idn, mixed_script=mixed)
                if tech:
                    tier = 4 if tech in ("homograph_idn", "exact_brand_match") else (3 if tech in ("combosquat", "hyphen_variation", "homograph_ascii") else 2)
                    consider(tier, tech, sim, "sld", sld_unicode, spec, False)
            # 1b) brand glued to a lure word (gidewallet.com): too short for a substring match, safe with the lure
            f_flat = form.replace("-", "")
            if not is_strict and len(f_flat) >= 4 and lures:
                glued = _glued(f_flat, lures)
                if sld_unicode.replace("-", "") in glued:
                    sim = round(max(74.0, len(f_flat) / max(len(sld_unicode.replace("-", "")), 1) * 100.0), 1)
                    consider(3, "combosquat", sim, "sld", sld_unicode, spec, False)

            # 2) every subdomain label, even when the registered domain is unrelated (gi-de.astrobale-core.tech)
            if is_own:
                continue
            for lbl in sub_unicode_labels:
                if lbl in _INFRA_SUBDOMAIN_LABELS and lbl != form:
                    continue
                if is_strict:
                    segs = [p for p in lbl.split("-") if p]
                    if lbl == form or form in segs:
                        sim = 100.0 if lbl == form else round(max(82.0, len(form) / max(len(lbl), 1) * 100.0), 1)
                        consider(4, "subdomain_impersonation", sim, "subdomain", lbl, spec, True)
                else:
                    tech, sim = _classify_typo(lbl, form, is_idn=idn, mixed_script=mixed)
                    if tech:
                        consider(4 if tech in ("exact_brand_match", "hyphen_variation", "combosquat", "homograph_idn") else 3,
                                 "subdomain_impersonation", max(sim, 85.0 if tech != "typosquat_substitution" else sim),
                                 "subdomain", lbl, spec, False)
            # 2b) brand split across adjacent labels: gi.de.attacker.com, giesecke.devrient.attacker.net
            if not is_strict and len(form.replace("-", "")) >= 4 and len(sub_unicode_labels) >= 2:
                target = skeletonize(form.replace("-", ""))
                for i in range(len(sub_unicode_labels) - 1):
                    pair = sub_unicode_labels[i:i + 2]
                    if skeletonize("".join(pair)) == target:
                        consider(4, "subdomain_impersonation", 95.0, "subdomain", ".".join(pair), spec, False)
            # 2c) brand glued to a lure word inside a subdomain label (gidelogin.attacker.net)
            if not is_strict and len(f_flat) >= 4 and lures:
                glued = _glued(f_flat, lures)
                for lbl in sub_unicode_labels:
                    if lbl.replace("-", "") in glued:
                        consider(4, "subdomain_impersonation", 88.0, "subdomain", lbl, spec, False)

        # 3) multi-word keyword co-occurrence across the full hostname (giesecke + devrient)
        if spec.get("co_terms") and len(spec["co_terms"]) >= 2:
            full_flat = skeletonize(decode_idna_host(fqdn))
            if all(t.replace("-", "") in full_flat for t in spec["co_terms"]):
                sub_flat = skeletonize(".".join(sub_unicode_labels))
                in_sub = bool(sub) and not is_own and all(t.replace("-", "") in sub_flat for t in spec["co_terms"])
                consider(4 if in_sub else 3, "subdomain_impersonation" if in_sub else "keyword_cooccurrence", 92.0,
                         "subdomain" if in_sub else "sld", sub if in_sub else sld_unicode, spec, False)

    for rec in per_keyword.values():
        rec.pop("_rank", None)
    return {"parts": parts, "idn": idn_info, "orig_apex": orig_apex, "is_own": is_own, "best": best,
            "per_keyword": tuple(per_keyword.values()), "sub_unicode_labels": tuple(sub_unicode_labels), "sld_unicode": sld_unicode}


def evaluate_domain_match(
    hostname: str,
    original_domain: str,
    keywords: Optional[Sequence[str]] = None,
    allowlist: Optional[Iterable[str]] = None,
    evidence: Optional[Dict[str, Any]] = None,
    intel: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Evaluate a discovered hostname against the original domain and every analyst keyword
    across subdomains, SLD, registered domain, Unicode/Punycode representation, and skeletons.

    The name analysis is cached; `evidence` / `intel` only influence the benign-word-collision decision,
    so evaluating the same host repeatedly (CT, intel, scoring) costs one real evaluation.
    """
    orig_apex, allow = _allow_set(original_domain, allowlist)
    kws = tuple(k for k in (keywords or ()) if isinstance(k, str))
    lures = get_lure_words()
    core = _match_core(hostname or "", original_domain or "", kws, allow, lures)
    parts, idn_info = core["parts"], core["idn"]
    fqdn, reg, sub, sld = parts["fqdn"], parts["registered_domain"], parts["subdomain"], parts["sld"]
    is_own = core["is_own"]
    sub_unicode_labels = list(core["sub_unicode_labels"])
    sld_unicode = core["sld_unicode"]
    best = core["best"]

    strength = ""
    if best is not None:
        _, sim, strong_flag, matched_in, technique, keyword_raw, matched_label, spec = best
        strength = "strong" if strong_flag else "weak"
        benign_col = is_benign_word_collision(fqdn, matched_label, spec, evidence=evidence, intel=intel)
        if matched_in == "subdomain":
            benign_col = False  # the technique says "subdomain impersonation": never also "unrelated word"
        elif benign_col:
            technique = "benign_collision"
    else:
        sim = 0.0
        matched_in = "none"
        technique = "content_infrastructure" if (evidence or intel) else "none"
        keyword_raw = ""
        matched_label = sld_unicode
        benign_col = False
        # Still check if the domain itself is a common collision word
        if any(p in _BENIGN_WORD_COLLISIONS for p in re.split(r"[-.]", sld_unicode)):
            benign_col = True
            technique = "benign_collision"

    # Exact subdomain label that triggered impersonation (multi-level: login.gi-de.attacker-domain.com)
    matching_subdomain = ""
    if technique == "subdomain_impersonation" and sub:
        matching_subdomain = matched_label if matched_label in sub_unicode_labels else sub

    reasons: List[str] = []
    if technique == "subdomain_impersonation" and not is_own:
        reasons.append(f"Brand keyword '{keyword_raw}' appears in subdomain '{sub}' of third-party domain '{reg}'")
    elif technique == "homograph_idn":
        scripts_str = "/".join(idn_info["scripts"]) or "Unicode"
        reasons.append(f"IDN/homograph domain ({scripts_str}) visually mimics '{keyword_raw}'")
    elif technique in ("homograph_ascii", "hyphen_variation", "combosquat", "exact_brand_match", "keyword_cooccurrence") or technique.startswith("typosquat_"):
        reasons.append(f"{_TECHNIQUE_LABELS.get(technique, technique)} matching '{keyword_raw}' ({sim:.0f}% similarity)")
    if strength == "weak" and technique not in ("none", "benign_collision", "content_infrastructure"):
        reasons.append(f"'{keyword_raw}' is a very short abbreviation: weak evidence on its own")
    if idn_info["mixed_script"]:
        reasons.append(f"Mixed/non-Latin script detected ({', '.join(idn_info['scripts'])})")

    # Brand + malicious context (login / verify / wallet / payment ...): only meaningful next to a real brand match
    context: List[str] = []
    if best is not None and technique in NAME_MATCH_TECHNIQUES and not is_own:
        context = lure_context(sub_unicode_labels + [sld_unicode], spec["forms"], lures)
        if context:
            reasons.append(f"Brand + malicious context: {', '.join(context[:4])}")

    keyword_hits = [dict(h) for h in core["per_keyword"]]
    return {
        "domain": fqdn,
        "registered_domain": reg,
        "matching_subdomain": matching_subdomain,
        "subdomain": sub,
        "sld": sld,
        "tld": parts["tld"],
        "original_domain": orig_apex,
        "matched_keyword": keyword_raw,
        "matched_keywords": [h["keyword"] for h in keyword_hits],
        "keyword_hits": keyword_hits,
        "keyword_strength": strength,
        "matching_technique": _TECHNIQUE_LABELS.get(technique, technique),
        "technique_key": technique,
        "similarity_percent": sim,
        "matched_in": matched_in,
        "is_subdomain_impersonation": bool(technique == "subdomain_impersonation" and not is_own),
        "is_idn": idn_info["is_idn"],
        "mixed_script": idn_info["mixed_script"],
        "scripts": idn_info["scripts"],
        "unicode": idn_info["unicode_host"],
        "is_benign_collision": benign_col,
        "is_own_domain": is_own,
        "match_reasons": reasons,
        "context_keywords": context,
    }


# Techniques where the NAME itself imitates a brand keyword (as opposed to "no match" / dictionary collisions).
NAME_MATCH_TECHNIQUES = frozenset({
    "subdomain_impersonation", "homograph_idn", "homograph_ascii", "exact_brand_match", "hyphen_variation",
    "combosquat", "keyword_cooccurrence", "typosquat_transposition", "typosquat_omission", "typosquat_insertion",
    "typosquat_repetition", "typosquat_keyboard", "typosquat_substitution",
})

# Evidence that is independent of the domain NAME. A name match alone never earns "Confirmed Impersonation".
_CORROBORATING_INTEL = {
    "feed": "listed in a phishing feed",
    "favicon_hash": "serves the brand's favicon (hash match)",
    "asset_hash": "loads the brand's logo/favicon files",
    "analytics": "contains the brand's analytics ID",
    "daily_title": "brand title cloned (URLScan)",
    "safe_browsing": "listed by Google Safe Browsing",
}


def corroborating_evidence(cand: Dict[str, Any]) -> List[str]:
    """
    Independent, non-name evidence that the site actually imitates the brand or is already known malicious:
    page content (identical favicon / logo, cloned title or text, brand resources, shared analytics ID) or
    threat-intel (phishing feed, favicon/asset-hash match, VirusTotal vendors). Returned as readable strings.
    """
    ev = cand.get("evidence") or {}
    out: List[str] = []
    fav = ev.get("favicon") or {}
    vd = ev.get("visual_distance")
    if fav.get("exact_match"):
        out.append("favicon is byte-identical to the brand's")
    if vd is not None and vd <= 10:
        out.append(f"logo/favicon visually matches the brand (pHash distance {vd})")
    if ev.get("shared_analytics"):
        out.append("shares the brand's analytics ID")
    if ev.get("brand_resources"):
        out.append(f"loads {ev['brand_resources']} resource(s) from the brand's own servers")
    if ev.get("brand_in_title"):
        out.append("brand name in the page title")
    if (ev.get("title_similarity") or 0) >= 0.85:
        out.append("page title is a near-copy of the brand's")
    if (ev.get("text_similarity") or 0) >= 0.5:
        out.append("page text closely matches the brand homepage")
    for i in cand.get("intel") or []:
        votes = int(i.get("malicious_votes") or 0)
        if i.get("source") == "virustotal" and votes >= 2:
            out.append(f"VirusTotal: {votes} vendors flag it malicious")
        elif i.get("match") in _CORROBORATING_INTEL:
            out.append(_CORROBORATING_INTEL[i["match"]])
    return list(dict.fromkeys(out))


def classify_candidate(cand: Dict[str, Any], score: Optional[int] = None, verdict: Optional[str] = None) -> str:
    """
    Map detailed verdict + match signals into the 3 high-level analyst classifications:
      - 'Confirmed Impersonation'  : high score AND independent corroboration beyond the domain name
      - 'Potential Impersonation'  : a name match or suspicious signals that still need analyst review
      - 'Benign/Unrelated'
    """
    v = verdict or cand.get("verdict") or ""
    s = cand.get("score") if score is None else score
    s = int(s or 0)
    mm = cand.get("match_meta") or {}
    weak_kw = mm.get("keyword_strength") == "weak"

    if v in ("brand_owned", "redirect_brand"):
        return "Benign/Unrelated"
    if mm.get("is_benign_collision") and v not in ("phishing",):
        return "Benign/Unrelated"
    if v == "phishing" or s >= 70:
        # Pre-computed by the scorer when available, otherwise derived from the candidate's own evidence.
        corroborated = cand["corroboration"] if "corroboration" in cand else corroborating_evidence(cand)
        return "Confirmed Impersonation" if corroborated else "Potential Impersonation"
    if v in ("suspicious", "offline", "parked") or s >= 35 or (mm.get("is_subdomain_impersonation") and not weak_kw) \
            or (mm.get("is_idn") and mm.get("mixed_script")):
        return "Potential Impersonation"
    # A strong brand-name match (exact / combo / typo / homograph of a real keyword) is a lead until the site is
    # shown to be unrelated. Only an inspected live site with no brand content ("live_unrelated") clears it;
    # "registered, no website" or "could not be reached" cannot disprove it. Very short abbreviations never
    # qualify on the name alone.
    if mm.get("technique_key") in NAME_MATCH_TECHNIQUES and not weak_kw and not mm.get("is_own_domain") \
            and v != "live_unrelated":
        return "Potential Impersonation"
    return "Benign/Unrelated"
