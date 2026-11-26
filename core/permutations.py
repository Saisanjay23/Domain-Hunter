"""
Typosquat / lookalike domain permutation engine (dnstwist-style fuzzers).

    generate_permutations("adani.com")  ->  [{"domain": "adanl.com", "fuzzer": "replacement", ...}, ...]

Fuzzers work on the brand label only and keep the public suffix intact (bbc.co.uk fuzzes
"bbc", never "co"). The suffix is then swapped separately (tld-swap) and fuzzed labels
are also tried on .com / .net for brands that are not on .com.

Depth:
    quick     ~ few hundred candidates, the highest-yield fuzzers only
    standard  ~ 1-3k candidates (default)
    deep      ~ 5-15k candidates, every fuzzer on several TLDs
"""

import re
from typing import Dict, Iterable, List, Optional

from .domains import split_host

DEPTHS = ("quick", "standard", "deep")

_VALID_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

QWERTY = {
    "1": "2q", "2": "3wq1", "3": "4ew2", "4": "5re3", "5": "6tr4", "6": "7yt5", "7": "8uy6", "8": "9iu7", "9": "0oi8", "0": "po9",
    "q": "12wa", "w": "3esaq2", "e": "4rdsw3", "r": "5tfde4", "t": "6ygfr5", "y": "7uhgt6", "u": "8ijhy7", "i": "9okju8", "o": "0plki9", "p": "lo0",
    "a": "qwsz", "s": "edxzaw", "d": "rfcxse", "f": "tgvcdr", "g": "yhbvft", "h": "ujnbgy", "j": "ikmnhu", "k": "olmji", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}

# ASCII lookalikes that are valid in hostnames.
ASCII_GLYPHS = {
    "a": ["4"], "b": ["6", "lb"], "d": ["cl", "b"], "e": ["3"], "g": ["q", "9"], "i": ["1", "l"],
    "l": ["1", "i"], "m": ["rn", "nn"], "n": ["m", "r"], "o": ["0"], "q": ["g"], "s": ["5"],
    "u": ["v"], "v": ["u"], "w": ["vv"], "z": ["2"], "0": ["o"], "1": ["l", "i"], "5": ["s"],
}
ASCII_GLYPHS_MULTI = {"rn": "m", "nn": "m", "vv": "w", "cl": "d", "ii": "u"}

# Unicode lookalikes (registered as punycode xn--). Cyrillic first: they render identically.
UNICODE_GLYPHS = {
    "a": ["а", "à", "á", "ä", "å", "ą"],
    "c": ["с", "ç"],
    "d": ["ԁ"],
    "e": ["е", "è", "é", "ê", "ë", "ę"],
    "g": ["ɡ"],
    "h": ["һ"],
    "i": ["і", "í", "ï", "ı"],
    "j": ["ј"],
    "k": ["κ"],
    "l": ["ł", "ӏ"],
    "n": ["ñ", "ń"],
    "o": ["о", "ò", "ó", "ö", "ø", "ο"],
    "p": ["р"],
    "s": ["ѕ", "ś"],
    "u": ["ü", "ú", "µ"],
    "x": ["х"],
    "y": ["у", "ý"],
    "z": ["ż", "ž"],
}

VOWELS = "aeiou"

# Words phishers bolt onto a brand (combosquatting). Ordered by how often they appear in phishing.
COMBO_WORDS = [
    "login", "secure", "support", "verify", "account", "online", "portal", "update", "pay", "app",
    "help", "service", "signin", "auth", "my", "web", "kyc", "wallet", "bank", "official",
    "group", "india", "global", "careers", "jobs", "offer", "rewards", "invest", "mail", "id",
    "access", "connect", "client", "customer", "billing", "payment", "refund", "claim", "gift", "promo",
    "cloud", "team", "hr", "admin", "info", "net", "shop", "store", "trade", "crypto",
    "corp", "ltd", "inc", "us", "uk", "uae", "ksa", "hq", "center", "desk",
]
COMBO_COUNT = {"quick": 12, "standard": 40, "deep": len(COMBO_WORDS)}

# TLDs that are cheap, popular with phishers, or simply common.
TLDS_QUICK = ["com", "net", "org", "co", "io", "info", "xyz", "online", "site", "top", "shop", "app", "in", "us", "me", "cc", "biz", "live", "pro", "vip"]
TLDS_STANDARD = TLDS_QUICK + [
    "store", "tech", "cloud", "dev", "icu", "club", "ws", "pw", "su", "ru", "cn", "tk", "ml", "ga", "cf", "gq",
    "ltd", "group", "world", "life", "today", "email", "support", "services", "finance", "help", "link", "click",
    "work", "buzz", "asia", "eu", "uk", "co.uk", "de", "fr", "nl", "ae", "sa", "com.sa", "co.in", "net.in", "org.in",
    "ai", "id", "ph", "my", "sg", "hk", "com.au", "ca", "mobi", "cyou", "sbs", "lol", "rest", "bond", "monster",
]
TLDS_DEEP = TLDS_STANDARD + [
    "ink", "fun", "space", "website", "digital", "network", "systems", "solutions", "agency", "company", "center",
    "zone", "best", "host", "press", "news", "media", "global", "today", "one", "plus", "tel", "name", "page",
    "chat", "social", "money", "cash", "loan", "loans", "credit", "exchange", "trade", "market", "deals", "sale",
    "br", "com.br", "mx", "es", "it", "pl", "tr", "com.tr", "ir", "pk", "com.pk", "bd", "lk", "np", "ng", "za", "co.za",
    "ke", "jp", "kr", "tw", "vn", "th", "nz", "ie", "ch", "at", "be", "se", "no", "dk", "fi", "pt", "gr", "ro", "ua", "kz",
]
TLDS = {"quick": TLDS_QUICK, "standard": TLDS_STANDARD, "deep": TLDS_DEEP}


def _valid_label(label: str) -> bool:
    if not _VALID_LABEL.match(label):
        return False
    # Labels with '--' in positions 3-4 are reserved for IDNA (xn--) except our own punycode output
    return not (label[2:4] == "--" and not label.startswith("xn--"))


# ------------------------------------------------------------------ fuzzers
def omission(label: str) -> Iterable[str]:
    for i in range(len(label)):
        yield label[:i] + label[i + 1:]


def repetition(label: str) -> Iterable[str]:
    for i, c in enumerate(label):
        if c.isalnum():
            yield label[:i] + c + label[i:]


def transposition(label: str) -> Iterable[str]:
    for i in range(len(label) - 1):
        if label[i] != label[i + 1]:
            yield label[:i] + label[i + 1] + label[i] + label[i + 2:]


def replacement(label: str) -> Iterable[str]:
    for i, c in enumerate(label):
        for k in QWERTY.get(c, ""):
            yield label[:i] + k + label[i + 1:]


def insertion(label: str) -> Iterable[str]:
    for i, c in enumerate(label):
        for k in QWERTY.get(c, ""):
            yield label[:i] + k + label[i:]
            yield label[:i + 1] + k + label[i + 1:]


def vowel_swap(label: str) -> Iterable[str]:
    for i, c in enumerate(label):
        if c in VOWELS:
            for v in VOWELS:
                if v != c:
                    yield label[:i] + v + label[i + 1:]


def hyphenation(label: str) -> Iterable[str]:
    for i in range(1, len(label)):
        if label[i - 1] != "-" and label[i] != "-":
            yield label[:i] + "-" + label[i:]


def bitsquatting(label: str) -> Iterable[str]:
    for i, c in enumerate(label):
        for bit in range(8):
            flipped = chr(ord(c) ^ (1 << bit))
            if flipped in "abcdefghijklmnopqrstuvwxyz0123456789-":
                yield label[:i] + flipped + label[i + 1:]


def addition(label: str, prepend: bool = False) -> Iterable[str]:
    for c in "abcdefghijklmnopqrstuvwxyz0123456789":
        yield label + c
        if prepend:
            yield c + label


def homoglyph_ascii(label: str) -> Iterable[str]:
    for i, c in enumerate(label):
        for g in ASCII_GLYPHS.get(c, []):
            yield label[:i] + g + label[i + 1:]
    for seq, rep in ASCII_GLYPHS_MULTI.items():
        start = label.find(seq)
        while start != -1:
            yield label[:start] + rep + label[start + len(seq):]
            start = label.find(seq, start + 1)


def homoglyph_unicode(label: str, all_positions: bool = False) -> Iterable[str]:
    """Yields unicode lookalikes (one substituted character; optionally every occurrence)."""
    for i, c in enumerate(label):
        for g in UNICODE_GLYPHS.get(c, []):
            yield label[:i] + g + label[i + 1:]
            if all_positions and label.count(c) > 1:
                yield label.replace(c, g)


def combosquatting(label: str, words: List[str]) -> Iterable[str]:
    for w in words:
        if w == label:
            continue
        yield f"{label}-{w}"
        yield f"{label}{w}"
        yield f"{w}-{label}"
        yield f"{w}{label}"


def various(label: str) -> Iterable[str]:
    yield "www" + label
    yield "www-" + label
    yield label + "com"
    yield label + "-com"
    yield label + "online"
    if "-" in label:
        yield label.replace("-", "")
        yield label.replace("-", ".")  # gi-de -> gi.de style (only valid when it lands on a real suffix)


def to_ascii(label: str) -> Optional[str]:
    """IDNA-encodes a label (unicode -> xn--). Returns None if it cannot be encoded."""
    if label.isascii():
        return label
    try:
        return label.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None


# ------------------------------------------------------------------ engine
def generate_permutations(
    domain: str,
    depth: str = "standard",
    extra_keywords: Optional[List[str]] = None,
    max_results: int = 20000,
) -> List[Dict[str, str]]:
    """
    Generates lookalike candidates for a brand's registrable domain.
    Returns a list of {"domain", "fuzzer", "unicode"} (unicode is the display form for IDN).
    """
    depth = depth if depth in DEPTHS else "standard"
    _, label, suffix = split_host(domain)
    if not label or not suffix:
        return []
    original = f"{label}.{suffix}"
    if label.startswith("xn--"):
        try:
            label = label.encode("ascii").decode("idna")
        except UnicodeError:
            pass

    out: Dict[str, Dict[str, str]] = {}

    def add(new_label: str, fuzzer: str, tld: str = suffix) -> None:
        if len(out) >= max_results or not new_label:
            return
        if "." in new_label:  # "various" dotted form, e.g. gi.de -> keep only if it is a real host
            parts = new_label.split(".")
            if not all(_valid_label(p) for p in parts):
                return
            full = f"{new_label}.{tld}"
        else:
            enc = to_ascii(new_label)
            if not enc or not _valid_label(enc):
                return
            full = f"{enc}.{tld}"
        if full == original or full in out:
            return
        out[full] = {"domain": full, "fuzzer": fuzzer, "unicode": f"{new_label}.{tld}" if not new_label.isascii() else ""}

    # Suffix variants to apply to fuzzed labels: the original suffix plus .com/.net when different.
    extra_tlds = [] if depth == "quick" else [t for t in ("com", "net") if t != suffix]
    if depth == "deep":
        extra_tlds += [t for t in ("org", "co", "in", "xyz", "online") if t != suffix and t not in extra_tlds]

    fuzzers = [
        ("omission", omission(label)),
        ("repetition", repetition(label)),
        ("transposition", transposition(label)),
        ("replacement", replacement(label)),
        ("homoglyph", homoglyph_ascii(label)),
        ("vowel-swap", vowel_swap(label)),
        ("hyphenation", hyphenation(label)),
        ("various", various(label)),
    ]
    if depth in ("standard", "deep"):
        fuzzers += [
            ("insertion", insertion(label)),
            ("bitsquatting", bitsquatting(label)),
            ("addition", addition(label, prepend=depth == "deep")),
            ("idn-homoglyph", homoglyph_unicode(label, all_positions=depth == "deep")),
        ]

    for name, gen in fuzzers:
        for cand in gen:
            add(cand, name)
            for t in extra_tlds:
                add(cand, name, t)

    # Combosquatting: brand + keyword on the original suffix and .com
    words = COMBO_WORDS[:COMBO_COUNT[depth]]
    clean_extras: List[str] = []
    for raw_kw in extra_keywords or []:
        kw = (raw_kw or "").strip().lower()
        if not kw:
            continue
        if "+" in kw or "&" in kw:
            parts = [re.sub(r"[^a-z0-9-]", "", p) for p in re.split(r"[+&/\s]+", kw) if p.strip()]
            joined = "".join(parts)
            hyph = "-".join(p for p in parts if p)
            if len(hyph) >= 2:
                clean_extras.append(hyph)
            if len(joined) >= 2 and joined != hyph:
                clean_extras.append(joined)
            for p in parts:
                if len(p) >= 4:
                    clean_extras.append(p)
        else:
            norm = re.sub(r"[^a-z0-9-]+", "-", kw).strip("-")
            if norm:
                clean_extras.append(norm)
                if "-" in norm:
                    clean_extras.append(norm.replace("-", ""))

    words = list(dict.fromkeys(words + [w for w in clean_extras if 2 <= len(w) <= 24]))
    combo_tlds = [suffix] + [t for t in ("com",) if t != suffix]
    if depth == "deep":
        combo_tlds += [t for t in ("net", "online", "xyz") if t not in combo_tlds]
    for cand in combosquatting(label, words):
        for t in combo_tlds:
            add(cand, "combosquat", t)

    # Independent keyword typosquats + brand-keyword combos (for multi-keyword analyst inputs)
    for kw_label in clean_extras[:6]:
        if kw_label == label or len(kw_label.replace("-", "")) < 4:
            # Short <=3 char abbreviations (like G+D -> 'gd') get targeted lure combos only
            if 2 <= len(kw_label.replace("-", "")) <= 3:
                for lure in ("login", "secure", "security", "portal", "verify"):
                    add(f"{kw_label}-{lure}", "combosquat", suffix)
                    if "com" != suffix:
                        add(f"{kw_label}-{lure}", "combosquat", "com")
            continue
        for t in (suffix, "com", "net", "org"):
            add(kw_label, "keyword-exact", t)
        for cand in combosquatting(kw_label, COMBO_WORDS[:6]):
            add(cand, "combosquat", suffix)
            if "com" != suffix:
                add(cand, "combosquat", "com")
        for fname, kgen in (
            ("omission", omission(kw_label)),
            ("repetition", repetition(kw_label)),
            ("transposition", transposition(kw_label)),
            ("replacement", replacement(kw_label)),
            ("homoglyph", homoglyph_ascii(kw_label)),
            ("hyphenation", hyphenation(kw_label)),
        ):
            for cand in kgen:
                add(cand, fname, suffix)
                if depth != "quick" and "com" != suffix:
                    add(cand, fname, "com")

    # TLD swap of the untouched label
    for t in TLDS[depth]:
        if t != suffix:
            add(label, "tld-swap", t)

    # Brand on a deeper suffix of its own ccTLD: adani.co.in -> adani.in, adani.com.sa -> adani.sa
    if "." in suffix:
        add(label, "tld-swap", suffix.split(".")[-1])

    return list(out.values())


def permutation_stats(perms: List[Dict[str, str]]) -> Dict[str, int]:
    stats: Dict[str, int] = {}
    for p in perms:
        stats[p["fuzzer"]] = stats.get(p["fuzzer"], 0) + 1
    return dict(sorted(stats.items(), key=lambda kv: -kv[1]))
