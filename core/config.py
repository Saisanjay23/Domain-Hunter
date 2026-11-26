"""
API-key configuration. Keys come from environment variables or a `.env` file in the project
root. The web UI's "API keys" page can write the .env file (localhost only); key values are
never sent back to the browser, only a masked hint (last 4 characters).

    URLSCAN_API_KEY   optional: anonymous search works, a key raises rate limits / unlocks more fields
    SHODAN_API_KEY    Shodan search API (filters need a paid membership)
    FOFA_KEY          FOFA API key   (FOFA_EMAIL too, for older accounts)
    CENSYS_PAT        Censys Platform personal access token (CENSYS_ORG_ID for organisation accounts)
    SERPAPI_KEY       SerpApi, used for automated Google Lens reverse logo search
    WHOISXML_API_KEY  WhoisXML API key (Brand Alert daily NRD + Domains & Subdomains Discovery)
"""

import hashlib
import os
import re
import tempfile
from typing import Dict, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(PROJECT_ROOT, ".env")

SOURCES = {
    "urlscan": {"name": "URLScan", "env": ["URLSCAN_API_KEY"], "key_required": False,
                "does": "Scans that loaded the brand's favicon/logo/JS files, lookalike domains, free-hosting pages"},
    "shodan": {"paid": True, "name": "Shodan", "env": ["SHODAN_API_KEY"], "key_required": True,
               "does": "Servers serving the brand favicon, cloned titles, the brand's analytics ID in HTML"},
    "fofa": {"paid": True, "name": "FOFA", "env": ["FOFA_KEY", "FOFA_EMAIL"], "key_required": True,
             "does": "Servers serving the brand favicon, lookalike hosts/titles, analytics ID in page body"},
    "censys": {"paid": True, "name": "Censys", "env": ["CENSYS_PAT", "CENSYS_ORG_ID"], "key_required": True,
               "does": "Hosts and web properties serving the brand favicon, lookalike titles/hostnames"},
    "serpapi": {"paid": True, "name": "Google Lens (SerpApi)", "env": ["SERPAPI_KEY"], "key_required": True,
                "does": "Automated reverse image search of the brand logo"},
    "whoisxml": {"paid": True, "name": "WhoisXML", "env": ["WHOISXML_API_KEY"], "key_required": True,
                 "does": "Daily newly registered/updated lookalike domains (Brand Alert) & domain discovery"},
    "virustotal": {"name": "VirusTotal", "env": ["VIRUSTOTAL_API_KEY"], "key_required": True,
                   "does": "Search flagged URLs, malicious/suspicious domains & subdomain intelligence"},
    "safebrowsing": {"name": "Google Safe Browsing", "env": ["GOOGLE_SAFE_BROWSING_KEY"], "key_required": True,
                     "does": "Checks every candidate against Google's phishing / malware lists (Lookup API v4)"},
    "otx": {"name": "AlienVault OTX", "env": ["OTX_API_KEY"], "key_required": False,
            "does": "Passive DNS: other hostnames seen under a suspicious registered domain (works without a key)"},
}

# Everything the settings page may read or write (whitelist).
KEY_FIELDS = {
    "URLSCAN_API_KEY": {"source": "urlscan", "label": "API key", "secret": True, "required": False},
    "SHODAN_API_KEY": {"source": "shodan", "label": "API key", "secret": True, "required": True},
    "FOFA_KEY": {"source": "fofa", "label": "API key", "secret": True, "required": True},
    "FOFA_EMAIL": {"source": "fofa", "label": "Account e-mail (older accounts only)", "secret": False, "required": False},
    "CENSYS_PAT": {"source": "censys", "label": "Personal access token", "secret": True, "required": True},
    "CENSYS_ORG_ID": {"source": "censys", "label": "Organisation ID (organisation accounts only)", "secret": False, "required": False},
    "SERPAPI_KEY": {"source": "serpapi", "label": "API key", "secret": True, "required": True},
    "WHOISXML_API_KEY": {"source": "whoisxml", "label": "API key", "secret": True, "required": True},
    "VIRUSTOTAL_API_KEY": {"source": "virustotal", "label": "API key", "secret": True, "required": True},
    "GOOGLE_SAFE_BROWSING_KEY": {"source": "safebrowsing", "label": "API key", "secret": True, "required": True},
    "OTX_API_KEY": {"source": "otx", "label": "API key (optional, raises limits)", "secret": True, "required": False},
    # Storage backend (not a threat-intel source). The URI holds credentials, so it is a secret, but a single
    # value: replica-set URIs contain commas, so it must never be split into a key list.
    "MONGODB_URI": {"source": "mongodb", "label": "Connection string", "secret": True, "required": False, "multi": False},
    "MONGODB_DB": {"source": "mongodb", "label": "Database name", "secret": False, "required": False},
}

SOURCE_LINKS = {
    "urlscan": "https://urlscan.io/user/profile/",
    "shodan": "https://account.shodan.io/",
    "fofa": "https://en.fofa.info/",
    "censys": "https://platform.censys.io/",
    "serpapi": "https://serpapi.com/manage-api-key",
    "whoisxml": "https://user.whoisxmlapi.com/products",
    "virustotal": "https://www.virustotal.com/gui/my-apikey",
    "safebrowsing": "https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com",
    "otx": "https://otx.alienvault.com/api",
}

_VALUE_RE = re.compile(r"^[\x21-\x7e]{1,512}$")  # printable ASCII, no spaces / newlines
_ITEM_RE = re.compile(r"^[\x21-\x2b\x2d-\x7e]{1,512}$")  # one key of a list: same, minus the comma separator

# Secret variables hold a comma-separated list of keys that are rotated (SHODAN_API_KEY=key1,key2).
MULTI_KEY_FIELDS = {name for name, meta in KEY_FIELDS.items() if meta["secret"] and meta.get("multi", True)}
MAX_KEYS = 10

_loaded_mtime: Optional[float] = None   # mtime of the .env we last read (None = never read)
_from_file: set = set()                 # variables that came from .env (they may be updated / removed)


def _mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except OSError:
        return -1.0


def load_env(path: Optional[str] = None) -> None:
    """
    Minimal .env reader (KEY=value lines). Real environment variables win over the file;
    values that came from the file are refreshed (or removed) when the file changes.
    """
    global _loaded_mtime
    path = path or ENV_FILE
    _loaded_mtime = _mtime(path)
    values: Dict[str, str] = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip().removeprefix("export ").strip()
                v = v.strip().strip('"').strip("'")
                if k and v:
                    values[k] = v
    for k in list(_from_file):
        if k not in values:
            os.environ.pop(k, None)
            _from_file.discard(k)
    for k, v in values.items():
        if k not in os.environ or k in _from_file:
            os.environ[k] = v
            _from_file.add(k)


def _raw(name: str) -> str:
    if _loaded_mtime is None or _mtime(ENV_FILE) != _loaded_mtime:
        load_env()  # first use, or .env was created / edited while the server runs
    return os.environ.get(name, "").strip()


def split_keys(raw: str) -> List[str]:
    return list(dict.fromkeys(k.strip() for k in (raw or "").split(",") if k.strip()))


def get_list(name: str) -> List[str]:
    """All keys of a variable, in order (a single value is a list of one)."""
    raw = _raw(name)
    return split_keys(raw) if name in MULTI_KEY_FIELDS else ([raw] if raw else [])


def get(name: str) -> Optional[str]:
    """The (first) value of a variable."""
    vals = get_list(name)
    return vals[0] if vals else None


def key_id(value: str) -> str:
    """Stable, non-reversible reference to a key, so the UI can address it without seeing it."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]


def is_configured(source: str) -> bool:
    meta = SOURCES[source]
    return (not meta["key_required"]) or bool(get(meta["env"][0]))


# Paid platforms (Shodan, FOFA, Censys, SerpApi, WhoisXML) are never called while free mode is on, which is the
# default: a saved key whose plan cannot run the searches only produces errors. FREE_ONLY_MODE=0 turns them back on.
def free_only() -> bool:
    return _raw("FREE_ONLY_MODE").lower() not in ("0", "false", "no", "off")


def is_paid(source: str) -> bool:
    return bool((SOURCES.get(source) or {}).get("paid"))


def is_enabled(source: str) -> bool:
    """Should automated searches call this source? Free built-ins always; paid ones only outside free mode."""
    if source not in SOURCES:
        return True
    if is_paid(source) and free_only():
        return False
    return is_configured(source)


def mask(value: Optional[str]) -> str:
    """Never reveals a key: last 4 characters only, and only for values long enough to hide."""
    if not value:
        return ""
    return f"•••• {value[-4:]}" if len(value) >= 12 else "••••"


def key_status() -> List[Dict]:
    """Per-variable status for the settings page: where the value comes from and a masked hint."""
    get("URLSCAN_API_KEY")  # make sure .env is loaded / refreshed
    out = []
    for name, meta in KEY_FIELDS.items():
        val = os.environ.get(name, "").strip()
        origin = "file" if name in _from_file else ("system" if val else "none")
        keys = get_list(name)
        entry = {"name": name, **meta, "set": bool(val), "origin": origin,
                 "hint": mask(keys[0]) if (meta["secret"] and keys) else (val[:2] + "•••" if val else ""),
                 "editable": origin != "system", "multi": name in MULTI_KEY_FIELDS}
        if name in MULTI_KEY_FIELDS:
            entry["keys"] = [{"id": key_id(k), "hint": mask(k), "position": i + 1} for i, k in enumerate(keys)]
            entry["max_keys"] = MAX_KEYS
        out.append(entry)
    return out


class SettingsError(ValueError):
    pass


def validate_value(name: str, value: str) -> str:
    if name not in KEY_FIELDS:
        raise SettingsError(f"unknown setting {name}")
    value = (value or "").strip()
    if not value:
        return ""
    if name in MULTI_KEY_FIELDS:
        items = split_keys(value)
        if len(items) > MAX_KEYS:
            raise SettingsError(f"{name}: at most {MAX_KEYS} keys")
        if not all(_ITEM_RE.match(k) for k in items):
            raise SettingsError(f"{name}: use each key exactly as issued (no spaces, commas or line breaks, max 512 characters)")
        return ",".join(items)
    if name == "MONGODB_URI":
        if not value.startswith(("mongodb://", "mongodb+srv://")):
            raise SettingsError("MONGODB_URI must start with mongodb:// or mongodb+srv://")
        if not re.match(r"^[!-~]{10,2048}$", value):
            raise SettingsError("MONGODB_URI must not contain spaces or line breaks (percent-encode special characters in the password)")
        return value
    if name == "MONGODB_DB":
        if not re.match(r"^[A-Za-z0-9_\-]{1,63}$", value):
            raise SettingsError("The database name may only contain letters, digits, _ and - (max 63 characters)")
        return value
    if not _VALUE_RE.match(value):
        raise SettingsError(f"{name}: use the key exactly as issued (no spaces or line breaks, max 512 characters)")
    return value


def _editable_list(name: str) -> List[str]:
    if name not in MULTI_KEY_FIELDS:
        raise SettingsError(f"{name} does not hold a key list")
    if os.environ.get(name) and name not in _from_file and get_list(name):
        raise SettingsError(f"{name} is set in the system environment; change it there")
    return get_list(name)


def add_key(name: str, value: str) -> str:
    """Appends one key to a variable's rotation list. Returns its id."""
    value = (value or "").strip()
    if not _ITEM_RE.match(value):
        raise SettingsError("Paste one key exactly as issued (no spaces, commas or line breaks)")
    keys = _editable_list(name)
    if value in keys:
        raise SettingsError("This key is already saved")
    if len(keys) >= MAX_KEYS:
        raise SettingsError(f"At most {MAX_KEYS} keys per source")
    save_keys({name: ",".join(keys + [value])})
    return key_id(value)


def remove_key(name: str, kid: str) -> None:
    keys = _editable_list(name)
    remaining = [k for k in keys if key_id(k) != kid]
    if len(remaining) == len(keys):
        raise SettingsError("Key not found (it may already have been removed)")
    save_keys({name: ",".join(remaining)})


def make_primary(name: str, kid: str) -> None:
    """Moves a key to the front of the rotation list (it is tried first)."""
    keys = _editable_list(name)
    first = [k for k in keys if key_id(k) == kid]
    if not first:
        raise SettingsError("Key not found")
    save_keys({name: ",".join(first + [k for k in keys if key_id(k) != kid])})


def save_keys(values: Dict[str, str], path: Optional[str] = None) -> List[str]:
    """
    Writes whitelisted keys to .env, keeping every other line and comment. An empty value
    removes the key. Variables set in the real system environment are left alone.
    Returns the names that changed.
    """
    path = path or ENV_FILE
    clean = {name: validate_value(name, v) for name, v in values.items()}
    for name in clean:
        if os.environ.get(name) and name not in _from_file:
            raise SettingsError(f"{name} is set in the system environment; change it there")

    lines: List[str] = []
    if os.path.isfile(path):
        with open(path, encoding="utf-8-sig") as f:
            lines = f.read().splitlines()

    changed: List[str] = []
    seen = set()
    out: List[str] = []
    for line in lines:
        m = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        name = m.group(1) if m else None
        if name in clean:
            seen.add(name)
            new = clean[name]
            old = line.split("=", 1)[1].strip().strip('"').strip("'")
            if new != old:
                changed.append(name)
            out.append(f"{name}={new}")  # empty value keeps the placeholder line but disables the key
            continue
        out.append(line)
    for name, new in clean.items():
        if name not in seen and new:
            out.append(f"{name}={new}")
            changed.append(name)

    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".env.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(out).rstrip("\n") + "\n")
        os.replace(tmp, path)  # atomic: a crash never leaves a half-written .env
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    if path == ENV_FILE:
        load_env()
    return changed


def sources_status() -> List[Dict]:
    """Safe-to-display status (never the key values)."""
    out = []
    for key, meta in SOURCES.items():
        key_count = len(get_list(meta["env"][0]))
        has_key = key_count > 0
        off_by_free_mode = bool(meta.get("paid")) and free_only()
        out.append({
            "id": key, "name": meta["name"], "does": meta["does"], "env": meta["env"][0], "key_count": key_count,
            "has_key": has_key, "enabled": (has_key or not meta["key_required"]) and not off_by_free_mode,
            "mode": "free_mode_off" if off_by_free_mode else ("key" if has_key else ("anonymous" if not meta["key_required"] else "off")),
            "paid": bool(meta.get("paid")),
        })
    return out
