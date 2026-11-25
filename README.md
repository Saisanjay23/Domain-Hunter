# Brand Impersonation Hunter

Give it a brand's domain; it returns the lookalike and phishing domains targeting that brand, ranked by an explainable risk score, with the searches, hashes and takedown material to act on them.

It combines typosquat generation, Certificate Transparency, free phishing feeds, threat-intel platforms (URLScan, Shodan, FOFA, Censys, Google Lens), DNS, live-site inspection against the brand's favicon and logo, and a case workflow (history, triage, takedown packs, monitoring).

## Quick start

```bash
pip install -r requirements.txt
python favicon_hash.py --ui                          # web UI on http://127.0.0.1:8080
python favicon_hash.py --hunt adani.com -o hunt.json -c hunt.csv      # or from the terminal
```

Every API key is optional. With none, a hunt still uses permutations, CT logs, two phishing feeds, anonymous URLScan, DNS, RDAP and live-site inspection.

## What a hunt does

| Stage | What it does |
|---|---|
| 1. Fingerprint | Brand favicons and logos (MMH3 / SHA-256 / pHash), title, analytics IDs, TLS certificate organisation, rare JS/CSS files, and an allowlist of the brand's own domains (input, redirect host, certificate SANs, `--allow`). |
| 2. Generate | dnstwist-style permutations: omission, repetition, transposition, keyboard replacement / insertion, vowel swap, hyphenation, bitsquatting, ASCII and Unicode (IDN) homoglyphs, combosquatting (`brand-login`) and TLD swaps. `--depth quick / standard / deep` gives about 150 / 600-1,200 / 2,500+ candidates. |
| 3. CT logs | crt.sh hostnames containing the brand. A brand that only appears in a subdomain is tracked as that exact host. |
| 4. Phishing feeds | OpenPhish and Phishing.Database matched against the brand (see below). |
| 5. Threat intel | Automatic searches on every configured platform: pages loading the brand's favicon / logo, servers serving the brand favicon, the brand's analytics ID in other sites' HTML, brand pages on free hosting, lookalike titles and hostnames, and Google Lens on the logo. IP-only hits go to an "Infrastructure" table. |
| 6. DNS | Async A / AAAA / MX / NS lookups with per-TLD wildcard detection. |
| 7. Inspect | Visits each live lookalike once (HTML and up to 4 images; no JavaScript; nothing is submitted): favicon byte match, logo pHash similarity, hot-linked brand resources, shared analytics ID, password form, brand in the title, text similarity, parking pages, redirects to the brand, certificate issued to the brand's organisation. |
| 8. RDAP | Registration date, registrar and abuse contact (no WHOIS scraping). |
| 9. Score | Explainable 0-100 score with reasons. Verdicts: High risk, Suspicious, Parked, Offline (seen by intel, now taken down), Redirects to brand, Brand-owned, No website, Web unreachable, Live and unrelated. |

Beyond the ranked table, a hunt also returns favicon / logo hash queries and impersonation dorks for FOFA, Shodan, Censys and URLScan; pivot queries for analytics IDs and rare brand files; search-engine dorks (impersonation pages, free hosting, fake jobs and helplines, social media, apps, paste and code leaks); and reverse-image links for every brand image.

**Precision notes.** Favicon and logo matches are strong signals. JS/CSS files score weakly and only when rare: files used by hundreds of other sites (CMS plugins, WordPress core) are dropped, because they would turn every such site into a "lookalike".

## Web UI

Start with `python favicon_hash.py --ui` (or `python app.py --port 8080`). The server binds to localhost; icon previews are embedded, so your browser never contacts suspect hosts.

| Section | Purpose |
|---|---|
| Impersonation hunt | The main workflow: run a hunt and review ranked results, evidence, queries and dorks. |
| Asset scan, Batch scan | Discover and hash every favicon, touch icon, manifest icon and logo of a site (or many), with per-icon queries. |
| Logo inspector | Hash images found through reverse image search or on suspect pages, compare with the scanned brand, and build queries. |
| Hash aggregator | Merge MMH3 / MD5 / SHA-256 values (or an existing query) into one OR query per platform. |
| Dork generator | Title, hostname, certificate and page-content dorks for brand names, project names and domains. |
| History, Watchlist | Reopen past hunts, triage domains, monitor brands on a schedule. |
| API keys, Storage | Configure sources and choose SQLite or MongoDB. |

## Configuration

### API keys (Settings → API keys, or `.env`)

Copy `.env.example` to `.env` or use the page; changes apply without a restart. A saved key is never shown again (last 4 characters only), a variable set in the system environment wins and is read-only, and the settings endpoints answer only requests from this machine.

| Source | Variable | Without a key |
|---|---|---|
| URLScan | `URLSCAN_API_KEY` | Works anonymously (rate-limited, 100 results per query) |
| Shodan | `SHODAN_API_KEY` | Skipped (favicon / title / HTML filters need a paid membership) |
| FOFA | `FOFA_KEY` (+ `FOFA_EMAIL` for older accounts) | Skipped |
| Censys Platform | `CENSYS_PAT` (+ `CENSYS_ORG_ID`) | Skipped |
| Google Lens (SerpApi) | `SERPAPI_KEY` | Skipped (manual reverse-image links are still shown) |
| crt.sh, DNS, RDAP, feeds | none | Always on |

**Several keys per source.** Keys are comma-separated (`SHODAN_API_KEY=key1,key2`) and tried in order. A key that hits a rate limit pauses for the platform's `Retry-After` time (default 60 s), one out of credits for 12 h, one whose plan doesn't allow the query for 30 min, and an invalid key until replaced; the next key takes over automatically. The page shows each key's state, countdown and call count, with Test all, Make primary, Remove and Reset paused keys. The **Test** button uses free account endpoints (Censys has none, so it runs one 1-result search).

crt.sh is often overloaded; when it fails the hunt continues and says so. Each failed or skipped source is listed in the results.

### Storage: SQLite or MongoDB

SQLite (`data/hunter.db`, override with `BRAND_HUNTER_DB`) is the default. For MongoDB, open **Settings → Storage**, paste a connection string and click *Save and switch* (or set `MONGODB_URI` and optionally `MONGODB_DB` in `.env`). The connection is tested first and a broken string is never saved; storage switches immediately.

- **Strings:** `mongodb://127.0.0.1:27017`, replica sets, and Atlas (`mongodb+srv://user:password@cluster0.xxxxx.mongodb.net/`). Percent-encode special characters in the password. The database defaults to the one in the URI, otherwise `brand_hunter`.
- **Credentials** stay in `.env`; the UI shows hosts and database only, and every error message is redacted.
- **Layout:** `hunts`, `candidates` (one document per lookalike per hunt, queryable: `db.candidates.find({target: "paypal.com", verdict: "phishing"}).sort({score: -1})`, and never near the 16 MB document limit), `triage`, `watchlist`, `alerts`, `counters`.
- **Copy data:** switching doesn't move old records. Use *Copy local SQLite to MongoDB* (or `python favicon_hash.py --migrate-history`); it is safe to repeat. Webhook URLs are copied too, so protect the database like any credential store.
- **Several app instances** can share one MongoDB: each due watchlist hunt is claimed atomically, so exactly one runs it.
- **If MongoDB is unreachable,** hunts still complete (with a note that they weren't saved) and History / Watchlist / triage report "not reachable". The app never silently falls back to SQLite.

## Phishing feeds

Each hunt matches the brand against the **OpenPhish** public feed (live URLs, refreshed hourly) and **Phishing.Database** (about 390,000 active phishing domains, refreshed daily). They are cached in `data/feeds/`; if a download fails the stale copy is used and the hunt says so. A listed domain scores +45 and stays in the results even after it goes offline. Short brand names match strictly (`adani` matches `adani-login.com`, `secureadani.com`, `adanipower.in`, but not `madani-tours.com`).

## Case management

| Feature | What it does |
|---|---|
| **History** | Every hunt is saved. Results compare with the previous hunt of the same brand: new domains get a **New** badge and filter, and each domain shows when it was first seen. |
| **Triage** | Per brand and domain: Open, Investigating, Confirmed, Takedown sent, Taken down, False positive, plus a note. Statuses carry over to later hunts, and false positives drop out of review, so repeated hunts get quieter. |
| **Takedown pack** | Registrar and hosting-provider abuse contacts (domain RDAP + IP RDAP, Cloudflare's abuse form where relevant), a draft abuse e-mail with defanged indicators, a printable evidence report, and links to Google Safe Browsing, Microsoft SmartScreen, Netcraft and APWG. Nothing is sent: you review and send. |
| **IOC export** | `Blocklist` (plain domains) and `STIX 2.1` (stable IDs). Excludes false positives; includes High risk, Suspicious, Offline and Parked domains at score 45+, plus anything you confirmed. |
| **Watchlist** | Monitor brands every 6 hours to 7 days. The first hunt is a silent baseline; later hunts alert only on new High risk or Suspicious domains at or above your threshold and not marked false positive, in the UI and optionally by webhook (Slack, Teams, Mattermost, Discord or any JSON endpoint). |

The scheduler runs inside the web server (checks every 30 s), so brands are monitored only while it is running; `BRAND_HUNTER_SCHEDULER=0` turns it off. Scheduled hunts spend your API-key quota. Write endpoints reject cross-site requests.

> **Safety:** inspecting lookalikes makes plain HTTP requests from your machine to possibly hostile hosts. Run large hunts from an analysis network or VPN.

## Asset scanning and hashes

- **Discovery:** HTML `<link>` icons (`icon`, `shortcut icon`, `apple-touch-icon`, `mask-icon`, `fluid-icon`), `<base href>`, meta-refresh, inline `data:` favicons, web manifests (linked or probed), root fallbacks on the requested and the post-redirect host, homepage fallbacks (`https` → `https://www.` → `http` → `http://www.`), IDN domains and pasted URLs.
- **Validation:** non-images (soft-404 HTML with status 200, XML/JSON error bodies) are rejected by magic bytes; identical bytes are deduplicated and their other URLs listed (`also_found_at`).
- **Logos and subdomains (optional):** JSON-LD `Organization.logo`, `og:image`, `<img>` with "logo"; subdomain probes (`careers`, `portal`, `vpn`, `login`, ...) using the Public Suffix List, discarding probes that redirect to another organisation.
- **Hashes:** **MMH3** (Shodan / FOFA / ZoomEye favicon hash), **MD5 / SHA-256** (Censys; URLScan's resource `hash:`), **pHash** (perceptual; transparent images are flattened onto white so a PNG and a JPEG copy compare correctly).
- **Accurate queries:** icons are tagged `favicon`, `logo` or `subdomain`. Logos never go into favicon-hash filters (those platforms index favicons only) and are searched on URLScan. Subdomain-portal icons are listed individually but kept out of the master queries, since SaaS-hosted portals share favicons with all their customers.

### Platform query reference

Checked against each platform's documentation (and URLScan's live API); `core/platforms.py` is the single source of truth.

| Platform | Favicon query | Multi-value OR | Notes |
|---|---|---|---|
| **FOFA** | `icon_hash="<mmh3>"` | `(icon_hash="a" \|\| icon_hash="b")` | Login required. `host="x"` is a token match; substring search needs `host*="*x*"` (membership or F-points). |
| **Shodan** | `http.favicon.hash:<mmh3>` | `http.favicon.hash:a,b,c` | Comma-separated values are OR-ed; whitespace is AND; `-hostname:x` excludes. Filters need a login. |
| **Censys Platform** | `host.services.endpoints.http.favicons.hash_md5: "<md5>" or web.endpoints.http.favicons.hash_md5: "<md5>"` / `web.endpoints.http.favicons.hash_sha256: "<sha256>"` | `field: {"a", "b"}` | Legacy `search.censys.io` is retired (links open `platform.censys.io`). Hashes only the first 384 KB of a favicon. No `*` wildcards. |
| **URLScan** | `hash:<sha256>` | `hash:(a OR b)` | Matches any response a scanned page loaded, so it also catches kits that copy the logo. `page.domain:x*` matches any domain level starting with `x`; `page.domain.keyword:*x*` needs sign-in; `text.content` is Pro-only. |

## Command line

```bash
python favicon_hash.py --hunt adani.com -o hunt.json -c hunt.csv         # impersonation hunt
python favicon_hash.py --hunt bbc.co.uk --depth deep --allow bbci.co.uk
python favicon_hash.py -d gi-de.com                                      # asset scan
python favicon_hash.py -d gi-de.com -o gi_de.json -c gi_de.csv --save-icons ./downloaded_icons
python favicon_hash.py -f sample_targets.txt -o batch.json -c batch.csv  # batch scan
python favicon_hash.py -d gi-de.com --launch                             # open master queries on all 4 platforms
python favicon_hash.py --migrate-history                                 # copy SQLite history into MongoDB
```

Hunt options: `--depth quick|standard|deep`, `--no-ct`, `--no-feeds`, `--no-intel`, `--no-verify` (DNS only), `--no-rdap`, `--no-save` (skip history), `--allow other-brand-domain.com,...`, `--keywords ports,green,...` (extra combosquat words). Scan options: `--no-logos`, `--no-subdomains`, `--save-icons DIR`, `--timeout N`, `-q`.

## Library and API

```python
from favicon_hash import scan_domain

result = scan_domain("gi-de.com", timeout=10)
for icon in result["icons"]:
    print(icon["kind"], icon["is_primary"], icon["url"], icon["mmh3"], icon["md5"])
print(result["queries"]["combined"])    # {"fofa": ..., "shodan": ..., "censys": ..., "urlscan": ...}
```

`POST /api/hunt` returns a `job_id`; poll `GET /api/hunt/{job_id}` for progress and the result, `DELETE` it to cancel. Past hunts: `GET /api/hunts` and `GET /api/hunts/{id}`. Everything else (triage, takedown, IOC export, watchlist, alerts, settings, storage) is documented at `/docs`.

## Layout

```
app.py                  FastAPI server and API
favicon_hash.py         CLI entry point and scan_domain() library wrapper
core/
  hunter.py             hunt pipeline (fingerprint, generate, CT, feeds, intel, DNS, inspect, RDAP, score)
  permutations.py       lookalike generator (typo, homoglyph / IDN, combosquat, TLD swap)
  discovery.py          async DNS, crt.sh, RDAP, brand allowlist from certificate SANs
  feeds.py              OpenPhish + Phishing.Database matching
  sources.py, keypool.py   URLScan / Shodan / FOFA / Censys / SerpApi clients; multi-key rotation
  pivots.py             analytics / rare-file pivots, search-engine dorks, automatic intel plan
  verifier.py           live-site inspection and explainable scoring
  takedown.py, alerts.py   abuse contacts, e-mail and evidence report, blocklist / STIX; alert rules and webhooks
  store.py, mongostore.py, mongouri.py, migrate.py   case store (SQLite / MongoDB) and data copy
  config.py             keys and settings from .env / environment
  crawler.py, hasher.py, matcher.py, query_gen.py, platforms.py, impersonation.py, domains.py, exporter.py
web/static/             dashboard (index.html, app.js, style.css)
tests/                  pytest suite (offline)
```

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest -q tests                  # offline, no network needed
python -m ruff check app.py favicon_hash.py core tests
```

To also run the contract tests against a real MongoDB (a throwaway database is created and dropped):

```bash
BRAND_HUNTER_TEST_MONGO_URI=mongodb://127.0.0.1:27017 python -m pytest -q tests/test_mongo.py
```
