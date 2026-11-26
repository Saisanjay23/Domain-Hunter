# Brand Impersonation Hunter

Give it a brand's domain; it returns the lookalike and phishing domains targeting that brand, ranked by an explainable risk score, with the searches, hashes and takedown material to act on them.

It combines typosquat generation, Certificate Transparency, free phishing feeds, threat-intel platforms (URLScan, Shodan, FOFA, Censys, Google Lens), DNS, live-site inspection against the brand's favicon and logo, and a case workflow (history, triage, takedown packs, monitoring).

## Quick start

```bash
pip install -r requirements.txt
# MongoDB must be running (local default mongodb://127.0.0.1:27017, or set MONGODB_URI)
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

## How candidates are matched, scored and classified

The analyst gives the original domain (`gi-de.com`) and, optionally, keywords (`Giesecke`, `Devrient`, `G+D`, `Giesecke+Devrient`). **Every keyword is expanded and searched independently** (CT, URLScan, Bing/DuckDuckGo/Wayback, VirusTotal) and matched against the *whole hostname*, split with the Public Suffix List into subdomain, second-level label, registered domain and TLD. The keyword that triggered each match, and every other keyword that matched, is recorded.

| Technique | Example (brand `gi-de.com`) |
|---|---|
| Exact / combo | `gi-de-login.net`, `secure-gi-de.org`, `gi-de.xyz` |
| **Subdomain impersonation** (brand under someone else's registered domain) | `gi-de.astrobale-core.tech`, `login.gi-de.attacker.com`, `gi.de.attacker.com` (brand split across labels) |
| Typosquat | transposition `gi-ed`, omission `gieseck`, repetition `gieseecke`, insertion `gieseckex`, keyboard `gieseckw`, substitution `gi-do`, hyphenation `gide` |
| Homograph / IDN | Cyrillic `gі-dе.com`, `xn--` Punycode, mixed-script, `1`→`l` / `0`→`o` digit tricks |
| Multi-word | `gieseckedevrient-security.com`, `giesecke.devrient.evil.net` |

**Precision rules.** Short brand stems are one edit from ordinary words, so `wide.com` / `side.com` are *not* typosquats of `gi-de` (a hyphenated stem must keep its hyphen: `gi-do`, `gi-d`). Edit budget is one edit up to 9 characters (`deviant.com` is not `devrient`). Abbreviations of three characters or fewer (`G+D`, `gd`) are recorded but weak: they never reach "Potential" on the name alone. Dictionary collisions (`guided`, `gideon`, `goods`, `gdpr`) are benign unless page or intel evidence says otherwise. The brand's own domains (allowlist, certificate SANs, redirect-to-brand, brand-organisation TLS certificate) are never candidates.

**Brand + malicious context.** A brand match next to a lure word (`login`, `secure`, `verification`, `banking`, `wallet`, `account`, `authentication`, `payment`, ... anywhere in the hostname, including subdomains: `login.gi-de.evil.net`) gets extra priority (`brand_lure_context`) and is listed under *Malicious Context*. A short stem glued to a lure word (`gidewallet.com`, `gidelogin.evil.net`) counts as a combosquat; glued to any other word (`gidewear`, `gideon`) it does not. The list is configurable with `LURE_KEYWORDS` (`.env.example`).

**Legitimate ownership.** Besides the allowlist, a candidate is *Likely brand-owned* (Benign) when the evidence is verifiable: its DNS is served by the brand's own name servers, its mail goes to the brand's own mail servers, its TLS certificate also covers a brand domain (shared CDN / multi-tenant certificates are ignored), its certificate is issued to the brand's organisation, or it redirects to the brand. WHOIS/RDAP registrant names are *not* trusted for this: anyone can type a company name into a registration form.

**Classification.**

| Class | Meaning |
|---|---|
| **Confirmed Impersonation** | Score ≥ 70 *and* independent, non-name evidence: identical favicon / matching logo, brand in the title, cloned text, brand resources, shared analytics ID, a phishing-feed listing, a favicon/asset hash match, or ≥ 2 VirusTotal vendors. |
| **Potential Impersonation** | A strong keyword name match, or suspicious signals, that nothing has disproved. A domain-name match plus registration age and mail servers **alone is capped at 69 and stays Potential**. |
| **Benign / Unrelated** | Brand-owned, dictionary collisions, weak abbreviations with no other signal, or a live site inspected and found unrelated. |

**Threat score (0-100).** A sum of independent signals, each with its reason and points shown under *Why this score* (`score_breakdown` in the API/JSON/CSV): name match / subdomain position, similarity and technique, mixed-script IDN, registration age, mail servers, CT certificate, page content (favicon, logo pHash, title, text, brand resources, analytics ID, password form), phishing feeds, VirusTotal vendor count, favicon/asset-hash intel. All weights and thresholds are tunable: set `THREAT_SCORE_WEIGHTS` (see `.env.example`); `GET /api/scoring-weights` shows the effective values.

**Optional VirusTotal.** With `VIRUSTOTAL_API_KEY`, besides keyword discovery a hunt checks the reputation of up to 12 of the most suspicious candidates (free tier: 4 requests/minute; it stops cleanly when rate limited). Only vendor *detections* count as evidence; a clean answer adds nothing.

**Bring your own list.** `POST /api/impersonation/evaluate` runs the same matcher, score and classification over a list of hostnames (offline; add `"resolve": true` for DNS):

```bash
curl -s localhost:8080/api/impersonation/evaluate -H 'content-type: application/json' -d '{
  "original_domain": "gi-de.com", "keywords": ["Giesecke","Devrient","G+D"],
  "domains": ["gi-de.astrobale-core.tech", "wide.com", "gi-ed.com"]}'
```

## Infrastructure Investigator

**Sidebar → Infrastructure** (or **Map infrastructure** on any hunt result). Give it one domain, hostname or URL — a phishing site or your own — and it maps the operation behind it, free sources only:

1. **Fingerprint** every domain: DNS, RDAP/WHOIS (registrant only when published), IP owner, ASN (Team Cymru DNS, RIPEstat fallback), TLS certificate and SANs, and one safe page visit (no JavaScript, nothing submitted) for the phishing-kit "DNA": title, favicon hash, analytics IDs, Telegram exfiltration bots and chat IDs, crypto wallets, contact e-mails, the host forms post stolen data to, download lures, HTML skeleton.
2. **Pivot** from each fingerprint: certificate SANs, crt.sh and OTX passive DNS (siblings under the same registered domain), same IP (HackerTarget, URLScan), same favicon / exact title (URLScan), uncommon shared name servers (HackerTarget). Each root / IP / name server / favicon / title is searched once; a source that rate-limits is skipped for the rest of the run.
3. **Link by evidence strength.** Strong: shared certificate, same attacker-owned registered domain, same Telegram bot / chat ID / wallet / data-collection host, identical kit. Medium: small dedicated IP, uncommon name server, same favicon / title / analytics ID (cloned pages carry the brand's own ID). Weak: mass-hosting IPs, provider name servers, registrar, ASN. A domain's confidence is the weakest hop on its strongest chain back to the seed, so an unlucky shared-hosting neighbour is never reported as "the actor".
4. **Dossier.** What they are doing (credential harvesting, card fraud, crypto drainer, malware, support / investment / job scams — content-based; login or checkout pages only count on domains under a year old or with kit artefacts), who / what they target, who is behind it (public data only), infrastructure habits, tradecraft with MITRE ATT&CK techniques, timeline, and **what they will likely do next**: the next domains their naming pattern predicts, checked live in DNS (registered ones are listed first).

A **legitimate** seed gets an organisation-footprint view instead (estate, no malicious behaviour seen) plus **Sites impersonating this domain**: other registered domains serving its exact title, favicon or layout. Exports: graph PNG, IOC CSV, full JSON (`GET /api/investigate/{id}/iocs.csv` too). API: `POST /api/investigate {target, depth 1-3, max_domains, keywords}`, then poll `GET /api/investigate/{id}`.

**Limits, honestly.** "Who is behind it" stops at public data: most registrations are privacy-protected, and naming a person needs registrar / law-enforcement process. Telegram bot secrets found in kits are masked; report bots to Telegram rather than using them. Free sources rate-limit (HackerTarget allows about 50 lookups a day, OTX throttles anonymous use), so a run reports which sources it had to skip. A typical 15-domain investigation takes 1-3 minutes.

## Interface

A dark ("Obsidian") and light ("Porcelain") theme share one design system (`web/static/css/tokens.css`): indigo-to-cyan brand gradients, glass surfaces, severity colours that stay legible in both themes, and motion that respects `prefers-reduced-motion`. The theme switch is in the top bar (Light / Dark / System, where System follows your OS live; dark is the default).

- **Overview** is the home page: an exposure index (0-100, derived from your saved hunts, with the formula shown), KPI tiles with sparklines and deltas, an exposure trend, threat mix, a per-brand table, live source coverage and an activity timeline. With no history it shows a first-run guide, and **Preview with sample data** shows the dashboard populated (clearly labelled, never stored).
- **Command palette**: `Ctrl K` (`⌘ K` on Mac) or `/` from anywhere. Jump to any page, switch theme, or type a domain to hunt it, run the daily radar on it, or investigate it.
- **Notification centre** (bell): watchlist alerts, source issues and running jobs in one place; toasts are typed and dismissible.
- Responsive down to phone width, with a slide-in navigation drawer.
- Static assets are always revalidated, so a UI update is never hidden behind a stale cached file.

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
| Scan Scheduler | Batches of monitored domains (each with its own keywords), scanned automatically on a schedule, with per-domain dashboards. See below. |
| Data Management | Per-domain / per-batch volumes, scoped deletions with typed confirmation, and the audit log. |
| Infrastructure | One domain in, linked infrastructure out. Every investigation is saved: reopen, export or delete it, and see what changed since the last one for the same seed. |
| API keys, Storage | Configure sources; MongoDB connection and transaction support. |

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
| VirusTotal | `VIRUSTOTAL_API_KEY` | Skipped (free key is enough; see "Optional VirusTotal") |
| Bing RSS, DuckDuckGo, Wayback | none | Always on (DuckDuckGo's anti-bot challenge is detected and skipped, never bypassed) |
| Google Safe Browsing | `GOOGLE_SAFE_BROWSING_KEY` | Skipped. One batched check of every candidate; a listing scores +45 and counts as corroboration. Google limits the Lookup API to non-commercial use (commercial: Google Web Risk). |
| AlienVault OTX passive DNS | `OTX_API_KEY` (optional) | Works anonymously. For the most suspicious registered domains, finds sibling brand hostnames CT never saw. |

**Free mode (default).** Only free sources are used: paid platforms (Shodan, FOFA, Censys, SerpApi / Google Lens, WhoisXML) are never called, even when a key is saved, and every URLScan query is rewritten to the form its free plan accepts (no leading wildcards or `.keyword` substring fields). Free-tier keys (URLScan, VirusTotal, Google Safe Browsing, OTX) are still used when present. `FREE_ONLY_MODE=0` in `.env` turns paid platforms back on.

**Source activity.** Skipped searches, quota limits, anti-bot challenges and outages are never shown on the results screens. They are logged on **API keys → Source activity** (per source: what happened, where, when, how often, and what to do) and via `GET /api/sources/events`.

**Source availability.** *API keys → Check availability* (or `GET /api/sources/health`) probes every free source once (about `example.com`, cached 5 minutes) and reports up / challenged / rate-limited / degraded / down. Keyed sources are not called there (that would spend quota); their own *Test* button checks the key.
| crt.sh, DNS, RDAP, feeds | none | Always on |

**Several keys per source.** Keys are comma-separated (`SHODAN_API_KEY=key1,key2`) and tried in order. A key that hits a rate limit pauses for the platform's `Retry-After` time (default 60 s), one out of credits for 12 h, one whose plan doesn't allow the query for 30 min, and an invalid key until replaced; the next key takes over automatically. The page shows each key's state, countdown and call count, with Test all, Make primary, Remove and Reset paused keys. The **Test** button uses free account endpoints (Censys has none, so it runs one 1-result search).

crt.sh is often overloaded; when it fails the hunt continues and says so. Each failed or skipped source is listed in the results.

### Storage: MongoDB

MongoDB is the only database. With no configuration the app uses the local server `mongodb://127.0.0.1:27017` and the database `brand_hunter`. To use another server open **Settings → Storage**, paste a connection string and click *Save* (or set `MONGODB_URI` and optionally `MONGODB_DB` in `.env`). The connection is tested first and a broken string is never saved.

- **Strings:** `mongodb://127.0.0.1:27017`, replica sets, and Atlas (`mongodb+srv://user:password@cluster0.xxxxx.mongodb.net/`). Percent-encode special characters in the password. The database defaults to the one in the URI, otherwise `brand_hunter`.
- **Credentials** stay in `.env`; the UI shows hosts and database only, and every error message is redacted.
- **Collections:** `hunts`, `candidates`, `triage`, `watchlist`, `alerts`, `counters` (hunts and cases), `infra_investigations` (Infrastructure history) and `organizations`, `monitored_domains`, `scan_batches`, `batch_domain_memberships`, `batch_executions`, `scan_jobs`, `impersonation_findings`, `scan_observations`, `scheduler_locks`, `application_settings`, `audit_logs` (Scan Scheduler). Schema, indexes and query plans: [docs/SCHEDULER.md](docs/SCHEDULER.md).
- **Transactions:** on a replica set (or Atlas) every multi-collection delete and the full reset run as one all-or-nothing transaction. On a standalone server (Storage page shows which you have) the same deletes use a recoverable workflow: the target is hidden first, every step is scoped and idempotent, and the scheduler finishes an interrupted delete automatically within a minute.
- **SQLite is gone:** older versions kept history in `data/hunter.db`. That backend, its importer and `--migrate-history` were removed; MongoDB is the only database.
- **Several app instances** can share one MongoDB: due watchlist hunts and scheduled batch runs are claimed atomically, so exactly one instance runs each.
- **If MongoDB is unreachable,** hunts still complete (with a note that they weren't saved), the API answers 503 "not reachable", and the scheduler retries on its next tick. The app never falls back to another database.

### Scan Scheduler

Batches of monitored domains that the **server** scans automatically (no browser needs to be open):

- **Batches:** name, description, organization, schedule (daily at a time, weekly on chosen days, every N hours, or manual only) in any IANA time zone, scan depth, missed-run policy (*run once when back* or *skip*), notifications (in-app, webhook; on new findings and/or failures). Create, edit, pause/resume, enable/disable, duplicate (copies start paused), run now, cancel, retry failed domains, execution history.
- **Domains:** paste or upload TXT / CSV / Excel (max 2 MB). URLs become hostnames, `www.` and IDNs are normalised, duplicates are merged (their keywords too), and invalid lines are shown with the reason so you can correct or remove them. Nothing is dropped silently. Each domain keeps its own keywords and allowlist.
- **Isolation:** each domain is scanned on its own with only its keywords. Every finding belongs to exactly one monitored domain (`impersonation_findings` is unique on domain + host), so the same hostname found for two brands is two separate findings. All filtering, paging and exports happen server-side.
- **Dismiss as false positive:** hidden from the review views, counts and alerts, kept across rescans, and brought back only if the host is later *Confirmed*. Restore it from the *Dismissed* tab.
- **Lifecycle** (separate from the Confirmed / Potential / Inactive / Benign classification): *New*, *Previously Discovered*, *Updated* (evidence changed), *Reappeared*, *Currently Unreachable* (only when its own DNS says NXDOMAIN: a source outage never marks a host gone), plus an analyst *Under review* flag. First seen is kept, last seen is updated, and every scan records an observation per finding.
- **Engine:** leases in MongoDB (restart-safe, multi-instance safe, one run per batch and one scan per domain at a time), configurable parallelism, per-domain timeout, retries with exponential back-off (longer after rate limits), graceful shutdown that resumes on the next start. Settings: *Scan Scheduler → Engine settings* (`SCHEDULER_CONCURRENCY`, `SCHEDULER_JOB_TIMEOUT` set defaults; `BRAND_HUNTER_SCHEDULER=0` turns background scheduling off).
- **Scale:** per-domain counters keep the overview / batch / data pages independent of the number of findings; observations are recorded only when something changed and expire after `observation_retention_days` (default 365, a MongoDB TTL index). `GET /api/scheduler/health` returns 200 while the engine is ticking and 503 when it is off or stalled (for monitoring). `python tools/load_test.py` reproduces the measurements in [docs/SCHEDULER.md](docs/SCHEDULER.md).
- **Export:** CSV / JSON of one domain or of a whole batch.

### Classification

Every candidate is *Confirmed* (high score **and** independent corroboration), *Potential* (needs review), *Inactive / Historical* or *Benign*. Two rules keep the review queue short without hiding live threats:

- **Inactive / Historical:** listed by a feed or reputation source, but the domain no longer exists (NXDOMAIN) and was never seen live (no inspected page, no URLScan sighting, nothing reported in the last 30 days). It returns to Potential / Confirmed on its own if it comes back. A never-seen lookalike with no DNS stays Potential: it may be activated later.
- **Benign (page only mentions the brand):** a live third-party page found by a title / text search whose title does not present itself *as* the brand and that has no password form, brand assets, lure wording or reputation listing ("Probiotic sold on Amazon", "Amazon Landing Page Generator"). A page titled "Amazon: Earth's Biggest Selection" or "Sign in | PayPal" stays Potential.

Measured on a real `amazon.com` quick hunt (736 candidates): Potential 492 → 189 (−62 %), Inactive 272, Confirmed 32 → 32.

### Reset all data

*Data Management → Reset all data* backs up every application collection (gzip JSON lines, each file read back and counted) to `data/backups/reset-<time>/`, then deletes hunts, cases, watchlist, alerts, scan batches, findings and saved investigations (one transaction when the server supports it). API keys, storage and scheduler settings are kept, the reset is audited, and nothing outside this application's collections is touched. Restore with `python -m core.reset restore <folder>`.

### Security

- Settings, storage and every destructive Data Management call answer only requests from this machine, and all write endpoints reject cross-site requests.
- Deletions need the exact domain or batch name typed back, are scoped by validated ids, refuse while a scan of the target runs, and are written to `audit_logs`.
- Page inspection never connects to loopback, private, link-local or cloud-metadata addresses, including through redirects (`BRAND_HUNTER_ALLOW_PRIVATE_FETCH=1` allows it for intentional internal scans).
- Write endpoints are rate limited per client (`BRAND_HUNTER_RATE_LIMIT`, default 120/min, stricter for deletions), bodies are capped (`BRAND_HUNTER_MAX_BODY_MB`, default 25), responses carry `nosniff` / `DENY` framing / `no-referrer` headers, and CSV exports neutralise spreadsheet formulas.

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

`POST /api/hunt` returns a `job_id`; poll `GET /api/hunt/{job_id}` for progress and the result, `DELETE` it to cancel. Past hunts: `GET /api/hunts` and `GET /api/hunts/{id}`. Everything else (triage, takedown, IOC export, watchlist, alerts, settings, storage, `/api/scheduler/*`, `/api/data/*`) is documented at `/docs`.

## Layout

```
app.py                  FastAPI app wiring (routes in api/routes, background services in api/services)
api/services/batch_scheduler.py   Scan Scheduler engine (claims, executor, retries, recovery)
api/security.py         rate limiting, body limit, security headers
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
  store.py, mongostore.py, mongouri.py   MongoDB case store (hunts, triage, watchlist, alerts)
  investigations.py     Infrastructure Investigator history (save, list, reopen, diff, delete)
  reset.py              verified backup + full data reset, restore
  scheduler_store.py    Scan Scheduler data layer: batches, domains, executions, jobs, findings lifecycle, scoped deletes
  schedule.py, domain_input.py   schedules / next run (time zones, DST); bulk domain import (TXT / CSV / XLSX)
  netguard.py           SSRF guard for page inspection
  config.py             keys and settings from .env / environment
  domain_matcher.py     hostname matching (subdomain / typosquat / homograph / multi-keyword) and classification
  scoring.py            tunable threat-score weights and thresholds (THREAT_SCORE_WEIGHTS)
  bulk.py               offline bulk evaluation of a hostname list (POST /api/impersonation/evaluate)
  health.py             free-source availability probes (GET /api/sources/health)
  infra.py              Infrastructure Investigator: fingerprint, pivot, evidence-weighted linking, operator dossier, predictions
  dorks.py, daily_intel.py   keyword dorks and the daily threat radar
  crawler.py, hasher.py, matcher.py, query_gen.py, platforms.py, impersonation.py, domains.py, exporter.py
web/static/             dashboard: index.html, css/ (tokens, shell, components, overview, infra, scheduler), js/ (shell = theme, palette, notifications, overview; scheduler, datamgmt)
docs/SCHEDULER.md       scheduler architecture, collections and indexes, isolation, deletion, measurements
tools/                  check.py (all checks in one command), load_test.py (scheduler scale test)
tests/                  pytest suite (offline; includes Playwright browser tests)
```

## Development

```bash
pip install -r requirements-dev.txt
python tools/check.py                      # everything: lint, JavaScript syntax, all tests incl. browser tests
python tools/check.py --quick              # same without the browser (Playwright) tests
python tools/check.py --live               # also run storage / scheduler / reset tests on a real MongoDB
python -m pytest -q tests                  # just the tests (offline; in-memory MongoDB via mongomock)
python -m ruff check .                     # fixed rule set in ruff.toml; never use --fix with a partial --select
python -m playwright install chromium     # once, for tests/test_ui.py (skipped when no browser is installed)
```

A test that hangs is stopped after `BRAND_HUNTER_TEST_TIMEOUT` seconds (default 180) and the stack of the stuck line is written to `.pytest-hang.log`. `tests/test_hygiene.py` fails when an imported package is missing from `requirements.txt`, a class or function is defined twice in one module, or a JavaScript file does not parse.

To also run the storage and scheduler suites against a real MongoDB (throwaway `bih_test_*` databases are created and dropped):

```bash
BRAND_HUNTER_TEST_MONGO_URI=mongodb://127.0.0.1:27017 python -m pytest -q tests/test_mongo.py tests/test_scheduler.py
```
