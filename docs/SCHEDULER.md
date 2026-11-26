# Scan Scheduler, MongoDB storage and Data Management

Technical reference for the batch scan scheduler, the MongoDB-only storage layer and the data-management
workflow. User-facing overview: README → *Storage*, *Scan Scheduler*, *Security*.

## 1. Components

| Layer | File | Responsibility |
|---|---|---|
| Engine | `api/services/batch_scheduler.py` | Background loop (every 15 s): recovery, due-batch claiming, launching executions, per-domain jobs, retries, notifications, graceful shutdown |
| Data layer | `core/scheduler_store.py` | Every MongoDB read/write of the scheduler and Data Management: batches, domains, memberships, executions, jobs, findings lifecycle, observations, locks, settings, audit, scoped deletes |
| Schedules | `core/schedule.py` | Validation and next-run computation (daily / weekly / every N hours / manual, IANA time zones, DST) |
| Bulk input | `core/domain_input.py` | TXT / CSV / XLSX / pasted text → normalised entries with per-line status (never dropped silently) |
| API | `api/routes/scheduler.py`, `api/routes/datamgmt.py` | `/api/scheduler/*`, `/api/data/*` |
| UI | `web/static/js/scheduler.js`, `web/static/js/datamgmt.js`, `web/static/css/scheduler.css` | Scan Scheduler and Data Management pages (render server data only) |
| Storage | `core/store.py`, `core/mongostore.py` | MongoDB connection selection and the case store (hunts, candidates, triage, watchlist, alerts) |
| History / reset | `core/investigations.py`, `core/reset.py` | Infrastructure investigation history; verified backup + full data reset |

The scan itself is the existing hunt engine (`core.hunter.run_hunt`), called once per monitored domain with
that domain's keywords and allowlist. Each domain scan is saved as a normal hunt (`hunts` / `candidates`, id =
the scan job id, flagged `scheduled_batch: true`) so the full evidence view (*Full report*) works unchanged.

## 2. Execution flow

```
tick()                                   (background thread, every 15 s, in every app instance)
 ├─ recover()        running executions whose heartbeat is older than lease_seconds (120 s) → back to queued;
 │                   their running jobs → queued (or failed after max_attempts interruptions); locks released
 ├─ schedule_due()   find_one_and_update leases a due batch (status active, next_run_at ≤ now, lease expired)
 │                   → create_execution(slot) or apply the missed-run policy → advance next_run_at → release lease
 └─ launch_queued()  find_one_and_update claims a queued execution (owner = this instance) → worker thread

run_execution()      claims queued jobs (find_one_and_update, attempts+1) up to `concurrency`, heart-beats the
                     execution and the leases of its running jobs, watches cancel flags, finishes the execution
                     (completed / partially_completed / failed / cancelled), sends notifications
run_job()            acquire domain lease "domain:<id>" (no overlapping scans of one domain, even from two
                     batches) → run_hunt(domain, keywords) with a timeout watchdog → save hunt →
                     apply_scan_results() (findings lifecycle + observations) → release lease;
                     on error: retry with back-off retry_base·2^(attempt-1) (×3 after rate limits, cap 1 h, ±10 % jitter)
```

**Overlap and idempotency guards**

| Guard | Mechanism |
|---|---|
| One run per batch | `scan_batches.active_execution_id` is claimed atomically (`{active_execution_id: null}` filter) before an execution is inserted; a stale claim (finished / missing execution) is cleared automatically |
| One execution per schedule slot | `batch_executions.slot_key = "<batch>:<slot ts>"`, unique sparse index |
| Two instances, one due batch | the batch lease (`lease_owner`, `lease_until`) is taken with `find_one_and_update` |
| One scan per domain | `scheduler_locks` lease `domain:<domain_id>` (upsert with `{until < now OR owner = me}`; a held lease raises DuplicateKeyError) |
| Stopped instance | heartbeat expiry → `recover()` in any instance |
| Graceful shutdown | stop claiming; running scans are interrupted and their jobs/execution re-queued without counting an attempt |

**Missed runs.** A slot older than the grace window (¼ of the period, clamped to 15 min…6 h) follows the batch
policy: `run_once` (one catch-up run, not one per missed slot) or `skip` (audited as `schedule.missed_skipped`).

## 3. Collections and indexes

| Collection | Key fields | Indexes |
|---|---|---|
| `organizations` | `_id org_*`, `name`, `name_key` | `name_key` unique |
| `monitored_domains` | `_id md_*`, `domain`, `organization_id`, `keywords[]` (≤30), `allowlist[]` (≤100), `depth`, `status`, `stats{}` (per-domain counters), `last_scan_at`, `last_status` | `domain` unique; `organization_id` |
| `scan_batches` | `_id bt_*`, `name`, `schedule{}`, `status`, `next_run_at`, `missed_policy`, `notify{}` (webhook stored, never returned), `active_execution_id`, lease | `name_key` unique; `(status, next_run_at)` |
| `batch_domain_memberships` | `_id "<batch>:<domain>"`, `batch_id`, `domain_id` | `(batch_id, domain_id)` unique; `domain_id` |
| `batch_executions` | `_id ex_*`, `batch_id`, `trigger`, `status`, totals, `current[]` (≤10), `cancel_requested`, `owner`, `heartbeat`, `slot_key` | `(batch_id, created)`; `(status, heartbeat)`; `slot_key` unique sparse |
| `scan_jobs` | `_id jb_*`, `execution_id`, `batch_id`, `domain_id`, `keywords_used`, `status`, `attempts`, `next_attempt_at`, `hunt_id`, `counts{}` | `(execution_id, status, next_attempt_at)`; `(domain_id, created)`; `batch_id` |
| `impersonation_findings` | `_id "<domain_id>:<host>"`, `domain_id`, `host`, `classification`, `lifecycle`, `score`, evidence summary, `first_seen`, `last_seen`, `missed_scans`, `first_/last_ job / execution / batch ids`, `under_review`, `dismissed` | `(domain_id, host)` unique; `(domain_id, score, host)`; `(domain_id, classification, score, host)`; `(domain_id, lifecycle, score, host)`; `(domain_id, last_seen)`; `host` |
| `scan_observations` | `_id "<job>:<host>"`, `finding_id`, `domain_id`, `job_id`, `execution_id`, `batch_id`, `change`, `score`, `observed_at`, `observed_dt` | `(domain_id, observed_at)`; `(finding_id, observed_at)`; `job_id`; TTL on `observed_dt` |
| `scheduler_locks` | `_id`, `owner`, `until` | — |
| `application_settings` | `_id "scheduler"`: `enabled`, `concurrency`, `max_parallel_executions`, `job_timeout`, `max_attempts`, `retry_base_seconds`, `lease_seconds` | — |
| `audit_logs` | `_id au_*`, `at`, `actor` (client address), `action`, `target_type`, `target_id`, `details` | `at`; `(target_type, target_id)` |
| `infra_investigations` | `_id` (12 hex job id), `seed`, `params`, `summary{}`, `result{}` (graph, domains, dossier), `size_bytes`, `trimmed` | `created`; `(seed, created)` |

No document holds an unbounded array: batch membership is its own collection, keyword / allowlist / current-domain
arrays are capped, and per-scan history lives in `scan_observations`.

## 4. Domain isolation

* A finding's `_id` starts with its monitored-domain id; `(domain_id, host)` is unique. The same hostname found
  for `paypal.com` and `microsoft.com` is two findings with their own lifecycle, score and history.
* Every read and delete filters on a validated `domain_id` server-side (`check_id` accepts only `md_` + 12 hex);
  finding ids passed to a domain endpoint must start with that domain's id (cross-domain ids are ignored).
* A job records the keywords it used; the hunt is called with that domain's keywords only.

## 5. Findings lifecycle

| Lifecycle | Rule |
|---|---|
| New | first time this host is found for this monitored domain |
| Previously Discovered (`seen`) | found again, evidence fingerprint unchanged (classification, verdict, score, DNS status, A records, HTTP status, final URL, title) |
| Updated | found again, fingerprint changed |
| Reappeared | found again after being missed or unreachable |
| Currently Unreachable | missing from the scan **and** its own DNS answers NXDOMAIN; a DNS timeout or a source outage leaves the state unchanged (`missed_scans` + 1) |
| Under review | analyst flag (`under_review`), independent of the lifecycle and kept across scans |

Benign / unrelated candidates are only stored when the host is already a finding (so a downgrade stays visible).

## 6. Deletion workflow (Data Management)

Every destructive operation is a function that takes an optional MongoDB session (`run_atomic` in `core/scheduler_store.py`):

* **Replica set / Atlas** (`supports_transactions`): the whole operation runs in one multi-document transaction through
  `session.with_transaction`: all of it or nothing, no half-deleted state is ever visible.
* **Standalone server**: the same function runs with no session as a recoverable workflow. The target is first marked
  `deleting` (hidden from the UI and the scheduler), each step is a scoped, idempotent `delete_many`, and the target's
  own document is removed last. If the process stops half-way, the engine's tick (`finish_interrupted_deletes`) repeats
  the delete for anything still marked `deleting` for more than 60 s.

Common to both:

1. `GET /api/data/impact` shows exactly what will be removed (counts, batches, running scans, shared data note).
2. The request must come from this machine, same-origin, and carry the exact domain / batch name (`confirm`).
3. A running scan blocks the delete (or is asked to stop with `cancel_active`).
4. Saved hunts are removed only when the scheduler created them (`scheduled_batch: true`); manual Brand Hunt history and
   infrastructure data are never touched by a domain or batch delete.
5. An `audit_logs` entry records who (client address), what and the counts removed.

**Reset all data** (`core/reset.py`): backup of every application collection (gzip JSON lines, each file read back and
counted before anything is deleted), then one wipe (transaction when supported), then an audit entry; refuses while a
batch is running. Verified on a standalone server, a replica set and mongomock; a failing backup deletes nothing.

## 7. Measurements: indexes (QA database, 1,761 findings, 4,061 observations)

Default findings sort `(score desc, host asc)` inside one domain, before and after the sort-matching indexes:

| Query | Before | After |
|---|---|---|
| All findings, page 1 | `SORT ← FETCH ← IXSCAN(domain_id_1_host_1)`, 1,030 keys / 1,030 docs examined | `LIMIT ← FETCH ← IXSCAN(domain_id_1_score_-1_host_1)`, 50 / 50 |
| Potential tab | `SORT ← … IXSCAN(domain_id_1_classification_1_score_-1)`, 959 / 959 | `LIMIT ← … IXSCAN(domain_id_1_classification_1_score_-1_host_1)`, 50 / 50 |
| New tab | `SORT ← … IXSCAN(domain_id_1_lifecycle_1)`, 27 / 27 | `LIMIT ← … IXSCAN(domain_id_1_lifecycle_1_score_-1_host_1)`, 27 / 27 |

API latency, median of 25 sequential requests on the same machine (the in-memory sort grows with the number of
findings of a domain; the index keeps a page at 50 documents examined):

| Endpoint | Before | After |
|---|---|---|
| findings, page 1 | 19.9 ms | 13.8 ms |
| findings, page 15 | 21.2 ms | 13.0 ms |
| overview / batches / batch detail / domain dashboard / data summary | 9.6 / 11.4 / 17.7 / 19.1 / 14.8 ms | 11.3 / 10.5 / 23.3 / 21.5 / 17.7 ms (unchanged code; differences are run-to-run noise at this size) |

## 8. Scale test (`tools/load_test.py`, real MongoDB 8.2.1 standalone, throwaway database)

300 monitored domains, ~300 findings per scan, 6 runs ("days") with churn (disappearing / new / re-scored lookalikes),
concurrency 4. The scan engine is a deterministic generator, so this measures the scheduler and the database layer.

| | Before | After |
|---|---|---|
| Findings stored | 116,982 | 116,982 |
| Observations after 6 runs | 540,000 (241 MB) | 284,784 (133 MB): only changes are recorded |
| Overview page | 393 ms | 18.7 ms |
| Batch list | 385 ms | 16.5 ms |
| Batch detail (300 domains) | 638 ms | 51.9 ms |
| Data summary | 331 ms | 42.7 ms |
| Domain dashboard / findings page / search | 16 / 13 / 14 ms | 16.5 / 19 / 20 ms (page reads are index-backed; unchanged within noise) |
| Throughput | 18–25 domains/s | 18–23 domains/s (unchanged: bound by writing 300 findings per domain) |

What changed: per-domain counters stored on the monitored domain and refreshed after every scan or analyst change
(pages sum ~300 small documents instead of aggregating ~117k findings), observations written only when a finding is new,
updated, reappeared or unreachable (a repeat sighting only moves `last_seen`), and a TTL index
(`observation_retention_days`, default 365) so history cannot grow forever.

Soak: 30 consecutive runs of 300 domains x ~120 findings: every run completed 300/300, 46,800 findings (stable after run 8),
485,518 observations (228 MB, ~15,000 per run = the changed findings), run time 10.7–28.5 s (typically 12 s), all pages
stayed under 60 ms at the end. The retention TTL caps observations at the changes of the last year.

Tests prove the stored counters equal a live aggregate after a scan, a re-scan, dismissals, deletes, history clearing and
for data that predates the counters.

## 9. Verified behaviour (live QA, separate `brand_hunter_qa` database)

* Batch created in the UI from pasted text with invalid lines, a duplicate (keywords merged) and an IP; invalid lines
  corrected and re-validated server-side.
* Real run of 3 public domains (quick depth): 3/3 completed in ~4 min with concurrency 2; each hunt received only its
  own keywords; 2,274 findings stored; live progress ("Scanning 2 of 3") and per-domain stages shown.
* Second scan of one domain: 15 new, 51 updated, the rest previously discovered; hosts missing from the scan kept
  their state; the *Under review* flag survived.
* Hard kill of the server mid-run, restart: the new instance took over the stale run after ~105 s, re-queued both
  interrupted scans (attempt 2), completed them, released all domain locks and cleared the batch's active run.
* Data Management: delete refused while the domain was scanning; wrong confirmation keeps the button disabled; a
  domain delete removed only that domain's 601 findings, observations, job and saved report; audit entry written.

## 10. Known limitations

* The engine runs inside the web-server process: schedules run while at least one app instance is running
  (missed slots then follow the missed-run policy).
* Without a replica set there are no multi-document transactions; deletes use the recoverable workflow above (a replica set gives real transactions with no code change).
* A hard-killed instance's running scans are resumed after the 120 s lease expires (graceful shutdown resumes at once).
* The SSRF guard resolves the name before connecting; a DNS-rebinding host with a ~0 s TTL could still race it.
* A domain shared by several batches has one configuration (keywords / allowlist): editing it in one batch applies to all.
* A scan's duration and source coverage depend on the free sources' availability (crt.sh, DuckDuckGo, URLScan anonymous limits).
* Throughput is bound by the hunt engine's network calls in production; the 300-domain database layer itself sustained ~20 domains/s.
