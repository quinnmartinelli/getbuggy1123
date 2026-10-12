# GetBuggy on LingCode Cloud, with MongoDB — Design

Date: 2026-10-11 · Status: draft, awaiting founder review

## Goal

Move GetBuggy's live hosting from Render to LingCode Cloud, using MongoDB Atlas
as the only database. Success: the public URL takes a real check end to end
(checkbox → queued → crawled in real Chromium → report shown and saved for 30
days), `post_deploy_check.py` passes against it, and every rule in `CLAUDE.md`
still holds.

## What was asked vs. what is assumed

- **Asked:** use MongoDB; deploy to LingCode Cloud; split web + jobs (option
  "Split"); hand-off via an always-on worker that polls MongoDB (option "C").
- **Already true:** `report_store.py` saves reports to MongoDB (`reports`
  collection, 30-day TTL) when `MONGODB_URI` is set. Atlas cluster
  `cluster0.zvqnag.mongodb.net` accepts the `hhuangweijia_db_user` login
  (verified 2026-10-11 with a read-only ping). Atlas IP access list allows
  `0.0.0.0/0` — **currently set to expire after 1 week; must be made permanent
  before go-live.**
- **Assumed:** LingCode compute jobs run linux/amd64 images (verify on first
  upload); LingCode does not publish fixed egress IPs, so the Atlas allow-list
  stays open and the database password is the only lock.

## Why split

LingCode's always-on Python app tier is 512 MB with a fixed image (no apt, so
no Chromium system libraries). Render needed 2 GB before real crawls stopped
crashing (PROJECT_STATUS.md Known Issues, 2026-09-18). LingCode container jobs
take a custom Docker image and up to 4 GB, so Chromium runs there and the web
server runs without it.

## Architecture

```
visitor ──HTTPS──> web (LingCode hosted app, Python 3.12, 512 MB, no Chromium)
                     │  POST /api/check   → insert crawl_jobs {status: queued}
                     │  GET  /api/check-status/{id} → read crawl_jobs, else reports
                     ▼
               MongoDB Atlas  (db: getbuggy — crawl_jobs, reports, workers)
                     ▲
                     │  claim queued job, write progress + result
worker (LingCode container job, existing Dockerfile image, 4 GB, Chromium)
   scheduled every 30 min, claims for ~35 min, drains, exits
```

### Units

| Unit | Purpose | Depends on |
|------|---------|-----------|
| `crawl_runner.py` (new, extracted from `server._run_crawl_job`) | Runs one crawl via `run_site_check_subprocess.py`: the watchdog, the 6-minute cap, the partial report on cap. Reports progress to a *sink* object (`set_progress`, `add_page`, `set_meta`, `finish(result)`, `fail(detail)`). | subprocess, `core` |
| In-memory sink (in `server.py`) | Today's `_jobs` dict behaviour. Used when `CRAWL_MODE` is unset — local dev, CI, the harness. | — |
| `job_queue.py` (new) | MongoDB `crawl_jobs` + `workers` access: `enqueue`, `active_count`, `claim_next`, `heartbeat`, `update_progress`, `finish`, `fail`, `get`, `mark_stale`. Off when `MONGODB_URI` unset. Never logs a URL or the URI. | pymongo |
| Mongo sink (in `crawl_worker.py`) | Writes runner events to `crawl_jobs` through `job_queue`. | `job_queue` |
| `crawl_worker.py` (new) | Worker loop: startup browser self-test, claim → run (≤ `MAX_CONCURRENT_CHECKS` at once, threads), heartbeat, claim window, drain, exit. | `crawl_runner`, `job_queue`, `report_store` |
| `server.py` (changed) | Same gates as today. `CRAWL_MODE=queue` → enqueue instead of starting a thread; status and health read MongoDB. | `job_queue`, `report_store` |

Default behaviour with `CRAWL_MODE` unset is byte-for-byte today's flow, so
local dev, CI, `regression_check.py`, and the existing Docker image are
unaffected.

### Data model (db `getbuggy`, override with `MONGODB_DB_NAME`)

- `crawl_jobs`: `_id` (job id, the existing random 128-bit id), `url`,
  `page_cap`, `status` (`queued`|`running`|`done`|`error`), `created_at`,
  `claimed_at`, `worker_id`, `heartbeat_at`, `pages_checked`, `pages_total`,
  `meta`, `pages_done`, `result`, `detail`. TTL 1 day on `created_at` — this
  is job state, not the saved report. Index on `(status, created_at)`.
- `reports`: unchanged (30-day TTL).
- `workers`: `_id` (worker id), `started_at`, `last_seen`, `browser_ok`,
  `browser_detail`. TTL 1 day on `last_seen`.
- **Never stored:** the visitor's IP address, user agent, or anything else
  about the visitor. Rate limiting stays in the web process's memory, as
  today.

### Flow of one check

1. `POST /api/check`: authorization checkbox → URL validation (existing SSRF
   validation) → rate limits → **capacity**: under an in-process lock,
   `active_count()` (queued + running, excluding stale) must be below
   `MAX_CONCURRENT_CHECKS` (2). Otherwise the same plain-English "busy"
   message as today → `enqueue` → `record_run` → return `job_id`.
2. The worker polls every 2 s with
   `find_one_and_update({status: queued}, {$set: {status: running, worker_id, claimed_at, heartbeat_at}}, sort created_at)`.
   This claim is atomic: two workers can never take the same job.
3. The runner streams `PROGRESS`/`META`/`PAGE` into `crawl_jobs`. On finish
   it sets `result` + `status: done` and calls `report_store.save_report`
   (unchanged). On cap it builds a partial report exactly as today.
4. `GET /api/check-status/{id}` returns the **same JSON shape as today**
   (the frontend is unchanged), built from `crawl_jobs`, falling back to
   `reports`.

### Keeping a worker alive

LingCode schedule `*/30 * * * *`, overlap policy `allow`, timeout 3600 s.
Each worker claims for `WORKER_CLAIM_WINDOW_SECONDS` (default 2100 = 35 min),
then stops claiming, waits for its in-flight crawls (each ≤ 6 min + kill
margin), and exits. That gives about 5 minutes of overlap between
consecutive workers, so there's never a window with nothing claiming. It
averages roughly 1.3 worker containers running at any time.
The global cap of 2 crawls still holds regardless of the worker count,
because the web server enforces it at enqueue time.

## When things go wrong

Every case below gives a plain-English message. Nothing is ever guessed.

| Situation | Detection | What the visitor sees |
|-----------|-----------|----------------------|
| Worker crashes mid-crawl | `running` job whose `heartbeat_at` (updated every 10 s) is older than 60 s | "This check stopped unexpectedly on our side before it finished. Nothing is wrong with your site — please try again." Not counted toward capacity. No automatic retry. |
| No worker running | `queued` job unclaimed for more than 180 s | "Our checking service didn't pick this up in time. Please try again in a few minutes." Logged as `WORKER_MISSING`, sent to Sentry if `SENTRY_DSN` is set. |
| MongoDB unreachable at submit | `enqueue` raises | 503 + "We can't start a check right now — please try again in a few minutes." No rate-limit budget is spent. |
| MongoDB unreachable on status poll | read raises | "We lost track of this check for a moment — refresh in a few seconds." The job keeps running. |
| MongoDB unreachable from the worker | claim/update raises | The worker logs, backs off 5 s, and keeps running. An in-flight crawl's final write is retried 3 times, then the job ends as stale (above). |
| Browser won't launch in the worker | startup self-test (`health_check_subprocess.py`) fails | The worker records `browser_ok: false`, claims nothing, and exits. `/health` goes red. |

Staleness is computed when the job is read (and the worker also sweeps on
startup), so no separate cleanup job is needed.

## Health, version, and deploy checks

- `/health` in queue mode returns 200 only if a MongoDB ping succeeds **and**
  some worker reported `last_seen` within 90 s with `browser_ok: true`.
  Otherwise it returns 503 with a plain-English reason. A real browser
  launch still happens, in the worker's self-test, so `/health` keeps
  meaning "up and actually able to check." Local mode is unchanged.
- `/version`: the hosted app has no `.git` (this folder isn't a git repo
  either), so `_get_git_commit` falls back to a `VERSION` file written into
  the source tarball at deploy time.
- `post_deploy_check.py --url https://<slug>.apps.lingcode.app` must pass
  `/version`, `/health`, and a real crawl of `https://example.com`.

## Configuration

| Where | Value |
|-------|-------|
| LingCode backend vault (injected into both web and worker) | `MONGODB_URI` |
| Web env | `CRAWL_MODE=queue`, existing `RATE_LIMIT_PER_IP_PER_HOUR`, `DAILY_GLOBAL_RUN_CAP`, `MAX_CONCURRENT_CHECKS`, optional `SENTRY_DSN` |
| Worker env | `CRAWL_CONCURRENCY` (current value per PROJECT_STATUS.md), `WORKER_CLAIM_WINDOW_SECONDS`, `MAX_CONCURRENT_CHECKS`. `ENABLE_REAL_FORM_SUBMISSION` is never set. |
| Not configurable | 30-day report retention (privacy policy), 6-minute crawl cap default, 60-second page timeout default (all unchanged) |

## Deployment

- **Web:** LingCode hosted app (Python buildpack, `uvicorn server:app`). The
  source tarball excludes `venv/`, `__pycache__/`, the test fixtures, and
  `tests/`. 129 files total today, under the 500-file cap.
- **Worker:** the existing `Dockerfile`, with `CMD` overridden to
  `python crawl_worker.py`. Built with `--platform linux/amd64`, saved, and
  uploaded as the job image (≤ 2 GB). The job and its schedule are declared
  in `lingcode.compute.json`.
- **Blocker to resolve before deploy:** LingCode has no agent tool for hosted
  apps or compute jobs. They deploy via the REST API (needs an account
  token) or the LingCode IDE. Either the founder provides a token for the
  deploy session only (never stored in the repo or the app), or runs those
  two uploads from the IDE with steps written out.
- **Render:** left as-is (suspended) until LingCode passes
  `post_deploy_check.py`, then retired.

## Testing

1. **Unit** (CI, no network): `job_queue` against `mongomock` (new dev-only
   dependency): atomic claim, capacity count, stale detection, unclaimed
   timeout. `crawl_runner` with the existing `tests/fake_crawl_worker.py`
   and both sinks. `server` in queue mode: enqueue, the capacity/busy
   message, the status payload shape, `/health` red/green.
2. **Regression harness** (`regression_check.py --skip-live`): unchanged and
   must pass — the default mode is untouched.
3. **Local end to end with real Atlas** (database `getbuggy_dev`, not
   `getbuggy`): web in queue mode + `crawl_worker.py`, crawl the `test_site/`
   fixture, then kill the worker mid-crawl to see the stale message.
4. **Local Docker** (required by CLAUDE.md, since this changes where and how
   the browser launches): the worker image built `linux/amd64`, run with
   `--memory=4g --read-only --tmpfs /tmp`, against `getbuggy_dev`. A real
   crawl of `medvi.org` must finish or return a partial report at the cap.
   Peak RSS gets recorded.
5. **Live:** `post_deploy_check.py` against the LingCode URL, plus one real
   check through the browser UI.

## CLAUDE.md / docs changes (need explicit founder sign-off)

- Replace "Every push to `main` deploys to Render automatically" with the
  LingCode deploy steps. The post-deploy check and deploy log rule stay.
- Note that this working copy is not a git repository. The "small commits"
  and "push to main" rules can't be followed until it is (or until we work
  in the real repo).
- `PLAN.md`: record the decisions (split, option C, Atlas open allow-list).
  `PROJECT_STATUS.md`: architecture, config, deploy log.
- `legal/`: no change needed — no hosting provider or database is named
  there today (checked 2026-10-11). Whether to start naming processors is a
  lawyer question, flagged, not decided here.

## Risks the founders should know

- **Cost:** about 1.3 always-running 4 GB containers plus the web app,
  whether or not anyone is checking a site.
- **Open Atlas allow-list:** anyone can attempt to connect. The password
  (shared in a chat on 2026-10-11) should be rotated after go-live.
- **Crawl start latency:** up to 2 s for the poll, plus nothing else, since
  the worker is already warm. A cold start only happens if the overlap
  fails.
- **Rate limits** remain in memory on a single web instance and reset on
  restart (same as today).

## Out of scope

Moving rate limits to MongoDB, LingCode Postgres, accounts, Stripe, Pro,
scheduled re-checks, or anything else from PLAN.md Phases 2–4.
