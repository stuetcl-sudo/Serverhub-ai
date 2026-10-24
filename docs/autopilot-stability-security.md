# Autopilot stability and security (Issue #11)

Based on merged PR #10 (`42483fb0fe59f76e783ca309aff1ac381dd24d84`).
No production installation, proxy configuration, credentials, Control services,
SSH, firewall or database is changed by this development work.

## Budget admission and resume

`spec.model_route`, when present, must be a nonempty string; invalid types return
HTTP 422, including requests with explicit budgets. The existing defaults remain
20,000 total tokens and 1.0 cost unit. Owner route configuration through
`PUT /api/settings/models/{name}` additionally accepts:

| Field | Default | Meaning |
| --- | ---: | --- |
| `default_job_token_budget` | 20000 | Copied into new jobs when omitted |
| `default_job_cost_budget` | 1 | Copied into new jobs when omitted |
| `ordinary_job_token_limit` | 200000 | Above this, an owner must authorize the budget |
| `ordinary_job_cost_limit` | 10 | Above this, an owner must authorize the budget |
| `max_job_token_budget` | 2000000 | Hard ceiling, including owners |
| `max_job_cost_budget` | 1000 | Hard ceiling, including owners |

Set ordinary limits/defaults no higher than hard ceilings. New job submissions
and `PUT /api/jobs/{id}/budget` enforce the same limits, including MCP
`create_development_job` and `update_job_budget`. An owner may update another
user's scoped job, but this never changes its initiating identity or tool grants.
Route updates do not enlarge existing job budgets. Already admitted jobs keep
their assigned budget; reducing route ceilings constrains new submissions/updates.

Budget pause saves minimum known next-request requirements in checkpoint metadata
without removing previous progress. Resume returns HTTP 409 with remaining and
required budget and `budget_endpoint` when that request cannot fit. Increase the
budget through the existing endpoint, then resume. The owner requirement applies
above ordinary limits, not merely to the job's creator. Paid cost exhaustion is
also blocked; zero-cost Ollama routes remain usable with a zero cost allowance.
Daily quota exhaustion returns an explicit next-UTC-day message; increasing the
job budget cannot bypass it. Context-window and pricing errors still require
correcting model configuration; more job tokens cannot solve them. When a legacy
pause has no request estimate, resume checks at least 32 remaining tokens and
nonexhausted paid cost; normal provider preflight remains authoritative.

Pause/approval/budget stops and graceful worker shutdown do not consume failure
attempts. Actual transient failures and lost leases still do. Existing claim,
resume and interruption audit/events record execution entries separately; token
charges are never refunded merely because an attempt was paused. Historical
attempt counts are not retroactively rewritten.

## Parent and child lifecycle

Queued/retrying/dependency-wait children are paused with their parent; running
children recheck every ancestor before tools and are stopped by the supervisor.
A terminal/cancel-requested ancestor prevents execution. Only automatically
parent-paused children become runnable when the parent is released; explicit
operator pauses and policy/budget stops remain blocked. Dependency-wait state is
preserved, including treating delegated failures as planner observations. Parent
and child checkpoints, stable command IDs and uncertain-write reconciliation
remain intact. An already dispatched remote effect cannot be recalled by a pause;
its result is reconciled, never blindly replayed. Permission expiry remains wall
clock based and every resumed operation still reauthorizes.

## Per-user quotas

Environment settings apply equally to owners and other users:

| Environment setting | Default |
| --- | ---: |
| `SERVERHUB_MAX_USER_JOBS` | 2 running jobs |
| `SERVERHUB_MAX_USER_PENDING_JOBS` | 100 nonterminal jobs |
| `SERVERHUB_USER_DAILY_JOBS` | 500 admissions |
| `SERVERHUB_USER_DAILY_RUNTIME_SECONDS` | 864000 admitted execution seconds |
| `SERVERHUB_USER_DAILY_TOKENS` | 10000000 reserved tokens |
| `SERVERHUB_USER_DAILY_COST` | 1000 reserved cost units |

Daily windows use UTC. PostgreSQL advisory locks serialize admission and token
reservations; workers serialize per-user concurrency with existing global/host
limits. Idempotent resubmission consumes no new admission/runtime quota. Daily
runtime is conservatively reserved from each job's time limit, not refunded on
cancellation; child jobs also reserve it. Request reservations are charged before
sending, including uncertain/failed requests; successful lower provider usage is
refunded to the job ledger but not to the conservative daily admission ledger.
Usage above a reservation is retained. This intentionally favors bounded resource
use over maximally filling a day's allowance. Counters persist in `system_state`.
Existing sandbox CPU/memory/process and timeout limits remain unchanged; this PR
does not add per-user aggregate cgroups. Pending/daily submission limits produce
422 with an actionable reason; exhausted daily model quota pauses the job.

## Proxy login protection

`SERVERHUB_TRUSTED_PROXY_CIDRS` defaults to `[]`. For a reviewed, same-host Caddy or
nginx deployment, explicitly set `["127.0.0.1/32","::1/128"]` if those are its
actual socket peers. Only explicit loopback CIDRs are now accepted. Remote proxy
CIDRs from older configurations require an operator-reviewed local-proxy design;
this is an intentional configuration compatibility restriction. Do not set a
universal trust network. The proxy must replace/append the actual client address.
Uvicorn's automatic forwarded-header rewriting remains disabled. The application
walks X-Forwarded-For from the trusted peer right-to-left; malformed headers fall
back to the peer and cannot create attacker-chosen identities. OAuth/public URL
handling and routes are unchanged.

IP admission slots are charged before password verification, preserving concurrent
brute-force bounds. A successful login refunds only its own slot in the same
counter window; failed/abandoned attempts remain charged. The global admission
limit still includes successes and failures. Distinct forwarded clients have
distinct counters. Users genuinely behind the same NAT still share the IP failure
ceiling; no header heuristic can safely distinguish them. No live Caddy/nginx
configuration is edited automatically.

## Incidents, monitor and watchdog

Container restart anomalies use a delta from a fresh prior observation of the
same container ID; first samples, replacement IDs, counter resets and stale samples
are not evidence of a restart storm. Raw cumulative counts remain available.
Telemetry-owned incidents close only after consecutive complete positive
observations. Missing collectors, failed measurements and offline gaps reset the
stability evidence. Human-created/legacy incidents without telemetry provenance
are never automatically closed. Closure contains samples, timestamps and an audit
event; it proves the symptom cleared, not a root cause or repair attribution.

- `SERVERHUB_INCIDENT_STABLE_SAMPLES=3`
- `SERVERHUB_INCIDENT_STABLE_SECONDS=120`
- `SERVERHUB_MONITOR_RESTART_LIMIT=3`
- `SERVERHUB_MONITOR_RESTART_WINDOW_SECONDS=3600`
- `SERVERHUB_MONITOR_RESTART_BACKOFF_SECONDS=60`

Monitor restarts reserve durable per-host/operation/target attempts before
execution. Cooldown doubles across attempts, capped by the window; new jobs cannot
reset it. Retry of the same job uses the same command key for reconciliation.
Blocked repairs report incomplete results. Existing monitoring.repair, concrete
operation grants and broker allowlists remain mandatory.

The root configuration watchdog cleans only old (one hour), matching journal-key
temporary regular files in root-protected directories, under the recovery flock.
It rejects links, hard links, foreign ownership and writable-by-others files;
armed/live records and recent files are left alone. Unrecognized/orphaned files
without a corresponding journal are retained for operator inspection. It never
removes checkpoints or backups. Existing independent operation rollback is intact.

## Upgrade, rollback and verification

No new database migration: the schema remains `0006_pause_clock`. Quota and monitor
ledgers and incident evidence use existing JSON state. Review the new defaults and
proxy CIDR restriction before upgrading. Read-only production preflight from a
reviewed checkout (not executed against production during this task):

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/src" python3.12 -B -m serverhub.ops.installer --source "$PWD" --preflight
```

After separate deployment authorization, follow [upgrade.md](upgrade.md): make
and verify protected database/config backups, build with
`./scripts/install-ubuntu.sh --build-only`, then use the reviewed
`sudo ./scripts/repair-install.sh` maintenance procedure. Do not operate generic
Control unit names. Retain the previous trusted release and backup. A rollback to
PR #10 requires no database downgrade, but must use the documented controlled
release/offline recovery procedure and restore compatible route configuration;
it removes these enforcement improvements. Pause autonomous work before rollback,
verify service health and policy/audit access, and review interrupted writes before
resuming. No automatic rollback across a trust-boundary change is authorized.

Regression coverage includes budget pause/increase/resume/completion, role/route
ceilings through API and OAuth MCP, malformed routes, nested pause/cancel,
continuations, durable daily accounting, concurrent PostgreSQL admission/claims,
proxy spoofing/failed/successful login, delta-based incidents, monitor caps and
root watchdog recovery. Exact local and CI counts are recorded in the PR. Local
PostgreSQL, native systemd and Ollama omissions are not described as real tests;
the repository's disposable Ubuntu CI exercises those separately. A discovered
frontend datetime-local minimum used UTC rather than local time; it is corrected
so non-UTC browsers can create valid short-lived permissions.
