# Autopilot reliability

This change extends the merged PR #9 on `hardening/security-a634`. It does not
install anything on a production host, change policies, or authorize deployment.

## Budgets and recovery

The historical default is 20,000 total tokens and 1.0 API cost units per job, not
a model context-window limit. Model routes now accept `default_job_token_budget`
(0–2,000,000) and `default_job_cost_budget` (0–1000). Configure these through the
owner model-route API (`PUT /api/settings/models/{name}`; see OpenAPI for the existing
route configuration). Defaults are copied at submission; changing a route does
not silently enlarge running jobs. An explicit job budget, including zero, wins.
The development dashboard and MCP `create_development_job` accept both budgets.
Context limits, output reservations, measured usage, uncertain reservations and
child-job accounting retain their existing enforcement.

Budget exhaustion now pauses instead of terminating the job. Checkpoints and
accounted usage are retained. The initiating identity (or owner) can use
`PUT /api/jobs/{id}/budget` with `token_budget` and `cost_budget`, or MCP
`update_job_budget`, then the existing resume action. Updates require job.submit,
are limited to queued/paused/approval-blocked jobs, cannot lower limits below
usage, and are audited. No automatic unbounded budget increase is implemented.

## Deadlines and SIGTERM

Migration `0006_pause_clock` adds `paused_at` and `paused_seconds`. Only explicit
paused/waiting_approval time is excluded. Running, retry/backoff, queue-after-start,
worker downtime and dependency-wait time still consume the execution deadline.
Parent deadline checks and delegated child time limits use the same clock.
Existing paused records start from their recorded updated_at. This cannot recover
pause history absent from old databases. Original started_at remains unchanged.
Permissions still expire by wall clock and are rechecked at execution/resume.

Forked job processes reset SIGTERM/SIGINT to default rather than inheriting the
parent's flag-only stop handler. The supervisor still owns termination, lease
recovery and audit; external writes retain existing idempotency/reconciliation
requirements. SIGTERM is not proof an external operation did not take effect.

## Watchdog and broker

Watchdog restore uses a unique exclusive temporary file, preserves ownership and
mode, fsyncs file and directory, and cleans up its own temporary file on ordinary
failure. A stale deterministic filename from an older interrupted restore cannot
block retry. Unknown leftover files are not deleted. SIGKILL can leave an orphan
unique temp file: root may review these, but subsequent restore remains possible.

The broker accepts 1–16 connections (`max_connections`, root config, default 4),
with a bounded socket backlog. Excess connections are closed without dispatch.
Only explicit diagnostic reads run concurrently: systemd status/logs, network and
storage diagnostics, and Docker event inventory. All other operations retain a
single writer lock, including unknown operations until rejected by the allowlist.
Existing adapter filesystem locks and serialized hash-chain audit writes remain.
Controller priority and host/global job limits are unchanged. Broker lock wait
order is not a new priority scheduler; write throughput remains intentionally
serialized. A disconnected client must treat write outcomes as uncertain and use
existing reconciliation, never blind retry.

## Source reads

No generic files.read endpoint was needed. Development already has read_file with
project-based development.read authorization. It now walks directory descriptors
with O_NOFOLLOW, rejects symlink/hardlink/special-file reads, limits UTF-8 source
to 64 KiB, and denies common credential locations (.env, SSH/cloud configuration,
credentials/secrets files). Credential files must never be placed in ordinary
source files: filename rules and existing redaction are not a general secret
classifier. Neither controller paths nor production repositories become readable.

## Upgrade and rollback (operator procedure, not executed on production)

This changes trusted Python code and the schema; ordinary signed automatic
activation must reject the schema mismatch. Use the existing reviewed offline
[upgrade procedure](upgrade.md), with a verified PostgreSQL/config backup and
restore test in a disposable database first. For an already namespaced installation:

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/src" python3.12 -B -m serverhub.ops.installer --source "$PWD" --preflight
./scripts/install-ubuntu.sh --build-only
sudo ./scripts/repair-install.sh
```

The repair workflow controls AI service downtime, backup, migration, grants and
health verification. Never operate the generic ServerHub Control services. Review
migration 0006 and the broker concurrency change before approving this procedure.
Rollback across schema revisions is not an ordinary activation rollback: retain
the previous release plus protected backups, use the documented offline recovery
procedure, and verify health/migrations before resuming jobs. Downgrade to 0005 is
tested on a disposable database, but removes pause-accounting fields; do not run a
destructive database downgrade automatically on production. Code-only rollback can
produce a health revision mismatch, and older code counts approval pauses again.

## Verification scope

Regression tests exercise model defaults/explicit limits, exhausted-budget pause,
retained usage and checkpoints, approval pause/recovery, expired grants, child
signal handling, watchdog failed-rename retry, source traversal/link/credential
denials, bounded broker slots and real Unix-socket concurrent reads/serialized
writes. Existing write recovery, authorization, queue priority and audit tests run
unchanged. The real socket test skips only when the local sandbox prohibits Unix
sockets; it is mandatory under CI. Exact CI outcomes are recorded in the PR.

PR #11 extends these behaviors; see [autopilot-stability-security.md](autopilot-stability-security.md)
for guarded resume, conservative daily quotas, failure-attempt semantics, scoped
watchdog cleanup and local-proxy login settings.
