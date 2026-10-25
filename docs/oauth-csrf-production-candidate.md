# OAuth CSRF candidate based on the installed production release

2026-10-25 UTC. No merge, production deployment, production restart, credential,
SSH, firewall, code-anchor or production database change was performed.

## Decision

The source candidate passes local compatibility, backend, migration, PostgreSQL,
MCP, OAuth and WebKit verification. It is **not yet cleared for production
activation**: offline owner maintenance of protected Python code, a fresh verified
production backup and its isolated restore drill, and a protected candidate-specific
rollback journal remain mandatory. A signed ordinary upgrade must still reject
these changed Python bytes. Do not weaken or bypass that check.

## Why PR13 was blocked

PR13 (`8677f22901c0e1d0948d42200184ed8b1e448247`) is based on
`69de5c1c6179ef1120c8d4a0af22204924e3aec9`, with migrations through
`0003_schedules`. The installed release is
`repair-20261024T195431Z-60f67b`, schema `0006_pause_clock`.
GitHub comparison confirms that the installed source base is 82 commits ahead
of that old main/PR base. Replacing production with the full PR artifact would
discard existing job/runtime, security, MCP and namespace repairs. Its generic
`serverhub-worker.service` target belongs to legacy Control on this host.
The preflight also lacked a verified production restore drill and a safe current
rollback checkpoint. Passing PR13's old-base CI did not address these differences.

## Candidate identity and exact difference

Base: `42483fb0fe59f76e783ca309aff1ac381dd24d84`. Branch:
`release/oauth-csrf-42483fb`. Compare with the pinned review base
`release/installed-repair-20261024-base`, not old main.
The candidate commit is the commit containing this document; the external
release ledger records its full SHA and wheel checksums.

All 65 installed package files match this base byte for byte. The built candidate
has the identical package file set and changes exactly two runtime modules:

| File | Change |
| --- | --- |
| `src/serverhub/mcp.py` | Per-nonce consent cookie; nonce format check; matching cookie deletion; explicit same-site Continue link; validated callback CSP source |
| `src/serverhub/main.py` | Use that callback source only when rendering a validated consent page |

The added/removed runtime patch lines match PR13 exactly. There is no schema or
data migration. All migration bytes including 0004–0006, database grants,
dependencies, release/recovery/installer code, units, job engine and remaining
63 package files are unchanged. The MCP tool definitions/handlers are unchanged.
The unsigned review bundle copies the actual installed compiled frontend,
preserving production web bytes rather than rebuilding an older frontend.
Every locked dependency version was compared with both the installed production
venv and the test venv and matched.

Other source changes are OAuth regression tests, a dedicated WebKit CI job,
this documentation and a test fixture correction. The packaging fixture now
uses a temporary test-anchor path instead of accidentally consulting the real
`/etc/serverhub/trusted-code-hashes.json`; production verification is unchanged.

## Verification

- Clean installed-base suite previously showed 439 passed, 8 skipped and one
  environment-dependent packaging fixture failure against the protected real
  anchor. The isolated fixture correction resolves that failure without changing
  the runtime. The baseline overlapping-consent regression reproduces 403 instead
  of 303, establishing the defect independently of the fix.
- Final combined local run: **466 passed, 8 skipped**, 474 collected. Includes
  all 12 real PostgreSQL migration/grant/worker/login/backup tests and eight
  WebKit cases. No failed tests. One existing Starlette/httpx deprecation warning.
- OAuth coverage: approval/denial, parallel flow completion in either order,
  missing/wrong/legacy cookie, expiration, user binding, replay, S256, exact
  redirect/resource, invalid scope rejection, all seven nonempty scope sets,
  tool listing and forbidden calls, and CSP delimiter injection.
- WebKit 1.64.1 with iPhone 13 profile and real isolated HTTPS: cross-site entry,
  Strict session behavior, dashboard/Continue link, production cookie flags,
  parallel approval and denial, both orders, callbacks with an encoded path and
  existing query. Entry/callback/dashboard shell are stubs. No real ChatGPT
  account or physical iPhone end-to-end test was performed.
- Host browser libraries were extracted only under `/tmp`. Playwright's
  system-ldconfig-only precheck was skipped because it cannot see these local
  libraries; the actual browser loader, HTTPS requests and assertions ran.
  The CI job installs normal dependencies and does not skip this precheck.
- Wheel/sdist build, targeted Ruff and `git diff --check` pass. No production
  dependency change was needed. The new CI workflow is not represented as a
  completed CI run until exact-commit GitHub checks finish.
- Independent read-only code review found no critical/important runtime defect.
  Its requested additional browser denial/query coverage is included above.

The eight skips: six root/disposable-filesystem tests (autopilot recovery,
namespace journal ownership, host-audit broker target, host-operation protection,
node checkpoint ownership, protected release audit fixture) and two real-Ollama
tests. Native root systemd activation is not proven by this local run.

## Backup and rollback evidence

The real disposable PostgreSQL drill created a checksum-verified custom archive,
parsed it with pg_restore, restored 25 tables into a generated disposable DB,
and separately verified a restored marker row and `0006_pause_clock`. Restore
over a nonempty DB was rejected. All generated DBs were removed.

Actual previous package files and the candidate wheel were copied into an
isolated release tree. The installed independent recovery release module matches
the candidate/base release module byte for byte. Using that unchanged implementation,
both an expired watchdog journal and explicit rollback switched the filesystem
back to `repair-20261024T195431Z-60f67b`; database marker data was preserved.
Service commands were recorded and constrained to `serverhub-ai-*`, never executed.
This proves code selection/journal behavior; it does not prove live service restarts,
root ownership or production-backup restoration.

Published latest production backup remains `20261025T031724Z-ed741a29906e`,
status `checksummed; restore drill required`. Protected archive contents and the
live release journal are not accessible to the ordinary test identity. Control
MCP is monitor_only and has no native AI backup/release API. Do not copy secret
archives to an ordinary user workspace or elevate through simulated MCP actions.

## Concrete controlled deployment plan — not executed

1. Owner reviews this exact commit, runtime diff and external evidence/checksums.
   Require successful exact-commit checks including WebKit; complete the six
   root-only cases in a disposable native runner before declaring native readiness.
   Preserve the tested installed web artifact when signing; the generic builder's
   frontend source must not silently substitute different compiled bytes.
2. Select and document the offline owner-maintenance path required by
   `docs/upgrade.md#executable-code-anchor`. This is a separate owner decision:
   ordinary signed verify/prepare cannot accept changed Python code. Keep the
   stable independent recovery runtime and the previous release intact. Do not
   run a broad repair/installer or silently regenerate trust/code anchors.
   Have the owner sign the reviewed artifacts externally; no signing key enters
   the agent or repository. The current bundle is deliberately unsigned, with
   no production signature or fabricated validation approval.
3. Through the authorized native maintenance account, create a fresh protected
   PostgreSQL/configuration checkpoint. Verify every archive checksum and
   parseability. Restore the actual checkpoint only into a protected disposable
   isolated PostgreSQL environment; verify schema, audit chain and representative
   job/OAuth data without publishing secrets. Record backup ID and drill evidence.
4. Immediately before activation, recheck that `/opt/serverhub/current` resolves
   exactly to `/opt/serverhub/releases/repair-20261024T195431Z-60f67b`, schema is
   0006, namespace ownership is valid, and Control units/PIDs are recorded.
   Validate the protected journal: `previous` is that exact path, `candidate` is
   the reviewed immutable release, `release_id` matches, `backup_id` identifies
   the verified checkpoint, and `deadline` has the agreed 30–900 second grace.
   Stop if another armed journal exists. Arm before switching code.
5. The existing activation implementation restarts `serverhub-ai-api` and
   `serverhub-ai-worker` and try-restarts `serverhub-ai-broker`/`serverhub-ai-node`.
   Account for all four AI services in the maintenance window; do not introduce
   an ad-hoc API-only bypass. Record current jobs/checkpoints and use the existing
   worker recovery semantics. No DB migration or downgrade is needed.
   Never target generic Control units, PostgreSQL, Docker or proxy for restart.
6. Within the grace period, verify `/health`, schema, discovery/S256/resource/
   scopes, MCP unauthenticated challenge, authenticated OAuth negatives,
   approval/denial, parallel tabs, callback and representative authorized and
   forbidden MCP calls. Verify all AI services, worker recovery and existing
   job checkpoint/budget semantics. Recheck legacy Control and unrelated PIDs.
   Mark the journal verified only after these checks pass.

## Concrete rollback plan — not executed on production

On failed health/security/job checks, use the independent recovery runtime and
the reviewed protected journal to revert to the exact previous release above.
Validate the journal before invoking rollback; the pre-existing journal could
otherwise select an older incompatible release. The unchanged rollback routine
switches code, restarts the same two AI services and try-restarts broker/node;
the independent timer performs the same action on an expired armed journal.
Repeat health/schema/MCP/Control checks and record `state: reverted`.
Do not downgrade Alembic or restore destructively over the live database.
Both releases use schema 0006; retain all jobs/data, backups, old executable and
owner-reviewed anchor/recovery checkpoint. Any database recovery is a separate
reviewed operation into an empty database, never an implicit rollback side effect.

## Remaining risk and boundary

Many abandoned authorizations can accumulate five-minute cookies and hit browser
or proxy quotas; no CSRF bypass was identified. Existing consent pages opened
before activation may need a fresh authorization. Physical-device/real-account,
root-native activation and actual production-archive restoration are outstanding.
The protected owner-maintenance decision and production restore proof are release
gates, not candidate source incompatibilities that can safely be patched away.
