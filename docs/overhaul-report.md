# Stability and autonomy overhaul — delivery report

Date: 22 October 2026. Review branch: `overhaul/stability-autonomy`.
Pull request: https://github.com/stuetcl-sudo/Serverhub-ai/pull/1

This is an implemented update of the existing FastAPI/PostgreSQL/systemd/node and
React architecture. It does not replace the application with a new framework, deploy
to production, or claim the original whole-platform vision is production-ready.

## Delivered behavior and root causes

| Observed failure | Confirmed cause and implemented correction |
| --- | --- |
| Migration inaccessible working directory | Privilege changes inherited the invoking directory and source search path. Migrations now run from an absolute installed release directory with caller import hooks removed; Alembic has an explicit release override and absolute script location. |
| Partial installation could not resume | Existence of either API/node config aborted installation. A protected atomic install journal now persists credentials/release/phase before side effects, repeats incomplete idempotent steps and retains completed steps. |
| Worker sandbox failed before startup | Mandatory `InaccessiblePaths` included optional Docker/broker paths. Missing optional paths are prefixed with `-`; strict filesystem/capability protection remains. |
| Loopback frontend 403 | Middleware rejected an Origin differing from the configured public origin, including a same-origin loopback asset request. Same-origin loopback access is now supported with exact host/port checks; foreign origins remain rejected. Asset existence, delivery and read/traversal modes are verified. |
| Missing/unreadable models | File existence incorrectly meant configured; the example used an unsupported route shape; no editable/testable UI existed. Validated database routes plus discovery/tool-test/save UI replace normal YAML editing. The shipped file was 0644, so the observed VM permission issue cannot honestly be attributed to that mode alone. Diagnostics inspect actual mode/ancestors and the repair workflow restores a validated non-secret fallback's readability. |
| Private Ollama required ad hoc HTTP edits | The broad boolean exception had no private-address restriction or guided setup. Consent is now endpoint-specific and limited to literal RFC1918/ULA HTTP; public/DNS/metadata HTTP is rejected. HTTPS remains the public default. |
| Read-only diagnostics blocked | `diagnostics.network` and inventory refresh were absent from the read classifier. They are classified correctly; expiring profile grants intersect identity, target, operation, arguments and environment. Broker allowlists remain independent. |
| Extensive manual job log inspection | Denials now retain structured exact request/permission evidence and remediation. Jobs record tool results, checkpoints and progress; diagnostics expose worker, schema, model, asset and host setup state. |
| Unfinished jobs reported success | Explicit incomplete outcomes and AI summaries lacking deterministic checks now become terminal `partial` results. Partial dependencies do not unlock successors. Verification states its limited measurable scope. |

Additional safeguards include model-route database write denial for workers,
protected command stderr, file writes with restrictive permissions before contents,
secret-safe malformed-model errors, and bounded explicitly permitted service logs.

## Installation and migration

Use [installation.md](installation.md) for the single Ubuntu workflow. Source builds
run as a normal user; the wrapper installs prerequisites, uses a checksum-pinned
Node build and hashed Python dependencies, builds both artifacts, and invokes native
installation through sudo. Rerun the same command after an interrupted fresh install.

For a reviewed existing installation, build with `--build-only`, then run
`sudo ./scripts/repair-install.sh`. It backs up database/configuration, preserves
credentials and identities, applies additive `0004_runtime`, refreshes explicit
PostgreSQL grants and reviewed units/code anchors, and healthchecks activation.
An invalid legacy model fallback remains root-only and cannot block access to the new Setup UI. Normal failure restores previous code/configuration; an independent rollback timer
is armed before service interruption. See [upgrade.md](upgrade.md) for schema and
legacy-partial-install limitations. No database is deleted to recover installation.

## Verified results

| Verification | Actual result |
| --- | --- |
| Local full Python suite with disposable PostgreSQL 16.2 | **134 passed, 1 skipped**. The optional live external Ollama test is not configured. |
| Local targeted provider/core/overhaul regressions | **60 passed, 1 skipped** after the provider-error sanitization change; subsequent migration fixture strengthening passed **22 tests, 1 skipped** in the overhaul file. |
| Frontend tests | **24 passed**, across API, dashboard and new setup/profile/diagnostic tests. |
| Frontend build | TypeScript/Vite completed; real compiled assets served by the API. |
| Real local controller/worker/node lifecycle | API startup and actual schema health, individually authenticated node, two durable node-command workflow steps, persisted success and valid audit chain passed. |
| Browser check against local real API | Desktop login/host overview/persisted job result passed; 390px mobile had no horizontal overflow; no JavaScript errors. Setup-specific flows also have React integration regressions. |
| Native Ubuntu 24.04 CI | Dedicated disposable runner built through the documented workflow, installed actual PostgreSQL/systemd accounts/services, deliberately interrupted installation before migration, resumed and reran without resetting credentials. |
| Native model/autonomy CI | Ollama HTTP fixture discovery, capability check, actual harmless structured tool probe, saved route, dedicated unprivileged node report and an adult account's expiring read-only AI job passed. Job finished `succeeded` with deterministic inventory-freshness evidence. |
| Unauthorized action | The adult account's attempted SSH-service restart returned **403**. Unit/policy/broker protections were retained; no SSH restart ran. Worker PostgreSQL tests reject model-route updates and protected policy/audit/recovery changes. |
| Native upgrade/recovery CI | Protected real database/config backup, successful upgrade, then deliberate post-upgrade health failure and restoration of previous release/configuration with healthy services all passed. |
| Dependency scanning | GitHub Python audit and npm audit completed successfully; frontend audit reported zero known vulnerabilities at scan time. |
| Code quality | Ruff on backend, new regressions/native smoke script and `git diff --check` passed. |

CI evidence for native install/upgrade/rollback and the preceding complete source
validation: https://github.com/stuetcl-sudo/Serverhub-ai/actions/runs/39813687220
The final application code revision also passed all four CI jobs:
https://github.com/stuetcl-sudo/Serverhub-ai/actions/runs/39814398317
(**133 Python tests passed, 2 skipped; 24 frontend tests passed; native upgrade/rollback and dependency scanning passed**).
Exact machine-readable local evidence is in `verification/overhaul/`; CI job logs
and artifacts are available from the linked runs. Hosted non-root Python testing
also skips the root-owned checkpoint test, which passes in the local isolated-root
suite. A deprecation warning from the FastAPI/Starlette HTTPX test adapter remains;
it is not a failing runtime healthcheck.

The native test uses a fresh ServerHub install on a disposable GitHub-hosted Ubuntu
24.04 runner. It is real systemd/account/PostgreSQL execution, not only a mocked
installer. It is not a separately booted pristine Ubuntu Server ISO on the user's
hypervisor, and it does not verify every possible pre-existing package state.

## Remaining limitations and production prerequisites

- A real external/private-LAN Ollama host and real model were not supplied. Official
  HTTP contracts and tool-call behavior are exercised with mocks and a real local
  HTTP fixture; the opt-in real-provider test is skipped. A successful setup probe
  does not establish that a model can solve arbitrary administration tasks.
- ARM64/Raspberry Pi native installation and actual Home Assistant, AdGuard, UniFi,
  UISP, production Docker, cloud providers and private Git services remain unverified
  in this overhaul. No unsupported write capability has been added or fabricated.
- Multi-node HTTPS proxy/certificate trust and first node enrollment remain explicit
  administrator work. The installer does not overwrite an existing reverse proxy or
  open ports. Ordinary provider selection and policy grants are editable in the UI;
  privileged broker targets and executable project definitions remain root-owned.
- Network diagnostics/service logs/status/restarts/Docker/scanners require an enabled
  node broker and exact local target allowlists. A controller policy alone cannot
  enable these. Inventory and container inspection use available node observations;
  missing privileged collection remains visible.
- Development profiles authorize the existing registered sandbox pipeline. They do
  not create project definitions, invent arbitrary commands, implement generic
  application deployment, finish Jarvis, or add a new autonomous test-failure patch
  repair loop. See [development.md](development.md) for existing staging boundaries.
- Verification proves only its listed checks from recent authenticated inventory;
  the AI's prose is not independent proof of the entire natural-language goal.
  External writes with ambiguous outcomes still stop for reconciliation rather than
  being blindly retried. Unsupported/unverified work remains partial or failed.
- Repair performs additive schema migration. Automatic rollback does not drop new
  tables/data. Old 0003 code can report a health revision mismatch after code rollback
  while 0004 remains; complete the upgrade or follow reviewed recovery guidance.
  An abruptly killed repair restores code through the watchdog; configuration
  snapshots remain protected for manual restoration where needed.
- Legacy partially installed systems with no journal/current runtime or missing
  credentials are not silently adopted. Inspect/back up them before repair.
- Explicit service-log grants can reveal private operational data. Redaction covers
  common credential patterns but is not a general guarantee for every log format;
  grant such access only to an appropriate account after reviewing the unit.

Before production: review the PR and policy/broker targets, reproduce installation
and upgrade on a VM matching the intended host, test the actual model and a scoped
read-only job, confirm HTTPS/node identities, rehearse backup restore, and only then
connect approved nodes. No production release or deployment is included in this PR.
