# Production readiness release candidate

This candidate integrates both `feature/autonomous-host-agents` (including final
provider-aware token accounting and durable reservations) and
`feature/host-audit-workflow`. Neither feature branch is discarded. The target
for review is `overhaul/stability-autonomy`; this is not a production deployment
or a claim that every master-task capability is complete.

## Installation and migration

Use [the Ubuntu installation workflow](installation.md). On a fresh controller,
`./scripts/install-ubuntu.sh --public-url https://YOUR-CONTROLLER --ai-identity`
selects a dedicated `serverhub-ai` nologin worker account. API, migration and node
accounts remain separate. A root-owned systemd worker drop-in selects the identity;
the worker retains its restricted database role, state directory and sandbox.
No sudo membership, Docker group, broker socket or unrestricted command endpoint
is granted. The installer journal records the selection; resume with the same
option. Existing installations must use [the backed-up upgrade procedure](upgrade.md),
not rerun a fresh install with a different identity. Conversion of an existing
worker identity is not automated by this candidate.

The release reconciles existing additive schema migration 0004. There is no new
schema migration. Rebuild the wheel and frontend from this branch before upgrade.
Upgrade backs up PostgreSQL and `/etc/serverhub`, arms the independent release
watchdog, migrates, activates and verifies. Failed activation restores the previous
release/configuration. Do not downgrade additive database tables destructively.
Review trust-boundary changes locally as root; an AI worker cannot approve them.

## Persistent authenticated access

The default remains loopback HTTP behind an explicitly configured HTTPS reverse
proxy; see `packaging/config/nginx.conf.example`. This is a native systemd API;
there is no requirement for a terminal-held SSH tunnel. Existing proxy/firewall/
SSH configuration is never changed by installation.

A controller may instead serve HTTPS directly. Provision a certificate from your
trusted public or private PKI with the exact DNS/IP Subject Alternative Name.
Install the certificate chain and private key in a root-owned directory searchable
by `serverhub-api`, with the key root:serverhub-api 0640 and directory 0750.
Copy and adapt `packaging/config/access.env.example` to
`/etc/serverhub/access.env`, also root:serverhub-api 0640. Use the **test VM's own
address**, not the production host address. The file selects bind/port, canonical
public origin, TLS files and an independently certificate-verified health URL.
For a private PKI, supply its CA certificate through `SERVERHUB_HEALTH_CA`; never
turn off certificate validation. The example's private addresses are examples,
not endpoints this release has configured.

After explicit operator review, `sudo systemctl restart serverhub-api` loads the
optional access environment. The installer enables this systemd service, so it
survives reboot. Certificate renewal must preserve the group/read permissions and
restart the API; private-PKI enrollment/renewal is operator-managed. No HTTP
redirect listener or public Ollama listener is created. A non-loopback production
HTTP listener is rejected at startup. Reverse-proxy deployments keep loopback
binding; untrusted forwarded headers remain disabled. Authenticated APIs still
require user/node identities, and cookie writes still require an allowed Origin.
Only the UI assets and normal authentication/discovery endpoints are public.

Run the certificate-aware health command with the API environment loaded, or
`serverhub health --url https://CONTROLLER:9080 --ca-file /path/to/ca.pem`.
Native upgrade and release activation use the protected health URL/CA from the
API/access environment, rather than assuming loopback plaintext.

The canonical public origin is always allowed for assets and cookie requests,
even if a legacy explicit origins list retains the old domain. Foreign Origins
remain rejected. Missing assets and API routes return 404 rather than SPA HTML.
Filesystem asset validation and installed-service health checks remain mandatory.

## Long jobs, recovery and evidence

Provider formatting, tool-schema estimates, context limits, cumulative budgets,
output reservations and durable pre-request debits retain the
[token-fix guarantees](token-budget-fix.md). Context pressure now replaces bulky
older tool observations with bounded previews and durable call references. It
preserves the system instructions, original request, call IDs and response order.
Full results remain in `ai.completed_calls` and verification evidence, outside the
model prompt. Compaction never refunds previously billed tokens or invents a
summary. If immutable instructions/schemas still do not fit, existing actionable
preflight pause behavior applies. The estimator remains approximate; real provider
usage is authoritative when valid.

Read-only external integration failures become durable tool observations so the
model can choose another diagnostic. The same failed operation/arguments may
execute twice; further identical attempts are suppressed, including after a
worker restart. Mutating integration failures still stop for explicit recovery;
a request with an ambiguous write is never blindly replayed. Job/model budgets,
step limits, policy checks, leases and hard timeouts remain enforced.

Broker records now include structured arguments, peer UID, actual effective UID/
GID, unique execution ID, before/after phases and available verification/exit-code
metadata. Node envelopes correlate command, job, host and initiating operator.
Correlation fields are diagnostic metadata, never broker authorization. Critical
service status/logs can be independently allowlisted for diagnostics, while
restarting those services remains forbidden. The
broker still independently checks its peer UID and root-owned allowlists.
Reported execution context is node evidence, not proof against a compromised
node. Actual selected provider/model/route are recorded in job events.

New broker audit records are append-oriented, fsynced and hash-linked under a
locked root-only regular file, defaulting to
`/var/lib/serverhub-broker/audit/events.jsonl`. Systemd creates the broker state
directory as root-owned 0700. The native Ubuntu test recorded `/var/log` mode 0775 and `/var/lib` mode
0755. The default avoids the group-writable `/var/log` ancestor: a protected child alone cannot prevent parent-directory
replacement. Existing `/var/log/serverhub-broker/events.jsonl` files are retained;
an operator may copy a reviewed legacy audit file to the new protected location
before broker activation to preserve one chain. Explicit custom audit paths still
must satisfy the full ancestor checks. Group/world-readable files, symlinks, incomplete
trailing records and unsafe ancestors are rejected. Existing legacy records form
an explicitly unlinked prefix; they are not retroactively authenticated. Use
`serverhub.node.broker.verify_broker_audit(path)` for a read-only chain check.
Root/database administrators can still rewrite a complete local chain or remove
its tail. Export hashes/logs to an independent append-only system for stronger
retention; that external sink is not provisioned here. Null exit codes mean the
adapter has no underlying process exit code, not successful execution.

Reviewed upgrades and rollbacks now also `try-restart` active local broker/node
services after switching the release, leaving disabled services stopped. Upgrade
controller, agent and broker from the same candidate before enabling the
new audit correlation envelope. Older brokers reject the additional metadata
rather than silently accepting a changed protocol.

## Acceptance evidence and remaining gates

Exact test results and environment evidence are recorded in the PR and the final
verification section below. The reusable Ubuntu CI script exercises real service
identities, interrupted install/resume/repeat, migration, model setup through an
explicit HTTP fixture, a persistent delegated read-only job, authorization denial,
upgrade, injected failure/rollback and persistent certificate-verified HTTPS.
The fixture is not a real Ollama model.

The configured test VM `192.168.122.10:9080` and old production-side forwarding
port `192.168.68.135:19080` both timed out from this development environment on
2026-10-23. Direct, proxy-disabled requests to both addresses additionally failed
with `ConnectError: [Errno 101] Network is unreachable`. No SSH credentials or
network path to those hosts are available here.
Consequently the actually installed revision, failed tunnel's systemd/journal
state and real private Ollama endpoint cannot be inspected or verified. No
production changes were made. ServerHub Control MCP ping succeeded, but its
operation executor explicitly supports policy simulation only; it exposes neither
remote installation/command execution nor a Docker backup operation.

Outstanding production gates:

- Real `qwen2.5:3b` tool-call job and measured accounting on the operator's Ollama
  server, including long-context quality after compaction.
- Private VM connectivity, correct DNS/CA enrollment, certificate renewal and an
  actual VM reboot/access check. A disposable service restart is not a reboot.
- Operator-enrolled full host administration. This candidate intentionally retains
  the compiled operation allowlist; it does **not** implement a sudo-equivalent
  unrestricted policy or claim the AI can administer arbitrary host actions.
- General package installation/update, arbitrary configuration changes, existing
  Compose/image upgrades with application-aware rollback, automated Docker volume
  backup/restore and the complete Jarvis development pilot remain unfinished.
  Existing allowlisted restart, initial Compose deployment, isolated development
  workspace/test/staging mechanisms retain their documented limits.
- A real full Docker backup has **not** run. The available connector cannot create
  one, no selected container list or protected destination is configured, and live
  database volumes require application-consistent dumps or approved quiescence.
  Controller PostgreSQL/config backups do not substitute for Docker backups.
- Independent audit retention and off-host backups/restore tests are operator
  infrastructure requirements; no destination credentials were assumed.

Do not label this candidate fully production-ready until these gates have
independent evidence. The original master-task message was truncated in section
6; requirements beyond the received text cannot be assessed here.


## Received master-task acceptance status

| Area | Candidate result | Evidence or remaining gate |
|---|---|---|
| Branch reconciliation | Preserved both feature histories and combined conflict resolutions | Merge commit has token-fix and host-audit parents; native test retains both workflows |
| Token accounting | Provider-aware estimates, durable reservations, measured usage and preflight pause/resume | Provider/budget regressions plus native delegated fixture job; real private Ollama unavailable |
| Long-context recovery | Bounded previews retain original request and durable full tool results | Resumed persisted Ollama-format job test completes with deterministic verification |
| Frontend assets | Canonical-origin fix, routing 404s and direct TLS authentication checks | Asset/API regressions, TypeScript/Vite build, desktop/mobile browser smoke |
| Installation | Native install, interruption/resume/repeat and dedicated worker | Disposable Ubuntu 24.04 systemd CI; existing worker-identity migration is not automated |
| Access | Persistent TLS API or explicitly configured HTTPS proxy, no terminal tunnel required | TLS service restart test and API 401; private VM routing/PKI enrollment and real reboot remain blocked |
| Authorization | Exact expiring grants, independent broker allowlists and protected mutations retained | Unauthorized SSH restart 403; direct AI socket access denied; critical-unit read requires explicit grant |
| Full administration | Not implemented as unrestricted/sudo-equivalent host policy | Compiled broker allowlist and forbidden-operation tests reject arbitrary execution; no production enrollment performed |
| Durable execution | Existing PostgreSQL leases, checkpoints, recovery, budgets and deterministic verification retained | PostgreSQL restart/cancellation/ledger tests and complete native read-only lifecycle |
| Repair adaptation | Read-only integration errors become observations; identical failures execute at most twice | Durable repeated-tool test; mutating ambiguity remains blocked for reconciliation |
| Host operations | Inventory and registered status/log/restart/initial Compose operations retained | Live disposable Linux discovery and broker status; general packages/config writes/image updates remain unfinished |
| Development | Existing isolated registered workflow/patch/test/staging path retained | Existing development regressions; a complete autonomous Jarvis pilot remains unfinished |
| Audit | Database append protections plus protected correlated/hash-linked broker log | PostgreSQL denial tests and actual native root broker audit chain; independent off-host retention not configured |
| Backup/rollback | Controller DB/config backup and reviewed upgrade rollback | Native backup/failed-upgrade checks; Docker application backup/restore has not run and is unfinished |

Unavailable environments and missing implementations are separate limitations.
Passing the scoped regression suite does not certify the unfinished capabilities.


## Final verification

Validated source: `77374d7302a0d02bd1d27184c44ddb1bb5004c41`.
[GitHub CI](https://github.com/stuetcl-sudo/Serverhub-ai/actions/runs/39920897882)
passed all four jobs: backend, frontend, dependency audits and native Ubuntu.

- Local disposable PostgreSQL 16.2: **222 passed, 1 skipped**, 19.69 seconds.
  The skip is the optional real Ollama endpoint. Actual API startup, migrations,
  separate database roles, Linux discovery (696 native packages), two durable node
  commands, persisted read-only audit, database audit chain and desktop/mobile
  browser smoke passed. Restricted-container network/systemd collectors report
  explicit gaps; distinct real service UIDs are tested separately in Ubuntu CI.
- Hosted PostgreSQL suite: **219 passed, 4 skipped**, 18.23 seconds. Three root-only
  fixture checks are skipped on the unprivileged test runner; the fourth is real
  Ollama. The root fixture checks passed in the isolated local root suite.
- Frontend: **30 passed**; TypeScript/Vite build passed; no browser JavaScript
  errors and no horizontal overflow at 390px. Python wheel/sdist build and Ruff
  checks passed. Dependency audits passed.
- Native Ubuntu 24.04: documented fresh build/install, injected interruption,
  resume/repeat with credentials preserved, `serverhub-ai` worker identity,
  API/worker health, Ollama HTTP **fixture** setup, budget pause at zero attempts
  followed by verified read-only completion, honest partial host audit,
  unauthorized SSH restart **403**, actual root broker status/audit and denied
  direct AI socket access, controller backup, upgrade, injected-failure rollback,
  certificate-verified TLS service restarts and **independent systemd watchdog
  rollback after abandoned activation** all passed.

The expanded native broker test first failed at `29c08fb` because the audit path
traversed Ubuntu's group-writable `/var/log` (0775). The fix at `de01618` moved its
default to a root-only systemd state directory; the final native run proves the
correlated root audit and unchanged socket isolation. This failure was fixed;
its run is retained as evidence, not counted as passing.

Machine-readable results: [local](verification/readiness/local-results.json) and
[CI](verification/readiness/ci-results.json). They contain fixture metadata and no
credentials or production configuration. These results do not remove the
production gates and unfinished features listed above.
