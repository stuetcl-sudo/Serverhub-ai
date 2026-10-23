# Production acceptance and actual verification

PR [#6](https://github.com/stuetcl-sudo/Serverhub-ai/pull/6) preserves the existing
FastAPI, PostgreSQL, React, systemd, MCP/OAuth, independent broker, audit and
rollback architecture. Both earlier feature branches remain in its ancestry.
The base is `overhaul/stability-autonomy`; the consolidated review branch is
`release/production-readiness`. It has not been merged or deployed to production.

Use [installation](installation.md), [reviewed upgrades](upgrade.md) and
[delegated administration](delegated-administration.md). Earlier candidate
evidence is preserved in [the historical report](production-readiness-previous.md);
its test counts and unfinished-feature statements are historical.

## Observed tests

The local development runtime became unavailable during this work. Subsequent
source changes were made through GitHub, and actual execution took place in
disposable GitHub Actions Ubuntu 24.04 runners. None of these results represents
a test on the owner's private production host.

| Execution | Observed result and evidence |
| --- | --- |
| PostgreSQL 16 API/backend | At `442ccb33a14260c9514940a6e3e17a202e81c0af`: 254 passed, 6 skipped, 1 warning. [Run 39946677391](https://github.com/stuetcl-sudo/Serverhub-ai/actions/runs/39946677391), backend job 120390915748. |
| Frontend | At 4ed938f (and repeated at f3cfba3): 31 tests passed, TypeScript/Vite build passed, npm high-severity audit passed with zero findings. These are DOM tests/build, not a new full browser session. |
| Fresh native install | Actual PostgreSQL/systemd installation, intentional interruption/resume/repeat, dedicated AI identity, healthy API/worker, certificate-verified persistent TLS, static assets, unauthorized API 401, SSH restart 403 and direct worker broker access denial passed. |
| Reviewed upgrade/recovery | Actual configuration/database backup, additive migration, old-install repair, injected activation failure and independent timer rollback passed on Ubuntu. |
| Real Ollama read-only job | Actual qwen2.5:3b daemon/model and persistent job passed, not an HTTP fixture. [Run 39945270317](https://github.com/stuetcl-sudo/Serverhub-ai/actions/runs/39945270317) recorded 2,250 provider-reported tokens, one attempt, inventory.read plus task.verify and verified success. Another real-model run at 4ed938f also passed. |
| Native host transactions | [Run 39943512380](https://github.com/stuetcl-sudo/Serverhub-ai/actions/runs/39943512380), native job 120380643727: actual pinned-package upgrade plus failed-acceptance rollback, configuration rollback, healthy stateless Compose update plus unhealthy-candidate rollback passed. |
| Docker backup/restore | Same native job: cleanly stopped PostgreSQL 16 container, discovered volumes/binds, encrypted backup, SHA/HMAC verification, Compose metadata and image exports, isolated restore into fresh storage and SQL verification of the restored row passed. Original source storage was not overwritten. |
| Independent operation watchdog | The root systemd timer recovered an intentionally abandoned stopped-container operation. This was timer-driven recovery, not a direct test call to recovery code. |
| Autonomous Jarvis | Actual pinned upstream source and qwen2.5:3b exercised dependency installation, source-edit attempts, eight upstream dashboard tests and an independent version check. At f3cfba3 the model inspected and repaired the injected local regression, installed dependencies and passed all registered checks. Staging then failed because extraction reset the release root to mode 0700. The fix normalizes the root as well as descendants to the project-only group permissions; actual runtime acceptance and failed-next-stage rollback still require a passing run. |

The six backend skips are four root-only fixtures and two opt-in live-model tests.
Root behavior runs separately in the native job; real-model execution runs
separately in the actual Ollama workflow. The native installer also uses an HTTP
Ollama fixture for predictable onboarding failures: that fixture is not counted
as real model inference. Read-only host audit can be partial when its inventory
collectors report gaps; partial is not verified success.

The actual model digest observed for qwen2.5:3b is
`357c53fb659c5076de1d65ccb0b397446227b71a42be9d1603d46168015c9e4b`.
Model outputs remain nondeterministic even with the same digest. A 3B model is
not guaranteed to solve arbitrary development or infrastructure tasks.

## Implemented boundaries

- Dedicated `serverhub-ai` worker opt-in; separate API/node/migration identities
  and independently authenticated root broker. No AI sudo or Docker socket.
- Scoped, expiring identity/host/project/environment/argument policies.
  One maintenance or development grant covers its permitted steps until expiry.
- Durable queues, priorities, dependencies, parent/child receipts, leases,
  checkpoints, model reservations, cancellation, emergency stop and bounded repair.
- Provider-aware approximate input estimates with explicit margins, separate
  context/job/output limits, provider actual usage, durable unknown-request
  debits and attempt-safe preflight pause. Compaction does not refund usage.
- Root-enrolled pinned packages/configuration/stateless Compose operations with
  pre-change journals, acceptance gates and independently recoverable inverses.
- Encrypted Docker archives, explicit retention, capacity/mount validation,
  scheduled operations and isolated restores. Planned downtime provides database
  consistency; this is not an online snapshot or automatic production cutover.
- Autonomous registered-repository tools with isolated Git branches, source
  inspection, edits, fixed dependency/build/test contracts, root-pinned independent
  checks and staged runtime. Neither model prose nor passing a build alone proves
  completion. See the observed limitations of the live pilot above.
- Functional authenticated UI and MCP operations reuse the same job queue,
  authorization and audit checks; OAuth compatibility remains.

## Remaining gates and limitations

1. The private test VM `192.168.122.10`, production-side forwarding endpoint
   and owner's private Ollama/NTFS disk are inaccessible from this development
   environment. Disposable Ubuntu evidence does not verify their routing,
   certificates, real reboot, storage durability, ARM64 hardware or backups.
2. Actual autonomous Jarvis runtime staging and failed-next-stage rollback have
   not yet passed the expanded live integration suite. Do not deploy production
   on the strength of unit/fixture checks.
3. Stateful package/application migrations, online database snapshots, privileged
   container restores and automatic production cutover require application-specific
   reviewed adapters. General arbitrary root shell execution is not exposed.
4. Hash-linked root audit is append-oriented and protected from AI/database runtime
   roles. A malicious root can rewrite or truncate an entire local chain.
   Independent off-host/WORM retention is not provisioned.
5. Staging has a private network with a separate HTTP probe, no public preview
   gateway, and fresh per-release data. It does not migrate production data.
6. Conversion of an existing worker identity to `serverhub-ai` is not automated.
   Fresh installation supports `--ai-identity`; reviewed upgrade preserves the
   existing identity.
7. A release signing key, production enrollment and the owner's application
   acceptance/restore contracts have not been supplied. Self-generated changes
   cannot modify policy, audit, broker, recovery or trust anchors silently.

## Operator deployment procedure

Do not run these commands on production until the release gates are reviewed.

1. Check out the reviewed PR commit as an ordinary operator. On a clean Ubuntu
   24.04 machine run `./scripts/install-ubuntu.sh --public-url https://YOUR-CONTROLLER --ai-identity`.
   Follow its owner onboarding; provision the exact trusted HTTPS certificate
   and persistent systemd access described in [installation](installation.md).
2. For an existing controller, build with
   `./scripts/install-ubuntu.sh --build-only`, then explicitly run
   `sudo ./scripts/repair-install.sh` from that checkout. Backups, additive
   migrations 0004/0005, service repair, watchdog and health checks are included.
3. Configure/test the private Ollama route in Setup. Plain HTTP requires the
   exact trusted private endpoint opt-in; never publish Ollama by default.
4. Locally review and enroll root-owned named operation/project plans, then grant
   only the required identity, host, project, target, environment and expiry.
5. Validate `/mnt/storage/ServerHub-Backups` is on the intended mounted disk,
   escrow the encryption key separately and perform an isolated restore drill.
6. Verify API and worker health, authenticated assets, a real read-only job,
   denied unauthorized operations, emergency stop and audit chain on this host.
7. For schema-compatible release activation, rollback with
   `sudo ./scripts/upgrade.sh rollback`. Reviewed repair failures restore the
   previous executable/configuration. Additive migrations are not destructively
   downgraded; old revision-0003 health checks can report a mismatch after a code
   rollback. See [upgrade recovery](upgrade.md) for the exact limitation.

No production command, enrollment, merge or deployment has been performed by
this engineering session.
