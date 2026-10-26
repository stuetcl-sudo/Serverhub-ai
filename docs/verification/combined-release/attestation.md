# Owner-maintenance read-only attestation (phase 1)

Review `scripts/attest-production.py` before executing it. It uses only Ubuntu's
system Python standard library, `/usr/bin/systemctl show`, and `/usr/bin/psql`.
It never imports installed ServerHub Python, executes a release binary, sources
environment files, writes anchors, runs migrations, changes services, or creates
backups. Normal OS/database access logs and filesystem access timestamps may
still be updated by reads. The only requested file write is the owner's report
outside the production installation.

From a reviewed checkout of the exact PR16 commit, in a private owner directory:

```sh
(umask 077; set -C; sudo /usr/bin/python3 -I scripts/attest-production.py > serverhub-attestation.json)
```

This is one manual sudo invocation. `set -C` refuses to overwrite an existing
report. Exit 2 preserves partial evidence and means **stop and review**, not
repair. Do not run install, repair-install, upgrade, or regenerate anchors to
make this report pass. Send the report for review; do not send environment files.

The report includes release identity/path and manifest digest, exact installed
Python module hashes compared with the existing protected code anchor, all
non-cache site-packages hashes (including native dependency bytes), migrations,
frontend, trust-file hashes, independent recovery module/dependency hashes and
watchdog digest. Dependency and watchdog authenticity still require independent
approved artifact hashes; self-consistency is not authenticity. A recovery
runtime intentionally older than the active code will be reported as an anchor
mismatch and requires explicit review, never automatic replacement.

Only the existing `serverhub_api` database identity is used, in a read-only
session with a five-second statement timeout, to SELECT `alembic_version`.
The password stays in the child environment, never command arguments or report.
No privileged fallback or new database grants are used. Unsupported configuration
or SELECT denial is a blocker reported without command output. No secret file
contents, URLs, process environments, journal logs, or database rows are emitted.

Root ownership and non-writability are checked along paths. Symlinked scanned
files fail closed. The explicitly resolved current release must be directly under
`/opt/serverhub/releases`. Systemd User/Group/PID/start-time and unit/drop-in hashes
are sampled twice. ServerHub Control's Python source tree is hashed twice,
excluding configuration/credential files. These samples prove only observed
stability during collection, **not historical preservation**. Compare with a
previous trusted Control baseline and reviewed unit identities. Timer executions
or concurrent legitimate activity can invalidate a sample; review and recollect.
The script is not a hardware attestation service and cannot defend against root
changing files between reads. Keep the report private: paths and code hashes are
operational metadata even though credentials are omitted.

## Phase 2 remains gated

No production installer is released by this collector, even if all local checks
pass. Before implementing/pinning the final owner-approved procedure:

1. Review actual report against approved PR14 installed artifacts, trust anchors,
   recovery runtime, service identity baseline, and actual schema.
2. In a separately authorized maintenance phase create a fresh protected backup;
   retain original unchanged. Restore to an isolated PostgreSQL environment with
   production-equivalent restricted roles and representative jobs/audit/OAuth data.
3. Run 0007 migration and negative privilege tests, budget/pause/child/restart tests,
   then inject failure after migration. Verify rollback preserves jobs, audit and
   OAuth and that the previous release works against the selected recovery schema.
4. Verify signed candidate artifact hashes, dependency lock, independent recovery,
   and exact permitted trust changes through the existing offline owner procedure.
   Ordinary release activation must continue rejecting changed protected code.
5. Only then publish a pinned script with one explicit owner approval, protected
   backup/restore evidence, audit journal, healthchecks and failure recovery.

Unavailable here: actual owner-run production evidence, protected fresh backup,
production-equivalent isolated restore and migration/rollback observations.
Fixture tests do not satisfy these gates. No production action is performed by CI.

## Timer and recovery correction after the first owner observation

Owner-reported production: `oauth-csrf-pr14-3e9a2f4`, schema
`0006_pause_clock`, active code/manifest/directory checks true, zero Control
Python changes, no collection errors. The original total false result included
normal watchdog transitions and a recovery comparison against the wrong anchor.
This report was supplied by the owner; a complete new report has not yet been
collected using the corrected script.

The committed recovery timer has OnBootSec=15, OnUnitActiveSec=5, AccuracySec=1,
and explicitly triggers serverhub-ai-recovery.service. The service is root-owned
Type=oneshot with the default Restart=no. Roughly six-second successful executions
are consistent with this configuration. The collector now requires exact reviewed
service/timer file hashes, no drop-ins, loaded units, reciprocal trigger properties,
active timer, oneshot/no-restart/root execution, Result=success and exit status zero.
Only this exact pair may vary PID/start timestamps and normal running/dead states.
All other services still require exact snapshots. Failed states, changed files,
identities, overrides, triggers and timer deactivation fail closed. The journal is
also queried for failures/error-priority messages during collection, without
returning message contents. An unreadable journal blocks attestation. A deleted or
lost journal cannot provide historical assurance; a compromised root is outside
this local collector's trust model.

Recovery is intentionally independent: `docs/upgrade.md` describes its stable
runtime, and PR14's production candidate procedure explicitly preserves it.
The reviewed pre-OAuth source is commit
`42483fb0fe59f76e783ca309aff1ac381dd24d84`, as recorded in PR14 compatibility evidence.
`scripts/attestation-recovery-baseline.json` pins all 65 Python files from that
commit, the standalone watchdog and reviewed unit files. The script pins that
baseline's SHA-256. It verifies every file and the exact Python file set; main.py
and mcp.py are not excluded. This is an independent **source-reference integrity
check**, not creation/replacement of a production trust anchor or release approval.
The original host active-code anchor remains untouched and still governs active
runtime checks. Dependency hashes still require artifact verification separately.

Copy/review the script AND its adjacent baseline from the same pinned PR commit.
Use the same read-only command, with a new report filename so existing evidence
is retained. The previous script checksum no longer applies. Do not copy runtime
modules or regenerate host anchors. A baseline mismatch remains blocked for review;
it never triggers an upgrade. No recovery-runtime change is needed merely to
match the two OAuth entrypoint changes.

Regression coverage: scheduled oneshot transitions, unsuccessful exit/result,
identity/type/restart/trigger/drop-in changes, timer and Control changes, journal
failure followed by success, pinned recovery baseline, tampered baseline and
unexpected runtime Python modules. Actual updated production attestation, fresh
backup restore, migration from the actual backup and post-migration rollback are
still outstanding. No production deployment is authorized.
