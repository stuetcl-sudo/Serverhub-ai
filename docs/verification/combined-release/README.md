# Combined autopilot/OAuth candidate — NOT cleared for production

User specification: combine merged PR12 with installed OAuth release
`oauth-csrf-pr14-3e9a2f4`, without production changes or trust bypass.

## Verified source and connection

PR12 merged at `0781775cfbb2fbc0723a192f3c1617e3fa87403e` into
`hardening/security-a634`. Both validate and real-Ollama workflows succeeded
on this merge (40181293087 / 40181293062). PR14's reviewed runtime commit is
`3e9a2f4bc32d455a2cecffddd495494d8ed08078`; validate and OAuth WebKit workflows
succeeded there (40221038130 / 40221038103). These are source-release checks,
not combined-candidate verification.

The candidate starts at the PR12 merge and applies PR14 without conflicts.
Only main.py and mcp.py change at runtime relative to PR12. Byte-hash tests pin
both modules to PR14. PR12 migration 0007 and restricted worker grants remain.
The original PR14 compatibility/rollback documents describe its historical
0006 base and are retained as historical evidence, not current production proof.

On 2026-10-26, Control MCP ping returned version 1.0.0/status ok. AI OS MCP
returned an enrolled serverhub host with fresh inventory. No mutating MCP tool
was called. backup_status returned []: no backup is visible to this identity.
It does not establish that root-protected backups do not exist.

## Release gates blocked by available interfaces

The connected MCP interfaces expose no read-only operation for resolving
/opt/serverhub/current, reading release.json, active package hashes, code/trust
anchor hashes, recovery-runtime hashes, or the actual database migration head.
Reported release names and historical PR14 compatibility files cannot replace
these observations. The active release and exact schema therefore remain unverified.
Do not substitute host inventory for executable provenance.

There is no authorized archive-read/export or isolated production-backup restore
interface. No fresh production checkpoint or production-data restore has been
performed. Creating a backup would also be a production write during a phase
explicitly restricted to no production changes. Existing disposable-database
restore tests are not production-backup proof.

## Required owner-maintenance evidence before an installer can be pinned

Obtain, through the established authorized maintenance channel, a sanitized
read-only attestation containing: current resolved release path and release ID;
schema head; package/migration/dependency/web hashes; trust/code anchors and
independent recovery hashes; unit ownership and Control PID/start-time records.
Do not export secrets, database URLs/passwords or signing keys.

An owner-controlled maintenance phase must then create a protected checkpoint
and restore it into an empty isolated database, checking audit chain, OAuth
records and representative persisted jobs. Test 0006 -> 0007 only after confirming
that 0006 is actually the source schema. Verify the real API/worker grants.
Exercise failed migration and failed health recovery against an immutable previous
release; retain the backup and independent watchdog. Schema rollback must not
silently drop quota state or restore over a live database.

Only then can a candidate-specific installer pin artifacts AND source/trust
preconditions, collect one owner approval, arm an independent rollback journal,
run the approved migration/grants, activate and verify health/OAuth/MCP/job
recovery. Ordinary signed activation rejects changed protected code and schema;
never regenerate anchors or invoke broad repair merely to circumvent this gate.

No production installation command is released: prerequisite hashes, backup
restore evidence and the approved trust transition are missing. Issuing a command
now would imply guarantees this candidate cannot establish. This is a blocked
candidate, not a deployment-ready upgrade.
