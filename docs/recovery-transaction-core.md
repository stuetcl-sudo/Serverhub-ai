# Issue #20: durable transaction core (draft, not release clearance)

Based on PR #21 `f49c8f188e338f87ee294671a53478fe5ba4a03f`.
PR #16 remains a draft. PR #17–19 were merged into its candidate branch,
not evidence of installation or merge into the production baseline.

## Implemented

`ops/recovery_transaction.py` provides a standard-library transaction core.
It is deliberately NOT wired into `repair`, release activation, systemd or MCP.
The existing schema-changing repair rejection remains untouched.

Two persistent SQLite files have separate responsibilities: an exclusive
transaction on `lock.sqlite` serializes upgrader/recovery processes; independently
committed FULL-synchronous events in `journal.sqlite` retain each phase intent.
Neither file is replaced or unlinked. Process death releases the lease without
PID guessing or lease expiry. A missing, malformed or inconsistent journal
fails closed. Records validate immutable identities, checkpoint checksums,
recovery origin and legal transitions before any recovery adapter call.

The order is prepare -> quiesce all writers -> checkpoint -> isolated restore
verification -> migrate -> activate -> probe -> commit -> admit candidate writes
-> complete. Each side effect has a preceding durable intent. Recovery before
commit verifies and restores the checkpoint through an idempotent adapter while
writers remain fenced. The adapter must retain the failed database and restore
into a NEW database, never overwrite live data. Commit is irreversible: after
that point recovery can only resume candidate writes. A separate restored phase
prevents restoring again after previous-release writes may have been admitted.

There is no runtime replacement, service control, database restore, native
adapter implementation, CLI or automatic backup-job creation in this core.
Root ownership/path checks apply by default; the explicit non-root constructor
option is for synthetic local tests and is not an authorization boundary.
Deployment requires a root-controlled LOCAL filesystem, never NAS/NFS.

## Actual local verification

- 32 focused tests passed on Python 3.12 / Windows, including exclusive process
  contention and forced child-process termination at prepared plus ten upgrade
  and recovery boundaries. Recovery creates a new adapter from separately
  persisted synthetic DB/config state, not the killed child's memory.
- Tests cover failures during migration, activation, probing, restore and write
  admission; immutable checkpoint retention; repeat recovery; invalid journal
  records/transitions; missing journal; and private error-message sanitization.
- Independent review found incomplete journal validation; six new regressions
  failed before the correction and passed afterward. A separate check corrected
  retry of failed write admission without repeating database restoration.
- Ruff for changed Python files and whitespace checks passed.
- Full repository pytest was attempted, but collection stopped with 18 errors
  from Linux-only `fcntl`, `grp`, `pwd` and `resource` imports on Windows, plus
  one skipped test. This is NOT a passing full suite or real PostgreSQL proof.

The base PR #21 exact-head CI was inspected: backend/frontend/dependencies,
native Ubuntu and OAuth/WebKit succeeded; both legacy migration jobs failed.
Those are historical base results, not verification of this new branch.

## Remaining release blockers

1. Implement and independently review the native adapter: persistent fencing of
   every DB/config writer, quiesced DB/config/code checkpoint, exact identities
   for jobs/audit/OAuth/config, restore into a new DB and coordinated selection.
2. Share this lease/journal with native repair and the independent watchdog.
   Preserve the independently attested old recovery runtime unchanged. Enrollment
   must be explicit; do not regenerate trust anchors or silently replace it.
3. Run real disposable PostgreSQL failure/SIGKILL tests with production-equivalent
   roles, connection failures, restore failures and code/config selection.
4. Obtain fresh installed-version/local-change attestation and an already
   authorized protected real-backup restore acceptance. No new backup is approved
   by this PR. Production data/job history/OAuth and legacy Control must survive.

Do not close #20, remove the schema-change block, merge or deploy this draft as a
complete coordinated recovery implementation.
