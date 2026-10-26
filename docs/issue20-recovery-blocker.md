# Issue 20: interim fail-closed protection, not migration release clearance

Base: PR16 candidate a9623febf458aeedc1fac0e81558d4d37b506a08.

Confirmed defects: repair's exception handler switches old code and restarts it
without restoring/verifying database compatibility; the independent release
watchdog does the same. Recovery-runtime replacement occurs before migration,
and configuration snapshots are process-memory state rather than a complete
crash-recoverable transaction. Backups are taken before application quiescence.
A successful synthetic restore drill does not cure these transaction defects.

This change blocks schema-changing repair BEFORE backup, runtime/trust writes,
service stops and migrations. Actual database revision, previous manifest and
candidate migration head must all be 0007. There is no force/bypass flag. The
exception handler checks actual schema before old-code activation. Uncertain
schema leaves AI API/worker stopped and records manual_recovery_required when
an armed journal exists. The watchdog refuses legacy repair journals with no
schema proof and repair journals incompatible with the actual DB/previous code.
It retains the candidate link and never restarts old code in that case. Control
services are not part of the stop list. Credentials are not logged.

This is deliberately an interim containment change, NOT completion of issue20.
It makes legacy schema-changing repair unavailable; existing legacy-upgrade
acceptance tests requiring that unsafe path will need the completed replacement
transaction, not relaxed assertions. Do not merge/deploy this draft as a complete
production upgrade. Existing deployed watchdog code is unchanged by this PR.

Remaining implementation gates:
- Durable transaction lock and phase journal, root-controlled and fsynced, shared
  by repair and independent watchdog; preserve old recovery runtime until commit.
- Quiesce all writers before a final checkpoint; verify actual protected archive
  via isolated restore and check jobs/audit/OAuth/configuration identities.
- Explicit owner-approved coordinated code/config/database recovery, with no loss
  of post-checkpoint writes and no silent destructive restore/downgrade.
- Failure injection after each migration/activation phase and SIGKILL recovery,
  plus safe resumption when DB connectivity is unavailable or restore fails.
- Actual production attestation/archive evidence and independent release review.

No production changes, database restore, trust regeneration or merge performed.
