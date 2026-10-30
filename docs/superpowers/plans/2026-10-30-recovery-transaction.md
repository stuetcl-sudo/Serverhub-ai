# Recovery transaction implementation plan

**Goal:** Build a reviewable, crash-tested transaction core for issue #20 without enabling a production upgrade.

**Architecture:** A persistent SQLite journal records intent before every side effect. A separate SQLite exclusive transaction serializes the upgrader and recovery process, with automatic lock release on process death. An explicit adapter owns quiescence, immutable checkpoints, isolated restore verification and idempotent recovery. The existing schema-change block remains in force until the native adapter and independent runtime enrollment are reviewed and proven.

**Tech stack:** Python 3.12 standard library, pytest. Separate checkout based on PR #21 at f49c8f1.

**Constraints:** No deployment, merge, host or Docker restart, production backup creation, credentials or policy changes. Preserve Control. No neighbor host. Synthetic local fixtures only.

## Tasks

- [x] Write failing tests for cross-process exclusion, journal persistence after forced process death, ordering, failure at each phase and repeat recovery. Real DB connectivity remains a native-adapter gate.
- [x] Implement `ops/recovery_transaction.py`: durable journal, exclusive process lease and adapter-driven transaction. Never replace the recovery runtime or overwrite a live database. Commit before admitting application writes; recovery before commit must preserve failed candidate state.
- [x] Run focused tests and attempt full suite; document platform limitations and actual test results in `docs/recovery-transaction-core.md`.
- [ ] Independently review changes and publish a separate draft PR. List native adapter, PostgreSQL crash drill and production attestation as remaining gates; do not close #20.

## Decision record

The connector cannot enumerate authorized hosts/projects and Control cannot reach its broker. Therefore no installed-version or local-change claim is possible. Work continues locally through existing GitHub access. The user explicitly requested autonomous execution, so no design-approval interruption is introduced.

SQLite locking supports the local Windows test environment and the Linux target without an external dependency. A durable lock file is never unlinked or replaced. A journal is not a native recovery adapter: production remains blocked until real code/config/database operations meet the adapter contract.
