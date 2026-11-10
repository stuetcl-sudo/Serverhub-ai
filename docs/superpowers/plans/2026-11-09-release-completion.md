# ServerHub OS release completion

Goal: consolidate the latest existing candidate and local Homelab fix, run current Linux backend/frontend/package checks, repair reproduced defects, and produce an auditable release candidate.

Architecture: retain FastAPI/PostgreSQL, durable worker, React and existing policy boundaries. Base 67b0aa6 includes PR16, PR21 and PR22. Work in an isolated clone. Production activation remains subject to the existing separate release policy; issue20's native adapter must not be represented as implemented by the transaction core.

Tasks:
- [x] Reproduce and integrate the local inventory zero-argument guidance regression (0a2cdc4) against the latest candidate.
- [x] Review recovery journal correctness, add failing regression tests for confirmed defects, fix and run crash tests.
- [ ] Run full Linux Python suite, frontend tests/build, package build and lint. Resolve actionable failures and record externally dependent skips.
- [ ] Verify an isolated application runtime and record exact readiness limits and source revision.

Review focus: interrupted recovery, malformed journals, concurrent operations, fabricated host arguments, accidentally testing another installed source tree.

Execution: autonomous inline work as requested. No production data, SSH/firewall/OAuth secrets, release trust anchors or existing services are changed.

## Execution ledger

- Base: 67b0aa6, isolated clone; source of prior local correction: 0a2cdc4.
- Inventory regressions: 2 failures before integration, 28 orchestrator tests passed afterward.
- Independent recovery review found DELETE/FULL power-loss durability and missing directory synchronization; 3 regressions failed first, then 63 recovery/orchestrator tests passed.
- First local full suite: 549 passed / 27 skips. Frontend: 34 passed; build passed.
- Lint: two pre-existing unused imports removed; full src/tests lint passes.
- First disposable PostgreSQL run: 576 passed, 2 failures, 3 skips. Test infrastructure changed to shared disposable PostgreSQL loopback namespace and version-matched PostgreSQL 16 clients; no test assertions relaxed.
- Ruling: preserve the issue20 schema-change rejection and leave production untouched. The existing native adapter is absent, so automatic migration cannot be claimed safe.
- Ruling: use disposable Docker fixtures for real PostgreSQL/root-file checks, not native host systemd claims. Misreading this distinction would overstate readiness.
- Deferred minor from review: an already-existing journal is not rechecked for private read permissions on every open; protected ownership/no-write checks remain.
