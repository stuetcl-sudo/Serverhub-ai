# Production-compatible OAuth candidate implementation plan

> Execute inline under the user's explicit autonomous authorization. No merge, production deployment, service restart, credential change or production database mutation.

**Goal:** Build and verify an OAuth-only candidate preserving the exact installed repair-20261024T195431Z-60f67b runtime.

**Architecture:** Base the worktree on 42483fb0fe59f76e783ca309aff1ac381dd24d84, which matches all 65 installed package files and the original wheel. Transfer only PR13's OAuth/CSP production-code patch. Keep schema 0006_pause_clock, dependencies, service identities, frontend and all other Python modules unchanged. Isolate all database and rollback exercises from production.

**Tech stack:** Python 3.12, FastAPI, SQLAlchemy/Alembic, PostgreSQL 16, pytest, WebKit/Playwright.

**Spec:** User request and /home/serverhub/oauth-csrf-release-preflight-20261025.md.

## Tasks and ledger

- [x] Identify installed source through complete package hash and original wheel comparison.
- [x] Establish isolated PostgreSQL and a baseline, documenting the production-anchor test fixture failure.
- [x] Reproduce concurrent consent failure on the unchanged baseline (403 instead of 303).
- [x] Apply only the approved src/serverhub/mcp.py and src/serverhub/main.py patch; pass OAuth/WebKit cases.
- [x] Build the candidate wheel and assert exactly those two package files differ from installation; all migrations, dependencies and service/recovery contracts remain unchanged.
- [x] Run full backend, PostgreSQL migration/grant, MCP, OAuth and WebKit suites: 466 passed, 8 skipped. Fix test fixture isolation and browser dependencies.
- [x] Exercise real backup/restore with isolated PostgreSQL and an isolated code-switch/watchdog rollback drill using actual candidate files. No live systemctl execution.
- [x] Preserve installed web bytes in unsigned review bundle; record hashes and owner-signing/maintenance gates. Never generate a production signature or update anchors.
- [x] Obtain independent final review: no critical/important defect; expand browser denial/query-path coverage and pass it.
- [ ] Publish pinned-base candidate PR and record exact source SHA/current CI status in the external release ledger.
- [x] Record production-backup verification limits, deployment steps, service impact and exact previous-release rollback target. Confirm live Control and recorded services/code unchanged.

Production remains blocked on owner-maintained Python code anchors, a fresh protected production backup/restore proof, candidate-specific protected journal and root-native validation. These are not marked completed by the isolated test drill. See docs/oauth-csrf-production-candidate.md.

## Review focus

Parallel flows and replay: independent pending records, cookie deletion affects only completed flow. Safari: Strict cross-site entry plus same-site continuation, callback CSP source encoding. Artifact compatibility: package file set and all non-OAuth bytes unchanged, schema head identical. Recovery: rollback selects the current production release rather than a stale journal target, PostgreSQL exercises target only a fresh isolated cluster. Trust: unsigned candidate is not a production authorization; protected production backups/keys remain outside this worktree.

Ruling: Proceed without a plan approval pause because the user explicitly authorizes autonomous Git/workspace/test execution and requests completion without production mutations.
