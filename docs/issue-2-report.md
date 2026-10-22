# Issue #2 — first implementation increment

Scope: token-budget blocker and read-only discovery, based on the unmerged
`overhaul/stability-autonomy` branch. This increment does not complete or close
issue #2. The dependency order and remaining work are explicit in
[host-autonomy.md](host-autonomy.md).

## Implemented

- Replace UTF-8 bytes-as-tokens/double-encoded schemas with an explicitly labelled
  mixed ASCII/UTF-8 estimate and framing/headroom. Adapt output reserve to remaining
  job/context space; keep paid API cost enforcement and conservative uncertain
  request charging. Persist readable estimate/reserve/measured usage events.
- Send configured Ollama context size; actionable preflight errors identify
  estimated input, output reserve, used/limit/context and serialized byte size.
- Preserve Docker observations when a container disappears during batched inspect;
  cap container count and inspect duration; make incomplete coverage explicit.
- Parse Compose v2 dependency labels correctly, scope service edges by project,
  record image/volume/project relationships, exclude arbitrary labels/env/logs.
- Automatic periodic discovery plus broker-only bounded Docker event hints and
  debounced refresh, without adding Docker access to workers.
- Read-only DRM GPU observations and opt-in reviewed Caddy JSON endpoint extraction.
- Persist timestamped structural snapshots/diffs in existing inventory samples;
  bounded per-host retention and scoped API/UI history; omit snapshots from chart
  responses. No schema migration or role/grant expansion is needed.
- Fix two existing frontend test races: wait for host options and event listeners
  rather than assuming the render already completed asynchronous effects.

## Local verification, 22 October 2026

| Check | Result |
| --- | --- |
| Full backend suite, disposable PostgreSQL 16.2 / Python 3.12 | **155 passed, 1 skipped**, 25.63 seconds |
| Skip | Real external Ollama endpoint/model not configured |
| Frontend unit/integration tests | **28 passed** |
| TypeScript and Vite production build | Passed |
| Ruff, application source and new discovery tests | Passed |
| Native installer staging into an isolated directory | Passed; hardened units/config/trust files generated |
| Fresh migration and upgrade/idempotence regressions | Passed in full PostgreSQL suite |
| Actual API + worker + enrolled native node, disposable database | Startup healthy; persistent node inventory jobs succeeded |
| Durable command records and audit chain | Two delivered commands; audit verification passed |
| Real Linux discovery | Kernel/packages/memory/disks/ports observed; unavailable restricted collectors reported as errors |
| Browser smoke, live disposable backend | Login, live host, inventory history and persisted result passed; no JavaScript errors |
| Mobile smoke | 390px viewport, history and chat without horizontal overflow |
| Actual fresh Ubuntu/systemd install | Verified separately by GitHub `native-ubuntu` workflow; inspect final PR checks before installation |

The local PostgreSQL server runs in an isolated temporary namespace; a test-only
UID compatibility shim is used for the bundled PostgreSQL executables, never the
application. This does not prove separate OS service users or systemd confinement
inside this constrained container. Those checks belong to the native Ubuntu CI
job. Real discovery reported expected interface/routing/systemd permission/tool
gaps in this environment. No existing production infrastructure was contacted.

Reproducible repository checks:

```sh
python -m pip install -e '.[test]'
# For PostgreSQL-specific coverage, use only your disposable test database:
export SERVERHUB_TEST_POSTGRES_URL=postgresql+psycopg://serverhub:isolated-ci-only@127.0.0.1:5432/serverhub_test
export SERVERHUB_TEST_DATABASE_CONFIRM=isolated
python -m pytest --junitxml=test-results/backend.xml
python -m ruff check src/serverhub tests/test_inventory_history.py
npm --prefix frontend ci
npm --prefix frontend test -- --run
npm --prefix frontend run build
python -m serverhub.ops.installer --stage --root /tmp/serverhub-issue2-stage --source .
```

`.github/workflows/ci.yml` supplies the disposable PostgreSQL service and fresh
Ubuntu 24.04 native install/resume/upgrade/failed-health rollback environment.
`tests/test_inventory_history.py` includes Docker fixtures, a disappearing container,
collection limits/deadline, gaps, addition/change/removal, project-scoped graph
edges, secret exclusion, denied history access, retention isolation, Caddy
extraction, forbidden event arguments and event debounce/periodic recovery.
Provider tests cover the full real tool schema with mocked native qwen2.5:3b
responses; these fixtures never execute model-requested infrastructure changes.

## UI evidence

Screenshots use the real disposable backend and enrolled test Linux node, with
its actual constrained collection gaps. They contain no production data or
credentials. A sample with no observed Docker access does not fabricate containers.

![Desktop host change history](screenshots/inventory-history-desktop.png)

![Mobile host change history](screenshots/inventory-history-mobile.png)

## Limitations and security review

Token counting remains an estimate without the actual model tokenizer. Provider
usage can exceed a reserve; it is charged and further execution stops. Configure
provider-side billing caps when a hard financial ceiling is needed. The job
budget is cumulative across requests, not only one prompt. Configured context
must be supported by the model and fit inference-host RAM/VRAM; new GPU admission
control is not implemented in this increment.

Real external Qwen, Docker and Caddy behavior, ARM64, NVIDIA utilization and
production workloads are unverified here. Caddy discovery observes reviewed
configuration, not live endpoint health. Docker snapshots are bounded observations,
not a transaction; a race/incomplete sample explicitly breaks diff continuity.
History retains at most 1,000 samples per host and is not a backup or long-term
forensic archive. Event hints can overlap or be missed during downtime; periodic
full reconciliation is authoritative.

The optimization planner/apply/rollback workflow, editable multi-agent registry,
independent durable delegation, new agent MCP methods, extended bounded-job grants,
model-resource admission and Jarvis staging pilot remain to be implemented.
Existing policy authorization, OAuth, MCP, durable jobs, audit and protected
backup/release recovery remain in place; none is relaxed to make jobs pass.

Before connecting production: review this PR and base PR #1, require green CI,
exercise the reviewed Ubuntu install/upgrade on a disposable VM, test your actual
private Ollama model/context, enroll a noncritical node, review its broker target
allowlists and expiring read-only grants, verify its inventory/gaps/history, and
validate your protected backup/restore procedure. Production rollout and merging
require the owner's separate explicit approval.
