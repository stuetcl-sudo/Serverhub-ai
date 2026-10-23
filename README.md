# ServerHub AI OS

The [production-readiness candidate](docs/production-readiness.md) reconciles both
feature branches and documents native TLS access, context compaction, dedicated
worker identity, audit improvements and the remaining release gates.

The [token-budget and execution fix](docs/token-budget-fix.md) records the measured
20k failure, provider-aware accounting, durable reservations and attempt-safe
preflight pause/resume behavior.

A [persistent read-only host audit](docs/host-audit.md) now collects fresh node
evidence and generates capacity/security/update/zone plans without a model or
production changes. See [its verification report](docs/host-audit-report.md).

The first [issue #2 increment](docs/host-autonomy.md) fixes model token accounting
and adds bounded read-only discovery history. See [its verification report](docs/issue-2-report.md)
for implemented scope, tests and remaining multi-agent/optimization work.

The stability/autonomy overhaul adds resumable native installation, owner-managed
Ollama discovery/tool testing, expiring autonomy profiles, actionable diagnostics
and verified/partial job outcomes. Start with [the native Ubuntu workflow](docs/installation.md)
and [legacy migration guidance](docs/upgrade.md). See [the overhaul verification report](docs/overhaul-report.md)
for exact tests and remaining limitations. No production deployment is implied.

Native Linux infrastructure management with a FastAPI controller, PostgreSQL-backed durable jobs, independently authenticated node agents and a React/TypeScript administration interface.

**Delivery status:** implemented software with automated verification, not a certification of production readiness. Read [the delivery report](docs/delivery-report.md) for exact tested functionality and remaining limitations before installing. Broad autonomous administration, every possible repair, and automatic elimination of all security issues are not claimed.

## Start here

- [Installation](docs/installation.md): native Ubuntu 24.04 controller and Debian/Ubuntu ARM64 nodes.
- [Administrator guide](docs/administrator.md): identity, expiring host/project approvals, jobs and family access.
- [Architecture](docs/architecture.md), [security boundaries](docs/security-boundaries.md).
- [Integrations](docs/integrations.md), [development workflows](docs/development.md), [MCP and OAuth](docs/mcp.md).
- [Backup/recovery](docs/recovery.md), [upgrades](docs/upgrade.md), [operations](docs/operations.md), [troubleshooting](docs/troubleshooting.md).

## Development

Python 3.12+, Node 22.12+, PostgreSQL 16+. The controller does not require Docker.

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install -e '.[test]'
npm ci --prefix frontend
npm run build --prefix frontend
.venv/bin/pytest
```

Production uses PostgreSQL. SQLite is explicitly development-only. To exercise the application locally without managing an OS service, set `SERVERHUB_DEV_MODE=true`, `SERVERHUB_DATABASE_URL=sqlite:////absolute/path/serverhub-dev.db`, `SERVERHUB_PUBLIC_URL=http://127.0.0.1:9080`, `SERVERHUB_ALLOWED_ORIGINS='["http://127.0.0.1:9080"]'` and `SERVERHUB_FRONTEND_DIR="$PWD/frontend/dist"`. Then run:

```bash
serverhub migrate
serverhub create-user --username owner
serverhub serve
# In another terminal with the same environment:
serverhub worker --inline
```

The local development mode still enforces authentication and operation policy. No nodes, model credentials, or repair grants are preconfigured. The worker continues independently of the browser.

## Scope and trust

All infrastructure changes require an unexpired explicit policy, including owner requests. Agent tools use compiled operation allowlists and a separate root-owned broker allowlist. No arbitrary shell, root SSH, `sudo`, unrestricted SQL, or raw Docker socket tool is exposed to the AI. Broker deployment accepts only registered, hash-pinned Compose projects. Unknown services are reported with evidence and are never removed merely for being unknown.

Database grants keep policy/users/session/control-plane state read-only to the worker; audit records are append-only. Native service hardening makes installed source, configuration and recovery artifacts read-only to workers. The independent backup/recovery services hold recovery permissions. Root and database administrators remain part of the trusted computing base.

Automatic firewall/SSH/network mutation and generic production application deployment are deliberately unavailable until separately implemented and verified adapters can prove recovery. See the report rather than inferring a capability from a dashboard page.

## Repository and release

`src/serverhub` contains controller, agent, AI, integrations, native operations and development tools. `frontend` is the real-data web client. `migrations`, `packaging`, `scripts`, `policies`, `tests` and `.github/workflows` contain native deployment and validation assets. The release archive includes source, Git history, a wheel, locked dependencies and prebuilt web assets. No production data, API credentials or private signing keys are included.

License: Apache-2.0.
