# Development autonomy, MCP and Jarvis follow-up

This extends PR #6 without changing ServerHub Control, its OAuth/MCP, broker,
worker, Docker Gateway or credentials. It does not deploy to production.

## Root causes and behavior

* Fresh project configuration now uses `projects: []`. The exact old empty
  `projects: {}` is accepted as empty and normalized during backed-up native repair.
  Nonempty mappings and malformed definitions are rejected. `/api/projects` returns
  a safe 503 with a remediation, without echoing parser values or secrets.
* Development runs on the **controller**. A host-specific grant cannot match a
  hostless job. Owner-created development profiles now bind subject, registered
  project, exact capabilities, development environment and expiry, without requiring
  an enrolled host. They include workspace/read/patch/dependencies/test/artifact.
  Infrastructure operations are excluded; mixed infrastructure targets are rejected.
  Network, draft PR publication and host-specific isolated staging are separate opt-ins.
* Archive creation uses `development.artifact`, not the staging capability. Old
  narrowly enumerated grants must be reviewed/regranted; no existing grant expands
  silently. Production releases remain separately protected.
* Hostless infrastructure chat chooses a host only when exactly one non-revoked,
  authorized host exists. Zero/multiple hosts return an actionable 422. Staging
  requires an explicit host; its UI selector lists enrolled hosts.
* The AI broker is intentionally disabled by default. Controller-only development
  does not need it. Host administration/staging requires explicit root enrollment;
  applying a reviewed plan enables **only** `serverhub-ai-broker.service`, including
  at boot. Diagnostics distinguish the missing AI broker and never substitute the
  legacy `serverhub-broker.service`. Broker allowlists and peer UID checks remain.
* Sandbox preflight runs `/usr/bin/python3 -I` **inside bubblewrap**, checks Python,
  pip, venv and SSL and records results. Missing tools stop execution with precise
  repair guidance. Native prerequisites include `python3-pip` and `python3-venv`.
  Project dependencies and pinned pytest install into the isolated workspace, never
  a production `.venv`. Builds/tests have no network. Dependency networking needs
  root project configuration **and** a live `development.network` dependency-phase
  grant. It shares worker networking, not a package-host egress allowlist; approve
  this powerful capability only for reviewed projects/dependencies.
* Normal workflow checkpoints now survive policy denial independently of the result
  object. Resume checks the original initiating account's denied operation before
  queuing. Every executed tool rechecks live expiry/revocation/emergency state.
  Missing verification produces `partial`, including ordinary development jobs.

## Delegate once

Register a protected project using `docs/examples/projects.yaml` or the concrete
[Jarvis main example](examples/jarvis-project.yaml) and its
[external acceptance check](examples/jarvis-check.py). Repository URLs, commands and independent checks are
root-owned contracts; prompts cannot replace them. Through **Policies → Development
autonomy**, choose the authenticated owner/admin account, registered project and
expiry. Select controller-only development. Enable dependency networking only if
needed. Do not select staging for a no-patch run.

Equivalent authenticated owner REST request:

```json
{"profile":"development","subject_id":"AUTHENTICATED_ACCOUNT_ID","project":"jarvis-os","hours":4,"allow_dependency_network":true,"allow_staging":false,"allow_publication":false}
```

`POST /api/policies/profiles` returns exact policy IDs for revocation via
`PATCH /api/policies/ID` with `{"enabled":false}`. Household/read-only role ceilings
still prevent development mutations. The worker has no policy-write permission.
A denied job shows operation, host, project, environment and missing permission.
Review that scope, grant it once if appropriate, then resume the same job. Browser
or ChatGPT disconnection does not cancel a queued/running PostgreSQL-backed job.

## MCP from ChatGPT

Use the **AI OS** HTTPS origin's `/mcp`; keep the Control connector unchanged.
Follow [mcp.md](mcp.md) for exact pre-registration, callback, S256 PKCE, audience,
consent and revocation instructions. No DCR/CIMD fallback or unauthenticated mode is
provided. An actual connection from the owner's ChatGPT account remains an external
acceptance check; native CI exercises the real HTTP OAuth consent/token/MCP path.

| Scope | Development tools |
| --- | --- |
| `serverhub:read` | `list_projects`, `job_progress`, `job_result`, `job_logs`, `development_artifacts` |
| `serverhub:jobs` | `create_development_job`, `resume_job`, `cancel_job`, `publish_development_result` |
| `serverhub:policies` | Owner-only `grant_development_profile`, `revoke_policy` |

A read scope never grants writes; scopes also cannot override identity/role/policy.
`list_projects` filters nonowner visibility. Job reads/logs/results and controls use
the same ownership rules as REST. Logs are cursor-based, bounded and redacted.
`development_artifacts` returns SHA-256 manifest and a bounded source patch; full
archives remain in protected worker storage and are not an arbitrary file download.

Example tool arguments, in order:

```json
{"name":"create_development_job","arguments":{"project":"jarvis-os","idempotency_key":"jarvis-main-validation"}}
{"name":"job_progress","arguments":{"job_id":"RETURNED_JOB_ID"}}
{"name":"job_logs","arguments":{"job_id":"RETURNED_JOB_ID","after":0}}
{"name":"development_artifacts","arguments":{"job_id":"RETURNED_JOB_ID"}}
```

Add a bounded `prompt` for autonomous investigation/edit/test/repair. Supply
`stage:true` and an explicit `host_id` only after separate staging enrollment and
policy. No tool accepts executable strings, clone URLs, filesystem destinations or
credentials. Use `cancel_job` for cancellation; paused/blocked jobs use `resume_job`.

## Draft PR publication

Optional, default off. Root project configuration must specify a credential-free
`https://github.com/OWNER/REPO.git` repository, explicit `publication_paths` (for
example `[app]`) and `publication_token_env: SERVERHUB_GITHUB_JARVIS`. Provision that
fine-grained repository Contents/Pull requests credential privately to the API's
protected service environment; never put its value in YAML, the repository, prompts
or worker environment. This step is an operator credential-provisioning task, not
performed by this change. Token installation/rotation must be separately authorized.

The owner must additionally opt into `allow_publication:true`. MCP
`publish_development_result` or the verified job's **Publish verified candidate as
draft PR** button uses `POST /api/projects/jobs/JOB_ID/publish`. It checks the live
project/operation/target/environment grant and verified result, limits source paths,
rejects `.github`/metadata/unsafe paths and binary/oversized files, verifies content
hashes after secret redaction, requires the exact upstream base, and only creates a
new `serverhub/JOB_ID` ref and draft PR. It never updates existing refs or merges.
Retries reconcile the same deterministic commit/branch. Publication is audited and
cached only after success; revoked permission still rejects a cached request.
HTTP tests use GitHub API fixtures; no real runtime publisher credential is available
in this development environment, so external draft PR creation is not claimed verified.

## Real Jarvis pilot

`scripts/test-jarvis-pilot.py` is destructive **disposable CI only** and refuses other
contexts. Never run it on the physical server, existing VM or Jarvis production.
The Ubuntu 24.04 workflow first installs/interrupts/resumes/upgrades AI OS and starts
an independent Control fixture. The pilot then:

1. Creates an OAuth S256 connection and a controller-only project grant; queues a
   no-patch workflow over actual MCP against public Jarvis `main`.
2. Installs application requirements plus pinned `pytest==8.3.5` into workspace
   `runtime`; builds Python source and runs actual `tests/test_dashboard_routes.py`.
   Independent checks assert the expected version and sandbox secret/mount/resource
   boundaries. Native preflight logs actual Python/pip availability.
3. Runs actual Ollama `qwen2.5:3b` against a **local fork of that exact public main
   commit**, with a deliberately injected harmless VERSION regression. The original
   upstream/production repositories are never written. Model tools correct the
   version, run the configured checks and finish only after independent verification.
4. Interrupts the worker after an edit, verifies durable recovery and bounded token
   accounting, then opts into root-enrolled isolated staging at private port 28098.
   An intentional bad health check must restore the healthy predecessor.
5. Verifies Control sentinel hashes, NSS identities, active PIDs/start timestamps and
   Docker Gateway HTTP remain unchanged.

Pinned upstream acceptance commit: `0c0ab744cb4159b0d36c00cf52defe3d4caab02b`
(Jarvis main 0.23.0). If main advances, update/review independent expectations before
changing this pin. This is the eight dashboard route tests, not a claim that every
Jarvis feature/test or a local pets branch passed. Application requirements are
pinned upstream; transitive dependencies are not fully hash-locked by that project.
Small-model nonprogress fails closed; passing one run does not prove all prompts work.

## Reviewed production procedure — NOT executed

For an existing **namespace-3 AI OS** installation only; legacy generic units or
namespace-2 identities must use [control-coexistence.md](control-coexistence.md).
A machine with Control only follows the fresh installer, never the migration tool.
Select the reviewed tested PR commit; do not build an unreviewed moving branch.

```bash
git clone --branch release/production-readiness https://github.com/stuetcl-sudo/Serverhub-ai.git serverhub-ai-os
cd serverhub-ai-os
git checkout REVIEWED_TESTED_COMMIT_SHA
# Read-only, no repairs/services/credentials changed:
sudo env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/src" python3.12 -B -m serverhub.ops.installer --source "$PWD" --preflight
# Build as the ordinary operator (installs scoped prerequisites, never source builds as root):
./scripts/install-ubuntu.sh --build-only
# Existing AI OS: root-reviewed repair backs up DB/config before activation:
sudo ./scripts/repair-install.sh
# Verify using the exact configured origin and CA; password is prompted privately:
/opt/serverhub/current/venv/bin/python -m serverhub.ops.verify_install --url https://YOUR_CONTROLLER_ORIGIN --ca-file /PATH/TO/PUBLIC_CA --username dennis
```

For a **fresh** AI OS installation alongside Control, replace build/repair with:

```bash
./scripts/install-ubuntu.sh --public-url https://YOUR_CONTROLLER_ORIGIN --owner dennis --ai-identity
```

Broker activation is not implicit. Configure projects/models/profiles using the
protected contract and owner UI. An explicitly reviewed root broker plan can be
previewed with `python -m serverhub.node.enroll --plans /ABS/REVIEWED_PLANS.yaml`
using the installed interpreter; `--apply` authorizes its own AI broker activation.
Never enable, stop, restart or replace Control's generic broker/worker units.

Repair reports `backup_id`, `previous_release` and current release. Keep that JSON,
protected backup and previous release. Failed repair automatically restores its
previous config/unit snapshots and code symlink. An independent recovery timer
handles interrupted activation. For a verified upgrade's **schema-compatible code
rollback**:

```bash
sudo ./scripts/upgrade.sh rollback
/opt/serverhub/current/venv/bin/python -m serverhub.ops.verify_install --url https://YOUR_CONTROLLER_ORIGIN --ca-file /PATH/TO/PUBLIC_CA --username dennis
```

This change adds no SQL migration (schema stays `0005_priority`). Rollback retains
DB data and additive columns. Newly configured publisher fields are unsupported by
older code; retain or restore the backed-up project configuration after review,
and do not run old conflicting identity/unit releases. Code rollback is not a DB
restore or generic trust-anchor downgrade. Before another signed update, use the
reviewed compatible checkout's `repair-install.sh` to establish its independent
code anchor. For data restore, follow [backup-recovery.md](backup-recovery.md): use a
new empty database and verified archive, never automatic deletion of a live database.
