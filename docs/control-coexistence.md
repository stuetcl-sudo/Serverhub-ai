# Installing AI OS alongside ServerHub Control

This change addresses the actual `serverhub-worker.service` **and**
`serverhub-broker.service` collisions. No aliases from old names are installed.
Existing Control MCP, OAuth, Docker Gateway, broker and worker are not upgraded,
reconfigured, stopped or restarted by this workflow. The physical production host
has not been accessed or changed during development.

## Resource boundaries

| Resource | AI OS | Existing Control |
| --- | --- | --- |
| API / worker | `serverhub-ai-api.service`, `serverhub-ai-worker.service` | Existing names retained |
| Broker / node | `serverhub-ai-broker.service`, `serverhub-ai-node.service` | `serverhub-broker.service` unchanged |
| Recovery | `serverhub-ai-recovery.*`, `serverhub-ai-operation-watchdog.*`, `serverhub-ai-release-watchdog.*` | Existing timers unchanged |
| Backup | `serverhub-ai-backup.service`, `serverhub-ai-backup.timer` | Existing backups unchanged |
| Broker socket | `/run/serverhub-ai-broker/control.sock` | Existing socket unchanged |
| Executables | `/opt/serverhub` | `/opt/serverhub-control` untouched |
| Independent recovery | `/opt/serverhub/recovery-ai` | Legacy AI `/opt/serverhub/recovery` retained during migration |
| Configuration | `/etc/serverhub` | Existing Control configuration untouched |
| Database | Existing AI OS `serverhub` and `serverhub_*` PostgreSQL roles | Existing database/roles never adopted |
| Accounts | Existing AI OS `serverhub-api`, `serverhub-worker`, `serverhub-node`, `serverhub-migrate`, `serverhub-staging`; optional `serverhub-ai` worker | Never adopt a pre-existing unclaimed identity |
| Access | Loopback TCP 9080, authenticated API; documented TLS access | MCP / OAuth / Docker Gateway ports unchanged |

State, audit records, configuration, database and service identities retain their
existing AI OS names to preserve credentials, authorization and recovery history.
The installation **refuses** shared identities or occupied reserved paths rather
than reassigning ownership. Thus an independently installed Control using any of
those same identities/paths is an explicit blocker requiring a reviewed resource
migration; changing service names alone cannot safely resolve such a collision.

## Fresh Ubuntu 24.04 installation next to Control

Run only after reviewing this PR and obtaining a checkout at its tested commit:

```bash
git checkout release/production-readiness
sudo env PYTHONPATH="$PWD/src" python3.12 -m serverhub.ops.installer --source "$PWD" --preflight
./scripts/install-ubuntu.sh --public-url https://YOUR-CONTROLLER --ai-identity
```

Preflight runs before package installation in the normal installation workflow
and again inside the root installer. It inspects destination units (including
loaded vendor/transient units, aliases and drop-ins), reserved paths and symlinks,
NSS users/groups, TCP 9080 and existing PostgreSQL objects. A stopped/uninspectable
existing PostgreSQL cluster blocks installation; have its administrator inspect
and start it before rerunning. Preflight never starts it or deletes objects. Reserved path
ancestors must be root-owned and not group/world writable; an unsafe shared
ancestor is reported without changing global host permissions. The disposable
GitHub image normalizes its runner-owned `/opt` and writable `/var/log` explicitly
as test preparation, outside the production installer.
`--build-only` only builds and does not claim or migrate an installed namespace.

A clean preflight creates a root-only ownership claim immediately before the
first install phase. Resume uses the same claim and installer journal. An
unclaimed pre-existing path/account/group/database is never silently reused.
Do not delete ownership or installation journals to force a retry. Review the
reported resource and resolve its ownership first. Configuration and reserved
unit drop-ins are checked again during upgrades and uninstall.

After installation, use the existing authenticated setup/installed-verification
workflow. The owner's VM was separately upgraded and checked by the owner:
**12 passed, 2 partial, 0 failed**; the partial checks concern missing approval
policies and host enrollment. Those are setup steps, not permission to bypass
policy checks.

## Migrate an existing legacy AI OS installation

This is a local-root, maintenance-window operation. Back up and verify the AI OS
database/configuration first; keep a root console available. It is **not** a
migration of ServerHub Control. Do not run it against a host that has only Control.

```bash
./scripts/install-ubuntu.sh --build-only
sudo env PYTHONPATH="$PWD/src" .build-venv/bin/python -m serverhub.ops.migrate_units --source "$PWD" --plan
sudo env PYTHONPATH="$PWD/src" .build-venv/bin/python -m serverhub.ops.migrate_units --source "$PWD" --apply --repair-legacy-permissions
```

The plan verifies the completed legacy installer journal, independent root-owned
code/trust anchors against every installed AI OS module, current release identity,
and every old unit's exact expected content, and the known optional worker
identity and root-enrolled broker administration drop-ins. It also checks that
loaded systemd fragments match the reviewed files without a pending daemon reload. A foreign or customized legacy worker/broker, mixed Control/AI
installation, occupied new namespace or pending operation **aborts before any
service change**. No generic `serverhub-*` snapshot/stop operation is used.
Customized/older unit layouts require manual review; do not replace a Control
unit to make the migration pass.

Older installers could preserve group/world write bits in executable trees and
write `installed.json` as 0666. The release record is **not** used as a trust
anchor: its identity/schema/digest must match the independently protected code
anchor and actual module hashes. A previously repaired host may have a newer
root trust anchor than its initial install journal; that current protected anchor
is authoritative. Any code hash, file set, owner or symlink mismatch blocks adoption.

`--repair-legacy-permissions` is explicit local-root authorization to seal the
verified AI OS executable/recovery trees, preserving source bytes and executable
bits while removing group/world writes and stale bytecode. It is never an AI/MCP
tool and never changes Control paths. Without this flag, writable anchored runtime
files cause refusal before stopping services. This is permission repair for a
reviewed host, not forensic recovery of a potentially compromised machine; a hash
mismatch requires a separate trusted restore. Fresh install, repair and signed
release preparation now seal new runtimes before exposing them to service users.

Before stopping proven AI OS units, migration writes a root-only file/config/unit
checkpoint and arms a standalone systemd rollback timer that also runs after boot.
It changes only those proven units and AI node/broker socket configuration, then
runs the reviewed backup/migration/upgrade/health workflow. Credentials, database,
accounts, audit and workload data stay in place. The previous independent recovery
runtime remains intact. New recovery code is installed separately in `recovery-ai`.

On failure it restores the old current-release link, exact saved configuration,
unit contents/ownership/modes and enabled/active states. An interrupted process is
recovered after the 30-minute migration deadline by the independent timer. To
recover immediately while a journal is still armed:

```bash
sudo env PYTHONPATH="$PWD/src" .build-venv/bin/python -m serverhub.ops.migrate_units --rollback
```

This rollback applies to an **armed, unverified namespace migration**, not a
completed migration. The protected `unit-migration.json` contains configuration
secrets; never paste it into issues. A successful conversion is retained across
subsequent code rollbacks: do not reinstall old generic unit files. Normal reviewed
upgrades use `sudo ./scripts/repair-install.sh`; schema-compatible release rollback
uses `sudo ./scripts/upgrade.sh rollback`. Very old code with hardcoded old socket
paths must be reviewed before selecting it as a rollback target.

## Verification and limits

CI has separate disposable Ubuntu 24.04 drills for:

* Active harmless Control-name services, real loopback gateways, identity/file
  hashes, unchanged MainPID and start timestamps across install, resume, upgrade,
  failed-health rollback, host operations and staging tests.
* Rejection of real service/path/user/group/listening-port conflicts before any
  installer account/path/unit creation.
* Installation of exact legacy commit `1905abc`, deliberate namespace health
  failure and rollback, credential preservation, then successful migration retry.

These fixtures are not the owner's actual Control application. Observed CI results
are recorded in the PR; physical-host compatibility still requires its read-only
preflight and operator acceptance. No physical server installation or auto-merge
is part of this change.
