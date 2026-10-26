# Controlled native upgrades

After a successful upgrade, run [installed verification](installed-verification.md).
It checks the running service through the authenticated API, preserves warning
and collection-gap evidence, and can exercise a fixed read-only persistent job.

## Stability/autonomy overhaul and legacy installations

For a namespaced installation with `/var/lib/serverhub-install/ownership.json`, use the explicit local-root workflow below after reviewing protected-code changes. Legacy generic-unit installations must first use [the verified namespace migration](control-coexistence.md); unclaimed/partial installations without the required legacy journal need manual review and are not silently adopted. This is not callable by an AI worker. It intentionally accepts reviewed trust-boundary changes; signing a normal autonomous release must never silently replace its trust anchors.

```sh
# Check out the reviewed release/production-readiness branch/ref as your normal user.
./scripts/install-ubuntu.sh --build-only
sudo ./scripts/repair-install.sh
```

This preserves database passwords, sessions, enrolled identities and operator configuration. An invalid/obsolete model fallback remains root-only and does not block the upgrade; configure a validated database route through Setup afterwards. Only a schema-validated non-secret fallback is made readable to service users. It creates and checks a protected PostgreSQL/configuration backup, prepares a new native runtime, stops API/worker during migration, applies additive migrations through `0006_pause_clock`, reapplies explicit grants, updates reviewed systemd units and code anchors, switches the release, and checks API/worker/frontend health. The reviewed upgrade also updates the separate `recovery-ai` maintenance runtime; normal signed releases do not change it.

An independent 300-second release watchdog is armed before service interruption. A normal failure restores the previous release and saved configuration/units, restarts services, and retains backups. An abruptly killed repair can be reverted by the watchdog to the previous code; its configuration snapshot remains in the protected backup for administrator restoration. No automatic destructive database downgrade occurs. The old pre-overhaul health endpoint expects revision 0003 exactly, so it may report a migration mismatch after code rollback to 0003 while additive schema 0004/0005 remains. Complete the reviewed upgrade or perform a separately reviewed recovery; do not edit `alembic_version` to hide this mismatch.

Migration 0004 adds `model_routes`, `worker_heartbeats` and `policies.environment` (existing grants retain `any` environment). The worker may read model routes and publish heartbeat rows, but cannot change provider endpoints, policies, users, audit history or backup state. No policy grants or model endpoints are silently created. Configure these in Setup after upgrading.

A failed first install created by the new journaled installer should be resumed with the original installation command instead. A legacy partial installation without a usable current/recovery runtime needs operator inspection and backup before adoption; the repair command does not invent or reset its missing credentials.

## Normal signed releases


The independent maintenance runtime is installed at `/opt/serverhub/recovery-ai/venv` and is not switched during normal upgrades. Recovery timers use it instead of candidate code.

The worker cannot modify installed code, systemd definitions, policy/audit tables,
backup archives, recovery journals, trust digests, or signing keys. Native release
activation is an independent root maintenance operation.

## Bundle format and verification

An upgrade directory contains `release.json`, base64 `release.sig`, and exactly the
artifacts listed by SHA256 in the manifest. Required artifacts are:

- `application.whl` (a Python wheel, renamed only in the transfer bundle)
- `requirements.lock` (hashed locked production dependencies)
- `web.tar.gz` (compiled frontend, `index.html` at archive root)
- `alembic.ini`
- `migrations.tar.gz` (migration files at archive root)

`release.json` uses format1, a unique safe `release_id`, `schema_revision`,
`trust_boundary_digest`, `files`, and `validation: {"passed": true}`. The independent
release process must run all checks before signing. `release.sig` is an Ed25519
signature of canonical JSON (sorted keys, compact separators), base64 encoded.
The private key stays outside the platform and outside the repository; there is no
built-in key and the AI must never receive it. Install only the owner's public key
at `/etc/serverhub/trusted-release-key.pem` mode0644 root-owned.

Trust-boundary digest includes authorization, policy, audit, worker execution,
node dispatch/broker, recovery and installer code, DB grants, and service unit
files. A bundle changing this digest is rejected; review/install such a trust
change through an explicit offline owner procedure, never by updating the stored
digest automatically. Independent signing is still necessary: a digest alone is
not a substitute for source review and tests.

Copy a verified bundle into a root-owned directory with no group/world-writable
ancestors, then:

```sh
sudo ./scripts/upgrade.sh verify --bundle /opt/serverhub-upgrade/bundle
sudo ./scripts/upgrade.sh prepare --bundle /opt/serverhub-upgrade/bundle
sudo sh -c '. /etc/serverhub/recovery.env; export SERVERHUB_DATABASE_URL; \
  /opt/serverhub/recovery-ai/venv/bin/python -m serverhub.ops.release activate \
  --release OWNER_VERIFIED_RELEASE_ID'
```

Activation refuses concurrent unverified releases, creates a protected PostgreSQL
and configuration backup, writes an independent rollback journal before switching
the current symlink, restarts API/worker, and checks the actual health endpoint. A
failed activation reverts the symlink. The independent release-watchdog timer also
reverts an armed release whose deadline expires if the initiating process died.

## Database migrations

Automatic activation requires the **same schema revision** as the installed
release. Schema-changing upgrades fail closed because automatic code rollback does
not safely roll back arbitrary database migrations.

For a schema change: stop API and worker; create and verify a backup; restore it in
a disposable database; review migration SQL; run the new migration as the offline
migration identity; apply explicit table grants; start the candidate; verify jobs,
login, agents and health. Only then record the new installed revision. Recovery
uses an empty database restored from the protected backup plus the previous code,
not a destructive automatic downgrade of the live database.

```sh
sudo ./scripts/upgrade.sh rollback
```

This restores the previous executable release for schema-compatible activation.
It does not roll back application data or migrations. Keep the original archive
and previous release until a restore drill passes.

## Executable code anchor

For the exact PR14 OAuth candidate only, the reviewed
[single-command offline owner procedure](pr14-owner-release.md) provides
interactive root approval, fixed artifact hashes, isolated production-backup
restore, and independent rollback of both executable code and protected anchors.
It does not change the normal signed-release verifier or permit autonomous
Python updates. Read that procedure before running `sudo bash scripts/release-pr14.sh`.

Initial installation also stores `/etc/serverhub/trusted-code-hashes.json`. The independent verifier compares actual wheel module bytes and its exact package file set with this root-owned anchor, rejects startup `.pth`/unexpected installation payloads and changed CLI entry points, and checks the signed artifact hashes. Repeating an old trust digest in a new signed manifest cannot conceal changed policy code. Since Python modules share an interpreter, the whole Python package is anchored. Automatic upgrades are therefore limited to unchanged Python code (for example frontend or dependency artifacts); Python-code improvements require explicit offline owner review and maintenance of the stable recovery runtime/anchor. A fully autonomous self-code-update approval service is not implemented.

## Build a signed bundle

Build the wheel and frontend, run the independent checks, then use an external
owner-controlled mode0600 Ed25519 PEM key:

```sh
python scripts/build-release.py --release-id OWNER_SELECTED_RELEASE_ID \
  --output /absolute/path/new-bundle --validation /absolute/path/verification.json \
  --signing-key /external/private/owner-release.pem
```

The validation JSON must report `state: passed` and contain check evidence. The
owner must review that evidence and the source; possession of a JSON report is
not itself independent approval. The tool packages deterministic web/migration
archives and signs the manifest. No key is generated or stored in the repository.

See [Control coexistence and legacy unit migration](control-coexistence.md) before installing alongside ServerHub Control or upgrading generic `serverhub-*.service` AI OS units. New AI OS services use `serverhub-ai-*`; never stop or replace Control units.


### Issue #7 identity namespace boundary

Releases through `7da8bea` used `serverhub-worker` and related Linux identities,
even with AI-prefixed systemd units. Do **not** rerun apply/repair to adopt those
identities. Follow [the explicit migration and rollback procedure](control-coexistence.md).
The new ownership claim is namespace 3; old namespace-2 claims are rejected by
ordinary upgrade. Database names, PostgreSQL roles and passwords are preserved.
The standalone migration timer restores the old claim, config, units and original
homes after an interrupted/unverified conversion. After verified migration,
select only identity-compatible releases for ordinary code rollback; do not
restore generic Control-conflicting services or legacy identity defaults.

### Development/MCP follow-up

The exact legacy empty project mapping is normalized to an array during backed-up
repair. Malformed nonempty configuration fails safely instead of being replaced.
No new SQL revision is needed. Existing host-specific development grants are not
broadened: review/regrant a controller-only project profile, adding staging,
network or draft PR publication only when wanted. See [the exact reviewed upgrade
and rollback procedure](development-mcp.md#reviewed-production-procedure--not-executed).

### Autopilot reliability

The autopilot update adds migration `0006_pause_clock` and model/job budget defaults.
See [pause-clock semantics, security limits and reviewed recovery](autopilot-reliability.md).
Automatic activation across schema revisions remains prohibited.
