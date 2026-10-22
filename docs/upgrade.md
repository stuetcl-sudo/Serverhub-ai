# Controlled native upgrades

The independent maintenance runtime is installed at `/opt/serverhub/recovery/venv` and is not switched during normal upgrades. Recovery timers use it instead of candidate code.

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
  /opt/serverhub/recovery/venv/bin/python -m serverhub.ops.release activate \
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
