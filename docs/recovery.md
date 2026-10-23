# Backup and recovery

Protected backups are created by a root systemd service, not by the AI worker.
`/var/backups/serverhub` is root-owned mode0700; worker/node/API services cannot
read or delete archives. Daily timer runs around03:15 with a random delay and
catches up after downtime. A curated root-written status file is exposed at
`/var/lib/serverhub-status/backups.json` for `/api/recovery/status`.

Backups contain a PostgreSQL custom-format dump, optional configuration tar,
SHA256 manifest, archive parse validation, and no secret-bearing process arguments.
Configuration archives do include secrets; keep destination private and replicate
through a separately administered encrypted backup mechanism. This release does
not provide immutable off-site storage or automatic encryption/key custody.

Run root maintenance commands with the protected database URL loaded from the
service environment (do not paste credentials into command lines):

```sh
sudo systemctl start serverhub-ai-backup.service
sudo ./scripts/backup.sh list
sudo ./scripts/backup.sh verify --id BACKUP_ID
```

To restore-test, load `/etc/serverhub/recovery.env` in a root shell and export
`SERVERHUB_DATABASE_URL`, then run:

```sh
/opt/serverhub/current/venv/bin/python -m serverhub.ops.backup \
  restore-drill --id BACKUP_ID
```

A drill creates a random new `serverhub_verify_*` database, restores the archive,
checks restored public table count, and drops only that generated database. The
maintenance role needs CREATEDB for this drill; the default migration identity
has no CREATEDB, so use a separately authorized local PostgreSQL maintenance
identity. Do not grant CREATEDB to API/worker. A parsed archive or checksum alone
is **not** a successful restore drill.

Actual restore requires an explicitly selected **empty database** and matching
`--confirm-database NAME`. The tool does not drop or clean an existing database.
Stop API/worker, restore into the empty recovery database, verify, reapply grants,
then deliberately change protected service configuration to use it. Configuration
archives are not automatically extracted over `/etc`; inspect members and restore
specific files as root to avoid unintended overwrite.

## Independent configuration rollback

The broker exposes no firewall, SSH, credential, or route mutation. Root operators
can arm the independent watchdog around a separately approved manual change:

```sh
sudo /opt/serverhub/current/venv/bin/python -m serverhub.node.watchdog \
  arm --path /etc/APP/CONFIG --timeout 90 --service APP.service
```

The timer must already be active. `arm` returns an ID and one-time commit token;
keep the token private. Verify current access and dependent service behavior from
an independent connection before the change. If verification succeeds before the
deadline, call `commit --id ID --token TOKEN`; otherwise the root timer restores
the exact checksummed bytes/permissions and restarts the specified service. The
journal is protected from the worker. This guard is implemented and file-level
recovery is tested; automatic network lockout prevention across actual routers,
firewalls and remote SSH is not verified or enabled.

## Uninstall

```sh
sudo ./scripts/uninstall.sh --plan
sudo ./scripts/uninstall.sh --apply
```

Uninstall disables/removes only known ServerHub units and executable releases.
It retains the stable `/opt/serverhub/recovery` recovery runtime, PostgreSQL data/roles, service accounts, node identity/journal,
configuration, backups and rollback evidence. Remove retained sensitive data only
under a separately reviewed disposal procedure.

See [Control coexistence and legacy unit migration](control-coexistence.md) before installing alongside ServerHub Control or upgrading generic `serverhub-*.service` AI OS units. New AI OS services use `serverhub-ai-*`; never stop or replace Control units.
