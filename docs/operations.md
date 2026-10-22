# Native operations

## Service roles and paths

| Component | Identity | Writable data | Protected capabilities |
|---|---|---|---|
| Controller API | serverhub-api | /var/lib/serverhub-api, explicitly granted DB tables | Authenticated owner policy/user management |
| Job worker | serverhub-worker | /var/lib/serverhub-worker, job/observational DB tables | No root/sudo/Docker socket; policy SELECT only |
| Node agent | serverhub-node | /var/lib/serverhub-node | Individual HTTPS identity; peer-authenticated broker access |
| Local broker | root, node socket group | /run/serverhub-broker, protected broker audit | Compiled operation allowlist intersected with root-owned exact targets |
| Backup service | root | /var/backups/serverhub, curated status file | Database/config checkpoints; AI cannot delete archives |
| Recovery timers | root | protected journals and root-approved targets | Independent configuration/release rollback |
| Migration/bootstrap | serverhub-migrate, offline use | DB schema owned by this identity | Never supplied to normal worker/API |

## Read operational state

```sh
sudo systemctl status serverhub-api serverhub-worker serverhub-node
sudo journalctl -u serverhub-worker -n 100 --no-pager
sudo systemctl list-timers 'serverhub-*'
sudo /opt/serverhub/current/venv/bin/serverhub health
```

Node logs omit URLs, tokens and request bodies. Broker events are in
`/var/log/serverhub-broker/events.jsonl` root-only and fsynced before and after a
permitted action. A missing broker audit prevents new actions. Controller job/audit
records are available under authenticated API routes with role/host checks.

An offline node retains its command journal. Controller inventory remains its last
observation and must be shown as stale. Command delivery is bounded by expiry and
reauthorizes the original job owner's current role/policies. A pending repair does
not grant a permanent capability. Local journals prevent a completed command from
being repeated after a lost response. Interrupted mutations whose outcome is
uncertain are rejected as `in_doubt`; reconcile actual service state before issuing
a new, explicitly authorized job.

## Inventory coverage

Unprivileged discovery collects OS/kernel, packages, CPU/RAM/disk, available sensor
readings, interfaces/addresses/routes/DNS, listeners and systemd state. Each failing
collector appears in `errors`. Docker/firewall data requires the separately enabled
broker. The build sandbox may deny netlink and systemd, so unavailable collectors
are recorded rather than substituted. Docker output excludes environment values,
raw commands and arbitrary labels. Reverse proxy recognition from a service name is
an inference, not verified proxy routing configuration.

Security analysis reports evidence and confidence separately. A listener bound to
0.0.0.0/:: is not proof of LAN or Internet access. Trivy uses an installed supported
binary and scanner database; images must be owner-allowlisted. Lynis is opt-in and
returns audit warnings/suggestions. The platform does not install scanners by
silently running remote scripts, claim complete CVE coverage, or remove unknown
services automatically.

## Controlled repairs

Use narrow policies (subject + host/project + operation + target constraints +
expiry). Add root broker targets separately. Check health after a restart and keep
critical services out of repair allowlists until their dependent behavior is
rehearsed. The current broker implements systemd restart/status, immutable-image
container restart, pinned initial Compose deployment with healthchecks, diagnostic
TCP/DNS tests against named targets, Trivy and Lynis scans. It does not implement
arbitrary command execution, Docker exec, host networking edits, SSH/sudo changes,
existing Compose upgrades, image pruning, or destructive volume/database actions.

For service degradation, record inventory baselines and investigate root cause;
restarting a process is not proof that its application/data is healthy. Use
application-specific integration checks where configured.

## Emergency and recovery

Owner emergency stop rejects subsequent mutating operations at the controller.
It cannot undo a root broker operation already in progress; local operation timeouts
and independent recovery remain relevant. If controller trust is in question,
stop `serverhub-worker.service` locally. Timers, protected backups and root operator
access remain independent. Use the backup/recovery guide before a release change.
