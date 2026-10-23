# Delegated native administration and Docker recovery

These adapters extend the existing API/worker/node/root-broker architecture. The
AI runtime never gets sudo, a root shell or the Docker socket. Root enrollment
selects immutable named capabilities; an authenticated owner separately grants
their use for one identity, host, project, environment and expiry. A maintenance
grant covers all matching steps until it expires; no per-step prompt is required.

## Enroll capabilities once

Use the Ubuntu installation workflow in [installation.md](installation.md),
including the installer option --ai-identity for the dedicated serverhub-ai
worker. Review root-owned plan files and SHA-256 hashes outside AI workspaces.
An administrator enrolls named plans locally:

    sudo /opt/serverhub/current/venv/bin/python -m serverhub.node.enroll \
      --plans /etc/serverhub/approved-plans.yaml
    sudo /opt/serverhub/current/venv/bin/python -m serverhub.node.enroll \
      --plans /etc/serverhub/approved-plans.yaml --apply

The first command prints a plan. --apply explicitly enables administration,
generates missing backup keys, writes a broker sandbox drop-in and restarts that
broker. Installing reviewed .deb files executes their root maintainer scripts:
this is a powerful owner-approved trust boundary. Never enroll unreviewed
packages or artifacts supplied by a model. SSH, authentication, controller,
systemd control files and audit/recovery directories remain protected.

Example approved-plans.yaml (replace paths and hashes, then root:root 0600):

    docker_backup_plans:
      household:
        containers: [database, application]
        destination: /mnt/storage/ServerHub-Backups
        key_file: /etc/serverhub/docker-backup.key
        required_mount: /mnt/storage
        allowed_bind_roots: [/srv/household]
        include_images: true
        allow_isolated_restore: true
        # allow_ntfs: true       # explicit opt-in after mount validation
        # retention_keep: 14     # explicit deletion authorization; absent means retain
    package_plans:
      app-upgrade:
        stateless: true
        debs:
          - {path: /srv/reviewed/app_2.deb, sha256: REPLACE_WITH_64_HEX}
        previous_debs:
          - {path: /srv/reviewed/app_1.deb, sha256: REPLACE_WITH_64_HEX}
        verify_file:
          path: /usr/share/example/version
          sha256: REPLACE_WITH_64_HEX
    configuration_plans:
      app-config:
        path: /etc/example.conf
        candidate: {path: /srv/reviewed/example.conf, sha256: REPLACE_WITH_64_HEX}
        service: example.service

Every ancestor must be root-owned without group/world write. The destination must
already exist on the intended mounted filesystem; inspect findmnt and capacity
before enrollment. required_mount is checked at runtime; otherwise a backup
resolving to the OS filesystem is rejected unless root explicitly sets
allow_system_disk: true. Unmounted storage cannot silently redirect these
backups onto the OS disk. Do not use the AI worker's state directory for keys or backup storage.
The worker cannot delete protected archives.

In Approval policies, choose Maintenance, identity, host, expiry and exact named
backup/package/configuration/Compose targets. Service/container restart targets
are separate lists. The Backups page queues these structured operations and
shows job outcomes and root transaction history. The authenticated MCP tools
docker_backup and host_maintenance use the same queue and authorization checks.

## Docker consistency and verification

docker.backup.create discovers bind mounts and named volumes from Docker, includes
container configuration, writable container filesystems, Compose label paths and
adjacent .env files, and optionally exports images. Bind roots are owner-enrolled;
protected host/control-plane paths are rejected. Shared writable mounts with
unselected running containers are rejected.

The initial implementation deliberately uses planned downtime for consistency.
Containers stop in reverse declared dependency order; known database engines
must exit cleanly, and restart occurs in declared order with healthchecks. A root
timer can restart the original containers if the broker dies mid-backup.
Application writers outside the selected containers and database tablespaces
outside discovered mounts require an application-specific adapter. This is not
an online database snapshot implementation.

Capacity is checked for root-protected temporary plaintext and encrypted
destination space. AES-256-GCM authenticates each artifact; the manifest has
SHA-256 checksums and an HMAC. Keep an independent protected copy of the generated
32-byte encryption key: losing it makes restoration impossible. Never commit it.
Ciphertext protects confidentiality on NTFS even when POSIX permission semantics
are unavailable. NTFS mounting/deletion protection is still an administrator
responsibility; allow_ntfs is explicit and does not claim protection against root
or someone removing the physical disk.

Operations:

- docker.backup.list: list authenticated archives for the enrolled target.
- docker.backup.verify: authenticate manifest, hashes and encrypted artifacts.
- docker.restore.plan: validate an archive and describe isolated recovery.
- docker.restore.apply: explicitly enrolled isolated restore into fresh volumes,
  a private internal Docker network, no host ports, dropped capabilities and
  no-new-privileges. Original containers/volumes are not overwritten.
- docker.backup.create: create and verify a new archive; retain all previous
  archives unless the root plan explicitly sets retention_keep.

Use target and returned backup_id only; a model cannot choose archive paths.
Inspect the restored container IDs, query the restored database, compare expected
application data, and run application acceptance checks. Process-only containers
without a healthcheck remain partial; do not equate a running PID with recovery.
Production cutover is a separately reviewed operation. The safe restore adapter
does not clone privileged containers or reproduce host networking/capabilities.
Restores preserve an explicit Config.User or a mapped nonroot runtime UID:GID
observed before shutdown. Root may enroll restore_users by exact container name
when an application needs a particular nonroot startup identity. Docker 26+ is
required for isolated directory mount subpaths.

Scheduled backups use the existing schedules API/UI, a job of kind operation and
spec {operation: docker.backup.create, arguments: {target: household}}. Scheduling
does not extend a permission's expiry. Check failed/blocked scheduled jobs and
renew only the intended grant.

## Package, configuration and Compose rollback

package.plan checks pinned .deb metadata, exact previous installed versions and
apt simulation. Only the approved local artifacts are installed with dpkg;
APT is used for simulation only, with no repository downloads. package.apply snapshots inverse packages, requires the declared
stateless contract, installs only enrolled artifacts and checks versions plus
an optional fixed file hash. Removal of unrelated packages and critical
controller/OS/database packages is denied. On failed acceptance it restores the
previous artifacts; this is not a rollback mechanism for database schema/data
migrations or arbitrary package maintainer side effects.

configuration.plan/apply accept only an exact enrolled file and immutable
candidate. The root journal saves previous bytes, ownership and mode. Optional
noncritical service restart and exact candidate verification gate commitment;
failure restores the file and service. Network/SSH/authentication/control-plane
paths cannot be modified through this adapter.

compose_updates entries contain stateless: true, project and previous/candidate
contracts {path: ROOT_DIRECTORY, compose_file: FILE, sha256: HASH}. Both manifests
must use pinned image digests, nonroot users, a read-only rootfs, cap_drop ALL,
no-new-privileges and real healthchecks. Only loopback published TCP ports and
enrolled declarative features are accepted. In-place automatic updates reject
data volumes and service additions/removals. A failed candidate restores the
previous Compose manifest and waits for its healthchecks. Stateful application
updates require separately tested migration and data recovery contracts.

Root transaction journals are in /var/lib/serverhub-broker/operations, and
serverhub-ai-operation-watchdog.timer invokes an independently installed stdlib-only
recovery executable. Do not disable that timer. A journal already reverted by
recovery cannot be rearmed/committed by a late broker heartbeat.

## Autonomous development and staging

Root registers projects in /etc/serverhub/projects.yaml: HTTPS/local repository,
base ref, immutable dependency/build/test argv, external root-protected acceptance
checks, artifact paths and resource limits. Commands run in bubblewrap with no
host credentials, Docker socket or control-plane files. Dependency networking is
available only when both the project contract and expiring grant allow it;
build/test/acceptance phases have no network. No unsandboxed fallback exists.

The Development page accepts a natural-language task or an explicit patch.
Autonomous jobs plan, inspect bounded text files, edit/commit an isolated branch,
run configured checks, observe failures and attempt bounded corrections.
Repeated checks on the same failing commit are suppressed after two failures;
source corrections are limited to five, with model/time/token budgets. Three rounds
without meaningful source, inspection, plan or check progress end as partial with
a stronger-model recommendation. The model first sees inspection tools; source
editing and checks are exposed after inspection, and finish after verified checks.
A literal Python-constant editor avoids fragile quote matching. Request history
is compacted by complete assistant/tool groups while full receipts remain durable.
Natural-language success claims never bypass checks. Checkpoints retain tool
receipts, source commits, plan and command outcomes.

An owner grants the Development profile once for the exact project/host, expiry
and optional dependency-network permission. Production deployment is excluded.
Infrastructure planners can delegate a development subtask, release their host
execution slot, resume its persisted receipt, and include child usage in the
parent task budget. Cancellation propagates to descendants. Children of failed, completed or expired
parents are cancelled before execution and during supervision; parent/child budgets
and verification receipts remain scoped to the initiating identity.

For runtime staging, root enrolls staging_projects with the same project name:

    staging_projects:
      jarvis:
        argv: [/usr/bin/python3, -m, uvicorn, app.main_auth:app,
               --host, 127.0.0.1, --port, "28098"]
        port: 28098
        health_path: /api/health
        health_contains: "0.23.0"
        memory_mb: 1024
        acceptance_script:
          path: /srv/checks/jarvis-stage.py
          sha256: REPLACE_WITH_64_HEX
        environment: {SAFE_MODE: "true", DRY_RUN: "true", WORKER_ENABLED: "false"}

The candidate must contain its Python dependencies under runtime and must pass
independent checks. The broker verifies its SHA-256, rejects links/special files,
makes a root-owned release, runs the pinned owner acceptance script as a separate
nonprivileged checker, and launches a systemd DynamicUser with private data, a project-specific read-only source group,
private network, no capabilities and explicit limits. PID 1 starts both the pinned acceptance checker and the fixed HTTP probe as
separate nonprivileged, capability-free transient units. The probe joins only
the candidate's private network namespace through NetworkNamespacePath; the
broker does not switch UID or grant namespace capabilities to model output. The job succeeds only
after actual HTTP acceptance. Failed staging stops the new unit, relaunches the
previous unit and checks its previous HTTP contract; an independent timer can
recover abandoned attempts.

Staging has no public listener or authenticated preview proxy. Inspect it locally
with the root-controlled network namespace checker; exposing a staging preview
requires a separately reviewed authenticated gateway. Staging state is isolated;
it does not migrate or overwrite production data. Per-release data is fresh.

The guarded scripts/test-jarvis-pilot.py uses real public Jarvis source at a
pinned commit and a deliberately injected local version regression. Actual qwen
must inspect/edit it, install dependencies, run upstream dashboard tests plus an
external version check, stage it, and demonstrate a failed next-stage rollback.
This tests the autonomous workflow; it does not claim to complete every open
feature in Jarvis OS.

## Audit and acceptance boundaries

Ubuntu 24.04 user-namespace restrictions are handled by an unattached,
root-installed serverhub-build AppArmor label used explicitly by aa-exec for
Bubblewrap. On Ubuntu this explicit label permits creation of the nested user
namespace; the worker has no host capabilities. ProtectKernelTunables is disabled
on the worker unit because its locked parent /proc/sys mount prevents bubblewrap
from mounting a fresh PID-private /proc. The unprivileged worker still cannot
write host sysctls; project processes receive a fresh isolated /proc, never a
bind mount exposing worker credentials. It permits namespace setup, retains the filesystem/network sandbox
and dropped capabilities, and never disables the global kernel restriction.
A changed existing profile requires explicit local review. Routine package and
configuration adapters cannot replace AppArmor, Bubblewrap, Python, the package
manager, ServerHub state/audit files or other compiled protected controls.

The root broker fsyncs an append-oriented hash chain independently of the AI
worker. Records include job/operator/model correlation and effective OS identity.
Database runtime roles cannot rewrite audit history. A malicious root operator
can rewrite a local chain; export/checkpoint heads to independently administered
append-only storage before treating this as off-host tamper-resistant retention.
No remote retention endpoint or WORM credentials have been enrolled.

Read the actual CI evidence and production acceptance checklist before connecting
servers. An implemented adapter is not a substitute for an application-specific
restore drill, vendor-supported upgrade plan or validation of the intended host.
