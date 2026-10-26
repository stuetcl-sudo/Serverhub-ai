# PR14: one-command offline owner maintenance

From the reviewed checkout:

```sh
sudo bash scripts/release-pr14.sh
```

This is the explicit offline owner maintenance procedure permitted by
[the executable code anchor policy](upgrade.md#executable-code-anchor). It is
not an autonomous signed release. Its one interactive `RELEASE PR14` approval
authorizes only the pinned OAuth patch and the corresponding protected
trust/code-anchor transition. Ordinary `upgrade.sh verify/prepare` still rejects
changed Python. No signing key is generated, read, replaced or accepted by this
script; an independent release signature is mandatory for the normal signed
upgrade path, which this procedure does not invoke or weaken.

Review both scripts and their tests before running sudo. The shell wrapper
copies the Python helper to a root-private `/run` directory, verifies its
hardcoded SHA256, clears the caller environment and uses `python -I` from the
existing independent recovery runtime. It never imports application code from
the checkout or candidate for maintenance. The plan and helper digest are shown
before confirmation. There is no unattended `--yes` option or production test
backend. Prior blanket development permission does not suppress the requested
interactive owner approval.

## Exact release identity

| Item | Value |
| --- | --- |
| Release ID | `oauth-csrf-pr14-3e9a2f4` |
| Source commit | `3e9a2f4bc32d455a2cecffddd495494d8ed08078` |
| Required previous release | `repair-20261024T195431Z-60f67b` |
| Schema, unchanged | `0006_pause_clock` |
| Wheel SHA256 | `a96f24266030fd8a611ae6614de0e21faf5e484f04822704dc8fc92bc1b8a130` |
| Reviewed source archive SHA256 | `89b83d3871549bcedb6045ca31cc4aa93e43bcfa0e139daf6f617722851f7fe5` |
| Previous trust digest | `d8880cdfcfd97ecd6845627e0c7f52d9a0069ef364ddd6acbd40caa8d8c7b42c` |
| Candidate trust digest | `5846e2d5940f9fa73408311c438c1ee88a47579211eb8770e0be36e2633010a6` |

The other four artifact digests are pinned in `scripts/release_pr14.py` and
documented in `oauth-csrf-production-candidate.md`. The exact input directory is
`/home/serverhub/oauth-rc-evidence-20261025/unsigned-bundle/`, and the reviewed
source archive is its sibling `owner-reviewed-source-3e9a2f4.tar.gz`.
Inputs may originate in the owner's workspace, but only hash-verified bytes are
copied into protected state and consumed. Nothing is rebuilt or downloaded.

The protected baseline package must match its existing anchor exactly. The
candidate wheel must have precisely the same package inventory, and the only
changed package bytes must be the pinned `serverhub/main.py` and `serverhub/mcp.py`.
Frontend/migrations must match the pinned archives and installed baseline.
Locked dependency versions must match both installed and recovery runtimes.

## Preconditions and interaction

The existing namespaced installation, independent recovery runtime, existing
release watchdog, PostgreSQL 16 tools, root maintenance access, enrolled agent,
healthy model configuration and existing owner/operation permissions are required.
Unknown installations, unsafe file ownership, modified baselines, conflicting
release checkpoints, incompatible schema and altered artifacts stop safely.
No service identities, policies, grants, keys or credentials are repaired.

After the single release approval, sign in with the existing ServerHub owner
username/password when prompted. The password is hidden and never saved or
passed as a command-line argument. A temporary normal API session is revoked at
exit. If `/etc/serverhub/pr14-owner.token` already exists as a private root-owned
0600 file, its existing session is used and retained instead. No token file is
required for interactive use. If there are multiple enrolled hosts, select a
displayed host ID for the fixed `inventory.refresh` acceptance job. An optional
root-private `/etc/serverhub/pr14-host-id` can select it in advance.

The script uses only `https://ai.dennishub.dk`, verifies TLS, refuses redirects
and never accepts caller-provided proxy/environment overrides. The callback
`https://client.example/pr14-release-callback` is registered only for the temporary
test OAuth client; redirects are inspected, never followed or contacted.

## Backup, drill and activation

1. Reuse `BackupManager` to create a fresh transaction-consistent PostgreSQL
   dump and `/etc/serverhub` snapshot under `/var/backups/serverhub`, verify
   checksums, parse the dump and inspect the configuration archive.
2. Restore the actual dump into a new socket-only PostgreSQL cluster beneath
   `/var/lib/serverhub-pr14-restore`. The parent is root-owned 0755 and each
   generated child belongs to postgres with mode 0700; no TCP listener exists.
   Verify schema 0006, the audit hash chain, owner data and job/OAuth table counts.
   Stop and remove only this disposable cluster after the drill. No live
   database is created, dropped, downgraded or restored over.
3. Clone the sealed previous runtime into the new protected release, replace
   only the two approved application modules, relocate copied console-script
   interpreter paths, write the release manifest, seal and fsync the complete
   candidate tree. No pip, migrations, grants or broad repair installation runs.
4. Exercise the shared code/anchor recovery routine against private executable
   trees and anchors. Existing recovery service commands are recorded in this
   drill, not run against production. Tests separately exercise the actual
   journal/checksum recovery path under partial writes, expiry, reboot and
   failed healthchecks.
5. Save exact old/new trust and code anchors. The durable root-private journal
   binds previous/candidate paths, source/wheel hash, backup ID, all four anchor
   hashes, boot ID, watchdog helper digest and a 900-second acceptance deadline.
   Atomic writes fsync both data and containing directories.
6. Install a dedicated `serverhub-ai-pr14-owner-watchdog.service` and `.timer`
   without changing existing unit definitions or the recovery runtime. The
   enabled timer runs after boot and every 30 seconds. It retries failed
   rollback; a changed boot ID triggers recovery without waiting for a potentially
   stale wall clock. It imports only the existing independent recovery package.
7. Under the mutation lock, update only the two protected anchor files, switch
   the release with existing `ReleaseManager` primitives and restart AI API/worker,
   try-restarting AI broker/node. Existing active jobs retain the installed
   worker's persistent recovery/checkpoint/budget semantics; this is a service
   restart, not a claim that the queue has been drained. The script records
   job-state counts. No Control, database, Docker or proxy service is restarted.

## Acceptance and recovery

Before marking verified, check API health/schema, all four AI services, unchanged
unrelated service identities, public resource/PKCE discovery and unauthenticated
MCP challenge. Register/revoke a temporary OAuth client, approve/deny overlapping
flows in both orders, check callback/state, Origin denial, replay rejection and
invalid PKCE rejection. Exchange real tokens and check authenticated MCP
initialize/tools-list and forbidden scope access. Run the existing installed
verifier including a completed durable `inventory.refresh` job. Partial diagnostics
or collector gaps fail acceptance; permissions are never expanded to make it pass.

On any post-arm failure, restore the exact previous executable AND old code/trust
anchors. The independent watchdog performs the same recovery after parent death,
deadline expiry or reboot. Reverted is persisted only after service restart and
health succeed; otherwise the durable journal stays armed and recovery retries.
The watchdog and parent serialize mutations so an expired checkpoint cannot be
marked verified. It refuses an unrelated current release or tampered recovery
files. There is no automatic database restore or downgrade.

Successful reruns verify identity, package integrity, anchors and health and
return without another backup/install/job. A known reverted attempt is archived
in protected state and can be retried with a fresh backup. An interrupted armed
attempt is first rolled back and stops for inspection. Unknown/partially prepared
candidate trees are retained and rejected rather than deleted or silently adopted.
The dedicated watchdog remains enabled but does nothing for a verified/reverted
journal; old executable releases, backups and recovery evidence are retained.

## Reports and test scope

`/var/lib/serverhub-release/pr14/report.json` and `journal.json` are root-private.
They contain identities, hashes, phases, backup/check counts, durable job receipts
and acceptance results. Passwords, bearer/refresh tokens, consent codes, session
cookies, URLs containing credentials, prompts and raw HTTP/database/subprocess
errors are never serialized. The report is checkpointed before each phase.
Configuration backups necessarily contain protected configuration; they remain
under the existing private backup boundary, not in the public report.

Run the isolated tests with:

```sh
python -m pytest tests/test_pr14_release.py
bash -n scripts/release-pr14.sh
```

Tests cover transaction success and every phase failure, real private-file code
and anchor rollback, reboot/expiry, failed rollback health retry, tampering,
symlinks/hardlinks, fsync boundaries, secret-free failure reports, actual isolated
OAuth/MCP, owner login/logout and actual PostgreSQL dump/restore including bad
schema/audit/archive cases. Systemd production writes are substituted with test
recorders. This is not a claim that the production sudo command or real service
restart has run. Root ownership/systemd behavior also needs the repository's
disposable native runner checks; never run its destructive fresh-install scripts
on the production host. No production invocation is part of development.
