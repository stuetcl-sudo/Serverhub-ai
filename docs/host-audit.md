# Persistent read-only host audit

This increment implements the first audit/reporting workflow from issue #3 and
extends the dry-run groundwork for issue #2. It is stacked on PR #4, whose token
and discovery changes remain required. It does not implement automatic optimization
changes, the editable multi-agent registry or a production rollout.

## Run an audit

In **Managed hosts**, select an enrolled host and choose **Run read-only audit**.
Follow its persistent job in **Jobs & activity**. Its report shows ordered findings,
evidence, missing observations, historical comparison, proposed zones, review
requirements and verification/rollback prerequisites. No model is needed and the
UI submits a zero-token/zero-cost operation job.

An MCP OAuth client with `serverhub:jobs` can call `audit_host` with `host_id`.
It returns a queued job ID, not a synchronous audit or repair claim. Use existing
`job_progress`/`job_result` to follow it. Existing generic `submit_job` also supports
the complete operation arguments:

```json
{
  "kind": "operation",
  "host_id": "REPLACE_WITH_ENROLLED_HOST",
  "token_budget": 0,
  "cost_budget": 0,
  "spec": {
    "operation": "host.audit",
    "arguments": {
      "baseline": {
        "observed_at": "2020-01-01T00:00:00Z",
        "source": "example historical operator report, not current telemetry",
        "disk_percent": {"/example-data": 75},
        "container_count": 1
      }
    }
  }
}
```

This example is synthetic. Enter your historical baseline privately at runtime;
production measurements are not bundled into the repository. Baseline timestamps
require a timezone and cannot be in the future. Its values are always labelled
caller-reported/unverified, never imported as current facts. Only current node
observations can produce current findings. Missing current values remain unknown.
The simple dashboard button uses no baseline or directory-scan target; advanced
arguments currently use REST/MCP generic job submission.

## Authorization and persistence

`host.audit`, `inventory.read` and `inventory.refresh` must all be permitted for
the authenticated identity and concrete host. Owners inherit existing safe-read
semantics; other users need an expiring host-scoped grant. New read-only autonomy
profiles include these operations; existing stored grants are **not silently
expanded**. An owner can issue a reviewed new profile through Setup. Prompt text,
agent personas and historical baseline input cannot grant authority.

The job requests fresh authenticated node inventory using a durable command key.
It checkpoints sanitized analysis input, controller receipt time and sample ID
before analysis. A retry reuses a saved observation less than five minutes old;
a stale checkpoint requests a new generation of inventory. Policy is rechecked
on execution and node delivery. Revocation, missing permissions or offline-node
deadlines remain visible as blocked/failed jobs. Logs show collection, analysis
and report phases. Browser disconnection does not own execution.

The current audit deliberately returns `partial` with explicit coverage gaps,
including independent gateway/WAN verification, restore tests, runtime traffic and
vendor lifecycle checks. Zero observed findings does not mean a clean security
bill of health. `changes_executed` is always empty. A report/action plan is not a
remediation result, an executed rollback or an approval grant.

## Measurements and ordering

- Disk capacity comes first: warning at 80%, high at 90%, critical at 95% used.
  Evidence retains free/used/total bytes and filesystem/mount. Growth uses at least
  two recorded samples spanning 60 seconds; linear time-to-full is labelled an
  estimate, not a guarantee. Historical reported percentages do not generate a rate.
- Read-only `findmnt` and `losetup` inventory records mount and backing-file
  relationships, capped at 1,000 entries. NTFS/fuseblk backing-file layers receive
  a review finding, with Docker ownership explicitly unverified until mapped.
- Docker socket mounts (including `:ro`), privileged containers, unconfined
  AppArmor, unhealthy/restarting containers, non-loopback published ports, missing
  Compose provenance and implicit/explicit `latest` tags produce specific evidence.
  Unknown containers are never deleted or stopped.
- Host listeners are separated from host firewall observations and unknown gateway
  policy/WAN exposure. The audit performs no external scan or network change.
- Failed units, NVIDIA PCI/DRM observations and an optional three-second fixed
  `nvidia-smi` read support diagnosis. Failure/tool absence does not justify driver
  reinstall or prove no GPU exists. SMART tool availability is not SMART health.
- Local `apt list --upgradable` and reboot-required flag are read only; no cache
  update, package installation or reboot occurs. Cache freshness, ESM coverage and
  vendor lifecycle remain unverified. Plans require dependency checks, protected
  backup/restore, staging, coordinated downtime and separately approved changes.
- Zone proposals cover proxy, smart-home, AI, apps, media, management and
  private-data. Name-based classification is explicitly inferred; actual network
  attachments and Compose declarations are distinct from unobserved runtime flows.
  Host-network/multicast exceptions require service/client verification. Migration
  proposals are staged and never applied by this workflow.

Reports cap prioritized findings at 100, zone proposals at 100 and dependency
entries at 200. Counts/limits are explicit; input inventory collectors retain their
own timeout/output/container limits. Analysis uses at most 120 historical samples.

## Optional approved directory usage

A privileged `du` scan is opt-in and independently scoped. The node's protected
root-owned broker YAML may register a target, never an arbitrary model path:

```yaml
storage_targets:
  data: /srv/approved-data
```

The directory and every ancestor must be root-owned, protected against group/other
writes and free of symlinks. Broad/system/secret/control-plane roots are refused.
This may deliberately reject permissive NTFS mounts: do not relax directory
permissions or relocate production data merely to make a scan pass. Use approved
manual diagnostics and a reviewed storage plan if safe prerequisites are absent.

Grant `diagnostics.storage` for that exact named target. Setup's autonomy form has
**Approved storage target names**; this only creates a scoped expiring policy,
not a broker configuration. Submit `storage_target: "data"` in `host.audit`
arguments to request it. Missing permission identifies that exact operation/target.

The broker invokes fixed GNU `du --one-file-system --max-depth=1 --block-size=1
--null -- PATH`, with a 10-second timeout and bounded output. No shell, symlink
following, cross-filesystem recursion, deletion or file-content read is exposed.
It returns at most 100 entries, sorted by allocated blocks. Allocated usage is not
apparent size or a guarantee of freeable space. A timed-out/failed scan stops the
job explicitly; it never becomes an empty successful measurement. This is a
bounded measurement, not storage cleanup or a general filesystem API.

## Installation, upgrade and rollback

Follow [installation.md](installation.md) on a disposable Ubuntu 24.04 VM with the
reviewed `feature/host-audit-workflow` ref. For an existing installation, build and
use the root-reviewed [repair/upgrade workflow](upgrade.md). Broker/control-plane
code and trust digests change; a worker must not update its own trust anchors.
No schema migration is required: job checkpoints and the existing metrics JSON
store new fields. Old samples lack per-mount growth data and remain valid.

The existing protected native release recovery remains authoritative. This audit
performs no changes that need application rollback. Automated optimization
checkpoints/apply/rollback, deep GPU/runtime/SMART diagnosis, live UniFi policy
correlation, production update/reboot execution and the Jarvis pilot remain
subsequent separately reviewed implementation work.
