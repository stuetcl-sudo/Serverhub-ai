# Host autonomy extension — issue #2

This branch is an incremental implementation on `overhaul/stability-autonomy`.
It does not close issue #2 or claim its entire acceptance list is implemented.
No production systems have been changed and neither PR is automatically merged.

## Delivery order and current status

1. **Token blocker:** implemented with provider regression tests and numeric job
   diagnostics; see [ai-accounting.md](ai-accounting.md). Actual external Qwen
   behavior is unverified without an explicitly configured test endpoint.
2. **Read-only discovery:** Docker race recovery, Compose dependency identities,
   image/volume/project graph edges, structural history, bounded event hints,
   Linux DRM GPU inventory, reviewed Caddy JSON endpoint extraction and dashboard
   history are implemented. Real Docker/Caddy daemons remain optional integration
   checks, not a claimed live verification in this development environment.
3. **Optimization engine:** remaining. Existing security findings, metric baselines,
   policy-gated operation jobs and independent release rollback are preserved;
   they are not a complete measured host optimization engine.
4. **Durable multi-agent registry/orchestrator and UI:** remaining. Existing logical
   specialist switching shares one job's identity and state, but is not the new
   editable registry, independently scheduled delegation or admission controller.
5. **Agent MCP tools:** remaining. Existing authenticated MCP tools are preserved;
   no `agent_message` or `agent_create` capability is advertised by this increment.
6. **Extended bounded-job preapproval/service protections:** remaining. Existing
   expiring host/project/argument/environment policies and exact broker allowlists
   remain enforced, with destructive/SSH/firewall operations forbidden.
7. **Jarvis pilot:** remaining; no Jarvis repository, staging host or release was
   selected or changed. Existing isolated development workflows are preserved.
8. **Readiness:** backend/frontend/build/native staging and disposable controller
   checks are run for this increment; GitHub's native Ubuntu workflow separately
   covers actual systemd/PostgreSQL install/resume/upgrade/rollback. See PR checks
   and [issue-2-report.md](issue-2-report.md) for exact verified results.

## Discovery behavior

An enrolled native agent automatically reports a full inventory every configured
`interval` seconds (bounded to 30–3600, default 60). It polls controller commands
at most every 15 seconds during normal operation. With a configured restricted
broker, it asks for a recent fixed Docker event hint at most every 15 seconds.
Container/network/image/volume events request a full refresh, debounced to at
least 30 seconds. Explicit authorized refresh commands can run sooner. Offline
or older brokers fall back to periodic reconciliation. Event windows overlap;
this is a refresh hint, not an exactly-once event stream. Missed events are
reconciled by the next complete inventory after reconnecting.

The worker receives no root, sudo, Docker group or Docker socket access. The
local broker's `inventory.events` accepts **no arguments** and is absent from
controller node-command and AI tool allowlists. It executes only a fixed read-only
Docker event query with a 30-second window and a three-second process deadline.
Event payloads/labels never cross the broker boundary.

Docker inspects at most 1,000 containers, in batches of 25, within a 30-second
inspect budget (an already-started bounded command may finish slightly later).
A container disappearing between `ls` and `inspect` no longer destroys all other
observations: bounded per-ID retries retain the others and mark a collection gap.
Truncation/gaps set `complete=false`; an incomplete snapshot cannot prove deletion.
Other Docker listing commands retain existing output/time limits. This is a bound
on collector work, not a guarantee of a consistent transactional Docker snapshot.

Only selected Compose labels are extracted. Environment variables, arbitrary
labels, raw commands and healthcheck logs are excluded. Compose `depends_on`
values such as `db:service_healthy:true` identify service `db`, scoped to its own
project. Declared dependencies and endpoint configuration are verified facts
about configuration; runtime dependency health and internet exposure remain
unverified. Graph edges are replaced from each report so removed objects do not
remain current. Hardware includes read-only Linux DRM sysfs GPU identification
and available VRAM attributes; this does not provide NVIDIA utilization or infer
that an empty DRM list means no GPU exists.

### Optional Caddy configuration evidence

Caddy endpoint discovery is opt-in because its admin API/configuration may contain
secrets. The node's **root-owned broker configuration** can reference a reviewed,
root-owned adapted JSON file with protected ancestors:

```yaml
caddy_json: /etc/serverhub/caddy-inventory.json
```

Create/update that reviewed JSON through your existing Caddy administration
procedure; do not copy secrets into this repository. Only server names, listener
addresses and host matchers are returned. TLS keys, handler bodies, headers and
raw upstream configurations are excluded. Without this reference the report says
unavailable; nothing enables or exposes Caddy's admin API. This increment does
not verify endpoint reachability or proxy response health.

## Timestamped structural history

The existing `inventory_samples.metrics` JSON now also stores a sanitized resource
snapshot and structural diff; no database schema migration is needed. There are
at most **1,000 samples per host**, covering metrics and structural history
(about 16.7 hours at the default 60-second full-report interval). Retention pruning
starts on that host's next report after upgrade; it never deletes another host's
samples. This is operational history, not a long-term backup archive. Older
samples remain compatible and show no structural baseline.

`GET /api/hosts/{id}/inventory/history?limit=30` uses the same authenticated
`inventory.read` host policy as inventory. Limit is clamped to 1–100. Entries
include controller receipt time, node observation time, collection-error count,
and per-section added/changed/removed IDs and counts. IDs are limited to 100 per
change type, while counts remain complete. A missing/incomplete collector is
`unavailable` and cannot infer removals. On reappearance after a gap it is a new
baseline, rather than claiming continuity across the gap. Metrics chart responses
omit the larger internal snapshots/diffs.

In **Managed hosts → select host → Changes**, the UI presents this API history
with explicit first observations, gaps and bounded identifiers. It uses actual
backend data and the existing refresh/error behavior.

## Installation and upgrade

Use [installation.md](installation.md) on an isolated Ubuntu 24.04 VM, selecting
the reviewed `feature/autonomous-host-agents` commit rather than the base branch.
For an existing overhaul installation, review the changes and follow
[upgrade.md](upgrade.md):

```sh
# In the reviewed checkout, as your normal user:
./scripts/install-ubuntu.sh --build-only
sudo ./scripts/repair-install.sh
```

This change includes broker/agent/control-plane code, so its protected trust
digest changes. The local-root reviewed repair path is required; do not overwrite
trust anchors or auto-sign a routine worker release to bypass review. Preserve
your current model route, context setting, grants, enrollment and broker allowlists.
New runtime options take effect after the reviewed agent/broker update. The model
context must fit the real model and inference host; `num_ctx` is now explicit.
Rollback uses the existing protected recovery workflow. Added JSON fields are
backward compatible; no destructive downgrade or data conversion is required.
