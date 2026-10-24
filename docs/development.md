# Controlled development workflows

The `development` job produces a tested, immutable release candidate from an
owner-configured project. It creates a separate Git branch and checkout, validates a
unified patch, installs configured dependencies, runs configured build/tests and optional
independent checks, and creates a deterministic SHA-256-addressed archive and manifest.
The existing source repository remains unchanged.

Copy and adapt [projects.yaml](examples/projects.yaml) under `/etc/serverhub/projects.yaml`.
Configuration, its ancestors and the independent-checks directory must be root-owned and
not group/world writable. Configure a credential-free HTTPS repository or a local
repository readable by the unprivileged development worker. No credentials are inserted
into clone URLs, and Git disables hooks, global/system config and interactive prompting.
Private Git authentication requires a separately reviewed read-only source mirror;
credential-helper execution is intentionally disabled.

Submit a job using this body (job execution limits may also be supplied):

```json
{
  "kind": "development",
  "project": "jarvis",
  "spec": {"project": "jarvis", "base_commit": "FULL_HEXADECIMAL_COMMIT", "patch": "UNIFIED_DIFF", "stage": false}
}
```

The base commit must exactly match the configured remote base ref. Omit it to use the
current configured ref. Project-scoped active policies must explicitly allow
`development.workspace`, `development.patch`, `development.dependencies`,
`development.test`, `development.artifact` and optionally `development.stage` as needed. Dependency commands with network
also require `development.network` and `allow_dependency_network:true` in owner config.
User-supplied commands, URLs, destination paths or additional job fields are rejected.

A model can queue this same pipeline through the `development.submit` tool using a
structured patch. It receives a child job ID rather than a fabricated deployment result.
For autonomous correction, use `development_autonomous` with a bounded prompt instead:
its fixed tool catalog supports plans, source inspection, bounded edits, configured
checks and finish. Failed checks feed back into the next model round. Identical
failed checks and three rounds without source/check progress stop with partial
results. The original repository and independent acceptance checks cannot be modified.
A small local model can still fail; a verified result is mandatory for success.


## Isolation and verification

Repository code executes under bubblewrap with a fresh user/PID/network/mount namespace,
no capabilities, a clean environment, read-only `/usr` and `.git`, and only its own
workspace writable. Host `/etc/serverhub`, backups, home directories and Docker sockets
are not mounted. Time, process, memory, CPU, core dump and file-size limits apply.
Network is disabled for builds/tests. Explicitly permitted dependency commands use
an isolated HTTPS gateway to exact root-registered public package hosts; the host
network namespace, DNS configuration and private services remain inaccessible.
See [security-review-a634.md](security-review-a634.md) for limits, IPv4 gateway
transport, trusted registry assumptions and fail-closed behavior.

Root-owned independent tests are mounted read-only at `/checks`, allowing checks not
editable by a generated patch. Configure these for meaningful application guarantees.
Generated project tests alone cannot prove that self-modified tests remain honest.

Workspace symlinks, submodules, binary patches, unsafe paths and protected metadata
changes are rejected. Generated `node_modules` and `.venv` trees may contain dependency
symlinks but are excluded from candidate archives and cannot be patched through this
workflow. Archives reject hardlinks and traversal, normalize ownership/timestamps and
have size/file-count bounds. Candidate paths do not include arbitrary host content.

Opt-in staging requires an explicit enrolled host, independent root-owned checks,
a separate staging policy and a root-enrolled `development.deploy` broker plan.
The broker starts a dedicated private-network systemd staging unit, tests HTTP
health inside that namespace, and restores the verified predecessor if the new
candidate fails. It never uses Jarvis production port 8088. Normal controller-only
build/test/archive jobs need no host or root broker. `release:true` still fails
closed without a separately configured production adapter.


## Restart behavior

Workspace identity, patch digest, command completion and candidate metadata persist.
Successfully checkpointed commands are skipped on resume. If a worker crashes between a
Git patch commit and its checkpoint, reapplying the patch can stop safely rather than
inventing success; inspect the preserved checkout before resuming. Interrupted dependency
commands may execute again inside the isolated workspace. They must therefore be
idempotent install/build operations.

If bubblewrap is missing or cannot create its namespaces, the job stops before running
project code. There is no unsandboxed fallback. See [the MCP/Jarvis follow-up guide](development-mcp.md) for the current executable
Ubuntu CI pilot, scoped grants, publisher, upgrade and remaining external checks.
