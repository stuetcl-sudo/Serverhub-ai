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
`development.test` and `development.stage` as needed. Dependency commands with network
also require `development.network` and `allow_dependency_network:true` in owner config.
User-supplied commands, URLs, destination paths or additional job fields are rejected.

A model can queue this same pipeline through the `development.submit` tool using a
structured patch. It receives a child job ID rather than a fabricated deployment result.
The current implementation does not automatically generate a new patch in response to
failed tests; failed results and workspace state are retained for the next authorized
repair job. It does not finish Jarvis functionality merely by having this pipeline.

## Isolation and verification

Repository code executes under bubblewrap with a fresh user/PID/network/mount namespace,
no capabilities, a clean environment, read-only `/usr` and `.git`, and only its own
workspace writable. Host `/etc/serverhub`, backups, home directories and Docker sockets
are not mounted. Time, process, memory, CPU, core dump and file-size limits apply.
Network is disabled for builds/tests; an explicitly permitted dependency command shares
the worker network with DNS/CA trust mounted. It does not implement destination-level
egress filtering, so approve dependency network access accordingly.

Root-owned independent tests are mounted read-only at `/checks`, allowing checks not
editable by a generated patch. Configure these for meaningful application guarantees.
Generated project tests alone cannot prove that self-modified tests remain honest.

Workspace symlinks, submodules, binary patches, unsafe paths and protected metadata
changes are rejected. Generated `node_modules` and `.venv` trees may contain dependency
symlinks but are excluded from candidate archives and cannot be patched through this
workflow. Archives reject hardlinks and traversal, normalize ownership/timestamps and
have size/file-count bounds. Candidate paths do not include arbitrary host content.

Staging checks execute configured isolated commands and record pass/fail. The workflow
does not yet start or retain a generic externally accessible staging service; use a
reviewed registered deployment adapter for that lifecycle. `release:true` requires a
production policy but still fails closed because no generic production deploy adapter
is installed. The platform's own signed-release maintenance path is separate.

## Restart behavior

Workspace identity, patch digest, command completion and candidate metadata persist.
Successfully checkpointed commands are skipped on resume. If a worker crashes between a
Git patch commit and its checkpoint, reapplying the patch can stop safely rather than
inventing success; inspect the preserved checkout before resuming. Interrupted dependency
commands may execute again inside the isolated workspace. They must therefore be
idempotent install/build operations.

If bubblewrap is missing or cannot create its namespaces, the job stops before running
project code. There is no unsandboxed fallback. This delivery environment allowed real
Git/patch/archive tests but denied namespace creation; actual sandbox code execution
must be verified on the intended native Linux host before using development jobs.
