# Enforced trust boundaries and limitations

This is a policy-gated administration platform with isolated service identities.
A prompt, model response, job argument, or household role is never a source of
administrative authority. The controller evaluates persisted identity, role ceiling,
operation, host/project, explicit target constraints, production flag and expiry.
Node commands are checked again when dispatched.

The worker is not root, has no sudo or Docker group membership/socket, cannot write
`/etc/serverhub` or installed releases, and cannot read/delete protected backups.
PostgreSQL grants deny worker policy/user/session/secret/recovery-control writes;
OAuth tables have no worker privileges. Audit UPDATE/DELETE/TRUNCATE are denied
and an append-only database trigger prevents accidental audit mutation. The audit
hash chain detects changes when checked; it is not protection against an all-powerful
database administrator or proof of non-repudiation. Export to independently operated
append-only storage for that stronger requirement.

The root broker is deliberately a small trusted computing base. Its Unix socket
checks SO_PEERCRED against explicit unprivileged node UIDs, while filesystem socket
permissions exclude the worker. Every operation uses compiled functions and bounded
argument-array subprocesses. The broker uses root-owned immutable target config and
refuses protected control-plane/authentication/network/database service restarts.
No shell endpoint exists. Root-owned Compose manifests bind to an exact hash and
restrict image digests, permissions, mounts, published ports and healthchecks.
No policy can enable a missing compiled operation.

Node identities are separate random bearer credentials, sent only over validated
HTTPS and revocable individually. Enrollment tokens are one-use and short-lived.
This implementation does not supply mTLS certificate issuance, TPM-backed identity,
remote attestation, or automatic secret rotation. Protect the controller TLS key,
node identity files and enrollment channel. HTTPS termination and certificate
lifecycle are operator-managed.

Root-only backups and watchdogs use protected files and run outside worker/job
lifetimes. Native releases require an external Ed25519 signature, artifact checksums,
independent check metadata, and an unchanged enforcement-code/service/grant digest.
An AI-generated change cannot sign itself. Existing migration schema changes require
an offline owner procedure and restore rehearsal. Root and PostgreSQL administrators
remain trust anchors; their compromise defeats local protections.

Actual systemd execution, Unix socket peer credentials across distinct host users,
Ubuntu VM installation, remote ARM64 execution and real production backup recovery
must be verified on disposable target machines. Staged configuration tests and
mocked command-adapter tests are not substitutes for those integration checks.
The implementation has no claim to identify or remove every vulnerability.
