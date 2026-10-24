# Security review against a63400f

Scope: the security-priority follow-up to PR #6, based exactly on
`a63400f64b118c20ed617196b5c4709b8b93f57b`. Work is on a separate branch;
no production installation, Control, Caddy, SSH, firewall, credentials or data
were changed. Installed production revision is operator-provided, not remotely
attested by this work. A running `1.0.0` version string does not identify a commit.

Reviewed inputs: `serverhub-hardening.patch` and
`ServerHub AI OS – samlet gennemgang og fejlliste.pdf` (24 October 2026).
The report does not identify its Git commit and reports 104 tests, while this
base has 337 local tests; findings were checked individually against source.
Input SHA-256:

- Patch: `7c1411db5fe9a747388cf79daddc27065e54cd431681312a68a3591f11e0bf63`
- PDF: `4d7227a04e4f4ec636e50ad1188c413fa7618d6cacf09ff818c527e33e7b52d3`

The patch was not applied wholesale. In particular its short read allowlist
would remove valid capabilities, and treating Prometheus queries as writes would
prevent legitimate read-only grants.

## Findings and disposition

| Report finding | Status at this change | Evidence / boundary |
| --- | --- | --- |
| 1 byte-based token accounting / all schemas / full history | Already partly fixed at base | Provider-specific mixed UTF-8/BPE **estimate**, 20% uncertainty, context/output/job limits, actual provider usage and durable reservations exist. Specialist/phase tool schemas and compaction exist. No blanket budget inflation. Remaining compaction efficiency/small-model nonprogress needs a separate agent follow-up. |
| 2 no source/log reads | Already fixed at base | Development `read_file`/`list_files`, `systemd.logs` with fixed unit/broker scope. No arbitrary host-file or shell read added. |
| 3 dependency `--share-net` | Fixed here | No shared host namespace. Per-command private Unix CONNECT gateway, exact registered public HTTPS hosts, checked/pinned DNS, public-address and local-interface/LAN rejection. Normal tests/build have no gateway. |
| 4 Compose security options/root variants | Fixed here | Strict boolean read_only; exactly cap_drop ALL and no-new-privileges:true; explicit canonical nonzero numeric UID/GID; reject extra seccomp/AppArmor/label options and both braced/unbraced interpolation. Existing image/hash/volume/network restrictions retained. |
| 5 suffix-based read bypass | Fixed here | Explicit complete read classification. Unknown suffixes never gain authority. Every integration read, including Prometheus and AdGuard status, requires a live scoped grant; classification is separate from owner's limited built-in core diagnostic reads. |
| 6 Home Assistant/AdGuard role names | Fixed here | Household ceiling uses actual registry names. Positive and denied scoped integration tests. No existing policy rows rewritten. Invalid old spellings were not registered executable operations. |
| 7 paused wall time counts toward deadline | Open | Active-time/deadline semantics are outside this security-only PR. Do not describe paused/resumed long jobs as fixed. |
| 8 inherited SIGTERM / graceful shutdown | Open | Requires job-supervisor/child signal changes and interruption tests. |
| 9 resume burns attempts | Open | Separate job-lifecycle fix required. |
| 10 recovery stale O_EXCL temporary | Open, confirmed | `node/watchdog.py` uses deterministic `.serverhub-recovery-ID` with O_EXCL. Cleanup must validate provenance, not blindly unlink an arbitrary entry. |
| 11 account lockout / proxy IP | Fixed here | Shared DB-backed IP, IP/account failure and global admission limits; no new account-wide attacker lock. Trust forwarding only from explicitly configured peers. Actual Caddy test included, no production proxy edits. |
| 12 single-thread broker / exceptions | Mixed | Handler already catches unexpected Exception and returns sanitized failure. Broker remains single-threaded; bounded parallelism/serialization of writes is follow-up work. |
| 13 inventory every 60 seconds / slow poll | Already improved at base | Command polls are bounded to 15 seconds; full inventory debounced and event hints sampled separately. Faster push delivery remains future work. |
| 14 unexpected agent exception / in_doubt | Open | Schema/error journal handling needs follow-up; never blindly retry an uncertain write as a safe failure. |
| 15 backup unverified | Mixed | Installed TCP/password backups use protected pgpass; checksums and real PostgreSQL restore drills exist. Docker encrypted/consistent/isolated restore has native tests. Generic socket pgpass edge, configuration restore automation, independent offsite copies and core-backup encryption/retention are not claimed resolved. |
| 16 memory poisoning | Open, mitigated | Scoped historical observations are untrusted and policy is enforced independently. No prompt-injection immunity is claimed. |
| 17 Ubuntu AppArmor/scanner paths | Already partly fixed at base | Named AI build AppArmor profile and actual Ubuntu CI exist. Scanner cache/lock path compatibility is not certified by this PR. |
| 18 runtime egress/OpenAPI | Partly addressed | Untrusted dependency code is isolated here. Trusted worker needs provider/Git networking; `/docs`/OpenAPI remain configurable. Whole-runtime destination restrictions and docs authentication remain follow-ups. |
| hash_secret docstring | Fixed here | It now accurately describes unkeyed SHA-256 of high-entropy tokens. |
| argv-list redaction / truncation visibility | Open | Requires dedicated redaction/evidence-retention changes; no source credentials added here. |
| usage finally masks errors / DB hiccups | Open | Separate accounting/supervisor reliability work; existing conservative reservation behavior retained. |
| BasicAuth(None), report timestamp | Already handled at base | Missing required credential references raise IntegrationError; inventory ingestion stamps the observation before its timestamp response. |
| production release adapter fails closed | Intentional boundary | No generic production adapter or automatic release permission added. |

## Authorization compatibility

`is_read` describes a known read operation, not an authorization bypass. The
complete compiled integration read set is tested. An owner still has its established
core inventory/service/diagnostic read authority, with the node's independent fixed
target allowlists. Argument-limited **integration** reads always match subject,
host/project, environment, expiry and arguments; owner cannot bypass a named query,
repository, entity/site or integration grant merely because it is a read.
Nonowner roles continue requiring appropriate grants and role ceilings. Writes,
production release approvals, emergency stop and audit remain enforced. Invalid
Home Assistant/AdGuard spellings are corrected in role ceilings; stored grants
are never silently expanded or replaced.

## Dependency network boundary

`allow_dependency_network:true` plus an active dependency-phase grant now enables
**only** the gateway. `--share-net` is removed. The sandbox sees a new network
namespace with loopback, one private Unix gateway socket, public CA certificates
and a root-installed stdlib bridge. It does not receive the host DNS configuration,
controller files, home directories, Docker socket or credentials.

Root project contracts may set `dependency_hosts` (default `pypi.org`,
`files.pythonhosted.org`, `registry.npmjs.org`) and `max_dependency_bytes`
(default 512 MiB, maximum 2 GiB per command). Hosts are exact names, no URLs or
wildcards. Only CONNECT to port 443 is accepted. DNS is resolved by trusted code,
all answers must be globally routable, translated/loopback/private/metadata/mixed
answers are rejected, and validated IPs are pinned for connect. Connected host
interface networks are also rejected. Gateway outbound transport uses public IPv4
only; IPv6-only dependency registries fail closed, so custom IPv6 transition/NAT64
prefixes cannot bridge to private IPv4 services. This restriction applies only to
untrusted dependency egress, not the host's IPv6 inventory or trusted AI providers.
No host firewall, routing, SSH or kernel
network setting changes are needed.

Connections and bytes are bounded. Builds/tests never receive this gateway.
Non-proxy-aware commands cannot get direct network access; unsupported destinations
fail closed. Private registries need a separately reviewed vendored dependency
workflow; do not restore host networking to make a build work. TLS stays end-to-end
and uses certificate verification in normal package clients. This is not package
signature verification or a guarantee against a malicious allowed public registry.
Public outbound HTTPS is still a powerful explicitly delegated capability.

## Login and Caddy

Limits are enforced only on `POST /api/auth/login`, in the existing protected
`system_state` table (no SQL revision or expanded worker grants). PostgreSQL
advisory locking serializes admission counters across API processes. Rejected
IP/account attempts cannot consume the global admission bucket indefinitely.
Counters are refreshed after locking, including sessions retained during password
verification, so concurrent failures cannot overwrite a newer count with cached state.
Counters expire and have bounded cardinality. Passwords, tokens and raw forwarding
headers are not stored in counters. Hashing client identities is pseudonymization,
not anonymization.

Defaults: 10 admitted attempts/minute/client, 100/minute globally, and 5 failed
attempts per client/account per 900 seconds. Rejection returns **429** and
`Retry-After`; incorrect admitted passwords return **401**. Failures no longer set
a global account lock, so another legitimate client can still sign in. A
pre-existing `locked_until` remains respected until its normal expiry; this change
does not modify credentials or silently clear old security state. NAT users may
share a client bucket. Distributed abuse can exhaust the global short window;
limits reduce server abuse, not eliminate denial-of-service.

The native API already disables Uvicorn's unconditional proxy-header rewriting.
`SERVERHUB_TRUSTED_PROXY_CIDRS` defaults to `[]`; forged headers from untrusted
peers are ignored. When enabled, XFF is validated right-to-left starting at the
actual socket peer. Malformed/oversized headers fall back to the peer bucket.
For the existing direct loopback Caddy, an operator can review adding **only to
AI OS's protected API environment**:

```sh
SERVERHUB_TRUSTED_PROXY_CIDRS='["127.0.0.1/32","::1/128"]'
```

Keep the API loopback-bound and trust only its actual reverse proxy. Processes on
a trusted proxy address are in that trust boundary. Do not trust broad networks or
all clients. Caddy normally sanitizes incoming X-Forwarded headers; if it is itself
behind a CDN/proxy, review that trust chain first. No rate-limit plugin, nginx swap,
or active Caddy routing change is required. Optional standalone AI vhost example:
`packaging/config/Caddyfile.ai.example`. The installer never writes the active
`/docker/caddy/Caddyfile`, Control routes, Pocket ID or existing OAuth configuration.

Primary reference: https://caddyserver.com/docs/caddyfile/directives/reverse_proxy

## Tests and production procedure

A separate PostgreSQL process-race test verifies shared admission limits.
Unit/negative tests cover real operation names and grants, unknown suffixes,
query/integration constraints for owner and readonly, Compose bypass variants,
shared persistent admission and spoofed forwarding, DNS rebinding/private IPv4/IPv6,
public local LAN addresses, gateway framing and fail-closed namespace arguments.
The existing MCP/OAuth and development job tests remain in the full suite.

`test-hardening-native.py` refuses any context except the guarded disposable
Ubuntu CI installation. It exercises actual namespaces, denial of host/LAN/
metadata TCP, actual package-index HTTPS, a host sentinel and actual Caddy with
validated upstream TLS, two client addresses and forged forwarding headers.
The existing actual Jarvis/Ollama pipeline then installs real pinned dependencies
through the gateway and verifies tests/staging/rollback. These scripts must never
be run against an existing VM or physical production installation.

No source change is considered native-verified until the corresponding GitHub job
passes; final PR description records exact test counts and run links. A local
Unix-socket restriction is a skip, not a passed integration test.

After review, in an operator checkout pinned to the tested security commit:

```bash
sudo env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/src" python3.12 -B -m serverhub.ops.installer --source "$PWD" --preflight
./scripts/install-ubuntu.sh --build-only
sudo ./scripts/repair-install.sh
```

This is the **reviewable, non-executed** namespace-3 upgrade procedure. Repair
backs up configuration/database, stages a separate executable release and arms
independent rollback before activation. No migration/grant expansion is needed.
Preview existing root-enrolled Compose contracts before scheduling writes: images
with named/root-like users or extra security options now fail closed and need
owner review, never an automatic rewrite.

For Caddy, review the actual peer separately, add the AI API trust setting only if
appropriate, then restart only `serverhub-ai-api.service` using the normal operator
maintenance procedure. Do not reload/change the active Caddy or Control to install
these code changes. Run the installed authenticated verifier against the exact
configured HTTPS origin/CA, then an authorized disposable development task.

Schema-compatible code rollback:

```bash
sudo ./scripts/upgrade.sh rollback
```

It restores the previous executable release and preserves database contents.
If new dependency contract fields were added, review restoring the backed-up
project contract for the previous version. Counter rows are harmless to old code.
Rollback to a63400f reintroduces its known network/policy vulnerabilities; do not
continue untrusted dependency jobs under the old host-network behavior.
