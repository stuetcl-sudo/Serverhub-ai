# Native Ubuntu 24.04 installation

The controller runs directly under systemd with PostgreSQL 16 and separate API,
worker, migration and node identities. Docker is not required. Start on a disposable
Ubuntu Server 24.04 x86_64 VM with at least 2 GB RAM and normal sudo access.

## One workflow

Check out the reviewed source revision. During review of this overhaul:

```sh
git clone --branch release/production-readiness https://github.com/stuetcl-sudo/Serverhub-ai.git serverhub-ai-os
cd serverhub-ai-os
./scripts/install-ubuntu.sh --public-url https://serverhub.example.net --owner dennis --ai-identity
```

Pin the reviewed commit with git checkout before running the workflow. This is the
unmerged release candidate; consult [delegated administration](delegated-administration.md)
and current CI evidence before any production enrollment. After review/merge,
use the reviewed main branch or signed release ref instead.
Run the wrapper as your normal user. It validates Ubuntu/Python, installs apt
prerequisites, downloads an official SHA256-pinned Node.js 22.23.4 build into
`.build-tools`, installs hashed Python runtime dependencies in `.build-venv`, builds
the frontend/wheel, and invokes the native installer through sudo. It does not
replace the system's Node or install the controller in Docker. TLS access to apt,
PyPI, npm and nodejs.org is required; use reviewed caches for an offline environment.
The build tools are pinned; apt security updates are intentionally not frozen.

The installer creates dedicated `serverhub-ai-api`, `serverhub-ai-worker`,
`serverhub-ai-node`, `serverhub-ai-staging`, and `serverhub-ai-migrate` accounts; a separate `serverhub` database
and roles; root-owned release files; hardened systemd units; protected configuration;
and initial owner credentials. It does not edit existing SSH, firewall, VPN, Docker
workloads or reverse-proxy configuration. PostgreSQL package installation starts a
local cluster; do not use a host with an unrelated/conflicting PostgreSQL deployment
for the first installation.

For a previously built, reviewed checkout, `scripts/install.sh --check`, `--plan`
and `--stage --root /tmp/serverhub-install-check` remain available. Invoke this
low-level script with `.build-venv/bin/python` and `PYTHONPATH=src` if system Python
does not have the application dependencies; the high-level workflow handles that.
Staging writes inspectable files only and does not prove systemd can start.

## Resume after interruption

Rerun **the same workflow with the same origin and reviewed source**. Installation
progress, release ID and generated credentials are persisted in root-only
`/var/lib/serverhub-install/state.json` before side effects. Completed phases are
retained; a migration interrupted before checkpointing is safely repeated. Repeated
successful installation does not reset passwords or recreate a removed bootstrap
credential file. A failed initial activation stops newly started controller services;
accounts, database and recovery material remain for resumption. No database or
existing service is deleted to make installation succeed.

Do not delete the journal or environment files to bypass a failure. For a failure:

```sh
sudo cat /var/lib/serverhub-install/last-command-error.log
sudo journalctl -u serverhub-ai-api -u serverhub-ai-worker -n 100 --no-pager
```

Command stderr is protected because it may contain sensitive connection details.
If the source/trust digest changed, or this is a legacy installation without a
journal, follow [upgrade.md](upgrade.md), rather than treating it as a fresh install.

## Open the dashboard and complete setup

Read `/etc/serverhub/bootstrap-owner.txt` with sudo, store the password privately,
then remove that file. The API listens on `127.0.0.1:9080` by default. For initial
access, use an SSH tunnel from your computer:

```sh
ssh -L 9080:127.0.0.1:9080 YOUR_VM_USER@YOUR_VM_ADDRESS
```

Open `http://localhost:9080`, log in and choose **Setup & diagnostics**. Loopback
same-origin asset requests are accepted. Cookie writes still require the exact
same loopback Origin. Non-secure cookies are allowed only on an HTTP loopback
request whose direct peer is also loopback; public access keeps Secure cookies.
Never expose port 9080 on an untrusted network. For normal multi-node use, configure
a trusted HTTPS proxy matching the supplied public URL, or use the native API's
certificate-verified TLS listener. Follow [persistent authenticated access](persistent-access.md)
for the systemd access environment and exact key/CA permissions; this survives
service restarts and does not depend on an SSH terminal. An nginx example is in
`packaging/config/nginx.conf.example`; an existing proxy is not overwritten.

The first-run wizard guides you through:

1. **AI provider:** enter your controller-reachable Ollama URL, discover installed
   models, select a tool-capable model, test it and save the `default` route.
2. **Host enrollment:** create a one-use enrollment token in Managed hosts, then
   install/configure a native node using the exact owner-selected name.
3. **Autonomy:** select an authenticated account, target host, profile, explicit
   target arguments and expiration. No per-tool prompts are required within this grant.
4. **Health & first job:** inspect diagnostics, then request CPU/memory/disk
   observations and inventory-freshness verification with the host selected.

No YAML editing is required for normal model selection or controller policy grants.
Root-owned node/broker/project configuration remains a separate trust boundary.

## Ollama on a separate private host

For example, enter `http://192.168.68.20:11434` and explicitly check the trusted
private HTTP exception. It permits this configured literal RFC1918/ULA endpoint;
it does not allow public HTTP, metadata/link-local addresses, arbitrary DNS names
or redirects. Prefer HTTPS where available. Keep Ollama bound/firewalled to the
trusted network; this application never exposes it publicly, changes its bind
address, downloads models or changes an external host's firewall.

Discovery uses `/api/tags`; capability validation uses `/api/show`; an actual
harmless structured tool-call probe uses `/api/chat`. Saving requires a successful
probe. Provider tests have bounded time/output and a $0.10 cost budget. An advertised
`tools` capability alone is not accepted as working tool calling.

Owner-managed routes are stored in PostgreSQL. The worker has SELECT access only.
They override the optional root-owned `models.yaml` fallback. A disabled database
route does not silently fall back to YAML. Configuration refreshes on the next job;
there is no routine service restart. Paid provider secrets remain environment
references, provisioned separately in API/worker environments. No raw secrets are
accepted by this setup API.

## Agent onboarding

For another Ubuntu/Debian x86_64 or ARM64 node, use reviewed built Python artifacts
and Python 3.12+. Debian 12's normal Python 3.11 is insufficient. ARM64 runtime
compatibility has not been verified by the Ubuntu x86_64 job.

```sh
sudo env PYTHONPATH="$PWD/src" .build-venv/bin/python -m serverhub.ops.installer \
  --source "$PWD" --apply --role node --public-url https://serverhub.example.net
```

The controller's public HTTPS certificate must be trusted by that node. Set `name`
and the one-use `enrollment_token` in `/etc/serverhub/node.yaml` locally as root;
keep root ownership, group `serverhub-ai-node`, mode 0640. A private CA can be supplied
with `ca_bundle`. Then start `serverhub-ai-node.service`. The resulting individual
identity and durable command journal are private to the node account. Remove the
consumed token from the configuration. Revocation requires a new owner enrollment.

Inventory collection works without the root broker; unavailable privileged
observations are recorded explicitly. Network probes, unit status/logs, restarts,
Docker and scanners currently use the separately enabled broker and its root-owned
fixed target allowlists. A controller grant cannot create or bypass a broker
allowlist. No worker account receives sudo, root SSH or Docker socket access.

## Self-diagnostics

For an existing installation, use [the one-command installed verifier](installed-verification.md)
to check authenticated API/assets/worker health and optionally run a live model
probe and fixed read-only inventory job. It never runs the destructive fresh-CI
installation scripts on your VM.

**Setup & diagnostics** checks database/migration revisions, fresh worker heartbeats,
model configuration and timestamped readiness evidence, API-readable assets,
configuration permissions, sandbox paths, local tool presence, active grants and
node observations. Use **Test connection & tools** for a live provider probe.
An agent heartbeat does not prove broker connectivity or fresh inventory.

A local read-only doctor command is also available with the API environment loaded:

```sh
sudo sh -c 'set -a; . /etc/serverhub/api.env; set +a; \
  /opt/serverhub/current/venv/bin/serverhub doctor'
```

It reports actionable findings and never repairs or broadens permissions. The
controller cannot inspect another service's mount namespace directly; systemd path
checks and node broker evidence state their scope explicitly.

See [Control coexistence and legacy unit migration](control-coexistence.md) before installing alongside ServerHub Control or upgrading generic `serverhub-*.service` AI OS units. New AI OS services use `serverhub-ai-*`; never stop or replace Control units.
