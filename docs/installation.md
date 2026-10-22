# Native installation

This package runs the controller directly on Linux under systemd. Docker is not a
runtime dependency. Full host installation and systemd hardening must first be
rehearsed in a disposable Ubuntu Server 24.04 VM; this delivery's constrained build
container only verified staging and software tests. Do not install it directly on
an existing critical server as its first deployment.

## Supported targets

- Controller: Ubuntu Server 24.04 LTS x86_64, Python 3.12, systemd, PostgreSQL 16.
- Nodes: Ubuntu/Debian x86_64 or ARM64, Python 3.12+. Debian 12 normally supplies
  Python 3.11, so it needs a separately maintained Python 3.12 installation.
- Local HTTPS reverse proxy and a certificate trusted by each node. The provided
  proxy example is deliberately not installed over an existing proxy.
- At least 2 GB RAM for the controller, additional capacity for projects/models.
  Ollama and remote model providers are provisioned independently.

## Build a release

From the repository root using Python 3.12 and Node 22+:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
python -m pytest
python -m build
npm --prefix frontend ci
npm --prefix frontend run build
```

Use the supplied `requirements.lock` for production dependencies. It includes
hashes and is installed with pip's `--require-hashes` mode. The wheel in `dist/`
and compiled `frontend/dist/` must exist before `--apply`. For offline installs,
prepopulate an approved pip wheel cache; the installer does not download arbitrary
application code selected by AI.

## Inspect before applying

```sh
./scripts/install.sh --check
./scripts/install.sh --plan --public-url https://serverhub.example.net
./scripts/install.sh --stage --root /tmp/serverhub-install-tree \
  --public-url https://serverhub.example.net
```

`--stage` writes configuration and units under the specified tree, calls no package
manager/systemctl/PostgreSQL operations, and uses obvious staging placeholders in
credential fields. It does not create service accounts or prove that systemd can
start on the actual target. `--check` reports `ready_for_apply` and missing tools.

On the disposable target VM:

```sh
sudo ./scripts/install.sh --apply --install-dependencies \
  --public-url https://serverhub.example.net --owner dennis
```

The installer creates dedicated `serverhub-api`, `serverhub-worker`,
`serverhub-node`, and offline `serverhub-migrate` identities. It creates a separate
PostgreSQL database named `serverhub`, distinct API/worker/migration roles,
root-owned release files, protected configuration, systemd units, and an initial
owner account. It refuses an existing installation or unexpected privileged service
account. It never changes SSH, firewall, VPN, existing Docker workloads, or existing
reverse proxies. Package installation can start a new local PostgreSQL service;
review conflicts with an existing host PostgreSQL installation first.

Generated initial credentials are in `/etc/serverhub/bootstrap-owner.txt` mode
0600. Store the credential privately and remove that bootstrap file. A supplied
owner password can instead be sent on standard input with
`--owner-password-stdin`; do not put passwords on a command line or in shell
history. Configure the HTTPS proxy using `packaging/config/nginx.conf.example`,
matching `SERVERHUB_PUBLIC_URL` and allowed origins. HTTP API binds localhost.

## Agent onboarding

In the owner UI/API create a one-use enrollment token for the exact node name.
Install another node using the same release artifacts:

```sh
sudo ./scripts/install.sh --apply --role node \
  --public-url https://serverhub.example.net
```

Edit root-owned `/etc/serverhub/node.yaml` and set `name` to the owner-selected
name and `enrollment_token` to that one-use token. Ensure the file is root-owned,
group `serverhub-node`, mode0640. Supply `ca_bundle` for a private CA. HTTPS
validation cannot be disabled. Then:

```sh
sudo systemctl enable --now serverhub-node.service
sudo journalctl -u serverhub-node.service -n 50
```

The resulting individual node secret and local idempotency journal live under
`/var/lib/serverhub-node`, accessible only to that node identity. Remove the
consumed enrollment token from the config. A revoked token requires owner-driven
re-enrollment; no shared SSH/root credential exists.

## Enable controlled privileged observations or repairs

The unprivileged agent reports partial inventory. To inspect Docker/firewall or
perform approved repairs, configure `/etc/serverhub/broker.yaml` as root and enable
`serverhub-broker.service`. Installer records the node UID and socket group. Broker
configuration must remain root-owned mode0600 and all parent directories must be
root-owned and not group/world writable. Default mutation allowlists are empty.

A systemd repair requires **both** an expiring controller policy and an exact
root-owned `allowed_services` entry. Protected ServerHub, network, SSH, Docker daemon,
database, and authentication services cannot be restarted through this adapter.
Docker restart targets additionally bind to an exact approved immutable image ID.
Initial Compose deployment requires an owner-provisioned root-owned manifest with
pinned image digests, non-root users, read-only roots, dropped capabilities,
loopback-only ports, healthchecks and exact manifest hash. Existing Compose project
updates are deliberately rejected until an application-specific data recovery
adapter is implemented.

Models/integrations/project configuration starts empty. Follow the integration
and administration guides before granting any writes. Verify backups and a restore
drill, negative authorization tests, node revocation, and emergency stop before
connecting a real server.
