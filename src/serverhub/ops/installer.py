"""Native installer. --stage writes an inspectable tree without changing the host."""

from __future__ import annotations

import argparse
import fcntl
import tempfile
import time
import grp
import hashlib
import json
import os
import platform
import pwd
import secrets
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


class InstallError(RuntimeError):
    pass


ACCOUNTS = {
    "serverhub-ai-api": "/var/lib/serverhub-ai-api",
    "serverhub-ai-worker": "/var/lib/serverhub-ai-worker",
    "serverhub-ai-node": "/var/lib/serverhub-ai-node",
    "serverhub-ai-staging": "/var/lib/serverhub-ai-stage-runtime",
    "serverhub-ai-migrate": "/var/lib/serverhub-ai-migrate",
}
TRUST_FILES = [
    "packaging/postgresql-grants.sql",
    "packaging/trust-boundaries.json",
    "src/serverhub/auth.py",
    "src/serverhub/policy.py",
    "src/serverhub/audit.py",
    "src/serverhub/jobs.py",
    "src/serverhub/node_api.py",
    "src/serverhub/node/broker.py",
    "src/serverhub/mcp.py",
    "src/serverhub/oauth_models.py",
    "src/serverhub/main.py",
    "src/serverhub/settings.py",
    "src/serverhub/integrations/registry.py",
    "src/serverhub/ai/providers.py",
    "src/serverhub/node/watchdog.py",
    "src/serverhub/ops/installer.py",
    "src/serverhub/ops/coexistence.py",
    "src/serverhub/ops/runtime_permissions.py",
    "src/serverhub/ops/migrate_units.py",
    "src/serverhub/ops/unit_recovery.py",
    "src/serverhub/ops/release.py",
    "src/serverhub/ops/backup.py",
]
CONTROLLER_UNITS = [
    "serverhub-ai-api.service",
    "serverhub-ai-worker.service",
    "serverhub-ai-backup.service",
    "serverhub-ai-backup.timer",
    "serverhub-ai-release-watchdog.service",
    "serverhub-ai-release-watchdog.timer",
]
NODE_UNITS = [
    "serverhub-ai-node.service",
    "serverhub-ai-broker.service",
    "serverhub-ai-recovery.service",
    "serverhub-ai-recovery.timer",
    "serverhub-ai-operation-watchdog.service",
    "serverhub-ai-operation-watchdog.timer",
]


def os_release(path="/etc/os-release"):
    values = {}
    try:
        for line in Path(path).read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                values[key] = value.strip('"')
    except OSError:
        pass
    return values


def check_compatibility(role="controller", source=None) -> dict:
    operating = os_release()
    architecture = platform.machine()
    controller_ok = (
        operating.get("ID") == "ubuntu"
        and operating.get("VERSION_ID") == "24.04"
        and architecture in {"x86_64", "amd64"}
    )
    node_ok = operating.get("ID") in {"ubuntu", "debian"} and architecture in {
        "x86_64",
        "amd64",
        "aarch64",
        "arm64",
    }
    python_ok = sys.version_info >= (3, 12)
    tools = ["python3", "systemctl", "useradd", "runuser"]
    if role == "controller":
        tools += ["psql", "pg_dump", "pg_restore", "createdb", "dropdb"]
    dependencies = {tool: shutil.which(tool) is not None for tool in tools}
    artifacts = {}
    if source:
        source = Path(source)
        artifacts = {
            "wheel": bool(list((source / "dist").glob("*.whl"))),
            "requirements.lock": (source / "requirements.lock").is_file(),
            "frontend": (source / "frontend/dist/index.html").is_file() if role == "controller" else True,
        }
    systemd_running = Path("/run/systemd/system").is_dir()
    return {
        "os": operating.get("PRETTY_NAME", "unknown"),
        "architecture": architecture,
        "python": platform.python_version(),
        "role": role,
        "compatible": (controller_ok if role == "controller" else node_ok) and python_ok,
        "dependencies": dependencies,
        "artifacts": artifacts,
        "systemd_running": systemd_running,
        "ready_for_apply": (controller_ok if role == "controller" else node_ok)
        and python_ok
        and all(dependencies.values())
        and all(artifacts.values())
        and systemd_running,
    }


class Installer:
    def __init__(
        self,
        source: str | Path,
        *,
        root="/",
        role="controller",
        public_url="https://serverhub.local",
        runner=None,
        ai_identity=False,
    ):
        self.source = Path(source).resolve()
        self.root = Path(root).absolute()
        self.role = role
        self.ai_identity = bool(ai_identity)
        self.public_url = public_url.rstrip("/")
        self.runner = runner or subprocess.run
        if not self.public_url.startswith("https://") or any(char in self.public_url for char in "\n\r'\" "):
            raise InstallError("public URL must be an HTTPS origin without whitespace or quotes")
        self.writes = []

    def path(self, value: str) -> Path:
        if not value.startswith("/") or ".." in Path(value).parts:
            raise InstallError("installation paths must be absolute without traversal")
        path = self.root / value.lstrip("/")
        if self.root.is_symlink() or not path.resolve().is_relative_to(self.root.resolve()):
            raise InstallError("installation path escapes its root")
        cursor = path
        while cursor != self.root and cursor != cursor.parent:
            if cursor.is_symlink():
                raise InstallError("installation refuses symlinked destination paths")
            cursor = cursor.parent
        return path

    def write(self, value, data, mode=0o644):
        path = self.path(value)
        if (
            getattr(self, "preserve_configuration", False)
            and path.exists()
            and (value.endswith((".env", ".yaml")) or value == "/var/lib/serverhub-status/backups.json")
        ):
            return path
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".serverhub-", dir=path.parent)
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "w") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            Path(temporary).unlink(missing_ok=True)
        self.writes.append(
            {"path": value, "mode": oct(mode), "sha256": hashlib.sha256(data.encode()).hexdigest()}
        )
        return path

    def units(self):
        return (CONTROLLER_UNITS if self.role == "controller" else []) + NODE_UNITS

    def trust_digest(self):
        data = []
        for relative in TRUST_FILES:
            data.append(relative.encode() + b"\0" + (self.source / relative).read_bytes())
        for path in sorted((self.source / "packaging/systemd").glob("*")):
            data.append(path.name.encode() + b"\0" + path.read_bytes())
        return hashlib.sha256(b"\n".join(data)).hexdigest()

    def plan(self):
        return {
            "role": self.role,
            "root": str(self.root),
            "public_url": self.public_url,
            "ai_identity": self.ai_identity,
            "actions": [
                "validate Ubuntu/Debian and Python 3.12",
                "create dedicated nologin service accounts",
                "install locked wheel in root-owned native virtualenv",
                "write role-specific protected configuration",
                "configure local PostgreSQL roles and run migrations"
                if self.role == "controller"
                else "configure HTTPS node enrollment",
                "install hardened systemd units",
                "initialize owner credentials"
                if self.role == "controller"
                else "register individual node identity",
                "start services and run local healthcheck",
            ],
            "units": self.units(),
            "trust_boundary_digest": self.trust_digest(),
            "never_changes": [
                "firewall",
                "SSH",
                "VPN",
                "existing Docker workloads",
                "existing reverse proxy",
                "unrelated databases",
            ],
        }

    def stage(
        self,
        *,
        api_password="STAGING_ONLY_NOT_A_CREDENTIAL",
        worker_password="STAGING_ONLY_NOT_A_CREDENTIAL",
        migrate_password="STAGING_ONLY_NOT_A_CREDENTIAL",
        node_uid=999,
        node_gid=999,
    ):
        if self.root.resolve() == Path("/"):
            raise InstallError("--stage requires a separate --root directory")
        return self._configuration(
            api_password, worker_password, migrate_password, node_uid=node_uid, node_gid=node_gid, staged=True
        )

    def _configuration(
        self, api_password, worker_password, migrate_password, *, node_uid, node_gid=None, staged=False
    ):
        if self.role == "controller":
            from .sandbox_setup import configure
            configure(self,staged=staged)
        for unit in self.units():
            self.write("/etc/systemd/system/" + unit, (self.source / "packaging/systemd" / unit).read_text())
        if self.ai_identity and self.role == "controller":
            self.write("/etc/systemd/system/serverhub-ai-worker.service.d/10-ai-identity.conf",
                       "[Service]\nUser=serverhub-ai\nGroup=serverhub-ai-worker\n")
        self.write("/opt/serverhub/recovery-ai/operation_watchdog.py",
                   (self.source / "src/serverhub/ops/operation_watchdog.py").read_text(), 0o600)
        self.write("/etc/serverhub/trust-boundaries.sha256", self.trust_digest() + "\n")
        # Python modules share one interpreter and can monkey-patch each other.
        # Anchor the whole package, rather than trusting a manifest's claim that
        # only selected security modules remained unchanged.
        code_hashes = {
            str(path.relative_to(self.source / "src")): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((self.source / "src/serverhub").rglob("*.py"))
        }
        self.write(
            "/etc/serverhub/trusted-code-hashes.json",
            json.dumps({"format": 1, "files": code_hashes}, sort_keys=True) + "\n",
            0o600,
        )
        self.write(
            "/etc/serverhub/trust-boundaries.json",
            (self.source / "packaging/trust-boundaries.json").read_text(),
            0o600,
        )
        origins = json.dumps([self.public_url], separators=(",", ":"))
        common = (
            f"SERVERHUB_DEV_MODE=false\nSERVERHUB_PUBLIC_URL={self.public_url}\n"
            f"SERVERHUB_ALLOWED_ORIGINS='{origins}'\nSERVERHUB_FRONTEND_DIR=/opt/serverhub/current/web\n"
        )
        if self.role == "controller":
            for name, password in (("api", api_password), ("worker", worker_password)):
                content = (
                    common
                    + f"SERVERHUB_DATABASE_URL=postgresql+psycopg://serverhub_{name}:{password}@127.0.0.1/serverhub\nSERVERHUB_STATE_DIR=/var/lib/serverhub-ai-{name}\n"
                )
                if name == "api":
                    content += (
                        "SERVERHUB_SECRET_KEY="
                        + ("STAGING_ONLY" if staged else secrets.token_urlsafe(48))
                        + "\n"
                    )
                self.write(f"/etc/serverhub/{name}.env", content, 0o640)
            self.write(
                "/etc/serverhub/recovery.env",
                common
                + f"SERVERHUB_DATABASE_URL=postgresql+psycopg://serverhub_migrate:{migrate_password}@127.0.0.1/serverhub\n",
                0o600,
            )
            self.write(
                "/etc/serverhub/models.yaml",
                (self.source / "packaging/config/models.yaml").read_text(),
                0o644,
            )
            self.write(
                "/etc/serverhub/integrations.yaml",
                (self.source / "packaging/config/integrations.yaml").read_text(),
                0o644,
            )
            self.write(
                "/etc/serverhub/projects.yaml",
                (self.source / "packaging/config/projects.yaml").read_text(),
                0o644,
            )
        self.write(
            "/etc/serverhub/node.yaml",
            f"controller_url: {self.public_url}\nname: {platform.node() or 'serverhub'}\nstate_dir: /var/lib/serverhub-ai-node\ninterval: 60\nbroker_socket: /run/serverhub-ai-broker/control.sock\n# Add a one-time enrollment_token from the owner UI before enabling this node.\n",
            0o640,
        )
        self.write(
            "/etc/serverhub/broker.yaml",
            f"socket: /run/serverhub-ai-broker/control.sock\nallowed_uids: [{node_uid}]\nsocket_gid: {node_gid if node_gid is not None else node_uid}\nallowed_services: []\nallowed_containers: []\ncompose_projects: {{}}\nnetwork_targets: {{}}\nallowed_scan_images: []\nrecovery_directory: /var/lib/serverhub-recovery\n",
            0o600,
        )
        self.write(
            "/etc/serverhub/README",
            "Root-owned configuration. API, worker, and node identities are separate.\nModels/integrations are disabled until the owner supplies documented endpoints and secret environment references.\nBroker action allowlists are empty by default. No SSH, firewall or VPN changes are made by installation.\n",
        )
        self.write("/var/lib/serverhub-status/backups.json", '{"backups": [], "updated_at": null}\n')
        if staged:
            self.write("/install-plan.json", json.dumps(self.plan(), indent=2) + "\n")
            self.write("/staged-files.json", json.dumps(self.writes, indent=2) + "\n")
        return {
            "state": "staged" if staged else "configured",
            "root": str(self.root),
            "files": self.writes,
            "units": self.units(),
        }

    def _run(self, command, *, env=None, stdin=None, timeout=600, cwd="/"):
        if Path(command[0]).name == "apt-get":
            # Ubuntu's apt needrestart hook can otherwise restart unrelated
            # Control daemons. Scope suspension to this subprocess, never edit
            # host needrestart configuration or mask foreign units.
            env = dict(os.environ if env is None else env, NEEDRESTART_SUSPEND="1")
        try:
            return self.runner(
                command,
                env=env,
                input=stdin,
                text=True,
                capture_output=True,
                check=True,
                timeout=timeout,
                cwd=cwd,
            )
        except (subprocess.SubprocessError, OSError) as error:
            logdir = self.path("/var/lib/serverhub-install")
            logdir.mkdir(parents=True, exist_ok=True, mode=0o700)
            target = logdir / "last-command-error.log"
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(str(getattr(error, "stderr", "") or "Command unavailable or timed out"))
            raise InstallError(
                f"{Path(command[0]).name} failed. Read /var/lib/serverhub-install/last-command-error.log as root, fix the reported prerequisite and rerun the same installation command"
            ) from error

    def _activate(self, release):
        current = Path("/opt/serverhub/current")
        temporary = current.with_name(".current-install")
        temporary.unlink(missing_ok=True)
        temporary.symlink_to(release)
        os.replace(temporary, current)

    def _health_configuration(self):
        # Root-only deployment config, independent of the caller's environment.
        from .repair import read_environment
        options = {}
        for filename in ("api.env", "access.env"):
            path = self.path("/etc/serverhub/" + filename)
            if path.exists():
                options.update(read_environment(path))
        return options.get("SERVERHUB_HEALTH_URL", "http://127.0.0.1:9080"), options.get("SERVERHUB_HEALTH_CA")

    def _healthchecks(self, release):
        import httpx
        from serverhub.diagnostics import verify_frontend_http

        import ssl
        url, ca = self._health_configuration()
        verification = ssl.create_default_context(cafile=ca) if ca else True
        for attempt in range(30):
            try:
                with httpx.Client(base_url=url, verify=verification, timeout=5, trust_env=False) as client:
                    response = client.get("/health")
                    response.raise_for_status()
                    verify_frontend_http(client)
                self._run(
                    ["systemctl", "is-active", "--quiet", "serverhub-ai-api.service", "serverhub-ai-worker.service"]
                )
                return
            except (httpx.HTTPError, InstallError, ValueError):
                if attempt == 29:
                    raise InstallError(
                        "API, worker or frontend health failed. Run sudo serverhub doctor with api.env loaded and inspect journalctl -u serverhub-ai-api -u serverhub-ai-worker. Fix the diagnostic and rerun this command"
                    ) from None
                time.sleep(1)

    def apply(self, *, install_dependencies=False, owner="owner", owner_password=None, enable_broker=False):
        if self.root != Path("/") or os.geteuid() != 0:
            raise InstallError("--apply requires root and root=/; use --stage for isolated validation")
        from .coexistence import require_safe, write_claim, claim
        try:
            require_safe(root=self.root, units=self.units(), runner=self.runner)
            if claim(self.root) is None:
                write_claim(self.root)
        except (RuntimeError, ValueError) as error:
            raise InstallError(str(error)) from error
        directory = self.path("/var/lib/serverhub-install")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
        with (directory / "lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise InstallError("Another ServerHub installer is running") from None
            return self._apply_locked(install_dependencies, owner, owner_password, enable_broker)

    def _apply_locked(self, install_dependencies, owner, owner_password, enable_broker):
        journal = self.path("/var/lib/serverhub-install/state.json")
        if journal.exists():
            state = json.loads(journal.read_text())
            if bool(state.get("ai_identity", False)) != self.ai_identity:
                raise InstallError("Resume must use the original --ai-identity option; changing service identity requires a reviewed migration")
            if (state["role"], state["public_url"], state["trust_digest"]) != (
                self.role,
                self.public_url,
                self.trust_digest(),
            ):
                raise InstallError(
                    "Pending/completed installer belongs to another release or origin. Use the documented upgrade workflow; do not delete the install journal"
                )
        else:
            if self.path("/etc/serverhub/api.env").exists() or self.path("/etc/serverhub/node.yaml").exists():
                raise InstallError(
                    "Existing installation has no resume journal. Use scripts/repair-install.sh for a backed-up, credential-preserving upgrade"
                )
            state = {
                "format": 1,
                "ai_identity": self.ai_identity,
                "role": self.role,
                "public_url": self.public_url,
                "trust_digest": self.trust_digest(),
                "completed": [],
                "state": "installing",
                "release_id": "local-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
                "credentials": {name: secrets.token_urlsafe(32) for name in ("api", "worker", "migrate")},
                "owner": owner,
                "owner_password": owner_password or secrets.token_urlsafe(30),
            }
            self.write("/var/lib/serverhub-install/state.json", json.dumps(state), 0o600)
        self.preserve_configuration = True

        def persist():
            self.write("/var/lib/serverhub-install/state.json", json.dumps(state), 0o600)

        def phase(name, action):
            if name not in state["completed"]:
                state["phase"] = name
                persist()
                action()
                state["completed"].append(name)
                persist()

        activated = False
        was_installed = state.get("state") == "installed"
        try:
            report = check_compatibility(self.role, self.source)
            if not report["compatible"]:
                raise InstallError(
                    "Unsupported OS/architecture/Python. Controller requires Ubuntu 24.04 x86_64 and Python 3.12; run --check"
                )
            if install_dependencies and "dependencies" not in state["completed"]:
                packages = ["python3-venv", "ca-certificates", "iproute2", "procps", "util-linux", "bubblewrap", "git", "apparmor"]
                if self.role == "controller":
                    packages += ["postgresql-16", "postgresql-client-16"]
                phase(
                    "dependencies",
                    lambda: (
                        self._run(["apt-get", "update"], timeout=900),
                        self._run(
                            ["apt-get", "install", "-y", "--no-install-recommends", *packages], timeout=1800
                        ),
                    ),
                )
                report = check_compatibility(self.role, self.source)
            if not report["ready_for_apply"]:
                raise InstallError(
                    "Prerequisites or built artifacts missing. Run --check; build frontend/wheel or pass --install-dependencies as documented"
                )

            def accounts():
                selected = (
                    ACCOUNTS if self.role == "controller" else {"serverhub-ai-node": ACCOUNTS["serverhub-ai-node"]}
                )
                selected = dict(selected)
                if self.ai_identity and self.role == "controller":
                    selected["serverhub-ai"] = "/var/lib/serverhub-ai"
                for name, directory in selected.items():
                    try:
                        entry = pwd.getpwnam(name)
                        if (
                            entry.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"}
                            or entry.pw_dir != directory
                        ):
                            raise InstallError(
                                f"Existing {name} account has unexpected shell/home; inspect it before resuming"
                            )
                        memberships = {
                            grp.getgrgid(value).gr_name for value in os.getgrouplist(name, entry.pw_gid)
                        }
                        if memberships & {"sudo", "docker", "adm", "root"}:
                            raise InstallError(f"Existing {name} account has privileged group membership")
                    except KeyError:
                        self._run(
                            [
                                "useradd",
                                "--system",
                                "--user-group",
                                "--home-dir",
                                directory,
                                "--shell",
                                "/usr/sbin/nologin",
                                name,
                            ]
                        )
                    entry = pwd.getpwnam(name)
                    target = self.path(directory)
                    target.mkdir(parents=True, mode=0o700, exist_ok=True)
                    os.chown(target, entry.pw_uid, entry.pw_gid)
                    target.chmod(0o700)
                if self.ai_identity and self.role == "controller":
                    os.chown(self.path("/var/lib/serverhub-ai-worker"), pwd.getpwnam("serverhub-ai").pw_uid,
                             grp.getgrnam("serverhub-ai-worker").gr_gid)
                for directory, mode in (
                    ("/opt/serverhub", 0o755),
                    ("/var/backups/serverhub", 0o700),
                    ("/var/lib/serverhub-release", 0o700),
                    ("/var/lib/serverhub-recovery", 0o700),
                    ("/etc/serverhub", 0o755),
                    ("/var/lib/serverhub-status", 0o755),
                ):
                    target = self.path(directory)
                    target.mkdir(parents=True, mode=mode, exist_ok=True)
                    target.chmod(mode)

            phase("accounts", accounts)
            release = self.path("/opt/serverhub/releases/" + state["release_id"])

            def artifacts():
                release.mkdir(parents=True, mode=0o700, exist_ok=True)
                release.parent.chmod(0o755)
                release.chmod(0o700)
                wheels = sorted((self.source / "dist").glob("*.whl"))
                if len(wheels) != 1:
                    raise InstallError("dist must contain exactly one application wheel")
                for runtime in (release, self.path("/opt/serverhub/recovery-ai")):
                    runtime.mkdir(mode=0o700, exist_ok=True)
                    runtime.chmod(0o700)
                    self._run([sys.executable, "-m", "venv", str(runtime / "venv")])
                    self._run(
                        [
                            str(runtime / "venv/bin/pip"),
                            "install",
                            "--require-hashes",
                            "-r",
                            str(self.source / "requirements.lock"),
                        ],
                        timeout=1800,
                    )
                    self._run([str(runtime / "venv/bin/pip"), "install", "--no-deps", str(wheels[0])])
                if self.role == "controller":
                    shutil.copy2(self.source / "alembic.ini", release / "alembic.ini")
                    shutil.copytree(self.source / "migrations", release / "migrations", dirs_exist_ok=True)
                    shutil.copytree(self.source / "frontend/dist", release / "web", dirs_exist_ok=True)
                    from serverhub.diagnostics import verify_frontend_files

                    verify_frontend_files(release / "web")
                from .runtime_permissions import seal_runtime
                for runtime in (release, self.path('/opt/serverhub/recovery-ai')):
                    seal_runtime(runtime)
                (release / "installed.json").write_text(
                    json.dumps(
                        {
                            "manifest": {
                                "release_id": state["release_id"],
                                "schema_revision": "0005_priority",
                                "trust_boundary_digest": self.trust_digest(),
                            }
                        }
                    )
                )

                (release / "installed.json").chmod(0o644)

            phase("artifacts", artifacts)
            credentials = state["credentials"]

            def configure():
                node = pwd.getpwnam("serverhub-ai-node")
                self._configuration(
                    credentials["api"],
                    credentials["worker"],
                    credentials["migrate"],
                    node_uid=node.pw_uid,
                    node_gid=node.pw_gid,
                )
                for name in ("api", "worker", "node"):
                    target = self.path(
                        f"/etc/serverhub/{name}.env" if name != "node" else "/etc/serverhub/node.yaml"
                    )
                    if target.exists():
                        os.chown(target, 0, grp.getgrnam("serverhub-ai-" + name).gr_gid)
                        target.chmod(0o640)
                # These contain environment references, never secret values. Every
                # service can read, but none can replace or write, operator config.
                for filename in ("models.yaml", "integrations.yaml", "projects.yaml"):
                    target = self.path("/etc/serverhub/" + filename)
                    if target.exists():
                        os.chown(target, 0, 0)
                        target.chmod(0o644)

            phase("configuration", configure)
            environment = dict(
                os.environ,
                SERVERHUB_DATABASE_URL=f"postgresql+psycopg://serverhub_migrate:{credentials['migrate']}@127.0.0.1/serverhub",
                SERVERHUB_PUBLIC_URL=self.public_url,
                SERVERHUB_ALLOWED_ORIGINS=json.dumps([self.public_url]),
                SERVERHUB_STATE_DIR="/var/lib/serverhub-ai-migrate",
                SERVERHUB_RELEASE_DIR=str(release),
            )
            environment.pop("PYTHONPATH", None)
            environment.pop("PYTHONHOME", None)
            environment.pop("LD_PRELOAD", None)
            if self.role == "controller":

                def database():
                    self._run(["systemctl", "enable", "--now", "postgresql.service"])
                    roles = "\n".join(
                        f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='serverhub_{name}') THEN CREATE ROLE serverhub_{name} LOGIN PASSWORD '{password}'; END IF; END $$;"
                        for name, password in credentials.items()
                    )
                    self._run(
                        [
                            "runuser",
                            "-u",
                            "postgres",
                            "--",
                            "psql",
                            "-v",
                            "ON_ERROR_STOP=1",
                            "-d",
                            "postgres",
                        ],
                        stdin=roles,
                    )
                    result = self._run(
                        [
                            "runuser",
                            "-u",
                            "postgres",
                            "--",
                            "psql",
                            "-At",
                            "-d",
                            "postgres",
                            "-c",
                            "SELECT 1 FROM pg_database WHERE datname='serverhub'",
                        ]
                    )
                    if result.stdout.strip() != "1":
                        self._run(
                            [
                                "runuser",
                                "-u",
                                "postgres",
                                "--",
                                "createdb",
                                "--owner=serverhub_migrate",
                                "serverhub",
                            ]
                        )

                phase("database", database)
                phase(
                    "migrations",
                    lambda: self._run(
                        [
                            "runuser",
                            "-u",
                            "serverhub-ai-migrate",
                            "--",
                            str(release / "venv/bin/serverhub"),
                            "migrate",
                        ],
                        env=environment,
                        cwd=str(release),
                    ),
                )
                phase(
                    "database-grants",
                    lambda: self._run(
                        [
                            "runuser",
                            "-u",
                            "postgres",
                            "--",
                            "psql",
                            "-v",
                            "ON_ERROR_STOP=1",
                            "-d",
                            "serverhub",
                        ],
                        stdin=(self.source / "packaging/postgresql-grants.sql").read_text(),
                    ),
                )

                def bootstrap():
                    self._run(
                        [
                            "runuser",
                            "-u",
                            "serverhub-ai-migrate",
                            "--",
                            str(release / "venv/bin/serverhub"),
                            "create-user",
                            "--username",
                            state["owner"],
                            "--role",
                            "owner",
                            "--password-stdin",
                            "--if-absent",
                        ],
                        env=environment,
                        stdin=state["owner_password"] + "\n",
                        cwd=str(release),
                    )
                    self.write(
                        "/etc/serverhub/bootstrap-owner.txt",
                        f"username: {state['owner']}\npassword: {state['owner_password']}\nRemove this file after safely storing your credentials.\n",
                        0o600,
                    )

                phase("owner", bootstrap)
            self._activate(release)
            activated = True
            self._run(["systemctl", "daemon-reload"])
            if self.role == "controller":
                self._run(
                    [
                        "systemctl",
                        "enable",
                        "--now",
                        "serverhub-ai-api.service",
                        "serverhub-ai-worker.service",
                        "serverhub-ai-backup.timer",
                        "serverhub-ai-release-watchdog.timer",
                    ]
                )
                self._healthchecks(release)
            self._run(["systemctl", "enable", "--now", "serverhub-ai-recovery.timer", "serverhub-ai-operation-watchdog.timer"])
            if enable_broker:
                self._run(["systemctl", "enable", "--now", "serverhub-ai-broker.service"])
            state["state"] = "installed"
            state.pop("last_error", None)
            persist()
            return {
                "state": "installed",
                "public_url": self.public_url,
                "role": self.role,
                "release_id": state["release_id"],
                "onboarding": [
                    "Configure TLS reverse proxy; use an SSH tunnel for localhost onboarding.",
                    "Read /etc/serverhub/bootstrap-owner.txt as root and remove it after storing credentials.",
                    "Open Setup in the dashboard to connect Ollama, enroll a host and delegate an expiring policy.",
                ],
                "not_modified": ["firewall", "SSH", "VPN", "existing Docker workloads"],
            }
        except Exception as exc:
            state["state"], state["last_error"] = "interrupted", str(exc)
            persist()
            if activated and not was_installed:
                # No database/account deletion: preserve the exact credentials and
                # partial migration for an idempotent resume. Stop newly activated
                # services so a failed first install is not left serving traffic.
                try:
                    self._run(
                        [
                            "systemctl",
                            "stop",
                            "serverhub-ai-api.service",
                            "serverhub-ai-worker.service",
                            "serverhub-ai-backup.timer",
                            "serverhub-ai-release-watchdog.timer",
                        ]
                    )
                except InstallError:
                    pass
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--preflight", action="store_true", help="Read-only coexistence conflict inspection before building or installing")
    action.add_argument("--check", action="store_true")
    action.add_argument("--plan", action="store_true")
    action.add_argument("--stage", action="store_true")
    action.add_argument("--apply", action="store_true")
    parser.add_argument("--root", default="/")
    parser.add_argument("--source", default=str(Path(__file__).resolve().parents[3]))
    parser.add_argument("--role", choices=["controller", "node"], default="controller")
    parser.add_argument("--public-url", default="https://serverhub.local")
    parser.add_argument("--install-dependencies", action="store_true")
    parser.add_argument("--enable-broker", action="store_true")
    parser.add_argument("--ai-identity", action="store_true", help="Run worker as dedicated serverhub-ai; no sudo/Docker/broker privileges are granted")
    parser.add_argument("--owner", default="owner")
    parser.add_argument("--owner-password-stdin", action="store_true")
    args = parser.parse_args(argv)
    try:
        installer = Installer(args.source, root=args.root, role=args.role, public_url=args.public_url, ai_identity=args.ai_identity)
        if args.preflight:
            from .coexistence import require_safe
            report = require_safe(root=installer.root, units=installer.units(), live=installer.root == Path('/'))
        elif args.check:
            report = check_compatibility(args.role, args.source)
        elif args.plan:
            report = installer.plan()
        elif args.stage:
            report = installer.stage()
        else:
            password = sys.stdin.readline().rstrip("\n") if args.owner_password_stdin else None
            if password is not None and len(password) < 16:
                raise InstallError("owner password must contain at least 16 characters")
            report = installer.apply(
                install_dependencies=args.install_dependencies,
                owner=args.owner,
                owner_password=password,
                enable_broker=args.enable_broker,
            )
        print(json.dumps(report, indent=2))
        return 0
    except (InstallError, OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"Installation failed: {error}\n")


if __name__ == "__main__":
    main()
