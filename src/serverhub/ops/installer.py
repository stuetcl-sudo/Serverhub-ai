"""Native installer. --stage writes an inspectable tree without changing the host."""
from __future__ import annotations

import argparse
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
    "serverhub-api": "/var/lib/serverhub-api",
    "serverhub-worker": "/var/lib/serverhub-worker",
    "serverhub-node": "/var/lib/serverhub-node",
    "serverhub-migrate": "/var/lib/serverhub-migrate",
}
TRUST_FILES = ["packaging/postgresql-grants.sql", "packaging/trust-boundaries.json",
               "src/serverhub/auth.py", "src/serverhub/policy.py", "src/serverhub/audit.py",
               "src/serverhub/jobs.py", "src/serverhub/node_api.py", "src/serverhub/node/broker.py",
               "src/serverhub/mcp.py", "src/serverhub/oauth_models.py", "src/serverhub/main.py",
               "src/serverhub/settings.py", "src/serverhub/integrations/registry.py", "src/serverhub/ai/providers.py",
               "src/serverhub/node/watchdog.py", "src/serverhub/ops/installer.py",
               "src/serverhub/ops/release.py", "src/serverhub/ops/backup.py"]
CONTROLLER_UNITS = ["serverhub-api.service", "serverhub-worker.service", "serverhub-backup.service", "serverhub-backup.timer",
                    "serverhub-release-watchdog.service", "serverhub-release-watchdog.timer"]
NODE_UNITS = ["serverhub-node.service", "serverhub-broker.service", "serverhub-recovery.service", "serverhub-recovery.timer"]


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
    controller_ok = operating.get("ID") == "ubuntu" and operating.get("VERSION_ID") == "24.04" and architecture in {"x86_64", "amd64"}
    node_ok = operating.get("ID") in {"ubuntu", "debian"} and architecture in {"x86_64", "amd64", "aarch64", "arm64"}
    python_ok = sys.version_info >= (3, 12)
    tools = ["python3", "systemctl", "useradd", "runuser"]
    if role == "controller":
        tools += ["psql", "pg_dump", "pg_restore", "createdb", "dropdb"]
    dependencies = {tool: shutil.which(tool) is not None for tool in tools}
    artifacts = {}
    if source:
        source = Path(source)
        artifacts = {"wheel": bool(list((source / "dist").glob("*.whl"))), "requirements.lock": (source / "requirements.lock").is_file(),
                     "frontend": (source / "frontend/dist/index.html").is_file() if role == "controller" else True}
    systemd_running = Path("/run/systemd/system").is_dir()
    return {"os": operating.get("PRETTY_NAME", "unknown"), "architecture": architecture,
            "python": platform.python_version(), "role": role, "compatible": (controller_ok if role == "controller" else node_ok) and python_ok,
            "dependencies": dependencies, "artifacts": artifacts, "systemd_running": systemd_running,
            "ready_for_apply": (controller_ok if role == "controller" else node_ok) and python_ok and all(dependencies.values()) and all(artifacts.values()) and systemd_running}


class Installer:
    def __init__(self, source: str | Path, *, root="/", role="controller", public_url="https://serverhub.local", runner=None):
        self.source = Path(source).resolve()
        self.root = Path(root).absolute()
        self.role = role
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
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)
        path.chmod(mode)
        self.writes.append({"path": value, "mode": oct(mode), "sha256": hashlib.sha256(data.encode()).hexdigest()})
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
        return {"role": self.role, "root": str(self.root), "public_url": self.public_url,
                "actions": ["validate Ubuntu/Debian and Python 3.12", "create dedicated nologin service accounts", "install locked wheel in root-owned native virtualenv",
                            "write role-specific protected configuration", "configure local PostgreSQL roles and run migrations" if self.role == "controller" else "configure HTTPS node enrollment",
                            "install hardened systemd units", "initialize owner credentials" if self.role == "controller" else "register individual node identity",
                            "start services and run local healthcheck"],
                "units": self.units(), "trust_boundary_digest": self.trust_digest(),
                "never_changes": ["firewall", "SSH", "VPN", "existing Docker workloads", "existing reverse proxy", "unrelated databases"]}

    def stage(self, *, api_password="STAGING_ONLY_NOT_A_CREDENTIAL", worker_password="STAGING_ONLY_NOT_A_CREDENTIAL", migrate_password="STAGING_ONLY_NOT_A_CREDENTIAL", node_uid=999, node_gid=999):
        if self.root.resolve() == Path("/"):
            raise InstallError("--stage requires a separate --root directory")
        return self._configuration(api_password, worker_password, migrate_password, node_uid=node_uid, node_gid=node_gid, staged=True)

    def _configuration(self, api_password, worker_password, migrate_password, *, node_uid, node_gid=None, staged=False):
        for unit in self.units():
            self.write("/etc/systemd/system/" + unit, (self.source / "packaging/systemd" / unit).read_text())
        self.write("/etc/serverhub/trust-boundaries.sha256", self.trust_digest() + "\n")
        # Python modules share one interpreter and can monkey-patch each other.
        # Anchor the whole package, rather than trusting a manifest's claim that
        # only selected security modules remained unchanged.
        code_hashes = {str(path.relative_to(self.source / "src")): hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in sorted((self.source / "src/serverhub").rglob("*.py"))}
        self.write("/etc/serverhub/trusted-code-hashes.json", json.dumps({"format": 1, "files": code_hashes}, sort_keys=True) + "\n", 0o600)
        self.write("/etc/serverhub/trust-boundaries.json", (self.source / "packaging/trust-boundaries.json").read_text(), 0o600)
        origins = json.dumps([self.public_url], separators=(",", ":"))
        common = (f"SERVERHUB_DEV_MODE=false\nSERVERHUB_PUBLIC_URL={self.public_url}\n"
                  f"SERVERHUB_ALLOWED_ORIGINS='{origins}'\nSERVERHUB_FRONTEND_DIR=/opt/serverhub/current/web\n")
        if self.role == "controller":
            for name, password in (("api", api_password), ("worker", worker_password)):
                content = common + f"SERVERHUB_DATABASE_URL=postgresql+psycopg://serverhub_{name}:{password}@127.0.0.1/serverhub\nSERVERHUB_STATE_DIR=/var/lib/serverhub-{name}\n"
                if name == "api":
                    content += "SERVERHUB_SECRET_KEY=" + ("STAGING_ONLY" if staged else secrets.token_urlsafe(48)) + "\n"
                self.write(f"/etc/serverhub/{name}.env", content, 0o640)
            self.write("/etc/serverhub/recovery.env", common + f"SERVERHUB_DATABASE_URL=postgresql+psycopg://serverhub_migrate:{migrate_password}@127.0.0.1/serverhub\n", 0o600)
            self.write("/etc/serverhub/models.yaml", (self.source / "packaging/config/models.yaml").read_text(), 0o644)
            self.write("/etc/serverhub/integrations.yaml", (self.source / "packaging/config/integrations.yaml").read_text(), 0o644)
            self.write("/etc/serverhub/projects.yaml", (self.source / "packaging/config/projects.yaml").read_text(), 0o644)
        self.write("/etc/serverhub/node.yaml", f"controller_url: {self.public_url}\nname: {platform.node() or 'serverhub'}\nstate_dir: /var/lib/serverhub-node\ninterval: 60\nbroker_socket: /run/serverhub-broker/control.sock\n# Add a one-time enrollment_token from the owner UI before enabling this node.\n", 0o640)
        self.write("/etc/serverhub/broker.yaml", f"socket: /run/serverhub-broker/control.sock\nallowed_uids: [{node_uid}]\nsocket_gid: {node_gid if node_gid is not None else node_uid}\nallowed_services: []\nallowed_containers: []\ncompose_projects: {{}}\nnetwork_targets: {{}}\nallowed_scan_images: []\nrecovery_directory: /var/lib/serverhub-recovery\n", 0o600)
        self.write("/etc/serverhub/README", "Root-owned configuration. API, worker, and node identities are separate.\nModels/integrations are disabled until the owner supplies documented endpoints and secret environment references.\nBroker action allowlists are empty by default. No SSH, firewall or VPN changes are made by installation.\n")
        self.write("/var/lib/serverhub-status/backups.json", '{"backups": [], "updated_at": null}\n')
        if staged:
            self.write("/install-plan.json", json.dumps(self.plan(), indent=2) + "\n")
            self.write("/staged-files.json", json.dumps(self.writes, indent=2) + "\n")
        return {"state": "staged" if staged else "configured", "root": str(self.root), "files": self.writes, "units": self.units()}

    def _run(self, command, *, env=None, stdin=None, timeout=600):
        try:
            return self.runner(command, env=env, input=stdin, text=True, capture_output=True, check=True, timeout=timeout)
        except (subprocess.SubprocessError, OSError) as error:
            raise InstallError(f"{Path(command[0]).name} failed; see protected installation logs") from error

    def apply(self, *, install_dependencies=False, owner="owner", owner_password=None, enable_broker=False):
        if self.root != Path("/") or os.geteuid() != 0:
            raise InstallError("--apply requires root and root=/; use --stage for isolated validation")
        if self.path("/etc/serverhub/api.env").exists() or self.path("/etc/serverhub/node.yaml").exists():
            raise InstallError("an installation already exists; use the controlled upgrade procedure")
        report = check_compatibility(self.role, self.source)
        if not report["compatible"]:
            raise InstallError("unsupported OS, architecture, or Python; consult installation guide")
        if install_dependencies:
            packages = ["python3-venv", "ca-certificates", "iproute2", "procps", "util-linux"]
            if self.role == "controller":
                packages += ["postgresql", "postgresql-client"]
            self._run(["apt-get", "update"], timeout=900)
            self._run(["apt-get", "install", "-y", "--no-install-recommends", *packages], timeout=1800)
            report = check_compatibility(self.role, self.source)
        if not report["ready_for_apply"]:
            raise InstallError("required tools, built release artifacts, or running systemd are missing; run --check")
        accounts = ACCOUNTS if self.role == "controller" else {"serverhub-node": ACCOUNTS["serverhub-node"]}
        for name, directory in accounts.items():
            try:
                entry = pwd.getpwnam(name)
                if entry.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"} or entry.pw_dir != directory:
                    raise InstallError("existing service account has unexpected privileges or home")
                memberships = {grp.getgrgid(value).gr_name for value in os.getgrouplist(name, entry.pw_gid)}
                if memberships & {"sudo", "docker", "adm", "root"}:
                    raise InstallError("service account belongs to a privileged group")
            except KeyError:
                self._run(["useradd", "--system", "--user-group", "--home-dir", directory, "--shell", "/usr/sbin/nologin", name])
            path = self.path(directory)
            path.mkdir(parents=True, mode=0o700, exist_ok=True)
            user = pwd.getpwnam(name)
            os.chown(path, user.pw_uid, user.pw_gid)
            path.chmod(0o700)
        for directory, mode in (("/opt/serverhub", 0o755), ("/var/backups/serverhub", 0o700), ("/var/lib/serverhub-release", 0o700), ("/var/lib/serverhub-recovery", 0o700), ("/etc/serverhub", 0o755), ("/var/lib/serverhub-status", 0o755)):
            self.path(directory).mkdir(parents=True, mode=mode, exist_ok=True)
            self.path(directory).chmod(mode)
        api_password, worker_password, migrate_password = [secrets.token_urlsafe(32) for _ in range(3)]
        release_id = "local-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        release = self.path("/opt/serverhub/releases/" + release_id)
        release.mkdir(parents=True, mode=0o755)
        self._run([sys.executable, "-m", "venv", str(release / "venv")])
        self._run([str(release / "venv/bin/pip"), "install", "--require-hashes", "-r", str(self.source / "requirements.lock")], timeout=1800)
        wheels = sorted((self.source / "dist").glob("*.whl"))
        if len(wheels) != 1:
            raise InstallError("dist must contain exactly one application wheel")
        self._run([str(release / "venv/bin/pip"), "install", "--no-deps", str(wheels[0])])
        # Independent recovery tools must survive a broken current-release switch.
        recovery = self.path("/opt/serverhub/recovery")
        recovery.mkdir(mode=0o755)
        self._run([sys.executable, "-m", "venv", str(recovery / "venv")])
        self._run([str(recovery / "venv/bin/pip"), "install", "--require-hashes", "-r", str(self.source / "requirements.lock")], timeout=1800)
        self._run([str(recovery / "venv/bin/pip"), "install", "--no-deps", str(wheels[0])])
        if self.role == "controller":
            shutil.copy2(self.source / "alembic.ini", release / "alembic.ini")
            shutil.copytree(self.source / "migrations", release / "migrations")
        if self.role == "controller":
            shutil.copytree(self.source / "frontend/dist", release / "web")
        installed = {"manifest": {"release_id": release_id, "schema_revision": "0003_schedules", "trust_boundary_digest": self.trust_digest(), "source": "explicit owner local installation"}}
        (release / "installed.json").write_text(json.dumps(installed, indent=2) + "\n")
        self.path("/opt/serverhub/current").symlink_to(release)
        self._configuration(api_password, worker_password, migrate_password, node_uid=pwd.getpwnam("serverhub-node").pw_uid, node_gid=pwd.getpwnam("serverhub-node").pw_gid)
        for name in ("api", "worker", "node"):
            target = self.path(f"/etc/serverhub/{name}.env" if name != "node" else "/etc/serverhub/node.yaml")
            if target.exists():
                target.chown(0) if hasattr(target, "chown") else None
                os.chown(target, 0, grp.getgrnam("serverhub-" + name).gr_gid)
        if self.role == "controller":
            self._run(["systemctl", "enable", "--now", "postgresql.service"])
            roles = "\n".join(f"CREATE ROLE serverhub_{name} LOGIN PASSWORD '{password}';" for name, password in [("migrate", migrate_password), ("api", api_password), ("worker", worker_password)])
            self._run(["runuser", "-u", "postgres", "--", "psql", "-v", "ON_ERROR_STOP=1", "-d", "postgres"], stdin=roles)
            self._run(["runuser", "-u", "postgres", "--", "createdb", "--owner=serverhub_migrate", "serverhub"])
            environment = dict(os.environ, SERVERHUB_DATABASE_URL=f"postgresql+psycopg://serverhub_migrate:{migrate_password}@127.0.0.1/serverhub", SERVERHUB_PUBLIC_URL=self.public_url,
                               SERVERHUB_ALLOWED_ORIGINS=json.dumps([self.public_url]), SERVERHUB_STATE_DIR="/var/lib/serverhub-migrate")
            self._run(["runuser", "-u", "serverhub-migrate", "--", str(release / "venv/bin/serverhub"), "migrate"], env=environment)
            self._run(["runuser", "-u", "postgres", "--", "psql", "-v", "ON_ERROR_STOP=1", "-d", "serverhub"], stdin=(self.source / "packaging/postgresql-grants.sql").read_text())
            password = owner_password or secrets.token_urlsafe(30)
            self._run(["runuser", "-u", "serverhub-migrate", "--", str(release / "venv/bin/serverhub"), "create-user", "--username", owner, "--role", "owner", "--password-stdin"], env=environment, stdin=password + "\n")
            if owner_password is None:
                self.write("/etc/serverhub/bootstrap-owner.txt", f"username: {owner}\npassword: {password}\nRemove this file after safely storing your credentials.\n", 0o600)
            # Bootstrap owner is a human credential. The worker never receives it.
        self._run(["systemctl", "daemon-reload"])
        if self.role == "controller":
            self._run(["systemctl", "enable", "--now", "serverhub-api.service", "serverhub-worker.service", "serverhub-backup.timer", "serverhub-release-watchdog.timer"])
            self._run([str(release / "venv/bin/serverhub"), "health", "--url", "http://127.0.0.1:9080"])
        self._run(["systemctl", "enable", "--now", "serverhub-recovery.timer"])
        if enable_broker:
            self._run(["systemctl", "enable", "--now", "serverhub-broker.service"])
        return {"state": "installed", "public_url": self.public_url, "role": self.role, "release_id": release_id,
                "onboarding": ["Configure the provided TLS reverse proxy example for this origin.", "Retrieve owner credentials with sudo cat /etc/serverhub/bootstrap-owner.txt, then remove that file." if self.role == "controller" else "Obtain a one-time enrollment token from the controller owner.",
                               "Add a one-time enrollment token to /etc/serverhub/node.yaml and enable serverhub-node.service.", "Configure providers and explicit expiring policies before enabling repairs."],
                "not_modified": ["firewall", "SSH", "VPN", "existing Docker workloads"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
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
    parser.add_argument("--owner", default="owner")
    parser.add_argument("--owner-password-stdin", action="store_true")
    args = parser.parse_args(argv)
    try:
        installer = Installer(args.source, root=args.root, role=args.role, public_url=args.public_url)
        if args.check:
            report = check_compatibility(args.role, args.source)
        elif args.plan:
            report = installer.plan()
        elif args.stage:
            report = installer.stage()
        else:
            password = sys.stdin.readline().rstrip("\n") if args.owner_password_stdin else None
            if password is not None and len(password) < 16:
                raise InstallError("owner password must contain at least 16 characters")
            report = installer.apply(install_dependencies=args.install_dependencies, owner=args.owner, owner_password=password, enable_broker=args.enable_broker)
        print(json.dumps(report, indent=2))
        return 0
    except (InstallError, OSError, ValueError) as error:
        parser.exit(1, f"Installation failed: {error}\n")


if __name__ == "__main__":
    main()
