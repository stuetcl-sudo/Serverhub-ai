"""Signed native releases, protected checkpoints, and independent rollback."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import time
import uuid
import zipfile
from pathlib import Path

from .backup import BackupManager, digest
from serverhub.node.broker import trusted_file, BrokerDenied


class ReleaseError(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def safe_extract(archive: Path, destination: Path):
    """No links, devices, traversal, or existing-file substitution in artifacts."""
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as source:
        members = source.getmembers()
        if len(members) > 50000 or sum(member.size for member in members) > 1024 * 1024 * 1024:
            raise ReleaseError("release archive exceeds extraction limits")
        seen = set()
        for member in members:
            normalized = str(Path(member.name))
            target = destination / member.name
            if (normalized in seen or Path(member.name).is_absolute() or ".." in Path(member.name).parts
                    or not (member.isfile() or member.isdir())
                    or not target.resolve().is_relative_to(destination.resolve())
                    or target.exists()):
                raise ReleaseError("unsafe release archive member")
            seen.add(normalized)
            member.mode = 0o755 if member.isdir() else 0o644
        source.extractall(destination, members=members, filter="data")


class ReleaseManager:
    SERVICES = ("serverhub-ai-api.service", "serverhub-ai-worker.service")

    def __init__(self, install_root="/opt/serverhub", state_root="/var/lib/serverhub-release", *,
                 public_key="/etc/serverhub/trusted-release-key.pem", trust_digest="/etc/serverhub/trust-boundaries.sha256",
                 require_root=True, runner=None, clock=None,
                 code_hashes="/etc/serverhub/trusted-code-hashes.json"):
        self.install_root = Path(install_root)
        self.state_root = Path(state_root)
        self.public_key = Path(public_key)
        self.trust_digest = Path(trust_digest)
        self.code_hashes = Path(code_hashes)
        self.require_root = require_root
        self.runner = runner or subprocess.run
        self.clock = clock or time.time

    def _protect(self):
        if self.require_root and self.install_root == Path('/opt/serverhub'):
            from .coexistence import claim, require_safe
            from .installer import CONTROLLER_UNITS, NODE_UNITS
            if claim() is None:
                raise ReleaseError('Namespace ownership missing; use reviewed unit migration before upgrade/rollback')
            require_safe(units=CONTROLLER_UNITS + NODE_UNITS, live=False)
        if self.require_root and os.geteuid() != 0:
            raise ReleaseError("release operations require the independent root maintenance account")
        for path in (self.install_root, self.state_root):
            if not path.is_absolute() or path.is_symlink():
                raise ReleaseError("release directories must be absolute and not symlinks")
            path.mkdir(parents=True, exist_ok=True, mode=0o700 if path == self.state_root else 0o755)
            info = path.stat()
            if self.require_root and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022):
                raise ReleaseError("release directories must be root-owned and not writable by service users")

    def _run(self, command, timeout=300):
        try:
            return self.runner(command, check=True, text=True, capture_output=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as error:
            raise ReleaseError(f"{Path(command[0]).name} failed; consult protected maintenance logs") from error

    def verify_bundle(self, bundle: str | Path) -> dict:
        self._protect()
        bundle = Path(bundle)
        if bundle.is_symlink() or not bundle.is_dir():
            raise ReleaseError("release bundle must be a directory")
        for path in bundle.rglob("*"):
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise ReleaseError("release bundle must contain only regular files and directories")
        if self.require_root:
            try:
                for path in bundle.rglob("*"):
                    if path.is_file():
                        trusted_file(path)
                trusted_file(self.public_key)
                trusted_file(self.trust_digest)
            except (BrokerDenied, OSError) as error:
                raise ReleaseError("release artifacts and trust anchors must be root-owned and immutable to service users") from error
        manifest = json.loads((bundle / "release.json").read_text())
        if manifest.get("format") != 1 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", manifest.get("release_id", "")):
            raise ReleaseError("invalid release manifest")
        if not self.public_key.is_file() or self.public_key.is_symlink():
            raise ReleaseError("a trusted release signing key must be installed by the owner")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        try:
            public = serialization.load_pem_public_key(self.public_key.read_bytes())
            if not isinstance(public, Ed25519PublicKey):
                raise ReleaseError("release signing key must be Ed25519")
            public.verify(base64.b64decode((bundle / "release.sig").read_text().strip(), validate=True), canonical(manifest))
        except (ValueError, InvalidSignature) as error:
            raise ReleaseError("release signature verification failed") from error
        expected_trust = self.trust_digest.read_text().strip()
        if manifest.get("trust_boundary_digest") != expected_trust:
            raise ReleaseError("release changes protected trust boundaries; explicit owner review is required")
        files = manifest.get("files", {})
        if not all(item in files for item in ("application.whl", "requirements.lock", "web.tar.gz", "alembic.ini", "migrations.tar.gz")):
            raise ReleaseError("release bundle is missing a required artifact")
        actual = {str(path.relative_to(bundle)) for path in bundle.rglob("*") if path.is_file()}
        if actual != set(files) | {"release.json", "release.sig"}:
            raise ReleaseError("release contains unlisted or missing files")
        for name, checksum in files.items():
            path = bundle / name
            if Path(name).is_absolute() or ".." in Path(name).parts or digest(path) != checksum:
                raise ReleaseError("release artifact checksum failed")
        # Manifest claims alone do not prove that protected modules are unchanged.
        # Compare actual wheel bytes with the independent initial-install anchor.
        if self.require_root or self.code_hashes.is_file():
            try:
                if self.require_root:
                    trusted_file(self.code_hashes)
                anchor = json.loads(self.code_hashes.read_text())
                if anchor.get("format") != 1 or not anchor.get("files"):
                    raise ValueError("invalid code integrity anchor")
                with zipfile.ZipFile(bundle / "application.whl") as wheel:
                    if len(wheel.namelist()) != len(set(wheel.namelist())):
                        raise ValueError("duplicate wheel members")
                    packaged = {name for name in wheel.namelist() if name.startswith("serverhub/") and not name.endswith("/")}
                    if packaged != set(anchor["files"]):
                        raise ValueError("candidate adds or removes package code")
                    for name in wheel.namelist():
                        if not name.startswith("serverhub/") and not re.fullmatch(r"serverhub_ai_os-[^/]+\.dist-info/(METADATA|WHEEL|RECORD|entry_points\.txt|licenses/LICENSE)", name):
                            raise ValueError("unexpected wheel installation payload")
                    entrypoints = [name for name in wheel.namelist() if name.endswith(".dist-info/entry_points.txt")]
                    for name in entrypoints:
                        import configparser
                        configuration = configparser.ConfigParser()
                        configuration.read_string(wheel.read(name).decode())
                        if configuration.sections() != ["console_scripts"] or dict(configuration["console_scripts"]) != {"serverhub": "serverhub.cli:main"}:
                            raise ValueError("candidate changes executable entry points")
                    for module, checksum in anchor["files"].items():
                        if not module.startswith("serverhub/") or ".." in Path(module).parts:
                            raise ValueError("invalid anchored module")
                        if hashlib.sha256(wheel.read(module)).hexdigest() != checksum:
                            raise ValueError("protected module changed")
            except (OSError, ValueError, KeyError, zipfile.BadZipFile, BrokerDenied) as error:
                raise ReleaseError("candidate changes protected code or lacks the independent code anchor; explicit offline owner review is required") from error
        if not manifest.get("schema_revision") or not manifest.get("validation", {}).get("passed"):
            raise ReleaseError("release requires a schema revision and successful independent validation")
        return manifest

    def prepare(self, bundle: str | Path) -> dict:
        manifest = self.verify_bundle(bundle)
        bundle = Path(bundle)
        release = self.install_root / "releases" / manifest["release_id"]
        if release.exists():
            raise ReleaseError("release directory already exists")
        release.mkdir(parents=True, mode=0o700)
        try:
            self._run(["python3", "-m", "venv", str(release / "venv")])
            argv = [str(release / "venv/bin/pip"), "install", "--require-hashes", "-r", str(bundle / "requirements.lock")]
            if (bundle / "wheels").is_dir():
                argv.extend(["--no-index", "--find-links", str(bundle / "wheels")])
            self._run(argv, timeout=1800)
            # A wheel filename must carry its distribution metadata; artifact is renamed only in bundle.
            import zipfile
            with zipfile.ZipFile(bundle / "application.whl") as wheel:
                metadata = [name for name in wheel.namelist() if name.endswith(".dist-info/WHEEL")]
                if len(metadata) != 1:
                    raise ReleaseError("invalid application wheel")
                wheel_name = metadata[0].split(".dist-info/")[0] + "-py3-none-any.whl"
            staged_wheel = release / wheel_name
            shutil.copyfile(bundle / "application.whl", staged_wheel)
            self._run([str(release / "venv/bin/pip"), "install", "--no-deps", str(staged_wheel)])
            safe_extract(bundle / "web.tar.gz", release / "web")
            safe_extract(bundle / "migrations.tar.gz", release / "migrations")
            shutil.copyfile(bundle / "alembic.ini", release / "alembic.ini")
            if not (release / "web/index.html").is_file():
                raise ReleaseError("web archive must contain index.html at its root")
            installed = {"manifest": manifest, "manifest_sha256": hashlib.sha256(canonical(manifest)).hexdigest(), "prepared_at": self.clock()}
            from .runtime_permissions import seal_runtime
            seal_runtime(release, require_root=self.require_root)
            (release / "installed.json").write_text(json.dumps(installed, indent=2) + "\n")
            (release / "installed.json").chmod(0o644)
            return {"release_id": manifest["release_id"], "state": "prepared", "path": str(release)}
        except BaseException:
            shutil.rmtree(release, ignore_errors=True)
            raise

    def _write_journal(self, value):
        temporary = self.state_root / ".pending.tmp"
        temporary.write_text(json.dumps(value, indent=2) + "\n")
        temporary.chmod(0o600)
        os.replace(temporary, self.state_root / "pending.json")

    def _switch(self, target: Path):
        if not target.is_dir() or not target.resolve().is_relative_to((self.install_root / "releases").resolve()):
            raise ReleaseError("release target is outside the protected installation")
        temporary = self.install_root / (".current-" + uuid.uuid4().hex)
        temporary.symlink_to(target)
        os.replace(temporary, self.install_root / "current")

    def activate(self, release_id: str, database_url: str, *, grace_seconds=180, backup_destination="/var/backups/serverhub") -> dict:
        self._protect()
        if not 30 <= grace_seconds <= 900:
            raise ReleaseError("release verification grace period must be 30–900 seconds")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", release_id):
            raise ReleaseError("invalid release identifier")
        pending = self.state_root / "pending.json"
        if pending.exists() and json.loads(pending.read_text()).get("state") == "armed":
            raise ReleaseError("an unverified release is already pending")
        current = self.install_root / "current"
        if not current.is_symlink():
            raise ReleaseError("activation requires an existing installed release")
        previous = current.resolve()
        release = self.install_root / "releases" / release_id
        installed = json.loads((release / "installed.json").read_text())
        previous_installed = json.loads((previous / "installed.json").read_text())
        if installed["manifest"]["schema_revision"] != previous_installed["manifest"]["schema_revision"]:
            raise ReleaseError("schema-changing upgrades require the documented offline migration procedure")
        backup = BackupManager(backup_destination, require_root=self.require_root).create(database_url, ["/etc/serverhub"])
        journal = {"state": "armed", "previous": str(previous), "candidate": str(release), "deadline": self.clock() + grace_seconds,
                   "backup_id": backup["id"], "release_id": release_id}
        self._write_journal(journal)  # Independent timer sees this before activation.
        try:
            self._switch(release)
            self._run(["systemctl", "restart", *self.SERVICES])
            self._run(["systemctl", "try-restart", "serverhub-ai-broker.service", "serverhub-ai-node.service"])
            from .installer import Installer
            url, ca = Installer(release)._health_configuration()
            self._run([str(release / "venv/bin/serverhub"), "health", "--url", url,
                       *(["--ca-file", ca] if ca else [])], timeout=60)
            journal["state"] = "verified"
            journal["verified_at"] = self.clock()
            self._write_journal(journal)
            return journal
        except BaseException:
            self._rollback(journal)
            raise

    def _rollback(self, journal):
        self._switch(Path(journal["previous"]))
        self._run(["systemctl", "restart", *self.SERVICES])
        self._run(["systemctl", "try-restart", "serverhub-ai-broker.service", "serverhub-ai-node.service"])
        journal["state"] = "reverted"
        journal["reverted_at"] = self.clock()
        self._write_journal(journal)
        return journal

    def watchdog(self):
        self._protect()
        path = self.state_root / "pending.json"
        if not path.exists():
            return {"state": "idle"}
        journal = json.loads(path.read_text())
        if journal.get("state") == "armed" and journal["deadline"] <= self.clock():
            return self._rollback(journal)
        return {"state": journal.get("state", "invalid"), "deadline": journal.get("deadline")}

    def rollback(self):
        self._protect()
        path = self.state_root / "pending.json"
        if not path.exists():
            raise ReleaseError("no previous release checkpoint exists")
        return self._rollback(json.loads(path.read_text()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["verify", "prepare", "activate", "rollback", "watchdog"])
    parser.add_argument("--bundle")
    parser.add_argument("--release")
    parser.add_argument("--install-root", default="/opt/serverhub")
    parser.add_argument("--state-root", default="/var/lib/serverhub-release")
    parser.add_argument("--database-url-env", default="SERVERHUB_DATABASE_URL")
    args = parser.parse_args()
    manager = ReleaseManager(args.install_root, args.state_root)
    try:
        if args.action == "verify":
            result = manager.verify_bundle(args.bundle or "")
        elif args.action == "prepare":
            result = manager.prepare(args.bundle or "")
        elif args.action == "activate":
            result = manager.activate(args.release or "", os.environ[args.database_url_env])
        elif args.action == "rollback":
            result = manager.rollback()
        else:
            result = manager.watchdog()
        print(json.dumps(result, indent=2))
    except (ReleaseError, OSError, KeyError, ValueError) as error:
        parser.exit(1, f"Release operation failed: {error}\n")


if __name__ == "__main__":
    main()
