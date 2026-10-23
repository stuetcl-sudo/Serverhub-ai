"""Explicit local-root upgrade of an existing installation, with config/DB backup.

Unlike autonomous signed releases, this command intentionally accepts reviewed
trust-boundary changes from a local source checkout. It is never an AI tool.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import time
from datetime import datetime, timezone
from uuid import uuid4

from serverhub.node.broker import trusted_file
from .installer import Installer, InstallError
from .backup import BackupManager


def read_environment(path):
    result = {}
    for line in trusted_file(path).read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, value = line.split("=", 1)
        if not name.startswith("SERVERHUB_"):
            raise InstallError("Unexpected environment key in protected configuration")
        result[name] = value.strip("'\"")
    return result


def protect_model_fallback(path):
    """An obsolete/invalid fallback must not prevent owner access to new Setup.

    Never relax the permissions of a document that failed secret-free schema
    validation. The owner can provision a database route after the upgrade.
    """
    path = trusted_file(path)  # rejects symlinks/unsafe ancestors before chmod
    from serverhub.ai.providers import load_routes

    try:
        load_routes(path)
    except (ValueError, OSError):
        os.chown(path, 0, 0)
        path.chmod(0o600)
        return "needs_setup"
    os.chown(path, 0, 0)
    path.chmod(0o644)
    return "readable_validated_fallback"


def repair(source):
    if os.geteuid() != 0:
        raise InstallError("Run repair-install.sh as root on the controller")
    source = Path(source).resolve()
    env = read_environment("/etc/serverhub/recovery.env")
    api = read_environment("/etc/serverhub/api.env")
    public_url = api["SERVERHUB_PUBLIC_URL"]
    installer = Installer(source, public_url=public_url)
    current = Path("/opt/serverhub/current")
    previous = current.resolve(strict=True)
    if not previous.is_relative_to(Path("/opt/serverhub/releases")):
        raise InstallError("Current release is outside the native release directory")
    backup = BackupManager().create(env["SERVERHUB_DATABASE_URL"], [Path("/etc/serverhub")])
    snapshots = {}
    for path in [*Path("/etc/serverhub").glob("*"), *Path("/etc/systemd/system").glob("serverhub-*")]:
        if path.is_file() and not path.is_symlink():
            info = path.stat()
            snapshots[path] = (path.read_bytes(), info.st_mode & 0o777, info.st_uid, info.st_gid)
    release = Path("/opt/serverhub/releases") / (
        "repair-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:6]
    )
    release.mkdir(mode=0o755)
    from .release import ReleaseManager

    recovery = ReleaseManager()
    recovery._protect()
    pending = recovery.state_root / "pending.json"
    if pending.exists() and json.loads(pending.read_text()).get("state") == "armed":
        raise InstallError("Another release is awaiting verification; finish or roll it back before repair")
    recovery_journal = None
    try:
        wheels = sorted((source / "dist").glob("*.whl"))
        if len(wheels) != 1:
            raise InstallError("Build exactly one wheel before repair/upgrade")
        installer._run([sys.executable, "-m", "venv", str(release / "venv")])
        installer._run(
            [
                str(release / "venv/bin/pip"),
                "install",
                "--require-hashes",
                "-r",
                str(source / "requirements.lock"),
            ],
            timeout=1800,
        )
        installer._run([str(release / "venv/bin/pip"), "install", "--no-deps", str(wheels[0])])
        for directory in ("migrations", "frontend/dist"):
            shutil.copytree(
                source / directory, release / ("web" if directory == "frontend/dist" else directory)
            )
        shutil.copy2(source / "alembic.ini", release / "alembic.ini")
        from serverhub.diagnostics import verify_frontend_files

        verify_frontend_files(release / "web")
        for path in release.rglob("*"):
            if not path.is_symlink():
                path.chmod(path.stat().st_mode | (0o055 if path.is_dir() else 0o044))
        installer._run(["systemctl", "enable", "--now", "serverhub-release-watchdog.timer"])
        recovery_journal = {
            "state": "armed",
            "previous": str(previous),
            "candidate": str(release),
            "deadline": time.time() + 300,
            "backup_id": backup["id"],
            "release_id": release.name,
        }
        recovery._write_journal(recovery_journal)
        installer._run(["systemctl", "stop", "serverhub-api.service", "serverhub-worker.service"])
        environment = dict(
            os.environ,
            **env,
            SERVERHUB_RELEASE_DIR=str(release),
            SERVERHUB_STATE_DIR="/var/lib/serverhub-migrate",
        )
        environment.pop("PYTHONPATH", None)
        environment.pop("PYTHONHOME", None)
        environment.pop("LD_PRELOAD", None)
        installer._run(
            ["runuser", "-u", "serverhub-migrate", "--", str(release / "venv/bin/serverhub"), "migrate"],
            env=environment,
            cwd=str(release),
        )
        installer._run(
            ["runuser", "-u", "postgres", "--", "psql", "-v", "ON_ERROR_STOP=1", "-d", "serverhub"],
            stdin=(source / "packaging/postgresql-grants.sql").read_text(),
        )
        for unit in installer.units():
            installer.write("/etc/systemd/system/" + unit, (source / "packaging/systemd" / unit).read_text())
        # Validate non-secret provider format before relaxing fallback readability.
        models = Path("/etc/serverhub/models.yaml")
        models_state = protect_model_fallback(models) if models.exists() else "needs_setup"
        for directory in (Path("/etc/serverhub"), release.parent):
            directory.chmod(0o755)
        hashes = {
            str(p.relative_to(source / "src")): __import__("hashlib").sha256(p.read_bytes()).hexdigest()
            for p in (source / "src/serverhub").rglob("*.py")
        }
        installer.write(
            "/etc/serverhub/trusted-code-hashes.json",
            json.dumps({"format": 1, "files": hashes}, sort_keys=True),
            0o600,
        )
        installer.write("/etc/serverhub/trust-boundaries.sha256", installer.trust_digest() + "\n")
        (release / "installed.json").write_text(
            json.dumps(
                {
                    "manifest": {
                        "release_id": release.name,
                        "schema_revision": "0004_runtime",
                        "trust_boundary_digest": installer.trust_digest(),
                    }
                }
            )
        )
        installer._activate(release)
        installer._run(["systemctl", "daemon-reload"])
        installer._run(["systemctl", "restart", "serverhub-api.service", "serverhub-worker.service"])
        installer._run(["systemctl", "try-restart", "serverhub-broker.service", "serverhub-node.service"])
        installer._healthchecks(release)
        recovery_journal["state"], recovery_journal["verified_at"] = "verified", time.time()
        recovery._write_journal(recovery_journal)
        return {
            "state": "upgraded",
            "release": str(release),
            "previous_release": str(previous),
            "backup_id": backup["id"],
            "credentials": "retained",
            "models_configuration": models_state,
            "schema_rollback": "0004 is additive; previous code can run without dropping the new tables/column",
        }
    except BaseException:
        installer._activate(previous)
        for path, (content, mode, uid, gid) in snapshots.items():
            path.write_bytes(content)
            path.chmod(mode)
            os.chown(path, uid, gid)
        installer._run(["systemctl", "daemon-reload"])
        installer._run(["systemctl", "restart", "serverhub-api.service", "serverhub-worker.service"])
        installer._run(["systemctl", "try-restart", "serverhub-broker.service", "serverhub-node.service"])
        if recovery_journal:
            recovery_journal["state"], recovery_journal["reverted_at"] = "reverted", time.time()
            recovery._write_journal(recovery_journal)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(repair(args.source), indent=2))
    except Exception as exc:
        print(
            json.dumps(
                {
                    "state": "failed",
                    "error": str(exc),
                    "next_step": "Inspect protected installer logs; previous release/configuration restored when activation had begun. Backups are retained. Rerun after fixing the prerequisite.",
                }
            ),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
