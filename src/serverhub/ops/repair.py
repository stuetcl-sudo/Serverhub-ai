"""Explicit local-root upgrade of an existing installation, with config/DB backup.

Unlike autonomous signed releases, this command intentionally accepts reviewed
trust-boundary changes from a local source checkout. It is never an AI tool.
"""

import argparse
import json
import os
import pwd
import grp
from pathlib import Path
import shutil
import sys
import subprocess
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


def ensure_staging_account(installer):
    name, home = "serverhub-ai-staging", "/var/lib/serverhub-ai-stage-runtime"
    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        installer._run(["useradd", "--system", "--user-group", "--home-dir", home,
                        "--shell", "/usr/sbin/nologin", name])
        entry = pwd.getpwnam(name)
    memberships = {grp.getgrgid(gid).gr_name for gid in os.getgrouplist(name, entry.pw_gid)}
    if entry.pw_uid == 0 or entry.pw_dir != home or entry.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"} or memberships & {"root","sudo","docker","adm"}:
        raise InstallError("Unexpected staging account privileges/home/shell; inspect before upgrade")
    if grp.getgrnam(name).gr_gid != entry.pw_gid:
        raise InstallError("Staging account must use its dedicated primary group")
    directory=Path(home)
    directory.mkdir(mode=0o700,exist_ok=True)
    os.chown(directory,entry.pw_uid,entry.pw_gid)
    directory.chmod(0o700)


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
    from .coexistence import require_safe
    require_safe(units=installer.units(), runner=installer.runner)
    backup = BackupManager().create(env["SERVERHUB_DATABASE_URL"], [Path("/etc/serverhub")])
    snapshots = {}
    for path in [*Path("/etc/serverhub").glob("*"), *(Path("/etc/systemd/system") / name for name in installer.units())]:
        if path.is_file() and not path.is_symlink():
            info = path.stat()
            snapshots[path] = (path.read_bytes(), info.st_mode & 0o777, info.st_uid, info.st_gid)
    from .sandbox_setup import PROFILE_PATH, PROFILE
    profile_path=Path(PROFILE_PATH)
    introduced_profile=not profile_path.exists()
    if profile_path.exists():
        info=profile_path.stat()
        snapshots[profile_path]=(profile_path.read_bytes(),info.st_mode&0o777,info.st_uid,info.st_gid)
    stable_watchdog=Path("/opt/serverhub/recovery-ai/operation_watchdog.py")
    if stable_watchdog.exists():
        info=stable_watchdog.stat()
        snapshots[stable_watchdog]=(stable_watchdog.read_bytes(),info.st_mode&0o777,info.st_uid,info.st_gid)
    recovery_units=["serverhub-ai-operation-watchdog.service","serverhub-ai-operation-watchdog.timer"]
    introduced_units=[Path("/etc/systemd/system")/unit for unit in recovery_units
                      if not (Path("/etc/systemd/system")/unit).exists()]
    release = Path("/opt/serverhub/releases") / (
        "repair-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:6]
    )
    release.mkdir(mode=0o700)
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
        from .runtime_permissions import seal_runtime
        seal_runtime(release)
        stable_runtime = Path('/opt/serverhub/recovery-ai')
        stable_runtime.mkdir(mode=0o700, exist_ok=True)
        stable_runtime.chmod(0o700)
        installer._run([sys.executable, '-m', 'venv', str(stable_runtime / 'venv')])
        installer._run([str(stable_runtime / 'venv/bin/pip'), 'install', '--require-hashes', '-r', str(source / 'requirements.lock')], timeout=1800)
        installer._run([str(stable_runtime / 'venv/bin/pip'), 'install', '--no-deps', '--force-reinstall', str(wheels[0])])
        seal_runtime(stable_runtime)
        ensure_staging_account(installer)
        from .sandbox_setup import configure
        configure(installer)
        for unit in recovery_units:
            installer.write("/etc/systemd/system/"+unit,(source/"packaging/systemd"/unit).read_text())
        installer._run(["systemctl","daemon-reload"])
        installer.write("/opt/serverhub/recovery-ai/operation_watchdog.py",
                        (source / "src/serverhub/ops/operation_watchdog.py").read_text(), 0o600)
        installer._run(["systemctl", "enable", "--now", "serverhub-ai-release-watchdog.timer", "serverhub-ai-operation-watchdog.timer"])
        installer._run(["systemctl","restart","serverhub-ai-operation-watchdog.timer"])
        recovery_journal = {
            "state": "armed",
            "previous": str(previous),
            "candidate": str(release),
            "deadline": time.time() + 300,
            "backup_id": backup["id"],
            "release_id": release.name,
        }
        recovery._write_journal(recovery_journal)
        installer._run(["systemctl", "stop", "serverhub-ai-api.service", "serverhub-ai-worker.service"])
        environment = dict(
            os.environ,
            **env,
            SERVERHUB_RELEASE_DIR=str(release),
            SERVERHUB_STATE_DIR="/var/lib/serverhub-ai-migrate",
        )
        environment.pop("PYTHONPATH", None)
        environment.pop("PYTHONHOME", None)
        environment.pop("LD_PRELOAD", None)
        installer._run(
            ["runuser", "-u", "serverhub-ai-migrate", "--", str(release / "venv/bin/serverhub"), "migrate"],
            env=environment,
            cwd=str(release),
        )
        installer._run(
            ["runuser", "-u", "postgres", "--", "psql", "-v", "ON_ERROR_STOP=1", "-d", "serverhub"],
            stdin=(source / "packaging/postgresql-grants.sql").read_text(),
        )
        for unit in installer.units():
            installer.write("/etc/systemd/system/" + unit, (source / "packaging/systemd" / unit).read_text())
        from serverhub.development.config import normalize_empty_projects
        projects_path = Path("/etc/serverhub/projects.yaml")
        if projects_path.exists():
            normalize_empty_projects(projects_path, installer.write)
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
                        "schema_revision": "0005_priority",
                        "trust_boundary_digest": installer.trust_digest(),
                    }
                }
            )
        )
        (release / "installed.json").chmod(0o644)
        installer._activate(release)
        installer._run(["systemctl", "daemon-reload"])
        installer._run(["systemctl", "restart", "serverhub-ai-api.service", "serverhub-ai-worker.service"])
        installer._run(["systemctl", "try-restart", "serverhub-ai-broker.service", "serverhub-ai-node.service"])
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
            "schema_rollback": "0004/0005 are additive; rollback retains added columns and requires schema-compatible previous code",
        }
    except BaseException:
        installer._activate(previous)
        if introduced_profile and profile_path.exists() and profile_path.read_text()==PROFILE:
            subprocess.run(["/usr/sbin/apparmor_parser","--remove",str(profile_path)],check=False,capture_output=True,timeout=30)
            profile_path.unlink()
        if introduced_units:
            subprocess.run(["systemctl","disable","--now","serverhub-ai-operation-watchdog.timer"],check=False,capture_output=True,timeout=30)
            for path in introduced_units:
                path.unlink(missing_ok=True)
        if stable_watchdog not in snapshots:
            stable_watchdog.unlink(missing_ok=True)
        for path, (content, mode, uid, gid) in snapshots.items():
            path.write_bytes(content)
            path.chmod(mode)
            os.chown(path, uid, gid)
        installer._run(["systemctl", "daemon-reload"])
        installer._run(["systemctl", "restart", "serverhub-ai-api.service", "serverhub-ai-worker.service"])
        installer._run(["systemctl", "try-restart", "serverhub-ai-broker.service", "serverhub-ai-node.service"])
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
