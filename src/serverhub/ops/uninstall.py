"""Remove native services and executable releases while retaining recovery data."""
from __future__ import annotations
import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

from .installer import CONTROLLER_UNITS, NODE_UNITS, InstallError


def uninstall(*, apply=False, root="/", runner=None):
    destination = Path(root).absolute()
    units = CONTROLLER_UNITS + NODE_UNITS
    paths = ["/etc/systemd/system/" + name for name in units] + ["/opt/serverhub/current", "/opt/serverhub/releases"]
    retained = ["/etc/serverhub", "/var/backups/serverhub", "/var/lib/serverhub-release", "/var/lib/serverhub-recovery",
                "PostgreSQL database/roles", "dedicated service accounts", "node identity and command journal", "/opt/serverhub/recovery (independent recovery tools)"]
    plan = {"action": "uninstall", "apply": apply, "root": str(destination), "remove": paths, "retain": retained}
    if not apply:
        return plan
    if destination != Path("/") or os.geteuid() != 0:
        raise InstallError("uninstall --apply requires root and the actual installation root")
    runner = runner or subprocess.run
    existing = [name for name in units if (Path("/etc/systemd/system") / name).is_file()]
    if existing:
        runner(["systemctl", "disable", "--now", *existing], check=True, timeout=180, capture_output=True)
    install = Path("/opt/serverhub")
    if install.is_symlink() or (install.exists() and (install.stat().st_uid != 0 or install.stat().st_mode & 0o022)):
        raise InstallError("unsafe installation ownership; removal stopped")
    current = install / "current"
    if current.is_symlink():
        current.unlink()
    elif current.exists():
        raise InstallError("current is not an installation symlink; removal stopped")
    releases = install / "releases"
    if releases.is_symlink():
        raise InstallError("release directory is a symlink; removal stopped")
    if releases.exists():
        shutil.rmtree(releases)
    for name in existing:
        (Path("/etc/systemd/system") / name).unlink()
    runner(["systemctl", "daemon-reload"], check=True, timeout=60, capture_output=True)
    return {**plan, "state": "uninstalled", "reinstall": "Use saved recovery data and the documented restore procedure"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--plan", action="store_true")
    action.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(uninstall(apply=args.apply), indent=2))
    except (InstallError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Uninstall failed: {error}\n")


if __name__ == "__main__":
    main()
