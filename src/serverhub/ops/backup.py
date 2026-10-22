"""Protected PostgreSQL backups with checksum and disposable restore verification."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit


class BackupError(RuntimeError):
    pass


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


@contextmanager
def postgres_environment(database_url: str):
    """Keep credentials out of process arguments and error messages."""
    parsed = urlsplit(database_url.replace("postgresql+psycopg://", "postgresql://", 1))
    if parsed.scheme not in {"postgres", "postgresql"}:
        raise BackupError("a PostgreSQL connection URL is required")
    values = {
        "PGHOST": parsed.hostname or "/var/run/postgresql",
        "PGPORT": str(parsed.port or 5432),
        "PGUSER": unquote(parsed.username or "postgres"),
        "PGDATABASE": unquote(parsed.path.lstrip("/") or "postgres"),
        "PGCONNECT_TIMEOUT": "10",
    }
    # A temporary, 0600 pgpass file avoids both argv and inherited PGPASSWORD.
    with tempfile.TemporaryDirectory(prefix="serverhub-pg-") as temporary:
        credential = Path(temporary) / "pgpass"
        def escape(value):
            return value.replace("\\", "\\\\").replace(":", "\\:")
        password = unquote(parsed.password or "")
        credential.write_text(":".join([escape(values["PGHOST"]), values["PGPORT"], "*", escape(values["PGUSER"]), escape(password)]) + "\n")
        credential.chmod(0o600)
        environment = {k: v for k, v in os.environ.items() if k not in {"PGPASSWORD", "PGSERVICE", "PGSERVICEFILE", "PGPASSFILE"}}
        environment.update(values, PGPASSFILE=str(credential))
        yield environment


class BackupManager:
    def __init__(self, destination: str | Path = "/var/backups/serverhub", *, require_root: bool = True, runner=None):
        self.destination = Path(destination)
        self.require_root = require_root
        self.runner = runner or subprocess.run

    def _protect(self):
        if self.require_root and os.geteuid() != 0:
            raise BackupError("backup operation requires the independent root recovery service")
        if not self.destination.is_absolute() or self.destination.is_symlink():
            raise BackupError("backup destination must be an absolute, non-symlink directory")
        self.destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        mode = self.destination.stat()
        if self.require_root and (mode.st_uid != 0 or stat.S_IMODE(mode.st_mode) & 0o077):
            raise BackupError("backup destination must be root-owned mode 0700")

    def _run(self, argv, *, env=None, timeout=1800):
        try:
            return self.runner(argv, env=env, text=True, capture_output=True, check=True, timeout=timeout)
        except (subprocess.SubprocessError, OSError) as error:
            # pg clients may include connection details in stderr. Do not relay it.
            raise BackupError(f"{Path(argv[0]).name} failed; inspect protected recovery logs") from error

    def create(self, database_url: str, configuration: list[str | Path] | None = None) -> dict:
        self._protect()
        backup_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
        temporary = self.destination / (".partial-" + backup_id)
        temporary.mkdir(mode=0o700)
        try:
            dump = temporary / "postgres.dump"
            with postgres_environment(database_url) as env:
                self._run(["pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--file", str(dump)], env=env)
            if not dump.is_file() or not dump.stat().st_size:
                raise BackupError("pg_dump produced no archive")
            files = {"postgres.dump": {"sha256": digest(dump), "size": dump.stat().st_size}}
            snapshots = []
            if configuration:
                archive = temporary / "configuration.tar.gz"
                with tarfile.open(archive, "w:gz", dereference=False) as output:
                    for configured in configuration:
                        path = Path(configured)
                        if not path.is_absolute() or path.is_symlink() or not path.exists():
                            raise BackupError("configuration snapshot requires existing absolute nonsymlink paths")
                        for child in ([path] if path.is_file() else sorted(path.rglob("*"))):
                            if child.is_symlink():
                                raise BackupError("configuration snapshots reject symlinks")
                            if child.is_file():
                                output.add(child, arcname=str(child).lstrip("/"), recursive=False)
                        snapshots.append(str(path))
                files[archive.name] = {"sha256": digest(archive), "size": archive.stat().st_size}
            manifest = {"format": 1, "id": backup_id, "created_at": datetime.now(timezone.utc).isoformat(), "files": files,
                        "configuration_paths": snapshots, "verification": "checksummed; restore drill required"}
            (temporary / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
            for child in temporary.iterdir():
                child.chmod(0o600)
            self._run(["pg_restore", "--list", str(dump)], timeout=120)
            os.replace(temporary, self.destination / backup_id)
            return manifest
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise

    def _directory(self, backup_id: str) -> Path:
        self._protect()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", backup_id):
            raise BackupError("invalid backup identifier")
        directory = self.destination / backup_id
        if directory.is_symlink() or not directory.is_dir():
            raise BackupError("backup is unavailable")
        return directory

    def list(self) -> list[dict]:
        self._protect()
        values = []
        for path in sorted(self.destination.iterdir(), reverse=True):
            if path.is_dir() and not path.is_symlink() and not path.name.startswith("."):
                try:
                    values.append(self.verify(path.name, check_archive=False))
                except (BackupError, ValueError, OSError):
                    values.append({"id": path.name, "verification": "failed"})
        return values

    def verify(self, backup_id: str, *, check_archive=True) -> dict:
        directory = self._directory(backup_id)
        manifest = json.loads((directory / "manifest.json").read_text())
        if manifest.get("format") != 1 or manifest.get("id") != backup_id:
            raise BackupError("invalid backup manifest")
        if "postgres.dump" not in manifest.get("files", {}):
            raise BackupError("missing database archive")
        for name, expected in manifest["files"].items():
            if name not in {"postgres.dump", "configuration.tar.gz"}:
                raise BackupError("unexpected backup file")
            path = directory / name
            if path.is_symlink() or not path.is_file() or path.stat().st_size != expected["size"] or digest(path) != expected["sha256"]:
                raise BackupError("backup checksum verification failed")
        if check_archive:
            self._run(["pg_restore", "--list", str(directory / "postgres.dump")], timeout=120)
        return manifest

    def restore_drill(self, backup_id: str, maintenance_url: str) -> dict:
        """Restore ONLY into a new generated database, then destroy that database."""
        self.verify(backup_id)
        database = "serverhub_verify_" + uuid.uuid4().hex
        with postgres_environment(maintenance_url) as env:
            self._run(["createdb", "--maintenance-db", env["PGDATABASE"], database], env=env, timeout=120)
            try:
                self._run(["pg_restore", "--exit-on-error", "--no-owner", "--no-privileges", "--dbname", database,
                           str(self._directory(backup_id) / "postgres.dump")], env=env)
                result = self._run(["psql", "--dbname", database, "-At", "-v", "ON_ERROR_STOP=1", "-c",
                                    "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"], env=env, timeout=120)
                return {"backup_id": backup_id, "state": "verified", "restored_tables": int(result.stdout.strip()), "disposable_database": database}
            finally:
                self._run(["dropdb", "--maintenance-db", env["PGDATABASE"], database], env=env, timeout=120)

    def restore(self, backup_id: str, database_url: str, *, confirm_database: str):
        """Explicit maintenance action. No implicit DROP, clean, or production selection."""
        manifest = self.verify(backup_id)
        with postgres_environment(database_url) as env:
            if confirm_database != env["PGDATABASE"]:
                raise BackupError("typed database confirmation does not match")
            count = self._run(["psql", "-At", "-v", "ON_ERROR_STOP=1", "-c",
                               "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"], env=env, timeout=120)
            if int(count.stdout.strip()) != 0:
                raise BackupError("restore requires an empty database; existing data was not changed")
            self._run(["pg_restore", "--exit-on-error", "--no-owner", "--no-privileges", "--single-transaction",
                       "--dbname", env["PGDATABASE"], str(self._directory(backup_id) / "postgres.dump")], env=env)
        return {"backup_id": manifest["id"], "state": "restored"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["create", "list", "verify", "restore-drill", "restore"])
    parser.add_argument("--destination", default="/var/backups/serverhub")
    parser.add_argument("--database-url-env", default="SERVERHUB_DATABASE_URL")
    parser.add_argument("--id")
    parser.add_argument("--config", action="append", default=[])
    parser.add_argument("--confirm-database")
    parser.add_argument("--status-file", help="optional root-owned, read-only status export for dashboard")
    args = parser.parse_args()
    manager = BackupManager(args.destination)
    try:
        if args.action == "create":
            result = manager.create(os.environ[args.database_url_env], args.config)
        elif args.action == "list":
            result = manager.list()
        elif args.action == "verify":
            result = manager.verify(args.id or "")
        elif args.action == "restore-drill":
            result = manager.restore_drill(args.id or "", os.environ[args.database_url_env])
        else:
            result = manager.restore(args.id or "", os.environ[args.database_url_env], confirm_database=args.confirm_database or "")
        if args.status_file:
            status = Path(args.status_file)
            if not status.is_absolute() or status.is_symlink() or (status.exists() and status.stat().st_uid != 0):
                raise BackupError("status export must be a root-owned absolute nonsymlink file")
            status.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            temporary = status.with_suffix(".tmp")
            temporary.write_text(json.dumps({"updated_at": datetime.now(timezone.utc).isoformat(), "backups": manager.list()}, indent=2) + "\n")
            temporary.chmod(0o644)
            os.replace(temporary, status)
        print(json.dumps(result, indent=2))
    except (BackupError, KeyError, ValueError) as error:
        parser.exit(1, f"Backup operation failed: {error}\n")


if __name__ == "__main__":
    main()
