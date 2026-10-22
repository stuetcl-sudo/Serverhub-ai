"""Independent root-only configuration checkpoints and timed rollback.

AI/worker/node users cannot arm, commit, alter or delete recovery journals.
Network mutation is not exposed by the broker. Root operators can use this
utility as an independent guard around their own explicitly authorized changes.
"""
from __future__ import annotations
import argparse
import fcntl
from functools import wraps
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import time
import uuid
from pathlib import Path

from .broker import BrokerDenied, trusted_file
from .discovery import command


class RecoveryError(RuntimeError):
    pass


def _directory(path: str | Path) -> Path:
    p = Path(path)
    if not p.is_absolute() or p.is_symlink():
        raise RecoveryError("recovery directory must be absolute and not a symlink")
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = p.stat()
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise RecoveryError("recovery directory must be root-owned mode0700")
    for parent in p.parents:
        st = parent.lstat()
        if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise RecoveryError("unsafe recovery directory parent")
    return p


def _atomic(path: Path, value: dict) -> None:
    temporary = path.with_suffix(".new")
    fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(value, fh, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(temporary, path)


def _serialized(function):
    @wraps(function)
    def guarded(directory, *args, **kwargs):
        if os.geteuid() != 0:
            raise RecoveryError("root authorization required")
        protected = _directory(directory)
        fd = os.open(protected / ".recovery.lock", os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            return function(protected, *args, **kwargs)
        finally:
            os.close(fd)
    return guarded


@_serialized
def arm(directory: str | Path, target: str | Path, *, timeout: int = 90, service: str | None = None) -> dict:
    if os.geteuid() != 0:
        raise RecoveryError("root authorization required")
    if not 10 <= timeout <= 3600:
        raise RecoveryError("rollback timeout must be 10..3600 seconds")
    target = trusted_file(target)
    if service and (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]+\.service", service) or service.startswith("serverhub")):
        raise RecoveryError("invalid or protected recovery service")
    directory = _directory(directory)
    key, token = uuid.uuid4().hex, secrets.token_urlsafe(32)
    content = target.read_bytes()
    if len(content) > 16*1024*1024:
        raise RecoveryError("checkpoint target exceeds limit")
    backup = directory/f"{key}.checkpoint"
    fd = os.open(backup, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(content)
        fh.flush()
        os.fsync(fh.fileno())
    metadata = target.stat()
    record = {"id": key, "target": str(target), "backup": str(backup), "sha256": hashlib.sha256(content).hexdigest(),
              "target_uid": metadata.st_uid, "target_gid": metadata.st_gid, "target_mode": stat.S_IMODE(metadata.st_mode),
              "deadline": time.time()+timeout, "service": service, "state": "armed", "token_sha256": hashlib.sha256(token.encode()).hexdigest(), "created": time.time()}
    _atomic(directory/f"{key}.json", record)
    return {"id": key, "commit_token": token, "deadline": record["deadline"], "state": "armed"}


def _load(directory: Path, key: str) -> tuple[Path, dict]:
    if not re.fullmatch(r"[0-9a-f]{32}", key):
        raise RecoveryError("invalid recovery identifier")
    path = trusted_file(directory/f"{key}.json")
    data = json.loads(path.read_text())
    if data.get("id") != key:
        raise RecoveryError("recovery identity mismatch")
    return path, data


@_serialized
def commit(directory: str | Path, key: str, token: str) -> dict:
    if os.geteuid() != 0:
        raise RecoveryError("root authorization required")
    directory = _directory(directory)
    path, data = _load(directory, key)
    if data.get("state") != "armed" or data.get("deadline", 0) <= time.time():
        raise RecoveryError("checkpoint is no longer committable")
    if not hmac.compare_digest(data["token_sha256"], hashlib.sha256(token.encode()).hexdigest()):
        raise RecoveryError("invalid commit token")
    data.update(state="committed", committed=time.time())
    _atomic(path, data)
    return {"id": key, "state": "committed"}


@_serialized
def tick(directory: str | Path) -> list[dict]:
    if os.geteuid() != 0:
        raise RecoveryError("root authorization required")
    directory = _directory(directory)
    results = []
    for entry in sorted(directory.glob("*.json")):
        key = entry.stem
        try:
            path, data = _load(directory, key)
            if data.get("state") not in {"armed", "restoring"} or data.get("deadline", float("inf")) > time.time():
                continue
            backup = trusted_file(directory/f"{key}.checkpoint")
            content = backup.read_bytes()
            if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), data["sha256"]):
                raise RecoveryError("checkpoint checksum mismatch; recovery blocked")
            target = trusted_file(data["target"])
            data.update(state="restoring", restore_started=time.time())
            _atomic(path, data)
            temporary = target.parent/f".serverhub-recovery-{key}"
            fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, data["target_mode"])
            with os.fdopen(fd, "wb") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
                os.fchmod(fh.fileno(), data["target_mode"])
                os.fchown(fh.fileno(), data["target_uid"], data["target_gid"])
            os.replace(temporary, target)
            if data.get("service"):
                command("systemctl", "restart", data["service"], timeout=45)
                command("systemctl", "is-active", "--quiet", data["service"])
            data.update(state="reverted", reverted=time.time())
            _atomic(path, data)
            results.append({"id": key, "state": "reverted"})
        except (RecoveryError, BrokerDenied, OSError, ValueError, KeyError) as exc:
            # Never silently mark a failed restore as successful; retain checkpoint.
            results.append({"id": key, "state": "failed", "error": type(exc).__name__})
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", default="/var/lib/serverhub-recovery")
    subs = parser.add_subparsers(dest="command", required=True)
    arm_parser = subs.add_parser("arm")
    arm_parser.add_argument("--path", required=True)
    arm_parser.add_argument("--timeout", type=int, default=90)
    arm_parser.add_argument("--service")
    commit_parser = subs.add_parser("commit")
    commit_parser.add_argument("--id", required=True)
    commit_parser.add_argument("--token", required=True)
    subs.add_parser("tick")
    args = parser.parse_args()
    if args.command == "arm":
        result = arm(args.directory, args.path, timeout=args.timeout, service=args.service)
    elif args.command == "commit":
        result = commit(args.directory, args.id, args.token)
    else:
        result = tick(args.directory)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
