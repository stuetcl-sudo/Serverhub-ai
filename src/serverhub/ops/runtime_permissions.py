"""Seal native executable trees before exposing them to service identities."""
from pathlib import Path
import os
import stat


def seal_runtime(runtime, *, require_root=True):
    if require_root and os.geteuid() != 0:
        raise RuntimeError("Runtime sealing requires local root")
    expected_uid = 0 if require_root else os.geteuid()
    runtime = Path(runtime)
    if runtime.is_symlink() or runtime.stat().st_uid != expected_uid:
        raise RuntimeError('Runtime must be a root-owned directory')
    runtime.chmod(0o700)
    # Never follow virtualenv interpreter/lib64 symlinks into the operating system.
    for path in runtime.rglob('*'):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            continue
        if info.st_uid != expected_uid or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise RuntimeError('Foreign owner or special file in native runtime: ' + str(path))
        if path.suffix == '.pyc':
            path.unlink()  # old writable bytecode must not shadow validated source
            continue
        mode = stat.S_IMODE(info.st_mode) & ~0o022
        path.chmod(mode | (0o055 if path.is_dir() else 0o044))
    runtime.chmod(0o755)
