"""Git workspaces, validated patch application, and immutable candidate archives."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from .config import DevelopmentError, Project


SAFE_ID = re.compile(r"^[a-zA-Z0-9_-]{1,80}$")
COMMIT = re.compile(r"^[0-9a-f]{40,64}$")


def git(workspace: Path | None, *arguments: str, input: str | None = None, timeout: int = 120) -> str:
    command = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.ext.allow=never",
               "-c", "protocol.file.allow=always", "-c", "credential.helper=",
               "-c", "core.fsmonitor=false", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.required=false"]
    if workspace:
        command += ["-C", str(workspace)]
    command += list(arguments)
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "https:file"}
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(command, input=input.encode() if input is not None else None,
                                    stdout=output, stderr=subprocess.STDOUT,
                                    env=env, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise DevelopmentError("bounded Git operation timed out") from exc
        output.seek(0, os.SEEK_END)
        size = output.tell()
        if size > 2 * 1024 * 1024:
            raise DevelopmentError("Git output exceeded 2 MiB limit")
        output.seek(0)
        text = output.read().decode("utf-8", errors="replace")
        if result.returncode:
            # No repository URL/credential-bearing response is returned to chat.
            raise DevelopmentError(f"Git operation failed with exit status {result.returncode}")
        return text


def safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise DevelopmentError("patch path escapes its workspace")
    if any(part.lower() in {".git", ".serverhub", "node_modules", ".venv"} for part in path.parts):
        raise DevelopmentError("patch modifies protected workspace metadata")
    if "\\" in value or any(ord(char) < 32 for char in value):
        raise DevelopmentError("patch path contains unsafe characters")
    return path



def read_source(workspace: Path, relative: str) -> str:
    """Read bounded regular source via directory FDs; never follow symlinks."""
    path = safe_relative(relative)
    sensitive = {".ssh", ".aws", ".azure", ".kube", ".config", "credentials",
                 "credentials.json", "secrets", "secrets.json", "secrets.yaml", "secrets.yml",
                 "id_rsa", "id_ed25519", ".netrc", ".npmrc", ".pypirc"}
    if any(part.lower() in sensitive or PurePosixPath(part).stem.lower() in {"secret", "secrets", "credential", "credentials"} or (part.lower().startswith(".env") and part.lower() != ".env.example")
           for part in path.parts):
        raise DevelopmentError("Credential/configuration path is not readable source")
    if path.suffix not in {'.py','.json','.toml','.txt','.md','.yaml','.yml','.ts','.tsx','.js','.html','.css','.sql','.sh','.ini','.cfg','.conf','.lock'} and path.name not in {'Dockerfile','Makefile'}:
        raise DevelopmentError("Source path is outside the bounded text read allowlist")
    fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        source = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(source, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > 65536:
                raise DevelopmentError("Source must be a bounded regular file without hardlinks")
            content = stream.read(65537)
            if len(content) > 65536:
                raise DevelopmentError("Source file exceeds read bound")
            return content.decode("utf-8")
    finally:
        os.close(fd)


def assert_safe_tree(workspace: Path) -> None:
    """Reject symlink/submodule content before patching and before artifact export."""
    for root, dirs, files in os.walk(workspace, followlinks=False):
        if Path(root) == workspace:
            for generated in (".git", "node_modules", ".venv", ".pytest_cache", "__pycache__"):
                if generated in dirs:
                    # Generated dependency trees never enter candidate archives.
                    dirs.remove(generated)
        for name in dirs + files:
            path = Path(root) / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise DevelopmentError("workspace contains a symlink or non-regular entry")
    staged = git(workspace, "ls-files", "--stage")
    if any(line.startswith(("120000 ", "160000 ")) for line in staged.splitlines()):
        raise DevelopmentError("symlinks and submodules require a separate reviewed workflow")


class WorkspaceManager:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).absolute()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink():
            raise DevelopmentError("workspace root cannot be a symlink")

    def path(self, project: Project, job_id: str) -> Path:
        if not SAFE_ID.fullmatch(job_id):
            raise DevelopmentError("invalid job identity")
        result = self.root / project.name / job_id
        if any(parent.is_symlink() for parent in [result, *result.parents] if parent != self.root.parent):
            raise DevelopmentError("workspace path traverses a symlink")
        return result

    def prepare(self, project: Project, job_id: str, *, base_commit: str | None = None) -> Path:
        if base_commit is not None and not COMMIT.fullmatch(base_commit):
            raise DevelopmentError("base commit must be a complete hexadecimal commit ID")
        destination = self.path(project, job_id)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if destination.exists():
            if not (destination / ".git").is_dir():
                raise DevelopmentError("existing workspace is not a Git checkout")
            assert_safe_tree(destination)
            return destination
        try:
            git(None, "clone", "--no-checkout", "--no-hardlinks", "--no-local", "--",
                project.repository, str(destination))
            chosen = git(destination, "rev-parse", "--verify", f"origin/{project.base_ref}^{{commit}}").strip()
            if base_commit and chosen != base_commit:
                raise DevelopmentError("requested commit differs from the configured base ref")
            git(destination, "checkout", "-b", f"serverhub/{job_id}", chosen)
            git(destination, "config", "user.name", "ServerHub Development Agent")
            git(destination, "config", "user.email", "development@serverhub.local")
            assert_safe_tree(destination)
        except BaseException:
            # Preserve failed workspaces for owner review; never recursively delete via AI.
            raise
        return destination

    def apply_patch(self, workspace: Path, patch: str, *, message="Apply authorized ServerHub development change") -> dict:
        if not patch or len(patch.encode()) > 2 * 1024 * 1024:
            raise DevelopmentError("patch must contain 1 byte to 2 MiB")
        if "GIT binary patch" in patch or re.search(r"^(?:new file mode|new mode) (?:120000|160000)", patch, re.M):
            raise DevelopmentError("binary, symlink and submodule patches are unsupported")
        assert_safe_tree(workspace)
        stat_lines = git(workspace, "apply", "--numstat", "-z", "--", input=patch)
        paths: list[str] = []
        for record in stat_lines.split("\0"):
            if not record:
                continue
            fields = record.split("\t", 2)
            if len(fields) != 3 or not fields[2]:
                raise DevelopmentError("rename/copy patches must be represented as deletion and addition")
            safe_relative(fields[2])
            paths.append(fields[2])
        if not paths:
            raise DevelopmentError("patch changes no files")
        git(workspace, "apply", "--check", "--whitespace=error-all", "--", input=patch)
        git(workspace, "apply", "--index", "--whitespace=error-all", "--", input=patch)
        assert_safe_tree(workspace)
        git(workspace, "commit", "-m", message)
        return {"commit": git(workspace, "rev-parse", "HEAD").strip(),
                "patch_sha256": hashlib.sha256(patch.encode()).hexdigest(), "changed_paths": paths}

    def archive(self, workspace: Path, project: Project, *, destination: Path) -> dict:
        assert_safe_tree(workspace)
        selected: dict[str, Path] = {}
        total = 0
        for selected_path in project.artifact_paths:
            relative = PurePosixPath(selected_path)
            if str(relative) != ".":
                safe_relative(selected_path)
            target = workspace.joinpath(*relative.parts)
            if not target.exists():
                raise DevelopmentError("configured artifact path is missing")
            candidates = target.rglob("*") if target.is_dir() else [target]
            for path in candidates:
                rel = path.relative_to(workspace)
                if ".git" in rel.parts or any(part in {"node_modules", ".venv", ".pytest_cache", "__pycache__"} for part in rel.parts):
                    continue
                metadata = path.lstat()
                if not stat.S_ISREG(metadata.st_mode):
                    if stat.S_ISDIR(metadata.st_mode):
                        continue
                    raise DevelopmentError("non-regular artifact entry")
                if metadata.st_nlink != 1:
                    raise DevelopmentError("hard-linked artifact entries are unsupported")
                selected[rel.as_posix()] = path
        for path in selected.values():
            total += path.stat().st_size
        if total > project.max_artifact_bytes or len(selected) > 100000:
            raise DevelopmentError("candidate exceeds artifact size or file count budget")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, tmp_path = tempfile.mkstemp(prefix="candidate-", dir=destination.parent)
        os.close(descriptor)
        try:
            # Uncompressed deterministic tar, bounded by selected file sizes. Gzip timestamps
            # are avoided so the same candidate has the same digest.
            with tarfile.open(tmp_path, "w", format=tarfile.PAX_FORMAT) as archive:
                for name, path in sorted(selected.items()):
                    data = path.read_bytes()
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    entry.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                    entry.uid = entry.gid = 0
                    entry.uname = entry.gname = ""
                    entry.mtime = 0
                    archive.addfile(entry, io.BytesIO(data))
            with open(tmp_path, "rb") as artifact_file:
                digest = hashlib.file_digest(artifact_file, "sha256").hexdigest()
            os.chmod(tmp_path, 0o400)
            os.replace(tmp_path, destination)
        finally:
            Path(tmp_path).unlink(missing_ok=True)
        return {"artifact": str(destination), "sha256": digest, "files": len(selected),
                "bytes": destination.stat().st_size, "source_bytes": total,
                "commit": git(workspace, "rev-parse", "HEAD").strip()}


def write_manifest(path: Path, payload: dict) -> None:
    # The root broker needs the verified receipt, not a duplicate source diff.
    # Large diffs could otherwise exceed its 1 MiB receipt limit after JSON escaping.
    receipt = {key: value for key, value in payload.items() if key not in {"source_patch", "source_changes"}}
    if "commands" in receipt:
        receipt["commands"] = [{**command, "output": str(command.get("output", ""))[-4000:]}
                               for command in receipt["commands"]]
    encoded = json.dumps(receipt, sort_keys=True, indent=2).encode()
    if len(encoded) > 1024**2:
        raise DevelopmentError("candidate receipt exceeds the broker's 1 MiB limit")
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix="manifest-")
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o400)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def source_patch(workspace, base_commit):
    if not base_commit or not COMMIT.fullmatch(base_commit):
        return None
    try:
        patch = git(workspace, "diff", "--no-ext-diff", "--no-textconv", base_commit, "HEAD", timeout=30)
        return patch if len(patch.encode()) <= 500000 else None
    except DevelopmentError:
        return None


def source_changes(workspace: Path, base_commit: str | None, publication_paths=()) -> list | None:
    """Bounded tracked UTF-8 changes; no arbitrary file-reading API is exposed."""
    if not base_commit or not re.fullmatch(r"[a-f0-9]{40,64}", base_commit):
        return None
    if git(workspace, "diff", "--no-ext-diff", "--name-only", "HEAD").strip():
        return None  # builds must not alter the tracked source after its commit
    if publication_paths and git(workspace, "ls-files", "--others", "--exclude-standard", "--", *publication_paths).strip():
        return None  # do not omit generated, uncommitted source from a verified PR
    paths = git(workspace, "diff", "--name-only", "--no-renames", "-z", base_commit, "HEAD").split("\0")
    changed, total = [], 0
    for name in filter(None, paths):
        safe_relative(name)
        path = workspace / name
        if path.exists():
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 200000:
                return None
            try:
                content = path.read_bytes().decode("utf-8")
            except UnicodeError:
                return None
            if "\0" in content:
                return None
            total += len(content.encode())
        else:
            content = None
        changed.append({"path": name, "content": content, "mode": "100755" if path.exists() and path.stat().st_mode & 0o111 else "100644",
                        "sha256": hashlib.sha256(content.encode()).hexdigest() if content is not None else None})
        if total > 500000 or len(changed) > 100:
            return None
    return changed
