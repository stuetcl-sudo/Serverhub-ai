"""Immutable project contracts; prompts never supply executables or destinations."""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class DevelopmentError(RuntimeError):
    pass


class Command(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    argv: list[str] = Field(min_length=1, max_length=64)
    timeout: int = Field(default=300, ge=1, le=3600)
    network: bool = False

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: list[str]) -> list[str]:
        if any(not arg or "\0" in arg or len(arg) > 8192 for arg in value):
            raise ValueError("command arguments must be bounded non-empty strings")
        if value[0].startswith("/") and not value[0].startswith(("/usr/bin/", "/bin/", "/workspace/", "/checks/")):
            raise ValueError("executable must be inside the minimal sandbox")
        return value


class Project(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
    repository: str
    base_ref: str = "main"
    dependencies: list[Command] = Field(default_factory=list)
    build: list[Command] = Field(default_factory=list)
    tests: list[Command] = Field(min_length=1)
    checks_path: Path | None = None
    independent_checks: list[Command] = Field(default_factory=list)
    staging_checks: list[Command] = Field(default_factory=list)
    artifact_paths: list[str] = Field(default_factory=lambda: ["."])
    max_artifact_bytes: int = Field(default=128 * 1024 * 1024, ge=1024, le=2 * 1024**3)
    allow_dependency_network: bool = False
    max_memory_mb: int = Field(default=2048, ge=128, le=16384)
    max_processes: int = Field(default=64, ge=4, le=256)

    @field_validator("repository")
    @classmethod
    def validate_repository(cls, value: str) -> str:
        if value.startswith("/"):
            return value
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("repository must be an absolute local path or credential-free HTTPS URL")
        return value

    @field_validator("base_ref")
    @classmethod
    def validate_ref(cls, value: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_./-]{0,180}", value) or ".." in value:
            raise ValueError("invalid owner-configured base ref")
        return value

    @field_validator("artifact_paths")
    @classmethod
    def validate_paths(cls, paths: list[str]) -> list[str]:
        if not paths or len(paths) > 32:
            raise ValueError("artifact paths must contain 1 to 32 entries")
        for item in paths:
            path = Path(item)
            if path.is_absolute() or ".." in path.parts or any(p == ".git" for p in path.parts):
                raise ValueError("artifact paths must remain inside the project")
        return paths

    @model_validator(mode="after")
    def validate_network(self) -> Project:
        if any(command.network for command in self.build + self.tests + self.independent_checks + self.staging_checks):
            raise ValueError("network is available only for explicitly authorized dependency installation")
        if any(command.network for command in self.dependencies) and not self.allow_dependency_network:
            raise ValueError("network dependency commands require allow_dependency_network")
        if self.independent_checks and self.checks_path is None:
            raise ValueError("independent checks require an external checks_path")
        return self


def require_protected_file(path: Path, *, directory: bool = False) -> None:
    """Require root ownership and no group/world write through every ancestor."""
    target = path.absolute()
    if target.is_symlink():
        raise DevelopmentError(f"protected path must not be a symlink: {path}")
    if not (target.is_dir() if directory else target.is_file()):
        raise DevelopmentError(f"protected {'directory' if directory else 'file'} missing: {path}")
    for component in (target, *target.parents):
        meta = component.lstat()
        if stat.S_ISLNK(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
            raise DevelopmentError(f"project trust anchor is not root-owned and protected: {component}")


def load_projects(path: str | Path | None = None, *, enforce_permissions: bool = True) -> dict[str, Project]:
    chosen = Path(path or os.environ.get("SERVERHUB_PROJECTS_PATH", "/etc/serverhub/projects.yaml"))
    if not chosen.exists():
        return {}
    if enforce_permissions:
        require_protected_file(chosen)
    if chosen.stat().st_size > 1024 * 1024:
        raise DevelopmentError("project configuration exceeds 1 MiB")
    raw: Any = yaml.safe_load(chosen.read_text()) or {}
    if not isinstance(raw, dict) or set(raw) - {"projects"}:
        raise DevelopmentError("project configuration must contain only projects")
    entries = raw.get("projects", [])
    if not isinstance(entries, list):
        raise DevelopmentError("projects must be an array")
    projects: dict[str, Project] = {}
    for entry in entries:
        project = Project.model_validate(entry)
        if project.name in projects:
            raise DevelopmentError("duplicate project name")
        if enforce_permissions and project.checks_path:
            require_protected_file(project.checks_path, directory=True)
            for child in project.checks_path.rglob("*"):
                if child.is_symlink() or child.stat().st_uid != 0 or child.stat().st_mode & 0o022:
                    raise DevelopmentError("independent checks contain an unprotected path")
        projects[project.name] = project
    return projects


def project_descriptors(path: str | Path | None = None) -> list[dict]:
    return [
        {"name": project.name, "base_ref": project.base_ref,
         "build_steps": len(project.build), "test_steps": len(project.tests),
         "independent_checks": len(project.independent_checks),
         "staging_checks": len(project.staging_checks),
         "dependency_network": project.allow_dependency_network,
         "production_deployment": False}
        for project in load_projects(path).values()
    ]
