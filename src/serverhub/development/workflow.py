"""Durable development jobs with explicit project-scoped policy checks.

The result is a tested release candidate. Runtime deployment is delegated to a
separate owner-configured deployment adapter; this module cannot install itself,
modify controller trust anchors or deploy to production.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .config import DevelopmentError, Project, load_projects
from .sandbox import SandboxRunner
from .workspace import WorkspaceManager, git, write_manifest


ALLOWED_SPEC_KEYS = {"project", "patch", "base_commit", "stage", "release", "artifact_sha256"}


def _require(ctx: Any, project: str, operation: str, *, arguments: dict | None = None,
             production: bool = False) -> None:
    from serverhub.policy import authorize
    ctx.check_cancelled()
    authorize(ctx.db, ctx.principal, operation, host_id=getattr(ctx.job, "host_id", None),
              project=project, arguments=arguments or {}, production=production)


def _checkpoint(ctx: Any, state: dict) -> None:
    result = dict(ctx.job.result or {})
    result["_development"] = state
    ctx.job.result = result
    ctx.db.commit()
    ctx.heartbeat()


def _run_commands(ctx: Any, project: Project, workspace: Path, runner: SandboxRunner,
                  commands: list, phase: str, state: dict) -> None:
    completed = list(state.get("completed", []))
    for index, command in enumerate(commands):
        marker = f"{phase}:{index}"
        if marker in completed:
            continue
        operation = "development.dependencies" if phase == "dependencies" else "development.test"
        _require(ctx, project.name, operation, arguments={"phase": phase, "network": command.network})
        if command.network:
            _require(ctx, project.name, "development.network", arguments={"phase": phase})
        # Fixed argv is not derived from the prompt. Both command and all repository
        # code run in bubblewrap; failure never falls back to a shell on the host.
        ctx.log(f"Running configured {phase} command {index + 1}", {"argv": command.argv})
        result = runner.run(workspace, command, heartbeat=lambda: (ctx.check_cancelled(), ctx.heartbeat()))
        summaries = list(state.get("commands", []))
        # Generated stdout is untrusted. Keep it as bounded job output, not as a new instruction.
        summaries.append({"phase": phase, "index": index, **result.as_dict()})
        state["commands"] = summaries
        if result.returncode or result.timed_out:
            state["failed_phase"] = phase
            _checkpoint(ctx, state)
            raise DevelopmentError(f"configured {phase} command {index + 1} failed (exit {result.returncode})")
        completed.append(marker)
        state["completed"] = completed
        _checkpoint(ctx, state)


def development_job(ctx: Any, spec: dict) -> dict:
    if not isinstance(spec, dict) or set(spec) - ALLOWED_SPEC_KEYS:
        raise DevelopmentError("unknown development request fields; commands and URLs cannot be supplied")
    name = spec.get("project")
    if not isinstance(name, str):
        raise DevelopmentError("a configured project is required")
    projects = load_projects()
    if name not in projects:
        raise DevelopmentError("project is not configured by the owner")
    project = projects[name]
    if spec.get("release"):
        # There is intentionally no generic production exec/deploy switch. A release
        # request obtains authorization but still requires a separate deployment adapter.
        _require(ctx, name, "development.release", arguments={"artifact_sha256": spec.get("artifact_sha256")}, production=True)
        raise DevelopmentError("production deployment requires a separately configured release adapter; this job produces release candidates only")
    patch = spec.get("patch")
    if patch is not None and not isinstance(patch, str):
        raise DevelopmentError("patch must be a unified diff string")
    digest = hashlib.sha256((patch or "").encode()).hexdigest()
    state = dict((ctx.job.result or {}).get("_development", {}))
    if state and (state.get("project") != name or state.get("patch_sha256") != digest):
        raise DevelopmentError("persisted development request identity differs from this request")
    state.update({"project": name, "patch_sha256": digest})
    _require(ctx, name, "development.workspace")
    from serverhub.settings import get_settings
    root = Path(get_settings().state_dir) / "development"
    manager = WorkspaceManager(root / "workspaces")
    workspace = manager.prepare(project, ctx.job.id, base_commit=spec.get("base_commit"))
    state["workspace"] = str(workspace)
    _checkpoint(ctx, state)
    runner = SandboxRunner(project)
    availability = runner.preflight(workspace)
    if not availability["available"]:
        state["sandbox"] = availability
        _checkpoint(ctx, state)
        raise DevelopmentError("bubblewrap isolation is unavailable; job stopped without running project code")
    if patch and "patch_commit" not in state:
        _require(ctx, name, "development.patch", arguments={"patch_sha256": digest})
        # Crash recovery: a previous git commit is detected by its fixed trailer-free
        # message and by the tree diff hash only when our durable patch marker exists.
        result = manager.apply_patch(workspace, patch)
        state["patch_commit"] = result["commit"]
        state["changed_paths"] = result["changed_paths"]
        _checkpoint(ctx, state)
    _run_commands(ctx, project, workspace, runner, project.dependencies, "dependencies", state)
    _run_commands(ctx, project, workspace, runner, project.build, "build", state)
    _run_commands(ctx, project, workspace, runner, project.tests, "tests", state)
    _run_commands(ctx, project, workspace, runner, project.independent_checks, "independent", state)
    if spec.get("stage"):
        _require(ctx, name, "development.stage")
        if not project.staging_checks:
            raise DevelopmentError("staging was requested but no owner-configured staging healthchecks exist")
        _run_commands(ctx, project, workspace, runner, project.staging_checks, "staging", state)
    _require(ctx, name, "development.stage", arguments={"artifact": True})
    archive = manager.archive(workspace, project, destination=root / "candidates" / f"{ctx.job.id}.tar")
    result = {
        "project": name, "branch": f"serverhub/{ctx.job.id}",
        "source_commit": git(workspace, "rev-parse", "HEAD").strip(),
        "candidate": archive,
        "build_passed": bool(project.build), "tests_passed": True,
        "independent_checks_passed": bool(project.independent_checks),
        "staging_checks_passed": bool(spec.get("stage")),
        "production_deployed": False,
        "requires": ["owner-reviewed immutable release adapter", "exact artifact digest release policy"],
        "commands": state.get("commands", []),
    }
    write_manifest(root / "candidates" / f"{ctx.job.id}.json", result)
    state["candidate"] = archive
    _checkpoint(ctx, state)
    ctx.log("Development candidate verified and archived", {"sha256": archive["sha256"], "commit": archive["commit"]})
    return result


def register() -> None:
    from serverhub.jobs import register_handler
    register_handler("development", development_job)
