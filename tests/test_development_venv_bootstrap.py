"""Regression coverage for isolated development Python bootstrapping.

The bare 'python' command must resolve inside the workspace venv, never to
the Ubuntu host interpreter or an unsandboxed fallback.
"""
from pathlib import Path

import pytest

from serverhub.development.config import Command, DevelopmentError, Project
from serverhub.development.sandbox import CommandResult, SandboxRunner


def project():
    return Project(name="jarvis-os", repository="https://example.invalid/jarvis.git",
                   tests=[Command(argv=["python", "-m", "pytest"])])


def test_dependency_command_uses_workspace_venv_first(tmp_path):
    (tmp_path / ".git").mkdir()
    runner = SandboxRunner(project(), binary="/usr/bin/bwrap")
    argv = runner.arguments(tmp_path, Command(argv=["python", "-m", "pip", "install", "pytest"]))
    assert argv[argv.index("--setenv") + 2].startswith("/workspace/.venv/bin:")
    assert argv[-5:] == ["--", "python", "-m", "pip", "install", "pytest"][-5:]


def test_preflight_creates_venv_only_inside_sandbox(tmp_path, monkeypatch):
    runner = SandboxRunner(project(), binary="/usr/bin/bwrap")
    calls = []

    def fake_run(workspace, command, **kwargs):
        calls.append(command.argv)
        if command.argv[:3] == ["/usr/bin/python3", "-m", "venv"]:
            (workspace / ".venv").mkdir()
        return CommandResult(command.argv, 0, "ready")

    monkeypatch.setattr(runner, "run", fake_run)
    result = runner.preflight(tmp_path)
    assert result["available"] is True
    assert calls[1] == ["/usr/bin/python3", "-m", "venv", "/workspace/.venv"]
    # A system Python without global pip is valid: ensurepip belongs to venv.
    assert "venv_available" in calls[0][-1]
    assert "find_spec('pip')" not in calls[0][-1]
    assert calls[2] == ["/workspace/.venv/bin/python", "-m", "pip", "--version"]
    assert calls[3] == ["/usr/bin/env", "python", "-m", "pip", "--version"]
    assert result["unsandboxed_fallback"] is False


def test_preflight_fails_closed_when_venv_bootstrap_fails(tmp_path, monkeypatch):
    runner = SandboxRunner(project(), binary="/usr/bin/bwrap")
    calls = []

    def fake_run(workspace, command, **kwargs):
        calls.append(command.argv)
        if len(calls) == 2:
            return CommandResult(command.argv, 1, "venv unavailable")
        return CommandResult(command.argv, 0, "ready")

    monkeypatch.setattr(runner, "run", fake_run)
    result = runner.preflight(tmp_path)
    assert result["available"] is False
    assert len(calls) == 2
    assert result["unsandboxed_fallback"] is False


def test_preflight_rejects_symlinked_virtualenv(tmp_path):
    outside = tmp_path.parent / "outside-venv"
    outside.mkdir(exist_ok=True)
    (tmp_path / ".venv").symlink_to(outside, target_is_directory=True)
    runner = SandboxRunner(project(), binary="/usr/bin/bwrap")
    with pytest.raises(DevelopmentError, match="real directory"):
        runner.preflight(tmp_path)


def test_preflight_blocks_missing_bare_python_even_if_venv_pip_works(tmp_path, monkeypatch):
    runner = SandboxRunner(project(), binary="/usr/bin/bwrap")
    calls = []

    def fake_run(workspace, command, **kwargs):
        calls.append(command.argv)
        if command.argv[:3] == ["/usr/bin/python3", "-m", "venv"]:
            (workspace / ".venv").mkdir()
        if command.argv[:2] == ["/usr/bin/env", "python"]:
            return CommandResult(command.argv, 127, "env: python: No such file or directory")
        return CommandResult(command.argv, 0, "ready")

    monkeypatch.setattr(runner, "run", fake_run)
    result = runner.preflight(tmp_path)
    assert result["available"] is False
    assert result["returncode"] == 127
    assert result["unsandboxed_fallback"] is False
    assert len(calls) == 4
