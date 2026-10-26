"""Ollama download failures must never be mistaken for model availability."""
import subprocess

import pytest

from scripts.ollama_pull_retry import pull_model


def failure(message):
    return subprocess.CalledProcessError(1, ["ollama", "pull", "qwen2.5:3b"], stderr=message)


def test_transient_registry_503_retries_then_succeeds():
    attempts = []
    delays = []

    def runner(*args, **kwargs):
        attempts.append(kwargs)
        if len(attempts) < 3:
            raise failure("Error: 503: registry unavailable")
        return subprocess.CompletedProcess(args[0], 0, "", "")

    pull_model(["ollama", "pull", "qwen2.5:3b"], runner=runner, sleeper=delays.append)
    assert len(attempts) == 3
    assert delays == [10, 20]
    assert all(call["check"] and call["timeout"] == 600 for call in attempts)


def test_nontransient_pull_error_is_not_retried():
    attempts = []

    def runner(*args, **kwargs):
        attempts.append(True)
        raise failure("Error: model manifest not found")

    with pytest.raises(subprocess.CalledProcessError):
        pull_model(["ollama", "pull", "missing"], runner=runner, sleeper=lambda _: None)
    assert len(attempts) == 1


def test_persistent_503_fails_closed():
    attempts = []

    def runner(*args, **kwargs):
        attempts.append(True)
        raise failure("Error: 503")

    with pytest.raises(subprocess.CalledProcessError):
        pull_model(["ollama", "pull", "qwen2.5:3b"], runner=runner, sleeper=lambda _: None)
    assert len(attempts) == 3
