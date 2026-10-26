"""Bounded retries for transient Ollama registry failures in disposable CI.

Never treats a failed pull as success. The caller must independently verify
the model is installed before running real inference.
"""
from __future__ import annotations

import subprocess
import time


def pull_model(command, *, runner=subprocess.run, sleeper=time.sleep, attempts=3):
    if attempts < 1:
        raise ValueError("attempts must be positive")
    for attempt in range(1, attempts + 1):
        try:
            runner(command, check=True, capture_output=True, text=True, timeout=600)
            return
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr or ""
            # The registry returns HTTP 503 during transient model-layer pulls.
            # Never retry auth, disk, checksum, model or other permanent errors.
            transient = "Error: 503" in stderr or "error: 503" in stderr
            if not transient or attempt == attempts:
                raise
            print(f"OLLAMA_REGISTRY_503_RETRY={attempt}/{attempts}", flush=True)
            sleeper(10 * attempt)
