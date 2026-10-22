"""A small curated catalog with concrete, operator-reviewable Compose plans."""
from __future__ import annotations

import re
from typing import Any
import yaml

CATALOG = {
    "stirling-pdf": {
        "name": "Stirling PDF", "capabilities": ["pdf", "merge", "split", "convert", "ocr"],
        "description": "Browser-based PDF tools for conversion, splitting, merging and OCR.",
        "official_url": "https://docs.stirlingpdf.com/Server/Install/Docker/",
        "image_repository": "docker.stirlingpdf.com/stirlingtools/stirling-pdf",
        "container_port": 8080, "volume_mounts": {"stirling-config": "/configs", "stirling-data": "/usr/share/tessdata", "stirling-storage": "/storage"},
        "reason": "Appropriate for interactive PDF operations without introducing document indexing, Redis or a second database.",
        "limitations": ["Authentication must be configured for the selected pinned release before exposure", "OCR and conversion resource limits must fit the host"],
    },
    "paperless-ngx": {
        "name": "Paperless-ngx", "capabilities": ["pdf", "documents", "archive", "search", "ocr"],
        "description": "Document archive with OCR, tagging, search and ingestion workflows.",
        "official_url": "https://docs.paperless-ngx.com/setup/",
        "image_repository": "ghcr.io/paperless-ngx/paperless-ngx",
        "container_port": 8000, "volume_mounts": {"paperless-data": "/usr/src/paperless/data", "paperless-media": "/usr/src/paperless/media"},
        "reason": "Appropriate for a searchable document archive, with a separately registered Redis/database dependency plan.",
        "limitations": ["Dependency deployment and application secrets must be registered by the owner", "This catalog does not silently create database credentials"],
    },
}


def search(query: str = "") -> list[dict[str, Any]]:
    words = query.lower().split()
    scored = []
    for key, item in CATALOG.items():
        score = sum(word in " ".join(item["capabilities"] + [item["name"].lower(), item["description"].lower()]) for word in words)
        if not words or score:
            scored.append((score, {"id": key, **item}))
    return [item for _, item in sorted(scored, key=lambda pair: pair[0], reverse=True)]


def compose_plan(application: str, image_digest: str, port: int) -> dict:
    """Generate a plan, never deploy an arbitrary model-generated manifest.

    Exact image provenance and release-specific settings remain operator inputs.
    Broker deployments require this plan to be reviewed and registered as a
    root-owned, hash-pinned project first.
    """
    item = CATALOG.get(application)
    if not item:
        raise ValueError("Unknown catalog application")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_digest):
        raise ValueError("An operator-verified immutable SHA-256 image digest is required")
    if not 1024 <= port <= 65535:
        raise ValueError("Plan requires a non-privileged local port")
    if application == "paperless-ngx":
        return {"application": application, "deployable": False, "reason": item["reason"],
                "required_dependencies": ["owner-configured Redis", "owner-configured database", "protected secret file"],
                "documentation": item["official_url"]}
    document = {"name": application, "services": {application: {
        "image": item["image_repository"] + "@" + image_digest,
        "restart": "unless-stopped", "ports": [f"127.0.0.1:{port}:{item['container_port']}"],
        "security_opt": ["no-new-privileges:true"], "cap_drop": ["ALL"],
        "mem_limit": "4g", "cpus": 2.0, "pids_limit": 256,
        "volumes": [f"{name}:{mount}" for name, mount in item["volume_mounts"].items()],
        "logging": {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}},
    }}, "volumes": {name: {} for name in item["volume_mounts"]}}
    return {"application": application, "deployable": False, "compose": yaml.safe_dump(document, sort_keys=False),
            "reason": item["reason"], "required_steps": ["Verify digest and configure release-specific authentication", "Test startup/health in isolated staging", "Register root-owned broker project manifest and protected backup", "Register owner-approved reverse proxy route"],
            "limitations": item["limitations"]}
