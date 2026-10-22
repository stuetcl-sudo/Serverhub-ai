#!/usr/bin/env python3
"""Package validated native artifacts; signing key stays outside the repository."""
# ruff: noqa: E402
import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from serverhub.ops.installer import Installer
from serverhub.ops.release import canonical
from alembic.config import Config
from alembic.script import ScriptDirectory
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def archive(source, destination):
    with destination.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as target:
            for path in sorted(source.rglob("*")):
                if path.is_symlink():
                    raise ValueError("artifact source contains a symlink")
                if not path.is_file() or "__pycache__" in path.parts:
                    continue
                item = target.gettarinfo(str(path), arcname=str(path.relative_to(source)))
                item.uid = item.gid = item.mtime = 0
                item.uname = item.gname = ""
                item.mode = 0o644
                with path.open("rb") as contents:
                    target.addfile(item, contents)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--validation", type=Path, required=True, help="independently reviewed successful verification JSON")
    parser.add_argument("--signing-key", type=Path, required=True, help="external owner-controlled Ed25519 PEM key")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", args.release_id):
        parser.error("invalid release identifier")
    validation = json.loads(args.validation.read_text())
    if validation.get("state") != "passed" or not validation.get("checks"):
        parser.error("successful independent validation evidence is required")
    key_path = args.signing_key.resolve()
    if key_path.is_relative_to(ROOT) or key_path.stat().st_mode & 0o077:
        parser.error("private key must be external and mode0600 or stricter")
    private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        parser.error("Ed25519 private key required")
    wheels = list((ROOT / "dist").glob("*.whl"))
    if len(wheels) != 1 or not (ROOT / "frontend/dist/index.html").is_file():
        parser.error("build exactly one wheel and the frontend before packaging")
    args.output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(wheels[0], args.output / "application.whl")
    for name in ("requirements.lock", "alembic.ini"):
        shutil.copyfile(ROOT / name, args.output / name)
    shutil.copyfile(args.validation, args.output / "validation.json")
    archive(ROOT / "frontend/dist", args.output / "web.tar.gz")
    archive(ROOT / "migrations", args.output / "migrations.tar.gz")
    revision = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini"))).get_current_head()
    manifest = {"format": 1, "release_id": args.release_id, "schema_revision": revision,
                "trust_boundary_digest": Installer(ROOT).trust_digest(),
                "validation": {"passed": True, "evidence": "validation.json"},
                "files": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(args.output.iterdir())}}
    (args.output / "release.json").write_bytes(canonical(manifest))
    (args.output / "release.sig").write_text(base64.b64encode(private.sign(canonical(manifest))).decode() + "\n")
    print(json.dumps({"release_id": args.release_id, "output": str(args.output), "schema_revision": revision, "files": len(manifest["files"])}))


if __name__ == "__main__":
    main()
