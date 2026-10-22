from __future__ import annotations
import base64
import io
import hashlib
import json
import subprocess
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverhub.ops.backup import BackupError, BackupManager, digest, postgres_environment
from serverhub.ops.installer import InstallError, Installer
from serverhub.ops.release import ReleaseError, ReleaseManager, canonical, safe_extract
from serverhub.ops.uninstall import uninstall

SOURCE = Path(__file__).resolve().parents[1]


def test_native_installer_stage_is_contained_and_records_real_files(tmp_path):
    result = Installer(SOURCE, root=tmp_path).stage()
    assert result["state"] == "staged"
    assert (tmp_path / "etc/systemd/system/serverhub-api.service").is_file()
    assert (tmp_path / "etc/serverhub/recovery.env").stat().st_mode & 0o777 == 0o600
    broker = (tmp_path / "etc/serverhub/broker.yaml").read_text()
    assert "socket_gid: 999" in broker
    assert "allowed_services: []" in broker
    content = (tmp_path / "etc/serverhub/api.env").read_text()
    assert "SERVERHUB_ALLOWED_ORIGINS='[\"https://serverhub.local\"]'" in content
    assert "STAGING_ONLY" in content
    assert result["files"]


def test_installer_rejects_real_root_staging_and_path_traversal(tmp_path):
    with pytest.raises(InstallError, match="separate"):
        Installer(SOURCE).stage()
    installer = Installer(SOURCE, root=tmp_path)
    with pytest.raises(InstallError):
        installer.path("/../../etc/passwd")
    (tmp_path / "etc").symlink_to(SOURCE)
    with pytest.raises(InstallError, match="escapes|symlink"):
        installer.write("/etc/injected", "no")


def test_node_stage_does_not_install_controller_credentials(tmp_path):
    Installer(SOURCE, root=tmp_path, role="node").stage()
    assert not (tmp_path / "etc/serverhub/api.env").exists()
    assert not (tmp_path / "etc/serverhub/worker.env").exists()
    assert not (tmp_path / "etc/systemd/system/serverhub-api.service").exists()
    assert (tmp_path / "etc/systemd/system/serverhub-node.service").exists()


def test_worker_and_node_are_not_root_or_docker_group():
    worker = (SOURCE / "packaging/systemd/serverhub-worker.service").read_text()
    node = (SOURCE / "packaging/systemd/serverhub-node.service").read_text()
    assert "User=serverhub-worker" in worker
    assert "User=serverhub-node" in node
    assert "NoNewPrivileges=true" in worker
    assert "ProtectSystem=strict" in worker
    assert "CapabilityBoundingSet=\n" in worker
    assert "SupplementaryGroups=docker" not in worker + node
    assert "serverhub-recovery" in worker
    grants = (SOURCE / "packaging/postgresql-grants.sql").read_text()
    assert "REVOKE UPDATE, DELETE, TRUNCATE ON audit" in grants
    assert "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON users, session_tokens, policies" in grants


def test_uninstall_plan_retains_backups_and_database():
    result = uninstall()
    assert result["apply"] is False
    assert "/var/backups/serverhub" in result["retain"]
    assert "PostgreSQL database/roles" in result["retain"]


def fake_pg(argv, **kwargs):
    if argv[0] == "pg_dump":
        Path(argv[argv.index("--file")+1]).write_bytes(b"disposable-pg-archive")
    return subprocess.CompletedProcess(argv, 0, stdout="2\n", stderr="")


def test_backup_checkpoint_checksum_and_tamper_detection(tmp_path):
    manager = BackupManager(tmp_path / "backups", require_root=False, runner=fake_pg)
    config = tmp_path / "configuration"
    config.write_text("no secret test data")
    saved = manager.create("postgresql://owner:test-password@127.0.0.1/disposable", [config])
    assert manager.verify(saved["id"])["files"]["postgres.dump"]["size"] > 0
    assert "test-password" not in json.dumps(saved)
    (tmp_path / "backups" / saved["id"] / "postgres.dump").write_bytes(b"changed")
    with pytest.raises(BackupError, match="checksum"):
        manager.verify(saved["id"])


def test_backup_credentials_never_in_argv_and_pgpass_private():
    with postgres_environment("postgresql://operator:p%3Ass%5Cword@127.0.0.1/disposable") as environment:
        path = Path(environment["PGPASSFILE"])
        assert path.stat().st_mode & 0o777 == 0o600
        assert "p\\:ss\\\\word" in path.read_text()
        assert "PGPASSWORD" not in environment
    assert not path.exists()


def test_backup_restore_refuses_nonempty_database(tmp_path):
    manager = BackupManager(tmp_path / "backups", require_root=False, runner=fake_pg)
    saved = manager.create("postgresql://owner@127.0.0.1/disposable")
    with pytest.raises(BackupError, match="empty database"):
        manager.restore(saved["id"], "postgresql://owner@127.0.0.1/disposable", confirm_database="disposable")
    with pytest.raises(BackupError, match="confirmation"):
        manager.restore(saved["id"], "postgresql://owner@127.0.0.1/disposable", confirm_database="production")


def test_backup_drill_only_uses_generated_database_and_cleans_it(tmp_path):
    calls = []
    def runner(argv, **kwargs):
        calls.append(argv)
        return fake_pg(argv, **kwargs)
    manager = BackupManager(tmp_path / "backups", require_root=False, runner=runner)
    saved = manager.create("postgresql://owner@127.0.0.1/disposable")
    result = manager.restore_drill(saved["id"], "postgresql://owner@127.0.0.1/disposable")
    assert result["state"] == "verified"
    created = next(x for x in calls if x[0] == "createdb")[-1]
    deleted = next(x for x in calls if x[0] == "dropdb")[-1]
    assert created == deleted
    assert created.startswith("serverhub_verify_")
    assert created != "disposable"


@pytest.mark.parametrize("name,link", [("../outside", False), ("/absolute", False), ("symlink", True)])
def test_release_extraction_rejects_traversal_and_symlinks(tmp_path, name, link):
    archive = tmp_path / "release.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        member = tarfile.TarInfo(name)
        if link:
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/passwd"
            output.addfile(member)
        else:
            member.size = 3
            output.addfile(member, io.BytesIO(b"bad"))
    with pytest.raises(ReleaseError, match="unsafe"):
        safe_extract(archive, tmp_path / "destination")
    assert not (tmp_path / "outside").exists()


def signed_bundle(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    for name in ["application.whl", "requirements.lock", "web.tar.gz", "alembic.ini", "migrations.tar.gz"]:
        (bundle / name).write_bytes(b"test-artifact")
    manifest = {"format": 1, "release_id": "release-candidate", "schema_revision": "0001_core", "trust_boundary_digest": "a"*64,
                "validation": {"passed": True}, "files": {path.name: digest(path) for path in bundle.iterdir()}}
    key = Ed25519PrivateKey.generate()
    public = tmp_path / "public.pem"
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    trust = tmp_path / "trust.sha256"
    trust.write_text("a"*64)
    (bundle / "release.json").write_bytes(canonical(manifest))
    (bundle / "release.sig").write_text(base64.b64encode(key.sign(canonical(manifest))).decode())
    manager = ReleaseManager(tmp_path / "install", tmp_path / "state", public_key=public, trust_digest=trust, require_root=False)
    return manager, bundle, manifest


def test_signed_release_rejects_artifact_tampering(tmp_path):
    manager, bundle, manifest = signed_bundle(tmp_path)
    assert manager.verify_bundle(bundle)["release_id"] == manifest["release_id"]
    (bundle / "application.whl").write_bytes(b"tampered")
    with pytest.raises(ReleaseError, match="checksum"):
        manager.verify_bundle(bundle)


def test_signed_release_rejects_trust_boundary_changes(tmp_path):
    manager, bundle, _ = signed_bundle(tmp_path)
    manager.trust_digest.write_text("b"*64)
    with pytest.raises(ReleaseError, match="trust boundaries"):
        manager.verify_bundle(bundle)


def test_signed_release_rejects_changed_manifest_signature(tmp_path):
    manager, bundle, manifest = signed_bundle(tmp_path)
    manifest["release_id"] = "forged"
    (bundle / "release.json").write_bytes(canonical(manifest))
    with pytest.raises(ReleaseError, match="signature"):
        manager.verify_bundle(bundle)


def test_release_independent_watchdog_restores_previous_symlink(tmp_path):
    install = tmp_path / "install"
    state = tmp_path / "state"
    old = install / "releases/old"
    new = install / "releases/new"
    old.mkdir(parents=True)
    new.mkdir()
    (install / "current").symlink_to(new)
    calls = []
    manager = ReleaseManager(install, state, require_root=False, clock=lambda: 1000,
                             runner=lambda argv, **kwargs: calls.append(argv))
    manager._protect()
    manager._write_journal({"state": "armed", "previous": str(old), "candidate": str(new), "deadline": 999})
    result = manager.watchdog()
    assert result["state"] == "reverted"
    assert (install / "current").resolve() == old
    assert calls[0] == ["systemctl", "restart", "serverhub-api.service", "serverhub-worker.service"]


def test_independent_recovery_units_do_not_execute_current_candidate():
    for name in ["serverhub-backup.service", "serverhub-recovery.service", "serverhub-release-watchdog.service"]:
        unit = (SOURCE / "packaging/systemd" / name).read_text()
        assert "ExecStart=/opt/serverhub/recovery/venv/bin/python" in unit
        assert "ExecStart=/opt/serverhub/current" not in unit


def test_release_extraction_rejects_duplicate_members_and_normalizes_modes(tmp_path):
    archive = tmp_path / "duplicate.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        for _ in range(2):
            member = tarfile.TarInfo("index.html")
            member.size = 2
            output.addfile(member, io.BytesIO(b"ok"))
    with pytest.raises(ReleaseError, match="unsafe"):
        safe_extract(archive, tmp_path / "duplicate")
    with tarfile.open(archive, "w:gz") as output:
        member = tarfile.TarInfo("index.html")
        member.size = 2
        member.mode = 0o777
        output.addfile(member, io.BytesIO(b"ok"))
    safe_extract(archive, tmp_path / "normalized")
    assert (tmp_path / "normalized/index.html").stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize('change', ['policy', 'autostart'])
def test_signed_release_cannot_lie_about_unchanged_python_code(tmp_path, change):
    import zipfile
    manager, bundle, manifest = signed_bundle(tmp_path)
    manager.code_hashes = tmp_path / 'code-anchor.json'
    original = b'protected policy implementation\n'
    manager.code_hashes.write_text(json.dumps({'format':1,'files':{'serverhub/policy.py':hashlib.sha256(original).hexdigest()}}))
    key = Ed25519PrivateKey.generate()
    manager.public_key.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    def signed_wheel(content, autostart=False):
        with zipfile.ZipFile(bundle / 'application.whl', 'w') as wheel:
            wheel.writestr('serverhub/policy.py', content)
            if autostart:
                wheel.writestr('autostart.pth', b'import malicious_startup\n')
        manifest['files']['application.whl'] = digest(bundle / 'application.whl')
        (bundle / 'release.json').write_bytes(canonical(manifest))
        (bundle / 'release.sig').write_text(base64.b64encode(key.sign(canonical(manifest))).decode())
    signed_wheel(original)
    assert manager.verify_bundle(bundle)['trust_boundary_digest'] == manifest['trust_boundary_digest']
    # Even a newly signed bundle claiming the same trust digest must preserve actual code bytes.
    signed_wheel(b'def authorize(*args): return True\n' if change == 'policy' else original, change == 'autostart')
    with pytest.raises(ReleaseError, match='protected code'):
        manager.verify_bundle(bundle)
