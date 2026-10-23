import subprocess

import pytest

from serverhub.development.config import Command, DevelopmentError, Project
from serverhub.development.sandbox import SandboxRunner
from serverhub.development.workspace import WorkspaceManager, git


def repository(path):
    path.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(path)], check=True, capture_output=True)
    git(path, "config", "user.name", "Test")
    git(path, "config", "user.email", "test@example.invalid")
    (path / "app.py").write_text("print('old')\n")
    git(path, "add", "app.py")
    git(path, "commit", "-m", "Initial")
    return path


def project(path):
    return Project(name="example", repository=str(path), tests=[Command(argv=["/usr/bin/python3", "app.py"])])


def test_real_git_branch_patch_and_deterministic_candidate(tmp_path):
    source = repository(tmp_path / "source")
    config = project(source)
    manager = WorkspaceManager(tmp_path / "workspaces")
    workspace = manager.prepare(config, "job-1")
    assert git(workspace, "branch", "--show-current").strip() == "serverhub/job-1"
    patch = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-print('old')\n+print('new')\n"
    result = manager.apply_patch(workspace, patch)
    assert result["changed_paths"] == ["app.py"]
    assert (source / "app.py").read_text() == "print('old')\n"
    one = manager.archive(workspace, config, destination=tmp_path / "one.tar")
    two = manager.archive(workspace, config, destination=tmp_path / "two.tar")
    assert one["sha256"] == two["sha256"]
    assert one["files"] == 1 and one["commit"] == result["commit"]


def test_symlink_and_metadata_patch_denied(tmp_path):
    source = repository(tmp_path / "source")
    manager = WorkspaceManager(tmp_path / "workspaces")
    config = project(source)
    workspace = manager.prepare(config, "job-2")
    (workspace / "escape").symlink_to(tmp_path / "source")
    with pytest.raises(DevelopmentError, match="symlink"):
        manager.archive(workspace, config, destination=tmp_path / "bad.tar")
    (workspace / "escape").unlink()
    patch = "diff --git a/.git/config b/.git/config\n--- a/.git/config\n+++ b/.git/config\n@@ -1 +1 @@\n-a\n+b\n"
    with pytest.raises(DevelopmentError):
        manager.apply_patch(workspace, patch)


def test_generated_dependency_symlinks_excluded_from_artifact(tmp_path):
    source = repository(tmp_path / "source")
    manager = WorkspaceManager(tmp_path / "workspaces")
    config = project(source)
    workspace = manager.prepare(config, "job-3")
    (workspace / "node_modules").mkdir()
    (workspace / "node_modules" / "tool").symlink_to("/bin/sh")
    result = manager.archive(workspace, config, destination=tmp_path / "clean.tar")
    assert result["files"] == 1


def test_sandbox_arguments_hide_host_secrets_and_disallow_network(tmp_path):
    source = repository(tmp_path / "source")
    runner = SandboxRunner(project(source), binary="/usr/bin/bwrap")
    args = runner.arguments(source, Command(argv=["/usr/bin/python3", "app.py"]))
    assert "--unshare-all" in args and "--clearenv" in args and "--share-net" not in args
    assert "/etc/serverhub" not in args and "/var/run/docker.sock" not in args
    assert args[args.index("--ro-bind") + 1] == "/usr"
    with pytest.raises(DevelopmentError, match="network permission"):
        runner.arguments(source, Command(argv=["/usr/bin/true"], network=True))


def test_arbitrary_network_build_config_rejected(tmp_path):
    with pytest.raises(ValueError, match="network"):
        Project(name="example", repository=str(tmp_path), tests=[Command(argv=["true"], network=True)])
    with pytest.raises(ValueError):
        Command(argv=["/root/private-script"])


def test_broker_receipt_does_not_duplicate_large_source_and_bounds_logs(tmp_path):
    import json
    from serverhub.development.workspace import write_manifest
    receipt = tmp_path / 'receipt.json'
    payload = {'verified':True,'candidate':{'sha256':'f'*64},'source_patch':'界'*400000,
               'source_changes':[{'content':'界'*400000}], 'commands':[{'returncode':0,'output':'x'*64000}]}
    write_manifest(receipt, payload)
    recorded = json.loads(receipt.read_text())
    assert recorded['verified'] and recorded['candidate'] == payload['candidate']
    assert 'source_patch' not in recorded and 'source_changes' not in recorded
    assert len(recorded['commands'][0]['output']) == 4000
    assert len(payload['commands'][0]['output']) == 64000


def test_repository_query_credentials_rejected():
    with pytest.raises(ValueError, match='credential-free'):
        Project(name='example',repository='https://github.com/example/private.git?token=secret',
                tests=[Command(argv=['/usr/bin/true'])])


def test_publishable_source_preserves_bytes_and_rejects_uncommitted_build_changes(tmp_path):
    import hashlib
    from serverhub.development.workspace import source_changes
    source = repository(tmp_path / 'source')
    base = git(source, 'rev-parse', 'HEAD').strip()
    content = b"print('new')\r\n"
    (source / 'app.py').write_bytes(content)
    git(source, 'add', 'app.py')
    git(source, 'commit', '-m', 'Verified source change')
    changes = source_changes(source, base, ['app.py'])
    assert changes[0]['content'].encode() == content
    assert changes[0]['sha256'] == hashlib.sha256(content).hexdigest()
    (source / 'app.py').write_text("print('changed by build')\n")
    assert source_changes(source, base, ['app.py']) is None
    git(source, 'checkout', '--', 'app.py')
    (source / 'generated.py').write_text("print('not committed')\n")
    assert source_changes(source, base, ['generated.py']) is None
