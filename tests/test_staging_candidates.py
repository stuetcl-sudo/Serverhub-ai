"""Candidate authentication uses actual files, hashes and no-follow directory handles."""
import hashlib
import json
import pytest
from serverhub.node.staging import snapshot_candidate
from serverhub.node.docker_backup import DockerBackupError


def test_candidate_snapshot_is_stable_after_worker_changes_its_copy(tmp_path):
    source=tmp_path/'source'
    source.mkdir()
    content=b'candidate archive'
    (source/'job.tar').write_bytes(content)
    (source/'job.json').write_text(json.dumps({'candidate':{'sha256':hashlib.sha256(content).hexdigest()}}))
    destination=tmp_path/'snapshot'
    snapshot_candidate(source,'job',destination)
    (source/'job.tar').write_bytes(b'changed')
    assert destination.read_bytes()==content
    assert destination.stat().st_mode&0o777==0o600


def test_candidate_symlink_cannot_make_root_read_another_file(tmp_path):
    source=tmp_path/'source'
    source.mkdir()
    (source/'job.json').write_text('{}')
    (source/'job.tar').symlink_to('/etc/passwd')
    with pytest.raises(OSError):
        snapshot_candidate(source,'job',tmp_path/'snapshot')
    assert not (tmp_path/'snapshot').exists()


def test_symlinked_candidate_root_is_rejected(tmp_path):
    actual=tmp_path/'actual'
    actual.mkdir()
    link=tmp_path/'link'
    link.symlink_to(actual,target_is_directory=True)
    with pytest.raises(OSError):
        snapshot_candidate(link,'job',tmp_path/'snapshot')


def test_wrong_candidate_digest_leaves_no_root_snapshot(tmp_path):
    (tmp_path/'job.json').write_text(json.dumps({'candidate':{'sha256':'0'*64}}))
    (tmp_path/'job.tar').write_bytes(b'modified')
    with pytest.raises(DockerBackupError,match='digest'):
        snapshot_candidate(tmp_path,'job',tmp_path/'snapshot')
    assert not (tmp_path/'snapshot').exists()
