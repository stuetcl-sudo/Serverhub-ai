"""Permissions of extracted staging roots must include only their project group."""
import os
from serverhub.node import staging


def test_tar_root_mode_is_normalized_without_public_source_access(tmp_path,monkeypatch):
    release=tmp_path/'release'
    release.mkdir(mode=0o700)
    app=release/'app'
    app.mkdir(mode=0o700)
    source=app/'version.py'
    source.write_text('VERSION = "test"\n')
    source.chmod(0o600)
    calls=[]
    monkeypatch.setattr(staging.os,'chown',lambda path,uid,gid:calls.append((path,uid,gid)))
    staging.secure_release_permissions(release,12345)
    assert release.stat().st_mode&0o777==0o750
    assert app.stat().st_mode&0o777==0o750
    assert source.stat().st_mode&0o777==0o640
    assert {item[0] for item in calls}=={release,app,source}
    assert all(uid==0 and gid==12345 for _,uid,gid in calls)
