"""Approved maintenance never includes replacement of its own trust controls."""
from pathlib import Path
import pytest
from serverhub.node import administration
from serverhub.node.docker_backup import DockerBackupError


@pytest.mark.parametrize('name',['apparmor','bubblewrap','python3.12','dpkg','apt','libseccomp2','serverhub-ai-os'])
def test_even_root_enrolled_metadata_cannot_replace_runtime_or_policy_controls(monkeypatch,name):
    monkeypatch.setattr(administration,'command',lambda *args,**kw:
        'Package: '+name+'\nVersion: 1.0\nArchitecture: all\n')
    with pytest.raises(DockerBackupError,match='Critical package'):
        administration.package_description(Path('/reviewed/artifact.deb'))
