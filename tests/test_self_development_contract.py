"""Self-development enrollment is explicit and fail-closed by default."""
from pathlib import Path

import yaml

from serverhub.development.config import Project


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "docs/examples/serverhub-ai-project.yaml"


def test_self_development_example_is_valid_but_not_installed_by_default():
    raw = yaml.safe_load(EXAMPLE.read_text())
    assert set(raw) == {"projects"}
    assert len(raw["projects"]) == 1
    project = Project.model_validate(raw["projects"][0])
    assert project.name == "serverhub-ai"
    assert project.repository == "https://github.com/stuetcl-sudo/Serverhub-ai.git"
    assert project.base_ref == "release/autopilot-oauth-candidate"
    assert project.allow_dependency_network
    assert project.dependency_hosts == ["pypi.org", "files.pythonhosted.org"]
    assert project.checks_path == Path("/etc/serverhub/project-checks/serverhub-ai")
    assert len(project.independent_checks) == 1
    assert project.publication_token_env is None
    assert not project.publication_paths
    assert all(not command.network for command in project.build + project.tests + project.independent_checks)
    installed_default = yaml.safe_load((ROOT / "packaging/config/projects.yaml").read_text())
    assert installed_default == {"projects": []}


def test_self_development_checks_are_outside_editable_workspace():
    project = Project.model_validate(yaml.safe_load(EXAMPLE.read_text())["projects"][0])
    assert project.independent_checks[0].argv[-1] == "/checks/serverhub-ai-check.py"
    checks = (ROOT / "docs/examples/serverhub-ai-check.py").read_text()
    assert "Path(\"/workspace\")" in checks
    assert "development.release" in checks
    assert "--unshare-all" in checks
