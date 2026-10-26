"""Owner-controlled independent checks for self-development candidates.

Install as root at /etc/serverhub/project-checks/serverhub-ai/serverhub-ai-check.py.
The runner mounts it read-only at /checks, outside the editable Git workspace.
This is a minimal safety gate, NOT a substitute for complete CI or release review.
"""
from pathlib import Path

ROOT = Path("/workspace")
required = {
    "src/serverhub/development/workflow.py": (
        "production deployment requires a separately configured release adapter",
        "development.release",
    ),
    "src/serverhub/development/sandbox.py": (
        "--unshare-all",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--ro-bind",
    ),
    "src/serverhub/development/config.py": (
        "require_protected_file",
        "allow_dependency_network",
    ),
}
for relative, guards in required.items():
    target = ROOT / relative
    if not target.is_file() or target.is_symlink():
        raise SystemExit(f"missing or unsafe guarded source: {relative}")
    source = target.read_text()
    for guard in guards:
        if guard not in source:
            raise SystemExit(f"independent guard absent: {relative} / {guard}")
print("Independent self-development baseline guards present (static check only)")
