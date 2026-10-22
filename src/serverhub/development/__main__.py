"""Inspect protected project configuration and sandbox availability."""
import argparse
import json
from pathlib import Path

from .config import load_projects, project_descriptors
from .sandbox import SandboxRunner


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config")
    parser.add_argument("--project")
    parser.add_argument("--sandbox-check", type=Path)
    args = parser.parse_args()
    if args.sandbox_check:
        projects = load_projects(args.config)
        if not args.project or args.project not in projects:
            parser.error("--sandbox-check requires a configured --project")
        result = SandboxRunner(projects[args.project]).preflight(args.sandbox_check)
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["available"] else 1)
    print(json.dumps(project_descriptors(args.config), indent=2))


if __name__ == "__main__":
    main()
