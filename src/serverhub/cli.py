"""Native command line. No arbitrary command/SQL execution is exposed to AI tools."""
import argparse
import getpass
import json
import sys
from pathlib import Path
import os

from .auth import ROLES, hash_password
from .database import SessionLocal
from .models import User
from .settings import get_settings


def _alembic_config():
    from alembic.config import Config
    # Native release layout includes migrations beside the wheel-installed virtualenv.
    explicit = os.environ.get("SERVERHUB_RELEASE_DIR")
    candidates = ([Path(explicit) / "alembic.ini"] if explicit else [])
    candidates += [Path("/opt/serverhub/current/alembic.ini"), Path(__file__).resolve().parents[2] / "alembic.ini"]
    try:
        candidates.append(Path.cwd() / "alembic.ini")
    except (PermissionError, FileNotFoundError):
        pass
    for candidate in candidates:
        try:
            if candidate.is_file():
                config = Config(str(candidate.resolve()))
                config.set_main_option("script_location", str(candidate.resolve().parent / "migrations"))
                # Installed modules are already on sys.path; never inherit a caller's
                # inaccessible source directory during a privilege transition.
                config.set_main_option("prepend_sys_path", "")
                return config
        except PermissionError:
            continue
    raise RuntimeError("Cannot locate migrations. Set SERVERHUB_RELEASE_DIR to the installed release directory")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="serverhub")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="Run the unprivileged HTTP controller")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    worker = sub.add_parser("worker", help="Run the durable PostgreSQL job executor")
    worker.add_argument("--once", action="store_true")
    worker.add_argument("--inline", action="store_true", help="Development only: disable per-job process isolation")
    migrate = sub.add_parser("migrate", help="Apply schema migrations as the dedicated migration identity")
    migrate.add_argument("--revision", default="head")
    user = sub.add_parser("create-user", help="Bootstrap an owner locally; requires migration-role DB access")
    user.add_argument("--username", required=True)
    user.add_argument("--role", choices=sorted(ROLES), default="owner")
    user.add_argument("--password-stdin", action="store_true")
    user.add_argument("--if-absent", action="store_true", help="Resume bootstrap without resetting existing credentials")
    health = sub.add_parser("health", help="Read the controller health endpoint")
    health.add_argument("--url", default="http://127.0.0.1:9080")
    sub.add_parser("doctor", help="Read-only local diagnostics (use API database environment)")
    args = parser.parse_args(argv)
    settings = get_settings()
    if args.command == "doctor":
        from .diagnostics import collect_diagnostics
        with SessionLocal() as db:
            report = collect_diagnostics(db)
        print(json.dumps(report, indent=2, default=str))
        return 0 if report["healthy"] else 1
    if args.command == "serve":
        import uvicorn
        uvicorn.run("serverhub.main:app", host=args.host or settings.api_bind, port=args.port or settings.api_port,
                    proxy_headers=False, access_log=True)
    elif args.command == "worker":
        from .jobs import Worker, load_plugins
        if args.inline and not settings.dev_mode:
            parser.error("--inline is isolated-development only")
        load_plugins()
        executor = Worker(isolated=not args.inline)
        if args.once:
            print(json.dumps({"executed": executor.run_once()}))
        else:
            executor.run_forever()
    elif args.command == "migrate":
        from alembic import command
        command.upgrade(_alembic_config(), args.revision)
        print(json.dumps({"migrated": args.revision}))
    elif args.command == "create-user":
        from sqlalchemy import select
        password = sys.stdin.readline().rstrip("\n") if args.password_stdin else getpass.getpass("New password (14+ characters): ")
        if not args.password_stdin and password != getpass.getpass("Repeat password: "):
            parser.error("passwords do not match")
        with SessionLocal() as db:
            existing = db.scalar(select(User).where(User.username == args.username))
            if existing:
                if args.if_absent and existing.role == args.role and existing.enabled:
                    print(json.dumps({"id": existing.id, "username": existing.username, "state": "retained"}))
                    return 0
                parser.error("username already exists with incompatible role/state; no credential was changed")
            account = User(username=args.username, password_hash=hash_password(password), role=args.role)
            db.add(account)
            db.commit()
            print(json.dumps({"id": account.id, "username": account.username, "role": account.role}))
    elif args.command == "health":
        import httpx
        response = httpx.get(args.url.rstrip("/") + "/health", timeout=5, follow_redirects=False)
        print(response.text)
        response.raise_for_status()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
