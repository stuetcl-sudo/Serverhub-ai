"""Native command line. No arbitrary command/SQL execution is exposed to AI tools."""
import argparse
import getpass
import json
import sys
from pathlib import Path

from .auth import ROLES, hash_password
from .database import SessionLocal
from .models import User
from .settings import get_settings


def _alembic_config():
    from alembic.config import Config
    # Native release layout includes migrations beside the wheel-installed virtualenv.
    candidates = [Path.cwd() / "alembic.ini", Path(__file__).resolve().parents[2] / "alembic.ini",
                  Path("/opt/serverhub/current/alembic.ini")]
    for candidate in candidates:
        if candidate.is_file():
            return Config(str(candidate))
    raise RuntimeError("Cannot find alembic.ini; run from the repository/release root")


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
    health = sub.add_parser("health", help="Read the controller health endpoint")
    health.add_argument("--url", default="http://127.0.0.1:9080")
    args = parser.parse_args(argv)
    settings = get_settings()
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
            if db.scalar(select(User).where(User.username == args.username)):
                parser.error("username already exists; no credential was changed")
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
