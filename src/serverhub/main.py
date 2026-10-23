import importlib
import logging
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import FileResponse

from . import __version__
from .api import router
from .database import SessionLocal
from .jobs import load_plugins
from .policy import PermissionDenied
from .settings import get_settings

log = logging.getLogger(__name__)


class RequestSizeLimitMiddleware:
    """Bound request bodies even when a client omits Content-Length (chunked HTTP)."""

    def __init__(self, app, limit: int):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] in {"GET", "HEAD", "OPTIONS"}:
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        raw_length = headers.get(b"content-length")
        if raw_length is not None:
            try:
                length = int(raw_length)
                if length < 0:
                    raise ValueError()
            except ValueError:
                return await JSONResponse({"detail": "Invalid content length"}, 400)(scope, receive, send)
            if length > self.limit:
                return await JSONResponse({"detail": "Request body exceeds configured limit"}, 413)(scope, receive, send)
        messages, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > self.limit:
                return await JSONResponse({"detail": "Request body exceeds configured limit"}, 413)(scope, receive, send)
            messages.append(message)
            if not message.get("more_body", False):
                break
        index = 0

        async def replay():
            nonlocal index
            if index < len(messages):
                message = messages[index]
                index += 1
                return message
            return await receive()

        return await self.app(scope, replay, send)


def create_app() -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(app):
        load_plugins()
        yield

    app = FastAPI(title="ServerHub AI OS", version=__version__, lifespan=lifespan,
                  docs_url="/docs" if settings.enable_openapi else None,
                  openapi_url="/openapi.json" if settings.enable_openapi else None)
    if not settings.dev_mode:
        hostname = urlsplit(settings.public_url).hostname
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=[hostname, "127.0.0.1", "localhost", "::1"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        origin = request.headers.get("origin")
        allowed_origins = set(settings.allowed_origins) | {settings.public_url}
        # Same-origin loopback UI through an SSH tunnel. Never accept an
        # arbitrary Origin, LAN HTTP origin, or Origin unrelated to Host.
        if request.url.hostname in {"127.0.0.1", "localhost", "::1"}:
            allowed_origins.add(str(request.base_url).rstrip("/"))
        if origin and origin not in allowed_origins:
            return JSONResponse({"detail": "Origin is not allowed"}, status_code=403)
        if (request.method not in {"GET", "HEAD", "OPTIONS"} and request.cookies.get("serverhub_session")
                and not request.headers.get("authorization") and origin not in allowed_origins):
            return JSONResponse({"detail": "Cookie-authenticated writes require an allowed Origin"}, status_code=403)
        length = request.headers.get("content-length")
        if length:
            try:
                if int(length) > settings.max_request_bytes:
                    return JSONResponse({"detail": "Request body exceeds configured limit"}, status_code=413)
            except ValueError:
                return JSONResponse({"detail": "Invalid content length"}, status_code=400)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        if request.url.path.startswith(("/api", "/mcp", "/oauth")):
            response.headers["Cache-Control"] = "no-store"
        if not settings.dev_mode:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.exception_handler(PermissionDenied)
    async def permission_denied(request, exc):
        return JSONResponse({"detail": str(exc), "denial": exc.details}, status_code=403)

    @app.get("/health", include_in_schema=False)
    def health():
        try:
            from alembic.script import ScriptDirectory
            from .cli import _alembic_config
            expected = set(ScriptDirectory.from_config(_alembic_config()).get_heads())
            with SessionLocal() as db:
                db.execute(text("SELECT 1"))
                # A live connection without a migrated schema is not a healthy controller.
                installed = set(db.execute(text("SELECT version_num FROM alembic_version")).scalars())
                if installed != expected:
                    raise RuntimeError("Database migrations do not match the installed release")
            return {"status": "ok", "version": __version__, "database": "reachable"}
        except Exception:
            log.exception("Controller database healthcheck failed")
            return JSONResponse({"status": "unhealthy", "version": __version__, "database": "unavailable_or_unmigrated"}, status_code=503)

    app.include_router(router)
    for module_name in ("serverhub.node_api", "serverhub.extensions", "serverhub.mcp", "serverhub.setup"):
        try:
            extension = importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            if exc.name == module_name:
                continue
            raise
        extra_router = getattr(extension, "router", None)
        if extra_router:
            app.include_router(extra_router)
    frontend = settings.frontend_dir
    if (frontend / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=frontend / "assets"), name="assets")
    if (frontend / "index.html").is_file():
        @app.get("/{path:path}", include_in_schema=False)
        def frontend_index(path: str):
            # Never disguise a missing API route as an HTML success response.
            if path.split("/", 1)[0] in {"api", "mcp", ".well-known", "oauth", "assets"}:
                return JSONResponse({"detail": "Not found"}, status_code=404)
            candidate = (frontend / path).resolve()
            if path and candidate.is_relative_to(frontend.resolve()) and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(frontend / "index.html")
    app.add_middleware(RequestSizeLimitMiddleware, limit=settings.max_request_bytes)
    return app


app = create_app()
