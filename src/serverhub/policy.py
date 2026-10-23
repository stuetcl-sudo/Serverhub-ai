"""Server-side authorization. Model text is never authority.

Role ceilings and unexpired database grants are intersected. Owner infrastructure
writes are still policy gated. Missing scope cannot match a restricted grant.
"""
import math

from sqlalchemy import or_, select

from .database import utcnow
from .models import Host, Policy, SystemState, User


class PermissionDenied(Exception):
    def __init__(self, message, *, details=None):
        super().__init__(message)
        self.details = details or {}



FORBIDDEN = {
    "shell.exec", "command.exec", "credentials.write", "database.destroy", "database.drop",
    "security.disable", "audit.disable", "policy.disable", "policy.modify", "ssh.modify",
    "sudo.modify", "agent.exec", "docker.exec", "firewall.flush",
}
CONTROL = {"policy.manage", "users.manage", "models.manage", "node.enroll", "node.revoke", "emergency.manage"}
GLOBAL_READ = {"job.submit", "incident.report", "jobs.read-own", "profile.read"}
READ_SUFFIXES = (".read", ".list", ".status", ".inspect", ".metrics", ".discover", ".diagnose", ".lookup", ".query")
ADULT_OPS = {"inventory.read", "inventory.refresh", "network.diagnose", "dns.lookup", "systemd.status",
             "systemd.restart", "docker.restart", "docker.inspect", "docker.list", "homeassistant.states",
             "homeassistant.health", "adguard.status", "adguard.filter.refresh", "monitoring.read", "incident.report",
             "diagnostics.network"}
STANDARD_OPS = {"inventory.read", "network.diagnose", "diagnostics.network", "dns.lookup", "systemd.status", "monitoring.read", "incident.report"}


def is_read(operation: str) -> bool:
    return operation.endswith(READ_SUFFIXES) or operation in {
        "inventory.read", "inventory.refresh", "discovery.refresh", "diagnostics.network", "host.audit", "diagnostics.storage",
        "systemd.logs", "task.verify", "docker.backup.verify", "docker.restore.plan", "package.plan", "configuration.plan", "homeassistant.states", "homeassistant.health", "adguard.status"}


def operation_matches(pattern: str, operation: str) -> bool:
    if pattern == operation:
        return True
    # Wildcards are explicit prefix capabilities, never an arbitrary fnmatch expression.
    return pattern.endswith(".*") and operation.startswith(pattern[:-1])


def constraints_match(constraints: dict, arguments: dict) -> bool:
    """Exact argument allowlists. Operators must name every allowed target explicitly.

    `service_names` is shorthand for service, `container_names` for container,
    `integration_ids` for integration_id; other constraint keys match same-named args.
    `max_<field>` only accepts numeric values at or below the ceiling.
    """
    aliases = {"service_names": "service", "container_names": "container", "integration_ids": "integration_id",
               "release_digests": "digest", "project_names": "project"}
    for key, expected in constraints.items():
        if key.startswith("max_"):
            actual = arguments.get(key[4:])
            if (not isinstance(expected, (int, float)) or isinstance(expected, bool)
                    or not math.isfinite(expected) or not isinstance(actual, (int, float))
                    or isinstance(actual, bool) or not math.isfinite(actual) or actual > expected):
                return False
            continue
        actual = arguments.get(aliases.get(key, key))
        if isinstance(expected, list):
            if isinstance(actual, list):
                if not actual or not all(item in expected for item in actual):
                    return False
            elif actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


def _authorize(db, principal, operation: str, host_id: str | None = None, project: str | None = None,
              arguments: dict | None = None, production: bool = False) -> Policy | None:
    user = db.get(User, principal.id)
    if user:
        db.refresh(user)
    if not user or not user.enabled or user.role != principal.role:
        raise PermissionDenied("Authenticated account is disabled or its role changed")
    if operation in FORBIDDEN or any(operation.startswith(x + ".") for x in FORBIDDEN):
        raise PermissionDenied("Operation is outside the platform trust boundary")
    if operation in CONTROL:
        if principal.role != "owner":
            raise PermissionDenied("Owner role required")
        return None
    if host_id:
        host = db.get(Host, host_id)
        if host:
            db.refresh(host)
        if not host or host.revoked:
            raise PermissionDenied("Target host unavailable or revoked")
    if operation in GLOBAL_READ and principal.role != "readonly":
        return None
    if operation == "profile.read":
        return None
    if principal.role == "readonly" and not is_read(operation):
        raise PermissionDenied("Read-only role cannot perform this operation")
    if principal.role == "adult" and operation not in ADULT_OPS and not is_read(operation):
        raise PermissionDenied("Operation exceeds household role capabilities")
    if principal.role == "user" and operation not in STANDARD_OPS and not is_read(operation):
        raise PermissionDenied("Operation exceeds standard user capabilities")
    if principal.role == "owner" and is_read(operation):
        return None
    emergency = db.get(SystemState, "emergency_stop")
    if emergency:
        db.refresh(emergency)
    if emergency and emergency.value.get("enabled") and not is_read(operation):
        raise PermissionDenied("Emergency stop is active")
    production = production or operation in {"release.production", "development.release", "production.deploy", "network.apply", "firewall.apply"}
    grants = db.scalars(select(Policy).where(
        Policy.enabled.is_(True), Policy.expires_at > utcnow(),
        or_(Policy.subject_id == principal.id, Policy.role == principal.role),
    ).execution_options(populate_existing=True)).all()
    for grant in grants:
        if grant.host_id is not None and grant.host_id != host_id:
            continue
        if grant.project is not None and grant.project != project:
            continue
        if production and not grant.production:
            continue
        environment = operation_environment(operation, arguments or {}, production)
        if grant.environment not in {"any", environment}:
            continue
        if not any(operation_matches(pattern, operation) for pattern in grant.operations):
            continue
        if not constraints_match(grant.constraints or {}, arguments or {}):
            continue
        return grant
    raise PermissionDenied("No active policy permits this operation on the requested target")



def operation_environment(operation, arguments=None, production=False):
    if production or operation in {"release.production", "development.release", "production.deploy", "network.apply", "firewall.apply"}:
        return "production"
    if operation in {"development.stage", "development.deploy"} or (arguments or {}).get("stage") is True:
        return "staging"
    if operation.startswith("development."):
        return "development"
    return "read" if is_read(operation) else "maintenance"


def authorize(db, principal, operation: str, host_id=None, project=None, arguments=None, production=False):
    try:
        return _authorize(db, principal, operation, host_id, project, arguments, production)
    except PermissionDenied as exc:
        from .audit import redact
        details = {"operation": operation, "host_id": host_id, "project": project,
                   "arguments": redact(arguments or {}), "environment": operation_environment(operation, arguments, production),
                   "reason": str(exc), "missing_permission": operation,
                   "remediation": "An owner must grant this exact operation for this identity, target, arguments and environment with a future expiry, then resume the original job. Node broker allowlists are checked separately."}
        raise PermissionDenied(f"{operation} denied for host={host_id or '(none)'} project={project or '(none)'}: {exc}", details=details) from exc

def visible_host_ids(db, principal) -> list[str]:
    result = []
    for host in db.scalars(select(Host)).all():
        try:
            authorize(db, principal, "inventory.read", host.id)
            result.append(host.id)
        except PermissionDenied:
            pass
    return result
