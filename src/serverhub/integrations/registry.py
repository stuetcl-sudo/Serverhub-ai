"""Static operation registry. No arbitrary URL, HTTP verb, SQL or command tool.

The root-owned YAML identifies endpoints and capabilities. Secret values are
read only from named environment variables and are never returned in descriptors.
Every call must additionally pass the controller's persisted policy engine.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from serverhub.ai.providers import read_operator_yaml, validate_url


class IntegrationError(RuntimeError):
    def __init__(self, message: str, *, retryable: bool = False, rollback: dict | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.rollback = rollback


class IntegrationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str
    base_url: str
    token_env: str | None = None
    username_env: str | None = None
    password_env: str | None = None
    allow_insecure_http: bool = False
    ca_file: str | None = None
    allowed_operations: list[str] = Field(default_factory=list)
    allowed_entities: list[str] = Field(default_factory=list)
    allowed_sites: list[str] = Field(default_factory=list)
    allowed_repositories: list[str] = Field(default_factory=list)
    allowed_queries: dict[str, str] = Field(default_factory=dict)
    filter_sources: dict[str, str] = Field(default_factory=dict)
    validation_domains: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=20, ge=1, le=120)
    max_response_bytes: int = Field(default=2 * 1024 * 1024, ge=1024, le=16 * 1024 * 1024)

    @model_validator(mode="after")
    def safe_config(self):
        for env_ref in (self.token_env, self.username_env, self.password_env):
            if env_ref and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", env_ref):
                raise ValueError("Credential references must name environment variables")
        if self.kind not in {"home_assistant", "adguard", "unifi", "uisp", "prometheus", "grafana", "github", "serverhub_mcp", "postgresql"}:
            raise ValueError("Unknown integration kind")
        if self.kind == "postgresql":
            # base_url is not a DSN and cannot contain credentials. The DSN
            # lives exclusively in token_env and uses a read-only DB account.
            if self.base_url != "postgresql":
                raise ValueError("PostgreSQL base_url must be the literal postgresql; set token_env for DSN")
        else:
            self.base_url = validate_url(self.base_url, allow_http=self.allow_insecure_http)
        for source in self.filter_sources.values():
            if not source.startswith("https://"):
                raise ValueError("Filter sources require fixed HTTPS URLs")
            validate_url(source)
        for name, expected in self.validation_domains.items():
            if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", name) or expected not in {"allowed", "blocked"}:
                raise ValueError("Invalid DNS canary")
        return self


class Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid")
    integration_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")


class EntityArguments(Arguments):
    entity_id: str = Field(pattern=r"^(light|switch|input_boolean)\.[a-z0-9_]{1,100}$")
    power: bool


class SiteArguments(Arguments):
    site_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")


class QueryArguments(Arguments):
    query: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")


class RepoArguments(Arguments):
    repository: str = Field(pattern=r"^[a-zA-Z0-9_.-]{1,100}/[a-zA-Z0-9_.-]{1,100}$")


class RuleArguments(Arguments):
    rules: list[str] = Field(max_length=1000)

    @field_validator("rules")
    @classmethod
    def bounded_rules(cls, values):
        # Deliberately support only domain block/allow rules, no arbitrary
        # rewrites, redirects, file paths or client-specific configuration.
        if any(not re.fullmatch(r"(@@)?\|\|[a-zA-Z0-9.-]{1,253}\^", rule) for rule in values):
            raise ValueError("Only simple domain block/allow rules are supported")
        return list(dict.fromkeys(values))


class FilterArguments(Arguments):
    source: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    old_filter_id: int = Field(ge=1)


@dataclass(frozen=True)
class Operation:
    name: str
    kind: str
    arguments: type[Arguments]
    description: str
    writes: bool = False


OPERATIONS = {
    item.name: item for item in [
        Operation("home_assistant.status", "home_assistant", Arguments, "Read Home Assistant API health"),
        Operation("home_assistant.states", "home_assistant", Arguments, "Read configured entity states"),
        Operation("home_assistant.set_power", "home_assistant", EntityArguments, "Set an allowlisted light/switch/input_boolean and verify or roll back", True),
        Operation("adguard.status", "adguard", Arguments, "Read AdGuard health and statistics"),
        Operation("adguard.filters", "adguard", Arguments, "Read filter sources and custom rules"),
        Operation("adguard.refresh_filters", "adguard", Arguments, "Refresh configured filter subscriptions", True),
        Operation("adguard.set_rules", "adguard", RuleArguments, "Set simple domain rules with persisted checkpoint, canary verification and rollback", True),
        Operation("adguard.replace_filter", "adguard", FilterArguments, "Replace a filter with an owner-vetted HTTPS source, verify canaries, restore on failure", True),
        Operation("unifi.sites", "unifi", Arguments, "List sites through the official UniFi Network Integration API"),
        Operation("unifi.devices", "unifi", SiteArguments, "Read official adopted-device inventory for an allowed site"),
        Operation("unifi.clients", "unifi", SiteArguments, "Read official client inventory for an allowed site"),
        Operation("uisp.devices", "uisp", Arguments, "Read UISP Network API v2.1 device inventory"),
        Operation("uisp.sites", "uisp", Arguments, "Read UISP Network API v2.1 site inventory"),
        Operation("prometheus.query", "prometheus", QueryArguments, "Execute a fixed named PromQL query"),
        Operation("grafana.health", "grafana", Arguments, "Read Grafana API health"),
        Operation("grafana.dashboards", "grafana", Arguments, "Read Grafana dashboard index"),
        Operation("github.repository", "github", RepoArguments, "Read metadata and latest commits for an allowlisted repository"),
        Operation("postgresql.health", "postgresql", Arguments, "Read database version, connection and size through a read-only transaction"),
        Operation("serverhub_mcp.tools", "serverhub_mcp", Arguments, "Read existing ServerHub MCP tool metadata; no unrestricted delegation"),
    ]
}


def operation_schemas() -> list[dict]:
    return [{"type": "function", "function": {"name": name.replace(".", "__"), "description": item.description,
        "parameters": item.arguments.model_json_schema()}} for name, item in OPERATIONS.items()]


def load_integrations(path: str | Path | None = None) -> dict[str, IntegrationConfig]:
    if path is None:
        try:
            from serverhub.settings import get_settings
            path = getattr(get_settings(), "integration_config_path", "/etc/serverhub/integrations.yaml")
        except ImportError:
            path = "/etc/serverhub/integrations.yaml"
    data = read_operator_yaml(path).get("integrations", {})
    if not isinstance(data, dict):
        raise ValueError("integrations must be a mapping")
    result = {}
    for name, value in data.items():
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", name):
            raise ValueError("Invalid integration identifier")
        result[name] = IntegrationConfig.model_validate(value)
    return result


def describe_integrations(config: dict[str, IntegrationConfig] | None = None) -> list[dict]:
    configs = load_integrations() if config is None else config
    return [{"id": name, "kind": item.kind, "operations": [op for op in item.allowed_operations if op in OPERATIONS],
             "configured": True, "transport": "HTTPS" if item.base_url.startswith("https:") else ("PostgreSQL" if item.kind == "postgresql" else "HTTP (explicitly configured)"),
             "verification": "not_live_verified"} for name, item in configs.items()]


SENSITIVE_KEYS = {"password", "token", "access_token", "refresh_token", "secret", "api_key", "authorization", "cookie", "set-cookie", "password_hash", "dsn", "credentials"}


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): "[redacted]" if str(key).lower() in SENSITIVE_KEYS or any(secret in str(key).lower() for secret in ("password", "secret", "private_key")) else redact(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def secret(name: str | None, *, required=False) -> str | None:
    value = os.environ.get(name) if name else None
    if required and not value:
        raise IntegrationError("Integration credential is unavailable")
    return value


class APIClient:
    def __init__(self, cfg: IntegrationConfig, transport=None):
        self.cfg = cfg
        headers = {"Accept": "application/json, text/event-stream" if cfg.kind == "serverhub_mcp" else "application/json"}
        token = secret(cfg.token_env)
        if token:
            header = {"unifi": "X-API-Key", "uisp": "x-auth-token"}.get(cfg.kind, "Authorization")
            headers[header] = token if header != "Authorization" else f"Bearer {token}"
        auth = None
        if cfg.username_env or cfg.password_env:
            auth = httpx.BasicAuth(secret(cfg.username_env, required=True), secret(cfg.password_env, required=True))
        self.client = httpx.Client(headers=headers, auth=auth, timeout=cfg.timeout_seconds,
                                   verify=cfg.ca_file or True, follow_redirects=False, transport=transport, trust_env=False)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.client.close()

    def request(self, method: str, path: str, *, body=None, params=None) -> Any:
        if (path and not path.startswith("/")) or path.startswith("//") or ".." in path:
            raise IntegrationError("Invalid fixed API path")
        try:
            with self.client.stream(method, self.cfg.base_url + path, json=body, params=params) as response:
                raw = b""
                if self.cfg.kind == "serverhub_mcp" and response.headers.get("Mcp-Session-Id"):
                    self.client.headers["Mcp-Session-Id"] = response.headers["Mcp-Session-Id"]
                for chunk in response.iter_bytes():
                    raw += chunk
                    if len(raw) > self.cfg.max_response_bytes:
                        raise IntegrationError("Integration response exceeds configured bound")
                if response.status_code >= 300:
                    raise IntegrationError(f"Integration request failed (HTTP {response.status_code})", retryable=response.status_code in (429, 502, 503, 504))
                if not raw:
                    return {}
                try:
                    return json.loads(raw)
                except (ValueError, TypeError) as exc:
                    raise IntegrationError("Integration returned invalid JSON") from exc
        except httpx.HTTPError as exc:
            raise IntegrationError("Integration transport failed", retryable=True) from exc


def _checkpoint(callback, data):
    if callback is None:
        raise IntegrationError("Write requires a durable checkpoint callback")
    callback(redact(data))


def _canaries(client: APIClient, cfg: IntegrationConfig) -> dict:
    if set(cfg.validation_domains.values()) != {"allowed", "blocked"}:
        raise IntegrationError("DNS writes require operator-configured allowed and blocked canary domains")
    outcomes = {}
    for domain, expected in cfg.validation_domains.items():
        response = client.request("GET", "/control/filtering/check_host", params={"name": domain})
        # AdGuard documented reasons include FilteredBlackList, FilteredSafe*
        # and NotFilteredWhiteList/NotFilteredNotFound.
        reason = str(response.get("reason", ""))
        blocked = reason.startswith("Filtered")
        if not reason or blocked != (expected == "blocked"):
            raise IntegrationError("DNS filter canary verification failed")
        outcomes[domain] = {"reason": reason, "expected": expected, "passed": True}
    return outcomes


def _set_power(client, cfg, args, checkpoint):
    if args.entity_id not in cfg.allowed_entities:
        raise IntegrationError("Entity is not in the operator allowlist")
    path = "/api/states/" + args.entity_id
    before = client.request("GET", path)
    previous = before.get("state")
    if previous not in ("on", "off"):
        raise IntegrationError("Entity has no reversible on/off state")
    _checkpoint(checkpoint, {"operation": "home_assistant.set_power", "entity_id": args.entity_id, "previous_state": previous})
    desired = "on" if args.power else "off"
    domain = args.entity_id.split(".")[0]
    try:
        client.request("POST", f"/api/services/{domain}/turn_{desired}", body={"entity_id": args.entity_id})
        current = client.request("GET", path)
        if current.get("state") != desired:
            raise IntegrationError("Home Assistant state verification failed")
        return {"entity_id": args.entity_id, "state": desired, "verified": True, "physical_state_verified": False}
    except IntegrationError as exc:
        try:
            client.request("POST", f"/api/services/{domain}/turn_{previous}", body={"entity_id": args.entity_id})
            restored = client.request("GET", path).get("state") == previous
        except IntegrationError:
            restored = False
        raise IntegrationError("Home Assistant change failed; rollback attempted", rollback={"verified": restored}) from exc


def _set_rules(client, cfg, args, checkpoint):
    _canaries(client, cfg)
    before = client.request("GET", "/control/filtering/status")
    previous = before.get("user_rules")
    if not isinstance(previous, list):
        raise IntegrationError("AdGuard did not return a restorable rules checkpoint")
    _checkpoint(checkpoint, {"operation": "adguard.set_rules", "user_rules": previous})
    try:
        client.request("POST", "/control/filtering/set_rules", body={"rules": args.rules})
        actual = client.request("GET", "/control/filtering/status")
        if actual.get("user_rules") != args.rules:
            raise IntegrationError("AdGuard rule readback mismatch")
        checks = _canaries(client, cfg)
        return {"verified": True, "rule_count": len(args.rules), "canaries": checks}
    except IntegrationError as exc:
        try:
            client.request("POST", "/control/filtering/set_rules", body={"rules": previous})
            restored = client.request("GET", "/control/filtering/status").get("user_rules") == previous
            _canaries(client, cfg)
        except IntegrationError:
            restored = False
        raise IntegrationError("AdGuard rule change failed; rollback attempted", rollback={"verified": restored}) from exc


def _replace_filter(client, cfg, args, checkpoint, transport):
    candidate_url = cfg.filter_sources.get(args.source)
    if not candidate_url:
        raise IntegrationError("Replacement source is not in the operator-vetted catalog")
    checks_before = _canaries(client, cfg)
    before = client.request("GET", "/control/filtering/status")
    old = next((f for f in before.get("filters", []) if f.get("id") == args.old_filter_id), None)
    if not old or not old.get("enabled") or not isinstance(old.get("url"), str):
        raise IntegrationError("Original active filter was not found")
    if any(f.get("url") == candidate_url for f in before.get("filters", [])):
        raise IntegrationError("Replacement source is already configured")
    # Download candidate without AdGuard credentials or authorization headers.
    try:
        with httpx.Client(timeout=cfg.timeout_seconds, follow_redirects=False, transport=transport, trust_env=False) as public:
            with public.stream("GET", candidate_url) as response:
                raw = b""
                for chunk in response.iter_bytes():
                    raw += chunk
                    if len(raw) > 16 * 1024 * 1024:
                        raise IntegrationError("Replacement filter exceeds 16 MiB")
                if response.status_code != 200:
                    raise IntegrationError("Replacement filter download failed")
                text = raw.decode("utf-8")
        rules = [line for line in text.splitlines() if line.strip() and not line.startswith(("!", "#", "["))]
        if len(rules) < 10 or "<html" in text[:1024].lower():
            raise IntegrationError("Replacement filter has insufficient plausible filtering rules")
    except (httpx.HTTPError, UnicodeDecodeError) as exc:
        raise IntegrationError("Replacement filter is unavailable or invalid") from exc
    _checkpoint(checkpoint, {"operation": "adguard.replace_filter", "original_filter": old,
                             "candidate_url": candidate_url, "before_canaries": checks_before})
    added = False
    try:
        client.request("POST", "/control/filtering/add_url", body={"name": f"ServerHub vetted: {args.source}", "url": candidate_url, "whitelist": False})
        added = True
        client.request("POST", "/control/filtering/refresh", body={"whitelist": False})
        current = client.request("GET", "/control/filtering/status")
        replacement = next((f for f in current.get("filters", []) if f.get("url") == candidate_url), None)
        if not replacement or not replacement.get("enabled") or int(replacement.get("rules_count", 0)) < 10:
            raise IntegrationError("Replacement did not load active filtering rules")
        # Keep the previous source configured but disable it only once the
        # replacement has loaded. No source is deleted as an inference of use.
        old_data = {k: old[k] for k in ("name", "url") if k in old}
        old_data["enabled"] = False
        client.request("POST", "/control/filtering/set_url", body={"url": old["url"], "whitelist": False, "data": old_data})
        checks = _canaries(client, cfg)
        readback = client.request("GET", "/control/filtering/status")
        if any(f.get("id") == args.old_filter_id and f.get("enabled") for f in readback.get("filters", [])):
            raise IntegrationError("Original filter disable readback failed")
        return {"verified": True, "source": args.source, "original_retained": True, "loaded_rules": replacement["rules_count"], "canaries": checks,
                "limitations": "Canary filtering checks do not prove DNS network reachability or complete false-positive coverage"}
    except IntegrationError as exc:
        restored = False
        try:
            restore_data = {k: old[k] for k in ("name", "url", "enabled") if k in old}
            client.request("POST", "/control/filtering/set_url", body={"url": old["url"], "whitelist": False, "data": restore_data})
            # A timeout after add_url may still have applied the change. Reconcile
            # actual state instead of trusting the local acknowledgement flag.
            observed = client.request("GET", "/control/filtering/status")
            if added or any(f.get("url") == candidate_url for f in observed.get("filters", [])):
                client.request("POST", "/control/filtering/remove_url", body={"url": candidate_url, "whitelist": False})
            actual = client.request("GET", "/control/filtering/status")
            restored = (any(f.get("id") == args.old_filter_id and f.get("enabled") for f in actual.get("filters", []))
                        and not any(f.get("url") == candidate_url for f in actual.get("filters", [])))
            _canaries(client, cfg)
        except IntegrationError:
            restored = False
        raise IntegrationError("AdGuard source replacement failed; rollback attempted", rollback={"verified": restored}) from exc


def _postgres_health(cfg):
    import psycopg
    dsn = secret(cfg.token_env, required=True)
    try:
        with psycopg.connect(dsn, connect_timeout=10, options="-c default_transaction_read_only=on -c statement_timeout=5000") as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT current_database(), current_setting('server_version'), pg_database_size(current_database()), pg_is_in_recovery()")
                database, version, size_bytes, recovery = cur.fetchone()
                return {"database": database, "version": version, "size_bytes": size_bytes, "in_recovery": recovery, "read_only": True}
    except psycopg.Error as exc:
        raise IntegrationError("PostgreSQL health query failed", retryable=True) from exc


def execute(operation: str, arguments: dict, *, config: dict[str, IntegrationConfig] | None = None,
            transport: httpx.BaseTransport | None = None, checkpoint: Callable[[dict], None] | None = None) -> dict:
    """Execute one registered adapter after external persisted-policy approval.

    This lower-level API enforces the independent operator config allowlist; it
    does not infer a user identity. REST/MCP/jobs must authorize before calling.
    """
    op = OPERATIONS.get(operation)
    if op is None:
        raise IntegrationError("Operation is not registered")
    try:
        args = op.arguments.model_validate(arguments)
    except ValueError as exc:
        raise IntegrationError("Invalid integration arguments") from exc
    configs = load_integrations() if config is None else config
    cfg = configs.get(args.integration_id)
    if cfg is None or cfg.kind != op.kind:
        raise IntegrationError("Integration is not configured for this operation")
    if operation not in cfg.allowed_operations:
        raise IntegrationError("Operation is not in the operator allowlist")
    if op.writes and checkpoint is None:
        raise IntegrationError("Mutations require a durable checkpoint callback")
    if cfg.kind == "postgresql":
        return _postgres_health(cfg)
    with APIClient(cfg, transport) as client:
        if operation == "home_assistant.status":
            result = client.request("GET", "/api/")
        elif operation == "home_assistant.states":
            if not cfg.allowed_entities:
                raise IntegrationError("Configure allowed_entities before exposing household states")
            result = {"states": [state for state in client.request("GET", "/api/states") if state.get("entity_id") in cfg.allowed_entities]}
        elif operation == "home_assistant.set_power":
            result = _set_power(client, cfg, args, checkpoint)
        elif operation == "adguard.status":
            result = {"status": client.request("GET", "/control/status"), "stats": client.request("GET", "/control/stats")}
        elif operation == "adguard.filters":
            result = client.request("GET", "/control/filtering/status")
        elif operation == "adguard.refresh_filters":
            _checkpoint(checkpoint, {"operation": operation, "status": client.request("GET", "/control/filtering/status")})
            refreshed = client.request("POST", "/control/filtering/refresh", body={"whitelist": False})
            result = {"refresh": refreshed, "status": client.request("GET", "/control/filtering/status"), "verified": False, "verification": "Refresh acknowledged and status read; DNS effects not independently verified"}
        elif operation == "adguard.set_rules":
            result = _set_rules(client, cfg, args, checkpoint)
        elif operation == "adguard.replace_filter":
            result = _replace_filter(client, cfg, args, checkpoint, transport)
        elif operation == "unifi.sites":
            result = client.request("GET", "/sites", params={"limit": 100})
            # Site descriptors are filtered; tokens must be site-scoped too.
            if cfg.allowed_sites and isinstance(result, dict):
                result["data"] = [site for site in result.get("data", []) if site.get("id") in cfg.allowed_sites]
        elif operation in ("unifi.devices", "unifi.clients"):
            if args.site_id not in cfg.allowed_sites:
                raise IntegrationError("Site is not in the operator allowlist")
            result = client.request("GET", f"/sites/{args.site_id}/{operation.rsplit('.',1)[1]}", params={"limit": 100})
            result = {"inventory": result, "pagination": "first 100 records; inspect pagination metadata for completeness"}
        elif operation.startswith("uisp."):
            result = client.request("GET", "/" + operation.split(".")[1])
        elif operation == "prometheus.query":
            query = cfg.allowed_queries.get(args.query)
            if query is None:
                raise IntegrationError("Prometheus query is not in the operator allowlist")
            result = client.request("GET", "/api/v1/query", params={"query": query, "timeout": "5s"})
        elif operation == "grafana.health":
            result = client.request("GET", "/api/health")
        elif operation == "grafana.dashboards":
            result = client.request("GET", "/api/search", params={"type": "dash-db", "limit": 100})
        elif operation == "github.repository":
            if args.repository not in cfg.allowed_repositories:
                raise IntegrationError("Repository is not in the operator allowlist")
            result = {"repository": client.request("GET", f"/repos/{args.repository}"), "commits": client.request("GET", f"/repos/{args.repository}/commits", params={"per_page": 5})}
        elif operation == "serverhub_mcp.tools":
            # Existing Control MCP may expose read/write tools. Metadata only
            # is intentionally supported; no model-selected legacy passthrough.
            initialized = client.request("POST", "", body={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "serverhub-ai-os", "version": "1"}}})
            protocol = initialized.get("result", {}).get("protocolVersion")
            if protocol not in {"2025-03-26", "2025-06-18", "2025-11-25"}:
                raise IntegrationError("Existing MCP server did not negotiate a supported protocol")
            client.client.headers["MCP-Protocol-Version"] = protocol
            client.request("POST", "", body={"jsonrpc": "2.0", "method": "notifications/initialized"})
            result = client.request("POST", "", body={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            if "error" in result:
                raise IntegrationError("Existing MCP server rejected tool metadata access")
        else:
            raise IntegrationError("Adapter operation has no implementation")
    return redact(result if isinstance(result, dict) else {"data": result})
