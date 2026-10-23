"""Durable, model-independent tool loop with deterministic server-side authorization.

Specialists select instructions/model routes, never privileges. Remote writes are
journaled before execution and ambiguous interrupted writes stop for reconciliation.
"""
from __future__ import annotations

import json
import hashlib

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, func

from serverhub.database import utcnow
from serverhub.audit import redact
from serverhub.integrations.registry import OPERATIONS, IntegrationError, execute, operation_schemas
from serverhub.host_audit import AuditArguments
from .agents import AGENTS, BASE_INSTRUCTIONS
from .providers import BudgetExceeded as ProviderBudgetExceeded, ChatProvider, ProviderError, PreflightRejected, UsageBudget, load_routes, estimate_prompt


class Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Service(Arguments):
    service: str = Field(pattern=r"^[A-Za-z0-9_.@-]{1,160}$")


class Container(Arguments):
    container: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,160}$")


class Project(Arguments):
    project: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")


class Network(Arguments):
    target: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,100}$")


class BackupTarget(Arguments):
    target: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")


class BackupIdentity(BackupTarget):
    backup_id: str = Field(pattern=r"^[a-f0-9]{32}$")


class Scan(Arguments):
    scanner: str = Field(pattern=r"^(lynis|trivy)$")
    image: str | None = Field(default=None, max_length=256)


class Search(Arguments):
    query: str = Field(default="", max_length=512)


class InventoryQuery(Arguments):
    section: str = Field(pattern=r"^(packages|services|ports|containers|addresses|routes|hardware)$")
    query: str = Field(default="", max_length=256)
    limit: int = Field(default=30, ge=1, le=100)


class VerificationCheck(Arguments):
    kind: str = Field(pattern=r"^(inventory.fresh|host.online|systemd.active|container.healthy)$")
    target: str | None = Field(default=None, max_length=160)


class Verification(Arguments):
    checks: list[VerificationCheck] = Field(min_length=1, max_length=20)


class Specialist(Arguments):
    specialist: str = Field(pattern="^(" + "|".join(AGENTS) + ")$")


class Development(Arguments):
    prompt: str | None = Field(default=None, max_length=16000)
    project: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    patch: str | None = Field(default=None, max_length=2 * 1024 * 1024)
    base_commit: str | None = Field(default=None, pattern=r"^[a-f0-9]{40,64}$")
    stage: bool = False


TOOLS: dict[str, tuple[type[BaseModel], str]] = {
    "docker.compose.update": (BackupTarget, "Update a pinned root-enrolled stateless Compose release, verify health and automatically roll back failed verification"),
    "package.plan": (BackupTarget, "Inspect exact root-enrolled package versions and their cached rollback versions"),
    "package.apply": (BackupTarget, "Apply root-enrolled stateless package artifacts, verify versions and acceptance checks; automatically roll back failures"),
    "configuration.plan": (BackupTarget, "Inspect checksums for an enrolled configuration change without modifying it"),
    "configuration.apply": (BackupTarget, "Checkpoint and apply an enrolled configuration candidate, verify checksum/service, and restore on failure"),
    "docker.backup.create": (BackupTarget, "Create a root-enrolled encrypted offline-consistent backup; quiesces exact approved containers, verifies SHA-256 and restarts them"),
    "docker.backup.list": (BackupTarget, "List authenticated backup manifests for a named root-enrolled target"),
    "docker.backup.verify": (BackupIdentity, "Verify manifest authentication and all backup artifact SHA-256 values"),
    "docker.restore.plan": (BackupIdentity, "Validate an isolated restore plan without overwriting source data"),
    "docker.restore.apply": (BackupIdentity, "Restore into new isolated Docker resources, verify stored data and container health; source resources remain unchanged"),
    "host.audit": (AuditArguments, "Collect fresh read-only host inventory and generate ordered capacity/security/update/zone plans; no repairs, deletion, reboot or network changes. Historical baseline inputs remain unverified."),
    "inventory.read": (Arguments, "Read the current target host's last observed inventory; collection errors remain explicit"),
    "inventory.query": (InventoryQuery, "Inspect a bounded inventory section of the selected host with optional text filter"),
    "inventory.refresh": (Arguments, "Ask the target Linux node for a fresh inventory"),
    "diagnostics.network": (Network, "Probe a fixed owner-configured network target through the node"),
    "task.verify": (Verification, "Evaluate explicit inventory freshness, host liveness, service active state or container health from recent authenticated observations. Required before claiming a verified result."),
    "systemd.logs": (Service, "Read last 100 journal lines of an explicitly permitted broker-allowlisted unit"),
    "systemd.status": (Service, "Read an owner-allowlisted service's measured status"),
    "systemd.restart": (Service, "Restart an owner-allowlisted service and verify status"),
    "docker.restart": (Container, "Restart a broker-allowlisted safe container and verify health"),
    "docker.compose.apply": (Project, "Deploy an owner-registered immutable Compose project with broker health validation"),
    "security.scan": (Scan, "Run an installed allowlisted scanner through the node"),
    "memory.search": (Search, "Retrieve scoped historical observations and their verification status"),
    "catalog.search": (Search, "Find curated application plans and their operational limitations"),
    "agent.specialize": (Specialist, "Delegate the next planning phase to a specialist using the same permissions and durable shared state"),
    "development.list": (Arguments, "List only projects for which this authenticated identity has an active development workspace grant"),
    "development.submit": (Development, "Queue a project-policy-gated isolated development job; does not claim deployment"),
}
NODE_TOOLS = {"docker.compose.update","package.plan", "package.apply", "configuration.plan", "configuration.apply","docker.backup.create", "docker.backup.list", "docker.backup.verify", "docker.restore.plan", "docker.restore.apply", "inventory.refresh", "diagnostics.network", "systemd.status", "systemd.logs", "systemd.restart", "docker.restart", "docker.compose.apply", "security.scan"}


def tool_schemas(profile: str = "all") -> list[dict]:
    core = [{"type": "function", "function": {"name": name.replace(".", "__"), "description": description,
             "parameters": model.model_json_schema()}} for name, (model, description) in TOOLS.items()]
    if profile == "all":
        return core + operation_schemas()
    base = {"inventory.read", "inventory.query", "inventory.refresh", "task.verify", "agent.specialize", "development.list", "development.submit"}
    families = {"infrastructure": set(), "linux": {"systemd.", "package.", "configuration.", "diagnostics."},
                "docker": {"docker.", "catalog."}, "network": {"diagnostics.network"},
                "security": {"security.", "host.audit"}, "development": {"development."},
                "monitoring": {"memory.", "host.audit"}, "verification": set()}
    prefixes = families.get(profile, set())
    return [schema for schema in core + operation_schemas()
            if (schema["function"]["name"].replace("__", ".") in base or
                any(schema["function"]["name"].replace("__", ".").startswith(prefix) for prefix in prefixes))]


def _save(ctx, state: dict) -> None:
    checkpoint = dict(ctx.job.checkpoint or {})
    checkpoint["ai"] = state
    ctx.save_checkpoint(checkpoint, progress=min(0.95, state.get("step", 0) / max(1, int(getattr(ctx.job, "spec", {}).get("max_steps", 20)))))


def compact_context(messages: list[dict], tools: list[dict], cfg, remaining: int) -> tuple[list[dict], dict | None]:
    """Replace bulky observations with durable references, never model summaries.

    Tool call/response linkage, instructions and the operator request remain intact.
    Full results and verification evidence stay in the checkpoint outside the prompt.
    This changes future input cost only; already billed usage is never refunded.
    """
    initial = estimate_prompt(messages, tools, kind=cfg.kind)["estimated_input_tokens"]
    limit = min(cfg.context_limit, remaining)
    target = max(0, limit - min(cfg.max_output_tokens, max(32, limit // 4)))
    if initial <= target:
        return messages, None
    compacted = [dict(message) for message in messages]
    removed = []
    for message in compacted:
        if message.get("role") != "tool" or len(message.get("content") or "") <= 512:
            continue
        content = message["content"]
        message["content"] = json.dumps({"compacted": True, "call_id": message.get("tool_call_id"),
            "checkpoint": "ai.completed_calls", "preview": content[:256],
            "note": "Truncated observation, not complete evidence; request a bounded fresh query if necessary"})
        removed.append(message.get("tool_call_id"))
        if estimate_prompt(compacted, tools, kind=cfg.kind)["estimated_input_tokens"] <= target:
            break
    if not removed:
        return messages, None
    return compacted, {"input_before": initial,
        "input_after": estimate_prompt(compacted, tools, kind=cfg.kind)["estimated_input_tokens"],
        "compacted_calls": removed, "context_limit": cfg.context_limit,
        "remaining_job_budget": remaining, "target": target}


def _memory(ctx, query: str) -> dict:
    from serverhub.models import Memory, to_dict
    ctx.require("inventory.read")
    statement = select(Memory).where(Memory.host_id == ctx.job.host_id, Memory.project == ctx.job.project)
    if query:
        # Bound SQL and literal wildcard matching. Memory remains evidence, never authority.
        statement = statement.where(Memory.content.icontains(query, autoescape=True))
    rows = ctx.db.scalars(statement.order_by(Memory.created_at.desc()).limit(12)).all()
    return {"memories": [to_dict(row) for row in rows], "source": "historical; current outcome requires fresh verification"}


def _run_tool(ctx, operation: str, arguments: dict, state: dict, call_id: str) -> dict:
    if operation in OPERATIONS:
        op = OPERATIONS[operation]
        parsed = op.arguments.model_validate(arguments)
        args = parsed.model_dump(exclude_none=True)
        ctx.require(operation, arguments=args)
        def checkpoint(snapshot: dict):
            state["in_flight"]["checkpoint"] = snapshot
            _save(ctx, state)
        return execute(operation, args, checkpoint=checkpoint if op.writes else None)
    if operation not in TOOLS:
        raise ValueError("Model requested an unregistered tool")
    parsed = TOOLS[operation][0].model_validate(arguments)
    args = parsed.model_dump(exclude_none=True)
    if operation == "host.audit":
        from serverhub.host_audit import run_audit
        return run_audit(ctx, args)
    if operation in NODE_TOOLS:
        from serverhub.node_api import execute_node
        return execute_node(ctx, operation, args, idempotency_key=f"{ctx.job.id}:ai:{call_id}")
    if operation == "task.verify":
        from serverhub.verification import verify_inventory
        ctx.require("task.verify", arguments=args)
        ctx.require("inventory.read")
        return verify_inventory(ctx.db, ctx.job.host_id, args["checks"])
    if operation in {"inventory.read", "inventory.query"}:
        from serverhub.models import Host
        ctx.require("inventory.read")
        host = ctx.db.get(Host, ctx.job.host_id) if ctx.job.host_id else None
        if not host:
            raise ValueError("Select an enrolled host before inspecting infrastructure")
        inventory = host.inventory or {}
        if operation == "inventory.query":
            section = args["section"]
            value = (inventory.get("docker") or {}).get("containers", []) if section == "containers" else inventory.get(section, [])
            if isinstance(value, list):
                matching = [item for item in value if args["query"].lower() in json.dumps(item, default=str).lower()]
                return {"section": section, "records": matching[:args["limit"]], "total_matching": len(matching),
                        "truncated": len(matching) > args["limit"], "last_seen": str(host.last_seen)}
            return {"section": section, "value": value, "last_seen": str(host.last_seen)}
        compact = {key: inventory.get(key) for key in ("os", "hardware", "dns", "routes", "errors")}
        compact["hardware"] = {key: value for key, value in (inventory.get("hardware") or {}).items() if key != "processes_by_memory"}
        for section in ("services", "ports", "packages", "addresses"):
            records = inventory.get(section) or []
            compact[section] = {"total": len(records), "sample": records[:15], "truncated": len(records) > 15}
        containers = (inventory.get("docker") or {}).get("containers", [])
        compact["docker"] = {"available": (inventory.get("docker") or {}).get("available"),
                             "total": len(containers), "containers": containers[:15], "truncated": len(containers) > 15}
        return {"inventory": compact, "last_seen": host.last_seen.isoformat() + "Z" if host.last_seen else None,
                "source": "authenticated node's last report; use inventory.query for additional bounded records"}
    if operation == "memory.search":
        return _memory(ctx, args["query"])
    if operation == "catalog.search":
        from serverhub.catalog import search
        ctx.require("job.submit")
        return {"applications": search(args["query"]), "deployment": "plans require owner-registered pinned deployment manifests"}
    if operation == "agent.specialize":
        ctx.require("job.submit")
        state["specialist"] = args["specialist"]
        agent = AGENTS[args["specialist"]]
        return {"agent": agent.name, "instructions": agent.instructions, "permissions_changed": False}
    if operation == "development.list":
        from serverhub.development.config import project_descriptors
        from serverhub.policy import authorize, PermissionDenied
        visible = []
        for project in project_descriptors():
            try:
                authorize(ctx.db, ctx.principal, "development.workspace", ctx.job.host_id, project["name"])
                visible.append(project)
            except PermissionDenied:
                continue
        return {"projects": visible}
    if operation == "development.submit":
        from serverhub.jobs import submit_job, WaitingChildren, BudgetExceeded
        from serverhub.models import Job
        from serverhub.policy import authorize
        authorize(ctx.db, ctx.principal, "development.workspace", ctx.job.host_id, args["project"])
        key=f"{ctx.job.id}:development:{call_id}"
        job=ctx.db.scalar(select(Job).where(Job.owner_id==ctx.principal.id, Job.idempotency_key==key))
        if job is None:
            child_units=ctx.db.scalar(select(func.coalesce(func.sum(Job.tokens_used),0)).where(Job.parent_id==ctx.job.id))
            child_cost=ctx.db.scalar(select(func.coalesce(func.sum(Job.cost_used),0)).where(Job.parent_id==ctx.job.id))
            available=ctx.job.token_budget-ctx.job.tokens_used-child_units-4000
            if available<32:
                raise BudgetExceeded("Insufficient task-tree budget for development plus final verification")
            prompt=args.pop("prompt",None)
            kind="development_autonomous" if prompt else "development"
            payload={"project":args["project"],"prompt":prompt,"stage":args.get("stage",False)} if prompt else args
            job=submit_job(ctx.db,ctx.principal,kind,payload,host_id=ctx.job.host_id, project=args["project"],parent_id=ctx.job.id,
                idempotency_key=key,token_budget=available,cost_budget=max(0,ctx.job.cost_budget-ctx.job.cost_used-child_cost),
                time_limit=max(1,int(ctx.job.time_limit-(utcnow()-ctx.job.started_at).total_seconds())) if ctx.job.started_at else ctx.job.time_limit)
            ctx.db.commit()
        if job.state == "succeeded":
            return {"job_id":job.id,"state":job.state,"completed":True,"verified":job.result.get("verified", False),"result":job.result}
        if job.state in {"failed","partial","cancelled"}:
            return {"job_id":job.id,"state":job.state,"completed":False,"verified":False,"error":job.error,"result":job.result}
        ctx.job.depends_on=list(set((ctx.job.depends_on or [])+[job.id]))
        ctx.db.commit()
        raise WaitingChildren("Development subtask is queued; parent releases its execution slot and resumes from checkpoint")
    raise ValueError("Tool has no installed implementation")


def _pending_tools(ctx, state: dict, on_execution=None) -> None:
    for call in list(state.get("pending_calls") or []):
        operation = call["operation"]
        call_id = call["id"]
        if operation not in TOOLS and operation not in OPERATIONS:
            raise ValueError("Model requested an unregistered tool")
        prior = state["completed_calls"].get(call_id)
        if prior is not None:
            result = prior
        else:
            mutating = operation in OPERATIONS and OPERATIONS[operation].writes
            previous = state.get("in_flight")
            if previous and previous.get("id") == call_id and previous.get("mutating"):
                raise ValueError("An interrupted external mutation needs owner reconciliation; its durable checkpoint is retained")
            state["in_flight"] = {"id": call_id, "operation": operation,
                                  "arguments": call["arguments"], "mutating": mutating}
            _save(ctx, state)
            ctx.log("AI tool request", {"operation": operation, "arguments": call["arguments"],
                                        "specialist": state["specialist"]})
            fingerprint = hashlib.sha256(json.dumps([operation, call["arguments"]], sort_keys=True).encode()).hexdigest()
            failures = state.setdefault("failed_tools", {})
            try:
                if failures.get(fingerprint, 0) >= 2:
                    raise IntegrationError("Repeated failed operation suppressed; choose a changed diagnostic or remediation strategy", retryable=False)
                if on_execution:
                    on_execution()
                result = _run_tool(ctx, operation, call["arguments"], state, call_id)
            except IntegrationError as exc:
                state["in_flight"]["failure"] = {"error": str(exc), "rollback": exc.rollback}
                _save(ctx, state)
                if mutating:
                    raise
                failures[fingerprint] = min(3, failures.get(fingerprint, 0) + 1)
                result = {"error": str(exc), "verified": False, "completed": False,
                          "failure_class": "integration", "retryable": exc.retryable,
                          "identical_failures": failures[fingerprint],
                          "requires_changed_strategy": failures[fingerprint] >= 2}
            cleaned = redact(result)
            if len(json.dumps(cleaned, default=str).encode()) > 256 * 1024:
                cleaned = {"truncated": True, "detail": "Tool output exceeds conversation bound; inspect inventory/API directly"}
            result = cleaned
            state["completed_calls"][call_id] = result
            state["evidence"].append({"operation": operation, "result": result})
            state.pop("in_flight", None)
            _save(ctx, state)
            ctx.log("AI tool result", {"operation": operation, "call_id": call_id, "result": result})
        # Persist removal and its tool response in one checkpoint. A crash at any
        # earlier point reuses the completed result without repeating the effect.
        state["messages"].append({"role": "tool", "tool_call_id": call_id,
                                  "name": call["name"], "content": json.dumps(result, default=str)})
        state["pending_calls"] = [item for item in state["pending_calls"] if item["id"] != call_id]
        _save(ctx, state)


def _finish(ctx, state, budget):
    evidence = state.get("evidence", [])
    content = state["final_summary"]
    if not state.get("memory_recorded"):
        from serverhub.models import Memory
        ctx.db.add(Memory(host_id=ctx.job.host_id, project=ctx.job.project, kind="agent_outcome",
                         content=redact(content)[:16000],
                         evidence={"job_id": ctx.job.id, "tools": evidence[-30:]}, verified=False))
        ctx.db.commit()
        state["memory_recorded"] = True
        _save(ctx, state)
    checks = [entry["result"] for entry in evidence if entry["operation"] == "task.verify"]
    verified = bool(checks) and all(item.get("verified") is True for item in checks)
    unfinished_children = any(entry["operation"] == "development.submit" and not entry["result"].get("completed") for entry in evidence)
    writes_verified = all(entry["result"].get("verified") is True for entry in evidence if entry["operation"] in {"systemd.restart", "docker.restart", "docker.compose.apply"} or (entry["operation"] in OPERATIONS and OPERATIONS[entry["operation"]].writes))
    verified = verified and not unfinished_children and writes_verified
    return {"summary": redact(content), "evidence": evidence,
            "specialist": state["specialist"], "tokens_used": budget.tokens_used,
            "cost_used": budget.cost_used, "verified": verified, "completed": verified,
            "verification": "Explicit deterministic checks passed; summary itself is not independently verified" if verified else "Partial: missing successful deterministic checks, an unverified write, or unfinished child work"}


def autonomous_job(ctx, spec: dict) -> dict:
    if not isinstance(spec, dict) or set(spec) - {"prompt", "model_route", "max_steps", "specialist"}:
        raise ValueError("Unknown autonomous job fields")
    prompt = spec.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 16000:
        raise ValueError("A prompt of 1–16000 characters is required")
    steps = spec.get("max_steps", 20)
    if isinstance(steps, bool) or not isinstance(steps, int) or not 1 <= steps <= 100:
        raise ValueError("max_steps must be 1–100")
    selected = spec.get("specialist", "infrastructure")
    if selected not in AGENTS:
        raise ValueError("Unknown specialist")
    routes = load_routes()
    if not routes:
        raise ValueError("No model is configured. Open Setup → AI provider, discover an installed tool-capable model, test it and save the default route")
    if hasattr(ctx, "reconcile_model_reservation"):
        ctx.reconcile_model_reservation()
    state = dict((ctx.job.checkpoint or {}).get("ai") or {})
    if not state:
        state = {"specialist": selected, "step": 0, "messages": [
            {"role": "system", "content": BASE_INSTRUCTIONS},
            {"role": "user", "content": prompt}], "evidence": [], "completed_calls": {}}
        _save(ctx, state)
    from serverhub.models import Job
    child_units=ctx.db.scalar(select(func.coalesce(func.sum(Job.tokens_used),0)).where(Job.parent_id==ctx.job.id))
    child_cost=ctx.db.scalar(select(func.coalesce(func.sum(Job.cost_used),0)).where(Job.parent_id==ctx.job.id))
    budget = UsageBudget(max(0,ctx.job.token_budget-child_units), max(0,ctx.job.cost_budget-child_cost), ctx.job.tokens_used, ctx.job.cost_used)
    activity_this_attempt = False
    def mark_execution():
        nonlocal activity_this_attempt
        activity_this_attempt = True
    def before_model_request():
        if hasattr(ctx, "record_model_usage"):
            ctx.record_model_usage(budget.tokens_used, budget.cost_used)
        ctx.check_cancelled()
        ctx.heartbeat()
        if budget.last_preflight and hasattr(ctx, "reserve_model_request"):
            reservation = budget.last_preflight
            ctx.reserve_model_request(reservation["estimated_input_tokens"] + reservation["output_reserve_tokens"],
                                      reservation["cost_reserve"])
        ctx.log("AI provider request", {"model": routes[route].model, "provider": routes[route].kind,
                                       "model_route": route, "host_id": ctx.job.host_id})
        mark_execution()
    # Resume the saved model response before asking the provider for another one.
    _pending_tools(ctx, state, on_execution=mark_execution)
    if "final_summary" in state:
        return _finish(ctx, state, budget)
    start_step = int(state.get("step", 0))
    for index in range(start_step, steps):
        ctx.check_cancelled()
        specialist = AGENTS[state["specialist"]]
        route = spec.get("model_route") or (specialist.route if specialist.route in routes else "default")
        if route not in routes:
            raise ValueError("Configured model route is unavailable")
        messages = list(state["messages"])
        messages[0] = {"role": "system", "content": BASE_INSTRUCTIONS + "\nCurrent specialist: " + specialist.instructions}
        schemas = tool_schemas(state["specialist"])
        messages, compaction = compact_context(messages, schemas, routes[route], budget.token_limit - budget.tokens_used)
        if compaction:
            state["messages"] = messages
            state.setdefault("compactions", []).append(compaction)
            _save(ctx, state)
            ctx.log("Conversation observations compacted; full checkpoint evidence retained", compaction)
        previous_tokens, previous_cost = budget.tokens_used, budget.cost_used
        try:
            completion = ChatProvider(routes[route]).complete(messages, schemas, budget,
                         before_request=before_model_request)
        except ProviderBudgetExceeded as exc:
            from serverhub.jobs import BudgetExceeded, PreflightRejected as JobPreflightRejected
            if isinstance(exc, PreflightRejected) and not activity_this_attempt:
                data = exc.diagnostics
                safe = {"input_estimate": data.get("estimated_input_tokens"),
                        "output_reserve": data.get("output_reserve_tokens"), "minimum_output": 32,
                        "context_limit": data.get("context_limit"), "remaining_job_budget": data.get("remaining_tokens"),
                        "estimator": data.get("method"), "serialized_utf8_bytes": data.get("serialized_utf8_bytes")}
                raise JobPreflightRejected(str(exc), safe) from exc
            raise BudgetExceeded(str(exc)) from exc
        except ProviderError as exc:
            if exc.retryable:
                from serverhub.jobs import RetryableError
                raise RetryableError(str(exc)) from exc
            raise
        finally:
            charged_tokens = budget.tokens_used - previous_tokens
            charged_cost = budget.cost_used - previous_cost
            if hasattr(ctx, "record_model_usage"):
                ctx.record_model_usage(budget.tokens_used, budget.cost_used)
            elif charged_tokens or charged_cost:
                ctx.usage(charged_tokens, charged_cost)
        # Use numeric/unit labels that do not resemble credential keys; the
        # audit redactor intentionally masks any field named *token*.
        accounting = completion.accounting
        ctx.log("Model request accounting", {
            "unit": "tokens", "estimator": accounting.get("method"),
            "input_estimate": accounting.get("estimated_input_tokens"),
            "generation_reserve": accounting.get("output_reserve_tokens"),
            "input_measured": accounting.get("actual_input_tokens"),
            "output_measured": accounting.get("actual_output_tokens"),
            "usage_verified": accounting.get("usage_verified"),
            "serialized_utf8_bytes": accounting.get("serialized_utf8_bytes"),
            "request_utf8_bytes": accounting.get("request_utf8_bytes"),
            "provider_format": accounting.get("provider_format"),
            "uncertainty_margin": accounting.get("uncertainty_margin"),
            "job_limit": accounting.get("token_limit"), "already_spent": accounting.get("tokens_used"),
            "context_limit": accounting.get("context_limit"),
        })
        state["messages"].append(completion.assistant_message())
        state["step"] = index + 1
        state["pending_calls"] = [{"id": call.id, "name": call.name,
                                    "operation": call.name.replace("__", "."), "arguments": call.arguments}
                                   for call in completion.tool_calls]
        if not completion.tool_calls:
            state["final_summary"] = completion.content
        _save(ctx, state)
        if not completion.tool_calls:
            return _finish(ctx, state, budget)
        _pending_tools(ctx, state, on_execution=mark_execution)
    return {"summary": "Configured planning step limit reached; unfinished work remains", "completed": False,
            "evidence": state.get("evidence", []), "tokens_used": budget.tokens_used, "cost_used": budget.cost_used}


def register() -> None:
    from serverhub.jobs import register_handler
    register_handler("autonomous", autonomous_job)
