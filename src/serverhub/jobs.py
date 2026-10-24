"""PostgreSQL-backed queue with leases, process deadlines and persistent checkpoints.

External effects are at-least-once: adapters must reconcile idempotency keys. An
ambiguous external effect is never represented as a verified success.
"""
import multiprocessing
import math
import os
import signal
import time
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import func, select, text

from .audit import append_audit, redact
from .auth import Principal
from .database import SessionLocal, get_engine, utcnow
from .models import Host, Job, JobEvent, SystemState, User
from .policy import PermissionDenied, authorize
from .settings import get_settings

HANDLERS: dict[str, object] = {}
TERMINAL = {"succeeded", "partial", "failed", "cancelled"}
RUNNABLE = {"queued", "retry", "waiting_children"}



def elapsed_seconds(job, now=None):
    now = now or utcnow()
    if not job.started_at:
        return 0.0
    end = getattr(job, "paused_at", None) or now
    return max(0.0, (end-job.started_at).total_seconds()-getattr(job, "paused_seconds", 0.0))


def mark_paused(job):
    if job.state in {"paused", "waiting_approval"} and not job.paused_at:
        job.paused_at = utcnow()


def resume_clock(job):
    if job.paused_at:
        # A queue pause before the first start was never inside the execution
        # interval and must not create extra execution credit.
        if job.started_at:
            start = max(job.paused_at, job.started_at)
            job.paused_seconds += max(0.0, (utcnow()-start).total_seconds())
        job.paused_at = None


def resume_state(job):
    checkpoint = dict(job.checkpoint or {})
    state = checkpoint.pop("pause_previous_state", "queued")
    job.checkpoint = checkpoint
    return "waiting_children" if state == "waiting_children" else "queued"


def parent_stopped(db, job):
    seen, parent_id = {job.id}, job.parent_id
    while parent_id:
        if parent_id in seen:
            return True
        seen.add(parent_id)
        parent = db.get(Job, parent_id, populate_existing=True)
        if (not parent or parent.owner_id != job.owner_id or parent.state in TERMINAL | {"cancel_requested"}
                or (parent.started_at and elapsed_seconds(parent) >= parent.time_limit)):
            return True
        parent_id = parent.parent_id
    return False


def parent_paused(db, job):
    seen = {job.id}
    parent_id = job.parent_id
    while parent_id:
        if parent_id in seen:
            return True
        seen.add(parent_id)
        parent = db.get(Job, parent_id, populate_existing=True)
        if parent is None:
            return False
        if parent.state in {"paused", "pause_requested", "waiting_approval"}:
            return True
        parent_id = parent.parent_id
    return False



def pause_descendants(db, parent):
    pending, seen = [parent.id], {parent.id}
    while pending:
        children = db.scalars(select(Job).where(Job.parent_id.in_(pending), Job.owner_id == parent.owner_id)).all()
        pending = []
        for child in children:
            if child.id in seen:
                continue
            seen.add(child.id)
            pending.append(child.id)
            if child.state in RUNNABLE:
                if child.state == "waiting_children":
                    child.checkpoint = {**child.checkpoint, "pause_previous_state": "waiting_children"}
                child.state, child.failure_class = "paused", "parent_paused"
                mark_paused(child)
                _event(db, child, "Parent task paused", {"parent": parent.id})
            # Running children observe ancestor state before every tool and the
            # supervisor terminates them; keep their lease/accounting intact.



class RetryableError(Exception):
    pass


class BudgetExceeded(Exception):
    def __init__(self, message, diagnostics=None):
        super().__init__(message)
        self.diagnostics = diagnostics or {}



class PreflightRejected(BudgetExceeded):
    """No request or tool work in this execution attempt; pause without retry burn."""
    def __init__(self, message, diagnostics=None):
        super().__init__(message)
        self.diagnostics = diagnostics or {}


class JobCancelled(Exception):
    pass


class WaitingChildren(Exception):
    pass


class JobPaused(Exception):
    pass


class ParentPaused(JobPaused):
    pass


class LeaseLost(Exception):
    pass


def register_handler(kind: str, handler):
    HANDLERS[kind] = handler


def load_plugins():
    from importlib import import_module
    for name in ("serverhub.ai.orchestrator", "serverhub.extensions", "serverhub.development"):
        try:
            module = import_module(name)
        except ModuleNotFoundError as exc:
            if exc.name == name:
                continue
            raise
        register = getattr(module, "register", None)
        if register:
            register()


def _event(db, job: Job, message: str, data=None, level="info"):
    db.add(JobEvent(job_id=job.id, message=redact(message), data=redact(data or {}), level=level))


def submit_job(db, principal: Principal, kind: str, spec: dict, host_id: str | None = None,
               project: str | None = None, parent_id: str | None = None, depends_on: list | None = None,
               idempotency_key: str | None = None, run_after=None, max_attempts: int = 3,
               time_limit: int = 3600, token_budget: int | None = None, cost_budget: float | None = None, priority: int = 0) -> Job:
    if kind in {"development", "development_autonomous"}:
        from .development.config import configured_projects
        if not isinstance(spec, dict) or not isinstance(spec.get("project"), str):
            raise ValueError("Development jobs require a registered project")
        if project is None:
            project = spec["project"]
        if project != spec["project"] or project not in configured_projects():
            raise ValueError("Authenticated job project and registered specification must match")
        if spec.get("stage") is True and not host_id:
            raise ValueError("Isolated staging requires an explicitly selected enrolled host; controller-only checks do not need one")
    elif kind == "autonomous" and host_id is None:
        from .policy import visible_host_ids
        choices = visible_host_ids(db, principal)
        if len(choices) == 1:
            host_id = choices[0]
        else:
            raise ValueError("Select an enrolled host before inspecting infrastructure: no unambiguous authorized host is available")
    if kind in {"autonomous", "development", "development_autonomous"} and host_id:
        selected_host = db.get(Host, host_id)
        if not selected_host or selected_host.revoked:
            raise ValueError("Select an enrolled, non-revoked host")
    authorize(db, principal, "job.submit", host_id, project)
    if kind not in HANDLERS:
        raise ValueError(f"Unknown job kind: {kind}")
    if not isinstance(spec, dict):
        raise ValueError("job specification must be an object")
    if "model_route" in spec and (not isinstance(spec["model_route"], str) or not spec["model_route"].strip()):
        raise ValueError("spec.model_route must be a non-empty string")
    if token_budget is None or cost_budget is None:
        defaults = None
        if kind in {"autonomous", "development_autonomous"}:
            from .ai.providers import load_routes
            routes = load_routes()
            route = spec.get("model_route") or ("development" if kind == "development_autonomous" and "development" in routes else "default")
            defaults = routes.get(route)
        token_budget = token_budget if token_budget is not None else (defaults.default_job_token_budget if defaults else 20000)
        cost_budget = cost_budget if cost_budget is not None else (defaults.default_job_cost_budget if defaults else 1.0)
    if not (1 <= max_attempts <= 10 and 1 <= time_limit <= 86400 and 0 <= token_budget <= 2_000_000
            and math.isfinite(cost_budget) and 0 <= cost_budget <= 1000):
        raise ValueError("job execution limits outside supported bounds")
    if isinstance(priority, bool) or not isinstance(priority, int) or not -100 <= priority <= 100:
        raise ValueError("priority must be -100..100")
    dependencies = depends_on or []
    for dependency in dependencies + ([parent_id] if parent_id else []):
        linked = db.get(Job, dependency)
        if not linked or (linked.owner_id != principal.id and principal.role != "owner"):
            raise PermissionDenied("Job dependency or parent is unavailable")
    if len(set(dependencies)) != len(dependencies):
        raise ValueError("Duplicate dependencies")
    from .job_limits import lock_quota
    lock_quota(db)
    if idempotency_key:
        existing = db.scalar(select(Job).where(Job.owner_id == principal.id, Job.idempotency_key == idempotency_key))
        if existing:
            if (existing.kind, existing.spec, existing.host_id, existing.project) != (kind, spec, host_id, project):
                raise ValueError("Idempotency key already belongs to another request")
            return existing
    from .job_limits import check_route_budget, admit_job
    check_route_budget(principal, kind, spec, token_budget, cost_budget)
    # Concrete tools are authorized at submission AND execution. Autonomous plans
    # are not yet known, so each proposed tool is authorized separately at runtime.
    if kind == "operation":
        authorize(db, principal, spec.get("operation", ""), host_id, project, spec.get("arguments", {}),
                  bool(spec.get("production", False)))
    if kind == "workflow":
        if not isinstance(spec.get("steps"), list) or not spec["steps"] or len(spec["steps"]) > 100:
            raise ValueError("workflow requires 1–100 steps")
        for step in spec["steps"]:
            if not isinstance(step, dict) or not isinstance(step.get("operation"), str) or not isinstance(step.get("arguments", {}), dict):
                raise ValueError("Each workflow step requires an operation and argument object")
            authorize(db, principal, step.get("operation", ""), host_id, project, step.get("arguments", {}),
                      bool(step.get("production", False)))
    admit_job(db, principal.id, time_limit)
    job = Job(owner_id=principal.id, kind=kind, spec=spec, host_id=host_id, project=project,
              parent_id=parent_id, depends_on=dependencies, idempotency_key=idempotency_key, priority=priority,
              run_after=run_after or utcnow(), max_attempts=max_attempts, time_limit=time_limit,
              token_budget=token_budget, cost_budget=cost_budget)
    db.add(job)
    db.flush()
    _event(db, job, "Job accepted", {"kind": kind, "host_id": host_id})
    append_audit(db, principal.id, "job.submit", job.id, {"kind": kind, "host_id": host_id})
    return job


class JobContext:
    def __init__(self, db, job: Job, principal: Principal):
        self.db = db
        self.job = job
        self.principal = principal
        self.worker_id = job.worker_id

    def check_cancelled(self):
        self.db.refresh(self.job)
        if self.job.worker_id != self.worker_id or (self.job.lease_until and self.job.lease_until <= utcnow()):
            raise LeaseLost("Job lease expired or was claimed by another worker")
        if parent_stopped(self.db,self.job):
            raise JobCancelled("Parent task finished or its execution deadline expired")
        if parent_paused(self.db, self.job):
            raise ParentPaused("Parent task is paused; resume parent first")
        if self.job.state in {"cancel_requested", "cancelled"}:
            raise JobCancelled("Job cancelled")
        if self.job.state in {"pause_requested", "paused"}:
            raise JobPaused("Job paused")
        if self.job.state != "running":
            raise LeaseLost("Job is no longer running")
        if self.job.started_at and elapsed_seconds(self.job) >= self.job.time_limit:
            raise TimeoutError("Job deadline reached")
        if self.job.tokens_used > self.job.token_budget or self.job.cost_used > self.job.cost_budget:
            raise BudgetExceeded("Job token or API cost budget exceeded")
        emergency = self.db.get(SystemState, "emergency_stop")
        if emergency:
            self.db.refresh(emergency)
        if emergency and emergency.value.get("enabled"):
            raise JobPaused("Emergency stop is active")

    def require(self, operation, arguments=None, production=False):
        self.check_cancelled()
        return authorize(self.db, self.principal, operation, self.job.host_id, self.job.project,
                         arguments or {}, production)

    def heartbeat(self):
        self.check_cancelled()
        self.job.lease_until = utcnow() + timedelta(seconds=get_settings().lease_seconds)
        self.job.updated_at = utcnow()
        self.db.commit()

    def log(self, message, data=None):
        self.check_cancelled()
        _event(self.db, self.job, message, data)
        self.db.commit()

    def save_checkpoint(self, checkpoint: dict, progress: float | None = None):
        self.check_cancelled()
        self.job.checkpoint = checkpoint
        if progress is not None:
            self.job.progress = max(0.0, min(float(progress), 1.0))
        self.db.commit()

    def _model_accounting_job(self):
        # Usage settlement is allowed after cancellation/timeout, but never by
        # an old worker after ownership changed. Serialize with lease recovery.
        self.db.refresh(self.job, with_for_update=True)
        if self.job.worker_id != self.worker_id or self.job.state not in {"running", "pause_requested", "cancel_requested"}:
            raise LeaseLost("Model accounting lease belongs to another worker")

    def reconcile_model_reservation(self):
        self._model_accounting_job()
        checkpoint = dict(self.job.checkpoint or {})
        reservation = checkpoint.pop("model_request_reservation", None)
        if reservation is not None:
            # Already charged before dispatch. Unknown outcome must never be
            # refunded by a restarted worker. Clear atomically, charge once.
            self.job.checkpoint = checkpoint
            _event(self.db, self.job, "Retained uncertain model reservation after restart", {
                "reserved_units": reservation["reserved_units"], "reserved_cost": reservation["reserved_cost"]})
        self.db.commit()

    def reserve_model_request(self, units, cost):
        self._model_accounting_job()
        self.check_cancelled()
        if isinstance(units, bool) or not isinstance(units, int) or units < 0 or not math.isfinite(cost) or cost < 0:
            raise ValueError("Invalid model reservation")
        if self.job.tokens_used + units > self.job.token_budget or self.job.cost_used + cost > self.job.cost_budget:
            raise BudgetExceeded("Model reservation exceeds remaining job budget", {"minimum_tokens": units, "cost_reserve": cost})
        from .job_limits import charge_daily
        charge_daily(self.db, self.job.owner_id, units, cost)
        checkpoint = dict(self.job.checkpoint or {})
        if checkpoint.get("model_request_reservation"):
            raise RuntimeError("Previous model reservation must be settled first")
        checkpoint["model_request_reservation"] = {"base_units": self.job.tokens_used,
            "base_cost": self.job.cost_used, "reserved_units": units, "reserved_cost": cost}
        self.job.tokens_used += units
        self.job.cost_used += cost
        self.job.checkpoint = checkpoint
        self.db.commit()  # reservation and debit precede any external request

    def record_model_usage(self, total_units, total_cost):
        self._model_accounting_job()
        checkpoint = dict(self.job.checkpoint or {})
        reservation = checkpoint.get("model_request_reservation")
        base_units = reservation["base_units"] if reservation else self.job.tokens_used
        base_cost = reservation["base_cost"] if reservation else self.job.cost_used
        if (isinstance(total_units, bool) or not isinstance(total_units, int) or total_units < base_units
                or not math.isfinite(total_cost) or total_cost < base_cost):
            raise ValueError("Model settlement cannot refund earlier requests")
        from .job_limits import charge_daily
        charge_daily(self.db, self.job.owner_id, max(0, total_units-self.job.tokens_used),
                     max(0, total_cost-self.job.cost_used), enforce=False)
        self.job.tokens_used, self.job.cost_used = total_units, total_cost
        checkpoint.pop("model_request_reservation", None)
        self.job.checkpoint = checkpoint
        self.db.commit()  # actual usage/refund and ledger clear are one transaction

    def usage(self, tokens: int, cost: float):
        if not isinstance(tokens, int) or isinstance(tokens, bool) or tokens < 0 or not math.isfinite(cost) or cost < 0:
            raise ValueError("Usage cannot be negative")
        self.check_cancelled()
        from .job_limits import charge_daily
        charge_daily(self.db, self.job.owner_id, tokens, cost)
        self.job.tokens_used += tokens
        self.job.cost_used += cost
        self.db.commit()
        self.check_cancelled()


def _workflow(ctx, spec):
    steps = spec["steps"]
    checkpoint = dict(ctx.job.checkpoint or {})
    results = list(checkpoint.get("steps", []))
    if checkpoint.get("in_flight"):
        # The operation handler must reconcile deterministic command idempotency.
        ctx.log("Resuming interrupted step; adapter must reconcile its idempotency key")
    for index in range(len(results), len(steps)):
        step = dict(steps[index])
        ctx.require(step["operation"], step.get("arguments", {}), step.get("production", False))
        checkpoint["in_flight"] = index
        ctx.save_checkpoint(checkpoint, index / len(steps))
        step["idempotency_key"] = f"{ctx.job.id}:step:{index}"
        result = HANDLERS["operation"](ctx, step)
        ctx.check_cancelled()
        results.append(result)
        checkpoint = {"steps": results}
        ctx.save_checkpoint(checkpoint, len(results) / len(steps))
    return {"steps": results}


def _inventory(ctx, spec):
    ctx.require("inventory.read")
    host = ctx.db.get(Host, ctx.job.host_id)
    if not host:
        raise ValueError("A host target is required")
    return {"inventory": host.inventory, "last_seen": host.last_seen.isoformat() + "Z" if host.last_seen else None,
            "source": "last agent report; not a fresh probe"}


register_handler("workflow", _workflow)
register_handler("inventory", _inventory)


def _classify(exc):
    if isinstance(exc, PermissionDenied):
        return "waiting_approval", "policy", False
    if isinstance(exc, JobCancelled):
        return "cancelled", "cancelled", False
    if isinstance(exc, WaitingChildren):
        return "waiting_children", "dependency_wait", False
    if isinstance(exc, ParentPaused):
        return "paused", "parent_paused", False
    if isinstance(exc, JobPaused):
        return "paused", "paused", False
    if isinstance(exc, LeaseLost):
        return "failed", "lease_lost", False
    if isinstance(exc, PreflightRejected):
        return "paused", "preflight", False
    if isinstance(exc, BudgetExceeded):
        return "paused", "budget", False
    if isinstance(exc, TimeoutError):
        return "failed", "timeout", False
    if isinstance(exc, (RetryableError, ConnectionError)):
        return "retry", "transient", True
    return "failed", "execution", False


def execute_job(job_id: str, worker_id: str):
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if not job or job.worker_id != worker_id or job.state != "running":
            return
        user = db.get(User, job.owner_id)
        if not user:
            job.state, job.failure_class, job.error = "failed", "authorization", "Job owner no longer exists"
            job.worker_id, job.lease_until, job.finished_at = None, None, utcnow()
            db.commit()
            return
        ctx = JobContext(db, job, Principal(user.id, user.role, user.username))
        try:
            if not user.enabled:
                raise PermissionDenied("Job owner account disabled")
            ctx.check_cancelled()
            result = HANDLERS[job.kind](ctx, dict(job.spec))
            ctx.check_cancelled()
            job.result = redact(result if isinstance(result, dict) else {"value": result})
            job.progress = 1.0
            unverified = job.result.get("completed") is False or (job.kind in {"autonomous", "development", "development_autonomous"} and not job.result.get("verified"))
            job.state = "partial" if unverified else "succeeded"
            job.finished_at = utcnow()
            job.error = None
            job.failure_class = None
            _event(db, job, "Job completed" if not unverified else "Job stopped with partial or unverified results", {"state": job.state, "verification": job.result.get("verification")})
            append_audit(db, user.id, "job." + job.state, job.id, {"kind": job.kind})
        except BaseException as exc:
            # A failed transaction must not prevent persisting the failure classification.
            db.rollback()
            job = db.get(Job, job_id)
            if not job or job.worker_id != worker_id:
                return
            state, failure_class, retryable = _classify(exc)
            if retryable and job.attempts >= job.max_attempts:
                state = "failed"
            job.state = state
            mark_paused(job)
            if state in {"paused", "waiting_approval"}:
                job.attempts = max(0, job.attempts - 1)
            if isinstance(exc, BudgetExceeded):
                data = exc.diagnostics
                job.checkpoint = {**job.checkpoint, "budget_pause": {
                    "minimum_tokens": data.get("minimum_tokens", (data.get("estimated_input_tokens", data.get("input_estimate")) or 0) + 32),
                    "minimum_cost": data.get("cost_reserve", 0),
                    "reason": str(exc)[:500]}}
            if isinstance(exc, PreflightRejected):
                job.result = {"completed": False, "preflight": exc.diagnostics,
                              "verification": "No provider request or tool execution in this attempt. Correct the configuration/scope and resume, or submit a separately authorized larger-budget job."}
            job.failure_class = failure_class
            job.error = redact(str(exc))[:4000]
            if isinstance(exc, PermissionDenied):
                job.result = {"completed": False, "denial": redact(exc.details), "verification": "No permission was bypassed; saved progress is retained for resume"}
            if state == "retry":
                job.run_after = utcnow() + timedelta(seconds=min(300, 2 ** job.attempts))
            if state in TERMINAL:
                job.finished_at = utcnow()
            _event(db, job, "Job interrupted", {"state": state, "class": failure_class, "error": job.error}, "warning")
            append_audit(db, job.owner_id, "job." + state, job.id, {"class": failure_class, "error": job.error})
        if job.state in {"paused", "waiting_approval"}:
            pause_descendants(db, job)
        job.lease_until = None
        job.worker_id = None
        job.updated_at = utcnow()
        db.commit()


def _child_execute(job_id, worker_id):
    # The parent stop handler only changes its own Worker flag. In a forked
    # child that handler would swallow terminate(), forcing SIGKILL.
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    # Forked processes must never reuse inherited pooled database connections.
    get_engine().dispose(close=False)
    execute_job(job_id, worker_id)


class Worker:
    def __init__(self, worker_id: str | None = None, isolated: bool = True):
        self.worker_id = worker_id or f"{os.uname().nodename}:{os.getpid()}:{uuid4().hex[:8]}"
        self.isolated = isolated
        self.stopping = False

    def heartbeat(self, job_id=None):
        from .models import WorkerHeartbeat
        with SessionLocal() as db:
            row = db.get(WorkerHeartbeat, self.worker_id)
            if not row:
                row = WorkerHeartbeat(worker_id=self.worker_id)
                db.add(row)
            row.seen_at, row.job_id = utcnow(), job_id
            db.commit()

    def _claim(self):
        settings = get_settings()
        with SessionLocal() as db:
            if db.bind.dialect.name == "postgresql":
                # This advisory lock makes global/per-host concurrency counts race-free.
                db.execute(text("SELECT pg_advisory_xact_lock(734882102)"))
            emergency = db.get(SystemState, "emergency_stop")
            if emergency and emergency.value.get("enabled"):
                return None
            from .scheduling import tick
            tick(db)
            # Release scheduling/quota locks before locking running jobs; model
            # accounting takes job -> quota locks and must never deadlock here.
            db.commit()
            if db.bind.dialect.name == "postgresql":
                db.execute(text("SELECT pg_advisory_xact_lock(734882102)"))
            emergency = db.get(SystemState, "emergency_stop", populate_existing=True)
            if emergency and emergency.value.get("enabled"):
                return None
            stale = db.scalars(select(Job).where(Job.state.in_(["running", "pause_requested", "cancel_requested"]),
                                                Job.lease_until <= utcnow()).with_for_update(skip_locked=True)).all()
            for job in stale:
                if job.state == "cancel_requested":
                    job.state = "cancelled"
                elif job.state == "pause_requested":
                    job.state = "paused"
                elif job.attempts >= job.max_attempts:
                    job.state = "failed"
                    job.failure_class = "lease_exhausted"
                else:
                    job.state = "retry"
                    job.run_after = utcnow()
                    job.failure_class = "restart_recovery"
                mark_paused(job)
                if job.state == "paused":
                    job.attempts = max(0, job.attempts - 1)
                job.worker_id = None
                job.lease_until = None
                if job.state in TERMINAL:
                    job.finished_at = utcnow()
                _event(db, job, "Recovered expired worker lease", {"state": job.state})
            for child in db.scalars(select(Job).where(Job.state == "paused", Job.failure_class == "parent_paused").with_for_update(skip_locked=True)):
                if not parent_paused(db, child):
                    resume_clock(child)
                    child.state = resume_state(child)
                    _event(db, child, "Parent pause released; runtime authorization remains required")
            db.flush()
            running = db.scalar(select(func.count()).select_from(Job).where(Job.state.in_(["running", "pause_requested", "cancel_requested"])))
            if running >= settings.max_concurrent_jobs:
                db.commit()
                return None
            candidates = db.scalars(select(Job).where(Job.state.in_(RUNNABLE), Job.run_after <= utcnow())
                                    .order_by(Job.priority.desc(), Job.run_after, Job.created_at).limit(100)
                                    .with_for_update(skip_locked=True)).all()
            chosen = None
            for job in candidates:
                if parent_paused(db, job):
                    continue
                user_running = db.scalar(select(func.count()).select_from(Job).where(
                    Job.owner_id == job.owner_id, Job.state.in_(["running", "pause_requested", "cancel_requested"])))
                if user_running >= settings.max_user_jobs:
                    continue
                if parent_stopped(db,job):
                    job.state,job.failure_class,job.error="cancelled","parent_stopped","Parent task finished or its execution deadline expired"
                    job.finished_at=utcnow()
                    _event(db,job,job.error)
                    continue
                if job.host_id:
                    host_running = db.scalar(select(func.count()).select_from(Job).where(
                        Job.host_id == job.host_id, Job.state.in_(["running", "pause_requested", "cancel_requested"])))
                    if host_running >= settings.max_host_jobs:
                        continue
                if job.started_at and elapsed_seconds(job) >= job.time_limit:
                    job.state, job.failure_class, job.error = "failed", "timeout", "Task deadline exceeded while awaiting dependencies"
                    job.finished_at = utcnow()
                    _event(db, job, job.error)
                    continue
                dependencies = [db.get(Job, dep) for dep in job.depends_on]
                # A delegated child failure is an observation for the parent planner,
                # while an ordinary failed prerequisite still blocks execution.
                if job.state == "waiting_children":
                    pending_children = [dep for dep in dependencies if dep and dep.parent_id == job.id]
                    if any(dep.state not in TERMINAL for dep in pending_children):
                        continue
                    dependencies = [dep for dep in dependencies if dep not in pending_children]
                if any(dep is None or dep.state in {"failed", "partial", "cancelled"} for dep in dependencies):
                    job.state = "failed"
                    job.failure_class = "dependency"
                    job.error = "A dependency failed or was cancelled"
                    job.finished_at = utcnow()
                    _event(db, job, job.error)
                    continue
                if any(dep.state != "succeeded" for dep in dependencies):
                    continue
                chosen = job
                break
            if chosen:
                continuation = chosen.state == "waiting_children"
                chosen.state = "running"
                if not continuation:
                    chosen.attempts += 1
                chosen.started_at = chosen.started_at or utcnow()
                chosen.worker_id = self.worker_id
                chosen.lease_until = utcnow() + timedelta(seconds=settings.lease_seconds)
                _event(db, chosen, "Job claimed", {"attempt": chosen.attempts, "worker": self.worker_id})
                job_id = chosen.id
            else:
                job_id = None
            db.commit()
            return job_id

    def _supervise(self, process, job_id):
        settings = get_settings()
        interrupted = None
        while process.is_alive():
            self.heartbeat(job_id)
            process.join(timeout=min(1.0, settings.lease_seconds / 4))
            with SessionLocal() as db:
                job = db.get(Job, job_id)
                if not job or job.worker_id != self.worker_id:
                    interrupted = ("failed", "lease_lost")
                elif job.state == "cancel_requested" or self.stopping:
                    interrupted = ("cancelled" if not self.stopping else "retry", "cancelled" if not self.stopping else "worker_shutdown")
                elif parent_stopped(db,job):
                    interrupted = ("cancelled", "parent_stopped")
                elif parent_paused(db, job):
                    interrupted = ("paused", "parent_paused")
                elif job.state == "pause_requested":
                    interrupted = ("paused", "paused")
                elif job.started_at and elapsed_seconds(job) >= job.time_limit:
                    interrupted = ("failed", "timeout")
                else:
                    emergency = db.get(SystemState, "emergency_stop")
                    if emergency and emergency.value.get("enabled"):
                        interrupted = ("paused", "emergency_stop")
                    elif job.state == "running":
                        job.lease_until = utcnow() + timedelta(seconds=settings.lease_seconds)
                        db.commit()
            if interrupted:
                process.terminate()
                process.join(timeout=3)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=3)
                break
        process.join()
        with SessionLocal() as db:
            job = db.get(Job, job_id)
            if job and job.worker_id == self.worker_id and (interrupted or job.state == "running"):
                state, failure = interrupted or ("retry" if job.attempts < job.max_attempts else "failed", "worker_crash")
                job.state = state
                job.failure_class = failure
                if failure == "worker_shutdown":
                    job.attempts = max(0, job.attempts - 1)
                job.error = "Worker process stopped; in-flight external effects require adapter reconciliation"
                mark_paused(job)
                if job.state == "paused":
                    job.attempts = max(0, job.attempts - 1)
                job.worker_id = None
                job.lease_until = None
                if state in TERMINAL:
                    job.finished_at = utcnow()
                _event(db, job, job.error, {"state": state, "class": failure}, "warning")
                append_audit(db, job.owner_id, "job." + state, job.id, {"class": failure})
                db.commit()

    def run_once(self) -> bool:
        self.heartbeat()
        job_id = self._claim()
        if not job_id:
            return False
        if self.isolated:
            process = multiprocessing.get_context("fork").Process(target=_child_execute,
                                                                    args=(job_id, self.worker_id))
            process.start()
            self._supervise(process, job_id)
        else:
            execute_job(job_id, self.worker_id)
        return True

    def run_forever(self):
        def stop(_signum, _frame):
            self.stopping = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        while not self.stopping:
            if not self.run_once():
                time.sleep(get_settings().worker_poll_seconds)
