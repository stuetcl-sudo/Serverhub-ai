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
TERMINAL = {"succeeded", "failed", "cancelled"}
RUNNABLE = {"queued", "retry"}


class RetryableError(Exception):
    pass


class BudgetExceeded(Exception):
    pass


class JobCancelled(Exception):
    pass


class JobPaused(Exception):
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
               time_limit: int = 3600, token_budget: int = 20000, cost_budget: float = 1.0) -> Job:
    authorize(db, principal, "job.submit", host_id, project)
    if kind not in HANDLERS:
        raise ValueError(f"Unknown job kind: {kind}")
    if not isinstance(spec, dict):
        raise ValueError("job specification must be an object")
    if not (1 <= max_attempts <= 10 and 1 <= time_limit <= 86400 and 0 <= token_budget <= 2_000_000
            and math.isfinite(cost_budget) and 0 <= cost_budget <= 1000):
        raise ValueError("job execution limits outside supported bounds")
    dependencies = depends_on or []
    for dependency in dependencies + ([parent_id] if parent_id else []):
        linked = db.get(Job, dependency)
        if not linked or (linked.owner_id != principal.id and principal.role != "owner"):
            raise PermissionDenied("Job dependency or parent is unavailable")
    if len(set(dependencies)) != len(dependencies):
        raise ValueError("Duplicate dependencies")
    if idempotency_key:
        existing = db.scalar(select(Job).where(Job.owner_id == principal.id, Job.idempotency_key == idempotency_key))
        if existing:
            if (existing.kind, existing.spec, existing.host_id, existing.project) != (kind, spec, host_id, project):
                raise ValueError("Idempotency key already belongs to another request")
            return existing
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
    job = Job(owner_id=principal.id, kind=kind, spec=spec, host_id=host_id, project=project,
              parent_id=parent_id, depends_on=dependencies, idempotency_key=idempotency_key,
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
        if self.job.state in {"cancel_requested", "cancelled"}:
            raise JobCancelled("Job cancelled")
        if self.job.state in {"pause_requested", "paused"}:
            raise JobPaused("Job paused")
        if self.job.state != "running":
            raise LeaseLost("Job is no longer running")
        if self.job.started_at and (utcnow() - self.job.started_at).total_seconds() >= self.job.time_limit:
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

    def usage(self, tokens: int, cost: float):
        if not isinstance(tokens, int) or isinstance(tokens, bool) or tokens < 0 or not math.isfinite(cost) or cost < 0:
            raise ValueError("Usage cannot be negative")
        self.check_cancelled()
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
    if isinstance(exc, JobPaused):
        return "paused", "paused", False
    if isinstance(exc, LeaseLost):
        return "failed", "lease_lost", False
    if isinstance(exc, BudgetExceeded):
        return "failed", "budget", False
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
            job.state = "succeeded"
            job.finished_at = utcnow()
            job.error = None
            job.failure_class = None
            _event(db, job, "Job completed", {"state": "succeeded"})
            append_audit(db, user.id, "job.succeeded", job.id, {"kind": job.kind})
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
            job.failure_class = failure_class
            job.error = redact(str(exc))[:4000]
            if state == "retry":
                job.run_after = utcnow() + timedelta(seconds=min(300, 2 ** job.attempts))
            if state in TERMINAL:
                job.finished_at = utcnow()
            _event(db, job, "Job interrupted", {"state": state, "class": failure_class, "error": job.error}, "warning")
            append_audit(db, job.owner_id, "job." + state, job.id, {"class": failure_class, "error": job.error})
        job.lease_until = None
        job.worker_id = None
        job.updated_at = utcnow()
        db.commit()


def _child_execute(job_id, worker_id):
    # Forked processes must never reuse inherited pooled database connections.
    get_engine().dispose(close=False)
    execute_job(job_id, worker_id)


class Worker:
    def __init__(self, worker_id: str | None = None, isolated: bool = True):
        self.worker_id = worker_id or f"{os.uname().nodename}:{os.getpid()}:{uuid4().hex[:8]}"
        self.isolated = isolated
        self.stopping = False

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
                job.worker_id = None
                job.lease_until = None
                if job.state in TERMINAL:
                    job.finished_at = utcnow()
                _event(db, job, "Recovered expired worker lease", {"state": job.state})
            db.flush()
            running = db.scalar(select(func.count()).select_from(Job).where(Job.state.in_(["running", "pause_requested", "cancel_requested"])))
            if running >= settings.max_concurrent_jobs:
                db.commit()
                return None
            candidates = db.scalars(select(Job).where(Job.state.in_(RUNNABLE), Job.run_after <= utcnow())
                                    .order_by(Job.run_after, Job.created_at).limit(100)
                                    .with_for_update(skip_locked=True)).all()
            chosen = None
            for job in candidates:
                if job.host_id:
                    host_running = db.scalar(select(func.count()).select_from(Job).where(
                        Job.host_id == job.host_id, Job.state.in_(["running", "pause_requested", "cancel_requested"])))
                    if host_running >= settings.max_host_jobs:
                        continue
                dependencies = [db.get(Job, dep) for dep in job.depends_on]
                if any(dep is None or dep.state in {"failed", "cancelled"} for dep in dependencies):
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
                chosen.state = "running"
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
            process.join(timeout=min(1.0, settings.lease_seconds / 4))
            with SessionLocal() as db:
                job = db.get(Job, job_id)
                if not job or job.worker_id != self.worker_id:
                    interrupted = ("failed", "lease_lost")
                elif job.state == "cancel_requested" or self.stopping:
                    interrupted = ("cancelled" if not self.stopping else "retry", "cancelled" if not self.stopping else "worker_shutdown")
                elif job.state == "pause_requested":
                    interrupted = ("paused", "paused")
                elif job.started_at and (utcnow() - job.started_at).total_seconds() >= job.time_limit:
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
                job.error = "Worker process stopped; in-flight external effects require adapter reconciliation"
                job.worker_id = None
                job.lease_until = None
                if state in TERMINAL:
                    job.finished_at = utcnow()
                _event(db, job, job.error, {"state": state, "class": failure}, "warning")
                append_audit(db, job.owner_id, "job." + state, job.id, {"class": failure})
                db.commit()

    def run_once(self) -> bool:
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
