"""Owner-controlled ceilings and durable, conservative per-user admission quotas.

PostgreSQL serializes quota reservations across API/worker processes. Unknown
model outcomes are charged, never refunded. No request content is stored here.
"""
from sqlalchemy import func, select, text

from .database import utcnow
from .models import Job, JobControlState
from .policy import PermissionDenied
from .settings import get_settings


def check_route_budget(principal, kind, spec, tokens, cost):
    from .ai.providers import load_routes
    routes = load_routes() if kind in {"autonomous", "development_autonomous"} else {}
    name = spec.get("model_route") or ("development" if kind == "development_autonomous" and "development" in routes else "default")
    if not isinstance(name, str):
        raise ValueError("spec.model_route must be a string")
    route = routes.get(name)
    hard_tokens = route.max_job_token_budget if route else 2_000_000
    hard_cost = route.max_job_cost_budget if route else 1000
    ordinary_tokens = route.ordinary_job_token_limit if route else 200000
    ordinary_cost = route.ordinary_job_cost_limit if route else 10
    if tokens > hard_tokens or cost > hard_cost:
        raise ValueError(f"Route {name} budget ceiling: tokens={hard_tokens}, cost={hard_cost}")
    if principal.role != "owner" and (tokens > ordinary_tokens or cost > ordinary_cost):
        raise PermissionDenied("Owner authorization required above ordinary route budget limits")


def lock_quota(db):
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(734882110)"))


def _ledger(db, user):
    lock_quota(db)
    key = "job-quota:" + utcnow().date().isoformat() + ":" + user
    row = db.get(JobControlState, key, populate_existing=True)
    if row is None:
        row = JobControlState(key=key, value={"tokens": 0, "cost": 0.0, "runtime": 0})
        db.add(row)
        db.flush()
    return row


def admit_job(db, user, runtime):
    settings = get_settings()
    row = _ledger(db, user)
    pending = db.scalar(select(func.count()).select_from(Job).where(
        Job.owner_id == user, Job.state.not_in(["succeeded", "partial", "failed", "cancelled"])))
    if pending >= settings.max_user_pending_jobs:
        raise ValueError("Per-user pending job quota reached; finish or cancel existing jobs")
    if row.value.get("jobs", 0) >= settings.user_daily_jobs:
        raise ValueError("Per-user daily job quota reached; retry next UTC day")
    if row.value["runtime"] + runtime > settings.user_daily_runtime_seconds:
        raise ValueError("Per-user daily admitted runtime quota reached; retry next UTC day")
    row.value = {**row.value, "runtime": row.value["runtime"] + runtime, "jobs": row.value.get("jobs", 0) + 1}


def charge_daily(db, user, tokens, cost, *, enforce=True):
    from .jobs import BudgetExceeded
    settings = get_settings()
    row = _ledger(db, user)
    if enforce and (row.value["tokens"] + tokens > settings.user_daily_tokens or row.value["cost"] + cost > settings.user_daily_cost):
        raise BudgetExceeded("Per-user daily model quota reached; resume next UTC day (raising the job budget does not bypass this quota)",
                             {"minimum_tokens": tokens, "cost_reserve": cost})
    row.value = {**row.value, "tokens": row.value["tokens"] + tokens, "cost": row.value["cost"] + cost}


def resume_budget_error(job, db=None):
    if job.failure_class not in {"budget", "preflight"}:
        return None
    saved = (job.checkpoint or {}).get("budget_pause", {})
    minimum = saved.get("minimum_tokens", 32)
    cost = saved.get("minimum_cost", 0)
    if db is not None:
        row = db.get(JobControlState, "job-quota:" + utcnow().date().isoformat() + ":" + job.owner_id,
                     populate_existing=True)
        settings = get_settings()
        if row and (row.value["tokens"] + minimum > settings.user_daily_tokens
                    or row.value["cost"] + cost > settings.user_daily_cost):
            return {"message": "Per-user daily model quota cannot fit the next request; retry next UTC day",
                    "budget_endpoint": f"/api/jobs/{job.id}/budget", "job_budget_increase_will_not_bypass_quota": True}
    child_tokens, child_cost = 0, 0
    if db is not None:
        child_tokens, child_cost = db.execute(select(func.coalesce(func.sum(Job.tokens_used), 0),
            func.coalesce(func.sum(Job.cost_used), 0)).where(Job.parent_id == job.id)).one()
    remaining_tokens = job.token_budget - job.tokens_used - child_tokens
    remaining_cost = job.cost_budget - job.cost_used - child_cost
    if (remaining_tokens < minimum or remaining_cost < cost
            or (job.cost_budget > 0 and remaining_cost <= 0)):
        return {"message": "Insufficient remaining budget to resume; raise the authorized budget first",
                "minimum_remaining_tokens": minimum, "minimum_remaining_cost": cost,
                "remaining_tokens": remaining_tokens,
                "remaining_cost": remaining_cost,
                "budget_endpoint": f"/api/jobs/{job.id}/budget"}
    return None
