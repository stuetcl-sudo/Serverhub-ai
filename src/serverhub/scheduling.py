"""Durable interval schedules. Missed intervals coalesce; grants never auto-renew."""

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from .audit import append_audit
from .auth import Principal, current_principal, principal_for_user, require_owner
from .database import get_db, utcnow
from .models import Job, Schedule, User, to_dict
from .policy import PermissionDenied, authorize

router = APIRouter(tags=["schedules"])


class NewSchedule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    kind: str = Field(pattern="^(inventory|operation|workflow|monitoring|autonomous)$")
    spec: dict
    host_id: str | None = None
    project: str | None = Field(default=None, max_length=200)
    interval_seconds: int = Field(ge=60, le=2678400)


@router.get("/schedules")
def list_schedules(actor: Principal = Depends(current_principal), db=Depends(get_db)):
    require_owner(actor)
    return [to_dict(row) for row in db.scalars(select(Schedule).order_by(Schedule.next_run))]


@router.post("/schedules", status_code=201)
def create_schedule(body: NewSchedule, actor: Principal = Depends(current_principal), db=Depends(get_db)):
    require_owner(actor)
    authorize(db, actor, "job.submit", body.host_id, body.project)
    # Validate the concrete job now; the first job is the first scheduled run.
    from .jobs import submit_job

    first = submit_job(db, actor, body.kind, body.spec, host_id=body.host_id, project=body.project)
    row = Schedule(
        **body.model_dump(),
        owner_id=actor.id,
        next_run=utcnow() + timedelta(seconds=body.interval_seconds),
        last_job_id=first.id,
    )
    db.add(row)
    db.flush()
    append_audit(
        db, actor.id, "schedule.created", row.id, {"kind": row.kind, "interval_seconds": row.interval_seconds}
    )
    db.commit()
    return to_dict(row)


class ScheduleStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


@router.patch("/schedules/{schedule_id}")
def schedule_status(
    schedule_id: str, body: ScheduleStatus, actor: Principal = Depends(current_principal), db=Depends(get_db)
):
    require_owner(actor)
    row = db.get(Schedule, schedule_id)
    if not row:
        raise HTTPException(404, "Schedule not found")
    row.enabled = body.enabled
    append_audit(db, actor.id, "schedule.status", row.id, {"enabled": body.enabled})
    db.commit()
    return to_dict(row)


def tick(db):
    from .jobs import TERMINAL, submit_job

    now = utcnow()
    due = db.scalars(
        select(Schedule)
        .where(Schedule.enabled.is_(True), Schedule.next_run <= now)
        .order_by(Schedule.next_run)
        .limit(100)
        .with_for_update(skip_locked=True)
    ).all()
    for row in due:
        previous = db.get(Job, row.last_job_id) if row.last_job_id else None
        # Never overlap a schedule with its own unfinished job, including paused/approval jobs.
        if previous and previous.state not in TERMINAL:
            row.next_run = now + timedelta(seconds=row.interval_seconds)
            continue
        user = db.get(User, row.owner_id)
        try:
            if not user or not user.enabled:
                raise PermissionDenied("Schedule owner is disabled")
            job = submit_job(
                db,
                principal_for_user(user),
                row.kind,
                row.spec,
                host_id=row.host_id,
                project=row.project,
                idempotency_key="schedule:" + row.id + ":" + row.next_run.isoformat(),
            )
            row.last_job_id, row.last_error = job.id, None
        except (PermissionDenied, ValueError) as exc:
            row.last_error = str(exc)[:1000]
            append_audit(db, row.owner_id, "schedule.blocked", row.id, {"reason": row.last_error})
        row.next_run = now + timedelta(seconds=row.interval_seconds)
        row.updated_at = now
