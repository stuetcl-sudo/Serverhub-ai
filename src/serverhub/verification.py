"""Deterministic verification of specifically named observations, never model prose."""

from .database import utcnow
from .models import Host, InventorySample
from sqlalchemy import select


def verify_inventory(db, host_id, checks):
    host = db.get(Host, host_id) if host_id else None
    if host:
        db.refresh(host)
    fresh = bool(
        host and not host.revoked and host.last_seen and (utcnow() - host.last_seen).total_seconds() < 180
    )
    inventory = host.inventory if host else {}
    sample = (
        db.scalar(
            select(InventorySample)
            .where(InventorySample.host_id == host_id)
            .order_by(InventorySample.created_at.desc())
            .limit(1)
        )
        if host
        else None
    )
    inventory_fresh = bool(fresh and sample and (utcnow() - sample.created_at).total_seconds() < 180)
    results = []
    for check in checks:
        kind, target = check["kind"], check.get("target")
        if kind in {"inventory.fresh", "host.online"}:
            passed = inventory_fresh and bool(inventory) if kind == "inventory.fresh" else fresh
        elif kind == "systemd.active":
            passed = (
                inventory_fresh
                and bool(target)
                and any(
                    x.get("name") == target and x.get("active") == "active"
                    for x in inventory.get("services", [])
                )
            )
        elif kind == "container.healthy":
            passed = (
                inventory_fresh
                and bool(target)
                and any(
                    x.get("name") == target and x.get("health") == "healthy"
                    for x in (inventory.get("docker") or {}).get("containers", [])
                )
            )
        else:
            passed = False
        results.append({**check, "passed": bool(passed)})
    return {
        "verified": bool(results) and all(x["passed"] for x in results),
        "checks": results,
        "scope": "Only the named deterministic checks; not proof of an arbitrary natural-language goal",
        "source": "recent authenticated node report",
    }


def verify_task(ctx, checks):
    """Combine current observations with this task's own verified child receipts."""
    from .models import Job
    from uuid import UUID
    inventory_checks=[check for check in checks if check.get('kind')!='job.verified']
    results=verify_inventory(ctx.db,ctx.job.host_id,inventory_checks)['checks'] if inventory_checks else []
    for check in checks:
        if check.get('kind')!='job.verified':
            continue
        child=None
        try:
            identity=str(UUID(check.get('target') or ''))
            child=ctx.db.get(Job,identity)
        except (ValueError,TypeError):
            pass
        passed=bool(child and child.parent_id==ctx.job.id and child.owner_id==ctx.job.owner_id
                    and child.host_id==ctx.job.host_id and child.state=='succeeded'
                    and (child.result or {}).get('verified') is True)
        results.append({**check,'passed':passed})
    return {'verified':bool(results) and all(item['passed'] for item in results),'checks':results,
            'scope':'Only named current observations and acceptance-verified direct child tasks; not arbitrary prose',
            'source':'Authenticated observations or durable child acceptance receipts'}
