"""Bounded structural inventory history using the existing durable sample table.

Store sanitized resource state alongside metrics; never treat a collector gap as
proof of removal. Only complete, consecutive section observations are diffed.
"""
from sqlalchemy import delete, select

from .models import InventorySample

HISTORY_LIMIT = 1000
DIFF_ID_LIMIT = 100


def resource_state(inventory: dict) -> dict:
    errors = {item.get("collector") for item in inventory.get("errors", [])}
    state = {}
    for section, identity in (("services", "name"), ("ports", None)):
        if section not in inventory or section in errors:
            continue
        rows = inventory[section]
        state[section] = {
            str(row.get(identity)) if identity else f"{row.get('protocol')}:{row.get('address')}:{row.get('port')}": row
            for row in rows
        }
    docker = inventory.get("docker") or {}
    if docker.get("available") and docker.get("complete", True) and "docker" not in errors:
        for section, identity in (("containers", "id"), ("networks", "name"), ("volumes", "name"), ("compose_projects", "name")):
            state[section] = {str(row.get(identity)): row for row in docker.get(section, [])}
        state["images"] = {f"{row.get('id')}:{row.get('repository')}:{row.get('tag')}": row for row in docker.get("images", [])}
    caddy = inventory.get("caddy") or {}
    if caddy.get("available") and "caddy" not in errors:
        state["caddy_endpoints"] = {str(row.get("server")): row for row in caddy.get("endpoints", [])}
    return state


def structural_diff(previous: dict, current: dict) -> dict:
    sections = {}
    for section in sorted(set(previous) | set(current)):
        if section not in current:
            sections[section] = {"status": "unavailable", "reason": "incomplete or unavailable collector; removals not inferred"}
            continue
        before, after = previous.get(section, {}), current[section]
        added, removed = sorted(set(after) - set(before)), sorted(set(before) - set(after))
        changed = sorted(key for key in set(after) & set(before) if after[key] != before[key])
        sections[section] = {"status": "compared" if section in previous else "first_observation",
                             "added": added[:DIFF_ID_LIMIT], "removed": removed[:DIFF_ID_LIMIT], "changed": changed[:DIFF_ID_LIMIT],
                             "counts": {"added": len(added), "removed": len(removed), "changed": len(changed)},
                             "truncated": max(len(added), len(removed), len(changed)) > DIFF_ID_LIMIT}
    return {"sections": sections, "source": "consecutive_authenticated_inventory", "id_limit": DIFF_ID_LIMIT}


def record_inventory(db, host, inventory, metrics):
    previous = db.scalar(select(InventorySample).where(InventorySample.host_id == host.id).order_by(InventorySample.id.desc()).limit(1))
    current = resource_state(inventory)
    changes = structural_diff((previous.metrics.get("inventory_state") or {}) if previous else {}, current)
    metrics.update({"inventory_state": current, "inventory_diff": changes,
                    "observed_at": inventory.get("observed_at")})
    db.add(InventorySample(host_id=host.id, metrics=metrics))
    db.flush()
    cutoff = db.scalar(select(InventorySample.id).where(InventorySample.host_id == host.id)
                       .order_by(InventorySample.id.desc()).offset(HISTORY_LIMIT - 1).limit(1))
    if cutoff is not None:
        db.execute(delete(InventorySample).where(InventorySample.host_id == host.id, InventorySample.id < cutoff))
