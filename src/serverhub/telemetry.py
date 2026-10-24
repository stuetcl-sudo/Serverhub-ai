"""Ingest authenticated observations, retaining provenance and collection gaps."""

from __future__ import annotations

import hashlib
import json
import math
import statistics

from sqlalchemy import delete, select

from .audit import redact
from .database import utcnow
from .models import Finding, GraphEdge, Host, Incident, InventorySample, Memory
from .node.security import analyze
from .inventory_history import record_inventory


def sanitize_observation(value):
    # Observation lists (notably packages) must remain complete. Audit-log list
    # truncation is intentionally not used for inventory; HTTP size limits bound it.
    if isinstance(value, dict):
        return {
            str(key): redact(item, str(key))
            if any(
                word in str(key).lower()
                for word in (
                    "password",
                    "secret",
                    "token",
                    "credential",
                    "authorization",
                    "cookie",
                    "private_key",
                    "api_key",
                    "environment",
                )
            )
            else sanitize_observation(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_observation(item) for item in value]
    return redact(value)


def metrics_from(inventory: dict) -> dict:
    hardware = inventory.get("hardware") or {}
    memory = hardware.get("memory") or {}
    load = hardware.get("load_average") or []
    cores = hardware.get("cpu_count") or 1
    return {
        "memory_percent": memory.get("percent"),
        "memory_used": memory.get("used"),
        "memory_total": memory.get("total"),
        "load_1m": load[0] if load else None,
        "load_per_core": (load[0] / cores) if load else None,
        "disk_usage": {str(disk.get("mountpoint")): {key: disk.get(key) for key in ("used", "free", "total", "percent", "fstype")}
                       for disk in hardware.get("disks", [])},
        "disk_max_percent": max((x.get("percent", 0) for x in hardware.get("disks", [])), default=None),
        "temperatures": {
            name: [entry.get("current") for entry in entries]
            for name, entries in hardware.get("sensors", {}).items()
        },
        "containers": len((inventory.get("docker") or {}).get("containers", [])),
        "collection_errors": len(inventory.get("errors", [])),
    }


def _edges(host: Host, inventory: dict):
    root = "host:" + host.id
    for interface in inventory.get("interfaces", []):
        identifier = root + ":interface:" + str(interface.get("name", "unknown"))
        yield root, identifier, "has_interface", True, {"source": "net_if_addrs"}
        for address in interface.get("addresses", []):
            if address.get("family") in {"AF_INET", "AF_INET6"}:
                yield (
                    identifier,
                    "ip:" + str(address.get("address")),
                    "owns_address",
                    True,
                    {"source": "net_if_addrs"},
                )
    for service in inventory.get("services", []):
        yield root, root + ":service:" + str(service.get("name")), "runs_service", True, {"source": "systemd"}
    for container in (inventory.get("docker") or {}).get("containers", []):
        identifier = root + ":container:" + str(container.get("id", container.get("name")))
        yield (
            root,
            identifier,
            "runs_container",
            True,
            {"name": container.get("name"), "source": "docker_inspect"},
        )
        for network in container.get("networks", {}):
            yield identifier, root + ":network:" + network, "attached_to", True, {"source": "docker_inspect"}
        for mount in container.get("mounts", []):
            yield (
                identifier,
                root + (":volume:" + str(mount["name"]) if mount.get("type") == "volume" and mount.get("name") else ":mount:" + str(mount.get("source"))),
                "mounts",
                True,
                {"rw": mount.get("rw"), "source": "docker_inspect"},
            )
        if container.get("image_id"):
            yield identifier, root + ":image:" + container["image_id"], "uses_image", True, {"source": "docker_inspect"}
        if container.get("compose_project") and container.get("compose_service"):
            project = root + ":compose:" + container["compose_project"]
            service = project + ":service:" + container["compose_service"]
            yield identifier, service, "implements_service", True, {"source": "compose_label", "runtime_health": "unverified"}
            yield service, project, "belongs_to_project", True, {"source": "compose_label"}
        for dependency in container.get("dependencies", []):
            yield (
                identifier,
                root + ":compose:" + str(container.get("compose_project")) + ":service:" + dependency,
                "declares_dependency",
                True,
                {"source": "compose_label", "runtime_health": "unverified"},
            )
    for endpoint in (inventory.get("caddy") or {}).get("endpoints", []):
        for hostname in endpoint.get("hosts", []):
            yield root + ":proxy:caddy", "hostname:" + hostname, "configured_endpoint", True, {"source": "reviewed_caddy_json", "reachability": "unverified"}
    for port in inventory.get("ports", []):
        identifier = (
            root
            + ":listener:"
            + str(port.get("protocol"))
            + ":"
            + str(port.get("address"))
            + ":"
            + str(port.get("port"))
        )
        yield (
            root,
            identifier,
            "listens_on",
            True,
            {"source": "socket_table", "internet_exposure": "unverified"},
        )
    for proxy in inventory.get("reverse_proxies", []):
        yield (
            root,
            root + ":proxy:" + str(proxy.get("name")),
            "may_proxy",
            False,
            {"source": "service_name_heuristic"},
        )
    for neighbor in inventory.get("neighbors", []):
        if neighbor.get("dst"):
            yield (
                root,
                "ip:" + str(neighbor["dst"]),
                "observed_neighbor",
                True,
                {"source": "neighbor_table", "ownership": "unknown", "state": neighbor.get("state")},
            )


def update_graph(db, host: Host, inventory: dict):
    db.execute(delete(GraphEdge).where(GraphEdge.host_id == host.id))
    seen = set()
    for source, target, relation, verified, evidence in _edges(host, inventory):
        identity = source[:300], target[:300], relation
        if identity in seen:
            continue
        seen.add(identity)
        db.add(
            GraphEdge(
                host_id=host.id,
                source=identity[0],
                target=identity[1],
                relation=relation,
                verified=verified,
                confidence=1.0 if verified else 0.5,
                evidence=evidence,
                last_seen=utcnow(),
            )
        )


def update_findings(db, host: Host, inventory: dict):
    current = {row.key: row for row in db.scalars(select(Finding).where(Finding.host_id == host.id))}
    observed = set()
    for item in analyze(inventory):
        key = item.get("key") or hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest()
        observed.add(key)
        row = current.get(key)
        if row is None:
            row = Finding(host_id=host.id, key=key)
            db.add(row)
        confidence = item.get("confidence", 0.5)
        if isinstance(confidence, str):
            confidence = {
                "verified_configuration": 1.0,
                "verified_observation": 1.0,
                "scanner_report": 0.9,
                "inferred": 0.5,
                "unknown": 0.0,
            }.get(confidence, 0.5)
        row.title = str(item.get("title") or item.get("summary") or "Observed configuration finding")[:300]
        row.severity, row.confidence = item.get("severity", "info"), float(confidence)
        row.service, row.evidence = str(item.get("service", "host"))[:200], item.get("evidence", {})
        row.remediation, row.last_seen = item.get("remediation", []), utcnow()
        if row.status in {None, "resolved", "not_observed"}:
            row.status = "open"
    # A missing collector is not proof of remediation. Keep stale evidence explicit.
    for key, row in current.items():
        if key not in observed and row.status == "open":
            row.status = "not_observed"


def detect_incidents(db, host: Host, inventory: dict, metrics: dict):
    observations, healthy = [], {}
    for metric, threshold, title in (
        ("memory_percent", 90, "High memory usage"),
        ("disk_max_percent", 90, "Disk capacity pressure"),
        ("load_per_core", 2, "High host load requires investigation"),
    ):
        value = metrics.get(metric)
        if isinstance(value, (int, float)) and math.isfinite(value) and value < threshold:
            healthy[title] = {"metric": metric, "value": value, "threshold": threshold}
        if isinstance(value, (int, float)) and math.isfinite(value) and value >= threshold:
            observations.append((title, {"metric": metric, "value": value, "threshold": threshold}))
    samples = db.scalars(
        select(InventorySample)
        .where(InventorySample.host_id == host.id)
        .order_by(InventorySample.id.desc())
        .limit(60)
    ).all()
    baseline_stable = {}
    for key in ("load_per_core", "memory_percent"):
        values = [sample.metrics.get(key) for sample in samples]
        values = [x for x in values if isinstance(x, (float, int)) and math.isfinite(x)]
        value = metrics.get(key)
        if len(values) >= 6 and isinstance(value, (int, float)):
            median = statistics.median(values)
            threshold = max(median * 3, 1 if key == "load_per_core" else 70)
            if math.isfinite(value) and median > 0 and value <= threshold:
                baseline_stable[key] = {"value": value, "median": median, "threshold": threshold}
            if median > 0 and value > threshold:
                observations.append(
                    (
                        "Performance diverged from observed baseline",
                        {"metric": key, "value": value, "median": median, "samples": len(values)},
                    )
                )
    if len(baseline_stable) == 2:
        healthy["Performance diverged from observed baseline"] = baseline_stable
    for service in inventory.get("services", []):
        if service.get("active") == "active":
            healthy["Failed service: " + str(service.get("name"))] = {"active": "active"}
        if service.get("active") == "failed":
            observations.append(
                (
                    "Failed service: " + str(service.get("name")),
                    {"service": service.get("name"), "source": "systemd"},
                )
            )
    for container in (inventory.get("docker") or {}).get("containers", []):
        if (container.get("restart_delta") == 0 and container.get("state") == "running"
                and container.get("health") in {None, "healthy"}):
            healthy["Unstable container: " + str(container.get("name"))] = {
                "state": container.get("state"), "health": container.get("health"), "restart_delta": 0}
        if container.get("health") == "unhealthy" or (container.get("restart_delta") or 0) >= 5:
            observations.append(
                (
                    "Unstable container: " + str(container.get("name")),
                    {
                        "container": container.get("name"),
                        "health": container.get("health"),
                        "restart_count": container.get("restart_count"), "restart_delta": container.get("restart_delta"),
                    },
                )
            )
    for title, evidence in observations:
        title = title[:300]
        incident = db.scalar(
            select(Incident).where(
                Incident.host_id == host.id, Incident.title == title, Incident.state == "open"
            )
        )
        if incident:
            incident.evidence = {
                **incident.evidence,
                "stable": [], "stable_since": None,
                "latest": evidence,
                "last_observed": utcnow().isoformat() + "Z",
            }
        else:
            db.add(Incident(host_id=host.id, title=title, severity="warning", evidence={**evidence, "source": "telemetry", "stable": []}))
            db.add(Memory(host_id=host.id, kind="incident", content=title, evidence=evidence, verified=True))

    from .settings import get_settings
    from .audit import append_audit
    from datetime import datetime
    settings = get_settings()
    active = {title[:300] for title, _ in observations}
    for incident in db.scalars(select(Incident).where(Incident.host_id == host.id, Incident.state == "open")):
        if incident.evidence.get("source") != "telemetry" or incident.title in active:
            continue
        evidence = dict(incident.evidence)
        if incident.title not in healthy or inventory.get("errors"):
            evidence["stable"] = []
            evidence["stable_since"] = None
        else:
            stable = list(evidence.get("stable", []))
            now = utcnow()
            # Large observation gaps are not continuous stability.
            if stable and (now-datetime.fromisoformat(stable[-1]["at"])).total_seconds() > settings.offline_seconds:
                stable = []
                evidence["stable_since"] = None
            if not stable or (now-datetime.fromisoformat(stable[-1]["at"])).total_seconds() >= 1:
                stable.append({"at": now.isoformat(), "observation": healthy[incident.title]})
            evidence["stable_since"] = evidence.get("stable_since") or stable[0]["at"]
            evidence["stable"] = stable[-settings.incident_stable_samples:]
            if (len(stable) >= settings.incident_stable_samples
                    and (now-datetime.fromisoformat(evidence["stable_since"])).total_seconds() >= settings.incident_stable_seconds):
                incident.state, incident.resolved_at = "resolved", now
                incident.resolution = {"verified": True, "method": "consecutive stable observations",
                                       "samples": stable, "scope": "symptom cleared; root cause not inferred"}
                append_audit(db, "telemetry", "incident.resolved", incident.id, incident.resolution)
        incident.evidence = evidence


def ingest_inventory(db, host: Host, inventory: dict):
    cleaned = sanitize_observation(inventory)
    from .settings import get_settings
    previous = {c.get("id"): c for c in (host.inventory.get("docker") or {}).get("containers", []) if c.get("id")}
    fresh = host.last_seen and (utcnow()-host.last_seen).total_seconds() <= get_settings().offline_seconds
    for container in (cleaned.get("docker") or {}).get("containers", []):
        old = previous.get(container.get("id"), {}).get("restart_count")
        count = container.get("restart_count")
        container["restart_delta"] = (count-old if fresh and type(count) is int and type(old) is int
                                      and count >= old else None)
    metrics = metrics_from(cleaned)
    detect_incidents(db, host, cleaned, metrics)
    host.inventory, host.last_seen = cleaned, utcnow()
    record_inventory(db, host, cleaned, metrics)
    update_graph(db, host, cleaned)
    update_findings(db, host, cleaned)


def ingest_scanner_result(db, host: Host, result: dict):
    """Persist scanner evidence separately from inventory configuration heuristics."""
    scanner = result.get("scanner")
    if scanner not in {"trivy", "lynis"}:
        return
    findings = list(result.get("findings", []))
    if scanner == "lynis":
        findings += [
            {
                "summary": str(warning),
                "severity": "medium",
                "service": "host",
                "evidence": {"warning": warning},
                "remediation": ["Review the Lynis check and vendor guidance"],
            }
            for warning in result.get("warnings", [])
        ]
    for item in findings[:10000]:
        evidence = {
            **item.get("evidence", {}),
            "scanner": scanner,
            "coverage": result.get("coverage"),
            "internet_exposure": "unverified",
        }
        key = str(
            item.get("key") or hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()
        )[:200]
        row = db.scalar(select(Finding).where(Finding.host_id == host.id, Finding.key == key))
        if row is None:
            row = Finding(host_id=host.id, key=key)
            db.add(row)
        row.title = str(item.get("summary") or item.get("title") or "Scanner finding")[:300]
        row.severity, row.confidence = item.get("severity", "info"), 0.9
        row.service = str(item.get("service", "host"))[:200]
        row.evidence, row.remediation = redact(evidence), item.get("remediation", [])
        row.status, row.last_seen = "open", utcnow()
