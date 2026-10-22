"""Deterministic read-only host audit. Plans never become execution authority.

Fresh authenticated observations and caller-reported historical baselines remain
separate. This module has no mutation adapter, shell endpoint or model dependency.
"""
from __future__ import annotations

import hashlib
import math
from pathlib import PurePosixPath
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select

from .database import utcnow
from .models import InventorySample


class ReportedBaseline(BaseModel):
    model_config = ConfigDict(extra="forbid")
    observed_at: datetime
    source: str = Field(default="caller_report", max_length=200)
    disk_percent: dict[str, float] = Field(default_factory=dict, max_length=20)
    container_count: int | None = Field(default=None, ge=0, le=100000)

    @field_validator("disk_percent")
    @classmethod
    def bounded_disks(cls, values):
        if any(len(key) > 512 or not math.isfinite(value) or not 0 <= value <= 100 for key, value in values.items()):
            raise ValueError("Disk baseline requires bounded mount names and percentages")
        return values

    @field_validator("observed_at")
    @classmethod
    def dated(cls, value):
        if value.tzinfo is None:
            raise ValueError("Baseline observation requires timezone")
        if value.astimezone(timezone.utc).replace(tzinfo=None) > utcnow():
            raise ValueError("Historical baseline cannot be in the future")
        return value


class AuditArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")
    baseline: ReportedBaseline | None = None
    storage_target: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,64}$")


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _plan(steps, verification, risk="requires service-specific staging and owner review"):
    return {"steps": steps, "risk": risk, "automatic_action": False, "approval_required": True,
            "verification": verification, "rollback": "Require tested restore/checkpoint before any approved change"}


def _finding(category, target, title, evidence, *, priority=20, severity="warning", steps=None, verification=None, confidence="observed_configuration"):
    key = hashlib.sha256(f"{category}:{target}".encode()).hexdigest()
    return {"id": key, "category": category, "target": target, "title": title, "priority": priority,
            "severity": severity, "confidence": confidence, "evidence": evidence,
            "impact": "Potential availability or security impact; not a measured improvement estimate",
            "action_plan": _plan(steps or ["Review the evidence and affected service dependencies"], verification or ["Repeat current health checks after an approved staged change"])}


def _growth(samples, mount):
    points = []
    for sample in samples:
        disk = (sample.metrics.get("disk_usage") or {}).get(mount) or {}
        used = disk.get("used")
        if _number(used):
            points.append((sample.created_at, used))
    points.sort(key=lambda point: point[0])
    if len(points) < 2 or (elapsed := (points[-1][0] - points[0][0]).total_seconds()) < 60:
        return {"status": "insufficient_history", "samples": len(points)}
    rate = (points[-1][1] - points[0][1]) / elapsed
    return {"status": "observed_trend", "bytes_per_second": rate, "samples": len(points),
            "window_seconds": elapsed, "warning": "Linear observed trend, not a forecast guarantee"}


def analyze_host(inventory: dict, *, received_at: datetime, samples=(), baseline: ReportedBaseline | None = None, storage=None) -> dict:
    findings, gaps = [], []
    errors = inventory.get("errors") or []
    failed = {entry.get("collector") for entry in errors}
    gaps.extend(f"collector:{name}" for name in sorted(str(x) for x in failed))
    hardware = inventory.get("hardware") or {}
    disks = hardware.get("disks") or []
    if not disks:
        gaps.append("disk_capacity")
    for disk in disks:
        mount = str(disk.get("mountpoint", "unknown"))
        percent = disk.get("percent")
        if not _number(percent):
            gaps.append("disk_capacity:" + mount)
            continue
        trend = _growth(samples, mount)
        rate, free = trend.get("bytes_per_second"), disk.get("free")
        if _number(rate) and rate > 0 and _number(free):
            trend["estimated_seconds_to_full"] = free / rate
        if percent >= 80:
            findings.append(_finding("disk_capacity", mount, f"Disk {mount} is {percent:g}% used",
                {"disk": disk, "trend": trend, "thresholds_percent": {"warning": 80, "high": 90, "critical": 95}},
                priority=0, severity="critical" if percent >= 95 else "high" if percent >= 90 else "warning",
                confidence="measured_capacity",
                steps=["Measure directory usage only through an explicitly approved storage target", "Map mounts, loopback backing files, named volumes and data owners", "Verify protected backups, restore test and free-space requirements before proposing expansion or relocation", "Do not delete, prune, truncate or move data automatically"],
                verification=["Re-measure free bytes and growth over multiple observations", "Check Docker and dependent application health", "Confirm backup restore before scheduling any migration"]))
    docker = inventory.get("docker") or {}
    containers = docker.get("containers") or []
    if not docker.get("available") or docker.get("complete") is False:
        gaps.append("docker_complete_inventory")
    zones, dependencies = [], []
    for container in containers:
        name = str(container.get("name") or container.get("id"))
        evidence = {"container_id": container.get("id"), "image": container.get("image"), "compose_project": container.get("compose_project")}
        socket_mounts = [item for item in container.get("mounts", []) if item.get("source") in {"/run/docker.sock", "/var/run/docker.sock"}]
        if socket_mounts:
            findings.append(_finding("docker_socket", name, "Container can access the Docker control socket", {**evidence, "mounts": socket_mounts},
                priority=10, severity="critical", steps=["Identify exact consumer API methods and required scope", "Test a narrowly scoped broker/proxy or removal in staging; a read-only socket mount does not restrict Docker API methods", "Verify Jarvis/monitoring clients before an approved redeploy"]))
        if container.get("privileged"):
            findings.append(_finding("privileged_container", name, "Privileged container requires service-specific review", {**evidence, "privileged": True}, priority=11, severity="high",
                steps=["Inventory required devices/capabilities and host integrations", "Test minimum privileges in staging; preserve Home Assistant and smart-home hardware/discovery", "Require backup and owner-approved redeploy"]))
        if any("apparmor=unconfined" in str(option) for option in container.get("security_opt", [])):
            findings.append(_finding("apparmor_unconfined", name, "Container disables AppArmor confinement", evidence, priority=12, severity="high"))
        if container.get("health") == "unhealthy" or container.get("restart_count", 0) >= 5:
            findings.append(_finding("container_health", name, "Container health or restart history needs diagnosis", {**evidence, "health": container.get("health"), "restart_count": container.get("restart_count")}, priority=15,
                steps=["Read approved bounded logs and dependency health", "Correlate disk/memory pressure before proposing an allowlisted restart"]))
        image = str(container.get("image") or "")
        if image and "@sha256:" not in image and (image.endswith(":latest") or ":" not in image.rsplit("/", 1)[-1]):
            findings.append(_finding("mutable_image", name, "Container image uses an implicit or explicit latest tag", evidence, priority=40,
                steps=["Resolve current immutable image digest without pulling/replacing workloads", "Test the pinned release with backups and dependency health checks before a reviewed update"]))
        bindings = {port: values for port, values in (container.get("ports") or {}).items() if
                    any(binding.get("HostIp") not in {"127.0.0.1", "::1"} for binding in (values or []))}
        if bindings:
            findings.append(_finding("published_container_ports", name, "Container publishes ports beyond an explicit loopback binding", {**evidence, "bindings": bindings, "wan_exposure": "unverified"}, priority=30,
                steps=["Verify proxy/client requirements and host plus gateway firewall separately", "Stage a service-specific bind/network proposal; do not change networking automatically"]))
        if not container.get("compose_project"):
            findings.append(_finding("compose_unknown", name, "Container has no observed Compose project provenance", evidence, priority=45,
                steps=["Identify deployment owner and approved manifest/version without deleting the container"]))
        host_network = container.get("network_mode") == "host"
        label = (name + " " + str(container.get("compose_project", ""))).lower()
        zone = next((zone for words, zone in ((["caddy", "proxy", "traefik"], "proxy"), (["homeassistant", "home-assistant", "matter", "adguard"], "smart-home"), (["ollama", "jarvis"], "AI"), (["jellyfin", "media"], "media"), (["postgres", "mariadb", "mysql"], "private-data"), (["glances", "grafana", "prometheus"], "management")) if any(word in label for word in words)), "apps")
        zones.append({"container": name, "proposed_zone": zone, "confidence": "inferred_from_name", "actual_networks": list((container.get("networks") or {}).keys()),
                      "host_network_exception": host_network, "note": "Validate multicast/discovery and clients; no network changes are performed"})
        for dependency in container.get("dependencies", []):
            dependencies.append({"from": name, "project": container.get("compose_project"), "to_service": dependency, "evidence": "compose_label", "runtime_flow": "unverified"})
    for port in inventory.get("ports", []):
        if port.get("scope") in {"all_interfaces", "global_address"}:
            findings.append(_finding("listener_review", f"{port.get('protocol')}:{port.get('port')}", "Listener binds beyond a loopback-only interface", {"listener": port, "lan_reachability": "unverified", "wan_exposure": "unverified"}, priority=30,
                steps=["Map documented clients, host firewall and separate UniFi/gateway policy", "Verify external exposure independently from an authorized vantage point", "Do not modify firewall, SSH, DNS, WAN or routing in this audit"]))
    for service in inventory.get("services", []):
        if service.get("active") == "failed":
            findings.append(_finding("failed_service", str(service.get("name")), "Failed systemd unit requires diagnosis", service, priority=20,
                steps=["Collect explicitly allowed bounded service logs/status", "Check configuration, devices and dependencies", "Do not blindly reinstall GPU/fancontrol packages or restart critical services"]))
    gpus = hardware.get("gpus") or {}
    nvidia = gpus.get("nvidia") or {}
    if nvidia.get("pci_devices") and nvidia.get("status") != "observed":
        findings.append(_finding("gpu_diagnostics", "nvidia", "NVIDIA PCI device observed without a successful driver probe", nvidia, priority=25,
            steps=["Inspect bounded approved driver/runtime service logs and kernel/device compatibility", "Verify container GPU runtime configuration separately", "Do not blindly reinstall drivers or reboot production"]))
    if not gpus or nvidia.get("status") not in {"observed", "no_devices_reported"}:
        gaps.append("gpu_driver_runtime")
    storage_metadata = inventory.get("storage") or {}
    gaps.extend("storage:" + str(error.get("collector", "unknown")) for error in storage_metadata.get("errors", []))
    mounts = storage_metadata.get("mounts") or []
    for loop in storage_metadata.get("loops") or []:
        backing = loop.get("back-file")
        if not isinstance(backing, str) or not backing.startswith("/"):
            continue
        matching = [mount for mount in mounts if isinstance(mount.get("target"), str) and PurePosixPath(backing).is_relative_to(mount["target"])]
        parent = max(matching, key=lambda mount: len(mount["target"]), default={})
        if "ntfs" in str(parent.get("fstype", "")).lower() or parent.get("fstype") == "fuseblk":
            findings.append(_finding("loopback_storage_layer", str(loop.get("name")), "Loopback backing file is on an observed NTFS/fuseblk mount", {"loop": loop, "backing_mount": parent, "docker_relationship": "unverified"}, priority=5,
                steps=["Map the loop filesystem and Docker root/volumes before attributing ownership", "Compare outer free space, inner filesystem use and allocated versus apparent backing-file size", "Verify backups, restore and downtime before a separate migration plan", "Do not relocate, resize or delete the backing file automatically"]))
    gaps.append("smart_device_health")
    updates = inventory.get("updates") or {}
    if updates.get("reboot_required") or updates.get("upgradable_count", 0):
        findings.append(_finding("update_plan", "host", "Pending updates or reboot require coordinated maintenance", updates, priority=35,
            steps=["Confirm package-cache freshness, supported versions and vendor lifecycle; ESM availability is not assumed", "Check service/database dependencies, protected backup and a successful restore test", "Test updates in staging and record rollback limitations", "Coordinate downtime and owner approval for reboot; never auto-reboot production"],
            verification=["Check boot, DNS, proxy, AdGuard, Home Assistant, Jellyfin and database health as applicable", "Compare package versions and workload health to pre-change observations"]))
    if not updates.get("available"):
        gaps.append("package_update_status")
    firewall = inventory.get("firewall") or {}
    exposure = {"host_firewall": "observed_configuration" if firewall.get("available") else "unverified", "gateway_policy": "unverified", "wan_exposure": "unverified"}
    if not firewall.get("available"):
        gaps.append("host_firewall")
    gaps.extend(["gateway_policy", "external_reachability", "backup_restore_test", "runtime_network_flows", "vendor_package_lifecycle"])
    if storage is None:
        gaps.append("approved_directory_usage")
    comparison = {"status": "no_historical_baseline_supplied", "verified": False}
    if baseline:
        current_disks = {str(disk.get("mountpoint")): disk.get("percent") for disk in disks}
        comparison = {"status": "historical_caller_report", "source": baseline.source, "observed_at": baseline.observed_at.isoformat(), "verified": False,
                      "disk_percent": {mount: {"reported": value, "current": current_disks.get(mount), "change_percentage_points": current_disks[mount] - value if _number(current_disks.get(mount)) else None} for mount, value in baseline.disk_percent.items()},
                      "containers": {"reported": baseline.container_count, "current": len(containers) if docker.get("available") and docker.get("complete", True) else None}}
    findings.sort(key=lambda row: (row["priority"], row["category"], row["target"]))
    return {"mode": "read_only_dry_run", "changes_executed": [], "received_at": received_at.isoformat() + "Z", "observed_at": inventory.get("observed_at"),
            "findings": findings[:100], "total_findings": len(findings), "truncated": len(findings) > 100,
            "baseline_comparison": comparison, "coverage_gaps": sorted(set(gaps)), "collector_errors": errors,
            "storage": storage, "mount_loopback": inventory.get("storage"), "gpu": hardware.get("gpus"),
            "exposure": exposure, "zone_proposal": zones[:100], "dependency_declarations": dependencies[:200],
            "zone_migration": _plan(["Verify backup/restore and dependency/client map", "Test one noncritical app in staging", "Validate proxy, smart-home multicast and host-network exceptions", "Schedule separately approved reversible migrations, one service at a time"], ["Verify each service and clients before the next stage"]),
            "verified": False, "completed": False,
            "status": "partial_audit" if gaps or errors else "audit_complete",
            "summary": "Read-only evidence and ordered plans recorded; no repairs or exposure claims verified"}


def run_audit(ctx, arguments):
    from .node_api import execute_node
    args = AuditArguments.model_validate(arguments)
    ctx.require("host.audit", arguments=args.model_dump(mode="json", exclude_none=True))
    ctx.require("inventory.read")
    if not ctx.job.host_id:
        raise ValueError("Host audit requires a concrete enrolled target")
    state = dict((ctx.job.checkpoint or {}).get("host_audit") or {})
    checkpoint = dict(ctx.job.checkpoint or {})
    if state.get("collected_at") and (utcnow() - datetime.fromisoformat(state["collected_at"])).total_seconds() > 300:
        state = {"generation": state.get("generation", 0) + 1}
    if not state.get("inventory"):
        ctx.log("Host audit: collecting fresh read-only inventory")
        ctx.require("inventory.refresh")
        outcome = execute_node(ctx, "inventory.refresh", {}, idempotency_key=f"{ctx.job.id}:audit:refresh:{state.get('generation', 0)}")
        ctx.db.expire_all()
        sample = ctx.db.scalar(select(InventorySample).where(InventorySample.host_id == ctx.job.host_id).order_by(InventorySample.id.desc()).limit(1))
        if not sample or (utcnow() - sample.created_at).total_seconds() > 300:
            raise RuntimeError("No fresh authenticated inventory sample was recorded; inspect node/broker delivery")
        from .models import Host
        # Use the sanitized persisted inventory; command audit payloads may be
        # truncated/redacted and are not a complete source for this analysis.
        current = ctx.db.get(Host, ctx.job.host_id).inventory
        if not current.get("os"):
            raise RuntimeError("Node inventory lacks OS provenance; audit cannot confirm collection")
        state.update({"inventory": {key: current.get(key) for key in ("observed_at", "hardware", "docker", "services", "ports", "firewall", "storage", "updates", "errors")},
                      "collected_at": sample.created_at.isoformat(), "sample_id": sample.id, "refresh_complete": bool(outcome)})
        checkpoint["host_audit"] = state
        ctx.save_checkpoint(checkpoint, progress=0.5)
    if args.storage_target and "storage" not in state:
        ctx.require("diagnostics.storage", arguments={"target": args.storage_target})
        state["storage"] = execute_node(ctx, "diagnostics.storage", {"target": args.storage_target}, idempotency_key=f"{ctx.job.id}:audit:storage:{state.get('generation', 0)}")
        checkpoint["host_audit"] = state
        ctx.save_checkpoint(checkpoint, progress=0.7)
    ctx.log("Host audit: prioritizing capacity and checking configuration evidence")
    samples = ctx.db.scalars(select(InventorySample).where(InventorySample.host_id == ctx.job.host_id).order_by(InventorySample.id.desc()).limit(120)).all()
    report = analyze_host(state["inventory"], received_at=datetime.fromisoformat(state["collected_at"]), samples=samples, baseline=args.baseline, storage=state.get("storage"))
    report["inventory_sample_id"] = state["sample_id"]
    ctx.log("Host audit: read-only report recorded", {"findings": report["total_findings"], "coverage_gaps": report["coverage_gaps"], "changes_executed": 0})
    return report
