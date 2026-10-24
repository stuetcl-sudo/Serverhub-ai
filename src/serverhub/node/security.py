"""Evidence-based configuration analysis, deliberately separate from vulnerability claims."""
from __future__ import annotations
import hashlib
import json
from typing import Any

MANAGEMENT_PORTS = {22: "SSH", 2375: "Docker API", 2376: "Docker TLS API", 3306: "MySQL", 5432: "PostgreSQL",
                    6379: "Redis", 8006: "Proxmox", 9000: "Management UI", 9443: "Management UI", 11434: "Ollama"}


def _finding(kind: str, service: str, severity: str, confidence: str, evidence: dict, summary: str, remediation: list[str]) -> dict:
    identity = json.dumps([kind, service, evidence.get("port"), evidence.get("address"), evidence.get("mount")], sort_keys=True)
    return {"key": hashlib.sha256(identity.encode()).hexdigest(), "kind": kind, "service": service,
            "severity": severity, "confidence": confidence, "evidence": evidence, "summary": summary,
            "remediation": remediation, "status": "open", "internet_exposure": "unverified"}


def analyze(inventory: dict[str, Any]) -> list[dict]:
    findings = []
    for port in inventory.get("ports", []):
        service = port.get("process") or f"unattributed-{port.get('protocol', 'tcp')}:{port.get('port')}"
        if port.get("scope") != "loopback" and port.get("port") in MANAGEMENT_PORTS:
            findings.append(_finding("management_listener", service, "high" if port["port"] in {2375, 6379, 11434} else "medium",
                                     "verified_configuration", {**port, "interpretation": "local bind observed; LAN/internet reachability unverified"},
                                     f"{MANAGEMENT_PORTS[port['port']]} listens beyond loopback",
                                     ["Check documented clients and access requirements", "Verify firewall and remote reachability", "Bind to a management address or restrict allowed sources under an approved network policy"]))
        if not port.get("process"):
            findings.append(_finding("unattributed_listener", service, "info", "verified_observation",
                                     port, "Listening port has no attributable process in this observation",
                                     ["Collect broker inventory to attribute the process", "Document service ownership; do not remove solely because ownership is unknown"]))
    for container in (inventory.get("docker") or {}).get("containers", []):
        service = container.get("name") or container.get("id", "unknown")
        evidence = {"container_id": container.get("id"), "image": container.get("image"), "state": container.get("state")}
        if container.get("privileged"):
            findings.append(_finding("privileged_container", service, "critical", "verified_configuration", {**evidence, "privileged": True},
                                     "Container runs privileged", ["Determine required devices/capabilities", "Redeploy with minimal explicit permissions through a tested release"]))
        if container.get("network_mode") == "host":
            findings.append(_finding("host_network", service, "medium", "verified_configuration", {**evidence, "network_mode": "host"},
                                     "Container shares host networking", ["Verify whether multicast, discovery or performance requires host networking", "Use a dedicated bridge if validated compatible"]))
        if not container.get("has_healthcheck"):
            findings.append(_finding("missing_healthcheck", service, "low", "verified_configuration", evidence,
                                     "Container has no Docker healthcheck", ["Define an application-specific healthcheck and test its failure behavior"]))
        if container.get("health") == "unhealthy" or (container.get("restart_delta") or 0) >= 5:
            findings.append(_finding("container_instability", service, "high", "verified_observation", {**evidence, "health": container.get("health"), "restart_count": container.get("restart_count")},
                                     "Container is unhealthy or repeatedly restarting", ["Inspect bounded logs and dependencies", "Compare resources to baseline before an authorized restart"]))
        for mount in container.get("mounts", []):
            source = mount.get("source", "")
            if source in {"/", "/etc", "/proc", "/sys", "/dev", "/root", "/var/run/docker.sock", "/run/docker.sock"} or source.startswith(("/etc/serverhub", "/opt/serverhub", "/var/lib/serverhub-recovery")):
                severity = "critical" if mount.get("rw") else "high"
                findings.append(_finding("dangerous_mount", service, severity, "verified_configuration", {**evidence, "mount": mount},
                                         "Container mounts a sensitive host path", ["Identify the consumer and required access", "Remove the mount or replace it with a narrowly scoped interface after validation"]))
    firewall = inventory.get("firewall") or {}
    if not firewall.get("available"):
        findings.append(_finding("firewall_unverified", "host", "info", "unknown", {"reason": firewall.get("reason", "not observed")},
                                 "Firewall state could not be verified", ["Use the read-only broker collector; do not infer that no firewall exists"]))
    for neighbor in inventory.get("neighbors", []):
        if neighbor.get("dst") and neighbor.get("state") not in [["FAILED"], ["INCOMPLETE"]]:
            # A neighbor observation does not prove a new/hostile device or ownership.
            neighbor.setdefault("attribution", "unverified")
    return findings


def vulnerability_findings(report: dict, *, service: str) -> list[dict]:
    """Normalize Trivy JSON without inventing reachability or claiming total coverage."""
    findings = []
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            severity = str(vuln.get("Severity", "UNKNOWN")).lower()
            evidence = {"scanner": "trivy", "target": result.get("Target"), "id": vuln.get("VulnerabilityID"),
                        "package": vuln.get("PkgName"), "installed": vuln.get("InstalledVersion"), "fixed": vuln.get("FixedVersion"),
                        "source": (vuln.get("DataSource") or {}).get("URL"), "scanner_reachability": "not_evaluated"}
            item = _finding("known_vulnerability", service, severity if severity in {"critical", "high", "medium", "low"} else "info",
                            "scanner_report", evidence, vuln.get("Title") or vuln.get("VulnerabilityID") or "Scanner finding",
                            ["Correlate package and runtime usage", "Test vendor-fixed version in staging" if vuln.get("FixedVersion") else "Review vendor advisory and compensating controls"])
            item["key"] = hashlib.sha256(json.dumps([service, evidence], sort_keys=True).encode()).hexdigest()
            findings.append(item)
    return findings
