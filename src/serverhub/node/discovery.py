"""Read-only Linux discovery. Every collector reports incomplete observations explicitly.

Docker and firewall inspection require the separately configured broker; the ordinary
agent has neither Docker-group membership nor a privileged socket.
"""
from __future__ import annotations

import hashlib
import csv
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

MAX_OUTPUT = 16 * 1024 * 1024
SECRET_KEYS = re.compile(r"password|passwd|secret|token|credential|authorization|api.?key", re.I)


class CollectionError(RuntimeError):
    pass


def bounded_run(argv: list[str], *, timeout: int = 15, limit: int = MAX_OUTPUT) -> str:
    """Bound captured streams, not every file the child legitimately writes.

    RLIMIT_FSIZE is deliberately not used: it also truncates apt/dpkg databases
    and cache files, unrelated to captured diagnostic output.
    """
    import selectors
    import signal
    if not argv or not Path(argv[0]).is_absolute():
        raise CollectionError("executable must use an absolute path")
    proc = None
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/nonexistent",
                 "DEBIAN_FRONTEND": "noninteractive", "APT_LISTCHANGES_FRONTEND": "none"}, start_new_session=True)
        deadline=time.monotonic()+timeout
        output=bytearray()
        error_tail=bytearray()
        captured=0
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout,selectors.EVENT_READ,True)
            selector.register(proc.stderr,selectors.EVENT_READ,False)
            while selector.get_map():
                remaining=deadline-time.monotonic()
                if remaining<=0:
                    raise CollectionError(f"{Path(argv[0]).name} timed out")
                for key,_ in selector.select(min(.1,remaining)):
                    block=os.read(key.fileobj.fileno(),65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    captured+=len(block)
                    if captured>limit:
                        raise CollectionError(f"{Path(argv[0]).name} exceeded output limit")
                    if key.data:
                        output.extend(block)
                    else:
                        error_tail.extend(block)
                        del error_tail[:-8192]
        try:
            proc.wait(timeout=max(.01,deadline-time.monotonic()))
        except subprocess.TimeoutExpired:
            raise CollectionError(f"{Path(argv[0]).name} timed out") from None
        if proc.returncode:
            raise CollectionError(f"{Path(argv[0]).name} exited {proc.returncode}; permission or tool failure")
        return output.decode("utf-8","replace")
    except CollectionError:
        # A protected operator diagnostic preserves the real package/tool cause.
        # It is not returned to a model or unauthenticated endpoint.
        if os.geteuid()==0:
            try:
                from .docker_backup import protected
                directory=protected('/var/lib/serverhub-broker/diagnostics',create=True)
                from serverhub.audit import redact
                payload={'executable':Path(argv[0]).name,'returncode':proc.returncode if proc else None,
                         'stderr':redact(bytes(locals().get('error_tail',b'')).decode('utf-8','replace')),
                         'stdout':redact(bytes(locals().get('output',b''))[-8192:].decode('utf-8','replace'))}
                fd=os.open(directory/'latest.json',os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'w') as stream:
                    json.dump(payload,stream)
            except (OSError,ValueError,RuntimeError):
                pass
        raise
    except OSError as exc:
        raise CollectionError(f"{Path(argv[0]).name}: {type(exc).__name__}") from exc
    finally:
        if proc is not None:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
            for stream in (proc.stdout,proc.stderr):
                if stream is not None:
                    stream.close()


def command(name: str, *args: str, timeout: int = 15) -> str:
    executable = shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not executable:
        raise CollectionError(f"{name} not installed")
    return bounded_run([executable, *args], timeout=timeout)


def _read(path: str, limit: int = 1024 * 1024) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read(limit)


def _os() -> dict:
    release = {}
    for line in _read("/etc/os-release").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            release[key.lower()] = value.strip('"')
    machine = _read("/etc/machine-id", 128).strip() if Path("/etc/machine-id").exists() else ""
    return {"hostname": socket.gethostname(), "kernel": platform.release(), "architecture": platform.machine(),
            "distribution": release, "boot_time": datetime.fromtimestamp(psutil.boot_time(), timezone.utc).isoformat(),
            "machine_id_sha256": hashlib.sha256(machine.encode()).hexdigest() if machine else None}


def _hardware() -> dict:
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append({"device": part.device, "mountpoint": part.mountpoint, "fstype": part.fstype,
                          "total": usage.total, "used": usage.used, "free": usage.free, "percent": usage.percent})
        except (PermissionError, OSError):
            continue
    # Container overlay roots may not appear in disk_partitions.
    if not any(item["mountpoint"] == "/" for item in disks):
        usage = psutil.disk_usage("/")
        disks.append({"device": "root", "mountpoint": "/", "fstype": "unknown", "total": usage.total,
                      "used": usage.used, "free": usage.free, "percent": usage.percent})
    sensors = {}
    if hasattr(psutil, "sensors_temperatures"):
        for name, entries in psutil.sensors_temperatures().items():
            sensors[name] = [{"label": x.label, "current": x.current, "high": x.high, "critical": x.critical} for x in entries]
    procs = []
    for proc in psutil.process_iter(["pid", "name", "memory_percent", "cpu_times"]):
        try:
            info = proc.info
            times = info.pop("cpu_times", None)
            info["cpu_seconds"] = times.user + times.system if times else 0
            procs.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return {"cpu_count": psutil.cpu_count(), "cpu_physical": psutil.cpu_count(logical=False),
            "load_average": os.getloadavg(), "memory": {"total": vm.total, "available": vm.available, "used": vm.used, "percent": vm.percent},
            "gpus": gpu_inventory(),
            "swap": {"total": swap.total, "used": swap.used, "percent": swap.percent}, "disks": disks, "sensors": sensors,
            "processes_by_memory": sorted(procs, key=lambda p: p.get("memory_percent") or 0, reverse=True)[:20]}


def _packages() -> list[dict]:
    lines = command("dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\\n").splitlines()
    packages = []
    for line in lines:
        fields = line.split("\t")
        if len(fields) == 4 and fields[3] == "installed":
            packages.append({"name": fields[0], "version": fields[1], "architecture": fields[2]})
    return packages


def _interfaces() -> list[dict]:
    stats = psutil.net_if_stats()
    result = []
    for name, addrs in psutil.net_if_addrs().items():
        st = stats.get(name)
        result.append({"name": name, "is_up": bool(st and st.isup), "mtu": st.mtu if st else None,
                       "speed_mbps": st.speed if st else None,
                       "addresses": [{"family": x.family.name, "address": x.address,
                                      "netmask": x.netmask, "broadcast": x.broadcast} for x in addrs]})
    return result


def _routes() -> dict:
    return {"ipv4": json.loads(command("ip", "-j", "-4", "route", "show", "table", "all")),
            "ipv6": json.loads(command("ip", "-j", "-6", "route", "show", "table", "all"))}


def _dns() -> dict:
    servers, search = [], []
    for line in _read("/etc/resolv.conf", 32768).splitlines():
        parts = line.split()
        if len(parts) > 1 and parts[0] == "nameserver":
            servers.append(parts[1])
        elif parts and parts[0] in {"search", "domain"}:
            search.extend(parts[1:])
    return {"nameservers": servers, "search": search, "source": "/etc/resolv.conf"}


def _scope(address: str) -> str:
    if address in {"0.0.0.0", "::", "*"}:
        return "all_interfaces"
    try:
        addr = ipaddress.ip_address(address.split("%", 1)[0])
        return "loopback" if addr.is_loopback else "link_local" if addr.is_link_local else "private" if addr.is_private else "global_address"
    except ValueError:
        return "unknown"


def _ports() -> list[dict]:
    connections = psutil.net_connections(kind="inet")
    result = []
    for conn in connections:
        if not conn.laddr or (conn.type == socket.SOCK_STREAM and conn.status != psutil.CONN_LISTEN):
            continue
        if conn.type == socket.SOCK_DGRAM and conn.raddr:
            continue
        address, port = conn.laddr.ip, conn.laddr.port
        process = None
        if conn.pid:
            try:
                process = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        result.append({"protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp", "address": address,
                       "port": port, "pid": conn.pid, "process": process, "scope": _scope(address),
                       "internet_exposure": "unverified", "lan_reachability": "unverified"})
    return sorted(result, key=lambda x: (x["protocol"], x["port"], x["address"]))


def _services() -> list[dict]:
    units = json.loads(command("systemctl", "list-units", "--type=service", "--all", "--output=json", "--no-pager"))
    result = []
    for unit in units:
        name = unit.get("unit")
        if not name:
            continue
        result.append({"name": name, "load": unit.get("load"), "active": unit.get("active"),
                       "sub": unit.get("sub"), "description": unit.get("description")})
    return result


def _docker() -> dict:
    # Explicitly unsupported in the unprivileged process; root broker performs this collector.
    return {"available": False, "reason": "privileged broker inventory required", "containers": [], "images": [],
            "volumes": [], "networks": [], "compose_projects": []}


MAX_CONTAINERS = 1000


def _dependency_names(value: str) -> list[str]:
    # Compose v2 labels encode service:condition:restart, not bare IDs. These
    # are configuration declarations, never proof of a healthy runtime edge.
    return sorted({entry.split(":", 1)[0] for entry in str(value).split(",")
                   if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}(?::[^,]{0,128})?", entry)})


def docker_inventory() -> dict:
    """Broker-only read. No environment, commands, arbitrary labels or health logs.

    Bound inspect batches, skip containers removed during observation and report
    collection gaps explicitly. An incomplete snapshot cannot prove a deletion.
    """
    ids = command("docker", "container", "ls", "--all", "--quiet").split()
    truncated = len(ids) > MAX_CONTAINERS
    ids = ids[:MAX_CONTAINERS]
    containers, gaps, compose = [], [], {}
    deadline = time.monotonic() + 30
    for offset in range(0, len(ids), 25):
        batch = ids[offset:offset + 25]
        if time.monotonic() >= deadline:
            gaps.append({"reason": "inspect time budget exhausted", "uninspected": len(ids) - offset})
            break
        try:
            inspected = json.loads(command("docker", "container", "inspect", *batch, timeout=max(1, min(10, int(deadline-time.monotonic())))))
        except CollectionError:
            # One container can disappear between ls and inspect. Do not throw
            # away every other container; at most one bounded retry per ID.
            inspected = []
            for identifier in batch:
                if time.monotonic() >= deadline:
                    gaps.append({"reason": "inspect time budget exhausted"})
                    break
                try:
                    inspected.extend(json.loads(command("docker", "container", "inspect", identifier, timeout=3)))
                except CollectionError:
                    gaps.append({"id": identifier, "reason": "inspect unavailable or removed during collection"})
        for raw in inspected:
            cfg = raw.get("Config") or {}
            host = raw.get("HostConfig") or {}
            state = raw.get("State") or {}
            labels = cfg.get("Labels") or {}
            project = labels.get("com.docker.compose.project")
            service = labels.get("com.docker.compose.service")
            if project:
                compose.setdefault(project, {"name": project, "services": [], "relationship": "verified_label"})["services"].append(service)
            containers.append({"id": raw["Id"], "name": raw.get("Name", "").lstrip("/"), "image": cfg.get("Image"),
                               "image_id": raw.get("Image"), "state": state.get("Status"), "running": state.get("Running"),
                               "restart_count": raw.get("RestartCount", 0), "health": (state.get("Health") or {}).get("Status"),
                               "has_healthcheck": bool(cfg.get("Healthcheck")), "privileged": host.get("Privileged", False),
                               "network_mode": host.get("NetworkMode"), "user": cfg.get("User", ""), "readonly_rootfs": host.get("ReadonlyRootfs", False),
                               "cap_add": host.get("CapAdd") or [], "security_opt": host.get("SecurityOpt") or [],
                               "memory_limit": host.get("Memory", 0), "nano_cpus": host.get("NanoCpus", 0),
                               "mounts": [{"name": m.get("Name"), "source": m.get("Source"), "destination": m.get("Destination"), "rw": m.get("RW"),
                                           "type": m.get("Type")} for m in raw.get("Mounts", [])],
                               "ports": raw.get("NetworkSettings", {}).get("Ports", {}),
                               "networks": {name: {"ipv4": n.get("IPAddress"), "ipv6": n.get("GlobalIPv6Address"), "gateway": n.get("Gateway")}
                                            for name, n in raw.get("NetworkSettings", {}).get("Networks", {}).items()},
                               "compose_project": project, "compose_service": service,
                               "dependencies": _dependency_names(labels.get("com.docker.compose.depends_on", ""))})
    def json_lines(args: tuple[str, ...]) -> list[dict]:
        return [json.loads(line) for line in command("docker", *args, "--format", "{{json .}}").splitlines() if line]
    images = [{"id": x.get("ID"), "repository": x.get("Repository"), "tag": x.get("Tag"), "size": x.get("Size")}
              for x in json_lines(("image", "ls"))]
    volumes = [{"name": x.get("Name"), "driver": x.get("Driver"), "scope": x.get("Scope")}
               for x in json_lines(("volume", "ls"))]
    networks = [{"id": x.get("ID"), "name": x.get("Name"), "driver": x.get("Driver"), "scope": x.get("Scope")}
                for x in json_lines(("network", "ls"))]
    for project in compose.values():
        project["services"] = sorted({name for name in project["services"] if name})
    return {"available": True, "complete": not gaps and not truncated, "gaps": gaps, "truncated": truncated,
            "container_limit": MAX_CONTAINERS, "containers": containers, "images": images, "volumes": volumes,
            "networks": networks, "compose_projects": list(compose.values())}


def docker_events() -> dict:
    """Local broker hint only. Fixed recent window; do not return event labels.

    Overlap is intentional: refreshes are debounced in the node. Periodic full
    snapshots reconcile missed events after downtime; this is not an event log.
    """
    until = int(time.time())
    text = command("docker", "events", "--since", str(until - 30), "--until", str(until),
                   "--filter", "type=container", "--filter", "type=network", "--filter", "type=volume",
                   "--filter", "type=image", "--format", "{{json .}}", timeout=3)
    return {"changed": bool(text.strip()), "window_seconds": 30}


def gpu_inventory() -> dict:
    devices = []
    # Linux DRM sysfs is read-only and available without vendor SDKs or root.
    for card in sorted(Path("/sys/class/drm").glob("card[0-9]*")):
        if not re.fullmatch(r"card[0-9]+", card.name):
            continue
        device = card / "device"
        item = {"name": card.name, "source": "linux_drm_sysfs"}
        for field, filename in (("vendor_id", "vendor"), ("device_id", "device"),
                                ("vram_total_bytes", "mem_info_vram_total"), ("vram_used_bytes", "mem_info_vram_used")):
            try:
                value = (device / filename).read_text()[:128].strip()
                item[field] = int(value) if field.startswith("vram") else value
            except (OSError, ValueError):
                continue
        devices.append(item)
    nvidia = {"pci_devices": [], "status": "unverified", "devices": []}
    for device in sorted(Path("/sys/bus/pci/devices").glob("*"))[:1000]:
        try:
            if (device / "vendor").read_text().strip() == "0x10de" and (device / "class").read_text().strip().startswith("0x03"):
                nvidia["pci_devices"].append(device.name)
        except OSError:
            continue
    if shutil.which("nvidia-smi", path="/usr/sbin:/usr/bin:/sbin:/bin"):
        try:
            text = command("nvidia-smi", "--query-gpu=index,name,memory.total,memory.used,utilization.gpu", "--format=csv,noheader,nounits", timeout=3)
            for row in list(csv.reader(text.splitlines()))[:32]:
                if len(row) == 5:
                    nvidia["devices"].append({"index": row[0].strip(), "name": row[1].strip(), "memory_total_mib": row[2].strip(), "memory_used_mib": row[3].strip(), "utilization_percent": row[4].strip()})
            nvidia["status"] = "observed" if nvidia["devices"] else "no_devices_reported"
        except CollectionError:
            nvidia["status"] = "probe_failed"
    else:
        nvidia["status"] = "tool_unavailable"
    return {"devices": devices, "source": "linux_drm_sysfs", "nvidia": nvidia,
            "coverage": "DRM/PCI and optional bounded nvidia-smi read; missing observations do not prove no GPU"}


def caddy_endpoints(document: dict) -> list[dict]:
    """Extract only declarative listeners/host matchers from reviewed adapted JSON.

    No admin API, credentials, handler bodies, TLS keys or raw config returned.
    Configured endpoints are not network reachability/health evidence.
    """
    endpoints = []
    servers = ((document.get("apps") or {}).get("http") or {}).get("servers") or {}
    def hosts(routes, depth=0):
        if depth > 8:
            return set()
        names = set()
        for route in routes[:1000]:
            for match in route.get("match", [])[:100]:
                names.update(name for name in match.get("host", [])[:100] if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9*_.:-]{1,253}", name))
            for handler in route.get("handle", [])[:100]:
                names.update(hosts(handler.get("routes", []), depth+1))
        return names
    for name, server in list(servers.items())[:100]:
        listeners = [value for value in server.get("listen", [])[:100] if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:\[\]-]{1,256}", value)]
        endpoints.append({"server": str(name)[:128], "listen": listeners, "hosts": sorted(hosts(server.get("routes", []))),
                          "source": "reviewed_caddy_json", "relationship": "verified_configuration", "reachability": "unverified"})
    return endpoints


def firewall_inventory() -> dict:
    try:
        rules = json.loads(command("nft", "--json", "list", "ruleset"))
        # Rule AST can include log prefixes, but never fetch files or resolve secrets.
        return {"available": True, "backend": "nftables", "ruleset": rules, "effectiveness": "unverified"}
    except CollectionError:
        try:
            status = command("ufw", "status", "verbose")
            return {"available": True, "backend": "ufw", "status": status, "effectiveness": "unverified"}
        except CollectionError:
            return {"available": False, "backend": "unknown", "effectiveness": "unverified", "reason": "insufficient privileges or no supported tool"}



def storage_inventory() -> dict:
    result = {"mounts": [], "loops": [], "errors": [], "smart_tool_available": bool(shutil.which("smartctl")),
              "smart_health": "unverified"}
    for key, args in (("mounts", ("findmnt", "--json", "--list", "--output", "TARGET,SOURCE,FSTYPE")),
                      ("loops", ("losetup", "--json", "--output", "NAME,BACK-FILE,SIZELIMIT,RO"))):
        try:
            raw = json.loads(command(*args, timeout=5))
            result[key] = raw.get("filesystems" if key == "mounts" else "loopdevices", [])[:1000]
        except (CollectionError, ValueError):
            result["errors"].append({"collector": key, "reason": "read unavailable; not proof of no mounts/loopback"})
    return result


def update_inventory() -> dict:
    result = {"available": False, "reboot_required": Path("/run/reboot-required").exists(), "esm_updates": "unverified"}
    try:
        text = command("apt", "list", "--upgradable", timeout=10)
        lines = [line for line in text.splitlines() if "/" in line and "[upgradable from:" in line]
        result.update({"available": True, "upgradable_count": len(lines), "source": "local_apt_cache",
                       "cache_freshness": "unverified", "packages": [line.split("/", 1)[0] for line in lines[:200]], "truncated": len(lines) > 200})
    except CollectionError:
        result["reason"] = "apt local cache listing unavailable; no update/install attempted"
    return result

def discover(*, privileged: bool = False) -> dict[str, Any]:
    inventory: dict[str, Any] = {"schema_version": 1, "observed_at": datetime.now(timezone.utc).isoformat(), "errors": []}
    collectors = {"storage": storage_inventory, "updates": update_inventory, "os": _os, "hardware": _hardware, "packages": _packages, "interfaces": _interfaces,
                  "routes": _routes, "dns": _dns, "ports": _ports, "services": _services, "docker": docker_inventory if privileged else _docker,
                  "firewall": firewall_inventory if privileged else lambda: {"available": False, "effectiveness": "unverified", "reason": "broker required"},
                  "neighbors": lambda: json.loads(command("ip", "-j", "neigh", "show"))}
    for name, collector in collectors.items():
        try:
            inventory[name] = collector()
        except Exception as exc:
            inventory[name] = [] if name in {"packages", "interfaces", "ports", "services", "neighbors"} else {}
            inventory["errors"].append({"collector": name, "error": type(exc).__name__, "detail": str(exc)[:256]})
    inventory["addresses"] = [{"interface": item["name"], **address}
                              for item in inventory.get("interfaces", []) for address in item.get("addresses", [])
                              if address.get("family") in {"AF_INET", "AF_INET6"}]
    inventory["reverse_proxies"] = [{"name": x.get("name"), "evidence": "service_name", "confidence": "inferred"}
                                    for x in inventory.get("services", []) if re.search(r"nginx|caddy|traefik|haproxy|apache2", x.get("name", ""), re.I)]
    return inventory
