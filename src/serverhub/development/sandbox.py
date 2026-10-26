"""Fail-closed bubblewrap runner for untrusted repository code.

Only /usr and the workspace are visible. No host /etc, /home, /run, Docker socket,
controller credentials, or backups are mounted. Production runs as an unprivileged
worker; tests can construct a runner but cannot bypass sandboxing.
"""
from __future__ import annotations

import os
import resource
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .config import Command, DevelopmentError, Project


@dataclass(frozen=True)
class CommandResult:
    argv: list[str]
    returncode: int
    output: str
    timed_out: bool = False

    def as_dict(self) -> dict:
        return {"argv": self.argv, "returncode": self.returncode,
                "output": self.output, "timed_out": self.timed_out}


class SandboxRunner:
    def __init__(self, project: Project, *, binary: str | None = None) -> None:
        self.project = project
        self.binary = binary or shutil.which("bwrap")
        if not self.binary:
            raise DevelopmentError("bubblewrap is required; no unsandboxed fallback is available")

    def arguments(self, workspace: Path, command: Command, proxy_socket: Path | None = None) -> list[str]:
        if workspace.is_symlink() or not workspace.is_dir():
            raise DevelopmentError("workspace is missing or is a symlink")
        prefix=[]
        profile=Path("/etc/apparmor.d/serverhub-ai-build")
        restriction=Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        if profile.exists() and restriction.exists() and restriction.read_text().strip()=="1":
            aa_exec=shutil.which("aa-exec",path="/usr/bin:/bin")
            if not aa_exec:
                raise DevelopmentError("AppArmor development label requires aa-exec; reinstall the native prerequisites")
            prefix=[aa_exec,"-p","serverhub-ai-build","--"]
        args = [*prefix,self.binary, "--unshare-all", "--die-with-parent", "--new-session",
                "--cap-drop", "ALL", "--ro-bind", "/usr", "/usr",
                "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin",
                "--symlink", "usr/lib", "/lib"]
        if Path("/usr/lib64").exists():
            args += ["--symlink", "usr/lib64", "/lib64"]
        args += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                 "--dir", "/home", "--dir", "/home/build",
                 "--bind", str(workspace.resolve()), "/workspace",
                 "--ro-bind", str(workspace.resolve() / ".git"), "/workspace/.git",
                 "--chdir", "/workspace", "--clearenv",
                 "--setenv", "PATH", "/workspace/.venv/bin:/workspace/node_modules/.bin:/usr/bin:/bin",
                 "--setenv", "HOME", "/home/build", "--setenv", "LANG", "C.UTF-8",
                 "--setenv", "CI", "1"]
        if self.project.checks_path:
            args += ["--ro-bind", str(self.project.checks_path), "/checks"]
        if command.network:
            if not self.project.allow_dependency_network:
                raise DevelopmentError("network permission is not configured")
            if proxy_socket is None:
                raise DevelopmentError("Dependency network requires the isolated HTTPS gateway")
            args += ["--dir", "/run", "--ro-bind", str(proxy_socket), "/run/serverhub-egress.sock",
                     "--ro-bind", str(Path(__file__).with_name("proxy_bridge.py")), "/sandbox-net.py"]
            if Path("/etc/ssl/certs").exists():
                args += ["--dir", "/etc", "--dir", "/etc/ssl", "--ro-bind", "/etc/ssl/certs", "/etc/ssl/certs"]
            return args + ["--", "/usr/bin/python3", "-I", "/sandbox-net.py", *command.argv]
        return args + ["--", *command.argv]

    def run(self, workspace: Path, command: Command, *,
            heartbeat: Callable[[], None] | None = None) -> CommandResult:
        from contextlib import ExitStack
        from .egress import gateway
        with ExitStack() as stack:
            proxy_socket = None
            if command.network:
                if not self.project.allow_dependency_network:
                    raise DevelopmentError("network permission is not configured")
                temporary = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="serverhub-egress-")))
                proxy_socket = stack.enter_context(gateway(temporary, self.project, command.timeout))
            return self._run(workspace, command, proxy_socket, heartbeat)

    def _run(self, workspace, command, proxy_socket, heartbeat):
        args = self.arguments(workspace, command, proxy_socket)
        memory_limit = self.project.max_memory_mb * 1024 * 1024
        process_limit = self.project.max_processes
        def limits() -> None:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
            resource.setrlimit(resource.RLIMIT_NPROC, (process_limit, process_limit))
            resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024**2, 256 * 1024**2))
            resource.setrlimit(resource.RLIMIT_CPU, (command.timeout, command.timeout + 1))
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=output,
                                       stderr=subprocess.STDOUT, env={"PATH": "/usr/bin:/bin"},
                                       start_new_session=True, preexec_fn=limits)
            import time
            deadline = time.monotonic() + command.timeout
            timed_out = False
            try:
                while process.poll() is None:
                    if heartbeat:
                        heartbeat()
                    if time.monotonic() >= deadline:
                        timed_out = True
                        os.killpg(process.pid, signal.SIGKILL)
                        break
                    try:
                        process.wait(timeout=min(1, max(.01, deadline - time.monotonic())))
                    except subprocess.TimeoutExpired:
                        pass
                process.wait(timeout=5)
            except BaseException:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                raise
            size = output.seek(0, os.SEEK_END)
            output.seek(max(0, size - 65536))
            content = output.read().decode("utf-8", errors="replace")
            if size > 65536:
                content = "[output truncated to last 64 KiB]\n" + content
            return CommandResult(list(command.argv), process.returncode or 0, content, timed_out)

    def preflight(self, workspace: Path) -> dict:
        """Create a job-local Python environment inside bubblewrap, never on the host.

        Ubuntu 24.04 does not provide a bare 'python' executable by default,
        and system pip is externally managed. Root-registered projects using
        'python -m pip' must resolve to an isolated, writable venv instead.
        """
        venv = workspace / ".venv"
        if venv.is_symlink() or (venv.exists() and not venv.is_dir()):
            raise DevelopmentError("project virtualenv path must be a real directory")
        tools = self.run(workspace, Command(argv=["/usr/bin/python3", "-I", "-c",
            "import importlib.util,json,ssl,sys; "
            "venv_available=importlib.util.find_spec('venv') is not None; "
            "print(json.dumps({'python':sys.version.split()[0],'venv_available':venv_available,'sandbox':True})); "
            "sys.exit(0 if venv_available else 78)"], timeout=10))
        if tools.returncode != 0 or tools.timed_out:
            return {"available": False, "returncode": tools.returncode,
                    "detail": tools.output, "remediation": "Install python3-venv, bubblewrap and the AI AppArmor profile through reviewed native repair; never use a production virtualenv", "unsandboxed_fallback": False}
        if not venv.exists():
            setup = self.run(workspace, Command(
                argv=["/usr/bin/python3", "-m", "venv", "/workspace/.venv"], timeout=45))
            if setup.returncode != 0 or setup.timed_out:
                return {"available": False, "returncode": setup.returncode,
                        "detail": setup.output, "remediation": "Repair isolated python3-venv prerequisites; never install into system Python or run outside bubblewrap", "unsandboxed_fallback": False}
        # Validate the executable *inside* the sandbox, not just on the host.
        result = self.run(workspace, Command(argv=["/workspace/.venv/bin/python", "-m",
            "pip", "--version"], timeout=10))
        return {"available": result.returncode == 0 and not result.timed_out,
                "returncode": result.returncode, "detail": tools.output + result.output,
                "remediation": "Repair the job-local virtualenv inside the isolated workspace; no unsandboxed fallback is permitted",
                "unsandboxed_fallback": False}
