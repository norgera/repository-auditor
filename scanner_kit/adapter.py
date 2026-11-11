"""The interface each scanner implements, and the limited tool runner it receives."""
import fnmatch
import os
import shutil
import signal
import subprocess
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import List, Optional


class ToolMissing(Exception):
    pass


class ToolTimeout(Exception):
    pass


class ToolFailed(Exception):
    """The tool ran but did not produce a usable result."""


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    location: str
    message: str
    remediation: Optional[str] = None


@dataclass
class Result:
    status: str = "complete"
    findings: List[Finding] = field(default_factory=list)
    message: str = ""
    secrets: List[str] = field(default_factory=list)  # values that must not appear in the response


@dataclass
class Completed:
    code: int
    stdout: str
    stderr: str


def _limits():
    try:
        import resource
        cpu = int(os.environ.get("SCAN_CPU_SECONDS", "30"))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    except (ImportError, ValueError, OSError):
        pass


@dataclass
class Context:
    workspace: str
    files: List[str]
    options: dict
    time_limit: float

    def run(self, cmd):
        """Run a tool inside the workspace with a time limit. Its whole process group dies on timeout."""
        if shutil.which(cmd[0]) is None:
            raise ToolMissing(cmd[0])
        env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "TMPDIR", "TRIVY_CACHE_DIR")}
        proc = subprocess.Popen(cmd, cwd=self.workspace, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, errors="replace", start_new_session=True, preexec_fn=_limits)
        try:
            out, err = proc.communicate(timeout=self.time_limit)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.communicate()
            raise ToolTimeout(cmd[0])
        return Completed(proc.returncode, out, err)

    def rel(self, path):
        """Strip any workspace prefix so that only repository-relative names are reported."""
        path = str(path)
        real = os.path.realpath(self.workspace)
        for prefix in (self.workspace, real):
            if path.startswith(prefix):
                return path[len(prefix):].lstrip("/")
        return path[2:] if path.startswith("./") else path


class Adapter:
    id = ""
    name = ""
    description = ""
    capabilities: List[str] = []
    tool: Optional[str] = None
    version_args: List[str] = ["--version"]
    accepts_patterns: List[str] = ["*"]
    input_mode = "files"
    max_bytes = 5 * 1024 * 1024
    max_files = 200

    def accepts(self, rel_path):
        name = PurePosixPath(rel_path).name
        return any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(rel_path, p) for p in self.accepts_patterns)

    def scan(self, ctx: Context) -> Result:
        raise NotImplementedError

    def tool_version(self):
        if not self.tool or shutil.which(self.tool) is None:
            return None
        try:
            out = subprocess.run([self.tool, *self.version_args], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            return None
        lines = (out.stdout or out.stderr).strip().splitlines()
        return lines[0][:80] if lines else None
