from __future__ import annotations

import json
import os
import re
import resource
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .core import SwarmError, redact, run_command, validate_contract


@dataclass(frozen=True)
class ResourceLimits:
    cpu_seconds: int = 45
    memory_bytes: int = 2_147_483_648
    timeout_seconds: int = 180
    max_log_bytes: int = 256_000
    max_concurrent_jobs: int = 1


def measure_resources() -> dict[str, Any]:
    meminfo = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, value = line.split(":", 1)
            meminfo[key] = int(value.strip().split()[0]) * 1024
    except (OSError, ValueError):
        meminfo = {}
    disk = shutil.disk_usage(Path.cwd())
    return {
        "cpu_count": os.cpu_count() or 1,
        "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None,
        "memory_total_bytes": meminfo.get("MemTotal"),
        "memory_available_bytes": meminfo.get("MemAvailable"),
        "disk_free_bytes": disk.free,
    }


def select_limits(resources: dict[str, Any]) -> ResourceLimits:
    available = resources.get("memory_available_bytes") or 1_073_741_824
    # Aggregate cgroup memory, not per-process virtual address space. Start at
    # 2 GiB; the real fixture run is the gate for whether this is sufficient.
    memory = min(2_147_483_648, max(536_870_912, available // 4))
    return ResourceLimits(memory_bytes=memory)


def _limited_preexec(limits: ResourceLimits):
    def apply():
        resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
    return apply


_BLOCKED_ENV_TERMS = (
    "secret", "token", "password", "credential", "api_key", "apikey", "authorization",
    "database_url", "postgres", "mysql", "redis", "woocommerce", "distributor", "gunbroker",
    "n8n", "docker", "production", "payment", "order", "customer", "aws_access", "private_key",
)


def _safe_agent_environment(env: dict[str, str] | None = None) -> dict[str, str]:
    """Keep process basics while excluding production and credential-like variables."""
    safe = {}
    for key, value in os.environ.items():
        lowered = key.lower()
        if any(term in lowered for term in _BLOCKED_ENV_TERMS):
            continue
        safe[key] = value
    safe.update(env or {})
    safe["SWARM_NETWORK_BLOCKED"] = "1"
    safe["NO_PROXY"] = "*"
    safe.pop("HTTP_PROXY", None)
    safe.pop("HTTPS_PROXY", None)
    safe.pop("ALL_PROXY", None)
    safe.update(_user_systemd_bus_environment())
    return safe


def _minimal_test_environment(env: dict[str, str] | None = None) -> dict[str, str]:
    """Build the deterministic test environment from an explicit allowlist."""
    allowed = {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "LC_ALL") if key in os.environ}
    allowed.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"})
    allowed.update(env or {})
    allowed["SWARM_NETWORK_BLOCKED"] = "1"
    allowed.pop("HTTP_PROXY", None)
    allowed.pop("HTTPS_PROXY", None)
    allowed.pop("ALL_PROXY", None)
    allowed.update(_user_systemd_bus_environment())
    return allowed


def _user_systemd_bus_environment() -> dict[str, str]:
    """Expose only the derived user-bus variables when a real socket exists."""
    uid = os.getuid()
    runtime_dir = Path("/run/user") / str(uid)
    bus = runtime_dir / "bus"
    if runtime_dir.is_dir() and bus.is_socket():
        return {
            "XDG_RUNTIME_DIR": str(runtime_dir),
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}",
        }
    return {}


def _codex_environment(env: dict[str, str] | None = None, pycache_dir: Path | None = None) -> dict[str, str]:
    """Pass only Codex runtime/authentication variables; never log values."""
    allowed_names = {
        "PATH", "HOME", "LANG", "LC_ALL", "TERM", "CODEX_HOME",
        "OPENAI_API_KEY", "OPENAI_BASE_URL",
    }
    result = {key: os.environ[key] for key in allowed_names if key in os.environ}
    result.update(_user_systemd_bus_environment())
    result.update(env or {})
    result["PYTHONDONTWRITEBYTECODE"] = "1"
    result["PYTHONNOUSERSITE"] = "1"
    if pycache_dir is not None:
        result["PYTHONPYCACHEPREFIX"] = str(pycache_dir)
    result["PYTEST_ADDOPTS"] = "-p no:cacheprovider"
    result["SWARM_NETWORK_BLOCKED"] = "1"
    result.pop("HTTP_PROXY", None)
    result.pop("HTTPS_PROXY", None)
    result.pop("ALL_PROXY", None)
    return result


_last_cgroup_peak_bytes = 0


def last_cgroup_peak_bytes() -> int:
    return _last_cgroup_peak_bytes


def limited_run(command: list[str], cwd: Path, prompt: str, limits: ResourceLimits, env: dict[str, str] | None = None, use_cgroup: bool = False, minimal_environment: bool = False, environment_builder=None) -> subprocess.CompletedProcess[str]:
    child_env = environment_builder(env) if environment_builder else (_minimal_test_environment(env) if minimal_environment else _safe_agent_environment(env))
    global _last_cgroup_peak_bytes
    cgroup_path: Path | None = None
    wrapped_command = list(command)
    if use_cgroup:
        systemd_run = shutil.which("systemd-run")
        if systemd_run:
            wrapped_command = [
                systemd_run, "--user", "--scope", "--quiet",
                "-p", f"MemoryMax={limits.memory_bytes}",
                "-p", "MemorySwapMax=0",
                "-p", "IPAddressDeny=any",
                "--", *command,
            ]
        else:
            cgroup_root = Path(os.environ.get("SWARM_CGROUP_ROOT", "/sys/fs/cgroup"))
            if not (cgroup_root / "cgroup.controllers").exists():
                raise SwarmError("cgroup v2 is required for aggregate agent memory limits")
            cgroup_path = cgroup_root / f"hermes-swarm-{os.getpid()}-{time.time_ns()}"
            try:
                cgroup_path.mkdir()
                (cgroup_path / "memory.max").write_text(str(limits.memory_bytes), encoding="ascii")
                if (cgroup_path / "memory.swap.max").exists():
                    (cgroup_path / "memory.swap.max").write_text("0", encoding="ascii")
            except OSError as exc:
                raise SwarmError(f"cannot create writable aggregate cgroup at {cgroup_root}: {exc}") from exc
    try:
        process = subprocess.Popen(
            wrapped_command,
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=child_env,
            preexec_fn=_limited_preexec(limits),
        )
        if cgroup_path is not None:
            try:
                (cgroup_path / "cgroup.procs").write_text(str(process.pid), encoding="ascii")
            except OSError as exc:
                process.kill()
                process.wait()
                raise SwarmError(f"cannot place agent process in aggregate cgroup: {exc}") from exc
        try:
            stdout, stderr = process.communicate(prompt, timeout=limits.timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            stdout, stderr = process.communicate()
            raise SwarmError(f"agent timed out after {limits.timeout_seconds}s: {command[0]}") from exc
        result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    finally:
        if cgroup_path is not None:
            try:
                peak = int((cgroup_path / "memory.peak").read_text(encoding="ascii").strip())
                _last_cgroup_peak_bytes = max(_last_cgroup_peak_bytes, peak)
            except (OSError, ValueError):
                pass
            try:
                (cgroup_path / "cgroup.kill").write_text("1", encoding="ascii")
            except OSError:
                pass
            try:
                cgroup_path.rmdir()
            except OSError:
                pass
    result.stdout = result.stdout[-limits.max_log_bytes:]
    result.stderr = result.stderr[-limits.max_log_bytes:]
    return result


def discover_commands() -> dict[str, Any]:
    commands = {}
    for name in ("hermes", "codex", "agy"):
        path = shutil.which(name)
        commands[name] = {"path": path}
        if path:
            commands[name]["version"] = run_command([path, "--version"], Path.cwd(), timeout=15).stdout.strip()
    return commands


def _codex_cli_schema(schema: Path) -> dict[str, Any]:
    """Remove JSON-Schema keywords unsupported by Codex response_format."""
    value = json.loads(schema.read_text(encoding="utf-8"))
    if isinstance(value, dict):
        return {key: _codex_cli_schema_value(item) for key, item in value.items() if key != "uniqueItems"}
    raise SwarmError("Codex schema must be a JSON object")


def _codex_cli_schema_value(value: Any) -> Any:
    if isinstance(value, dict):
        projected = {key: _codex_cli_schema_value(item) for key, item in value.items() if key != "uniqueItems"}
        if projected.get("type") == "object":
            projected.setdefault("additionalProperties", False)
        return projected
    if isinstance(value, list):
        return [_codex_cli_schema_value(item) for item in value]
    return value


def new_codex_job_id() -> str:
    """Generate one canonical, immutable ID for a Codex invocation."""
    return f"codex-writer-{uuid.uuid4().hex}"


def _job_id_filename(job_id: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{7,127}", job_id):
        raise SwarmError("Codex job ID is not canonical")
    return job_id


def _codex_job_schema(schema: Path, job_id: str) -> dict[str, Any]:
    value = _codex_cli_schema(schema)
    value.setdefault("properties", {}).setdefault("job_id", {})["const"] = job_id
    return value


class HermesAdapter:
    """Uses Hermes' non-mutating prompt path as the local orchestration contract."""

    def __init__(self, state_dir: Path, executable: str = "/home/jeff/.local/bin/hermes"):
        self.state_dir = state_dir
        self.executable = executable

    def prepare(self, job_id: str, evidence: str) -> str:
        if not Path(self.executable).exists():
            raise SwarmError(f"Hermes executable not found: {self.executable}")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        result = run_command([self.executable, "--print-prompt"], self.state_dir, timeout=30)
        if result.returncode:
            raise SwarmError(f"Hermes prompt probe failed: {redact(result.stderr)}")
        prompt = result.stdout
        (self.state_dir / "hermes-orchestration-prompt.txt").write_text(prompt, encoding="utf-8")
        return f"Hermes prepared local job {job_id}. Evidence: {redact(evidence)}"


class CodexAdapter:
    def __init__(self, schema: Path, limits: ResourceLimits, executable: str = "/home/jeff/.local/bin/codex"):
        self.schema = schema
        self.limits = limits
        self.executable = executable
        self.last_invocation: dict[str, Any] = {}
        self.last_cache_directory: Path | None = None

    def run(self, worktree: Path, job_id: str, prompt: str, git_metadata: Path | None = None) -> dict[str, Any]:
        canonical_job_id = _job_id_filename(job_id)
        cache_dir = Path("/home/jeff/hermes-swarm-runtime/python-cache") / canonical_job_id
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_dir.chmod(0o700)
        self.last_cache_directory = cache_dir
        result_dir = worktree / ".swarm"
        result_dir.mkdir(exist_ok=True)
        output = result_dir / f"codex-result-{canonical_job_id}.json"
        fd, output_name = tempfile.mkstemp(prefix=f"swarm-codex-result-{canonical_job_id}-", suffix=".json")
        os.close(fd)
        external_output = Path(output_name)
        schema_copy = result_dir / f"codex-result-{canonical_job_id}.schema.json"
        schema_copy.write_text(json.dumps(_codex_job_schema(self.schema, canonical_job_id)), encoding="utf-8")
        canonical_prompt = (
            f"RETURN JOB_ID EXACTLY AS SUPPLIED: {canonical_job_id}. "
            "Do not shorten, rewrite, or derive it.\n\n" + prompt
        )
        command = [self.executable, "--ask-for-approval", "never", "exec", "--ephemeral", "--sandbox", "workspace-write", "--skip-git-repo-check", "--cd", str(worktree)]
        if git_metadata:
            command.extend(["--add-dir", str(git_metadata)])
        command.extend(["--output-schema", str(schema_copy), "--output-last-message", str(external_output), "--color", "never", "--json", canonical_prompt])
        try:
            result = limited_run(command, worktree, "", self.limits, {"SWARM_ROLE": "CODEX_WRITER", "SWARM_DRY_RUN": "1"}, use_cgroup=True, environment_builder=lambda values: _codex_environment(values, cache_dir))
            self.last_invocation = {
                "executable": self.executable,
                "argv": command[:-1] + ["<prompt-argument>"],
                "working_directory": str(worktree),
                "environment_names": sorted(_codex_environment({"SWARM_ROLE": "CODEX_WRITER", "SWARM_DRY_RUN": "1"}, cache_dir)),
                "pycache_directory": str(cache_dir),
                "exit_code": result.returncode,
                "stdout": redact(result.stdout),
                "stderr": redact(result.stderr),
            }
            if result.returncode:
                raise SwarmError(f"Codex failed ({result.returncode}): {redact(result.stderr + result.stdout)}")
            if not external_output.exists() or not external_output.read_text(encoding="utf-8").strip():
                raise SwarmError("Codex did not write its schema-constrained result; output: " + redact(result.stdout + result.stderr))
            payload = json.loads(external_output.read_text(encoding="utf-8"))
            output.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            self.last_invocation["final_response"] = redact(json.dumps(payload, sort_keys=True))
        finally:
            external_output.unlink(missing_ok=True)
            shutil.rmtree(cache_dir, ignore_errors=True)
        validate_contract(payload, "codex", expected_job_id=canonical_job_id)
        return payload


class GeminiAdapter:
    def __init__(self, schema: Path, limits: ResourceLimits, executable: str = "/home/jeff/.local/bin/agy"):
        self.schema = schema
        self.limits = limits
        self.executable = executable

    def run(self, snapshot: Path, job_id: str, commit: str, prompt: str) -> dict[str, Any]:
        result_dir = snapshot / ".swarm"
        result_dir.mkdir(exist_ok=True)
        output = result_dir / "gemini-review.json"
        command = [self.executable, "--prompt", prompt, "--mode", "plan", "--sandbox", "--print-timeout", f"{self.limits.timeout_seconds}s"]
        result = limited_run(command, snapshot, prompt, self.limits, {"SWARM_ROLE": "GEMINI_READ_ONLY", "SWARM_DRY_RUN": "1", "SWARM_REVIEWED_COMMIT": commit}, use_cgroup=True)
        if result.returncode:
            raise SwarmError(f"Gemini failed ({result.returncode}): {redact(result.stderr + result.stdout)}")
        payload = self._extract_json(result.stdout)
        output.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        try:
            validate_contract(payload, "gemini")
        except SwarmError as exc:
            raise SwarmError(f"{exc}; Gemini payload: {redact(json.dumps(payload))}") from exc
        if payload["job_id"] != job_id:
            raise SwarmError("Gemini review is stale or bound to a different job")
        from .core import require_exact_commit
        require_exact_commit(commit, payload["reviewed_commit"])
        return payload

    @staticmethod
    def _extract_json(output: str) -> dict[str, Any]:
        try:
            value = json.loads(output)
            if isinstance(value, dict) and all(key in value for key in ("job_id", "reviewed_commit", "verdict")):
                return value
            if isinstance(value, dict) and isinstance(value.get("response"), str):
                return json.loads(value["response"])
        except json.JSONDecodeError:
            pass
        start, end = output.find("{"), output.rfind("}")
        if start >= 0 and end > start:
            return json.loads(output[start:end + 1])
        raise SwarmError("Gemini did not return a JSON review")
