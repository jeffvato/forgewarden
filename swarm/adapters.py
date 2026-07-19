from __future__ import annotations

import json
import os
import resource
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .core import SwarmError, redact, run_command, validate_contract


@dataclass(frozen=True)
class ResourceLimits:
    cpu_seconds: int = 45
    memory_bytes: int = 1_073_741_824
    timeout_seconds: int = 90
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
    # Node/V8-based local CLIs reserve virtual address space before the model
    # starts. Keep a hard cap, but leave enough headroom for their runtime.
    memory = min(12_884_901_888, max(1_073_741_824, (available * 85) // 100))
    return ResourceLimits(memory_bytes=memory)


def _limited_preexec(limits: ResourceLimits):
    def apply():
        resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
    return apply


def limited_run(command: list[str], cwd: Path, prompt: str, limits: ResourceLimits, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    child_env = os.environ.copy()
    child_env.update(env or {})
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            input=prompt,
            text=True,
            capture_output=True,
            timeout=limits.timeout_seconds,
            env=child_env,
            preexec_fn=_limited_preexec(limits),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SwarmError(f"agent timed out after {limits.timeout_seconds}s: {command[0]}") from exc
    result.stdout = result.stdout[-limits.max_log_bytes:]
    result.stderr = result.stderr[-limits.max_log_bytes:]
    return result


def discover_commands() -> dict[str, Any]:
    commands = {}
    for name in ("hermes", "codex", "gemini"):
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

    def run(self, worktree: Path, job_id: str, prompt: str) -> dict[str, Any]:
        result_dir = worktree / ".swarm"
        result_dir.mkdir(exist_ok=True)
        output = result_dir / "codex-result.json"
        fd, output_name = tempfile.mkstemp(prefix="swarm-codex-result-", suffix=".json")
        os.close(fd)
        external_output = Path(output_name)
        schema_copy = result_dir / "codex-result.schema.json"
        schema_copy.write_text(json.dumps(_codex_cli_schema(self.schema)), encoding="utf-8")
        command = [self.executable, "exec", "--ephemeral", "--sandbox", "workspace-write", "--skip-git-repo-check", "--cd", str(worktree), "--output-schema", str(schema_copy), "--output-last-message", str(external_output), "--color", "never", "--json", prompt]
        try:
            result = limited_run(command, worktree, "", self.limits, {"SWARM_ROLE": "CODEX_WRITER", "SWARM_DRY_RUN": "1"})
            if result.returncode:
                raise SwarmError(f"Codex failed ({result.returncode}): {redact(result.stderr + result.stdout)}")
            if not external_output.exists() or not external_output.read_text(encoding="utf-8").strip():
                raise SwarmError("Codex did not write its schema-constrained result; output: " + redact(result.stdout + result.stderr))
            payload = json.loads(external_output.read_text(encoding="utf-8"))
            output.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        finally:
            external_output.unlink(missing_ok=True)
        validate_contract(payload, "codex")
        if payload["job_id"] != job_id:
            raise SwarmError("Codex result job ID mismatch")
        return payload


class GeminiAdapter:
    def __init__(self, schema: Path, limits: ResourceLimits, executable: str = "/home/jeff/.nvm/versions/node/v24.11.1/bin/gemini"):
        self.schema = schema
        self.limits = limits
        self.executable = executable

    def run(self, snapshot: Path, job_id: str, commit: str, prompt: str) -> dict[str, Any]:
        result_dir = snapshot / ".swarm"
        result_dir.mkdir(exist_ok=True)
        output = result_dir / "gemini-review.json"
        command = [self.executable, "--prompt", prompt, "--approval-mode", "plan", "--sandbox", "--output-format", "json", "--skip-trust"]
        result = limited_run(command, snapshot, prompt, self.limits, {"SWARM_ROLE": "GEMINI_READ_ONLY", "SWARM_DRY_RUN": "1", "SWARM_REVIEWED_COMMIT": commit})
        if result.returncode:
            raise SwarmError(f"Gemini failed ({result.returncode}): {redact(result.stderr + result.stdout)}")
        payload = self._extract_json(result.stdout)
        output.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        validate_contract(payload, "gemini")
        if payload["job_id"] != job_id or payload["reviewed_commit"].lower() != commit.lower():
            raise SwarmError("Gemini review is stale or bound to a different commit")
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
