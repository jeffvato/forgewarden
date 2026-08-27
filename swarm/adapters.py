import json
import hashlib
import os
import re
import resource
import shutil
import shlex
import subprocess
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .core import (
    SwarmError,
    ensure_mailbox_directory,
    ensure_private_directory,
    read_restricted_bytes,
    redact,
    run_command,
    validate_contract,
    write_mailbox_json,
    write_restricted_text,
)
from .paths import runtime_root


@dataclass(frozen=True)
class WriterInvocationSpec:
    job_id: str
    git_root: Path
    codex_cwd: Path
    codex_relative_target: str
    git_relative_target: str
    expected_behavior: str
    failing_assertion: str
    writable_git_paths: tuple[str, ...]

    def target(self, seeded_hash: str | None = None) -> Path:
        if not self.codex_cwd.is_dir():
            raise SwarmError("Codex CWD does not exist")
        codex_target = self.codex_cwd / self.codex_relative_target
        git_target = self.git_root / self.git_relative_target
        if codex_target.is_symlink() or not codex_target.is_file():
            raise SwarmError("Codex target is not a regular file")
        try:
            resolved_cwd = self.codex_cwd.resolve()
            resolved_codex = codex_target.resolve()
            resolved_git = git_target.resolve()
            resolved_cwd.relative_to(self.git_root.resolve())
            resolved_codex.relative_to(self.git_root.resolve())
        except ValueError as exc:
            raise SwarmError("Codex target escaped the Git worktree") from exc
        if git_target.is_symlink() or not git_target.is_file():
            raise SwarmError("Git-root target is not a regular file")
        if resolved_codex != resolved_git:
            raise SwarmError("Codex and Git target paths do not resolve identically")
        if seeded_hash is not None:
            import hashlib
            if hashlib.sha256(resolved_git.read_bytes()).hexdigest() != seeded_hash:
                raise SwarmError("seeded target hash mismatch")
        return resolved_git

    def prompt(self) -> str:
        return (
            f"Work only in Git root {self.git_root}. Your actual CWD is {self.codex_cwd}. "
            f"The exact canonical job ID is {self.job_id}. The only writable source path is "
            f"{self.codex_relative_target} relative to your CWD, corresponding to "
            f"{self.git_relative_target} relative to Git root. Expected behavior: {self.expected_behavior}. "
            f"The sanitized failing assertion is: {self.failing_assertion}. Make the smallest source correction. "
            "Do not modify or create tests. Do not write Git metadata, stage files, create commits, remotes, or pushes."
        )


@dataclass
class CodexRunEvidence:
    job_id: str
    codex_version: str
    sanitized_argv: list[str]
    actual_cwd: str
    environment_variable_names: list[str]
    prompt_hash: str
    sanitized_prompt: str
    target_canonical_path: str
    target_pre_hash: str | None = None
    target_post_hash: str | None = None
    codex_exit_code: int | None = None
    jsonl_event_types: list[str] = field(default_factory=list)
    tool_commands: list[dict[str, Any]] = field(default_factory=list)
    sandbox_write_denials: list[str] = field(default_factory=list)
    schema_validation: str = "NOT_RUN"
    sanitized_final_response: str = "[MISSING_FINAL_RESPONSE]"
    claimed_changed_files: list[str] | None = None
    actual_normalized_changed_paths: list[str] | None = None
    persisted_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _codex_version(executable: str) -> str:
    result = run_command([executable, "--version"], Path.cwd(), timeout=15)
    return redact(result.stdout.strip() or result.stderr.strip())[:200] if result.returncode == 0 else "UNAVAILABLE"


def _jsonl_telemetry(stdout: str) -> tuple[list[str], list[dict[str, Any]], list[str]]:
    event_types: list[str] = []
    commands: list[dict[str, Any]] = []
    denials: list[str] = []
    denial_terms = re.compile(r"(?i)(permission denied|operation not permitted|read-only|sandbox|write.*denied|cannot write|index\.lock)")
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        event_type = event.get("type")
        if isinstance(event_type, str):
            event_types.append(event_type)
        item = event.get("item") if isinstance(event.get("item"), dict) else {}
        if item.get("type") == "command_execution":
            raw_command = str(item.get("command", ""))
            try:
                command_name = shlex.split(raw_command)[0] if shlex.split(raw_command) else ""
            except ValueError:
                command_name = raw_command.split(maxsplit=1)[0] if raw_command else ""
            commands.append({"name": redact(command_name)[:160], "exit_code": item.get("exit_code"), "status": redact(str(item.get("status", "")))[:80]})
        candidates = [item.get("message"), item.get("aggregated_output"), event.get("error")]
        for candidate in candidates:
            text = redact(str(candidate))[:512] if candidate is not None else ""
            if text and denial_terms.search(text):
                denials.append(text)
    return event_types, commands, denials


def normalize_changed_paths(spec: WriterInvocationSpec, paths: list[str]) -> list[str]:
    normalized: list[str] = []
    for raw in paths:
        path = Path(raw)
        if path.is_absolute() or "\\" in raw or any(part in {"", ".", ".."} for part in path.parts):
            raise SwarmError(f"unsafe Codex changed path: {raw}")
        candidate = spec.codex_cwd / path
        if candidate.is_symlink() or not candidate.exists():
            raise SwarmError(f"Codex changed path is missing or symlinked: {raw}")
        try:
            canonical = candidate.resolve().relative_to(spec.git_root.resolve()).as_posix()
        except ValueError as exc:
            raise SwarmError(f"Codex changed path escaped Git root: {raw}") from exc
        if canonical not in spec.writable_git_paths:
            raise SwarmError(f"Codex changed path outside scope: {canonical}")
        if canonical in normalized:
            raise SwarmError(f"duplicate Codex changed path: {canonical}")
        normalized.append(canonical)
    return normalized


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
    "gemini_api", "google_api", "anthropic_api", "hf_token", "huggingface", "github_token",
    "gh_token", "slack", "telegram", "oauth", "client_id", "client_secret",
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


def limited_run(command: list[str], cwd: Path, prompt: str, limits: ResourceLimits, env: dict[str, str] | None = None, use_cgroup: bool = False, minimal_environment: bool = False, environment_builder=None, network_isolated: bool = True) -> subprocess.CompletedProcess[str]:
    child_env = environment_builder(env) if environment_builder else (_minimal_test_environment(env) if minimal_environment else _safe_agent_environment(env))
    global _last_cgroup_peak_bytes
    cgroup_path: Path | None = None
    wrapped_command = list(command)
    if use_cgroup:
        systemd_run = shutil.which("systemd-run")
        if not systemd_run:
            raise SwarmError("systemd-run user scope is required for network-isolated execution")
        wrapped_command = [
            systemd_run, "--user", "--scope", "--quiet",
            "-p", f"MemoryMax={limits.memory_bytes}",
            "-p", "MemorySwapMax=0",
        ]
        if network_isolated:
            wrapped_command.extend(("-p", "IPAddressDeny=any"))
        wrapped_command.extend(("--", *command))
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
    value = json.loads(read_restricted_bytes(schema, "Codex schema"))
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
        ensure_private_directory(self.state_dir, "Hermes adapter state directory")
        result = run_command([self.executable, "--print-prompt"], self.state_dir, timeout=30)
        if result.returncode:
            raise SwarmError(f"Hermes prompt probe failed: {redact(result.stderr)}")
        prompt = result.stdout
        write_restricted_text(self.state_dir / "hermes-orchestration-prompt.txt", prompt, "Hermes orchestration prompt")
        return f"Hermes prepared local job {job_id}. Evidence: {redact(evidence)}"


class CodexAdapter:
    def __init__(self, schema: Path, limits: ResourceLimits, executable: str = "/home/jeff/.local/bin/codex", evidence_dir: Path | None = None):
        self.schema = schema
        self.limits = limits
        self.executable = executable
        self.evidence_dir = evidence_dir
        self.last_invocation: dict[str, Any] = {}
        self.last_evidence: CodexRunEvidence | None = None
        self.last_cache_directory: Path | None = None

    def persist_evidence(self) -> Path | None:
        if self.last_evidence is None or self.evidence_dir is None:
            return None
        path = self.evidence_dir / f"{self.last_evidence.job_id}.json"
        self.last_evidence.persisted_path = str(path)
        write_restricted_text(path, json.dumps(self.last_evidence.to_dict(), sort_keys=True), "Codex telemetry evidence")
        return path

    def record_actual_paths(self, paths: list[str]) -> None:
        if self.last_evidence is None:
            raise SwarmError("Codex telemetry is unavailable")
        self.last_evidence.actual_normalized_changed_paths = list(paths)
        self.persist_evidence()

    @staticmethod
    def _remove_unknown_option(command: list[str], stderr: str) -> list[str] | None:
        """Drop one harmless compatibility flag rejected by an older Codex CLI."""
        match = re.search(r"(?:unknown option|unexpected argument|unrecognized option|invalid option)[^\n]*(--[A-Za-z0-9-]+)", stderr, re.IGNORECASE)
        if not match:
            return None
        option = match.group(1)
        # These flags only control CLI presentation or local safety routing;
        # removing one lets the bounded worker use an older installed CLI.
        value_options = {"--output-schema", "--output-last-message", "--color"}
        removable = {"--approve-for-me", "--skip-git-repo-check", "--json"} | value_options
        if option not in removable or option not in command:
            return None
        index = command.index(option)
        end = index + 2 if option in value_options else index + 1
        if end > len(command) or (option in value_options and command[index + 1].startswith("--")):
            return None
        return command[:index] + command[end:]

    def run(self, spec: WriterInvocationSpec, prompt: str | None = None) -> dict[str, Any]:
        canonical_job_id = _job_id_filename(spec.job_id)
        target = spec.target()
        worktree = spec.git_root
        cache_dir = ensure_private_directory(runtime_root() / "python-cache" / canonical_job_id, "Codex Python cache directory")
        self.last_cache_directory = cache_dir
        result_dir = ensure_mailbox_directory(worktree / ".swarm")
        output = result_dir / f"codex-result-{canonical_job_id}.json"
        fd, output_name = tempfile.mkstemp(prefix=f"swarm-codex-result-{canonical_job_id}-", suffix=".json")
        os.close(fd)
        external_output = Path(output_name)
        schema_copy = result_dir / f"codex-result-{canonical_job_id}.schema.json"
        write_mailbox_json(schema_copy, _codex_job_schema(self.schema, canonical_job_id), "Codex schema")
        canonical_prompt = (
            f"RETURN JOB_ID EXACTLY AS SUPPLIED: {canonical_job_id}. Do not shorten, rewrite, or derive it.\n\n"
            + (prompt or spec.prompt())
        )
        # The installed Codex CLI no longer accepts the legacy
        # ``--approve-for-me`` flag.  Writer authorization is enforced by the
        # bounded prompt, filtered environment, and filesystem lease below.
        command = [self.executable, "exec", "--skip-git-repo-check", "--cd", str(spec.codex_cwd)]
        command.extend(["--output-schema", str(schema_copy), "--output-last-message", str(external_output), "--color", "never", "--json", canonical_prompt])
        evidence = CodexRunEvidence(
            job_id=canonical_job_id,
            codex_version=_codex_version(self.executable),
            sanitized_argv=command[:-1] + ["<prompt-argument>"],
            actual_cwd=str(spec.codex_cwd),
            environment_variable_names=sorted(_codex_environment({"SWARM_ROLE": "CODEX_WRITER", "SWARM_DRY_RUN": "1"}, cache_dir)),
            prompt_hash=hashlib.sha256(canonical_prompt.encode("utf-8")).hexdigest(),
            sanitized_prompt=redact(canonical_prompt)[:12000],
            target_canonical_path=str(target),
            target_pre_hash=hashlib.sha256(read_restricted_bytes(target, "Codex target")).hexdigest(),
        )
        self.last_evidence = evidence
        try:
            attempts = 0
            while True:
                result = limited_run(command, spec.codex_cwd, "", self.limits, {"SWARM_ROLE": "CODEX_WRITER", "SWARM_DRY_RUN": "1"}, use_cgroup=True, environment_builder=lambda values: _codex_environment(values, cache_dir))
                if result.returncode == 0 or attempts >= 2:
                    break
                compatible = self._remove_unknown_option(command, result.stderr)
                if compatible is None:
                    break
                command = compatible
                attempts += 1
            event_types, tool_commands, denials = _jsonl_telemetry(result.stdout)
            evidence.jsonl_event_types = event_types
            evidence.tool_commands = tool_commands
            evidence.sandbox_write_denials = denials
            evidence.codex_exit_code = result.returncode
            self.last_invocation = {
                "executable": self.executable,
                "argv": command[:-1] + ["<prompt-argument>"],
                "working_directory": str(spec.codex_cwd),
                "environment_names": sorted(_codex_environment({"SWARM_ROLE": "CODEX_WRITER", "SWARM_DRY_RUN": "1"}, cache_dir)),
                "pycache_directory": str(cache_dir),
                "exit_code": result.returncode,
                "prompt_hash": hashlib.sha256(canonical_prompt.encode("utf-8")).hexdigest(),
                "stdout": redact(result.stdout),
                "stderr": redact(result.stderr),
            }
            if result.returncode:
                evidence.schema_validation = "NOT_REACHED_PROCESS_EXIT"
                evidence.target_post_hash = hashlib.sha256(read_restricted_bytes(target, "Codex target")).hexdigest()
                self.persist_evidence()
                raise SwarmError(f"Codex failed ({result.returncode}): {redact(result.stderr + result.stdout)}")
            try:
                external_bytes = read_restricted_bytes(external_output, "Codex final response")
            except SwarmError as exc:
                evidence.schema_validation = "MISSING_FINAL_RESPONSE"
                evidence.target_post_hash = hashlib.sha256(read_restricted_bytes(target, "Codex target")).hexdigest()
                self.persist_evidence()
                raise SwarmError("Codex did not write a safe schema-constrained result; output: " + redact(result.stdout + result.stderr)) from exc
            if not external_bytes.strip():
                evidence.schema_validation = "MISSING_FINAL_RESPONSE"
                evidence.target_post_hash = hashlib.sha256(read_restricted_bytes(target, "Codex target")).hexdigest()
                self.persist_evidence()
                raise SwarmError("Codex wrote an empty schema-constrained result; output: " + redact(result.stdout + result.stderr))
            payload = json.loads(external_bytes)
            evidence.sanitized_final_response = redact(json.dumps(payload, sort_keys=True))[:12000]
            evidence.claimed_changed_files = payload.get("changed_files") if isinstance(payload, dict) and isinstance(payload.get("changed_files"), list) else None
            write_mailbox_json(output, payload, "Codex result")
            self.last_invocation["final_response"] = redact(json.dumps(payload, sort_keys=True))
            evidence.target_post_hash = hashlib.sha256(read_restricted_bytes(target, "Codex target")).hexdigest()
            try:
                validate_contract(payload, "codex", expected_job_id=canonical_job_id)
            except SwarmError as exc:
                evidence.schema_validation = "FAILED"
                self.persist_evidence()
                raise
            evidence.schema_validation = "PASSED"
            self.persist_evidence()
        finally:
            external_output.unlink(missing_ok=True)
            output.unlink(missing_ok=True)
            schema_copy.unlink(missing_ok=True)
            if result_dir.is_dir() and not any(result_dir.iterdir()):
                result_dir.rmdir()
            shutil.rmtree(cache_dir, ignore_errors=True)
        return payload


class GeminiAdapter:
    def __init__(self, schema: Path, limits: ResourceLimits, executable: str = "/home/jeff/.local/bin/agy", *, allow_external_review: bool = False):
        self.schema = schema
        self.limits = limits
        self.executable = executable
        self.allow_external_review = allow_external_review
        self.last_attempts: list[dict[str, Any]] = []
        self.last_schema: dict[str, Any] | None = None

    def _job_schema(self, job_id: str, commit: str) -> dict[str, Any]:
        value = json.loads(read_restricted_bytes(self.schema, "Gemini schema"))
        if not isinstance(value, dict):
            raise SwarmError("Gemini schema must be a JSON object")
        value["additionalProperties"] = False
        value["required"] = [
            "job_id", "reviewed_commit", "verdict", "risk", "blocking_findings",
            "non_blocking_notes", "tests_missing", "reasoning_summary", "proposed_rules",
        ]
        properties = value.setdefault("properties", {})
        properties.setdefault("job_id", {})["const"] = job_id
        properties.setdefault("reviewed_commit", {})["const"] = commit
        return value

    @staticmethod
    def _required_structure(job_id: str, commit: str) -> str:
        return json.dumps({
            "job_id": job_id,
            "reviewed_commit": commit,
            "verdict": "APPROVE|REJECT|HUMAN_REQUIRED",
            "risk": "LOW|MEDIUM|HIGH",
            "blocking_findings": [],
            "non_blocking_notes": [],
            "tests_missing": [],
            "reasoning_summary": "concise explanation",
            "proposed_rules": [],
        }, indent=2)

    def run(self, snapshot: Path, job_id: str, commit: str, prompt: str, *, formatting_retry: bool = True) -> dict[str, Any]:
        result_dir = ensure_mailbox_directory(snapshot / ".swarm")
        output = result_dir / "gemini-review.json"
        schema = self._job_schema(job_id, commit)
        self.last_schema = schema
        schema_path = result_dir / f"gemini-review-{job_id}.schema.json"
        write_mailbox_json(schema_path, schema, "Gemini schema")
        self.last_attempts = []
        required = self._required_structure(job_id, commit)
        base_prompt = (
            f"{prompt}\n\nIMPORTANT: Return exactly one JSON object. The alias `missing_tests` is forbidden; "
            "the required field is `tests_missing`. Do not omit any required field. The exact required structure is:\n"
            f"{required}"
        )
        current_prompt = base_prompt
        for attempt in range(2 if formatting_retry else 1):
            command = [
            self.executable, f"--print={current_prompt}", "--agent", "code-review-agent", "--sandbox",
                "--disable-slash-commands", "--output-format", "json",
                "--print-timeout", f"{self.limits.timeout_seconds}s",
            ]
            result = limited_run(
                command, snapshot, "", self.limits,
                {"SWARM_ROLE": "GEMINI_READ_ONLY", "SWARM_DRY_RUN": "1", "SWARM_REVIEWED_COMMIT": commit},
                use_cgroup=True, network_isolated=not self.allow_external_review,
            )
            attempt_record: dict[str, Any] = {"attempt": attempt + 1, "exit_code": result.returncode, "schema_path": str(schema_path)}
            if result.returncode:
                attempt_record["validation"] = "PROCESS_FAILED"
                attempt_record["error"] = redact(result.stderr + result.stdout)[:2000]
                self.last_attempts.append(attempt_record)
                raise SwarmError(f"Gemini failed ({result.returncode}): {redact(result.stderr + result.stdout)}")
            try:
                envelope = json.loads(result.stdout)
                if isinstance(envelope, dict) and envelope.get("status") not in (None, "SUCCESS"):
                    detail = redact(str(envelope.get("error") or envelope.get("response") or envelope.get("status")))[:2000]
                    raise SwarmError(f"agy provider returned status {envelope.get('status')}: {detail}")
                payload = self._extract_json(result.stdout)
                attempt_record["payload"] = redact(json.dumps(payload, sort_keys=True))[:12000]
                validate_contract(payload, "gemini", expected_job_id=job_id, expected_commit=commit)
                if payload["verdict"] == "APPROVE" and (payload["blocking_findings"] or payload["tests_missing"]):
                    raise SwarmError("Gemini APPROVE cannot contain blocking findings or missing tests")
                attempt_record["validation"] = "PASSED"
                self.last_attempts.append(attempt_record)
                write_mailbox_json(output, payload, "Gemini review")
                return payload
            except (SwarmError, json.JSONDecodeError) as exc:
                attempt_record["validation"] = "FAILED"
                attempt_record["error"] = redact(str(exc))[:2000]
                self.last_attempts.append(attempt_record)
                if attempt == 0 and formatting_retry:
                    current_prompt = (
                        f"{base_prompt}\n\nYour previous response was rejected for schema validation: "
                        f"{attempt_record['error']}. Return the exact required structure above, with job_id exactly "
                        f"{job_id}, reviewed_commit exactly {commit}, and no additional fields. This is a formatting-only "
                        "retry: review the same evidence and commit; do not change the review basis."
                    )
                    continue
                raise SwarmError(f"Gemini review rejected after formatting validation: {attempt_record['error']}") from exc
        raise SwarmError("Gemini review did not return a valid response")

    @staticmethod
    def _extract_json(output: str) -> dict[str, Any]:
        try:
            value = json.loads(output)
            if isinstance(value, dict) and isinstance(value.get("structured_output"), dict):
                return value["structured_output"]
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
