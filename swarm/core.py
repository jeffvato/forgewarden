from __future__ import annotations

import hashlib
import fcntl
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable


STATES = (
    "RECEIVED", "CLASSIFIED", "WORKTREE_READY", "CODEX_RUNNING", "CHECKS_RUNNING",
    "GEMINI_REVIEWING", "REVISION_REQUIRED", "READY_TO_DEPLOY", "AWAITING_JEFF",
    "DEPLOYING", "VERIFYING_PRODUCTION", "SUCCEEDED", "ROLLED_BACK", "FAILED",
)
HIGH_RISK_TERMS = (
    "database", "pricing", "map", "checkout", "payment", "order", "purchase order",
    "tracking", "credential", "secret", "backup", "restore", "firewall", "ssh", "dns",
    "sudo", "operating system", "ffl", "nfa", "state restriction", "migration",
    "deploy", "production", "destructive",
)
FORBIDDEN_DIFF_TERMS = (".env", "private key", "credential", "migration", "deployment policy", "risk policy")
SECRET_PATTERNS = (
    re.compile(r"(?is)-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----.*?-----END\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"),
    re.compile(r"(?i)(?:authorization|proxy-authorization)\s*[:=]\s*(?:bearer|basic)\s+[^\s,;]+"),
    re.compile(r"(?i)(?:cookie|set-cookie)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)(?:https?|postgres(?:ql)?|mysql|redis)://[^\s/@:]+:[^\s/@]+@[^\s]+"),
    re.compile(r"(?i)(api[_-]?key|token|password|secret|authorization)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"\b(?:sk|ghp|xoxb|AIza)[-_A-Za-z0-9]{12,}\b"),
    re.compile(r"\b\d{13,19}\b"),
)


class SwarmError(RuntimeError):
    pass


def redact(value: str) -> str:
    result = value
    for pattern in SECRET_PATTERNS:
        def replacement(match: re.Match[str]) -> str:
            token = match.group(0)
            if ":" in token or "=" in token:
                return re.split(r"[:=]", token, maxsplit=1)[0] + "=[REDACTED]"
            return "[REDACTED]"
        result = pattern.sub(replacement, result)
    return result


def _reject_symlink_path(path: Path, label: str) -> None:
    """Reject a mailbox path or any parent that could redirect I/O."""
    path = path.expanduser()
    if path.is_symlink() or any(parent.is_symlink() for parent in (path.parent, *path.parent.parents)):
        raise SwarmError(f"refusing symlink {label}: {path}")


def ensure_mailbox_directory(path: Path) -> Path:
    """Create or validate a model mailbox without following symlinks."""
    _reject_symlink_path(path, "mailbox directory")
    if path.exists() and not path.is_dir():
        raise SwarmError(f"mailbox path is not a directory: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o755)
    _reject_symlink_path(path, "mailbox directory")
    return path


def ensure_private_directory(path: Path, label: str) -> Path:
    """Create or validate a mode-0700 local artifact directory."""
    _reject_symlink_path(path, label)
    if path.exists() and not path.is_dir():
        raise SwarmError(f"{label} is not a directory: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    _reject_symlink_path(path, label)
    return path


def read_mailbox_json(path: Path, label: str) -> dict[str, Any]:
    """Read one structured mailbox result only from a regular, non-symlink file."""
    _reject_symlink_path(path, label)
    if not path.is_file():
        raise SwarmError(f"{label} is missing or not a regular file: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SwarmError(f"{label} is not valid UTF-8 JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise SwarmError(f"{label} must be a JSON object")
    return payload


def write_mailbox_json(path: Path, payload: dict[str, Any], label: str) -> None:
    """Create one structured mailbox file without following or replacing a symlink."""
    _reject_symlink_path(path, label)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    _reject_symlink_path(path, label)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise SwarmError(f"unable to create {label} safely: {path}") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True))
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    path.chmod(0o600)


def write_restricted_text(path: Path, content: str, label: str) -> None:
    """Atomically replace a restricted text artifact without following symlinks."""
    _reject_symlink_path(path, label)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    _reject_symlink_path(path, label)
    temporary = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600)
    except OSError as exc:
        raise SwarmError(f"unable to write {label} safely: {path}") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
    path.chmod(0o600)


def touch_restricted(path: Path, label: str) -> None:
    """Create a mode-0600 marker without following a symlink."""
    _reject_symlink_path(path, label)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    _reject_symlink_path(path, label)
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise SwarmError(f"unable to create {label} safely: {path}") from exc
    os.close(descriptor)
    path.chmod(0o600)


def restore_restricted_bytes(path: Path, content: bytes, label: str) -> None:
    """Restore a file by replacing its directory entry, never following its leaf."""
    path = path.expanduser()
    if any(parent.is_symlink() for parent in (path.parent, *path.parent.parents)):
        raise SwarmError(f"refusing symlink parent for {label}: {path}")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.restore"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def read_restricted_bytes(path: Path, label: str) -> bytes:
    """Read a regular file through a no-follow descriptor."""
    _reject_symlink_path(path, label)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SwarmError(f"unable to read {label} safely: {path}") from exc
    with os.fdopen(descriptor, "rb") as handle:
        return handle.read()


def validate_snapshot_symlinks(snapshot: Path) -> None:
    """Permit only symlinks whose targets remain inside the disposable snapshot."""
    root = snapshot.resolve()
    for item in snapshot.rglob("*"):
        if not item.is_symlink():
            continue
        try:
            item.resolve().relative_to(root)
        except (OSError, ValueError) as exc:
            raise SwarmError(f"snapshot contains an external or broken symlink: {item}") from exc


def validate_contract(payload: Any, kind: str, expected_job_id: str | None = None, expected_commit: str | None = None) -> None:
    if not isinstance(payload, dict):
        raise SwarmError(f"{kind} result must be a JSON object")
    required = {
        "codex": ("job_id", "status", "root_cause", "summary", "changed_files", "tests_added_or_changed", "commands_run", "remaining_risks", "requires_human_approval"),
        "gemini": ("job_id", "reviewed_commit", "verdict", "risk", "blocking_findings", "non_blocking_notes", "tests_missing", "reasoning_summary", "proposed_rules"),
    }[kind]
    missing = [key for key in required if key not in payload]
    if missing:
        raise SwarmError(f"{kind} result missing required fields: {', '.join(missing)}")
    if kind == "codex":
        if payload["status"] not in {"FIXED", "NOT_FIXED", "BLOCKED"}:
            raise SwarmError("invalid Codex status")
        for key in ("changed_files", "tests_added_or_changed", "commands_run", "remaining_risks"):
            if not isinstance(payload[key], list):
                raise SwarmError(f"Codex {key} must be an array")
        if any(not isinstance(item, str) for item in payload["changed_files"]):
            raise SwarmError("Codex changed_files must contain strings")
        if any(not isinstance(item, dict) or not isinstance(item.get("exit_code"), int) or not isinstance(item.get("command"), str) for item in payload["commands_run"]):
            raise SwarmError("invalid Codex command evidence")
        if expected_job_id is not None and payload["job_id"] != expected_job_id:
            raise SwarmError(f"Codex result job ID mismatch: expected {expected_job_id}, got {payload['job_id']}")
    else:
        allowed = set(required)
        extras = sorted(set(payload) - allowed)
        if extras:
            raise SwarmError(f"Gemini result contains forbidden fields: {', '.join(extras)}")
        if expected_job_id is not None and payload["job_id"] != expected_job_id:
            raise SwarmError(f"Gemini result job ID mismatch: expected {expected_job_id}, got {payload['job_id']}")
        if not re.fullmatch(r"[0-9a-fA-F]{40,64}", str(payload["reviewed_commit"])):
            raise SwarmError("Gemini reviewed_commit is not a full SHA")
        if expected_commit is not None:
            require_exact_commit(expected_commit, payload["reviewed_commit"])
        if payload["verdict"] not in {"APPROVE", "REJECT", "HUMAN_REQUIRED"} or payload["risk"] not in {"LOW", "MEDIUM", "HIGH"}:
            raise SwarmError("invalid Gemini verdict or risk")
        for key in ("blocking_findings", "non_blocking_notes", "tests_missing", "proposed_rules"):
            if not isinstance(payload[key], list):
                raise SwarmError(f"Gemini {key} must be an array")
        if not isinstance(payload["reasoning_summary"], str) or not payload["reasoning_summary"].strip():
            raise SwarmError("Gemini reasoning_summary must be a non-empty string")
        if not isinstance(payload["proposed_rules"], list) or len(payload["proposed_rules"]) > 1:
            raise SwarmError("Gemini may propose at most one rule")


def require_exact_commit(expected: str, reviewed: str) -> None:
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", str(reviewed)) or str(reviewed).lower() != expected.lower():
        raise SwarmError(f"reviewed commit mismatch: expected {expected}, got {reviewed}")


@dataclass
class Job:
    job_id: str
    service: str
    repository: Path
    evidence: str
    base_revision: str = "HEAD"
    state: str = "RECEIVED"
    risk: str = "HIGH"
    review_cycles: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


class AuditLog:
    def __init__(self, path: Path):
        path = path.expanduser()
        if path.is_symlink() or any(parent.is_symlink() for parent in (path.parent, *path.parent.parents)):
            raise SwarmError(f"refusing symlink audit path: {path}")
        self.path = path
        self.lock_path = path.with_name(path.name + ".lock")
        if self.lock_path.is_symlink() or any(parent.is_symlink() for parent in (self.lock_path.parent, *self.lock_path.parent.parents)):
            raise SwarmError(f"refusing symlink audit lock: {self.lock_path}")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.parent.chmod(0o700)
        if self.path.exists() and not self.path.is_file():
            raise SwarmError(f"audit path is not a regular file: {self.path}")
        if self.lock_path.exists() and not self.lock_path.is_file():
            raise SwarmError(f"audit lock is not a regular file: {self.lock_path}")
        if self.path.exists():
            self.path.chmod(0o600)
        lock_fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(lock_fd)
        self.lock_path.chmod(0o600)

    def record(self, job: Job, event: str, **data: Any) -> None:
        entry = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "job_id": job.job_id, "state": job.state, "event": event, **_audit_data(data)}
        lock_fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(lock_fd, "a+", encoding="ascii") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            audit_fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(audit_fd, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        self.path.chmod(0o600)


_AUDIT_SENSITIVE_KEYS = re.compile(
    r"(?i)(credential|secret|token|password|authorization|customer|order|distributor|"
    r"email|phone|address|card|cookie|session|payload|prompt|output|reasoning|summary|root_cause)"
)


def _audit_value(key: str, value: Any) -> Any:
    if _AUDIT_SENSITIVE_KEYS.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _audit_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list):
        return [_audit_value(key, item) for item in value]
    if isinstance(value, str):
        return redact(value)[:512]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact(str(value))[:512]


def _audit_data(data: dict[str, Any]) -> dict[str, Any]:
    return {str(key): _audit_value(str(key), value) for key, value in data.items()}


class ServiceLock:
    def __init__(self, directory: Path, service: str):
        self.path = directory / f"{hashlib.sha256(service.encode()).hexdigest()[:20]}.lock"
        self.fd: int | None = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(self.fd, str(os.getpid()).encode())
        except FileExistsError as exc:
            raise SwarmError("another repair already holds the per-service lock") from exc
        return self

    def __exit__(self, *_):
        if self.fd is not None:
            os.close(self.fd)
            self.path.unlink(missing_ok=True)


class DeploymentController:
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run

    def deploy(self, *_args, **_kwargs):
        raise SwarmError("deployment is mechanically disabled in Phase 1 dry-run mode")


class RuleStore:
    def __init__(self, root: Path):
        self.root = root
        self.active = root / "active.yaml"
        self.history = root / "history.jsonl"
        self.kill_switch = root / "DISABLED"
        root.mkdir(parents=True, exist_ok=True)

    def propose(self, rule: dict[str, Any], job: Job) -> str:
        if self.kill_switch.exists():
            return "DISABLED_BY_KILL_SWITCH"
        if len(rule.get("trigger", "")) > 240 or len(rule.get("rule", "")) > 240:
            return "REJECTED_INVALID"
        if rule.get("category") in {"SECURITY", "DATA", "DEPLOYMENT", "GOVERNANCE", "STYLE", "COMPATIBILITY"} or rule.get("confidence", 0) < 0.90:
            decision = "HUMAN_REQUIRED"
        else:
            decision = "PROPOSED_DRY_RUN"
        record = {"rule": rule, "source_job_id": job.job_id, "activation_decision": decision, "timestamp": time.time()}
        with self.history.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        return decision


def run_command(command: list[str], cwd: Path, timeout: int = 30, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    safe_env = os.environ.copy()
    if env:
        safe_env.update(env)
    try:
        return subprocess.run(command, cwd=cwd, env=safe_env, text=True, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise SwarmError(f"command timed out after {timeout}s: {command[0]}") from exc


class Orchestrator:
    def __init__(self, state_dir: Path, dry_run: bool = True, max_cycles: int = 3, audit_dir: Path | None = None):
        self.state_dir = state_dir
        self.dry_run = dry_run
        self.max_cycles = max_cycles
        self.audit = AuditLog((audit_dir or state_dir) / "audit.jsonl")
        self.rules = RuleStore(state_dir / ".agent-rules")
        self.deployments = DeploymentController(dry_run=dry_run)

    def classify(self, job: Job) -> None:
        lowered = (job.evidence + " " + job.service).lower()
        if any(term in lowered for term in HIGH_RISK_TERMS):
            job.risk = "HIGH"
        else:
            job.risk = "LOW"
        job.state = "CLASSIFIED"
        self.audit.record(job, "classified", risk=job.risk)

    def begin_review_cycle(self, job: Job) -> int:
        """Advance a review cycle, refusing a fourth Codex/Gemini attempt."""
        if job.review_cycles >= self.max_cycles:
            raise SwarmError(f"maximum review cycles exceeded ({self.max_cycles})")
        job.review_cycles += 1
        self.audit.record(job, "review_cycle_started", cycle=job.review_cycles)
        return job.review_cycles

    def _git(self, repo: Path, *args: str) -> str:
        result = run_command(["git", *args], repo)
        if result.returncode:
            raise SwarmError(redact(result.stderr.strip() or "git command failed"))
        return result.stdout.strip()

    def _assert_clean(self, job: Job) -> None:
        status = self._git(job.repository, "status", "--porcelain")
        if status:
            raise SwarmError("repair repository is dirty; refusing automatic work")

    def _worktree(self, job: Job) -> tuple[Path, str]:
        self._assert_clean(job)
        base = self._git(job.repository, "rev-parse", job.base_revision)
        path = Path(tempfile.mkdtemp(prefix=f"swarm-{job.job_id}-", dir=self.state_dir))
        result = run_command(["git", "worktree", "add", "--detach", str(path), base], job.repository)
        if result.returncode:
            shutil.rmtree(path, ignore_errors=True)
            raise SwarmError(redact(result.stderr))
        job.state = "WORKTREE_READY"
        self.audit.record(job, "worktree_ready", base_revision=base, path=str(path))
        return path, base

    def run(self, job: Job, codex_command: list[str], check_command: list[str], gemini_command: list[str]) -> dict[str, Any]:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        if (self.state_dir / "KILL_SWITCH").exists():
            job.state = "FAILED"
            self.audit.record(job, "kill_switch_blocked")
            raise SwarmError("global kill switch is enabled; refusing new jobs")
        self.classify(job)
        if job.risk == "HIGH":
            job.state = "AWAITING_JEFF"
            self.audit.record(job, "human_required", reason="high-risk classification")
            return {"job_id": job.job_id, "state": job.state, "risk": job.risk}
        with ServiceLock(self.state_dir / "locks", job.service):
            worktree, base = self._worktree(job)
            try:
                job.state = "CODEX_RUNNING"
                self.audit.record(job, "codex_started")
                codex = run_command(codex_command, worktree, timeout=60, env={"SWARM_ROLE": "CODEX_WRITER", "SWARM_DRY_RUN": "1"})
                result_file = worktree / ".swarm" / "codex-result.json"
                codex_result = read_mailbox_json(result_file, "Codex result")
                validate_contract(codex_result, "codex")
                if codex_result["job_id"] != job.job_id or codex_result["status"] != "FIXED" or codex.returncode:
                    raise SwarmError("Codex result or exit status did not authorize review")
                current_files = self._git(worktree, "diff", "--name-only", base).splitlines()
                if sorted(current_files) != sorted(codex_result["changed_files"]):
                    raise SwarmError("Codex claimed changed files do not match the actual diff")
                if any(any(term in item.lower() for term in FORBIDDEN_DIFF_TERMS) for item in current_files):
                    raise SwarmError("forbidden file change detected")
                job.state = "CHECKS_RUNNING"
                self.audit.record(job, "deterministic_checks_started")
                checks = run_command(check_command, worktree, timeout=60, env={"SWARM_ROLE": "DETERMINISTIC_CHECK"})
                if checks.returncode:
                    job.state = "FAILED"
                    self.audit.record(job, "deterministic_check_failed", output=redact(checks.stdout + checks.stderr))
                    return {"job_id": job.job_id, "state": job.state, "reason": "deterministic check failed"}
                from .quality_apply import build_safe_application_plan
                from .quality_review import evaluate_application_gate, scan_repository

                quality_review = scan_repository(worktree)
                self.audit.record(
                    job,
                    "quality_review_completed",
                    mode=quality_review["mode"],
                    counts=quality_review["counts"],
                    duplicate_findings_removed=quality_review["consolidation"]["duplicate_findings_removed"],
                    auto_apply_enabled=quality_review["auto_apply_enabled"],
                )
                quality_gate = evaluate_application_gate(
                    quality_review,
                    tests_added_or_changed=codex_result["tests_added_or_changed"],
                    changed_files=codex_result["changed_files"],
                )
                self.audit.record(
                    job,
                    "quality_application_gate_evaluated",
                    decision=quality_gate["decision"],
                    reason=quality_gate["reason"],
                    risky_findings=quality_gate["risky_findings"],
                    careful_findings=quality_gate["careful_findings"],
                )
                safe_application_plan = build_safe_application_plan(quality_review)
                self.audit.record(
                    job,
                    "safe_application_plan_created",
                    eligible_finding_count=len(safe_application_plan["eligible_finding_ids"]),
                    blocked_finding_count=len(safe_application_plan["blocked_finding_ids"]),
                    requires_explicit_invocation=safe_application_plan["requires_explicit_invocation"],
                )
                commit = self._git(worktree, "rev-parse", "HEAD")
                snapshot = Path(tempfile.mkdtemp(prefix=f"review-{job.job_id}-", dir=self.state_dir))
                # A separate checkout is created from the exact commit; Gemini never receives the writer worktree.
                run = run_command(["git", "clone", "--no-hardlinks", str(worktree), str(snapshot)], self.state_dir)
                if run.returncode:
                    raise SwarmError("could not create read-only Gemini snapshot")
                validate_snapshot_symlinks(snapshot)
                # Keep only the structured-output mailbox writable. Source, Git metadata,
                # and directories are read-only to the Gemini process.
                output_dir = snapshot / ".swarm"
                ensure_mailbox_directory(output_dir)
                quality_report_path = output_dir / "quality-review.json"
                write_mailbox_json(quality_report_path, quality_review, "quality report")
                plan_path = output_dir / "quality-application-plan.json"
                write_mailbox_json(plan_path, safe_application_plan, "quality application plan")
                for item in snapshot.rglob("*"):
                    if item == output_dir or output_dir in item.parents:
                        continue
                    if item.is_symlink():
                        continue
                    item.chmod(0o555 if item.is_dir() else 0o444)
                output_dir.chmod(0o755)
                job.state = "GEMINI_REVIEWING"
                self.begin_review_cycle(job)
                self.audit.record(job, "gemini_started", reviewed_commit=commit)
                review = run_command(gemini_command, snapshot, timeout=60, env={"SWARM_ROLE": "GEMINI_READ_ONLY", "SWARM_DRY_RUN": "1", "SWARM_REVIEWED_COMMIT": commit})
                review_file = snapshot / ".swarm" / "gemini-review.json"
                gemini = read_mailbox_json(review_file, "Gemini review")
                validate_contract(gemini, "gemini")
                if gemini["job_id"] != job.job_id:
                    raise SwarmError("stale or mismatched Gemini review rejected")
                require_exact_commit(commit, gemini["reviewed_commit"])
                if checks.returncode or gemini["verdict"] != "APPROVE" or gemini["risk"] != "LOW":
                    job.state = "AWAITING_JEFF" if gemini["verdict"] == "HUMAN_REQUIRED" else "REVISION_REQUIRED"
                    self.audit.record(job, "review_not_approved", verdict=gemini["verdict"], risk=gemini["risk"])
                    return {"job_id": job.job_id, "state": job.state, "commit": commit, "gemini": gemini, "quality_review": quality_review, "quality_gate": quality_gate, "safe_application_plan": safe_application_plan}
                if quality_gate["decision"] != "ALLOW_DRY_RUN":
                    job.state = "AWAITING_JEFF"
                    self.audit.record(
                        job,
                        "quality_application_gate_blocked",
                        decision=quality_gate["decision"],
                        reason=quality_gate["reason"],
                    )
                    return {"job_id": job.job_id, "state": job.state, "commit": commit, "gemini": gemini, "quality_review": quality_review, "quality_gate": quality_gate, "safe_application_plan": safe_application_plan}
                if gemini["proposed_rules"]:
                    decision = self.rules.propose(gemini["proposed_rules"][0], job)
                    self.audit.record(job, "learned_rule_decision", decision=decision)
                job.state = "READY_TO_DEPLOY" if not self.dry_run else "SUCCEEDED"
                self.audit.record(job, "dry_run_succeeded", commit=commit)
                return {"job_id": job.job_id, "state": job.state, "commit": commit, "base": base, "gemini": gemini, "quality_review": quality_review, "quality_gate": quality_gate, "safe_application_plan": safe_application_plan}
            finally:
                cleanup = run_command(["git", "worktree", "remove", "--force", str(worktree)], job.repository)
                if cleanup.returncode:
                    self.audit.record(job, "worktree_cleanup_warning", output=redact(cleanup.stderr))
