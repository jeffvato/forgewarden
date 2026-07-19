from __future__ import annotations

import hashlib
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


def validate_contract(payload: Any, kind: str) -> None:
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
    else:
        if not re.fullmatch(r"[0-9a-fA-F]{40,64}", str(payload["reviewed_commit"])):
            raise SwarmError("Gemini reviewed_commit is not a full SHA")
        if payload["verdict"] not in {"APPROVE", "REJECT", "HUMAN_REQUIRED"} or payload["risk"] not in {"LOW", "MEDIUM", "HIGH"}:
            raise SwarmError("invalid Gemini verdict or risk")
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
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.parent.chmod(0o700)
        if self.path.exists():
            self.path.chmod(0o600)

    def record(self, job: Job, event: str, **data: Any) -> None:
        entry = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "job_id": job.job_id, "state": job.state, "event": event, **_audit_data(data)}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
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
                if not result_file.exists():
                    raise SwarmError("Codex did not produce structured result JSON")
                codex_result = json.loads(result_file.read_text(encoding="utf-8"))
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
                commit = self._git(worktree, "rev-parse", "HEAD")
                snapshot = Path(tempfile.mkdtemp(prefix=f"review-{job.job_id}-", dir=self.state_dir))
                # A separate checkout is created from the exact commit; Gemini never receives the writer worktree.
                run = run_command(["git", "clone", "--no-hardlinks", str(worktree), str(snapshot)], self.state_dir)
                if run.returncode:
                    raise SwarmError("could not create read-only Gemini snapshot")
                # Keep only the structured-output mailbox writable. Source, Git metadata,
                # and directories are read-only to the Gemini process.
                output_dir = snapshot / ".swarm"
                output_dir.mkdir(exist_ok=True)
                for item in snapshot.rglob("*"):
                    if item == output_dir or output_dir in item.parents:
                        continue
                    item.chmod(0o555 if item.is_dir() else 0o444)
                output_dir.chmod(0o755)
                job.state = "GEMINI_REVIEWING"
                self.begin_review_cycle(job)
                self.audit.record(job, "gemini_started", reviewed_commit=commit)
                review = run_command(gemini_command, snapshot, timeout=60, env={"SWARM_ROLE": "GEMINI_READ_ONLY", "SWARM_DRY_RUN": "1", "SWARM_REVIEWED_COMMIT": commit})
                review_file = snapshot / ".swarm" / "gemini-review.json"
                if not review_file.exists():
                    raise SwarmError("Gemini did not produce structured review JSON")
                gemini = json.loads(review_file.read_text(encoding="utf-8"))
                validate_contract(gemini, "gemini")
                if gemini["job_id"] != job.job_id:
                    raise SwarmError("stale or mismatched Gemini review rejected")
                require_exact_commit(commit, gemini["reviewed_commit"])
                if checks.returncode or gemini["verdict"] != "APPROVE" or gemini["risk"] != "LOW":
                    job.state = "AWAITING_JEFF" if gemini["verdict"] == "HUMAN_REQUIRED" else "REVISION_REQUIRED"
                    self.audit.record(job, "review_not_approved", verdict=gemini["verdict"], risk=gemini["risk"])
                    return {"job_id": job.job_id, "state": job.state, "commit": commit, "gemini": gemini}
                if gemini["proposed_rules"]:
                    self.rules.propose(gemini["proposed_rules"][0], job)
                job.state = "READY_TO_DEPLOY" if not self.dry_run else "SUCCEEDED"
                self.audit.record(job, "dry_run_succeeded", commit=commit)
                return {"job_id": job.job_id, "state": job.state, "commit": commit, "base": base, "gemini": gemini}
            finally:
                cleanup = run_command(["git", "worktree", "remove", "--force", str(worktree)], job.repository)
                if cleanup.returncode:
                    self.audit.record(job, "worktree_cleanup_warning", output=redact(cleanup.stderr))
