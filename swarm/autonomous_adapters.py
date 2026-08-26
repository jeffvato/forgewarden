"""Adapters that bind the durable loop to ForgeWarden's existing workers."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .adapters import ResourceLimits
from .core import read_restricted_bytes, validate_contract
from .autonomous_loop import GitCheckpointController, TaskSpec, WorkerLease, WorkerResult
from .review_handoff import ReviewResult
from .review_runner import run_review_cycle


class ClaudeTaskAdapter:
    """Dispatch the local Claude Code CLI in the leased checkout."""

    def __init__(self, schema: Path, executable: str, limits: ResourceLimits | None = None):
        self.schema = Path(schema)
        self.executable = executable
        self.limits = limits or ResourceLimits()

    def dispatch(self, task: TaskSpec, lease: WorkerLease) -> WorkerResult:
        if not task.target_path:
            raise ValueError(f"{task.task_id} lacks an explicit Codex target path")
        job_id = "claude-" + task.task_id.lower()
        schema = json.loads(read_restricted_bytes(self.schema, "Claude result schema"))
        schema.setdefault("properties", {}).setdefault("job_id", {})["const"] = job_id
        prompt = (
            f"Work only in {lease.repository}. Edit only {task.target_path} and any files under the declared allowed paths: "
            f"{', '.join(task.allowed_paths)}. Expected behavior: {task.expected_behavior}. "
            f"The failing assertion is: {task.failing_assertion}. Run only the deterministic test command after editing. "
            "Do not edit tests, Git metadata, deployment settings, credentials, or remote systems. Return the required JSON result."
        )
        command = [self.executable, "--print", "--output-format", "json", "--no-session-persistence", "--permission-mode", "acceptEdits", "--allowed-tools", "Read,Edit,Write,Glob,Grep,Bash(python3 -m pytest*)", "--disallowed-tools", "Bash(git *),Bash(curl *),Bash(wget *)", "--json-schema", json.dumps(schema), prompt]
        completed = subprocess.run(command, cwd=lease.repository, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False, timeout=self.limits.timeout_seconds)
        if completed.returncode:
            raise RuntimeError(f"Claude failed ({completed.returncode}): {completed.stderr[-2000:]}")
        envelope = json.loads(completed.stdout.strip().splitlines()[-1])
        if envelope.get("is_error"):
            raise RuntimeError(f"Claude returned an error: {envelope.get('result', 'unknown error')}")
        payload = envelope.get("structured_output") or envelope.get("result")
        if not isinstance(payload, dict):
            raise RuntimeError("Claude did not return a structured worker result")
        validate_contract(payload, "codex", expected_job_id=job_id)
        return WorkerResult(None, tuple(payload["changed_files"]), tuple(task.test_command), payload.get("summary", ""))

    @staticmethod
    def _remove_mailbox_artifacts(repository: Path, job_id: str) -> None:
        """Keep the worker's declared Git scope free of adapter bookkeeping."""
        mailbox = repository / ".swarm"
        for name in (f"codex-result-{job_id}.json", f"codex-result-{job_id}.schema.json"):
            (mailbox / name).unlink(missing_ok=True)
        if mailbox.is_dir() and not any(mailbox.iterdir()):
            mailbox.rmdir()


CodexTaskAdapter = ClaudeTaskAdapter


def run_deterministic_tests(task: TaskSpec, result: WorkerResult, repository: WorkerLease | Path | str, limits: ResourceLimits | None = None) -> bool:
    """Run only the task's explicit, shell-free validation command."""
    if not task.test_command:
        return False
    if any(not item for item in task.test_command):
        return False
    cwd = repository.repository if isinstance(repository, WorkerLease) else Path(repository)
    completed = subprocess.run(list(task.test_command), cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False, timeout=(limits or ResourceLimits()).timeout_seconds)
    return completed.returncode == 0


class ExactReviewAdapter:
    """Use the existing independent review runner and convert its evidence."""

    def __init__(self, context: str, *, allow_external_review: bool = False, reviewers: tuple[str, ...] = ("CLAUDE",)):
        self.context = context
        self.allow_external_review = allow_external_review
        self.reviewers = reviewers

    def review(self, task: TaskSpec, commit: str, lease: WorkerLease) -> dict[str, ReviewResult]:
        job_id = "phase2a-" + hashlib.sha256(task.task_id.encode("utf-8")).hexdigest()[:24]
        result = run_review_cycle(Path(lease.repository), commit, job_id, self.context, allow_external_review=self.allow_external_review, reviewers=self.reviewers)
        if result["state"] != "APPROVED":
            raise RuntimeError("independent exact-commit review did not approve")
        reviews: dict[str, ReviewResult] = {}
        for item in result["reviews"]:
            payload = item.get("result")
            if item.get("state") != "APPROVED" or not isinstance(payload, dict):
                raise RuntimeError("review evidence is incomplete")
            role = str(item["provider"])
            reviews[role] = ReviewResult(role, commit, tuple(str(value) for value in payload.get("blocking_findings", [])), str(payload["risk"]), "APPROVED", str(payload["reasoning_summary"]))
        return reviews

    def resolve_review(self, task: TaskSpec, lease: WorkerLease) -> str:
        if not task.review_commit:
            return "UNRESOLVED"
        try:
            job_id = "phase2a-" + hashlib.sha256(task.task_id.encode("utf-8")).hexdigest()[:24]
            result = run_review_cycle(
                Path(lease.repository),
                task.review_commit,
                job_id,
                self.context,
                allow_external_review=self.allow_external_review,
                reviewers=self.reviewers,
            )
            if result["state"] == "APPROVED":
                return "PASSED"
            if any(item.get("state") == "UNAVAILABLE" for item in result.get("reviews", ())):
                return "EXTERNAL"
            return "REPAIRABLE"
        except Exception as exc:
            return "EXTERNAL" if "unavailable" in str(exc).lower() else "REPAIRABLE"


def commit_with_trusted_git(task: TaskSpec, result: WorkerResult, lease: WorkerLease) -> str:
    return GitCheckpointController(Path(lease.repository)).commit_worker_changes(task, result)
