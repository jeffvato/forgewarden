"""Adapters that bind the durable loop to ForgeWarden's existing workers."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from .adapters import CodexAdapter, ResourceLimits, WriterInvocationSpec
from .autonomous_loop import GitCheckpointController, ReviewUnavailable, TaskSpec, WorkerLease, WorkerResult
from .review_handoff import ReviewResult
from .review_runner import run_review_cycle


class CodexTaskAdapter:
    """Dispatch the local Codex CLI; Codex never creates Git history."""

    def __init__(self, schema: Path, executable: str, limits: ResourceLimits | None = None):
        self.schema = Path(schema)
        self.executable = executable
        self.limits = limits or ResourceLimits()

    def dispatch(self, task: TaskSpec, lease: WorkerLease) -> WorkerResult:
        if not task.target_path:
            raise ValueError(f"{task.task_id} lacks an explicit Codex target path")
        job_id = "codex-" + task.task_id.lower()
        spec = WriterInvocationSpec(job_id, Path(lease.repository), Path(lease.repository), task.target_path, task.target_path, task.expected_behavior, task.failing_assertion, task.allowed_paths)
        payload = CodexAdapter(self.schema, self.limits, self.executable).run(spec, spec.prompt())
        return WorkerResult(None, tuple(payload["changed_files"]), tuple(task.test_command), payload.get("summary", ""))



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

    def __init__(self, context: str, *, allow_external_review: bool = False, reviewers: tuple[str, ...] = ("CLAUDE", "GEMINI", "OPENROUTER", "NVIDIA")):
        self.context = context
        self.allow_external_review = allow_external_review
        self.reviewers = reviewers

    def review(self, task: TaskSpec, commit: str, lease: WorkerLease) -> dict[str, ReviewResult]:
        job_id = "phase2a-" + hashlib.sha256(task.task_id.encode("utf-8")).hexdigest()[:24]
        result = run_review_cycle(Path(lease.repository), commit, job_id, self.context, allow_external_review=self.allow_external_review, reviewers=self.reviewers, required_reviewers=("CLAUDE",), adjudicate_disagreements=True, sequential_fallback=True)
        if result["state"] != "APPROVED":
            claude = next((item for item in result.get("reviews", ()) if item.get("provider") == "CLAUDE"), None)
            gemini = next((item for item in result.get("reviews", ()) if item.get("provider") == "GEMINI"), None)
            # Claude is primary, but Gemini is the explicitly authorized
            # fallback. A fallback approval is safe only when Claude is
            # unavailable; a Claude rejection remains authoritative.
            if (
                claude is not None
                and claude.get("state") == "UNAVAILABLE"
                and gemini is not None
                and gemini.get("state") == "APPROVED"
                and isinstance(gemini.get("result"), dict)
            ):
                payload = gemini["result"]
                return {
                    "GEMINI": ReviewResult(
                        "GEMINI", commit, tuple(str(value) for value in payload.get("blocking_findings", [])),
                        str(payload["risk"]), "APPROVED", str(payload["reasoning_summary"]),
                    )
                }
            unavailable = [item for item in result.get("reviews", ()) if item.get("state") == "UNAVAILABLE"]
            if unavailable:
                detail = "; ".join(f"{item.get('provider', 'reviewer')}: {item.get('error', 'no diagnostic')}" for item in unavailable)
                raise ReviewUnavailable(f"independent exact-commit review resource unavailable: {detail[:1000]}")
            raise RuntimeError("independent exact-commit review did not approve")
        adjudication = result.get("adjudication")
        if isinstance(adjudication, dict) and adjudication.get("state") == "APPROVED":
            payload = adjudication["result"]
            return {
                "CLAUDE": ReviewResult(
                    "CLAUDE", commit, tuple(str(value) for value in payload.get("blocking_findings", [])),
                    str(payload["risk"]), "APPROVED", str(payload["reasoning_summary"]),
                )
            }
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
                required_reviewers=("CLAUDE",),
                adjudicate_disagreements=True,
                sequential_fallback=True,
            )
            if result["state"] == "APPROVED":
                return "PASSED"
            reviews = tuple(result.get("reviews", ()))
            claude = next((item for item in reviews if item.get("provider") == "CLAUDE"), None)
            gemini = next((item for item in reviews if item.get("provider") == "GEMINI"), None)
            if claude is not None and claude.get("state") == "UNAVAILABLE" and gemini is not None and gemini.get("state") == "APPROVED":
                return "PASSED"
            if claude is None or claude.get("state") == "UNAVAILABLE":
                detail = claude.get("error", "Claude review record was not returned") if claude else "Claude review record was not returned"
                return "EXTERNAL: " + str(detail)[:1000]
            return "REPAIRABLE"
        except Exception as exc:
            return ("EXTERNAL: " + str(exc)[:1000]) if "unavailable" in str(exc).lower() else "REPAIRABLE"


def commit_with_trusted_git(task: TaskSpec, result: WorkerResult, lease: WorkerLease) -> str:
    return GitCheckpointController(Path(lease.repository)).commit_worker_changes(task, result)
