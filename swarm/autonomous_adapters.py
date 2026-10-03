"""Adapters that bind the durable loop to ForgeWarden's existing workers."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from .adapters import CodexAdapter, ResourceLimits, WriterInvocationSpec
from .autonomous_loop import GitCheckpointController, ReviewUnavailable, TaskSpec, WorkerLease, WorkerResult
from .core import redact
from .review_handoff import ReviewResult
from .review_runner import run_review_cycle


def _review_failure_detail(result: dict[str, Any]) -> str:
    """Keep the durable failure cause useful without persisting reviewer prose."""
    details = []
    for item in result.get("reviews", ()):
        if not isinstance(item, dict):
            continue
        payload = item.get("result") if isinstance(item.get("result"), dict) else {}
        details.append({
            "provider": item.get("provider"), "state": item.get("state"),
            "error": item.get("error"), "verdict": payload.get("verdict"),
            "risk": payload.get("risk"), "blocking_findings": payload.get("blocking_findings"),
            "tests_missing": payload.get("tests_missing"),
        })
    return redact(json.dumps(details, sort_keys=True))[:1800] or "no provider diagnostics returned"


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

    def __init__(self, context: str, *, allow_external_review: bool = False, reviewers: tuple[str, ...] = ("ANYTHINGLLM",)):
        if reviewers != ("ANYTHINGLLM",):
            raise ValueError("autonomous review requires AnythingLLM/Qwen only")
        self.context = context
        self.allow_external_review = allow_external_review
        self.reviewers = reviewers

    @staticmethod
    def _anythingllm_record(result: dict[str, Any], *, expected_job_id: str, expected_commit: str) -> dict[str, Any]:
        reviews = result.get("reviews")
        if (
            not isinstance(reviews, (list, tuple))
            or len(reviews) != 1
            or not isinstance(reviews[0], dict)
            or reviews[0].get("provider") != "ANYTHINGLLM"
            or result.get("adjudication") is not None
        ):
            raise RuntimeError("autonomous review returned evidence outside the AnythingLLM/Qwen policy")
        review = reviews[0]
        if review.get("state") == "APPROVED":
            payload = review.get("result")
            if (
                not isinstance(payload, dict)
                or payload.get("job_id") != expected_job_id
                or payload.get("reviewed_commit") != expected_commit
                or payload.get("verdict") != "APPROVE"
                or payload.get("risk") != "LOW"
                or payload.get("blocking_findings") != []
                or payload.get("tests_missing") != []
            ):
                raise RuntimeError("AnythingLLM approval evidence failed exact binding or acceptance checks")
        return review

    def review(self, task: TaskSpec, commit: str, lease: WorkerLease) -> dict[str, ReviewResult]:
        job_id = "phase2a-" + hashlib.sha256(task.task_id.encode("utf-8")).hexdigest()[:24]
        result = run_review_cycle(
            Path(lease.repository), commit, job_id, self.context,
            allow_external_review=self.allow_external_review,
            reviewers=("ANYTHINGLLM",), required_reviewers=("ANYTHINGLLM",),
            adjudicate_disagreements=False, sequential_fallback=False,
        )
        review = self._anythingllm_record(result, expected_job_id=job_id, expected_commit=commit)
        if result["state"] != "APPROVED":
            if review.get("state") == "UNAVAILABLE":
                detail = str(review.get("error", "AnythingLLM review unavailable"))
                raise ReviewUnavailable(f"independent exact-commit review resource unavailable: {detail[:1000]}")
            raise RuntimeError("independent exact-commit review did not approve: " + _review_failure_detail(result))
        payload = review.get("result")
        if review.get("state") != "APPROVED" or not isinstance(payload, dict):
            raise RuntimeError("AnythingLLM review evidence is incomplete")
        return {
            "ANYTHINGLLM": ReviewResult(
                "ANYTHINGLLM", commit, tuple(str(value) for value in payload.get("blocking_findings", [])),
                str(payload["risk"]), "APPROVED", str(payload["reasoning_summary"]),
            )
        }

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
                reviewers=("ANYTHINGLLM",),
                required_reviewers=("ANYTHINGLLM",),
                adjudicate_disagreements=False,
                sequential_fallback=False,
            )
            required_review = self._anythingllm_record(result, expected_job_id=job_id, expected_commit=task.review_commit)
            if result["state"] == "APPROVED":
                if required_review.get("state") != "APPROVED":
                    return "REPAIRABLE: approved review cycle lacks AnythingLLM approval evidence"
                return "PASSED"
            if required_review.get("state") == "UNAVAILABLE":
                detail = required_review.get("error", "AnythingLLM review unavailable")
                return "EXTERNAL: " + str(detail)[:1000]
            return "REPAIRABLE: " + _review_failure_detail(result)
        except Exception as exc:
            return ("EXTERNAL: " + str(exc)[:1000]) if "unavailable" in str(exc).lower() else "REPAIRABLE: " + str(exc)[:1000]


def commit_with_trusted_git(task: TaskSpec, result: WorkerResult, lease: WorkerLease) -> str:
    return GitCheckpointController(Path(lease.repository)).commit_worker_changes(task, result)
