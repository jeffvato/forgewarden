"""Trusted self-hosting bridge for the canonical governed harness.

This module composes existing execution owners.  It does not grant workers Git,
validation, review, policy, credential, deployment, or continuation authority.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Mapping

from .autonomous_adapters import CodexTaskAdapter, ExactReviewAdapter, run_deterministic_tests
from .autonomous_loop import GitCheckpointController, TaskSpec, WorkerLease, WorkerResult
from .harness_controller import GovernedHarnessController, HarnessRunResult
from .harness_task import HarnessTask
from .harness_worker import InvocationPlan, WorkerOutput, WorkerRole, WorkerTransport
from .review_handoff import ReviewResult


class HarnessRuntimeError(ValueError):
    """The self-hosted runtime cannot safely compose its trusted owners."""


WorkerDispatch = Callable[[TaskSpec, WorkerLease], WorkerResult]
Validator = Callable[[TaskSpec, WorkerResult, Path], bool]
Committer = Callable[[TaskSpec, WorkerResult, WorkerLease], str]
Reviewer = Callable[[TaskSpec, str, WorkerLease], Mapping[str, ReviewResult]]


class SelfHostedHarnessRuntime:
    """Bridge canonical controller callbacks to existing trusted adapters."""

    def __init__(
        self, *, repository: Path, task_specs: tuple[TaskSpec, ...],
        worker_dispatch: WorkerDispatch, validator: Validator,
        committer: Committer, reviewer: Reviewer,
    ) -> None:
        supplied_repository = Path(repository)
        if supplied_repository.is_symlink() or any(parent.is_symlink() for parent in supplied_repository.parents):
            raise HarnessRuntimeError("self-hosted repository is unavailable or symlinked")
        self.repository = supplied_repository.resolve()
        if not self.repository.is_dir():
            raise HarnessRuntimeError("self-hosted repository is unavailable or symlinked")
        if not task_specs or any(not isinstance(item, TaskSpec) for item in task_specs):
            raise HarnessRuntimeError("validated task specifications are required")
        self.specs = {item.task_id: item for item in task_specs}
        if len(self.specs) != len(task_specs):
            raise HarnessRuntimeError("self-hosted task IDs must be unique")
        if not all(callable(item) for item in (worker_dispatch, validator, committer, reviewer)):
            raise HarnessRuntimeError("trusted self-hosted adapters are unavailable")
        self.worker_dispatch = worker_dispatch
        self.validator = validator
        self.committer = committer
        self.reviewer = reviewer
        self._results: dict[str, WorkerResult] = {}

    @classmethod
    def from_existing_adapters(
        cls, *, repository: Path, task_specs: tuple[TaskSpec, ...],
        codex_executable: str, codex_schema: Path, review_context: str,
        allow_external_review: bool = False,
    ) -> "SelfHostedHarnessRuntime":
        """Construct the bridge from the existing Codex/Git/review owners."""
        codex = CodexTaskAdapter(codex_schema, codex_executable)
        git = GitCheckpointController(repository)
        git.ensure_clean()
        review = ExactReviewAdapter(
            review_context, allow_external_review=allow_external_review,
            reviewers=("CLAUDE",),
        )
        return cls(
            repository=repository,
            task_specs=task_specs,
            worker_dispatch=codex.dispatch,
            validator=lambda task, result, repo: run_deterministic_tests(task, result, repo),
            committer=lambda task, result, lease: git.commit_worker_changes(task, result),
            reviewer=lambda task, commit, lease: review.review(task, commit, lease),
        )

    def _lease(self, task: HarnessTask, plan: InvocationPlan, session_id: str) -> WorkerLease:
        spec = self.specs.get(task.task_id)
        if spec is None:
            raise HarnessRuntimeError("canonical task is absent from the authoritative execution set")
        if (
            plan.task_id != task.task_id or plan.role is not WorkerRole.CODE_WRITER
            or plan.transport is not WorkerTransport.CLI or not plan.mutation_allowed
            or plan.deployment != "DISABLED" or plan.credential_handle is not None
            or tuple(task.relevant_files) != tuple(spec.allowed_paths)
        ):
            raise HarnessRuntimeError("canonical invocation plan violates self-hosted scope")
        return WorkerLease(
            f"self-hosted-{task.task_id.lower()}", task.task_id, session_id,
            str(self.repository), tuple(spec.allowed_paths), "WRITE",
            tuple(spec.test_command), time.time() + 300,
            deployment="DISABLED", dry_run=True, authority_expansion=False,
        )

    def run(
        self, controller: GovernedHarnessController, *, max_steps: int | None = None,
        authorized: Callable[[], bool] | None = None,
    ) -> HarnessRunResult:
        """Run existing owners through the canonical controller and durable scheduler."""
        if not isinstance(controller, GovernedHarnessController):
            raise HarnessRuntimeError("canonical governed controller is required")
        if set(controller.tasks) != set(self.specs):
            raise HarnessRuntimeError("controller and execution task sets do not match")

        def execute(plan: InvocationPlan) -> Mapping[str, object]:
            task = controller.tasks[plan.task_id]
            lease = self._lease(task, plan, controller.orchestrator.session_id)
            result = self.worker_dispatch(self.specs[task.task_id], lease)
            if not isinstance(result, WorkerResult):
                raise HarnessRuntimeError("Codex adapter returned an invalid result")
            self._results[task.task_id] = result
            return {
                "task_id": task.task_id,
                "worker_id": plan.worker_id,
                "context_sha256": plan.context_sha256,
                "candidate_commit": result.candidate_commit,
                "changed_files": list(result.changed_files),
                "attempted_actions": ["bounded_source_edit"],
                "denied_actions": ["git", "policy", "credentials", "deployment"],
                "summary": result.summary or "bounded worker result",
            }

        def validate(task: HarnessTask, _output: WorkerOutput) -> bool:
            return self.validator(self.specs[task.task_id], self._results[task.task_id], self.repository)

        def commit(task: HarnessTask, _output: WorkerOutput) -> str:
            lease = WorkerLease(
                f"trusted-git-{task.task_id.lower()}", task.task_id,
                controller.orchestrator.session_id, str(self.repository),
                tuple(self.specs[task.task_id].allowed_paths), "COMMIT", (),
                time.time() + 300,
            )
            return self.committer(self.specs[task.task_id], self._results[task.task_id], lease)

        def review(task: HarnessTask, commit_sha: str) -> ReviewResult:
            lease = WorkerLease(
                f"trusted-review-{task.task_id.lower()}", task.task_id,
                controller.orchestrator.session_id, str(self.repository),
                tuple(self.specs[task.task_id].allowed_paths), "REVIEW", (),
                time.time() + 300,
            )
            results = self.reviewer(self.specs[task.task_id], commit_sha, lease)
            if set(results) != {"CLAUDE"} or not isinstance(results["CLAUDE"], ReviewResult):
                raise HarnessRuntimeError("required exact Claude review is missing")
            return results["CLAUDE"]

        return controller.run(
            worker_executor=execute, validator=validate, committer=commit,
            reviewer=review, max_steps=max_steps, authorized=authorized,
        )
