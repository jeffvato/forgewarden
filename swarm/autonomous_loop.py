"""Durable, bounded ForgeWarden continuation controller.

This module owns orchestration state; worker callbacks only perform the bounded
operation described by the lease and return evidence to this controller.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping

from .work_checkpoint import WorkUnitCheckpoint, write_checkpoint
from .policy_gate import validate_safety_evidence
from .review_handoff import ReviewResult, complete_review_cycle, create_review_cycle, record_review

_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_TASK = re.compile(r"^FWQ-[0-9]{4}$")
_TERMINAL = {"DONE", "FAILED"}


class AutonomousLoopError(RuntimeError):
    """The durable loop cannot safely continue."""


@dataclass(frozen=True)
class TaskSpec:
    task_id: str
    requirement: str
    description: str
    dependencies: tuple[str, ...] = ()
    priority: int = 0
    allowed_paths: tuple[str, ...] = ()
    acceptance: tuple[str, ...] = ()
    retry_budget: int = 1
    worker_type: str = "CODEX"
    target_path: str | None = None
    expected_behavior: str = "implement the approved task"
    failing_assertion: str = "the approved regression assertion"
    test_command: tuple[str, ...] = ()
    initial_state: str = "READY"
    review_disposition: str | None = None
    blocker_resolved: bool = False
    blocker_external: bool = False
    authorized: bool = True
    review_commit: str | None = None
    review_context: str = "ForgeWarden exact-commit review"


def progress_queue(tasks: dict[str, TaskSpec], state: dict[str, Any], *, review_resolver: Callable[[TaskSpec, Mapping[str, Any]], str] | None = None, blocker_resolver: Callable[[TaskSpec, Mapping[str, Any]], bool] | None = None, plan_tasks: tuple[TaskSpec, ...] = ()) -> tuple[str, ...]:
    """Advance review/blocker states and enqueue the next authorized Core task."""
    transitions: list[str] = []
    for task in tasks.values():
        state["queued_tasks"].setdefault(task.task_id, {"state": task.initial_state, "attempts": 0})
    changed = True
    while changed:
        changed = False
        for task in tuple(tasks.values()):
            record = state["queued_tasks"][task.task_id]
            current = record["state"]
            if current == "REVIEW":
                disposition = review_resolver(task, record) if review_resolver else task.review_disposition
                if disposition == "PASSED":
                    record["state"] = "DONE"
                    if task.task_id not in state["completed_tasks"]:
                        state["completed_tasks"].append(task.task_id)
                    transitions.append(f"{task.task_id}:REVIEW->DONE")
                    changed = True
                elif disposition == "REPAIRABLE":
                    record["state"] = "REPAIR"
                    repair_id = _next_repair_id(tasks)
                    repair = replace(task, task_id=repair_id, description=f"Repair findings for {task.task_id}: {task.description}", dependencies=(), initial_state="READY", review_disposition=None, blocker_resolved=False, blocker_external=False)
                    tasks[repair_id] = repair
                    state.setdefault("task_specs", {})[repair_id] = asdict(repair)
                    state["queued_tasks"][repair_id] = {"state": "READY", "attempts": 0}
                    transitions.append(f"{task.task_id}:REVIEW->REPAIR:{repair_id}")
                    changed = True
                elif disposition == "EXTERNAL":
                    record["blocker_external"] = True
                    record["blocker"] = "required review resource unavailable"
                    transitions.append(f"{task.task_id}:REVIEW->EXTERNAL_BLOCKER")
            elif current == "BLOCKED":
                dependencies_done = all(state["queued_tasks"].get(dep, {}).get("state") == "DONE" for dep in task.dependencies)
                resolved = blocker_resolver(task, record) if blocker_resolver else task.blocker_resolved
                if dependencies_done and resolved:
                    record["state"] = "READY"
                    transitions.append(f"{task.task_id}:BLOCKED->READY")
                    changed = True
        if changed:
            continue
        if any(record["state"] == "READY" for record in state["queued_tasks"].values()):
            break
        for candidate in sorted(plan_tasks, key=lambda item: (item.priority, item.task_id)):
            if candidate.authorized and candidate.task_id not in tasks and candidate.requirement.startswith("Core "):
                tasks[candidate.task_id] = candidate
                state.setdefault("task_specs", {})[candidate.task_id] = asdict(candidate)
                state["queued_tasks"][candidate.task_id] = {"state": "READY", "attempts": 0}
                transitions.append(f"PLAN->READY:{candidate.task_id}")
                changed = True
                break
    return tuple(transitions)


def _next_repair_id(tasks: Mapping[str, TaskSpec]) -> str:
    used = {int(task_id.split("-")[1]) for task_id in tasks if task_id.startswith("FWQ-") and task_id[4:].isdigit()}
    value = max(used or {0}) + 1
    return f"FWQ-{value:04d}"


@dataclass(frozen=True)
class WorkerLease:
    lease_id: str
    task_id: str
    session_id: str
    repository: str
    allowed_paths: tuple[str, ...]
    operation: str
    commands: tuple[str, ...]
    expires_at: float
    deployment: str = "DISABLED"
    dry_run: bool = True
    authority_expansion: bool = False


@dataclass(frozen=True)
class WorkerResult:
    candidate_commit: str | None
    changed_files: tuple[str, ...]
    tests: tuple[str, ...]
    summary: str = ""


def _now() -> float:
    return time.time()


def _validate_task(task: TaskSpec) -> None:
    if not _TASK.fullmatch(task.task_id):
        raise AutonomousLoopError("invalid task ID")
    if task.priority < 0 or task.retry_budget < 0:
        raise AutonomousLoopError("task priority and retry budget must be non-negative")
    if any(not path or Path(path).is_absolute() or ".." in Path(path).parts for path in task.allowed_paths):
        raise AutonomousLoopError("task allowed paths must be relative and contained")
    if any(dep == task.task_id for dep in task.dependencies):
        raise AutonomousLoopError("task cannot depend on itself")


class AutonomousOrchestrator:
    """Persisted queue runner that continues until work or authority ends."""

    def __init__(self, state_path: Path, repository: Path, tasks: tuple[TaskSpec, ...], *, lease_seconds: float = 300.0, checkpoint_path: Path | None = None, audit_path: Path | None = None, session_id: str | None = None):
        self.state_path = Path(state_path)
        self.repository = Path(repository).resolve()
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path else self.state_path.with_name("work-checkpoint.json")
        self.audit_path = Path(audit_path) if audit_path else self.state_path.with_name("execution-log.jsonl")
        self.lease_seconds = lease_seconds
        self.tasks = {task.task_id: task for task in tasks}
        if len(self.tasks) != len(tasks) or any(task.task_id != key for key, task in self.tasks.items()):
            raise AutonomousLoopError("task IDs must be unique")
        for task in tasks:
            _validate_task(task)
        for task in tasks:
            if any(dep not in self.tasks for dep in task.dependencies):
                raise AutonomousLoopError(f"unknown dependency for {task.task_id}")
        self.session_id = session_id or uuid.uuid4().hex

    def _write(self, payload: Mapping[str, Any]) -> None:
        path = self.state_path
        if not path.is_absolute() or any(parent.is_symlink() for parent in (path.parent, *path.parent.parents)):
            raise AutonomousLoopError("unsafe durable state path")
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            with temporary.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def _log(self, event: str, **data: Any) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"timestamp": _now(), "session_id": self.session_id, "event": event, **data}, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def _initial(self) -> dict[str, Any]:
        return {"version": 1, "session_id": self.session_id, "phase": "ForgeWarden Core", "milestone": None, "current_work_package": None, "task_specs": {task_id: asdict(task) for task_id, task in self.tasks.items()}, "queued_tasks": {task_id: {"state": task.initial_state, "attempts": 0} for task_id, task in self.tasks.items()}, "active_task": None, "completed_tasks": [], "failed_tasks": [], "retry_count": {}, "worker_assigned": None, "worker_lease": None, "repository_head_before": None, "repository_head_after": None, "test_results": [], "reviewer_result": None, "acceptance_result": None, "unresolved_blockers": [], "next_action": "select next eligible task", "timestamps": {"created_at": _now(), "updated_at": _now()}, "stop_reason": None, "dry_run": True, "deployment": "DISABLED", "kill_switch": "ENGAGED"}

    def _load(self) -> dict[str, Any]:
        if not self.state_path.exists():
            state = self._initial()
            self._write(state)
            self._log("run_initialized")
            return state
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AutonomousLoopError("durable execution state is unreadable") from exc
        if not isinstance(state, dict) or state.get("version") != 1 or state.get("dry_run") is not True or state.get("deployment") != "DISABLED":
            raise AutonomousLoopError("durable state violates safety contract")
        for task_id, payload in state.get("task_specs", {}).items():
            if task_id not in self.tasks and isinstance(payload, dict):
                for key in ("dependencies", "allowed_paths", "acceptance", "test_command"):
                    payload[key] = tuple(payload.get(key, ()))
                self.tasks[task_id] = TaskSpec(**payload)
        if set(state.get("queued_tasks", {})) != set(self.tasks) or not isinstance(state.get("completed_tasks"), list) or not isinstance(state.get("failed_tasks"), list):
            raise AutonomousLoopError("durable state task queue does not match the approved queue")
        if state.get("session_id") != self.session_id and self.session_id:
            self.session_id = str(state["session_id"])
        self._recover_stale(state)
        return state

    def status(self) -> dict[str, Any]:
        """Return validated durable state without selecting or dispatching work."""
        state = self._load()
        return json.loads(json.dumps(state, sort_keys=True))

    def _enforce_safety(self) -> None:
        validate_safety_evidence(
            {"mode": "DRY_RUN", "deployment": "DISABLED", "kill_switch": "ENGAGED", "mutation_allowed": False},
            require_kill_switch=True,
        )

    def _recover_stale(self, state: dict[str, Any]) -> None:
        lease = state.get("worker_lease")
        if lease and float(lease.get("expires_at", 0)) <= _now():
            task_id = state.get("active_task")
            if task_id in self.tasks:
                state["queued_tasks"][task_id]["state"] = "READY"
                state["queued_tasks"][task_id]["attempts"] = state["queued_tasks"][task_id].get("attempts", 0) + 1
            state["active_task"] = None
            state["worker_assigned"] = None
            state["worker_lease"] = None
            state["next_action"] = "recovered expired worker lease"
            state["timestamps"]["updated_at"] = _now()
            self._write(state)
            self._log("stale_lease_recovered", task_id=task_id)

    def _select(self, state: Mapping[str, Any]) -> TaskSpec | None:
        ready = []
        for task in self.tasks.values():
            record = state["queued_tasks"][task.task_id]
            if record["state"] != "READY":
                continue
            if all(state["queued_tasks"][dep]["state"] == "DONE" for dep in task.dependencies):
                ready.append(task)
        return min(ready, key=lambda item: (item.priority, item.task_id)) if ready else None

    def _checkpoint(self, task: TaskSpec, state: Mapping[str, Any], *, starting: str, candidate: str | None, accepted: str | None, validation: tuple[str, ...], reviews: tuple[str, ...], next_action: str) -> None:
        write_checkpoint(self.checkpoint_path, WorkUnitCheckpoint("ForgeWarden Core", task.task_id, starting, candidate, accepted, (), validation, reviews[0] if reviews else "not started", reviews[1] if len(reviews) > 1 else "not started", (), None, next_action))

    def run(self, *, dispatch: Callable[[TaskSpec, WorkerLease], WorkerResult], validate: Callable[[TaskSpec, WorkerResult], bool], commit: Callable[[TaskSpec, WorkerResult], str], review: Callable[[TaskSpec, str, WorkerLease], tuple[str, ...]], repair: Callable[[TaskSpec, WorkerResult, WorkerLease], WorkerResult] | None = None, max_steps: int | None = None, authorized: Callable[[], bool] | None = None, review_resolver: Callable[[TaskSpec, Mapping[str, Any]], str] | None = None, blocker_resolver: Callable[[TaskSpec, Mapping[str, Any]], bool] | None = None, plan_tasks: tuple[TaskSpec, ...] = ()) -> dict[str, Any]:
        self._enforce_safety()
        state = self._load()
        steps = 0
        while max_steps is None or steps < max_steps:
            if authorized is not None and not authorized():
                state["stop_reason"] = "SUPERVISOR_TERMINATED"
                state["next_action"] = "resume only after explicit authorization"
                break
            transitions = progress_queue(self.tasks, state, review_resolver=review_resolver, blocker_resolver=blocker_resolver, plan_tasks=plan_tasks)
            if transitions:
                state["next_action"] = "queue progression: " + ", ".join(transitions)
                state["timestamps"]["updated_at"] = _now()
                self._write(state)
                self._log("queue_progressed", transitions=transitions)
            task = self._select(state)
            if task is None:
                unresolved = [task_id for task_id, record in state["queued_tasks"].items() if record["state"] not in {"DONE", "FAILED"}]
                if unresolved and all(state["queued_tasks"][task_id].get("blocker_external") for task_id in unresolved):
                    state["stop_reason"] = "REQUIRED_RESOURCE_UNAVAILABLE"
                    state["next_action"] = "restore review resource and resume queue evaluation"
                elif unresolved:
                    state["stop_reason"] = "QUEUE_REQUIRES_REEVALUATION"
                    state["next_action"] = "resolve internal queue evidence or derive authorized Core work"
                else:
                    state["stop_reason"] = "ALL_ACTIVE_WORK_COMPLETE"
                    state["next_action"] = "await next approved queue item"
                break
            record = state["queued_tasks"][task.task_id]
            attempts = int(record.get("attempts", 0))
            lease = WorkerLease(uuid.uuid4().hex, task.task_id, self.session_id, str(self.repository), task.allowed_paths, "IMPLEMENT_AND_TEST", ("approved deterministic test commands",), _now() + self.lease_seconds)
            state.update({"active_task": task.task_id, "current_work_package": task.task_id, "worker_assigned": task.worker_type, "worker_lease": asdict(lease), "repository_head_before": state.get("repository_head_after"), "next_action": "dispatch bounded worker"})
            record["state"] = "IN_PROGRESS"
            state["timestamps"]["updated_at"] = _now()
            self._write(state); self._log("worker_dispatched", task_id=task.task_id, lease_id=lease.lease_id)
            try:
                result = dispatch(task, lease)
                if not isinstance(result, WorkerResult) or (result.candidate_commit is not None and not _SHA.fullmatch(result.candidate_commit)):
                    raise AutonomousLoopError("worker returned invalid candidate evidence")
                if any(not file or Path(file).is_absolute() or ".." in Path(file).parts for file in result.changed_files):
                    raise AutonomousLoopError("worker returned an escaping changed path")
                if task.allowed_paths and any(not any(file == allowed or file.startswith(allowed.rstrip("/") + "/") for allowed in task.allowed_paths) for file in result.changed_files):
                    raise AutonomousLoopError("worker changed a path outside its lease")
                if not validate(task, result):
                    raise AutonomousLoopError("deterministic validation failed")
                candidate = commit(task, result)
                if not _SHA.fullmatch(candidate) or (result.candidate_commit is not None and candidate.lower() != result.candidate_commit.lower()):
                    raise AutonomousLoopError("trusted commit did not match worker candidate")
                review_payload = review(task, candidate, lease)
                if isinstance(review_payload, Mapping):
                    cycle = create_review_cycle(candidate)
                    for value in review_payload.values():
                        if not isinstance(value, ReviewResult):
                            raise AutonomousLoopError("reviewer returned invalid exact-commit evidence")
                        cycle = record_review(cycle, value)
                    complete_review_cycle(cycle)
                    reviews = tuple(f"{role}:{value.disposition}:{value.severity}" for role, value in sorted(cycle.reviews.items()))
                    reviews_approved = True
                else:
                    reviews = tuple(review_payload)
                    if len(reviews) < 2:
                        raise AutonomousLoopError("independent reviewer results are incomplete")
                    reviews_approved = False
                if repair and any(item.upper() not in {"APPROVED", "APPROVE", "LOW"} for item in reviews):
                    if attempts >= task.retry_budget:
                        raise AutonomousLoopError("review repair budget exhausted")
                    result = repair(task, result, lease)
                    if not validate(task, result):
                        raise AutonomousLoopError("repair validation failed")
                    candidate = commit(task, result)
                    if not _SHA.fullmatch(candidate) or (result.candidate_commit is not None and candidate.lower() != result.candidate_commit.lower()):
                        raise AutonomousLoopError("repair commit did not match candidate")
                    reviews = tuple(review(task, candidate, lease))
                if not reviews_approved and any(item.upper() not in {"APPROVED", "APPROVE", "LOW"} for item in reviews):
                    raise AutonomousLoopError("review rejected candidate")
                self._checkpoint(task, state, starting=state.get("repository_head_before") or candidate, candidate=candidate, accepted=candidate, validation=result.tests, reviews=reviews, next_action="select next eligible task")
                record["state"] = "DONE"; state["completed_tasks"].append(task.task_id); state["repository_head_after"] = candidate; state["test_results"] = list(result.tests); state["reviewer_result"] = list(reviews); state["acceptance_result"] = "PASSED"
                self._log("task_accepted", task_id=task.task_id, candidate_commit=candidate)
            except Exception as exc:
                record["attempts"] = attempts + 1; state["retry_count"][task.task_id] = attempts + 1
                if attempts < task.retry_budget:
                    record["state"] = "READY"; state["next_action"] = "retry failed task"
                else:
                    record["state"] = "FAILED"; state["failed_tasks"].append(task.task_id); state["unresolved_blockers"].append(f"{task.task_id}: {str(exc)[:500]}"); state["next_action"] = "continue with independent eligible work"
                self._log("task_failed", task_id=task.task_id, error=str(exc)[:500], retry=attempts < task.retry_budget)
            finally:
                state["active_task"] = None; state["worker_assigned"] = None; state["worker_lease"] = None; state["timestamps"]["updated_at"] = _now(); self._write(state)
                steps += 1
        if state.get("stop_reason") is None and max_steps is not None and steps >= max_steps:
            state["stop_reason"] = "STEP_BOUND_REACHED"; state["next_action"] = "resume durable run"
        state["timestamps"]["updated_at"] = _now(); self._write(state); self._log("run_checkpointed", stop_reason=state.get("stop_reason"), steps=steps)
        return state


class GitCheckpointController:
    """Trusted Git owner for an isolated worker checkout."""

    def __init__(self, repository: Path):
        self.repository = Path(repository).resolve()
        if not self.repository.is_dir() or self.repository.is_symlink():
            raise AutonomousLoopError("Git checkpoint repository must be a regular directory")

    def _git(self, *args: str) -> str:
        result = subprocess.run(["git", "-C", str(self.repository), *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode:
            raise AutonomousLoopError(f"Git operation failed: {result.stderr.strip()[:500]}")
        return result.stdout.strip()

    def head(self) -> str:
        value = self._git("rev-parse", "HEAD")
        if not _SHA.fullmatch(value):
            raise AutonomousLoopError("Git HEAD is not a full commit SHA")
        return value

    def ensure_clean(self) -> None:
        status = subprocess.run(["git", "-C", str(self.repository), "status", "--porcelain", "--untracked-files=all"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if status.returncode:
            raise AutonomousLoopError("repository is not a valid Git checkout")
        if status.stdout.strip():
            raise AutonomousLoopError("repository worktree must be clean before autonomous execution")

    def commit_worker_changes(self, task: TaskSpec, result: WorkerResult) -> str:
        if not result.changed_files:
            raise AutonomousLoopError("worker produced no changed files")
        allowed = task.allowed_paths
        for file in result.changed_files:
            path = Path(file)
            if path.is_absolute() or ".." in path.parts or (allowed and not any(file == item or file.startswith(item.rstrip("/") + "/") for item in allowed)):
                raise AutonomousLoopError("worker changed a path outside the trusted Git scope")
        status = subprocess.run(["git", "-C", str(self.repository), "status", "--porcelain", "--untracked-files=all"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if status.returncode:
            raise AutonomousLoopError(f"Git status failed: {status.stderr.strip()[:500]}")
        actual = tuple(sorted(filter(None, status.stdout.splitlines())))
        actual_paths = tuple(sorted(line[3:] for line in actual if len(line) >= 4))
        if tuple(sorted(result.changed_files)) != actual_paths:
            raise AutonomousLoopError("worker evidence does not match the actual Git worktree")
        self._git("add", "--", *result.changed_files)
        self._git("-c", "user.name=ForgeWarden", "-c", "user.email=forgewarden@localhost", "commit", "-m", f"Accept {task.task_id}")
        return self.head()
