"""Canonical, authority-free task records for the governed AI harness."""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Mapping


_TASK_ID = re.compile(r"^(?:FWQ-[0-9]{4}|FW-HARNESS-[0-9]{3})$")
_REQUIREMENT_ID = re.compile(r"^FW-[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*$")
_COMMIT = re.compile(r"^[0-9a-fA-F]{40,64}$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")


class HarnessTaskError(ValueError):
    """Task evidence or a requested transition violates the harness contract."""


class TaskStatus(str, Enum):
    QUEUED = "queued"
    READY = "ready"
    RUNNING = "running"
    AWAITING_VALIDATION = "awaiting_validation"
    AWAITING_REVIEW = "awaiting_review"
    REPAIR_REQUIRED = "repair_required"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


LEGACY_STATUS = {
    "BLOCKED": TaskStatus.BLOCKED,
    "READY": TaskStatus.READY,
    "IN_PROGRESS": TaskStatus.RUNNING,
    "REVIEW": TaskStatus.AWAITING_REVIEW,
    "REPAIR": TaskStatus.REPAIR_REQUIRED,
    "VALIDATED": TaskStatus.AWAITING_REVIEW,
    "DONE": TaskStatus.COMPLETED,
    "FAILED": TaskStatus.REJECTED,
}

ALLOWED_TRANSITIONS = {
    TaskStatus.QUEUED: frozenset({TaskStatus.READY, TaskStatus.BLOCKED, TaskStatus.CANCELLED}),
    TaskStatus.READY: frozenset({TaskStatus.RUNNING, TaskStatus.BLOCKED, TaskStatus.CANCELLED}),
    TaskStatus.RUNNING: frozenset({TaskStatus.AWAITING_VALIDATION, TaskStatus.REPAIR_REQUIRED, TaskStatus.BLOCKED, TaskStatus.CANCELLED}),
    TaskStatus.AWAITING_VALIDATION: frozenset({TaskStatus.AWAITING_REVIEW, TaskStatus.REPAIR_REQUIRED, TaskStatus.BLOCKED, TaskStatus.REJECTED}),
    TaskStatus.AWAITING_REVIEW: frozenset({TaskStatus.COMPLETED, TaskStatus.REPAIR_REQUIRED, TaskStatus.BLOCKED, TaskStatus.REJECTED}),
    TaskStatus.REPAIR_REQUIRED: frozenset({TaskStatus.READY, TaskStatus.RUNNING, TaskStatus.BLOCKED, TaskStatus.REJECTED, TaskStatus.CANCELLED}),
    TaskStatus.BLOCKED: frozenset({TaskStatus.READY, TaskStatus.REJECTED, TaskStatus.CANCELLED}),
    TaskStatus.COMPLETED: frozenset(),
    TaskStatus.REJECTED: frozenset(),
    TaskStatus.CANCELLED: frozenset(),
}


@dataclass(frozen=True)
class HarnessTask:
    """Versioned task evidence. It contains no method that executes model output."""

    task_id: str
    requirement_id: str
    title: str
    description: str
    status: TaskStatus
    priority: int
    assigned_role: str
    assigned_model: str | None
    repository: str
    created_at: str
    parent_task: str | None = None
    dependencies: tuple[str, ...] = ()
    authorized_capabilities: tuple[str, ...] = ()
    worktree: str | None = None
    relevant_files: tuple[str, ...] = ()
    expected_outputs: tuple[str, ...] = ()
    validation_requirements: tuple[str, ...] = ()
    retry_count: int = 0
    retry_limit: int = 0
    token_budget: int = 0
    cost_budget: float = 0.0
    started_at: str | None = None
    completed_at: str | None = None
    blocking_reason: str | None = None
    evidence_references: tuple[str, ...] = ()
    resulting_commit: str | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        _validate(self)


def _timestamp(value: str | None, field: str) -> None:
    if value is None:
        return
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise HarnessTaskError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise HarnessTaskError(f"{field} must include a timezone")


def _relative_paths(values: tuple[str, ...], field: str) -> None:
    if len(set(values)) != len(values):
        raise HarnessTaskError(f"{field} must not contain duplicates")
    for value in values:
        path = Path(value)
        if not value or path.is_absolute() or ".." in path.parts:
            raise HarnessTaskError(f"{field} must contain bounded relative paths")


def _validate(task: HarnessTask) -> None:
    if task.schema_version != 1:
        raise HarnessTaskError("unsupported task schema version")
    if not _TASK_ID.fullmatch(task.task_id):
        raise HarnessTaskError("invalid task ID")
    if not _REQUIREMENT_ID.fullmatch(task.requirement_id):
        raise HarnessTaskError("invalid requirement ID")
    if task.parent_task is not None and (not _TASK_ID.fullmatch(task.parent_task) or task.parent_task == task.task_id):
        raise HarnessTaskError("invalid parent task")
    if len(set(task.dependencies)) != len(task.dependencies) or any(not _TASK_ID.fullmatch(value) or value == task.task_id for value in task.dependencies):
        raise HarnessTaskError("invalid task dependencies")
    if not task.title.strip() or not task.description.strip() or not task.assigned_role.strip() or not task.repository.strip():
        raise HarnessTaskError("task identity, description, role, and repository are required")
    if task.priority < 0 or task.retry_count < 0 or task.retry_limit < 0 or task.retry_count > task.retry_limit:
        raise HarnessTaskError("priority and retry values must be bounded non-negative integers")
    if task.token_budget < 0 or not math.isfinite(task.cost_budget) or task.cost_budget < 0:
        raise HarnessTaskError("task budgets must be finite and non-negative")
    if len(set(task.authorized_capabilities)) != len(task.authorized_capabilities) or any(not _CAPABILITY.fullmatch(value) for value in task.authorized_capabilities):
        raise HarnessTaskError("authorized capabilities are malformed or duplicated")
    _relative_paths(task.relevant_files, "relevant_files")
    _relative_paths(task.evidence_references, "evidence_references")
    if any(not value.strip() for value in task.expected_outputs + task.validation_requirements):
        raise HarnessTaskError("output and validation entries must be non-empty")
    for value, field in ((task.created_at, "created_at"), (task.started_at, "started_at"), (task.completed_at, "completed_at")):
        _timestamp(value, field)
    if task.resulting_commit is not None and not _COMMIT.fullmatch(task.resulting_commit):
        raise HarnessTaskError("resulting commit must be an exact Git hash")
    if task.status == TaskStatus.BLOCKED and not (task.blocking_reason and task.blocking_reason.strip()):
        raise HarnessTaskError("blocked tasks require a blocking reason")
    if task.status != TaskStatus.BLOCKED and task.blocking_reason is not None:
        raise HarnessTaskError("blocking reason is valid only for blocked tasks")
    if task.status == TaskStatus.RUNNING and task.started_at is None:
        raise HarnessTaskError("running tasks require a started timestamp")
    if task.status in {TaskStatus.COMPLETED, TaskStatus.REJECTED, TaskStatus.CANCELLED} and task.completed_at is None:
        raise HarnessTaskError("terminal tasks require a completed timestamp")


def transition_task(task: HarnessTask, target: TaskStatus, *, occurred_at: str, blocking_reason: str | None = None, resulting_commit: str | None = None) -> HarnessTask:
    """Apply one controller-owned transition after validating exact evidence."""
    if not isinstance(target, TaskStatus) or target not in ALLOWED_TRANSITIONS[task.status]:
        raise HarnessTaskError(f"transition {task.status.value} -> {getattr(target, 'value', target)} is not allowed")
    _timestamp(occurred_at, "occurred_at")
    started = task.started_at or (occurred_at if target == TaskStatus.RUNNING else None)
    completed = occurred_at if target in {TaskStatus.COMPLETED, TaskStatus.REJECTED, TaskStatus.CANCELLED} else None
    commit = resulting_commit if resulting_commit is not None else task.resulting_commit
    if target == TaskStatus.COMPLETED and commit is None:
        raise HarnessTaskError("completed tasks require an exact resulting commit")
    return replace(task, status=target, started_at=started, completed_at=completed, blocking_reason=blocking_reason if target == TaskStatus.BLOCKED else None, resulting_commit=commit)


def legacy_status(value: str) -> TaskStatus:
    """Map persisted legacy state explicitly; unknown values fail closed."""
    try:
        return LEGACY_STATUS[value]
    except (KeyError, TypeError) as exc:
        raise HarnessTaskError("unknown legacy task status") from exc


def task_to_record(task: HarnessTask) -> dict[str, Any]:
    """Return a JSON-compatible, versioned persistence record."""
    record = asdict(task)
    record["status"] = task.status.value
    return record


def task_from_record(record: Mapping[str, Any]) -> HarnessTask:
    """Load one exact canonical record; missing or unknown fields fail closed."""
    fields = set(HarnessTask.__dataclass_fields__)
    if not isinstance(record, Mapping) or set(record) != fields:
        raise HarnessTaskError("canonical task record has an invalid field set")
    payload = dict(record)
    try:
        payload["status"] = TaskStatus(payload["status"])
        for field in ("dependencies", "authorized_capabilities", "relevant_files", "expected_outputs", "validation_requirements", "evidence_references"):
            if not isinstance(payload[field], (list, tuple)):
                raise TypeError(field)
            payload[field] = tuple(payload[field])
        return HarnessTask(**payload)
    except (TypeError, ValueError) as exc:
        if isinstance(exc, HarnessTaskError):
            raise
        raise HarnessTaskError("canonical task record is malformed") from exc


def from_legacy_task(spec: Mapping[str, Any], runtime: Mapping[str, Any], *, created_at: str, repository: str) -> HarnessTask:
    """Adapt existing TaskSpec/queue dictionaries without trusting extra fields."""
    required = {"task_id", "requirement", "description"}
    if not required.issubset(spec) or "state" not in runtime:
        raise HarnessTaskError("legacy task evidence is incomplete")
    allowed = tuple(spec.get("allowed_paths", ()))
    acceptance = tuple(spec.get("acceptance", ()))
    tests = tuple(spec.get("test_command", ()))
    status = legacy_status(runtime["state"])
    terminal = status in {TaskStatus.COMPLETED, TaskStatus.REJECTED, TaskStatus.CANCELLED}
    return HarnessTask(
        task_id=str(spec["task_id"]), requirement_id=str(spec["requirement"]),
        title=str(spec.get("title") or spec["description"]), description=str(spec["description"]),
        status=status, priority=int(spec.get("priority", 0)),
        assigned_role=str(spec.get("worker_type", "CODEX")), assigned_model=None,
        repository=repository, created_at=created_at, parent_task=spec.get("parent_task"),
        dependencies=tuple(spec.get("dependencies", ())), authorized_capabilities=tuple(spec.get("authorized_capabilities", ())),
        relevant_files=allowed, expected_outputs=acceptance, validation_requirements=(" ".join(tests),) if tests else (),
        retry_count=int(runtime.get("attempts", 0)), retry_limit=int(spec.get("retry_budget", 0)),
        started_at=created_at if runtime.get("state") == "IN_PROGRESS" else None,
        completed_at=created_at if terminal else None,
        blocking_reason=str(runtime.get("blocker")) if runtime.get("state") == "BLOCKED" and runtime.get("blocker") else ("legacy blocked task" if runtime.get("state") == "BLOCKED" else None),
        resulting_commit=spec.get("review_commit"),
    )
