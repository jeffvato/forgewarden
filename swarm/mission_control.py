"""Bounded read-only Mission Control projection for FW-HARNESS."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping

from .harness_context import BudgetAdmission, BudgetUsage
from .harness_task import HarnessTask, TaskStatus
from .harness_worker import WorkerRegistration


_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")
_SECRET = re.compile(r"(?i)(bearer\s+\S+|sk-[A-Za-z0-9_-]{8,}|AIza[A-Za-z0-9_-]{8,}|ya29\.[A-Za-z0-9._-]{8,}|api[_-]?key\s*[:=]|access[_-]?token\s*[:=]|client[_-]?secret\s*[:=])")


class MissionControlError(ValueError):
    """Canonical harness state cannot be projected safely."""


@dataclass(frozen=True)
class MissionTaskView:
    task_id: str
    requirement_id: str
    title: str
    status: str
    priority: int
    dependencies: tuple[str, ...]
    blocker: str | None
    relevant_files: tuple[str, ...]
    retry_count: int
    retry_limit: int
    resulting_commit: str | None


@dataclass(frozen=True)
class MissionControlView:
    schema_version: int
    tenant_id: str
    phase: str
    current_requirement: str | None
    current_task: str | None
    active_worker: str | None
    active_provider: str | None
    active_model: str | None
    task_queue: tuple[MissionTaskView, ...]
    validation_status: str
    review_status: str
    budget_used: BudgetUsage | None
    recent_decisions: tuple[str, ...]
    current_commit: str | None
    next_task: str | None
    kill_switch: str
    deployment: str = "DISABLED"
    mutation_allowed: bool = False


def project_mission_control(
    tasks: tuple[HarnessTask, ...], *, tenant_id: str, task_tenants: Mapping[str, str],
    current_task: str | None, worker: WorkerRegistration | None = None,
    budget: BudgetAdmission | None = None, validation_status: str = "not_started",
    review_status: str = "not_started", recent_decisions: tuple[str, ...] = (),
    current_commit: str | None = None, next_task: str | None = None,
    kill_switch: str = "ENGAGED",
) -> MissionControlView:
    """Create one immutable operator view without changing canonical state."""
    if not _TENANT.fullmatch(tenant_id) or not tasks or len(tasks) > 1024 or any(not isinstance(task, HarnessTask) for task in tasks):
        raise MissionControlError("Mission Control input is malformed or excessive")
    records = {task.task_id: task for task in tasks}
    if len(records) != len(tasks) or set(task_tenants) != set(records) or any(value != tenant_id for value in task_tenants.values()):
        raise MissionControlError("Mission Control task tenancy is incomplete or mismatched")
    if any(dependency not in records for task in tasks for dependency in task.dependencies):
        raise MissionControlError("Mission Control dependency is outside the canonical queue")
    visible_task_text = tuple(value for task in tasks for value in (task.title, task.blocking_reason) if value is not None)
    if any(len(value.encode()) > 1000 or _SECRET.search(value) for value in visible_task_text):
        raise MissionControlError("operator task state is excessive or secret-bearing")
    if current_task is not None and current_task not in records:
        raise MissionControlError("current task is not in the canonical queue")
    if next_task is not None and next_task not in records:
        raise MissionControlError("next task is not in the canonical queue")
    if current_commit is not None and not _SHA.fullmatch(current_commit):
        raise MissionControlError("current commit is not exact")
    if kill_switch != "ENGAGED":
        raise MissionControlError("Mission Control requires the engaged kill switch")
    if budget is not None and (current_task is None or budget.task_id != current_task):
        raise MissionControlError("budget evidence is bound to another task")
    if worker is not None and current_task is None:
        raise MissionControlError("active worker requires a current task")
    active = records.get(current_task) if current_task else None
    if worker is not None and (active is None or active.assigned_model != worker.model_id or (budget is not None and budget.worker_id != worker.worker_id)):
        raise MissionControlError("worker, model, or budget identity does not match the current task")
    text = (validation_status, review_status, *recent_decisions)
    if len(recent_decisions) > 32 or any(not isinstance(value, str) or not value.strip() or len(value.encode()) > 1000 or _SECRET.search(value) for value in text):
        raise MissionControlError("operator status text is malformed, excessive, or secret-bearing")
    queue = tuple(
        MissionTaskView(
            task.task_id, task.requirement_id, task.title, task.status.value, task.priority,
            task.dependencies, task.blocking_reason, task.relevant_files,
            task.retry_count, task.retry_limit, task.resulting_commit,
        )
        for task in sorted(tasks, key=lambda item: (item.priority, item.task_id))
    )
    return MissionControlView(
        1, tenant_id, "ForgeWarden Core", active.requirement_id if active else None,
        current_task, worker.worker_id if worker else None, worker.provider if worker else None,
        worker.model_id if worker else None, queue, validation_status, review_status,
        budget.task_usage if budget else None, recent_decisions, current_commit, next_task,
        kill_switch,
    )
