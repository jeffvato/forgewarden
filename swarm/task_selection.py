"""Deterministic, read-only selection of executable ForgeWarden work items."""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from .supervisor_state import SupervisorState


_TASK_HEADING = re.compile(r"^### (FWQ-[0-9]{4}) — (.+)$")
_TASK_ID = re.compile(r"FWQ-[0-9]{4}")
_PRIORITY = re.compile(r"P([0-9]+)")
_STATES = frozenset({"BLOCKED", "READY", "IN_PROGRESS", "REVIEW", "REPAIR", "VALIDATED", "DONE"})
_REQUIRED_FIELDS = ("Requirement", "State", "Priority", "Dependencies", "Description")


class TaskSelectionError(ValueError):
    """Raised when validated control evidence contains invalid task metadata."""


@dataclass(frozen=True)
class WorkItem:
    task_id: str
    title: str
    requirement: str
    state: str
    priority: int
    dependencies: tuple[str, ...]


@dataclass(frozen=True)
class SelectionDecision:
    active_phase: str
    selected: WorkItem | None
    reason: str
    eligible_task_ids: tuple[str, ...]
    ineligible: Mapping[str, str]


def _section(content: str, heading: str) -> str:
    marker = heading + "\n"
    if content.count(marker) != 1:
        raise TaskSelectionError(f"malformed control evidence: expected exactly one {heading}")
    remainder = content.split(marker, 1)[1]
    return remainder.split("\n## ", 1)[0]


def _active_phase(state: SupervisorState) -> str:
    try:
        current_state = _section(state.files["SWARM_STATUS.md"].content, "## Current state")
    except KeyError as exc:
        raise TaskSelectionError("missing SWARM_STATUS.md control evidence") from exc
    matches = re.findall(r"^- Active phase: (.+)$", current_state, flags=re.MULTILINE)
    if len(matches) != 1 or not matches[0].strip():
        raise TaskSelectionError("malformed SWARM_STATUS.md: exactly one active phase is required")
    return matches[0].strip()


def _parse_tasks(state: SupervisorState) -> dict[str, WorkItem]:
    try:
        content = _section(state.files["WORK_QUEUE.md"].content, "## Active queue")
    except KeyError as exc:
        raise TaskSelectionError("missing WORK_QUEUE.md control evidence") from exc

    tasks: dict[str, WorkItem] = {}
    current_id: str | None = None
    current_title = ""
    fields: dict[str, str] = {}

    def finish() -> None:
        nonlocal current_id, fields
        if current_id is None:
            return
        missing = [field for field in _REQUIRED_FIELDS if not fields.get(field)]
        if missing:
            raise TaskSelectionError(f"malformed task {current_id}: missing field(s): {', '.join(missing)}")
        task_state = fields["State"]
        if task_state not in _STATES:
            raise TaskSelectionError(f"malformed task {current_id}: invalid state {task_state}")
        priority = _PRIORITY.fullmatch(fields["Priority"])
        if priority is None:
            raise TaskSelectionError(f"malformed task {current_id}: priority must be P followed by digits")
        raw_dependencies = fields["Dependencies"]
        dependencies = () if raw_dependencies == "none" else tuple(item.strip() for item in raw_dependencies.split(","))
        if raw_dependencies != "none" and (not dependencies or any(not _TASK_ID.fullmatch(item) for item in dependencies) or len(set(dependencies)) != len(dependencies)):
            raise TaskSelectionError(f"malformed task {current_id}: invalid dependencies")
        tasks[current_id] = WorkItem(current_id, current_title, fields["Requirement"], task_state, int(priority.group(1)), dependencies)

    for line in content.splitlines():
        heading = _TASK_HEADING.fullmatch(line)
        if heading:
            finish()
            current_id, current_title = heading.groups()
            if current_id in tasks:
                raise TaskSelectionError(f"malformed WORK_QUEUE.md: duplicate task ID {current_id}")
            fields = {}
            continue
        if current_id is None or not line.startswith("- "):
            continue
        field, separator, value = line[2:].partition(":")
        if field in _REQUIRED_FIELDS and separator:
            if field in fields:
                raise TaskSelectionError(f"malformed task {current_id}: duplicate field {field}")
            fields[field] = value.strip()
    finish()
    return tasks


def _validate_graph(tasks: Mapping[str, WorkItem], active_phase: str) -> None:
    if active_phase != "ForgeWarden Core":
        raise TaskSelectionError(f"unsupported active phase: {active_phase}")
    for task in tasks.values():
        if task.state == "READY" and not task.requirement.startswith("Core "):
            raise TaskSelectionError(f"active-phase violation: {task.task_id} is not ForgeWarden Core work")
        for dependency in task.dependencies:
            if dependency not in tasks:
                raise TaskSelectionError(f"malformed task {task.task_id}: unknown dependency {dependency}")
            if dependency == task.task_id:
                raise TaskSelectionError(f"malformed task {task.task_id}: self dependency")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(task_id: str) -> None:
        if task_id in visiting:
            raise TaskSelectionError(f"malformed WORK_QUEUE.md: dependency cycle includes {task_id}")
        if task_id in visited:
            return
        visiting.add(task_id)
        for dependency in tasks[task_id].dependencies:
            visit(dependency)
        visiting.remove(task_id)
        visited.add(task_id)

    for task_id in sorted(tasks):
        visit(task_id)


def select_ready_task(state: SupervisorState) -> SelectionDecision:
    """Select the highest-priority executable READY item without changing state."""
    active_phase = _active_phase(state)
    tasks = _parse_tasks(state)
    _validate_graph(tasks, active_phase)

    eligible: list[WorkItem] = []
    ineligible: dict[str, str] = {}
    for task in sorted(tasks.values(), key=lambda item: item.task_id):
        if task.state != "READY":
            continue
        incomplete = [dependency for dependency in task.dependencies if tasks[dependency].state != "DONE"]
        if incomplete:
            states = ", ".join(f"{dependency}={tasks[dependency].state}" for dependency in incomplete)
            ineligible[task.task_id] = "dependencies not complete: " + states
            continue
        eligible.append(task)

    eligible.sort(key=lambda item: (item.priority, item.task_id))
    if not eligible:
        return SelectionDecision(
            active_phase=active_phase,
            selected=None,
            reason="NO_EXECUTABLE_READY_TASKS",
            eligible_task_ids=(),
            ineligible=MappingProxyType(ineligible),
        )
    return SelectionDecision(
        active_phase=active_phase,
        selected=eligible[0],
        reason="SELECTED_HIGHEST_PRIORITY_EXECUTABLE_READY_TASK",
        eligible_task_ids=tuple(item.task_id for item in eligible),
        ineligible=MappingProxyType(ineligible),
    )


def load_validated_work_items(state: SupervisorState) -> Mapping[str, WorkItem]:
    """Return the validated active queue for trusted read-only planning."""
    active_phase = _active_phase(state)
    tasks = _parse_tasks(state)
    _validate_graph(tasks, active_phase)
    return MappingProxyType(dict(tasks))
