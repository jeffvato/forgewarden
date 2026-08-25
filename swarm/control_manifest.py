"""Derive transition-only tasks from authoritative ForgeWarden control state."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .autonomous_loop import TaskSpec
from .supervisor_state import SupervisorState
from .task_selection import load_validated_work_items, select_ready_task


def _candidate_commit(repository: Path, value: str) -> str | None:
    if value.lower() == "pending" or value.lower() == "none":
        return None
    result = subprocess.run(["git", "-C", str(repository), "rev-parse", "--verify", f"{value}^{{commit}}"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    commit = result.stdout.strip()
    return commit if result.returncode == 0 and re.fullmatch(r"[0-9a-fA-F]{40}", commit) else None


def derive_control_transition_tasks(repository: Path, state: SupervisorState) -> tuple[TaskSpec, ...]:
    items = load_validated_work_items(state)
    checkpoint = state.resume.checkpoint
    candidate = _candidate_commit(repository, checkpoint.get("Candidate commit", "none"))
    result: list[TaskSpec] = []
    selected = select_ready_task(state).selected
    ordered = sorted(items.values(), key=lambda item: (0 if selected and item.task_id == selected.task_id else (1 if item.state in {"REVIEW", "BLOCKED"} else 2), item.priority, item.task_id))
    for item in ordered:
        if item.state not in {"REVIEW", "BLOCKED", "DONE"} and not (selected and item.task_id == selected.task_id):
            continue
        result.append(TaskSpec(
            task_id=item.task_id,
            requirement=item.requirement,
            description=item.title,
            dependencies=item.dependencies,
            priority=item.priority,
            initial_state=item.state,
            review_commit=candidate if item.state == "REVIEW" else None,
            blocker_external=item.state == "BLOCKED",
            blocker_resolved=False,
            authorized=True,
            target_path=item.target_path,
            allowed_paths=item.allowed_paths,
            test_command=item.test_command,
            expected_behavior=item.expected_behavior,
            failing_assertion=item.failing_assertion,
        ))
    return tuple(result)
