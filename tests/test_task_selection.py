from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

import pytest

from swarm.supervisor_state import ControlFile, ResumeState, SupervisorState
from swarm.task_selection import TaskSelectionError, load_validated_work_items, select_ready_task
from swarm.control_manifest import derive_control_transition_tasks


def _task(task_id: str, *, state: str = "READY", priority: str = "P0", dependencies: str = "none", requirement: str = "Core supervisor") -> str:
    return "\n".join((
        f"### {task_id} — {task_id} title",
        f"- Requirement: {requirement}",
        f"- State: {state}",
        f"- Priority: {priority}",
        f"- Dependencies: {dependencies}",
        "- Description: fixture task",
    ))


def _state(*tasks: str, phase: str = "ForgeWarden Core") -> SupervisorState:
    queue = "# ForgeWarden Work Queue\n## Active queue\n" + "\n\n".join(tasks) + "\n## Future queue population\n"
    status = f"# ForgeWarden Swarm Status\n## Current state\n- Active phase: {phase}\n## Resume protocol\n"
    files = {
        "WORK_QUEUE.md": ControlFile("WORK_QUEUE.md", Path("/repo/WORK_QUEUE.md"), queue, "0" * 64),
        "SWARM_STATUS.md": ControlFile("SWARM_STATUS.md", Path("/repo/SWARM_STATUS.md"), status, "0" * 64),
    }
    return SupervisorState(Path("/repo"), MappingProxyType(files), ResumeState(MappingProxyType({}), False))


def test_selects_lowest_priority_number_then_task_id_deterministically():
    state = _state(_task("FWQ-0010", priority="P0"), _task("FWQ-0002", priority="P0"), _task("FWQ-0003", priority="P1"))

    first = select_ready_task(state)
    second = select_ready_task(state)

    assert first == second
    assert first.selected is not None
    assert first.selected.task_id == "FWQ-0002"
    assert first.eligible_task_ids == ("FWQ-0002", "FWQ-0010", "FWQ-0003")
    assert first.reason == "SELECTED_HIGHEST_PRIORITY_EXECUTABLE_READY_TASK"


def test_dependencies_must_be_done_and_blocked_chains_are_auditable():
    state = _state(
        _task("FWQ-0001", state="DONE"),
        _task("FWQ-0002", state="BLOCKED", dependencies="FWQ-0001"),
        _task("FWQ-0003", dependencies="FWQ-0002"),
    )

    decision = select_ready_task(state)

    assert decision.selected is None
    assert decision.reason == "NO_EXECUTABLE_READY_TASKS"
    assert decision.ineligible == {"FWQ-0003": "dependencies not complete: FWQ-0002=BLOCKED"}


def test_completed_dependencies_make_ready_task_executable():
    decision = select_ready_task(_state(_task("FWQ-0001", state="DONE"), _task("FWQ-0002", dependencies="FWQ-0001")))

    assert decision.selected is not None
    assert decision.selected.task_id == "FWQ-0002"


def test_optional_executable_metadata_is_preserved_for_ready_work():
    task = _task("FWQ-0011", dependencies="FWQ-0010") + "\n" + "\n".join((
        "- Target path: swarm/work_checkpoint.py",
        "- Allowed paths: swarm/work_checkpoint.py, tests/test_work_checkpoint.py",
        "- Test command: python3 -m pytest -q tests/test_work_checkpoint.py",
        "- Expected behavior: implement deterministic checkpoint reconciliation",
        "- Failing assertion: stale checkpoint evidence is accepted",
    ))
    state = _state(_task("FWQ-0010", state="DONE"), task)
    item = load_validated_work_items(state)["FWQ-0011"]
    assert item.target_path == "swarm/work_checkpoint.py"
    assert item.allowed_paths == ("swarm/work_checkpoint.py", "tests/test_work_checkpoint.py")
    assert item.test_command == ("python3", "-m", "pytest", "-q", "tests/test_work_checkpoint.py")


def test_control_manifest_emits_selected_ready_task_first():
    state = _state(_task("FWQ-0010", state="DONE"), _task("FWQ-0011", dependencies="FWQ-0010"), _task("FWQ-0009", state="REVIEW"))
    tasks = derive_control_transition_tasks(Path("/repo"), state)
    assert tasks[0].task_id == "FWQ-0011"
    assert tasks[0].initial_state == "READY"


@pytest.mark.parametrize(
    "task_text, message",
    (
        (_task("FWQ-0001", state="UNKNOWN"), "invalid state"),
        (_task("FWQ-0001", priority="urgent"), "priority must be"),
        (_task("FWQ-0001", dependencies="FWQ-9999"), "unknown dependency"),
        (_task("FWQ-0001", dependencies="FWQ-0001"), "self dependency"),
    ),
)
def test_invalid_task_data_is_rejected(task_text, message):
    with pytest.raises(TaskSelectionError, match=message):
        select_ready_task(_state(task_text))


def test_dependency_cycle_is_rejected():
    state = _state(_task("FWQ-0001", dependencies="FWQ-0002"), _task("FWQ-0002", dependencies="FWQ-0001"))

    with pytest.raises(TaskSelectionError, match="dependency cycle"):
        select_ready_task(state)


def test_ready_task_outside_active_phase_is_rejected():
    with pytest.raises(TaskSelectionError, match="active-phase violation"):
        select_ready_task(_state(_task("FWQ-0001", requirement="FW-ENDPOINT")))


def test_unknown_active_phase_is_rejected():
    with pytest.raises(TaskSelectionError, match="unsupported active phase"):
        select_ready_task(_state(_task("FWQ-0001"), phase="Future platform"))


def test_no_ready_task_produces_immutable_auditable_evidence():
    decision = select_ready_task(_state(_task("FWQ-0001", state="DONE")))

    assert decision.selected is None
    assert decision.reason == "NO_EXECUTABLE_READY_TASKS"
    assert decision.eligible_task_ids == ()
    with pytest.raises(TypeError):
        decision.ineligible["FWQ-0001"] = "changed"
