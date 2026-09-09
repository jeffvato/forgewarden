from dataclasses import FrozenInstanceError

import pytest

from swarm.harness_task import HarnessTask, HarnessTaskError, TaskStatus, from_legacy_task, legacy_status, task_from_record, task_to_record, transition_task


NOW = "2026-09-09T12:00:00+00:00"
SHA = "a" * 40


def task(**changes):
    values = dict(task_id="FWQ-0066", requirement_id="FW-HARNESS-002", title="Canonical tasks", description="Consolidate task evidence", status=TaskStatus.QUEUED, priority=0, assigned_role="CODEX", assigned_model=None, repository="/repo", created_at=NOW, retry_limit=2, authorized_capabilities=("source.write",), relevant_files=("swarm/harness_task.py",), expected_outputs=("canonical record",), validation_requirements=("pytest",))
    values.update(changes)
    return HarnessTask(**values)


def test_required_lifecycle_is_complete_and_records_are_immutable():
    assert {item.value for item in TaskStatus} == {"queued", "ready", "running", "awaiting_validation", "awaiting_review", "repair_required", "blocked", "completed", "rejected", "cancelled"}
    with pytest.raises(FrozenInstanceError):
        task().status = TaskStatus.RUNNING


def test_controller_transition_path_sets_timestamps_and_exact_commit():
    current = transition_task(task(), TaskStatus.READY, occurred_at=NOW)
    current = transition_task(current, TaskStatus.RUNNING, occurred_at=NOW)
    current = transition_task(current, TaskStatus.AWAITING_VALIDATION, occurred_at=NOW)
    current = transition_task(current, TaskStatus.AWAITING_REVIEW, occurred_at=NOW)
    current = transition_task(current, TaskStatus.COMPLETED, occurred_at=NOW, resulting_commit=SHA)
    assert current.started_at == NOW and current.completed_at == NOW and current.resulting_commit == SHA


@pytest.mark.parametrize("source,target", [(TaskStatus.QUEUED, TaskStatus.COMPLETED), (TaskStatus.COMPLETED, TaskStatus.READY), (TaskStatus.READY, TaskStatus.AWAITING_REVIEW)])
def test_invalid_or_authority_skipping_transitions_fail_closed(source, target):
    base = task(status=source, completed_at=NOW if source == TaskStatus.COMPLETED else None)
    with pytest.raises(HarnessTaskError, match="not allowed"):
        transition_task(base, target, occurred_at=NOW, resulting_commit=SHA)


def test_blocked_and_completed_states_require_evidence():
    with pytest.raises(HarnessTaskError, match="blocking reason"):
        task(status=TaskStatus.BLOCKED)
    review = task(status=TaskStatus.AWAITING_REVIEW)
    with pytest.raises(HarnessTaskError, match="exact resulting commit"):
        transition_task(review, TaskStatus.COMPLETED, occurred_at=NOW)


def test_paths_capabilities_budgets_and_timestamps_are_bounded():
    for changes, match in [
        ({"relevant_files": ("../escape",)}, "relative paths"),
        ({"authorized_capabilities": ("SHELL *",)}, "capabilities"),
        ({"retry_count": 2, "retry_limit": 1}, "retry"),
        ({"cost_budget": float("inf")}, "budgets"),
        ({"created_at": "2026-09-09"}, "timezone"),
    ]:
        with pytest.raises(HarnessTaskError, match=match):
            task(**changes)


def test_legacy_adapter_maps_existing_state_and_keeps_requirement_separate():
    converted = from_legacy_task(
        {"task_id": "FWQ-0066", "requirement": "FW-HARNESS-002", "description": "schema", "dependencies": (), "allowed_paths": ("swarm/harness_task.py",), "acceptance": ("proof",), "test_command": ("pytest",), "retry_budget": 2, "worker_type": "CODEX"},
        {"state": "IN_PROGRESS", "attempts": 1}, created_at=NOW, repository="/repo",
    )
    assert converted.task_id == "FWQ-0066" and converted.requirement_id == "FW-HARNESS-002"
    assert converted.status == TaskStatus.RUNNING and converted.retry_count == 1
    assert converted.started_at == NOW


def test_unknown_legacy_status_fails_closed():
    with pytest.raises(HarnessTaskError, match="unknown legacy"):
        legacy_status("MODEL_APPROVED")


def test_canonical_persistence_round_trip_and_unknown_fields_fail_closed():
    original = task()
    assert task_from_record(task_to_record(original)) == original
    altered = task_to_record(original)
    altered["model_decision"] = "completed"
    with pytest.raises(HarnessTaskError, match="field set"):
        task_from_record(altered)


def test_legacy_terminal_record_can_be_loaded_without_inventing_a_commit():
    converted = from_legacy_task(
        {"task_id": "FWQ-0065", "requirement": "FW-HARNESS-001", "description": "inventory", "retry_budget": 0},
        {"state": "DONE", "attempts": 0}, created_at=NOW, repository="/repo",
    )
    assert converted.status == TaskStatus.COMPLETED and converted.completed_at == NOW
    assert converted.resulting_commit is None
