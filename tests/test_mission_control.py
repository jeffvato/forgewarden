from dataclasses import replace

import pytest

from swarm.harness_context import BudgetAdmission, BudgetUsage
from swarm.harness_task import HarnessTask, TaskStatus
from swarm.harness_worker import WorkerRegistration, WorkerRole, WorkerTransport
from swarm.mission_control import MissionControlError, project_mission_control


def task(task_id="FWQ-0001", status=TaskStatus.READY, **changes):
    value = HarnessTask(
        task_id, "FW-HARNESS-008", "Mission view", "bounded view", status, 1,
        "CODEX", "gpt-approved", "/repo", "2026-09-09T00:00:00Z",
        relevant_files=("swarm/mission_control.py",), retry_limit=2,
    )
    return replace(value, **changes)


def worker():
    return WorkerRegistration("codex-cli", "openai", "gpt-approved", WorkerTransport.CLI, (WorkerRole.CODE_WRITER,), True, executable="codex")


def project(tasks=None, **changes):
    values = tasks or (task(), task("FWQ-0002", dependencies=("FWQ-0001",), priority=2))
    args = dict(
        tenant_id="tenant-one", task_tenants={item.task_id: "tenant-one" for item in values},
        current_task="FWQ-0001", worker=worker(),
        budget=BudgetAdmission("FWQ-0001", "codex-cli", BudgetUsage(model_calls=1, tokens=20), BudgetUsage(model_calls=1, tokens=20)),
        validation_status="passed", review_status="awaiting_review", recent_decisions=("worker admitted",),
        current_commit="a" * 40, next_task="FWQ-0002", kill_switch="ENGAGED",
    )
    args.update(changes)
    return project_mission_control(values, **args)


def test_projection_exposes_bounded_operator_state_without_authority():
    view = project()
    assert view.current_requirement == "FW-HARNESS-008"
    assert view.active_worker == "codex-cli" and view.active_model == "gpt-approved"
    assert view.task_queue[1].dependencies == ("FWQ-0001",)
    assert view.budget_used.tokens == 20 and view.next_task == "FWQ-0002"
    assert view.kill_switch == "ENGAGED" and view.deployment == "DISABLED"
    assert view.mutation_allowed is False


def test_projection_does_not_mutate_canonical_tasks():
    original = task()
    before = repr(original)
    project((original,), task_tenants={original.task_id: "tenant-one"}, next_task=None)
    assert repr(original) == before


@pytest.mark.parametrize("changes,match", [
    ({"task_tenants": {"FWQ-0001": "tenant-two", "FWQ-0002": "tenant-one"}}, "tenancy"),
    ({"current_task": "FWQ-9999"}, "current task"),
    ({"next_task": "FWQ-9999"}, "next task"),
    ({"current_commit": "mutable-head"}, "commit"),
    ({"kill_switch": "DISENGAGED"}, "kill switch"),
])
def test_inconsistent_or_cross_tenant_state_denies(changes, match):
    with pytest.raises(MissionControlError, match=match):
        project(**changes)


def test_budget_must_bind_current_task():
    bad = BudgetAdmission("FWQ-0002", "codex-cli", BudgetUsage(), BudgetUsage())
    with pytest.raises(MissionControlError, match="budget evidence"):
        project(budget=bad)


def test_worker_model_and_budget_identity_must_match_current_task():
    wrong_model = replace(worker(), model_id="other-model")
    with pytest.raises(MissionControlError, match="worker, model"):
        project(worker=wrong_model)
    wrong_budget = BudgetAdmission("FWQ-0001", "other-worker", BudgetUsage(), BudgetUsage())
    with pytest.raises(MissionControlError, match="worker, model"):
        project(budget=wrong_budget)


@pytest.mark.parametrize("text", ["Bearer abc.def", "api_key=secret-value", "access_token: value"])
def test_secret_bearing_status_is_rejected(text):
    with pytest.raises(MissionControlError, match="secret-bearing"):
        project(recent_decisions=(text,))


def test_projection_rejects_unbounded_decision_history():
    with pytest.raises(MissionControlError, match="excessive"):
        project(recent_decisions=tuple(f"decision {index}" for index in range(33)))


def test_projection_rejects_secret_bearing_task_title():
    value = task(title="api_key=secret-value")
    with pytest.raises(MissionControlError, match="secret-bearing"):
        project((value,), task_tenants={value.task_id: "tenant-one"}, next_task=None)


def test_projection_rejects_dependency_outside_canonical_queue():
    value = task(dependencies=("FWQ-9999",))
    with pytest.raises(MissionControlError, match="dependency"):
        project((value,), task_tenants={value.task_id: "tenant-one"}, next_task=None)


def test_idle_projection_has_no_worker_or_budget():
    view = project(current_task=None, worker=None, budget=None, next_task="FWQ-0001", current_commit=None)
    assert view.current_task is None and view.active_worker is None and view.budget_used is None
