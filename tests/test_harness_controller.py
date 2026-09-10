from dataclasses import asdict
from pathlib import Path

import pytest

from swarm.autonomous_loop import AutonomousOrchestrator, TaskSpec
from swarm.harness_authority import HarnessAuthorityRequest, HarnessOperation
from swarm.harness_context import BudgetLedger, BudgetLimits, BudgetRequest, ContextItem, build_context_packet
from swarm.harness_controller import GovernedHarnessController, TaskExecution
from swarm.harness_models import HarnessModelRequest
from swarm.harness_task import HarnessTask, TaskStatus
from swarm.harness_worker import WorkerRegistration, WorkerRegistry, WorkerRole, WorkerTransport
from swarm.review_handoff import ReviewResult


NOW = "2026-09-09T00:00:00Z"
SHA_A, SHA_B = "a" * 40, "b" * 40


def canonical(task_id, priority, dependencies=()):
    return HarnessTask(task_id, "FW-HARNESS-013", task_id, "integrated fixture", TaskStatus.READY, priority, "CODEX", "gpt-approved", "/repo", NOW, dependencies=dependencies, authorized_capabilities=("source.write",), relevant_files=(f"swarm/{task_id}.py",), validation_requirements=("pytest",), token_budget=100, cost_budget=1.0, retry_limit=0)


def items(value):
    return (ContextItem("architecture_constraint", "D-023", "AI has no authority"), ContextItem("task_state", value.task_id, "ready"), ContextItem("forbidden_change", "deployment", "disabled"))


def execution(value):
    packet = build_context_packet(value, items(value))
    auth = HarnessAuthorityRequest(f"request-{value.task_id.lower()}", "tenant-one", value.task_id, "agent-one", "codex-cli", "openai", "gpt-approved", "source.write", value.relevant_files[0], HarnessOperation.WRITE, 10, "policy-v1", f"ticket-{value.task_id.lower()}")
    model = HarnessModelRequest(f"model-{value.task_id.lower()}", "tenant-one", value.task_id, "agent-one", "codex-cli", "openai", "gpt-approved", "fixture", "v1", "approval-v1", WorkerRole.CODE_WRITER, "INTERNAL", ("source.write",), packet.sha256, packet.byte_count, 10, 1000)
    return TaskExecution(items(value), BudgetRequest(tokens=10, cost_microunits=1000), "codex-cli", WorkerRole.CODE_WRITER, auth, model)


def authority(wire):
    return {**wire, "operation": wire["operation"].value if isinstance(wire["operation"], HarnessOperation) else wire["operation"], "lease_id": "lease-one", "expires_at": 9_999_999_999, "evidence_reference": "evidence/authority", "ticket_consumed": True, "admitted": True, "kill_switch": "ENGAGED", "deployment": "DISABLED", "authority_expanded": False}


def models(wire):
    return {**wire, "role": wire["role"].value if isinstance(wire["role"], WorkerRole) else wire["role"], "tool_permissions": list(wire["tool_permissions"]), "registry_evidence_reference": "evidence/model", "valid_until": 9_999_999_999, "reliability_score": .9, "reliability_samples": 10, "approved": True, "deployment_authority": "DISABLED"}


def controller(tmp_path, *, sink=lambda event, payload: None, limits=None):
    tasks = (canonical("FWQ-0100", 0), canonical("FWQ-0101", 1, ("FWQ-0100",)))
    specs = tuple(TaskSpec(value.task_id, value.requirement_id, value.description, dependencies=value.dependencies, priority=value.priority, allowed_paths=value.relevant_files, retry_budget=0, worker_type="CODEX", test_command=("pytest",)) for value in tasks)
    runner = AutonomousOrchestrator(tmp_path / "state.json", tmp_path / "repo", specs)
    bound = limits or BudgetLimits(4, 100, 0, 60, 0, 10_000)
    ledger = BudgetLedger(bound, {value.task_id: bound for value in tasks})
    registry = WorkerRegistry((WorkerRegistration("codex-cli", "openai", "gpt-approved", WorkerTransport.CLI, (WorkerRole.CODE_WRITER,), True, executable="codex"),))
    return GovernedHarnessController(orchestrator=runner, tasks=tasks, task_tenants={value.task_id: "tenant-one" for value in tasks}, executions={value.task_id: execution(value) for value in tasks}, workers=registry, budgets=ledger, authority_resolver=authority, model_resolver=models, evidence_sink=sink, timestamp=lambda: NOW)


def executor(plan):
    return {"task_id": plan.task_id, "worker_id": plan.worker_id, "context_sha256": plan.context_sha256, "candidate_commit": None, "changed_files": [f"swarm/{plan.task_id}.py"], "attempted_actions": ["edit scoped fixture"], "denied_actions": ["deploy"], "summary": "bounded fixture result"}


def test_integrated_lifecycle_automatically_advances_and_projects_same_state(tmp_path):
    commits = iter((SHA_A, SHA_B)); calls = []; evidence = []
    result = controller(tmp_path, sink=lambda event, payload: evidence.append((event, payload))).run(worker_executor=lambda plan: (calls.append(plan.task_id) or executor(plan)), validator=lambda task, output: True, committer=lambda task, output: next(commits), reviewer=lambda task, sha: ReviewResult("CLAUDE", sha, (), "LOW", "APPROVED", "exact"))
    assert calls == ["FWQ-0100", "FWQ-0101"]
    assert result.durable_state["completed_tasks"] == calls
    assert result.mission_control.current_commit == SHA_B and result.mission_control.next_task is None
    assert all(item.status == "completed" for item in result.mission_control.task_queue)
    assert [event for event, _ in evidence].count("fw_harness_lifecycle") == 10
    assert [payload["event"] for _, payload in evidence] == [
        "task_started", "worker_completed", "validation_completed", "review_completed", "task_accepted",
        "task_started", "worker_completed", "validation_completed", "review_completed", "task_accepted",
    ]
    assert evidence[-1][1]["resulting_commit"] == SHA_B


def test_restart_does_not_replay_completed_worker_or_budget(tmp_path):
    first = controller(tmp_path)
    commits = iter((SHA_A, SHA_B))
    first.run(worker_executor=executor, validator=lambda *args: True, committer=lambda *args: next(commits), reviewer=lambda task, sha: ReviewResult("CLAUDE", sha, (), "LOW", "APPROVED", "exact"))
    calls = []
    resumed = controller(tmp_path)
    state = resumed.run(worker_executor=lambda plan: calls.append(plan), validator=lambda *args: True, committer=lambda *args: SHA_A, reviewer=lambda task, sha: ReviewResult("CLAUDE", sha, (), "LOW", "APPROVED", "exact"))
    assert calls == [] and state.durable_state["stop_reason"] == "ALL_ACTIVE_WORK_COMPLETE"


def test_budget_denial_stops_before_worker_execution(tmp_path):
    calls = []
    result = controller(tmp_path, limits=BudgetLimits(0, 0, 0, 0, 0, 0)).run(worker_executor=lambda plan: calls.append(plan), validator=lambda *args: True, committer=lambda *args: SHA_A, reviewer=lambda task, sha: ReviewResult("CLAUDE", sha, (), "LOW", "APPROVED", "exact"), max_steps=1)
    assert calls == [] and result.durable_state["failed_tasks"] == ["FWQ-0100"]


def test_evidence_failure_prevents_validation_commit_and_completion(tmp_path):
    def fail(event, payload): raise RuntimeError("offline")
    later = []
    result = controller(tmp_path, sink=fail).run(worker_executor=executor, validator=lambda *args: later.append("validate") or True, committer=lambda *args: later.append("commit") or SHA_A, reviewer=lambda task, sha: ReviewResult("CLAUDE", sha, (), "LOW", "APPROVED", "exact"), max_steps=1)
    assert later == [] and result.durable_state["failed_tasks"] == ["FWQ-0100"]


def test_validation_or_review_failure_never_advances_dependency(tmp_path):
    failed = controller(tmp_path).run(worker_executor=executor, validator=lambda *args: False, committer=lambda *args: SHA_A, reviewer=lambda task, sha: ReviewResult("CLAUDE", sha, (), "LOW", "APPROVED", "exact"), max_steps=1)
    assert failed.durable_state["queued_tasks"]["FWQ-0101"]["state"] == "READY" or failed.durable_state["queued_tasks"]["FWQ-0101"]["state"] == "BLOCKED"


def test_kill_switch_authorization_stop_dispatches_nothing(tmp_path):
    calls = []
    result = controller(tmp_path).run(worker_executor=lambda plan: calls.append(plan), validator=lambda *args: True, committer=lambda *args: SHA_A, reviewer=lambda task, sha: ReviewResult("CLAUDE", sha, (), "LOW", "APPROVED", "exact"), authorized=lambda: False)
    assert calls == [] and result.durable_state["stop_reason"] == "SUPERVISOR_TERMINATED"
