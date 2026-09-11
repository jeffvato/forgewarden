from dataclasses import asdict
from pathlib import Path
import subprocess

import pytest

from swarm.autonomous_loop import AutonomousOrchestrator, TaskSpec
from swarm.harness_authority import HarnessAuthorityRequest, HarnessOperation
from swarm.harness_context import BudgetLedger, BudgetLimits, BudgetRequest, ContextItem, build_context_packet
from swarm.harness_controller import GovernedHarnessController, TaskExecution
from swarm.harness_runtime import HarnessRuntimeError, SelfHostedHarnessRuntime
from swarm.harness_models import HarnessModelRequest
from swarm.harness_task import HarnessTask, TaskStatus
from swarm.harness_worker import InvocationPlan, WorkerRegistration, WorkerRegistry, WorkerRole, WorkerTransport
from swarm.identity import IdentityRegistry, validate_identity_record
from swarm.keys import SecretHandleRegistry
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
    registry = WorkerRegistry((WorkerRegistration("codex-cli", "openai", "gpt-approved", WorkerTransport.CLI, (WorkerRole.CODE_WRITER,), True, executable="codex", identity_ref="fw-id/codex-cli"),))
    identities = IdentityRegistry(lambda *_args: None)
    identities.register(validate_identity_record({"schema_version": "1", "identity_id": "fw-id/codex-cli", "tenant_id": "tenant-one", "identity_kind": "AI_AGENT", "owner_identity_ref": "fw-id/owner", "purpose": "bounded test worker", "lifecycle_state": "ACTIVE", "created_at_epoch": 1, "lifecycle_changed_at_epoch": 1, "expires_at_epoch": 9_999_999_999, "provider_subject_ref": "provider/openai-codex", "credential_handle_ref": "fwkeys://tenant-one/provider/openai-codex"}))
    return GovernedHarnessController(orchestrator=runner, tasks=tasks, task_tenants={value.task_id: "tenant-one" for value in tasks}, executions={value.task_id: execution(value) for value in tasks}, workers=registry, budgets=ledger, identity_registry=identities, key_registry=SecretHandleRegistry(lambda *_args: None), authority_resolver=authority, model_resolver=models, evidence_sink=sink, timestamp=lambda: NOW)


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


def self_hosted_runtime(tmp_path, *, review_role="CLAUDE", validation=True):
    tmp_path.mkdir(parents=True, exist_ok=True)
    tasks = (canonical("FWQ-0100", 0), canonical("FWQ-0101", 1, ("FWQ-0100",)))
    specs = tuple(TaskSpec(value.task_id, value.requirement_id, value.description, dependencies=value.dependencies, priority=value.priority, allowed_paths=value.relevant_files, retry_budget=0, worker_type="CODEX", test_command=("pytest",)) for value in tasks)
    calls = []

    def dispatch(spec, lease):
        calls.append(("worker", spec.task_id, lease.operation, lease.deployment, lease.authority_expansion, lease.session_id))
        return __import__("swarm.autonomous_loop", fromlist=["WorkerResult"]).WorkerResult(None, spec.allowed_paths, spec.test_command, "bounded fixture")

    def validate(spec, result, repository):
        calls.append(("validate", spec.task_id, str(repository)))
        return validation

    def commit(spec, result, lease):
        calls.append(("commit", spec.task_id, lease.operation, lease.session_id))
        return SHA_A if spec.task_id == "FWQ-0100" else SHA_B

    def review(spec, commit_sha, lease):
        calls.append(("review", spec.task_id, lease.operation, lease.session_id))
        return {review_role: ReviewResult(review_role, commit_sha, (), "LOW", "APPROVED", "exact")}

    runtime = SelfHostedHarnessRuntime(repository=tmp_path, task_specs=specs, worker_dispatch=dispatch, validator=validate, committer=commit, reviewer=review)
    return runtime, calls


def test_self_hosted_runtime_uses_trusted_stage_owners_and_advances(tmp_path):
    runtime, calls = self_hosted_runtime(tmp_path)
    result = runtime.run(controller(tmp_path))
    assert result.durable_state["completed_tasks"] == ["FWQ-0100", "FWQ-0101"]
    assert [item[0] for item in calls] == ["worker", "validate", "commit", "review"] * 2
    worker_calls = [item for item in calls if item[0] == "worker"]
    assert all(item[2:5] == ("WRITE", "DISABLED", False) for item in worker_calls)
    for task_id in ("FWQ-0100", "FWQ-0101"):
        sessions = {item[-1] for item in calls if item[1] == task_id and item[0] in {"worker", "commit", "review"}}
        assert len(sessions) == 1


def test_self_hosted_runtime_fails_closed_before_later_stages(tmp_path):
    runtime, calls = self_hosted_runtime(tmp_path, validation=False)
    result = runtime.run(controller(tmp_path), max_steps=1)
    assert [item[0] for item in calls] == ["worker", "validate"]
    assert result.durable_state["failed_tasks"] == ["FWQ-0100"]

    bad_root = tmp_path / "other"
    bad_runtime, bad_calls = self_hosted_runtime(bad_root, review_role="QWEN")
    denied = bad_runtime.run(controller(bad_root), max_steps=1)
    assert [item[0] for item in bad_calls] == ["worker", "validate", "commit", "review"]
    assert denied.durable_state["failed_tasks"] == ["FWQ-0100"]


def test_self_hosted_worker_result_type_validation(tmp_path):
    runtime, _ = self_hosted_runtime(tmp_path)
    runtime.worker_dispatch = lambda *_args: {"changed_files": []}
    result = runtime.run(controller(tmp_path), max_steps=1)
    assert result.durable_state["failed_tasks"] == ["FWQ-0100"]


@pytest.mark.parametrize("changes", [
    {"task_id": "FWQ-9999"},
    {"deployment": "ENABLED"},
    {"credential_handle": "fwkeys://tenant-one/provider/key"},
    {"mutation_allowed": False},
])
def test_self_hosted_invalid_invocation_plan_fails_closed(tmp_path, changes):
    runtime, _ = self_hosted_runtime(tmp_path)
    governed = controller(tmp_path)
    task = governed.tasks["FWQ-0100"]
    plan = InvocationPlan("codex-cli", "openai", "gpt-approved", WorkerTransport.CLI, WorkerRole.CODE_WRITER, task.task_id, "a" * 64, "codex", None, None, "canonical-context-v1-over-stdin", ("HOME",), True)
    plan = __import__("dataclasses").replace(plan, **changes)
    with pytest.raises(HarnessRuntimeError, match="scope|absent"):
        runtime._lease(task, plan, governed.orchestrator.session_id)


def test_self_hosted_symlinked_repository_is_rejected(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    task = canonical("FWQ-0100", 0)
    spec = TaskSpec(task.task_id, task.requirement_id, task.description, allowed_paths=task.relevant_files)
    with pytest.raises(HarnessRuntimeError, match="symlinked"):
        SelfHostedHarnessRuntime(repository=link, task_specs=(spec,), worker_dispatch=lambda *_: None, validator=lambda *_: True, committer=lambda *_: SHA_A, reviewer=lambda *_: {})


def test_existing_adapter_constructor_rejects_dirty_git(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "fixture@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Fixture"], check=True)
    (tmp_path / "tracked.txt").write_text("clean\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "tracked.txt"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "fixture"], check=True)
    (tmp_path / "tracked.txt").write_text("dirty\n")
    task = canonical("FWQ-0100", 0)
    spec = TaskSpec(task.task_id, task.requirement_id, task.description, allowed_paths=task.relevant_files)
    with pytest.raises(Exception, match="clean|dirty|changes"):
        SelfHostedHarnessRuntime.from_existing_adapters(repository=tmp_path, task_specs=(spec,), codex_executable="codex", codex_schema=tmp_path / "schema.json", review_context="fixture")


def test_self_hosted_missing_reviewer_role_fails_closed(tmp_path):
    runtime, calls = self_hosted_runtime(tmp_path, review_role="QWEN")
    result = runtime.run(controller(tmp_path), max_steps=1)
    assert [item[0] for item in calls] == ["worker", "validate", "commit", "review"]
    assert result.durable_state["failed_tasks"] == ["FWQ-0100"]


def test_self_hosted_authorized_stop_and_max_steps_are_preserved(tmp_path):
    stopped_runtime, stopped_calls = self_hosted_runtime(tmp_path / "stopped")
    stopped = stopped_runtime.run(controller(tmp_path / "stopped"), authorized=lambda: False)
    assert stopped_calls == [] and stopped.durable_state["stop_reason"] == "SUPERVISOR_TERMINATED"

    bounded_runtime, bounded_calls = self_hosted_runtime(tmp_path / "bounded")
    bounded = bounded_runtime.run(controller(tmp_path / "bounded"), max_steps=1)
    assert bounded.durable_state["completed_tasks"] == ["FWQ-0100"]
    assert {item[1] for item in bounded_calls} == {"FWQ-0100"}


@pytest.mark.parametrize("stage", ["validator", "committer", "reviewer"])
def test_self_hosted_stage_exceptions_fail_closed(tmp_path, stage):
    runtime, calls = self_hosted_runtime(tmp_path)
    setattr(runtime, stage, lambda *_args: (_ for _ in ()).throw(RuntimeError("fixture failure")))
    result = runtime.run(controller(tmp_path), max_steps=1)
    assert result.durable_state["failed_tasks"] == ["FWQ-0100"]
    stages = [item[0] for item in calls]
    if stage == "validator":
        assert stages == ["worker"]
    elif stage == "committer":
        assert stages == ["worker", "validate"]
    else:
        assert stages == ["worker", "validate", "commit"]
