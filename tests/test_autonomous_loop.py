from __future__ import annotations

import json
import sys
import subprocess
import time
from dataclasses import asdict
from pathlib import Path
import pytest

from swarm.autonomous_loop import AutonomousOrchestrator, GitCheckpointController, ReviewUnavailable, TaskSpec, WorkerLease, WorkerResult, progress_queue
from swarm.autonomous_adapters import CodexTaskAdapter, ExactReviewAdapter, run_deterministic_tests
import swarm.autonomous_adapters as autonomous_adapters
from swarm.plan_derivation import derive_next_core_task
from swarm.cli import main
from swarm.review_handoff import ReviewResult
from test_supervisor_state import _write_control_files


SHA_A = "a" * 40
SHA_B = "b" * 40


def _tasks() -> tuple[TaskSpec, ...]:
    return (
        TaskSpec("FWQ-0001", "Core first", "first", priority=0, retry_budget=1),
        TaskSpec("FWQ-0002", "Core second", "second", dependencies=("FWQ-0001",), priority=1, retry_budget=1),
    )


def test_durable_loop_dispatches_checkpoint_and_automatically_selects_next(tmp_path: Path):
    calls: list[str] = []
    candidates = iter((SHA_A, SHA_B))
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", _tasks())

    def dispatch(task: TaskSpec, lease: WorkerLease) -> WorkerResult:
        calls.append(task.task_id)
        assert lease.task_id == task.task_id
        assert lease.dry_run and lease.deployment == "DISABLED"
        return WorkerResult(next(candidates), (f"swarm/{task.task_id}.py",), ("pytest -q",))

    def commit(task: TaskSpec, result: WorkerResult) -> str:
        return result.candidate_commit

    state = runner.run(dispatch=dispatch, validate=lambda task, result: True, commit=commit, review=lambda task, sha, lease: ("APPROVED", "LOW"))

    assert calls == ["FWQ-0001", "FWQ-0002"]
    assert state["completed_tasks"] == ["FWQ-0001", "FWQ-0002"]
    assert state["repository_head_after"] == SHA_B
    assert state["stop_reason"] == "ALL_ACTIVE_WORK_COMPLETE"
    assert json.loads((tmp_path / "work-checkpoint.json").read_text())['checkpoint']['accepted_commit'] == SHA_B
    events = (tmp_path / "execution-log.jsonl").read_text().splitlines()
    assert any(json.loads(line)["event"] == "task_accepted" for line in events)


def test_legacy_review_callback_rejects_empty_results(tmp_path: Path):
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", (TaskSpec("FWQ-0001", "Core", "empty", retry_budget=0),))
    state = runner.run(
        dispatch=lambda task, lease: WorkerResult(SHA_A, (), ("pytest",)),
        validate=lambda task, result: True,
        commit=lambda task, result: result.candidate_commit,
        review=lambda task, sha, lease: (),
    )
    assert state["failed_tasks"] == ["FWQ-0001"]
    assert "reviewer results are incomplete" in state["unresolved_blockers"][0]


def test_legacy_review_callback_accepts_one_approved_claude_result(tmp_path: Path):
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", (TaskSpec("FWQ-0001", "Core", "single"),))
    state = runner.run(
        dispatch=lambda task, lease: WorkerResult(SHA_A, (), ("pytest",)),
        validate=lambda task, result: True,
        commit=lambda task, result: result.candidate_commit,
        review=lambda task, sha, lease: ("APPROVED",),
    )
    assert state["completed_tasks"] == ["FWQ-0001"]


def test_recover_restart_and_retry_then_continue(tmp_path: Path):
    tasks = (TaskSpec("FWQ-0001", "Core first", "first", priority=0, retry_budget=2), _tasks()[1])
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", tasks)
    state = runner._initial()
    state["queued_tasks"]["FWQ-0001"] = {"state": "IN_PROGRESS", "attempts": 0}
    state["active_task"] = "FWQ-0001"
    state["worker_lease"] = {"expires_at": time.time() - 1}
    runner._write(state)
    attempts = {"FWQ-0001": 0, "FWQ-0002": 0}

    def dispatch(task: TaskSpec, lease: WorkerLease) -> WorkerResult:
        attempts[task.task_id] += 1
        if task.task_id == "FWQ-0001" and attempts[task.task_id] == 1:
            raise RuntimeError("transient worker failure")
        return WorkerResult(SHA_A if task.task_id == "FWQ-0001" else SHA_B, (), ("pytest -q",))

    result = runner.run(dispatch=dispatch, validate=lambda task, value: True, commit=lambda task, value: value.candidate_commit, review=lambda task, sha, lease: ("APPROVED", "LOW"), max_steps=5)

    assert result["completed_tasks"] == ["FWQ-0001", "FWQ-0002"]
    assert result["retry_count"]["FWQ-0001"] == 2
    assert result["failed_tasks"] == []
    assert any("stale_lease_recovered" in line for line in (tmp_path / "execution-log.jsonl").read_text().splitlines())


def test_orphaned_in_progress_claim_is_recovered_without_a_lease(tmp_path: Path):
    task = TaskSpec("FWQ-0001", "Core recovery", "recover orphan")
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", (task,))
    state = runner._initial()
    state["queued_tasks"][task.task_id] = {"state": "IN_PROGRESS", "attempts": 0}
    runner._write(state)

    recovered = runner.status()

    assert recovered["queued_tasks"][task.task_id] == {"state": "READY", "attempts": 1}
    assert any("orphaned_claim_recovered" in line for line in (tmp_path / "execution-log.jsonl").read_text().splitlines())


def test_retry_exhaustion_records_blocker_but_independent_work_continues(tmp_path: Path):
    tasks = (TaskSpec("FWQ-0001", "Core blocked", "blocked", priority=0, retry_budget=0), TaskSpec("FWQ-0002", "Core independent", "independent", priority=1, retry_budget=0))
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", tasks)
    seen: list[str] = []

    def dispatch(task: TaskSpec, lease: WorkerLease) -> WorkerResult:
        seen.append(task.task_id)
        if task.task_id == "FWQ-0001":
            raise RuntimeError("permanent failure")
        return WorkerResult(SHA_B, (), ("pytest -q",))

    state = runner.run(dispatch=dispatch, validate=lambda task, value: True, commit=lambda task, value: value.candidate_commit, review=lambda task, sha, lease: ("APPROVED", "LOW"))
    assert seen == ["FWQ-0001", "FWQ-0002"]
    assert state["failed_tasks"] == ["FWQ-0001"]
    assert state["completed_tasks"] == ["FWQ-0002"]
    assert state["unresolved_blockers"]


def test_safety_contract_and_authorization_stop_are_durable(tmp_path: Path):
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", _tasks())
    state = runner.run(dispatch=lambda task, lease: WorkerResult(SHA_A, (), ("pytest",)), validate=lambda task, value: True, commit=lambda task, value: value.candidate_commit, review=lambda task, sha, lease: ("APPROVED", "LOW"), authorized=lambda: False)
    assert state["stop_reason"] == "SUPERVISOR_TERMINATED"
    assert state["dry_run"] is True and state["deployment"] == "DISABLED" and state["kill_switch"] == "ENGAGED"


def test_worker_scope_and_tampered_queue_are_rejected(tmp_path: Path):
    task = TaskSpec("FWQ-0001", "Core scoped", "scoped", allowed_paths=("swarm",), retry_budget=0)
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", (task,))

    state = runner.run(
        dispatch=lambda task, lease: WorkerResult(SHA_A, ("tests/test_escape.py",), ("pytest",)),
        validate=lambda task, result: True,
        commit=lambda task, result: result.candidate_commit,
        review=lambda task, sha, lease: ("APPROVED", "LOW"),
    )
    assert state["failed_tasks"] == ["FWQ-0001"]
    state["queued_tasks"]["unexpected"] = {"state": "READY", "attempts": 0}
    (tmp_path / "run.json").write_text(json.dumps(state), encoding="utf-8")
    try:
        runner.run(
            dispatch=lambda task, lease: WorkerResult(SHA_A, (), ("pytest",)),
            validate=lambda task, result: True,
            commit=lambda task, result: result.candidate_commit,
            review=lambda task, sha, lease: ("APPROVED", "LOW"),
        )
    except Exception as exc:
        assert "queue" in str(exc)
    else:
        raise AssertionError("tampered queue must fail closed")


def test_cli_exposes_read_only_durable_loop_status(tmp_path: Path, capsys, monkeypatch):
    _write_control_files(tmp_path)
    status = tmp_path / "SWARM_STATUS.md"
    status.write_text(status.read_text(encoding="utf-8").replace("## Current state\n", "## Current state\n- Active phase: ForgeWarden Core\n"), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["swarm", "autonomous-loop-status", "--repository", str(tmp_path), "--state-dir", str(tmp_path / "state")])
    assert main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["selected_task"] == "FWQ-0001"
    assert payload["durable_state"] is None


def test_trusted_git_controller_commits_uncommitted_worker_evidence(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "allowed.py").write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "allowed.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base"], check=True)
    (repo / "allowed.py").write_text("after\n", encoding="utf-8")
    task = TaskSpec("FWQ-0001", "Core git", "git", allowed_paths=("allowed.py",))
    result = WorkerResult(None, ("allowed.py",), ("pytest -q",))
    controller = GitCheckpointController(repo)
    accepted = controller.commit_worker_changes(task, result)
    assert len(accepted) == 40
    assert controller.head() == accepted


def test_loop_accepts_only_exact_commit_review_contract(tmp_path: Path):
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", (TaskSpec("FWQ-0001", "Core review", "review"),))

    def reviews(task, commit, lease):
        return {
            "CLAUDE": ReviewResult("CLAUDE", commit, (), "LOW", "APPROVED", "exact review"),
            "GEMINI": ReviewResult("GEMINI", commit, (), "LOW", "APPROVED", "exact review"),
        }

    state = runner.run(
        dispatch=lambda task, lease: WorkerResult(SHA_A, ("swarm/review.py",), ("pytest",)),
        validate=lambda task, result: True,
        commit=lambda task, result: result.candidate_commit or SHA_A,
        review=reviews,
    )
    assert state["completed_tasks"] == ["FWQ-0001"]
    assert state["reviewer_result"] == ["CLAUDE:APPROVED:LOW", "GEMINI:APPROVED:LOW"]


def test_real_adapter_validation_requires_explicit_shell_free_test_command(tmp_path: Path):
    task = TaskSpec("FWQ-0001", "Core test", "test", test_command=("python3", "-c", "print('ok')"))
    lease = WorkerLease("lease", task.task_id, "session", str(tmp_path), (), "TEST", (), time.time() + 60)
    assert run_deterministic_tests(task, WorkerResult(None, (), task.test_command), lease)
    assert not run_deterministic_tests(TaskSpec("FWQ-0001", "Core test", "test"), WorkerResult(None, (), ()), lease)


def test_cli_autonomous_loop_run_persists_without_dispatch_when_step_bound_is_zero(tmp_path: Path, capsys, monkeypatch):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "allowed.py").write_text("value = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "allowed.py"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base"], check=True)
    manifest = tmp_path.parent / f"{tmp_path.name}-tasks.json"
    manifest.write_text(json.dumps({"tasks": [{"task_id": "FWQ-0001", "requirement": "Core test", "description": "bounded", "target_path": "allowed.py", "allowed_paths": ["allowed.py"], "test_command": ["python3", "-c", "print('ok')"]}]}), encoding="utf-8")
    state_dir = tmp_path.parent / f"{tmp_path.name}-state"
    monkeypatch.setattr(sys, "argv", ["swarm", "autonomous-loop-run", "--repository", str(tmp_path), "--task-manifest", str(manifest), "--state-dir", str(state_dir), "--max-steps", "0"])
    assert main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["stop_reason"] == "STEP_BOUND_REACHED"
    assert (state_dir / "autonomous-loop.json").is_file()


def test_cli_run_refuses_manifest_that_bypasses_authoritative_queue(tmp_path: Path, capsys, monkeypatch):
    _write_control_files(tmp_path)
    status = tmp_path / "SWARM_STATUS.md"
    status.write_text(status.read_text(encoding="utf-8").replace("## Current state\n", "## Current state\n- Active phase: ForgeWarden Core\n"), encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "allowed.py").write_text("value = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base"], check=True)
    manifest = tmp_path.parent / f"{tmp_path.name}-bad-tasks.json"
    manifest.write_text(json.dumps({"tasks": [{"task_id": "FWQ-0002", "requirement": "Core test", "description": "bypass", "target_path": "allowed.py", "allowed_paths": ["allowed.py"]}]}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["swarm", "autonomous-loop-run", "--repository", str(tmp_path), "--task-manifest", str(manifest), "--state-dir", str(tmp_path.parent / f"{tmp_path.name}-state"), "--max-steps", "0"])
    assert main() == 1
    assert "authoritative eligible queue task" in capsys.readouterr().out


def test_review_pass_promotes_task_and_unlocks_dependency():
    tasks = {
        "FWQ-0001": TaskSpec("FWQ-0001", "Core review", "review", initial_state="REVIEW", review_disposition="PASSED"),
        "FWQ-0002": TaskSpec("FWQ-0002", "Core next", "next", dependencies=("FWQ-0001",), initial_state="READY"),
    }
    state = {"queued_tasks": {"FWQ-0001": {"state": "REVIEW", "attempts": 0}, "FWQ-0002": {"state": "READY", "attempts": 0}}, "completed_tasks": [], "task_specs": {}}
    transitions = progress_queue(tasks, state)
    assert transitions == ("FWQ-0001:REVIEW->DONE",)
    assert state["queued_tasks"]["FWQ-0001"]["state"] == "DONE"


def test_repairable_review_creates_ready_repair_task():
    tasks = {"FWQ-0009": TaskSpec("FWQ-0009", "Core review", "audit", initial_state="REVIEW", review_disposition="REPAIRABLE")}
    state = {"queued_tasks": {"FWQ-0009": {"state": "REVIEW", "attempts": 0}}, "completed_tasks": [], "task_specs": {}}
    transitions = progress_queue(tasks, state)
    assert transitions == ("FWQ-0009:REVIEW->REPAIR:FWQ-0010",)
    assert state["queued_tasks"]["FWQ-0010"]["state"] == "READY"


def test_internal_blocker_resolution_and_plan_derivation_prevent_stall():
    tasks = {"FWQ-0001": TaskSpec("FWQ-0001", "Core blocked", "blocked", initial_state="BLOCKED", blocker_resolved=True)}
    plan = (TaskSpec("FWQ-0011", "Core planned", "next authorized work", priority=2),)
    state = {"queued_tasks": {"FWQ-0001": {"state": "BLOCKED", "attempts": 0}}, "completed_tasks": [], "task_specs": {}}
    transitions = progress_queue(tasks, state, plan_tasks=plan)
    assert transitions == ("FWQ-0001:BLOCKED->READY",)
    assert state["queued_tasks"]["FWQ-0001"]["state"] == "READY"
    state["queued_tasks"]["FWQ-0001"]["state"] = "DONE"
    state["completed_tasks"].append("FWQ-0001")
    tasks.pop("FWQ-0001")
    transitions = progress_queue(tasks, state, plan_tasks=plan)
    assert transitions == ("PLAN->READY:FWQ-0011",)


def test_external_review_wait_does_not_derive_unbounded_successors():
    tasks = {"FWQ-0009": TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW")}
    state = {"queued_tasks": {"FWQ-0009": {"state": "REVIEW", "attempts": 0, "blocker_external": True}}, "completed_tasks": [], "task_specs": {}}
    plan = (TaskSpec("FWQ-0010", "Core follow-up", "next package"),)

    transitions = progress_queue(tasks, state, plan_tasks=plan)

    assert transitions == ()
    assert "FWQ-0010" not in tasks


def test_progress_queue_limits_external_review_attempts_per_run():
    tasks = {
        "FWQ-0001": TaskSpec("FWQ-0001", "Core review one", "review", initial_state="REVIEW"),
        "FWQ-0002": TaskSpec("FWQ-0002", "Core review two", "review", initial_state="REVIEW"),
    }
    state = {"queued_tasks": {task_id: {"state": "REVIEW", "attempts": 0} for task_id in tasks}, "completed_tasks": [], "task_specs": {}}
    seen = []

    progress_queue(tasks, state, review_resolver=lambda task, record: (seen.append(task.task_id) or "EXTERNAL"))

    assert seen == ["FWQ-0001"]


def test_blocked_task_becomes_ready_when_dependencies_complete():
    tasks = {
        "FWQ-0001": TaskSpec("FWQ-0001", "Core dependency", "dependency", initial_state="DONE"),
        "FWQ-0002": TaskSpec("FWQ-0002", "Core blocked", "blocked", dependencies=("FWQ-0001",), initial_state="BLOCKED"),
    }
    state = {"queued_tasks": {"FWQ-0001": {"state": "DONE", "attempts": 0}, "FWQ-0002": {"state": "BLOCKED", "attempts": 0}}, "completed_tasks": ["FWQ-0001"], "task_specs": {}}

    transitions = progress_queue(tasks, state)

    assert transitions == ("FWQ-0002:BLOCKED->READY",)
    assert state["queued_tasks"]["FWQ-0002"]["state"] == "READY"


def test_external_blocker_remains_blocked_after_dependencies_complete():
    tasks = {
        "FWQ-0001": TaskSpec("FWQ-0001", "Core dependency", "dependency", initial_state="DONE"),
        "FWQ-0002": TaskSpec("FWQ-0002", "Core review", "review", dependencies=("FWQ-0001",), initial_state="BLOCKED", blocker_external=True),
    }
    state = {"queued_tasks": {"FWQ-0001": {"state": "DONE", "attempts": 0}, "FWQ-0002": {"state": "BLOCKED", "attempts": 0}}, "completed_tasks": ["FWQ-0001"], "task_specs": {}}

    transitions = progress_queue(tasks, state)

    assert transitions == ()
    assert state["queued_tasks"]["FWQ-0002"]["state"] == "BLOCKED"


def test_external_task_without_target_is_parked_before_dispatch(tmp_path):
    task = TaskSpec("FWQ-0001", "Core review", "review", initial_state="BLOCKED", blocker_external=True)
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path, (task,))
    state = runner._initial()
    state["queued_tasks"][task.task_id] = {"state": "READY", "attempts": 1}
    runner._write(state)

    recovered = runner.status()

    assert recovered["queued_tasks"][task.task_id]["state"] == "BLOCKED"
    assert recovered["queued_tasks"][task.task_id]["blocker_external"] is True


def test_recovery_preserves_latched_external_blocker_metadata(tmp_path):
    task = TaskSpec("FWQ-0001", "Core review", "review", initial_state="BLOCKED", blocker_external=False)
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path, (task,))
    state = runner._initial()
    state["task_specs"][task.task_id]["blocker_external"] = True
    state["queued_tasks"][task.task_id] = {"state": "BLOCKED", "attempts": 0}
    runner._write(state)

    recovered = runner.status()

    assert recovered["queued_tasks"][task.task_id]["blocker_external"] is True


def test_authoritative_ready_task_is_requeued_once_after_failure(tmp_path):
    task = TaskSpec("FWQ-0001", "Core retry", "retry", initial_state="READY")
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path, (task,))
    state = runner._initial()
    state["queued_tasks"][task.task_id] = {"state": "FAILED", "attempts": 2}
    runner._write(state)

    recovered = runner.status()

    assert recovered["queued_tasks"][task.task_id]["state"] == "READY"
    assert recovered["queued_tasks"][task.task_id]["recovery_requeued"] is True


def test_runner_advances_review_only_queue_and_executes_derived_plan_task(tmp_path: Path):
    review_task = TaskSpec("FWQ-0009", "Core review", "reviewed package", initial_state="REVIEW", review_disposition="PASSED")
    plan_task = TaskSpec("FWQ-0010", "Core follow-up", "next package", priority=1)
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", (review_task,))
    dispatched: list[str] = []
    state = runner.run(
        dispatch=lambda task, lease: (dispatched.append(task.task_id) or WorkerResult(SHA_A, ("swarm/next.py",), ("pytest",))),
        validate=lambda task, result: True,
        commit=lambda task, result: result.candidate_commit or SHA_A,
        review=lambda task, commit, lease: ("APPROVED", "LOW"),
        plan_tasks=(plan_task,),
    )
    assert dispatched == ["FWQ-0010"]
    assert state["completed_tasks"] == ["FWQ-0009", "FWQ-0010"]


def test_plan_derivation_creates_only_bounded_core_queue_population_task(tmp_path: Path):
    (tmp_path / "ROADMAP.md").write_text("# ForgeWarden Roadmap\n## Current implementation priority\nForgeWarden Core\n## Phase discipline\n", encoding="utf-8")
    (tmp_path / "WORK_QUEUE.md").write_text("# ForgeWarden Work Queue\n## Future queue population\n", encoding="utf-8")
    task = derive_next_core_task(tmp_path, {"FWQ-0001", "FWQ-0009"})
    assert task is not None
    assert task.task_id == "FWQ-0010"
    assert task.requirement.startswith("Core ")
    assert task.allowed_paths == ("WORK_QUEUE.md",)


def test_plan_derivation_reconciles_ids_already_persisted_in_queue(tmp_path: Path):
    (tmp_path / "ROADMAP.md").write_text("# ForgeWarden Roadmap\n## Current implementation priority\nForgeWarden Core\n", encoding="utf-8")
    (tmp_path / "WORK_QUEUE.md").write_text("# ForgeWarden Work Queue\n### FWQ-0010 — Existing queued task\n## Future queue population\n", encoding="utf-8")
    task = derive_next_core_task(tmp_path, {"FWQ-0009"})
    assert task is not None
    assert task.task_id == "FWQ-0011"


def test_review_resolver_does_not_promote_without_exact_candidate_evidence(tmp_path: Path):
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW")
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)
    assert ExactReviewAdapter("review").resolve_review(task, lease) == "UNRESOLVED"


def test_review_resolver_preserves_provider_unavailability_as_external(tmp_path: Path, monkeypatch):
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW", review_commit=SHA_A)
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)
    monkeypatch.setattr(
        autonomous_adapters,
        "run_review_cycle",
        lambda *args, **kwargs: {"state": "REVIEW_REQUIRED", "reviews": [{"state": "UNAVAILABLE"}]},
    )
    assert ExactReviewAdapter("review").resolve_review(task, lease) == "EXTERNAL: Claude review record was not returned"


def test_review_unavailability_preserves_provider_diagnostic(tmp_path: Path, monkeypatch):
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW", review_commit=SHA_A)
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)
    monkeypatch.setattr(
        autonomous_adapters,
        "run_review_cycle",
        lambda *args, **kwargs: {"state": "REVIEW_REQUIRED", "reviews": [{"provider": "CLAUDE", "state": "UNAVAILABLE", "error": "Claude verifier timed out"}]},
    )
    assert ExactReviewAdapter("review").resolve_review(task, lease) == "EXTERNAL: Claude verifier timed out"


def test_external_review_diagnostic_is_persisted_and_bounded(tmp_path: Path):
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW", review_disposition="EXTERNAL: Claude verifier failed with sk-secret-token")
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", (task,))
    state = runner.run(
        dispatch=lambda task, lease: (_ for _ in ()).throw(AssertionError("blocked review must not dispatch")),
        validate=lambda task, result: True,
        commit=lambda task, result: SHA_A,
        review=lambda task, commit, lease: ("APPROVED", "LOW"),
    )
    assert "Claude verifier failed" in state["queued_tasks"]["FWQ-0009"]["blocker"]
    assert "sk-secret-token" not in state["queued_tasks"]["FWQ-0009"]["blocker"]


def test_review_resolver_ignores_optional_provider_outage_when_claude_is_available(tmp_path: Path, monkeypatch):
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW", review_commit=SHA_A)
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)
    monkeypatch.setattr(
        autonomous_adapters,
        "run_review_cycle",
        lambda *args, **kwargs: {"state": "REVIEW_REQUIRED", "reviews": [
            {"provider": "CLAUDE", "state": "APPROVED"},
            {"provider": "OPENROUTER", "state": "UNAVAILABLE"},
        ]},
    )
    assert ExactReviewAdapter("review").resolve_review(task, lease) == "REPAIRABLE"


def test_exact_review_adapter_uses_claude_adjudication_as_final_evidence(tmp_path: Path, monkeypatch):
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW")
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)
    payload = {"job_id": "phase2a-" + "0" * 24, "reviewed_commit": SHA_A, "verdict": "APPROVE", "risk": "LOW", "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [], "reasoning_summary": "final", "proposed_rules": []}
    monkeypatch.setattr(autonomous_adapters, "run_review_cycle", lambda *args, **kwargs: {"state": "APPROVED", "reviews": [{"provider": "OPENROUTER", "state": "REVIEW_RETURNED", "result": payload}], "adjudication": {"provider": "CLAUDE_ADJUDICATION", "state": "APPROVED", "result": payload}})
    result = ExactReviewAdapter("review", reviewers=("CLAUDE", "OPENROUTER")).review(task, SHA_A, lease)
    assert set(result) == {"CLAUDE"}
    assert result["CLAUDE"].rationale == "final"


def test_codex_task_adapter_dispatches_bounded_writer(tmp_path: Path, monkeypatch):
    target = tmp_path / "target.py"
    target.write_text("pass\n", encoding="utf-8")
    task = TaskSpec("FWQ-0011", "Core", "implement", allowed_paths=("target.py",), target_path="target.py")
    lease = WorkerLease("lease", task.task_id, "session", str(tmp_path), task.allowed_paths, "IMPLEMENT_AND_TEST", (), time.time() + 60)
    captured = {}
    payload = {"job_id": "codex-fwq-0011", "status": "FIXED", "root_cause": "test", "summary": "ok", "changed_files": ["target.py"], "tests_added_or_changed": [], "commands_run": [], "remaining_risks": [], "requires_human_approval": False}
    monkeypatch.setattr("swarm.autonomous_adapters.CodexAdapter.run", lambda self, spec, prompt: payload)
    result = CodexTaskAdapter(Path(__file__).parents[1] / "schemas/codex-result.schema.json", "codex").dispatch(task, lease)
    assert result.changed_files == ("target.py",)


def test_codex_task_adapter_requires_target_path(tmp_path: Path):
    target = tmp_path / "target.py"
    target.write_text("pass\n", encoding="utf-8")
    task = TaskSpec("FWQ-0011", "Core", "implement")
    lease = WorkerLease("lease", task.task_id, "session", str(tmp_path), task.allowed_paths, "IMPLEMENT_AND_TEST", (), time.time() + 60)
    with pytest.raises(ValueError, match="target path"):
        CodexTaskAdapter(Path(__file__).parents[1] / "schemas/codex-result.schema.json", "codex").dispatch(task, lease)


def test_runner_stops_only_for_explicit_external_review_resource_blocker(tmp_path: Path):
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW", review_disposition="EXTERNAL")
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", (task,))
    state = runner.run(
        dispatch=lambda task, lease: (_ for _ in ()).throw(AssertionError("blocked review must not dispatch")),
        validate=lambda task, result: True,
        commit=lambda task, result: SHA_A,
        review=lambda task, commit, lease: ("APPROVED", "LOW"),
    )
    assert state["stop_reason"] == "REQUIRED_RESOURCE_UNAVAILABLE"


def test_runner_defers_candidate_when_review_resource_is_unavailable(tmp_path: Path):
    task = TaskSpec("FWQ-0013", "Core implementation", "bounded change", initial_state="READY")
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path, (task,))
    state = runner.run(
        dispatch=lambda task, lease: WorkerResult(None, (), (), "bounded"),
        validate=lambda task, result: True,
        commit=lambda task, result: SHA_A,
        review=lambda task, commit, lease: (_ for _ in ()).throw(ReviewUnavailable("reviewer unavailable")),
        max_steps=1,
    )
    assert state["queued_tasks"]["FWQ-0013"]["state"] == "REVIEW"
    assert state["queued_tasks"]["FWQ-0013"]["review_commit"] == SHA_A
    assert state["queued_tasks"]["FWQ-0013"]["blocker_external"] is True


def test_external_review_blocker_is_not_retried_on_resume(tmp_path: Path):
    state_path = tmp_path / "run.json"
    state_path.write_text(json.dumps({
        "version": 1,
        "session_id": "session",
        "phase": "ForgeWarden Core",
        "milestone": None,
        "current_work_package": "FWQ-0013",
        "task_specs": {"FWQ-0013": asdict(TaskSpec("FWQ-0013", "Core review", "review", initial_state="REVIEW", blocker_external=True, review_commit=SHA_A))},
        "queued_tasks": {"FWQ-0013": {"state": "REVIEW", "attempts": 1, "blocker_external": True, "review_commit": SHA_A}},
        "active_task": None,
        "completed_tasks": [],
        "failed_tasks": [],
        "retry_count": {},
        "worker_assigned": None,
        "worker_lease": None,
        "repository_head_before": None,
        "repository_head_after": None,
        "test_results": [],
        "reviewer_result": None,
        "acceptance_result": None,
        "unresolved_blockers": [],
        "next_action": "restore review resource and resume queue evaluation",
        "timestamps": {"created_at": 1, "updated_at": 1},
        "stop_reason": "REQUIRED_RESOURCE_UNAVAILABLE",
        "dry_run": True,
        "deployment": "DISABLED",
        "kill_switch": "ENGAGED",
    }), encoding="utf-8")
    runner = AutonomousOrchestrator(state_path, tmp_path / "repo", (TaskSpec("FWQ-0013", "Core review", "review", initial_state="REVIEW"),))
    calls = []
    state = runner.run(
        dispatch=lambda task, lease: (_ for _ in ()).throw(AssertionError("parked review must not dispatch")),
        validate=lambda task, result: True,
        commit=lambda task, result: SHA_A,
        review=lambda task, commit, lease: calls.append(task.task_id),
    )
    assert calls == []
    assert state["stop_reason"] == "REQUIRED_RESOURCE_UNAVAILABLE"


def test_resume_restores_exact_review_commit_from_durable_task_state(tmp_path: Path):
    state_path = tmp_path / "run.json"
    state_path.write_text(json.dumps({
        "version": 1,
        "session_id": "session",
        "phase": "ForgeWarden Core",
        "milestone": None,
        "current_work_package": "FWQ-0013",
        "task_specs": {"FWQ-0013": asdict(TaskSpec("FWQ-0013", "Core review", "review", initial_state="REVIEW", blocker_external=True, review_commit=SHA_A))},
        "queued_tasks": {"FWQ-0013": {"state": "REVIEW", "attempts": 0, "blocker_external": True, "review_commit": SHA_A}},
        "active_task": None,
        "completed_tasks": [],
        "failed_tasks": [],
        "retry_count": {},
        "worker_assigned": None,
        "worker_lease": None,
        "repository_head_before": None,
        "repository_head_after": None,
        "test_results": [],
        "reviewer_result": None,
        "acceptance_result": None,
        "unresolved_blockers": [],
        "next_action": "restore review resource and resume queue evaluation",
        "timestamps": {"created_at": 1, "updated_at": 1},
        "stop_reason": "REQUIRED_RESOURCE_UNAVAILABLE",
        "dry_run": True,
        "deployment": "DISABLED",
        "kill_switch": "ENGAGED",
    }), encoding="utf-8")
    runner = AutonomousOrchestrator(state_path, tmp_path / "repo", (TaskSpec("FWQ-0013", "Core review", "review", initial_state="REVIEW"),))
    assert runner.status()["task_specs"]["FWQ-0013"]["review_commit"] == SHA_A
