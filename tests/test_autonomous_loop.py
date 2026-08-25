from __future__ import annotations

import json
import time
from pathlib import Path

from swarm.autonomous_loop import AutonomousOrchestrator, TaskSpec, WorkerLease, WorkerResult


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
