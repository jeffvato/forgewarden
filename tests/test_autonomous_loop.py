from __future__ import annotations

import json
import sys
import shutil
import subprocess
import time
from dataclasses import asdict
from pathlib import Path
import pytest

from swarm.autonomous_loop import AutonomousLoopError, AutonomousOrchestrator, GitCheckpointController, ReviewUnavailable, TaskSpec, WorkerLease, WorkerResult, progress_queue
from swarm.autonomous_adapters import CodexTaskAdapter, ExactReviewAdapter, WorkerIsolationUnavailable, run_deterministic_tests
import swarm.autonomous_adapters as autonomous_adapters
from swarm.plan_derivation import derive_next_core_task
from swarm.cli import _validate_manifest_task_authority, main
from swarm.review_handoff import ReviewResult
from swarm.work_checkpoint import load_checkpoint, reconcile_checkpoint
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


def test_autonomous_loop_accepts_and_persists_anythingllm_review_without_legacy_attribution(tmp_path: Path):
    task = TaskSpec("FWQ-0001", "Core review", "single")
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", (task,))
    state = runner.run(
        dispatch=lambda *_: WorkerResult(SHA_A, (), ("pytest",)),
        validate=lambda *_: True,
        commit=lambda _task, result: result.candidate_commit,
        review=lambda _task, sha, _lease: {
            "ANYTHINGLLM": ReviewResult("ANYTHINGLLM", sha, (), "LOW", "APPROVED", "exact Qwen evidence")
        },
    )
    assert state["completed_tasks"] == ["FWQ-0001"]
    checkpoint = load_checkpoint(runner.checkpoint_path)
    assert checkpoint.claude_review == "NOT_USED"
    assert checkpoint.gemini_review == "NOT_USED"
    assert checkpoint.reviewer_evidence == ("ANYTHINGLLM:APPROVED:LOW",)
    assert reconcile_checkpoint(checkpoint, SHA_A)["expected_commit"] == SHA_A


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


def test_unexpired_persisted_lease_must_match_controller_binding(tmp_path: Path):
    task = TaskSpec("FWQ-0001", "Core lease", "bound lease", allowed_paths=("swarm/a.py",))
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", (task,))
    state = runner._initial()
    state["active_task"] = task.task_id
    state["queued_tasks"][task.task_id]["state"] = "IN_PROGRESS"
    state["worker_lease"] = asdict(WorkerLease(
        "a" * 32, task.task_id, runner.session_id, str(runner.repository), task.allowed_paths,
        "IMPLEMENT_AND_TEST", (), time.time() + 60, controller_digest="tampered",
    ))
    runner._write(state)

    with pytest.raises(Exception, match="controller binding"):
        runner.status()


def test_consumed_lease_cannot_be_replayed_after_restart(tmp_path: Path):
    task = TaskSpec("FWQ-0001", "Core lease", "no replay")
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", (task,))
    lease = WorkerLease(
        "a" * 32, task.task_id, runner.session_id, str(runner.repository), (),
        "IMPLEMENT_AND_TEST", ("approved deterministic test commands",), time.time() + 60,
        controller_digest=runner._controller_digest(task),
    )
    state = runner._initial()
    state["active_task"] = task.task_id
    state["queued_tasks"][task.task_id]["state"] = "IN_PROGRESS"
    state["worker_lease"] = asdict(lease)
    state["consumed_lease_ids"] = [lease.lease_id]
    runner._write(state)

    with pytest.raises(Exception, match="replays a consumed"):
        runner.status()


def test_supervisor_can_stop_between_worker_and_validation(tmp_path: Path):
    task = TaskSpec("FWQ-0001", "Core stop", "safe interruption")
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", (task,))
    checks = iter((True, True, False))
    dispatched = []
    validation_called = []

    state = runner.run(
        dispatch=lambda current, lease: (dispatched.append(True) or WorkerResult(SHA_A, (), ("pytest",))),
        validate=lambda current, result: (validation_called.append(True) or True),
        commit=lambda current, result: SHA_A,
        review=lambda current, sha, lease: ("APPROVED",),
        authorized=lambda: next(checks),
    )

    assert dispatched == [True]
    assert validation_called == []
    assert state["queued_tasks"][task.task_id]["state"] == "READY"
    assert state["stop_reason"] == "SUPERVISOR_TERMINATED"
    assert any("task_safely_interrupted" in line for line in (tmp_path / "execution-log.jsonl").read_text().splitlines())


def test_actual_worktree_scope_is_verified_before_deterministic_validation(tmp_path: Path):
    task = TaskSpec("FWQ-0001", "Core scope", "verify before execute", allowed_paths=("source.py",), target_path="source.py", retry_budget=0)
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", (task,))
    validation_called = []
    verification_called = []

    def verify(current, result):
        verification_called.append((current.task_id, result.changed_files))
        raise AutonomousLoopError("actual worktree contains an unreported path")

    state = runner.run(
        dispatch=lambda current, lease: WorkerResult(None, ("source.py",), ("pytest",)),
        validate=lambda current, result: validation_called.append(True) or True,
        commit=lambda current, result: SHA_A,
        review=lambda current, commit, lease: ("APPROVED", "LOW"),
        verify_changes=verify,
    )
    assert verification_called == [(task.task_id, ("source.py",))]
    assert validation_called == []
    assert state["queued_tasks"][task.task_id]["state"] == "FAILED"


def test_audit_evidence_refuses_symlink_target(tmp_path: Path):
    target = tmp_path / "outside.jsonl"
    audit = tmp_path / "audit.jsonl"
    audit.symlink_to(target)
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", _tasks(), audit_path=audit)

    with pytest.raises(Exception, match="unsafe audit evidence path"):
        runner.status()
    assert not target.exists()


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
    state_dir = tmp_path.parent / f"{tmp_path.name}-external-state"
    monkeypatch.setattr(sys, "argv", ["swarm", "autonomous-loop-status", "--repository", str(tmp_path), "--state-dir", str(state_dir)])
    assert main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["selected_task"] == "FWQ-0001"
    assert payload["durable_state"] is None


def test_cli_bounds_repository_local_durable_status_state(tmp_path: Path, capsys, monkeypatch):
    _write_control_files(tmp_path)
    status = tmp_path / "SWARM_STATUS.md"
    status.write_text(status.read_text(encoding="utf-8").replace("## Current state\n", "## Current state\n- Active phase: ForgeWarden Core\n"), encoding="utf-8")
    state_dir = tmp_path.parent / f"{tmp_path.name}-oversize-state"
    state_dir.mkdir()
    (state_dir / "autonomous-loop.json").write_text(" " * (1_048_577), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["swarm", "autonomous-loop-status", "--repository", str(tmp_path), "--state-dir", str(state_dir)])
    assert main() == 1
    assert "1 MiB status bound" in capsys.readouterr().out


def test_cli_plan_task_preserves_non_ready_initial_state(tmp_path: Path, capsys, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "source.py").write_text("pass\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "source.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base"], check=True)
    manifest = tmp_path / "tasks.json"
    manifest.write_text(json.dumps({"tasks": [], "plan_tasks": [{
        "task_id": "FWQ-0095", "requirement": "Core planned", "description": "blocked plan",
        "target_path": "source.py", "allowed_paths": ["source.py"], "test_command": ["pytest", "-q"],
        "authorized": True, "initial_state": "BLOCKED",
    }]}), encoding="utf-8")
    state_dir = tmp_path / "state"
    monkeypatch.setattr(sys, "argv", ["swarm", "autonomous-loop-run", "--repository", str(repo), "--task-manifest", str(manifest), "--state-dir", str(state_dir), "--max-steps", "0"])
    assert main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert "FWQ-0095" not in payload["queued_tasks"]


def test_durable_state_cannot_inject_task_authority_absent_from_manifest(tmp_path: Path):
    task = TaskSpec("FWQ-0001", "Core authorized", "root", allowed_paths=("source.py",), target_path="source.py", test_command=("pytest", "-q"))
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", (task,))
    state = runner._initial()
    injected = TaskSpec("FWQ-9999", "Core injected", "unapproved", allowed_paths=("private",), target_path="private/key.py", test_command=("python3", "-c", "print('no')"))
    state["task_specs"][injected.task_id] = asdict(injected)
    state["queued_tasks"][injected.task_id] = {"state": "READY", "attempts": 0}
    runner._write(state)
    with pytest.raises(AutonomousLoopError, match="not authorized by the current manifest"):
        runner.status()


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
    assert controller.head() != accepted
    assert (repo / "allowed.py").read_text(encoding="utf-8") == "before\n"
    controller.accept_candidate(accepted, task.allowed_paths)
    assert controller.head() == accepted
    assert (repo / "allowed.py").read_text(encoding="utf-8") == "after\n"
    controller.accept_candidate(accepted, task.allowed_paths)  # Re-reviewing current HEAD is idempotent.
    controller.accept_candidate(accepted.upper(), task.allowed_paths)  # Git object IDs are case-insensitive.
    assert controller.head() == accepted


def test_review_candidate_scope_rejects_a_path_outside_the_manifest(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "allowed.py").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "allowed.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base"], check=True)
    base = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    (repo / "private.txt").write_text("unauthorized\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "private.txt"], check=True)
    tree = subprocess.check_output(["git", "-C", str(repo), "write-tree"], text=True).strip()
    candidate = subprocess.check_output(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit-tree", tree, "-p", base, "-m", "out-of-scope candidate"], text=True).strip()
    subprocess.run(["git", "-C", str(repo), "reset", "--hard", base], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "clean", "-fd"], check=True, capture_output=True)
    controller = GitCheckpointController(repo)
    with pytest.raises(AutonomousLoopError, match="outside explicit allowed_paths"):
        controller.verify_candidate_scope(candidate, ("allowed.py",))
    with pytest.raises(AutonomousLoopError, match="outside explicit allowed_paths"):
        controller.accept_candidate(candidate, ("allowed.py",))
    assert controller.head() == base


def test_review_candidate_scope_accepts_only_an_explicitly_allowed_diff(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "allowed.py").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "allowed.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base"], check=True)
    base = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    (repo / "allowed.py").write_text("candidate\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "allowed.py"], check=True)
    tree = subprocess.check_output(["git", "-C", str(repo), "write-tree"], text=True).strip()
    candidate = subprocess.check_output(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit-tree", tree, "-p", base, "-m", "in-scope candidate"], text=True).strip()
    subprocess.run(["git", "-C", str(repo), "reset", "--hard", base], check=True, capture_output=True)
    controller = GitCheckpointController(repo)
    assert controller.verify_candidate_scope(candidate, ("allowed.py",)) == ("allowed.py",)
    controller.accept_candidate(candidate, ("allowed.py",))
    assert controller.head() == candidate
    assert (repo / "allowed.py").read_text(encoding="utf-8") == "candidate\n"


def test_rejected_candidate_does_not_advance_accepted_repository_head(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "allowed.py").write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "allowed.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base"], check=True)
    base = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
    task = TaskSpec("FWQ-0001", "Core candidate", "reject safely", allowed_paths=("allowed.py",), target_path="allowed.py", retry_budget=0)
    controller = GitCheckpointController(repo)
    runner = AutonomousOrchestrator(tmp_path / "run.json", repo, (task,))

    def dispatch(current, lease):
        (repo / "allowed.py").write_text("candidate\n", encoding="utf-8")
        return WorkerResult(None, ("allowed.py",), ("pytest",))

    state = runner.run(
        dispatch=dispatch,
        verify_changes=controller.verify_worker_changes,
        validate=lambda current, result: True,
        commit=controller.commit_worker_changes,
        review=lambda current, commit, lease: ("REJECT",),
        accepted=lambda current, candidate: controller.accept_candidate(candidate, current.allowed_paths),
    )
    assert state["queued_tasks"][task.task_id]["state"] == "FAILED"
    assert controller.head() == base
    assert (repo / "allowed.py").read_text(encoding="utf-8") == "before\n"


def test_untracked_candidate_is_removed_until_accepted(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "base.py").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "base.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base"], check=True)
    (repo / "new.py").write_text("candidate\n", encoding="utf-8")
    task = TaskSpec("FWQ-0001", "Core new file", "new file", allowed_paths=("new.py",))
    controller = GitCheckpointController(repo)
    candidate = controller.commit_worker_changes(task, WorkerResult(None, ("new.py",), ("pytest",)))
    assert not (repo / "new.py").exists()
    controller.ensure_clean()
    controller.accept_candidate(candidate, task.allowed_paths)
    assert (repo / "new.py").read_text(encoding="utf-8") == "candidate\n"


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


def _make_validation_repository(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    (path / "source.py").write_text("candidate = True\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "source.py"], check=True)
    subprocess.run(["git", "-C", str(path), "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base"], check=True)
    (path / "source.py").write_text("candidate = False\n", encoding="utf-8")
    (path / ".env").write_text("fixture-only-not-for-sandbox\n", encoding="utf-8")
    (path / "ignored-note.txt").write_text("must not be copied\n", encoding="utf-8")
    return path


def test_real_adapter_validation_uses_disposable_bubblewrap_snapshot(tmp_path: Path, monkeypatch):
    repo = _make_validation_repository(tmp_path / "repo")
    task = TaskSpec("FWQ-0001", "Core test", "test", allowed_paths=("source.py",), test_command=("python3", "-c", "print('ok')"))
    result = WorkerResult(None, ("source.py",), task.test_command)
    observed = {}

    def limited_run(command, cwd, prompt, limits, env, **kwargs):
        workspace = Path(command[command.index("--bind") + 1])
        observed.update(command=command, cwd=cwd, prompt=prompt, env=env, kwargs=kwargs, workspace=workspace)
        assert not (workspace / ".git").exists()
        assert not (workspace / ".env").exists()
        assert not (workspace / "ignored-note.txt").exists()
        assert (workspace / "source.py").read_text(encoding="utf-8") == "candidate = False\n"
        etc_targets = [command[index + 2] for index, item in enumerate(command[:-2]) if item == "--ro-bind" and command[index + 2].startswith("/etc/")]
        assert etc_targets == ["/etc/passwd", "/etc/group", "/etc/nsswitch.conf"]
        assert not any(command[index + 1:index + 3] == ["/etc", "/etc"] for index, item in enumerate(command[:-2]) if item == "--ro-bind")
        assert all((workspace.parent / "sandbox-etc" / Path(target).name).is_file() for target in etc_targets)
        return subprocess.CompletedProcess(command, 0, "ok\n", "")

    monkeypatch.setattr(autonomous_adapters.shutil, "which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None)
    monkeypatch.setattr(autonomous_adapters, "limited_run", limited_run)
    assert run_deterministic_tests(task, result, repo)
    assert observed["command"][:2] == ["/usr/bin/bwrap", "--unshare-all"]
    assert "--clearenv" in observed["command"]
    assert any(observed["command"][index + 1] == "/etc" for index, item in enumerate(observed["command"][:-1]) if item == "--tmpfs")
    assert not any(observed["command"][index + 1:index + 3] == ["/etc", "/etc"] for index, item in enumerate(observed["command"][:-2]) if item == "--ro-bind")
    assert "--tmpfs" in observed["command"]
    assert observed["cwd"] == Path("/")
    assert observed["kwargs"] == {"use_cgroup": True, "minimal_environment": True, "network_isolated": True}
    assert observed["env"] == {"SWARM_ROLE": "DETERMINISTIC_VALIDATION", "SWARM_DRY_RUN": "1"}
    assert not run_deterministic_tests(task, WorkerResult(None, ("../outside.py",), task.test_command), repo)
    assert not run_deterministic_tests(TaskSpec("FWQ-0001", "Core test", "test"), result, repo)


@pytest.mark.skipif(not shutil.which("bwrap") or not shutil.which("systemd-run"), reason="Linux bubblewrap and systemd-run are required")
def test_validation_process_cannot_read_host_tmp_or_git_metadata(tmp_path: Path):
    repo = _make_validation_repository(tmp_path / "repo")
    host_only = tmp_path / "host-only.txt"
    host_only.write_text("not-visible-to-sandbox\n", encoding="utf-8")
    code = (
        "import os,sys,pwd; "
        "assert not os.path.exists(sys.argv[1]), 'host tmp visible'; "
        "assert not os.path.exists('.git'), 'supervisor Git metadata visible'; "
        "assert not os.path.exists('.env'), 'environment file visible'; "
        "assert not os.path.exists('/etc/hostname'), 'host /etc visible'; "
        "assert not os.path.exists('/etc/os-release'), 'host /etc/os-release visible'; "
        "assert pwd.getpwuid(os.getuid()).pw_name in {'forgewarden','root'}, 'unexpected sandbox identity'; "
        "assert open('source.py', encoding='utf-8').read() == 'candidate = False\\n'"
    )
    task = TaskSpec("FWQ-0001", "Core isolation", "sandbox", allowed_paths=("source.py",), test_command=("python3", "-c", code, str(host_only)))
    result = WorkerResult(None, ("source.py",), task.test_command)
    assert run_deterministic_tests(task, result, repo)


def test_codex_task_adapter_fails_closed_before_worker_process(tmp_path: Path, monkeypatch):
    target = tmp_path / "target.py"
    target.write_text("pass\n", encoding="utf-8")
    task = TaskSpec("FWQ-0011", "Core", "implement", allowed_paths=("target.py",), target_path="target.py")
    lease = WorkerLease("lease", task.task_id, "session", str(tmp_path), task.allowed_paths, "IMPLEMENT_AND_TEST", (), time.time() + 60)
    monkeypatch.setattr("swarm.autonomous_adapters.CodexAdapter.run", lambda *args, **kwargs: pytest.fail("unsafe writer was launched"))
    with pytest.raises(WorkerIsolationUnavailable, match="OS-enforced sandbox"):
        CodexTaskAdapter(Path(__file__).parents[1] / "schemas/codex-result.schema.json", "codex").dispatch(task, lease)


def test_cli_refuses_markdown_only_authorization(tmp_path: Path, capsys, monkeypatch):
    _write_control_files(tmp_path)
    state_dir = tmp_path.parent / f"{tmp_path.name}-state"
    monkeypatch.setattr(sys, "argv", ["swarm", "autonomous-loop-run", "--repository", str(tmp_path), "--state-dir", str(state_dir)])
    assert main() == 1
    assert "explicit task manifest" in capsys.readouterr().out
    assert not (state_dir / "autonomous-loop.json").exists()


def test_cli_rejects_task_manifest_inside_repository(tmp_path: Path, capsys, monkeypatch):
    (tmp_path / "inside.json").write_text(json.dumps({"tasks": []}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["swarm", "autonomous-loop-run", "--repository", str(tmp_path), "--task-manifest", str(tmp_path / "inside.json"), "--state-dir", str(tmp_path.parent / f"{tmp_path.name}-state")])
    assert main() == 1
    assert "outside the Git repository" in capsys.readouterr().out


@pytest.mark.parametrize("symlink_ancestor", [False, True], ids=["manifest-file", "ancestor-directory"])
def test_cli_rejects_task_manifest_symlink_and_symlinked_ancestor(tmp_path: Path, capsys, monkeypatch, symlink_ancestor):
    repository = tmp_path / "repo"
    repository.mkdir()
    outside = tmp_path / "operator-control"
    outside.mkdir()
    external_manifest = outside / "tasks.json"
    external_manifest.write_text(json.dumps({"tasks": []}), encoding="utf-8")
    if symlink_ancestor:
        manifest_directory = repository / "linked-control"
        manifest_directory.symlink_to(outside, target_is_directory=True)
        manifest = manifest_directory / "tasks.json"
    else:
        manifest = repository / "tasks.json"
        manifest.symlink_to(external_manifest)
    state_dir = tmp_path / "state"
    monkeypatch.setattr(sys, "argv", [
        "swarm", "autonomous-loop-run", "--repository", str(repository),
        "--task-manifest", str(manifest), "--state-dir", str(state_dir),
    ])
    assert main() == 1
    assert "task manifest path is symlinked" in capsys.readouterr().out
    assert not (state_dir / "autonomous-loop.json").exists()


def test_cli_rejects_unbounded_authorized_task_manifest(tmp_path: Path, capsys, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    manifest = tmp_path / "unbounded.json"
    manifest.write_text(json.dumps({"tasks": [{"task_id": "FWQ-0001", "requirement": "Core test", "description": "unbounded", "target_path": "allowed.py", "allowed_paths": [], "test_command": ["pytest", "-q"], "authorized": True}]}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["swarm", "autonomous-loop-run", "--repository", str(repo), "--task-manifest", str(manifest), "--state-dir", str(tmp_path / "state")])
    assert main() == 1
    assert "non-empty allowed_paths" in capsys.readouterr().out


def test_review_state_manifest_requires_explicit_allowed_paths():
    item = {"task_id": "FWQ-0001", "requirement": "Core review", "description": "review existing candidate", "authorized": True, "initial_state": "REVIEW", "review_commit": SHA_A}
    with pytest.raises(AutonomousLoopError, match="explicit non-empty allowed_paths"):
        _validate_manifest_task_authority(item)


@pytest.mark.parametrize("target", ["../outside.py", "./allowed.py", "folder/../allowed.py", "C:/outside.py", "folder\\outside.py", "/outside.py"])
def test_manifest_rejects_noncanonical_or_absolute_target_paths(target: str):
    item = {"authorized": True, "initial_state": "READY", "target_path": target, "allowed_paths": ["allowed.py"], "test_command": ["pytest", "-q"]}
    with pytest.raises(AutonomousLoopError, match="target_path must be a normalized"):
        _validate_manifest_task_authority(item)


@pytest.mark.parametrize("path", ["../outside", "./allowed", "folder/../allowed", "D:/root", "folder\\outside", "/absolute"])
def test_manifest_rejects_noncanonical_or_absolute_allowed_paths(path: str):
    item = {"authorized": True, "initial_state": "READY", "target_path": "allowed.py", "allowed_paths": [path], "test_command": ["pytest", "-q"]}
    with pytest.raises(AutonomousLoopError, match="allowed_paths must be normalized"):
        _validate_manifest_task_authority(item)


@pytest.mark.parametrize("authorization", [None, False, 1, "true"])
def test_manifest_requires_explicit_boolean_authorization(authorization):
    item = {"authorized": authorization, "initial_state": "READY", "target_path": "allowed.py", "allowed_paths": ["allowed.py"], "test_command": ["pytest", "-q"]}
    with pytest.raises(AutonomousLoopError, match="explicit authorized: true"):
        _validate_manifest_task_authority(item)


def test_cli_autonomous_loop_run_persists_without_dispatch_when_step_bound_is_zero(tmp_path: Path, capsys, monkeypatch):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "allowed.py").write_text("value = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "allowed.py"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base"], check=True)
    manifest = tmp_path.parent / f"{tmp_path.name}-tasks.json"
    manifest.write_text(json.dumps({"tasks": [{"task_id": "FWQ-0001", "requirement": "Core test", "description": "bounded", "target_path": "allowed.py", "allowed_paths": ["allowed.py"], "test_command": ["python3", "-c", "print('ok')"], "authorized": True}]}), encoding="utf-8")
    state_dir = tmp_path.parent / f"{tmp_path.name}-state"
    monkeypatch.setattr(sys, "argv", ["swarm", "autonomous-loop-run", "--repository", str(tmp_path), "--task-manifest", str(manifest), "--state-dir", str(state_dir), "--max-steps", "0"])
    selected_reviewers = []
    original_adapter = ExactReviewAdapter
    def capture_adapter(*args, **kwargs):
        adapter = original_adapter(*args, **kwargs)
        selected_reviewers.append(adapter.reviewers)
        return adapter
    monkeypatch.setattr("swarm.cli.ExactReviewAdapter", capture_adapter)
    assert main() == 0
    assert selected_reviewers == [("DAYBREAK",)]
    payload = json.loads(capsys.readouterr().out)
    assert payload["stop_reason"] == "STEP_BOUND_REACHED"
    assert (state_dir / "autonomous-loop.json").is_file()


def test_cli_rejects_manifest_that_selects_disabled_reviewers(tmp_path: Path, capsys, monkeypatch):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "allowed.py").write_text("value = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "allowed.py"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base"], check=True)
    manifest = tmp_path.parent / f"{tmp_path.name}-disabled-reviewer.json"
    manifest.write_text(json.dumps({
        "reviewers": ["DAYBREAK", "CLAUDE"],
        "tasks": [{"task_id": "FWQ-0001", "requirement": "Core test", "description": "bounded", "target_path": "allowed.py", "allowed_paths": ["allowed.py"], "test_command": ["pytest", "-q"], "authorized": True}],
    }), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["swarm", "autonomous-loop-run", "--repository", str(tmp_path), "--task-manifest", str(manifest), "--state-dir", str(tmp_path.parent / f"{tmp_path.name}-state"), "--max-steps", "0"])
    assert main() == 1
    assert "requires Daybreak only" in capsys.readouterr().out


def test_cli_run_refuses_manifest_that_bypasses_authoritative_queue(tmp_path: Path, capsys, monkeypatch):
    _write_control_files(tmp_path)
    status = tmp_path / "SWARM_STATUS.md"
    status.write_text(status.read_text(encoding="utf-8").replace("## Current state\n", "## Current state\n- Active phase: ForgeWarden Core\n"), encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "allowed.py").write_text("value = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base"], check=True)
    manifest = tmp_path.parent / f"{tmp_path.name}-bad-tasks.json"
    manifest.write_text(json.dumps({"tasks": [{"task_id": "FWQ-0002", "requirement": "Core test", "description": "bypass", "target_path": "allowed.py", "allowed_paths": ["allowed.py"], "test_command": ["pytest", "-q"], "authorized": True}]}), encoding="utf-8")
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


def test_review_repair_does_not_promote_test_operands_to_writable_paths():
    task = TaskSpec("FWQ-0097", "Core review", "repair", initial_state="REVIEW", allowed_paths=("src/module.py",), test_command=("pytest", "tests/test_module.py"))
    state = {"queued_tasks": {task.task_id: {"state": "REVIEW", "attempts": 0}}, "completed_tasks": [], "task_specs": {}}
    progress_queue({task.task_id: task}, state, review_resolver=lambda *_: "REPAIRABLE: finding")
    repair_id = state["queued_tasks"][task.task_id]["repair_enqueued"]
    assert state["task_specs"][repair_id]["allowed_paths"] == ("src/module.py",)


def test_unauthorized_review_task_cannot_call_reviewer_or_complete():
    task = TaskSpec("FWQ-0098", "Core review", "untrusted", initial_state="REVIEW", authorized=False, review_disposition="PASSED")
    state = {"queued_tasks": {task.task_id: {"state": "REVIEW", "attempts": 0}}, "completed_tasks": [], "task_specs": {}}
    calls = []
    transitions = progress_queue({task.task_id: task}, state, review_resolver=lambda *_: calls.append("review") or "PASSED")
    assert transitions == ()
    assert calls == []
    assert state["queued_tasks"][task.task_id]["state"] == "REVIEW"


def test_unauthorized_ready_task_is_not_selected(tmp_path: Path):
    task = TaskSpec("FWQ-0099", "Core work", "untrusted", initial_state="READY", authorized=False)
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path / "repo", (task,))
    assert runner._select({"queued_tasks": {task.task_id: {"state": "READY"}}, "completed_tasks": []}) is None


def test_repairable_review_creates_ready_repair_task():
    tasks = {"FWQ-0009": TaskSpec("FWQ-0009", "Core review", "audit", initial_state="REVIEW", review_disposition="REPAIRABLE")}
    state = {"queued_tasks": {"FWQ-0009": {"state": "REVIEW", "attempts": 0}}, "completed_tasks": [], "task_specs": {}}
    transitions = progress_queue(tasks, state)
    assert transitions == ("FWQ-0009:REVIEW->REPAIR:FWQ-0010",)
    assert state["queued_tasks"]["FWQ-0010"]["state"] == "READY"
    assert state["queued_tasks"]["FWQ-0009"]["repair_enqueued"] == "FWQ-0010"


def test_completed_repair_from_review_unblocks_one_next_task():
    tasks = {
        "FWQ-0001": TaskSpec("FWQ-0001", "Core review", "review", initial_state="REVIEW", review_disposition="REPAIRABLE"),
        "FWQ-0002": TaskSpec("FWQ-0002", "Core continuation", "continue", dependencies=("FWQ-0001",), initial_state="BLOCKED"),
    }
    state = {"queued_tasks": {"FWQ-0001": {"state": "REVIEW", "attempts": 0}, "FWQ-0002": {"state": "BLOCKED", "attempts": 0}}, "completed_tasks": [], "task_specs": {}}

    assert progress_queue(tasks, state) == ("FWQ-0001:REVIEW->REPAIR:FWQ-0003",)
    state["queued_tasks"]["FWQ-0003"]["state"] = "DONE"

    transitions = progress_queue(tasks, state)

    assert state["queued_tasks"]["FWQ-0001"]["state"] == "DONE"
    assert state["queued_tasks"]["FWQ-0002"]["state"] == "READY"
    assert transitions[:2] == ("FWQ-0001:REPAIR->DONE:FWQ-0003", "FWQ-0002:BLOCKED->READY")


def test_repair_state_creates_follow_up_ready_unit_once():
    tasks = {"FWQ-0009": TaskSpec("FWQ-0009", "Core review", "audit", initial_state="REPAIR")}
    state = {"queued_tasks": {"FWQ-0009": {"state": "REPAIR", "attempts": 0}}, "completed_tasks": [], "task_specs": {}}
    transitions = progress_queue(tasks, state)
    assert transitions == ("FWQ-0009:REPAIR->READY:FWQ-0010",)
    assert state["queued_tasks"]["FWQ-0010"]["state"] == "READY"
    assert state["queued_tasks"]["FWQ-0009"]["repair_enqueued"] == "FWQ-0010"
    assert progress_queue(tasks, state) == ()


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


def test_external_review_marker_is_rechecked_when_resolver_is_available():
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW")
    tasks = {task.task_id: task}
    state = {"queued_tasks": {task.task_id: {"state": "REVIEW", "attempts": 0, "blocker_external": True}}, "completed_tasks": [], "task_specs": {}}
    seen = []

    transitions = progress_queue(tasks, state, review_resolver=lambda current, record: (seen.append(current.task_id) or "PASSED"))

    assert seen == [task.task_id]
    assert state["queued_tasks"][task.task_id]["state"] == "DONE"
    assert f"{task.task_id}:EXTERNAL_BLOCKER->RECHECK" in transitions


def test_external_review_cooldown_prevents_hot_retry():
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW")
    tasks = {task.task_id: task}
    state = {"queued_tasks": {task.task_id: {"state": "REVIEW", "attempts": 0, "blocker_external": True, "review_retry_after": 9_999_999_999}}, "completed_tasks": [], "task_specs": {}}
    seen = []

    progress_queue(tasks, state, review_resolver=lambda current, record: (seen.append(current.task_id) or "PASSED"))

    assert seen == []
    assert state["queued_tasks"][task.task_id]["state"] == "REVIEW"


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


def test_failed_recovery_task_gets_one_bounded_successor(tmp_path):
    task = TaskSpec("FWQ-0001", "Core retry", "retry", initial_state="READY")
    runner = AutonomousOrchestrator(tmp_path / "run.json", tmp_path, (task,))
    state = runner._initial()
    state["queued_tasks"][task.task_id] = {"state": "FAILED", "attempts": 2, "recovery_requeued": True}
    runner._write(state)

    recovered = runner.status()

    assert recovered["queued_tasks"][task.task_id]["state"] == "FAILED"
    successor_id = recovered["queued_tasks"][task.task_id]["recovery_followup"]
    assert recovered["queued_tasks"][successor_id]["state"] == "READY"


def test_completed_repair_successor_satisfies_blocked_dependency(tmp_path):
    parent = TaskSpec("FWQ-0001", "Core repair", "repair", initial_state="REPAIR")
    blocked = TaskSpec(
        "FWQ-0002", "Core continuation", "continue", dependencies=("FWQ-0001",),
        initial_state="BLOCKED", target_path="source.py", allowed_paths=("source.py",),
        test_command=("pytest", "tests/test_source.py"), blocker_external=False,
    )
    state = {
        "queued_tasks": {
            "FWQ-0001": {"state": "REPAIR", "repair_enqueued": "FWQ-0003"},
            "FWQ-0002": {"state": "BLOCKED", "blocker_external": True},
            "FWQ-0003": {"state": "DONE"},
        },
        "completed_tasks": [], "task_specs": {},
    }

    transitions = progress_queue({"FWQ-0001": parent, "FWQ-0002": blocked}, state)

    assert "FWQ-0002:EXTERNAL_BLOCKER->CONCRETE" in transitions
    assert "FWQ-0002:BLOCKED->READY" in transitions


def test_completed_repair_successor_in_completion_history_satisfies_dependency():
    tasks = {
        "FWQ-0001": TaskSpec("FWQ-0001", "Core repair", "repair", initial_state="REPAIR"),
        "FWQ-0002": TaskSpec("FWQ-0002", "Core continuation", "continue", dependencies=("FWQ-0001",), initial_state="BLOCKED"),
    }
    state = {
        "queued_tasks": {
            "FWQ-0001": {"state": "REPAIR", "repair_enqueued": "FWQ-0003"},
            "FWQ-0002": {"state": "BLOCKED"},
            "FWQ-0003": {"state": "REPAIR"},
        },
        "completed_tasks": ["FWQ-0003"], "task_specs": {},
    }

    transitions = progress_queue(tasks, state)

    assert "FWQ-0002:BLOCKED->READY" in transitions


def test_completed_repair_successor_history_unlocks_parent_without_successor_queue_record():
    tasks = {
        "FWQ-0001": TaskSpec("FWQ-0001", "Core repair", "repair", initial_state="REPAIR"),
        "FWQ-0002": TaskSpec("FWQ-0002", "Core continuation", "continue", dependencies=("FWQ-0001",), initial_state="BLOCKED"),
    }
    state = {
        "queued_tasks": {
            "FWQ-0001": {"state": "REPAIR", "repair_enqueued": "FWQ-0003"},
            "FWQ-0002": {"state": "BLOCKED"},
        },
        "completed_tasks": ["FWQ-0003"], "task_specs": {},
    }

    transitions = progress_queue(tasks, state)

    assert state["queued_tasks"]["FWQ-0001"]["state"] == "DONE"
    assert state["queued_tasks"]["FWQ-0002"]["state"] == "READY"
    assert transitions[:2] == ("FWQ-0001:REPAIR->DONE:FWQ-0003", "FWQ-0002:BLOCKED->READY")


def test_completed_repair_successor_history_normalizes_stale_ready_record():
    tasks = {
        "FWQ-0001": TaskSpec("FWQ-0001", "Core repair", "repair", initial_state="REPAIR"),
        "FWQ-0002": TaskSpec("FWQ-0002", "Core continuation", "continue", dependencies=("FWQ-0001",), initial_state="BLOCKED"),
    }
    state = {
        "queued_tasks": {
            "FWQ-0001": {"state": "REPAIR", "repair_enqueued": "FWQ-0003"},
            "FWQ-0002": {"state": "BLOCKED"},
            "FWQ-0003": {"state": "READY"},
        },
        "completed_tasks": ["FWQ-0003"], "task_specs": {},
    }

    transitions = progress_queue(tasks, state)

    assert state["queued_tasks"]["FWQ-0003"]["state"] == "DONE"
    assert state["queued_tasks"]["FWQ-0002"]["state"] == "READY"
    assert transitions[:2] == ("FWQ-0001:REPAIR->DONE:FWQ-0003", "FWQ-0002:BLOCKED->READY")


def test_completed_repair_successor_reconciles_parent_and_unlocks_one_next_task():
    tasks = {
        "FWQ-0001": TaskSpec("FWQ-0001", "Core repair", "repair", initial_state="REPAIR"),
        "FWQ-0002": TaskSpec("FWQ-0002", "Core continuation", "continue", dependencies=("FWQ-0001",), initial_state="BLOCKED"),
    }
    state = {
        "queued_tasks": {
            "FWQ-0001": {"state": "REPAIR", "repair_enqueued": "FWQ-0003"},
            "FWQ-0002": {"state": "BLOCKED"},
            "FWQ-0003": {"state": "DONE"},
        },
        "completed_tasks": [], "task_specs": {},
    }

    transitions = progress_queue(tasks, state)

    assert state["queued_tasks"]["FWQ-0001"]["state"] == "DONE"
    assert state["queued_tasks"]["FWQ-0002"]["state"] == "READY"
    assert state["completed_tasks"] == ["FWQ-0003", "FWQ-0001"]
    assert [task_id for task_id, record in state["queued_tasks"].items() if record["state"] == "READY"] == ["FWQ-0002"]
    assert "FWQ-0001:REPAIR->DONE:FWQ-0003" in transitions


def test_completed_repair_successor_reconciles_ready_parent_without_duplicate_ready_work():
    tasks = {
        "FWQ-0001": TaskSpec("FWQ-0001", "Core repair", "repair", initial_state="READY"),
        "FWQ-0002": TaskSpec("FWQ-0002", "Core continuation", "first", dependencies=("FWQ-0001",), initial_state="BLOCKED"),
        "FWQ-0003": TaskSpec("FWQ-0003", "Core continuation", "second", dependencies=("FWQ-0001",), initial_state="BLOCKED"),
    }
    state = {
        "queued_tasks": {
            "FWQ-0001": {"state": "READY", "repair_enqueued": "FWQ-0004"},
            "FWQ-0002": {"state": "BLOCKED"},
            "FWQ-0003": {"state": "BLOCKED"},
            "FWQ-0004": {"state": "DONE"},
        },
        "completed_tasks": [], "task_specs": {},
    }

    transitions = progress_queue(tasks, state)

    assert state["queued_tasks"]["FWQ-0001"]["state"] == "DONE"
    assert [task_id for task_id, record in state["queued_tasks"].items() if record["state"] == "READY"] == ["FWQ-0002"]
    assert "FWQ-0001:READY->DONE:FWQ-0004" in transitions


def test_completed_repair_successor_reconciles_validated_parent_and_unlocks_next_task():
    tasks = {
        "FWQ-0001": TaskSpec("FWQ-0001", "Core repair", "repair", initial_state="VALIDATED"),
        "FWQ-0002": TaskSpec("FWQ-0002", "Core continuation", "continue", dependencies=("FWQ-0001",), initial_state="BLOCKED"),
    }
    state = {
        "queued_tasks": {
            "FWQ-0001": {"state": "VALIDATED", "repair_enqueued": "FWQ-0003"},
            "FWQ-0002": {"state": "BLOCKED"},
            "FWQ-0003": {"state": "DONE"},
        },
        "completed_tasks": [], "task_specs": {},
    }

    transitions = progress_queue(tasks, state)

    assert state["queued_tasks"]["FWQ-0001"]["state"] == "DONE"
    assert state["queued_tasks"]["FWQ-0002"]["state"] == "READY"
    assert [task_id for task_id, record in state["queued_tasks"].items() if record["state"] == "READY"] == ["FWQ-0002"]
    assert "FWQ-0001:VALIDATED->DONE:FWQ-0003" in transitions


def test_completed_repair_successor_reconciles_review_parent_and_unlocks_one_next_task():
    tasks = {
        "FWQ-0001": TaskSpec("FWQ-0001", "Core repair", "repair", initial_state="REVIEW"),
        "FWQ-0002": TaskSpec("FWQ-0002", "Core continuation", "continue", dependencies=("FWQ-0001",), initial_state="BLOCKED"),
    }
    state = {
        "queued_tasks": {
            "FWQ-0001": {"state": "REVIEW", "repair_enqueued": "FWQ-0003"},
            "FWQ-0002": {"state": "BLOCKED"},
            "FWQ-0003": {"state": "DONE"},
        },
        "completed_tasks": [], "task_specs": {},
    }

    transitions = progress_queue(tasks, state)

    assert state["queued_tasks"]["FWQ-0001"]["state"] == "DONE"
    assert state["queued_tasks"]["FWQ-0002"]["state"] == "READY"
    assert [task_id for task_id, record in state["queued_tasks"].items() if record["state"] == "READY"] == ["FWQ-0002"]
    assert "FWQ-0001:REVIEW->DONE:FWQ-0003" in transitions


def test_completed_repair_successor_reconciles_blocked_parent_and_unlocks_one_next_task():
    tasks = {
        "FWQ-0001": TaskSpec("FWQ-0001", "Core repair", "repair", initial_state="BLOCKED"),
        "FWQ-0002": TaskSpec("FWQ-0002", "Core continuation", "continue", dependencies=("FWQ-0001",), initial_state="BLOCKED"),
        "FWQ-0003": TaskSpec("FWQ-0003", "Core continuation", "later", dependencies=("FWQ-0001",), initial_state="BLOCKED"),
    }
    state = {
        "queued_tasks": {
            "FWQ-0001": {"state": "BLOCKED", "repair_enqueued": "FWQ-0004"},
            "FWQ-0002": {"state": "BLOCKED"},
            "FWQ-0003": {"state": "BLOCKED"},
            "FWQ-0004": {"state": "DONE"},
        },
        "completed_tasks": [], "task_specs": {},
    }

    transitions = progress_queue(tasks, state)

    assert state["queued_tasks"]["FWQ-0001"]["state"] == "DONE"
    assert [task_id for task_id, record in state["queued_tasks"].items() if record["state"] == "READY"] == ["FWQ-0002"]
    assert "FWQ-0001:BLOCKED->DONE:FWQ-0004" in transitions


def test_completed_repair_successor_unlocks_only_one_deterministic_next_task():
    tasks = {
        "FWQ-0001": TaskSpec("FWQ-0001", "Core repair", "repair", initial_state="REPAIR"),
        "FWQ-0002": TaskSpec("FWQ-0002", "Core continuation", "first", dependencies=("FWQ-0001",), initial_state="BLOCKED"),
        "FWQ-0003": TaskSpec("FWQ-0003", "Core continuation", "second", dependencies=("FWQ-0001",), initial_state="BLOCKED"),
    }
    state = {
        "queued_tasks": {
            "FWQ-0001": {"state": "REPAIR", "repair_enqueued": "FWQ-0004"},
            "FWQ-0002": {"state": "BLOCKED"},
            "FWQ-0003": {"state": "BLOCKED"},
            "FWQ-0004": {"state": "DONE"},
        },
        "completed_tasks": [], "task_specs": {},
    }

    progress_queue(tasks, state)

    assert [task_id for task_id, record in state["queued_tasks"].items() if record["state"] == "READY"] == ["FWQ-0002"]


def test_queue_only_completed_repair_successor_reconciles_parent_and_unlocks_dependency():
    task = TaskSpec("FWQ-0002", "Core continuation", "continue", dependencies=("FWQ-0001",), initial_state="BLOCKED")
    state = {
        "queued_tasks": {
            "FWQ-0001": {"state": "REPAIR", "repair_enqueued": "FWQ-0003"},
            "FWQ-0002": {"state": "BLOCKED"},
            "FWQ-0003": {"state": "DONE"},
        },
        "completed_tasks": [], "task_specs": {},
    }

    transitions = progress_queue({task.task_id: task}, state)

    assert state["queued_tasks"]["FWQ-0001"]["state"] == "DONE"
    assert state["queued_tasks"]["FWQ-0002"]["state"] == "READY"
    assert transitions[:2] == ("FWQ-0001:REPAIR->DONE:FWQ-0003", "FWQ-0002:BLOCKED->READY")


def test_completed_recovery_successor_reconciles_failed_parent_and_unlocks_dependency():
    task = TaskSpec("FWQ-0002", "Core continuation", "continue", dependencies=("FWQ-0001",), initial_state="BLOCKED")
    state = {
        "queued_tasks": {
            "FWQ-0001": {"state": "FAILED", "recovery_followup": "FWQ-0003"},
            "FWQ-0002": {"state": "BLOCKED"},
            "FWQ-0003": {"state": "DONE"},
        },
        "completed_tasks": [], "task_specs": {},
    }

    transitions = progress_queue({task.task_id: task}, state)

    assert state["queued_tasks"]["FWQ-0001"]["state"] == "DONE"
    assert state["queued_tasks"]["FWQ-0002"]["state"] == "READY"
    assert transitions[:2] == ("FWQ-0001:FAILED->DONE:FWQ-0003", "FWQ-0002:BLOCKED->READY")


def test_repair_successor_id_skips_persisted_queue_ids():
    task = TaskSpec("FWQ-0001", "Core repair", "repair", initial_state="REPAIR")
    state = {
        "queued_tasks": {
            "FWQ-0001": {"state": "REPAIR"},
            "FWQ-0002": {"state": "BLOCKED"},
        },
        "completed_tasks": [], "task_specs": {},
    }

    progress_queue({task.task_id: task}, state)

    assert "FWQ-0003" in state["queued_tasks"]
    assert state["queued_tasks"]["FWQ-0002"]["state"] == "BLOCKED"


def test_plan_does_not_duplicate_task_already_in_persisted_queue():
    task = TaskSpec("FWQ-0010", "Core follow-up", "next package")
    tasks = {}
    state = {
        "queued_tasks": {task.task_id: {"state": "READY", "attempts": 0}},
        "completed_tasks": [], "task_specs": {},
    }

    assert progress_queue(tasks, state, plan_tasks=(task,)) == ()
    assert task.task_id not in tasks


def test_plan_does_not_create_ready_task_with_incomplete_dependency():
    task = TaskSpec("FWQ-0010", "Core follow-up", "next package", dependencies=("FWQ-0009",))
    state = {"queued_tasks": {}, "completed_tasks": [], "task_specs": {}}

    assert progress_queue({}, state, plan_tasks=(task,)) == ()
    assert task.task_id not in state["queued_tasks"]


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
    assert ExactReviewAdapter("review", allow_external_review=True).resolve_review(task, lease) == "UNRESOLVED"


def test_review_resolver_preserves_provider_unavailability_as_external(tmp_path: Path, monkeypatch):
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW", review_commit=SHA_A)
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)
    monkeypatch.setattr(
        autonomous_adapters,
        "run_review_cycle",
        lambda *args, **kwargs: {"state": "REVIEW_REQUIRED", "reviews": [{"provider": "DAYBREAK", "state": "UNAVAILABLE"}]},
    )
    assert ExactReviewAdapter("review", allow_external_review=True).resolve_review(task, lease) == "EXTERNAL: Daybreak review unavailable"


def test_daybreak_review_requires_explicit_external_transmission_consent(tmp_path: Path, monkeypatch):
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW", review_commit=SHA_A)
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)
    calls = []
    monkeypatch.setattr(autonomous_adapters, "run_review_cycle", lambda *args, **kwargs: calls.append("called"))
    with pytest.raises(ReviewUnavailable, match="explicit --allow-external-review"):
        ExactReviewAdapter("review").review(task, SHA_A, lease)
    assert ExactReviewAdapter("review").resolve_review(task, lease).startswith("EXTERNAL: Daybreak patch transmission requires explicit")
    assert calls == []


def test_review_unavailability_preserves_provider_diagnostic(tmp_path: Path, monkeypatch):
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW", review_commit=SHA_A)
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)
    monkeypatch.setattr(
        autonomous_adapters,
        "run_review_cycle",
        lambda *args, **kwargs: {"state": "REVIEW_REQUIRED", "reviews": [{"provider": "DAYBREAK", "state": "UNAVAILABLE", "error": "Daybreak reviewer timed out"}]},
    )
    assert ExactReviewAdapter("review", allow_external_review=True).resolve_review(task, lease) == "EXTERNAL: Daybreak reviewer timed out"


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


def test_review_resolver_uses_daybreak_as_the_only_provider_and_does_not_fallback(tmp_path: Path, monkeypatch):
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW", review_commit=SHA_A)
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)

    def unavailable(*args, **kwargs):
        assert kwargs["reviewers"] == ("DAYBREAK",)
        assert kwargs["required_reviewers"] == ("DAYBREAK",)
        return {"state": "REVIEW_REQUIRED", "reviews": [{"provider": "DAYBREAK", "state": "UNAVAILABLE"}]}

    monkeypatch.setattr(
        autonomous_adapters,
        "run_review_cycle",
        unavailable,
    )
    assert ExactReviewAdapter("review", allow_external_review=True).resolve_review(task, lease) == "EXTERNAL: Daybreak review unavailable"


def test_unexpected_gemini_result_cannot_replace_unavailable_anythingllm(tmp_path: Path, monkeypatch):
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW", review_commit=SHA_A)
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)
    payload = {"job_id": "phase2a-" + "0" * 24, "reviewed_commit": SHA_A, "verdict": "APPROVE", "risk": "LOW", "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [], "reasoning_summary": "Gemini fallback approval", "proposed_rules": []}
    monkeypatch.setattr(autonomous_adapters, "run_review_cycle", lambda *args, **kwargs: {"state": "REVIEW_REQUIRED", "reviews": [
        {"provider": "DAYBREAK", "state": "API access unavailable"},
        {"provider": "GEMINI", "state": "APPROVED", "result": payload},
    ]})
    adapter = ExactReviewAdapter("review", allow_external_review=True)
    with pytest.raises(RuntimeError, match="outside the Daybreak-only policy"):
        adapter.review(task, SHA_A, lease)
    assert adapter.resolve_review(task, lease).startswith("REPAIRABLE: autonomous review returned evidence outside")


def test_unexpected_gemini_result_does_not_override_anythingllm_rejection(tmp_path: Path, monkeypatch):
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW", review_commit=SHA_A)
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)
    payload = {"job_id": "phase2a-" + "0" * 24, "reviewed_commit": SHA_A, "verdict": "APPROVE", "risk": "LOW", "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [], "reasoning_summary": "Gemini fallback approval", "proposed_rules": []}
    monkeypatch.setattr(autonomous_adapters, "run_review_cycle", lambda *args, **kwargs: {"state": "REVIEW_REQUIRED", "reviews": [
        {"provider": "DAYBREAK", "state": "REVIEW_RETURNED", "result": {"verdict": "REJECT", "risk": "HIGH"}},
        {"provider": "GEMINI", "state": "APPROVED", "result": payload},
    ]})
    with pytest.raises(RuntimeError, match="outside the Daybreak-only policy"):
        ExactReviewAdapter("review", allow_external_review=True).review(task, SHA_A, lease)


def test_exact_review_adapter_rejects_unconfigured_adjudication_evidence(tmp_path: Path, monkeypatch):
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW")
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)
    payload = {"job_id": "phase2a-" + "0" * 24, "reviewed_commit": SHA_A, "verdict": "APPROVE", "risk": "LOW", "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [], "reasoning_summary": "final", "proposed_rules": []}
    monkeypatch.setattr(autonomous_adapters, "run_review_cycle", lambda *args, **kwargs: {"state": "APPROVED", "reviews": [{"provider": "OPENROUTER", "state": "REVIEW_RETURNED", "result": payload}], "adjudication": {"provider": "CLAUDE_ADJUDICATION", "state": "APPROVED", "result": payload}})
    with pytest.raises(RuntimeError, match="outside the Daybreak-only policy"):
        ExactReviewAdapter("review", allow_external_review=True, reviewers=("DAYBREAK",)).review(task, SHA_A, lease)


def test_exact_review_adapter_rechecks_qwen_job_and_commit_binding(tmp_path: Path, monkeypatch):
    task = TaskSpec("FWQ-0009", "Core review", "review", initial_state="REVIEW")
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)
    payload = {"job_id": "phase2a-" + "0" * 24, "reviewed_commit": SHA_A, "verdict": "APPROVE", "risk": "LOW", "blocking_findings": [], "tests_missing": []}
    monkeypatch.setattr(autonomous_adapters, "run_review_cycle", lambda *args, **kwargs: {"state": "APPROVED", "reviews": [{"provider": "DAYBREAK", "state": "APPROVED", "result": payload}]})
    with pytest.raises(RuntimeError, match="exact binding"):
        ExactReviewAdapter("review", allow_external_review=True).review(task, SHA_A, lease)


def test_codex_task_adapter_does_not_dispatch_without_os_isolation(tmp_path: Path, monkeypatch):
    target = tmp_path / "target.py"
    target.write_text("pass\n", encoding="utf-8")
    task = TaskSpec("FWQ-0011", "Core", "implement", allowed_paths=("target.py",), target_path="target.py")
    lease = WorkerLease("lease", task.task_id, "session", str(tmp_path), task.allowed_paths, "IMPLEMENT_AND_TEST", (), time.time() + 60)
    captured = {}
    monkeypatch.setattr("swarm.autonomous_adapters.CodexAdapter.run", lambda *args, **kwargs: pytest.fail("unsafe writer was launched"))
    with pytest.raises(WorkerIsolationUnavailable, match="OS-enforced sandbox"):
        CodexTaskAdapter(Path(__file__).parents[1] / "schemas/codex-result.schema.json", "codex").dispatch(task, lease)


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


@pytest.mark.parametrize("reviewers", [("GEMINI",), ("CLAUDE",), ("CLAUDE", "GEMINI"), ("OPENROUTER",), ("ANYTHINGLLM",), ("DAYBREAK", "CLAUDE"), ()])
def test_autonomous_reviewer_configuration_rejects_legacy_fallback(reviewers):
    with pytest.raises(ValueError, match="requires Daybreak only"):
        ExactReviewAdapter("review", allow_external_review=True, reviewers=reviewers)


@pytest.mark.parametrize("outcome", ["APPROVE", "REJECT", "UNAVAILABLE", "STALE", "WRONG_JOB", "MISSING_TEST", "MEDIUM"])
def test_autonomous_daybreak_review_uses_real_exact_contract(tmp_path, monkeypatch, outcome):
    from swarm.review_runner import run_review_cycle as canonical_review_cycle

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "fixture.txt").write_text("review fixture\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "fixture.txt"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "fixture"], check=True)
    sha = subprocess.check_output(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], text=True).strip()
    task = TaskSpec("FWQ-0063", "Core review", "review", initial_state="REVIEW", review_commit=sha)
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)
    calls = []

    def daybreak(snapshot, job_id, commit, context):
        calls.append("DAYBREAK")
        assert (snapshot / "fixture.txt").read_text() == "review fixture\n"
        assert commit == sha
        assert sha in (snapshot / "EXACT_CANDIDATE.patch").read_text(encoding="utf-8")
        if outcome == "UNAVAILABLE":
            raise RuntimeError("Daybreak Codex CLI unavailable")
        return {"job_id": "phase2a-" + "0" * 24 if outcome == "WRONG_JOB" else job_id,
                "reviewed_commit": SHA_B if outcome == "STALE" else commit,
                "verdict": "REJECT" if outcome == "REJECT" else "APPROVE",
                "risk": "MEDIUM" if outcome == "MEDIUM" else "LOW",
                "blocking_findings": [], "non_blocking_notes": [],
                "tests_missing": ["required proof"] if outcome == "MISSING_TEST" else [],
                "reasoning_summary": "fixture review", "proposed_rules": []}

    def forbidden(*args, **kwargs):
        pytest.fail("autonomous review invoked a disabled reviewer")

    def invoke(*args, **kwargs):
        assert kwargs["reviewers"] == ("DAYBREAK",)
        assert kwargs["required_reviewers"] == ("DAYBREAK",)
        assert kwargs["sequential_fallback"] is False
        assert kwargs["adjudicate_disagreements"] is False
        return canonical_review_cycle(*args, **kwargs, daybreak_runner=daybreak, claude_runner=forbidden, gemini_runner=forbidden)

    monkeypatch.setattr(autonomous_adapters, "run_review_cycle", invoke)
    adapter = ExactReviewAdapter("Review fixture read-only", allow_external_review=True, reviewers=("DAYBREAK",))
    if outcome == "APPROVE":
        result = adapter.review(task, sha, lease)
        assert set(result) == {"DAYBREAK"}
        assert result["DAYBREAK"].reviewed_commit == sha
        assert adapter.resolve_review(task, lease) == "PASSED"
    elif outcome in {"UNAVAILABLE", "STALE", "WRONG_JOB"}:
        with pytest.raises(ReviewUnavailable):
            adapter.review(task, sha, lease)
        assert adapter.resolve_review(task, lease).startswith("EXTERNAL:")
    else:
        with pytest.raises(RuntimeError, match="did not approve|review unavailable"):
            adapter.review(task, sha, lease)
        expected_state = "REPAIRABLE:" if outcome == "REJECT" else "EXTERNAL:"
        assert adapter.resolve_review(task, lease).startswith(expected_state)
    assert calls == ["DAYBREAK", "DAYBREAK"]


def test_default_autonomous_profile_requires_only_daybreak(monkeypatch, tmp_path):
    task = TaskSpec("FWQ-FALLBACK", "Core review", "review", initial_state="REVIEW")
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)
    captured = {}

    def cycle(*args, **kwargs):
        captured.update(kwargs)
        return {"state": "REVIEW_REQUIRED", "reviews": [{"provider": "DAYBREAK", "state": "UNAVAILABLE", "error": "outage"}]}

    monkeypatch.setattr(autonomous_adapters, "run_review_cycle", cycle)
    with pytest.raises(ReviewUnavailable):
        ExactReviewAdapter("review", allow_external_review=True).review(task, "a" * 40, lease)
    assert captured["reviewers"] == ("DAYBREAK",)
    assert captured["required_reviewers"] == ("DAYBREAK",)
    assert captured["sequential_fallback"] is False
    assert captured["adjudicate_disagreements"] is False


def test_default_profile_does_not_accept_disabled_reviewer_after_daybreak_outage(monkeypatch, tmp_path):
    task = TaskSpec("FWQ-FALLBACK-OK", "Core review", "review", initial_state="REVIEW")
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)
    captured = {}
    def cycle(*args, **kwargs):
        captured.update(kwargs)
        return {"state": "REVIEW_REQUIRED", "reviews": [{"provider": "DAYBREAK", "state": "UNAVAILABLE", "error": "429"}]}
    monkeypatch.setattr(autonomous_adapters, "run_review_cycle", cycle)
    with pytest.raises(ReviewUnavailable):
        ExactReviewAdapter("review", allow_external_review=True).review(task, "a" * 40, lease)
    assert captured["reviewers"] == ("DAYBREAK",)
    assert captured["sequential_fallback"] is False


def test_default_profile_preserves_daybreak_rejection(monkeypatch, tmp_path):
    task = TaskSpec("FWQ-FALLBACK-REJECT", "Core review", "review", initial_state="REVIEW")
    lease = WorkerLease("review", task.task_id, "session", str(tmp_path), (), "REVIEW", (), time.time() + 60)
    monkeypatch.setattr(autonomous_adapters, "run_review_cycle", lambda *args, **kwargs: {"state": "REVIEW_REQUIRED", "reviews": [{"provider": "DAYBREAK", "state": "REVIEW_RETURNED", "result": {"verdict": "REJECT", "risk": "MEDIUM", "blocking_findings": ["finding"], "tests_missing": []}}]})
    with pytest.raises(RuntimeError, match="did not approve"):
        ExactReviewAdapter("review", allow_external_review=True).review(task, "a" * 40, lease)
