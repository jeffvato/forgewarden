from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from pathlib import Path

from .adapters import CodexAdapter, WriterInvocationSpec, limited_run, select_limits
from .baseline import BASELINE_SHA, REPOSITORY, WRITABLE_DEADLINE, _AuthorizedKillSwitch, _deadline_test_command, _run_deadline_preflight
from .core import AuditLog, Job, SwarmError, redact, run_command
from .paths import audit_root, runtime_root


def run_deadline_codex_diagnostic(
    swarm_root: Path,
    runtime_root: Path,
    audit_root: Path,
    repository: Path = REPOSITORY,
    codex_executable: str = "/home/jeff/.local/bin/codex",
) -> dict[str, object]:
    """Run one diagnostic Codex turn through the production shared adapter."""
    job_id = "controlled-baseline-0rtmvv09-diagnostic"
    job = Job(job_id, "csv-processor-diagnostic", repository, "diagnostic-only deadline writer call")
    audit = AuditLog(audit_root / "audit.jsonl")
    limits = select_limits({"memory_available_bytes": 8 * 1024 * 1024 * 1024})
    limits = type(limits)(memory_bytes=2_147_483_648, timeout_seconds=180, max_log_bytes=256_000)
    state_dir = runtime_root / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    if not (runtime_root / "KILL_SWITCH").exists():
        raise SwarmError("diagnostic requires an initially engaged kill switch")
    worktree = Path(tempfile.mkdtemp(prefix=job_id + "-", dir=state_dir))
    worktree.rmdir()
    evidence_dir = audit_root / "codex-diagnostics"
    result: dict[str, object] = {"job_id": job_id, "worktree": str(worktree), "kill_switch_initial": "ENGAGED"}
    try:
        added = run_command(["git", "worktree", "add", "--detach", str(worktree), BASELINE_SHA], repository)
        if added.returncode:
            raise SwarmError(redact(added.stderr))
        worktree.chmod(0o700)
        working_directory, test_path, test_command = _deadline_test_command(worktree)
        _, _, _, preflight = _run_deadline_preflight(worktree, limits, (working_directory, test_path, test_command))
        seeded_hash = hashlib.sha256((worktree / WRITABLE_DEADLINE).read_bytes()).hexdigest()
        spec = WriterInvocationSpec(
            job_id, worktree, working_directory, "app/ai/deadline.py", WRITABLE_DEADLINE,
            "remaining_seconds() returns non-negative remaining monotonic time",
            "the seeded deadline contract assertion must pass after the smallest source correction",
            (WRITABLE_DEADLINE,),
        )
        spec.target(seeded_hash)
        result.update({"base": BASELINE_SHA, "working_directory": str(working_directory), "test_path": str(test_path), "test_command": test_command, "preflight": preflight, "seeded_hash": seeded_hash, "target": {"codex_relative": "app/ai/deadline.py", "git_relative": WRITABLE_DEADLINE}})
        with _AuthorizedKillSwitch(runtime_root, audit, job):
            git_pointer = worktree / ".git"
            hidden = state_dir / f"{job_id}.git-pointer"
            shutil.move(git_pointer, hidden)
            adapter = CodexAdapter(swarm_root / "schemas/codex-result.schema.json", limits, codex_executable, evidence_dir)
            try:
                payload = adapter.run(spec, spec.prompt() + f" Run only this argument-array deterministic test from {working_directory}: {test_command!r}. Do not commit.")
            finally:
                if git_pointer.exists():
                    generated = state_dir / f"{job_id}.generated-git"
                    shutil.move(git_pointer, generated)
                    result["codex_created_git_metadata"] = True
                shutil.move(hidden, git_pointer)
            actual = run_command(["git", "diff", "--name-only", BASELINE_SHA], worktree).stdout.splitlines()
            normalized_actual = [path for path in actual if path != ".swarm"]
            adapter.record_actual_paths(normalized_actual)
            result.update({"codex_result": payload, "actual_normalized_changed_paths": normalized_actual, "evidence_path": str(adapter.last_evidence.persisted_path if adapter.last_evidence else evidence_dir / f"{job_id}.json")})
        result["kill_switch_final"] = "ENGAGED"
        audit.record(job, "deadline_codex_diagnostic_completed", result="RECORDED_NO_COMMIT", evidence_path=result.get("evidence_path"), actual_normalized_changed_paths=result.get("actual_normalized_changed_paths"), limits=limits.__dict__)
        return result
    except Exception as exc:
        result["error"] = redact(str(exc))
        result["kill_switch_final"] = "ENGAGED"
        audit.record(job, "deadline_codex_diagnostic_failed", error=redact(str(exc)), evidence_path=str(evidence_dir / f"{job_id}.json"), limits=limits.__dict__)
        raise


if __name__ == "__main__":
    print(json.dumps(run_deadline_codex_diagnostic(Path(__file__).resolve().parents[1], runtime_root(), audit_root()), sort_keys=True))
