from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .adapters import GeminiAdapter, ResourceLimits, _minimal_test_environment, limited_run
from .baseline import BASELINE_SHA, WRITABLE_DEADLINE, _deadline_test_command
from .core import (
    AuditLog,
    Job,
    SwarmError,
    _reject_symlink_path,
    ensure_private_directory,
    read_restricted_bytes,
    redact,
    run_command,
    touch_restricted,
)


def _tree_hash(repo: Path, revision: str) -> str:
    result = run_command(["git", "rev-parse", f"{revision}^{{tree}}"], repo)
    if result.returncode:
        raise SwarmError(redact(result.stderr))
    return result.stdout.strip()


def _prior_invalid_payload(audit_path: Path, job_id: str, commit: str) -> str:
    _reject_symlink_path(audit_path, "Gemini recovery audit")
    if not audit_path.exists():
        return "[NOT_FOUND_IN_DURABLE_AUDIT]"
    try:
        raw = read_restricted_bytes(audit_path, "Gemini recovery audit")
    except SwarmError:
        return "[NOT_FOUND_IN_DURABLE_AUDIT]"
    for line in reversed(raw.decode("utf-8", errors="replace").splitlines()):
        if job_id in line and "missing_tests" in line:
            return redact(line)[:12000]
    return "[NOT_FOUND_IN_DURABLE_AUDIT]"


def recover_gemini_review(
    root: Path,
    repository: Path,
    runtime_root: Path,
    audit_dir: Path,
    job_id: str,
    repair_commit: str,
) -> dict[str, Any]:
    """Review retained evidence only; this path has no Codex or Git mutator."""
    audit_path = audit_dir / "audit.jsonl"
    job = Job(job_id, "n8n-csv-baseline", repository, "retained Gemini review-only recovery", state="GEMINI_REVIEWING")
    kill_switch = runtime_root / "KILL_SWITCH"
    _reject_symlink_path(kill_switch, "Gemini recovery kill switch")
    if not kill_switch.exists():
        raise SwarmError("review-only recovery requires the kill switch to be engaged")
    deployment_marker = runtime_root / "DEPLOYMENT_ENABLED"
    _reject_symlink_path(deployment_marker, "Gemini recovery deployment marker")
    if deployment_marker.exists():
        raise SwarmError("review-only recovery requires deployment to remain disabled")
    worktree: Path | None = None
    baseline = BASELINE_SHA
    try:
        if run_command(["git", "cat-file", "-e", f"{repair_commit}^{{commit}}"], repository).returncode:
            raise SwarmError("retained repair commit does not exist")
        parent_result = run_command(["git", "rev-list", "--parents", "-n", "1", repair_commit], repository)
        parents = parent_result.stdout.split()
        if len(parents) != 2:
            raise SwarmError("retained repair must have exactly one parent")
        defect_commit = parents[1]
        defect_parent = run_command(["git", "rev-parse", f"{defect_commit}^"], repository).stdout.strip()
        if defect_parent != baseline:
            raise SwarmError("retained repair parent is not the recorded synthetic defect from the clean baseline")
        diff = run_command(["git", "diff", "--name-only", defect_commit, repair_commit], repository).stdout.splitlines()
        if diff != [WRITABLE_DEADLINE]:
            raise SwarmError(f"retained repair changed unexpected files: {diff}")
        clean_tree = _tree_hash(repository, baseline)
        repair_tree = _tree_hash(repository, repair_commit)
        if repair_tree != clean_tree:
            raise SwarmError("retained repair tree does not equal the clean baseline tree")
        source_audit = json.loads("{}")
        audit_lines = read_restricted_bytes(audit_path, "Gemini recovery audit").decode("utf-8", errors="replace").splitlines()
        for line in audit_lines:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("job_id") == job_id and entry.get("event") == "trusted_commit_created":
                source_audit = entry
        if source_audit.get("repair_commit") != repair_commit or source_audit.get("repair_parent") != defect_commit:
            raise SwarmError("repair commit and job ID do not match the durable audit")
        state_dir = ensure_private_directory(runtime_root / "state", "Gemini recovery state")
        worktree = Path(tempfile.mkdtemp(prefix=f"gemini-review-{job_id}-", dir=state_dir))
        archive = worktree.parent / f"{worktree.name}.tar"
        exported = run_command(["git", "archive", "--format=tar", "-o", str(archive), repair_commit], repository)
        if exported.returncode:
            raise SwarmError(redact(exported.stderr))
        extracted = run_command(["tar", "-xf", str(archive), "-C", str(worktree)], worktree)
        archive.unlink(missing_ok=True)
        if extracted.returncode:
            raise SwarmError(redact(extracted.stderr))
        working_directory, test_path, test_command = _deadline_test_command(worktree)
        limits = ResourceLimits(memory_bytes=2_147_483_648, timeout_seconds=180, max_log_bytes=256_000)
        checks = limited_run(test_command, working_directory, "", limits, {"SWARM_ROLE": "GEMINI_REVIEW_PREFLIGHT"}, use_cgroup=True, minimal_environment=True)
        if checks.returncode:
            raise SwarmError("retained repair deterministic test failed: " + redact(checks.stdout + checks.stderr))
        source_hash = hashlib.sha256(read_restricted_bytes(worktree / WRITABLE_DEADLINE, "retained repair source")).hexdigest()
        (worktree / ".swarm").mkdir(mode=0o700)
        for path in worktree.rglob("*"):
            if path.is_file() and ".swarm" not in path.parts:
                path.chmod(0o444)
            elif path.is_dir() and path.name != ".swarm":
                path.chmod(0o555)
        snapshot = worktree
        prompt = (
            f"Review only retained repair commit {repair_commit} against synthetic parent {defect_commit} for job {job_id}. "
            f"The clean baseline is {baseline} with tree {clean_tree}. The repair tree is {repair_tree}. "
            f"The only changed file is {WRITABLE_DEADLINE}. Deterministic test passed. "
            "Do not edit, commit, merge, push, deploy, invoke Codex, or access secrets."
        )
        adapter = GeminiAdapter(root / "schemas/gemini-review.schema.json", limits)
        result = adapter.run(snapshot, job_id, repair_commit, prompt, formatting_retry=True)
        AuditLog(audit_path).record(job, "gemini_review_recovery_succeeded", synthetic_evidence=True, retained_commit=repair_commit, synthetic_parent=defect_commit, clean_baseline=baseline, clean_tree=clean_tree, repair_tree=repair_tree, deterministic="PASSED", original_invalid_payload=_prior_invalid_payload(audit_path, job_id, repair_commit), review_attempts=adapter.last_attempts, corrected_validation="PASSED", verdict=result["verdict"], risk=result["risk"])
        return {"job_id": job_id, "repair_commit": repair_commit, "synthetic_parent": defect_commit, "verdict": result["verdict"], "risk": result["risk"], "attempts": adapter.last_attempts}
    except Exception as exc:
        AuditLog(audit_path).record(job, "gemini_review_recovery_failed", retained_commit=repair_commit, original_invalid_payload=_prior_invalid_payload(audit_path, job_id, repair_commit), error=redact(str(exc)))
        raise
    finally:
        touch_restricted(kill_switch, "Gemini recovery kill switch")
        if worktree is not None:
            for path in sorted(worktree.rglob("*"), key=lambda item: len(item.parts), reverse=True):
                try:
                    if path.is_dir():
                        path.chmod(0o700)
                    else:
                        path.chmod(0o600)
                except OSError:
                    pass
            try:
                worktree.chmod(0o700)
            except OSError:
                pass
            shutil.rmtree(worktree, ignore_errors=True)
