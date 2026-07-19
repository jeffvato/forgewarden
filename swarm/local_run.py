from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .adapters import CodexAdapter, GeminiAdapter, HermesAdapter, limited_run, measure_resources, select_limits
from .core import Job, Orchestrator, SwarmError, redact, run_command


def _fixture(root: Path) -> Path:
    repo = root / "fixture-repository"
    repo.mkdir(parents=True)
    run_command(["git", "init", "-q", "-b", "main"], repo)
    (repo / "parser.py").write_text("def parse(value):\n    return value.strip()\n", encoding="utf-8")
    (repo / "test_parser.py").write_text("from parser import parse\nassert parse(' x ') == 'x'\n", encoding="utf-8")
    run_command(["git", "add", "."], repo)
    run_command(["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "initial"], repo)
    return repo


def _readonly_snapshot(worktree: Path, state_dir: Path, job_id: str) -> Path:
    snapshot = Path(tempfile.mkdtemp(prefix=f"review-{job_id}-", dir=state_dir))
    result = run_command(["git", "clone", "--no-hardlinks", str(worktree), str(snapshot)], state_dir)
    if result.returncode:
        raise SwarmError(redact(result.stderr))
    output = snapshot / ".swarm"
    output.mkdir(exist_ok=True)
    for item in snapshot.rglob("*"):
        if item == output or output in item.parents:
            continue
        item.chmod(0o555 if item.is_dir() else 0o444)
    output.chmod(0o755)
    return snapshot


def run_real_dry_run(root: Path) -> dict:
    runtime_root = root / ".integration-runtime"
    runtime_root.mkdir(parents=True, exist_ok=True)
    runtime = Path(tempfile.mkdtemp(prefix="run-", dir=runtime_root))
    resources = measure_resources()
    limits = select_limits(resources)
    commands = {name: shutil.which(name) for name in ("hermes", "codex", "gemini")}
    missing = [name for name, path in commands.items() if not path]
    if missing:
        raise SwarmError("required local CLI not found: " + ", ".join(missing))
    repo = _fixture(runtime)
    job = Job("real-local-" + next(tempfile._get_candidate_names()), "fixture-parser", repo, "harmless parser normalization defect")
    orchestrator = Orchestrator(runtime / "state", dry_run=True)
    hermes = HermesAdapter(runtime / "hermes", commands["hermes"])
    hermes.prepare(job.job_id, job.evidence)
    orchestrator.classify(job)
    if job.risk != "LOW":
        raise SwarmError("fixture was unexpectedly classified above LOW")
    with __import__("swarm.core", fromlist=["ServiceLock"]).ServiceLock(runtime / "state" / "locks", job.service):
        worktree, base = orchestrator._worktree(job)
        try:
            job.state = "CODEX_RUNNING"
            codex_prompt = f"""You are the sole application-code writer. Work only in this Git worktree. Job ID: {job.job_id}.\n\nRepair the harmless defect in parser.py so parse(value) normalizes surrounding whitespace and lowercases the result. Preserve the existing test, add a focused regression assertion if practical, run the test, inspect the diff, and commit the repair. Do not deploy, access secrets, change configuration, or modify files outside this fixture. Your final response MUST be JSON matching the supplied Codex result schema, with changed_files matching the committed diff."""
            codex = CodexAdapter(root / "schemas/codex-result.schema.json", limits, commands["codex"])
            codex_result = codex.run(worktree, job.job_id, codex_prompt)
            changed = orchestrator._git(worktree, "diff", "--name-only", base).splitlines()
            if sorted(changed) != sorted(codex_result["changed_files"]):
                raise SwarmError("real Codex result changed_files does not match the Git diff")
            job.state = "CHECKS_RUNNING"
            checks = limited_run(["python3", "-m", "unittest", "test_parser.py"], worktree, "", limits, {"SWARM_ROLE": "DETERMINISTIC_CHECK"})
            if checks.returncode:
                raise SwarmError("deterministic fixture test failed: " + redact(checks.stdout + checks.stderr))
            commit = orchestrator._git(worktree, "rev-parse", "HEAD")
            snapshot = _readonly_snapshot(worktree, runtime / "state", job.job_id)
            job.state = "GEMINI_REVIEWING"
            gemini_prompt = f"""You are the independent read-only reviewer. Do not edit, commit, push, deploy, or access secrets. Review the exact repair commit {commit} in this read-only snapshot for job {job.job_id}. Deterministic tests already passed. Return ONLY one JSON object matching schemas/gemini-review.schema.json. Set reviewed_commit to the exact full 40-character SHA. Reject scope creep or missing tests. You may propose at most one learned rule; it must remain PROPOSED and never be activated by you."""
            gemini = GeminiAdapter(root / "schemas/gemini-review.schema.json", limits, commands["gemini"])
            gemini_result = gemini.run(snapshot, job.job_id, commit, gemini_prompt)
            if gemini_result["verdict"] != "APPROVE" or gemini_result["risk"] != "LOW":
                job.state = "REVISION_REQUIRED"
                raise SwarmError("Gemini did not approve the deterministic fixture repair")
            for rule in gemini_result.get("proposed_rules", []):
                orchestrator.rules.propose(rule, job)
            job.state = "SUCCEEDED"
            orchestrator.audit.record(job, "real_local_dry_run_succeeded", base=base, commit=commit, resources=resources, limits=limits.__dict__, codex=codex_result, gemini=gemini_result)
            return {"job_id": job.job_id, "state": job.state, "base": base, "commit": commit, "resources": resources, "limits": limits.__dict__, "codex": codex_result, "gemini": gemini_result}
        finally:
            run_command(["git", "worktree", "remove", "--force", str(worktree)], repo)
