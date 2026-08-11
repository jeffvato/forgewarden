from __future__ import annotations

import json
import resource
import shutil
import subprocess
import tempfile
from pathlib import Path

from .adapters import CodexAdapter, HermesAdapter, WriterInvocationSpec, last_cgroup_peak_bytes, limited_run, measure_resources, select_limits
from . import claude_verifier
from .core import Job, Orchestrator, SwarmError, redact, require_exact_commit, run_command


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


def run_real_dry_run(root: Path, runtime_root: Path | None = None, audit_dir: Path | None = None) -> dict:
    runtime_root = runtime_root or (root / ".integration-runtime")
    runtime_root.mkdir(parents=True, exist_ok=True)
    runtime = Path(tempfile.mkdtemp(prefix="run-", dir=runtime_root))
    resources = measure_resources()
    limits = select_limits(resources)
    commands = {name: shutil.which(name) for name in ("hermes", "codex", "claude")}
    missing = [name for name, path in commands.items() if not path]
    if missing:
        raise SwarmError("required local CLI not found: " + ", ".join(missing))
    repo = _fixture(runtime)
    job = Job("real-local-" + next(tempfile._get_candidate_names()), "fixture-parser", repo, "harmless parser normalization defect")
    orchestrator = Orchestrator(runtime / "state", dry_run=True, audit_dir=audit_dir)
    hermes = HermesAdapter(runtime / "hermes", commands["hermes"])
    hermes.prepare(job.job_id, job.evidence)
    orchestrator.classify(job)
    if job.risk != "LOW":
        raise SwarmError("fixture was unexpectedly classified above LOW")
    with __import__("swarm.core", fromlist=["ServiceLock"]).ServiceLock(runtime / "state" / "locks", job.service):
        worktree, base = orchestrator._worktree(job)
        try:
            job.state = "CODEX_RUNNING"
            codex_prompt = f"""You are the sole application-code writer. Work only in this Git worktree. The exact required job_id value is {job.job_id}; copy it character-for-character into the final JSON. Repair the harmless defect in parser.py so parse(value) normalizes surrounding whitespace and lowercases the result. Preserve the existing test, add a focused regression assertion if practical, run the test, inspect the diff, and commit the repair. Do not deploy, access secrets, change configuration, or modify files outside this fixture. Your final response MUST be JSON matching the supplied Codex result schema, with changed_files matching the committed diff."""
            codex = CodexAdapter(root / "schemas/codex-result.schema.json", limits, commands["codex"])
            codex_spec = WriterInvocationSpec(job.job_id, worktree, worktree, "parser.py", "parser.py", "parse(value) normalizes whitespace and lowercases", "assert parse(' X ') == 'x'", ("parser.py", "test_parser.py"))
            codex_result = codex.run(codex_spec, codex_prompt)
            if codex_result["status"] != "FIXED":
                raise SwarmError(f"real Codex did not complete the repair: {codex_result['status']} ({codex_result['summary']})")
            changed = orchestrator._git(worktree, "diff", "--name-only", base).splitlines()
            if sorted(changed) != sorted(codex_result["changed_files"]):
                raise SwarmError(f"real Codex result changed_files mismatch: claimed={codex_result['changed_files']}, actual={changed}")
            job.state = "CHECKS_RUNNING"
            checks = limited_run(["python3", "-m", "unittest", "test_parser.py"], worktree, "", limits, {"SWARM_ROLE": "DETERMINISTIC_CHECK"})
            if checks.returncode:
                raise SwarmError("deterministic fixture test failed: " + redact(checks.stdout + checks.stderr))
            commit = orchestrator._git(worktree, "rev-parse", "HEAD")
            if commit == base or not changed:
                raise SwarmError("Codex did not produce a non-empty repair commit")
            review_diff = orchestrator._git(worktree, "diff", base, commit)[:100_000]
            snapshot = _readonly_snapshot(worktree, runtime / "state", job.job_id)
            job.state = "CLAUDE_REVIEWING"
            claude_prompt = f"""Review exact commit {commit} against its synthetic parent for job {job.job_id}. Deterministic test output was: {redact(checks.stdout + checks.stderr)[:4000]}. The exact base-to-commit diff is below:\n\n{redact(review_diff)}"""
            claude_result = claude_verifier.run(snapshot, job.job_id, commit, claude_prompt)
            if claude_result["verdict"] != "APPROVE" or claude_result["risk"] != "LOW":
                job.state = "REVISION_REQUIRED"
                raise SwarmError("Claude did not approve the deterministic fixture repair")
            for rule in claude_result.get("proposed_rules", []):
                decision = orchestrator.rules.propose(rule, job)
                orchestrator.audit.record(job, "learned_rule_decision", decision=decision)
            job.state = "SUCCEEDED"
            resources["peak_child_rss_kib"] = int(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
            resources["peak_cgroup_bytes"] = last_cgroup_peak_bytes()
            orchestrator.audit.record(
                job,
                "real_local_dry_run_succeeded",
                base=base,
                commit=commit,
                resources=resources,
                limits=limits.__dict__,
                codex_status=codex_result["status"],
                changed_files=codex_result["changed_files"],
                deterministic_checks="PASSED",
                reviewer="claude-sonnet-read-only",
                reviewer_decision=claude_result["verdict"],
                reviewer_risk=claude_result["risk"],
                reviewed_commit=claude_result["reviewed_commit"],
                proposed_rule_count=len(claude_result.get("proposed_rules", [])),
            )
            return {"job_id": job.job_id, "state": job.state, "base": base, "commit": commit, "resources": resources, "limits": limits.__dict__, "codex": codex_result, "claude": claude_result}
        finally:
            run_command(["git", "worktree", "remove", "--force", str(worktree)], repo)
