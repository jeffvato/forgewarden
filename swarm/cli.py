import argparse
import json
import shlex
from pathlib import Path

from .adapters import discover_commands, measure_resources, select_limits
from .core import SwarmError
from .baseline import run_controlled_baseline
from .gemini_recovery import recover_gemini_review
from .local_run import run_real_dry_run
from .phase2a import disable_autonomous_dry_run, enable_autonomous_dry_run, engage_kill_switch, recover_terminal_abandoned, run_worker_job, safety_status, workflow_status
from .paths import audit_root, runtime_root
from .quality_review import scan_repository, write_report
from .quality_apply import apply_safe_findings
from .quality_audit import review_audit
from .review_evidence import build_review_evidence
from .approval import create_approval_record, reconcile_approval, verify_approval
from .console import serve as serve_console


def main() -> int:
    parser = argparse.ArgumentParser(description="Local Hermes coding swarm (dry-run only)")
    parser.add_argument("command", choices=["start", "stop", "status", "workflow-status", "kill-switch", "dry-run", "controlled-baseline", "gemini-review-recovery", "quality-review", "quality-apply-safe", "quality-audit", "review-evidence", "claude-review", "approval-create", "approval-verify", "approval-reconcile", "phase2a-worker", "phase2a-recover-terminal", "console", "run", "autonomous-dry-run-status", "autonomous-dry-run-enable", "autonomous-dry-run-disable"], nargs="?", default="status")
    parser.add_argument("--state-dir", type=Path, default=Path(".swarm-state"))
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--audit-dir", type=Path)
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--service", default="fixture-parser")
    parser.add_argument("--job-id")
    parser.add_argument("--repair-commit")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--context-file", type=Path)
    parser.add_argument("--model", default="sonnet")
    parser.add_argument("--finding-id", action="append", default=[])
    parser.add_argument("--check-command", help="shell-free command string used for deterministic verification")
    parser.add_argument("--audit", type=Path)
    parser.add_argument("--quality-report", type=Path)
    parser.add_argument("--application-plan", type=Path)
    parser.add_argument("--audit-review", type=Path)
    parser.add_argument("--claude-review", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--reviewer")
    parser.add_argument("--decision", choices=["APPROVED", "REJECTED"])
    parser.add_argument("--ttl-seconds", type=int, default=3600)
    parser.add_argument("--consume", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    if args.command == "status":
        print({**safety_status(args.runtime_root or runtime_root()), "commands": discover_commands(), "resources": measure_resources(), "limits": select_limits(measure_resources()).__dict__})
        return 0
    if args.command == "workflow-status":
        print(json.dumps(workflow_status(args.runtime_root or runtime_root()), sort_keys=True))
        return 0
    if args.command == "console":
        serve_console(args.host, args.port)
        return 0
    if args.command == "autonomous-dry-run-status":
        print(safety_status(args.runtime_root or runtime_root()))
        return 0
    if args.command == "autonomous-dry-run-enable":
        try:
            print(enable_autonomous_dry_run(runtime_root=args.runtime_root or runtime_root(), audit_path=(args.audit_dir or audit_root()) / "audit.jsonl"))
            return 0
        except (SwarmError, OSError, ValueError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "autonomous-dry-run-disable":
        print(disable_autonomous_dry_run(runtime_root=args.runtime_root or runtime_root()))
        return 0
    if args.command == "quality-review":
        if not args.repository:
            parser.error("quality-review requires --repository")
        try:
            rendered = json.dumps(scan_repository(args.repository), indent=2, sort_keys=True) + "\n"
            if args.output:
                write_report(args.output, rendered)
            else:
                print(rendered, end="")
            return 0
        except (OSError, ValueError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "claude-review":
        if not args.context_file or not args.job_id:
            parser.error("claude-review requires --context-file and --job-id")
        try:
            context_path = args.context_file.expanduser()
            if context_path.is_symlink() or any(parent.is_symlink() for parent in (context_path.parent, *context_path.parent.parents)):
                raise ValueError("claude-review refuses symlinked context paths")
            from .claude_adapter import MAX_CONTEXT_BYTES, run_claude
            if not context_path.is_file():
                raise ValueError("claude-review context file is missing")
            if context_path.stat().st_size > MAX_CONTEXT_BYTES:
                raise ValueError("claude-review context file exceeds the 24000-byte bound")
            from .core import read_restricted_bytes
            result = run_claude(args.job_id, read_restricted_bytes(context_path, "Claude review context").decode("utf-8"), model=args.model)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, SwarmError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "quality-apply-safe":
        if not args.repository or not args.report or not args.finding_id or not args.check_command or not args.job_id or not args.audit or not args.approval or not args.evidence:
            parser.error("quality-apply-safe requires --repository, --report, --check-command, --job-id, --audit, --approval, --evidence, and at least one --finding-id")
        try:
            from .core import read_restricted_bytes
            report = json.loads(read_restricted_bytes(args.report, "quality report").decode("utf-8"))
            result = apply_safe_findings(args.repository, report, args.finding_id, shlex.split(args.check_command), job_id=args.job_id, audit_path=args.audit, approval_path=args.approval, approval_evidence_path=args.evidence)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["state"] == "APPLIED_VERIFIED" else 1
        except (OSError, ValueError, json.JSONDecodeError, SwarmError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "quality-audit":
        if not args.audit or not args.job_id:
            parser.error("quality-audit requires --audit and --job-id")
        try:
            print(json.dumps(review_audit(args.audit, args.job_id), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "review-evidence":
        if not args.quality_report or not args.application_plan or not args.audit_review:
            parser.error("review-evidence requires --quality-report, --application-plan, and --audit-review")
        try:
            result = build_review_evidence(args.quality_report, args.application_plan, args.audit_review, args.claude_review)
            rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
            if args.output:
                write_report(args.output, rendered)
            else:
                print(rendered, end="")
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "approval-create":
        if not args.evidence or not args.output or not args.job_id or not args.reviewer or not args.decision:
            parser.error("approval-create requires --evidence, --output, --job-id, --reviewer, and --decision")
        try:
            result = create_approval_record(args.evidence, args.output, job_id=args.job_id, reviewer=args.reviewer, decision=args.decision, ttl_seconds=args.ttl_seconds)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "approval-verify":
        if not args.approval or not args.evidence or not args.job_id:
            parser.error("approval-verify requires --approval, --evidence, and --job-id")
        try:
            print(json.dumps(verify_approval(args.approval, args.evidence, expected_job_id=args.job_id, consume=args.consume), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "approval-reconcile":
        if not args.approval or not args.evidence or not args.audit or not args.job_id:
            parser.error("approval-reconcile requires --approval, --evidence, --audit, and --job-id")
        try:
            print(json.dumps(reconcile_approval(args.approval, args.evidence, args.audit, expected_job_id=args.job_id), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "phase2a-worker":
        if not args.job_id:
            parser.error("phase2a-worker requires --job-id")
        try:
            print(run_worker_job(args.job_id, runtime_root=args.runtime_root or runtime_root(), audit_path=(args.audit_dir or audit_root()) / "audit.jsonl"))
            return 0
        except (SwarmError, OSError, ValueError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "phase2a-recover-terminal":
        try:
            print(recover_terminal_abandoned(args.runtime_root or runtime_root(), (args.audit_dir or audit_root()) / "audit.jsonl"))
            return 0
        except (SwarmError, OSError, ValueError) as exc:
            print(f"FAILED: {exc}")
            return 1
    args.state_dir.mkdir(parents=True, exist_ok=True)
    if args.command == "start":
        (args.state_dir / "RUNNING").write_text("dry-run\n", encoding="utf-8")
        print("dry-run controller marked started; no daemon or production service was launched")
        return 0
    if args.command in {"stop", "kill-switch"}:
        try:
            print(engage_kill_switch(args.runtime_root or runtime_root(), (args.audit_dir or audit_root()) / "audit.jsonl"))
            return 0
        except (SwarmError, OSError, ValueError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "dry-run":
        try:
            print(run_real_dry_run(Path(__file__).resolve().parents[1], args.runtime_root, args.audit_dir))
            return 0
        except (SwarmError, OSError, ValueError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "controlled-baseline":
        if not args.repository:
            parser.error("controlled-baseline requires --repository")
        try:
            print(run_controlled_baseline(Path(__file__).resolve().parents[1], args.repository, args.runtime_root, args.state_dir, args.audit_dir, synthetic_exercise=True))
            return 0
        except (SwarmError, OSError, ValueError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "gemini-review-recovery":
        if not args.repository or not args.job_id or not args.repair_commit:
            parser.error("gemini-review-recovery requires --repository, --job-id, and --repair-commit")
        try:
            result = recover_gemini_review(
                Path(__file__).resolve().parents[1],
                args.repository,
                args.runtime_root or runtime_root(),
                args.audit_dir or audit_root(),
                args.job_id,
                args.repair_commit,
            )
            print(result)
            return 0
        except (SwarmError, OSError, ValueError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if not args.repository:
        parser.error("run requires --repository")
    try:
        result = Orchestrator(args.state_dir, dry_run=True).run(
            Job("cli-" + __import__("uuid").uuid4().hex[:12], args.service, args.repository, "manual dry-run"),
            ["true"], ["true"], ["true"],
        )
    except SwarmError as exc:
        print(f"FAILED: {exc}")
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
