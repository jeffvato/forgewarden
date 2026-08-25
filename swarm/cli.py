import argparse
import json
import shlex
from codebase_index_evidence import build_index_evidence
from pathlib import Path

from .adapters import discover_commands, measure_resources, select_limits
from .core import SwarmError
from .baseline import run_controlled_baseline
from .gemini_recovery import recover_gemini_review
from .local_run import run_real_dry_run
from .phase2a import disable_autonomous_dry_run, enable_autonomous_dry_run, engage_kill_switch, recover_terminal_abandoned, run_worker_job, safety_status, workflow_status
from .paths import audit_root, runtime_root
from .quality_review import scan_repository, write_report
from .vulnerability_index import build_evidence, update_feed, write_evidence
from .quality_apply import apply_safe_findings
from .quality_audit import review_audit
from .phase5_release_audit import ReleaseAudit
from .review_evidence import build_review_evidence
from .approval import create_approval_record, reconcile_approval, verify_approval
from .codebase_index import CodebaseIndex
from .console import serve as serve_console
from .review_runner import read_context, render_result, run_review_cycle
from .autonomous_loop import AutonomousLoopError, AutonomousOrchestrator, GitCheckpointController, TaskSpec
from .autonomous_adapters import CodexTaskAdapter, ExactReviewAdapter, run_deterministic_tests
from .supervisor_state import load_supervisor_state
from .task_selection import select_ready_task
from .plan_derivation import derive_next_core_task


def main() -> int:
    parser = argparse.ArgumentParser(description="Local Hermes coding swarm (dry-run only)")
    parser.add_argument("command", choices=["start", "stop", "status", "workflow-status", "kill-switch", "dry-run", "controlled-baseline", "gemini-review-recovery", "quality-review", "quality-apply-safe", "quality-audit", "release-inventory", "review-evidence", "claude-review", "review-cycle", "approval-create", "approval-verify", "approval-reconcile", "codebase-index-build", "codebase-index-query", "codebase-index-delete", "index-evidence", "vulnerability-evidence", "vulnerability-update", "phase2a-worker", "phase2a-recover-terminal", "console", "run", "autonomous-loop-status", "autonomous-loop-run", "autonomous-dry-run-status", "autonomous-dry-run-enable", "autonomous-dry-run-disable"], nargs="?", default="status")
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
    parser.add_argument("--index-evidence", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--index-path", type=Path)
    parser.add_argument("--task-manifest", type=Path)
    parser.add_argument("--codex-executable", default="codex")
    parser.add_argument("--max-steps", type=int)
    parser.add_argument("--feed", type=Path, action="append", default=[])
    parser.add_argument("--feed-source", choices=["osv", "nvd", "cisa_kev"])
    parser.add_argument("--feed-url")
    parser.add_argument("--feed-output", type=Path)
    parser.add_argument("--revision", "--candidate-commit", dest="revision")
    parser.add_argument("--term")
    parser.add_argument("--actor")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--no-fresh-scan", action="store_true")
    parser.add_argument("--reviewer")
    parser.add_argument("--decision", choices=["APPROVED", "REJECTED"])
    parser.add_argument("--ttl-seconds", type=int, default=3600)
    parser.add_argument("--consume", action="store_true")
    parser.add_argument("--allow-external-review", action="store_true", help="allow the Gemini-compatible reviewer to contact its provider")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    if args.command == "status":
        print({**safety_status(args.runtime_root or runtime_root()), "commands": discover_commands(), "resources": measure_resources(), "limits": select_limits(measure_resources()).__dict__})
        return 0
    if args.command == "workflow-status":
        print(json.dumps(workflow_status(args.runtime_root or runtime_root()), sort_keys=True))
        return 0
    if args.command == "autonomous-loop-status":
        if not args.repository:
            parser.error("autonomous-loop-status requires --repository")
        try:
            state = load_supervisor_state(args.repository)
            selection = __import__("swarm.task_selection", fromlist=["select_ready_task"]).select_ready_task(state)
            durable_path = args.state_dir / "autonomous-loop.json"
            if durable_path.exists():
                # The durable state is read through the controller only when a
                # caller has supplied the same approved task set; control-state
                # status remains authoritative for queue eligibility.
                durable = json.loads(durable_path.read_text(encoding="utf-8"))
                if not isinstance(durable, dict) or durable.get("version") != 1 or durable.get("dry_run") is not True or durable.get("deployment") != "DISABLED":
                    raise AutonomousLoopError("durable state violates safety contract")
            else:
                durable = None
            print(json.dumps({"active_phase": selection.active_phase, "selected_task": selection.selected.task_id if selection.selected else None, "selection_reason": selection.reason, "durable_state": durable}, sort_keys=True))
            return 0
        except (OSError, ValueError, SwarmError, AutonomousLoopError, json.JSONDecodeError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "autonomous-loop-run":
        if not args.repository or not args.task_manifest:
            parser.error("autonomous-loop-run requires --repository and --task-manifest")
        try:
            if args.task_manifest.is_symlink() or any(parent.is_symlink() for parent in (args.task_manifest.parent, *args.task_manifest.parent.parents)):
                raise AutonomousLoopError("task manifest path is symlinked")
            if args.task_manifest.stat().st_size > 1_048_576:
                raise AutonomousLoopError("task manifest exceeds the 1 MiB bound")
            manifest = json.loads(args.task_manifest.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict) or not isinstance(manifest.get("tasks"), list) or len(manifest["tasks"]) > 100:
                raise AutonomousLoopError("task manifest must contain at most 100 tasks")
            tasks = []
            for item in manifest["tasks"]:
                if not isinstance(item, dict):
                    raise AutonomousLoopError("task manifest entries must be objects")
                tasks.append(TaskSpec(
                    task_id=item["task_id"], requirement=item["requirement"], description=item["description"],
                    dependencies=tuple(item.get("dependencies", ())), priority=int(item.get("priority", 0)),
                    allowed_paths=tuple(item.get("allowed_paths", ())), acceptance=tuple(item.get("acceptance", ())),
                    retry_budget=int(item.get("retry_budget", 1)), worker_type=str(item.get("worker_type", "CODEX")),
                    target_path=item.get("target_path"), expected_behavior=str(item.get("expected_behavior", "implement the approved task")),
                        failing_assertion=str(item.get("failing_assertion", "the approved regression assertion")), test_command=tuple(item.get("test_command", ())),
                        initial_state=str(item.get("initial_state", "READY")), review_disposition=item.get("review_disposition"),
                        blocker_resolved=bool(item.get("blocker_resolved", False)), blocker_external=bool(item.get("blocker_external", False)), authorized=bool(item.get("authorized", True)),
                    ))
            plan_tasks = []
            for item in manifest.get("plan_tasks", []):
                if not isinstance(item, dict):
                    raise AutonomousLoopError("plan task entries must be objects")
                plan_tasks.append(TaskSpec(
                    task_id=item["task_id"], requirement=item["requirement"], description=item["description"],
                    dependencies=tuple(item.get("dependencies", ())), priority=int(item.get("priority", 0)),
                    allowed_paths=tuple(item.get("allowed_paths", ())), acceptance=tuple(item.get("acceptance", ())),
                    retry_budget=int(item.get("retry_budget", 1)), worker_type=str(item.get("worker_type", "CODEX")),
                    target_path=item.get("target_path"), expected_behavior=str(item.get("expected_behavior", "implement the approved task")),
                    failing_assertion=str(item.get("failing_assertion", "the approved regression assertion")), test_command=tuple(item.get("test_command", ())), authorized=bool(item.get("authorized", True)),
                ))
            if not plan_tasks:
                plan_task = derive_next_core_task(args.repository, {task.task_id for task in tasks})
                if plan_task is not None:
                    plan_tasks.append(plan_task)
            control_files = (args.repository / "AGENTS.md", args.repository / "WORK_QUEUE.md", args.repository / "SWARM_STATUS.md")
            if all(path.is_file() for path in control_files):
                control_state = load_supervisor_state(args.repository)
                selected = select_ready_task(control_state).selected
                queue_mentions_task = bool(tasks) and f"### {tasks[0].task_id} —" in control_state.files["WORK_QUEUE.md"].content
                transition_only = bool(tasks) and tasks[0].initial_state in {"REVIEW", "BLOCKED"} and queue_mentions_task
                if (selected is None and not transition_only) or (selected is not None and (not tasks or tasks[0].task_id != selected.task_id)):
                    raise AutonomousLoopError("task manifest does not begin with the authoritative eligible queue task")
            git_controller = GitCheckpointController(args.repository)
            git_controller.ensure_clean()
            try:
                args.state_dir.resolve().relative_to(args.repository.resolve())
            except ValueError:
                pass
            else:
                raise AutonomousLoopError("autonomous state directory must be outside the Git repository")
            args.state_dir.mkdir(parents=True, exist_ok=True)
            codex = CodexTaskAdapter(Path(__file__).resolve().parents[1] / "schemas/codex-result.schema.json", args.codex_executable)
            reviewer = ExactReviewAdapter(str(manifest.get("review_context", "ForgeWarden exact-commit review")), allow_external_review=args.allow_external_review)
            orchestrator = AutonomousOrchestrator(args.state_dir / "autonomous-loop.json", args.repository, tuple(tasks), checkpoint_path=args.state_dir / "work-checkpoint.json", audit_path=args.state_dir / "execution-log.jsonl")
            result = orchestrator.run(dispatch=codex.dispatch, validate=lambda task, value: run_deterministic_tests(task, value, args.repository), commit=lambda task, value: git_controller.commit_worker_changes(task, value), review=lambda task, commit, lease: reviewer.review(task, commit, lease), max_steps=args.max_steps, plan_tasks=tuple(plan_tasks))
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, AutonomousLoopError, SwarmError) as exc:
            print(f"FAILED: {exc}")
            return 1
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
    if args.command in {"codebase-index-build", "codebase-index-query", "codebase-index-delete"}:
        if not args.repository or not args.index_path:
            parser.error(f"{args.command} requires --repository and --index-path")
        if not args.revision:
            parser.error(f"{args.command} requires --revision")
        try:
            index = CodebaseIndex(args.repository, args.index_path)
            if args.command == "codebase-index-build":
                result = index.build(args.revision)
            elif args.command == "codebase-index-delete":
                if not args.actor:
                    parser.error("codebase-index-delete requires --actor")
                index.delete(args.actor)
                result = {"state": "DELETED", "revision": args.revision}
            else:
                if not args.term or not args.actor:
                    parser.error("codebase-index-query requires --term and --actor")
                result = {"results": index.query(args.term, args.revision, args.actor, limit=args.limit, fresh_scan=not args.no_fresh_scan)}
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, SwarmError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "index-evidence":
        if not args.quality_report or not args.repository or not args.index_path or not args.revision or not args.actor:
            parser.error("index-evidence requires --quality-report, --repository, --index-path, --revision, and --actor")
        try:
            result = build_index_evidence(args.quality_report, args.repository, args.index_path, args.revision, args.actor)
            rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
            if args.output:
                write_report(args.output, rendered)
            else:
                print(rendered, end="")
            return 0
        except (OSError, ValueError, json.JSONDecodeError, SwarmError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "vulnerability-update":
        if not args.feed_source or not args.feed_url or not args.feed_output:
            parser.error("vulnerability-update requires --feed-source, --feed-url, and --feed-output")
        try:
            print(json.dumps(update_feed(args.feed_source, args.feed_url, args.feed_output), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "vulnerability-evidence":
        if not args.repository or not args.feed or not args.output:
            parser.error("vulnerability-evidence requires --repository, --feed, and --output")
        try:
            result = build_evidence(args.repository, args.feed)
            write_evidence(args.output, result)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"FAILED: {exc}")
            return 1
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
    if args.command == "review-cycle":
        if not args.repository or not args.revision or not args.context_file or not args.job_id:
            parser.error("review-cycle requires --repository, --revision, --context-file, and --job-id")
        try:
            result = run_review_cycle(
                args.repository,
                args.revision,
                args.job_id,
                read_context(args.context_file.expanduser()),
                allow_external_review=args.allow_external_review,
            )
            print(render_result(result), end="")
            return 0 if result["state"] == "APPROVED" else 1
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
    if args.command == "release-inventory":
        if not args.repository:
            parser.error("release-inventory requires --repository")
        try:
            rendered = json.dumps(ReleaseAudit(args.repository).inventory(), indent=2, sort_keys=True) + "\n"
            if args.output:
                write_report(args.output, rendered)
            else:
                print(rendered, end="")
            return 0
        except (OSError, ValueError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "review-evidence":
        if not args.quality_report or not args.application_plan or not args.audit_review:
            parser.error("review-evidence requires --quality-report, --application-plan, and --audit-review")
        try:
            result = build_review_evidence(args.quality_report, args.application_plan, args.audit_review, args.claude_review, args.index_evidence)
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
