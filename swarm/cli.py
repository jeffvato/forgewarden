import argparse
from pathlib import Path

from .adapters import discover_commands, measure_resources, select_limits
from .core import SwarmError
from .baseline import run_controlled_baseline
from .gemini_recovery import recover_gemini_review
from .local_run import run_real_dry_run
from .phase2a import activation_status, disable_autonomous_dry_run, enable_autonomous_dry_run


def main() -> int:
    parser = argparse.ArgumentParser(description="Local Hermes coding swarm (dry-run only)")
    parser.add_argument("command", choices=["start", "stop", "status", "kill-switch", "dry-run", "controlled-baseline", "gemini-review-recovery", "run", "autonomous-dry-run-status", "autonomous-dry-run-enable", "autonomous-dry-run-disable"], nargs="?", default="status")
    parser.add_argument("--state-dir", type=Path, default=Path(".swarm-state"))
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--audit-dir", type=Path)
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--service", default="fixture-parser")
    parser.add_argument("--job-id")
    parser.add_argument("--repair-commit")
    args = parser.parse_args()
    if args.command == "status":
        print({"mode": "DRY_RUN", "deployment": "DISABLED", "commands": discover_commands(), "resources": measure_resources(), "limits": select_limits(measure_resources()).__dict__})
        return 0
    if args.command == "autonomous-dry-run-status":
        print({"autonomous_dry_run": activation_status(args.runtime_root or Path("/home/jeff/hermes-swarm-runtime")), "deployment": "DISABLED"})
        return 0
    if args.command == "autonomous-dry-run-enable":
        try:
            print(enable_autonomous_dry_run())
            return 0
        except (SwarmError, OSError, ValueError) as exc:
            print(f"FAILED: {exc}")
            return 1
    if args.command == "autonomous-dry-run-disable":
        print(disable_autonomous_dry_run())
        return 0
    args.state_dir.mkdir(parents=True, exist_ok=True)
    if args.command == "start":
        (args.state_dir / "RUNNING").write_text("dry-run\n", encoding="utf-8")
        print("dry-run controller marked started; no daemon or production service was launched")
        return 0
    if args.command in {"stop", "kill-switch"}:
        (args.state_dir / "KILL_SWITCH").write_text("disabled\n", encoding="utf-8")
        print("kill switch enabled; no production service was stopped")
        return 0
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
                args.runtime_root or Path("/home/jeff/hermes-swarm-runtime"),
                args.audit_dir or Path("/home/jeff/hermes-swarm-audit"),
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
