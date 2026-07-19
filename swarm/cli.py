import argparse
from pathlib import Path

from .adapters import discover_commands, measure_resources, select_limits
from .core import SwarmError
from .local_run import run_real_dry_run


def main() -> int:
    parser = argparse.ArgumentParser(description="Local Hermes coding swarm (dry-run only)")
    parser.add_argument("command", choices=["start", "stop", "status", "kill-switch", "dry-run", "run"], nargs="?", default="status")
    parser.add_argument("--state-dir", type=Path, default=Path(".swarm-state"))
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--audit-dir", type=Path)
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--service", default="fixture-parser")
    args = parser.parse_args()
    if args.command == "status":
        print({"mode": "DRY_RUN", "deployment": "DISABLED", "commands": discover_commands(), "resources": measure_resources(), "limits": select_limits(measure_resources()).__dict__})
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
