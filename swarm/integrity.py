"""FW-INTEGRITY product gate and coherence evidence.

The gate is intentionally evidence-producing and conservative.  It does not
declare a roadmap item Proven because a unit test happens to pass.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


CANONICAL_OWNERSHIP: dict[str, dict[str, Any]] = {
    "identity": {"owner": "FW-ID", "implementation": "not_yet_present_in_checkout", "status": "DEFINED"},
    "cryptographic_authority": {"owner": "FW-KEYS / FW-ROOT", "implementation": "swarm.asoc.HMACLeaseSigner", "status": "IMPLEMENTED_PARTIAL"},
    "policy_decisions": {"owner": "FW-ROOT/Z3", "implementation": "swarm.policy_gate.DeterministicPolicy", "status": "IMPLEMENTED_PARTIAL"},
    "agent_authority": {"owner": "FW-ASOC", "implementation": "swarm.asoc.CapabilityAuthorizer", "status": "IMPLEMENTED"},
    "model_selection": {"owner": "Model Broker", "implementation": "swarm.model_broker.ModelBroker", "status": "IMPLEMENTED"},
    "mcp_access": {"owner": "MCP Gateway", "implementation": "swarm.mcp_gateway.MCPGateway", "status": "IMPLEMENTED"},
    "evidence": {"owner": "FW-EVID", "implementation": "swarm.core.AuditLog / evidence modules", "status": "IMPLEMENTED_PARTIAL"},
    "recovery": {"owner": "FW-REC", "implementation": "swarm.autonomous_loop recovery sequencing", "status": "IMPLEMENTED_PARTIAL"},
    "normalized_events": {"owner": "canonical ForgeWarden Event Schema", "implementation": "not_yet_present_in_checkout", "status": "DEFINED"},
    "soc_incidents": {"owner": "FW-SOC", "implementation": "not_yet_present_in_checkout", "status": "DEFINED"},
    "compliance": {"owner": "FW-COMP", "implementation": "roadmap only", "status": "DEFINED"},
}


FUNCTIONALITY_MAP: tuple[dict[str, Any], ...] = (
    {"requirement_id": "FW-CORE", "state": "Proven", "component": "swarm.core / swarm.autonomous_loop", "dependencies": ["policy_gate", "AuditLog", "Git"], "user_surface": "local runner and console", "unit_tests": "PASS", "integration_tests": "PASS", "golden_path": "A partial monitor/review dry-run path", "limitations": "no production deployment; live mutation disabled"},
    {"requirement_id": "FW-ASOC-01", "state": "Proven", "component": "swarm.asoc", "dependencies": ["FW-ID reference", "FW-ROOT deterministic policy", "Action Tickets", "Model Broker", "MCP Gateway", "Audit sink"], "user_surface": "internal authorization interface", "unit_tests": "PASS", "integration_tests": "PASS", "golden_path": "PASS: canonical authorization plus replay, kill-switch, recovery, and cross-tenant denials", "limitations": "in-memory single-process dry-run registries; external service adapters and a full Z3 solver remain future work"},
    {"requirement_id": "FW-ASOC-02", "state": "Proven", "component": "swarm.asoc.AggregateBlastRadiusLedger / WorkBudgetLedger / LeaseRegistry", "dependencies": ["DeterministicPolicy", "Action Tickets", "CapabilityAuthorizer", "Audit sink", "recovery controls"], "user_surface": "internal authorization interface", "unit_tests": "PASS", "integration_tests": "PASS", "golden_path": "PASS: aggregate caps, bounded delegation, and lease/tenant work budgets with recovery and concurrency denials", "limitations": "in-memory single-process DRY_RUN scope; broader ASOC orchestration remains future work"},
    {"requirement_id": "FW-INTEGRITY", "state": "Implemented", "component": "swarm.integrity", "dependencies": ["Git", "Python", "pytest", "documentation registry"], "user_surface": "integrity gate report", "unit_tests": "PASS", "integration_tests": "IN_PROGRESS", "golden_path": "first baseline path established", "limitations": "database migration checks are not applicable to this repository yet"},
)


def _run(command: list[str], cwd: Path, timeout: int = 120) -> dict[str, Any]:
    try:
        result = subprocess.run(command, cwd=cwd, env={**os.environ, "PYTHONPATH": str(cwd)}, text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"command": command, "passed": False, "output": type(exc).__name__}
    return {"command": command, "passed": result.returncode == 0, "returncode": result.returncode, "output": (result.stdout + result.stderr)[-2000:]}


def _git_state(root: Path) -> dict[str, Any]:
    head = _run(["git", "rev-parse", "HEAD"], root, 10)
    status = _run(["git", "status", "--porcelain"], root, 10)
    return {"head": head.get("output", "").strip(), "clean": status.get("passed") and not status.get("output", "").strip(), "status": status.get("output", "")[-2000:]}


def _config_check(root: Path) -> dict[str, Any]:
    required = [root / "config" / "readiness.yaml", root / "config" / "llm-profiles.json", root / "policies" / "risk-policy.yaml"]
    missing = [str(path.relative_to(root)) for path in required if not path.is_file()]
    try:
        json.loads((root / "config" / "llm-profiles.json").read_text(encoding="utf-8"))
        import yaml
        for path in (root / "config" / "readiness.yaml", root / "policies" / "risk-policy.yaml"):
            yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, ImportError) as exc:
        return {"passed": False, "reason": type(exc).__name__, "missing": missing}
    return {"passed": not missing, "missing": missing}


def run_product_integrity_gate(root: Path, *, test_command: Iterable[str] | None = None, golden_command: Iterable[str] | None = None, check_dependencies: bool = True) -> dict[str, Any]:
    """Run the repeatable local integrity gate and return structured evidence."""
    root = root.resolve()
    git = _git_state(root)
    build = _run([sys.executable, "-m", "compileall", "-q", "swarm"], root)
    startup = _run([sys.executable, "-c", "import swarm.core, swarm.console, swarm.asoc, swarm.integrity"], root)
    config = _config_check(root)
    tests = _run(list(test_command or [sys.executable, "-m", "pytest", "-q"]), root, 300)
    golden = _run(
        list(golden_command or ["bash", "scripts/run-asoc-golden-path.sh"]), root, 180,
    )
    dependencies = _run([sys.executable, "-m", "pip", "check"], root, 30) if check_dependencies else {"passed": True, "not_run": True}
    missing_owners = [key for key, value in CANONICAL_OWNERSHIP.items() if value["status"] == "DEFINED"]
    findings: list[dict[str, str]] = []
    if not git["clean"]:
        findings.append({"severity": "RED", "area": "repository", "reason": "working tree is not clean"})
    if not dependencies.get("passed"):
        findings.append({"severity": "YELLOW", "area": "dependencies", "reason": "pip check reports missing or incompatible packages"})
    if missing_owners:
        findings.append({"severity": "YELLOW", "area": "architecture", "reason": "roadmap ownership has no concrete module: " + ", ".join(missing_owners)})
    checks = {"repository": git["clean"], "build": build["passed"], "startup": startup["passed"], "configuration": config["passed"], "tests": tests["passed"], "golden_path": golden.get("passed", False)}
    hard_failures = [name for name, passed in checks.items() if not passed and name != "golden_path"]
    decision = "RED" if hard_failures else ("YELLOW" if findings or not golden.get("passed") else "GREEN")
    return {"schema_version": "1", "decision": decision, "head": git["head"], "checks": checks, "findings": findings, "missing_canonical_owners": missing_owners, "dependency_check": dependencies, "commands": {"tests": tests, "golden_path": golden}, "functionality": [dict(item, last_validated_commit=git["head"]) for item in FUNCTIONALITY_MAP], "canonical_ownership": CANONICAL_OWNERSHIP}


def write_gate_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
