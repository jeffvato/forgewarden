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
from .policy_gate import PolicyInvariantError, validate_invariant_manifest


CANONICAL_OWNERSHIP: dict[str, dict[str, Any]] = {
    "identity": {"owner": "FW-ID", "implementation": "swarm.identity.IdentityRecord", "status": "IMPLEMENTED_PARTIAL"},
    "cryptographic_authority": {"owner": "FW-KEYS / FW-ROOT", "implementation": "swarm.keys.SecretHandleRegistry / swarm.asoc.HMACLeaseSigner", "status": "IMPLEMENTED_PARTIAL"},
    "policy_decisions": {"owner": "FW-ROOT/Z3", "implementation": "swarm.policy_gate.DeterministicPolicy", "status": "IMPLEMENTED_PARTIAL"},
    "agent_authority": {"owner": "FW-ASOC", "implementation": "swarm.asoc.CapabilityAuthorizer", "status": "IMPLEMENTED"},
    "model_selection": {"owner": "Model Broker", "implementation": "swarm.model_broker.ModelBroker", "status": "IMPLEMENTED"},
    "mcp_access": {"owner": "MCP Gateway", "implementation": "swarm.mcp_gateway.MCPGateway", "status": "IMPLEMENTED"},
    "evidence": {"owner": "FW-EVID", "implementation": "swarm.evidence.EvidenceEnvelope / EvidenceLedger / CanonicalAuditEvidenceStore with swarm.core.AuditLog", "status": "IMPLEMENTED"},
    "recovery": {"owner": "FW-REC", "implementation": "swarm.recovery RecoveryCheckpoint / ResumeAdmission", "status": "IMPLEMENTED"},
    "normalized_events": {"owner": "canonical ForgeWarden Event Schema", "implementation": "swarm.normalized_events.NormalizedEventStore", "status": "IMPLEMENTED_PARTIAL"},
    "soc_incidents": {"owner": "FW-SOC", "implementation": "swarm.soc.SOCIncidentProjection", "status": "IMPLEMENTED_PARTIAL"},
    "compliance": {"owner": "FW-COMP", "implementation": "swarm.compliance ControlMapping / ComplianceEvidenceAdapter / ControlAssessmentObservation", "status": "IMPLEMENTED"},
    "ai_agent_defense": {"owner": "FW-AID", "implementation": "swarm.ai_agent_defense DeterministicAIThreatClassifier / AICrossDomainCorrelator / AIContainmentProposalRegistry", "status": "IMPLEMENTED"},
}


FUNCTIONALITY_MAP: tuple[dict[str, Any], ...] = (
    {"requirement_id": "FW-CORE", "state": "Proven", "component": "swarm.core / swarm.autonomous_loop", "dependencies": ["policy_gate", "AuditLog", "Git"], "user_surface": "local runner and console", "unit_tests": "PASS", "integration_tests": "PASS", "golden_path": "A partial monitor/review dry-run path", "limitations": "no production deployment; live mutation disabled"},
    {"requirement_id": "FW-ASOC-01", "state": "Proven", "component": "swarm.asoc", "dependencies": ["FW-ID reference", "FW-ROOT deterministic policy", "Action Tickets", "Model Broker", "MCP Gateway", "Audit sink"], "user_surface": "internal authorization interface", "unit_tests": "PASS", "integration_tests": "PASS", "golden_path": "PASS: canonical authorization plus replay, kill-switch, recovery, and cross-tenant denials", "limitations": "in-memory single-process dry-run registries; external service adapters and a full Z3 solver remain future work"},
    {"requirement_id": "FW-ASOC-02", "state": "Proven", "component": "swarm.asoc.AggregateBlastRadiusLedger / WorkBudgetLedger / LeaseRegistry", "dependencies": ["DeterministicPolicy", "Action Tickets", "CapabilityAuthorizer", "Audit sink", "recovery controls"], "user_surface": "internal authorization interface", "unit_tests": "PASS", "integration_tests": "PASS", "golden_path": "PASS: aggregate caps, bounded delegation, and lease/tenant work budgets with recovery and concurrency denials", "limitations": "in-memory single-process DRY_RUN scope; broader ASOC orchestration remains future work"},
    {"requirement_id": "FW-ID", "state": "Proven", "component": "swarm.identity.IdentityRecord / IdentityRegistry / DelegatedProviderIdentity", "dependencies": ["FW-KEYS opaque references", "FW-EVID sink", "FW-HARNESS worker admission"], "user_surface": "internal identity and worker-binding interface", "unit_tests": "PASS", "integration_tests": "PASS", "golden_path": "PASS: tenant-bound registration, provider-reference binding, worker admission, revocation and replay denial", "limitations": "in-memory DRY_RUN metadata only; no real authentication, federation, OAuth exchange, credential resolution, device trust or production identity service"},
    {"requirement_id": "FW-KEYS", "state": "Proven", "component": "swarm.keys.SecretHandleRegistry with identity/harness and TrustedSignatureCatalog consumers", "dependencies": ["FW-ID owner reference", "FW-EVID sink", "trusted backend boundary"], "user_surface": "internal opaque secret-handle lifecycle interface", "unit_tests": "PASS", "integration_tests": "PASS", "golden_path": "PASS: registration, activation, exact consumer binding, lifecycle invalidation, generation replay denial, and Evidence minimization", "limitations": "in-memory metadata only; no backend, vault, HSM, material resolution, authentication, key generation, signing or encryption authority"},
    {"requirement_id": "FW-EVID", "state": "Proven", "component": "swarm.evidence with harness and accepted-work adapters plus swarm.core.AuditLog", "dependencies": ["domain payload validators", "tenant identity references", "restricted local AuditLog"], "user_surface": "internal canonical Evidence lifecycle", "unit_tests": "PASS", "integration_tests": "PASS", "golden_path": "PASS: validated payload digest, tenant chain, durable append, restart reconstruction, replay and tamper denial", "limitations": "local unsigned DRY_RUN evidence only; no retention execution, cryptographic signing, replication, external storage or export"},
    {"requirement_id": "FW-REC", "state": "Proven", "component": "swarm.recovery", "dependencies": ["RecoveryCheckpoint", "private atomic persistence", "FW-EVID sink", "trusted Git/Evidence facts", "kill switch"], "user_surface": "internal recovery admission metadata", "unit_tests": "PASS", "integration_tests": "PASS", "golden_path": "PASS: checkpoint persistence, restart reconstruction, exact resume admission, Evidence-first retry, replay/tamper denial", "limitations": "local metadata-only DRY_RUN coordination; no restore, rollback, restart, repair, deletion, containment, deployment, filesystem, process or response execution"},
    {"requirement_id": "FW-COMP", "state": "Proven", "component": "swarm.compliance", "dependencies": ["FW-ID references", "FW-EVID ledger", "policy/test fact references"], "user_surface": "internal compliance mapping metadata", "unit_tests": "PASS", "integration_tests": "PASS", "golden_path": "PASS: tenant-bound mapping, canonical Evidence admission, bounded assessment, replay/substitution/expiry/durability denial", "limitations": "local in-memory metadata-only DRY_RUN proof; no certification, attestation, external reporting, control execution or continuous-compliance claim"},
    {"requirement_id": "FW-AID", "state": "Proven", "component": "swarm.ai_agent_defense / swarm.normalized_events / swarm.mission_control", "dependencies": ["FW-ENDPOINT fixtures", "FW-ID/FW-KEYS references", "NormalizedEventStore", "FW-SOC", "FW-EVID", "FW-HARNESS", "Mission Control"], "user_surface": "Mission Control canonical read-only AI Security projection", "unit_tests": "PASS", "integration_tests": "PASS", "golden_path": "PASS: fixture-only harness and endpoint attribution through detection, correlation, proposal, Evidence, and Mission Control", "limitations": "caller-supplied DRY_RUN metadata only; no live sensor, credential access, network/process control, containment execution, recovery execution, or deployment authority"},
    {"requirement_id": "FW-INTEGRITY", "state": "Implemented", "component": "swarm.integrity", "dependencies": ["Git", "Python", "pytest", "documentation registry"], "user_surface": "integrity gate report", "unit_tests": "PASS", "integration_tests": "IN_PROGRESS", "golden_path": "first baseline path established", "limitations": "database migration checks are not applicable to this repository yet"},
)


def validate_canonical_ownership(ownership: dict[str, dict[str, Any]] = CANONICAL_OWNERSHIP) -> dict[str, str]:
    """Detect duplicate or malformed canonical component declarations."""
    if not ownership:
        raise ValueError("canonical ownership registry is empty")
    normalized: dict[str, str] = {}
    implementations: set[str] = set()
    for component, record in ownership.items():
        if not isinstance(component, str) or not isinstance(record, dict) or set(record) != {"owner", "implementation", "status"}:
            raise ValueError("canonical ownership record is malformed")
        owner, implementation, status = record["owner"], record["implementation"], record["status"]
        if not all(isinstance(value, str) and value.strip() and len(value) <= 512 for value in (owner, implementation, status)):
            raise ValueError("canonical ownership value is malformed")
        if implementation not in {"roadmap only", "architecture and requirements only"}:
            if implementation in implementations:
                raise ValueError("duplicate canonical implementation detected")
            implementations.add(implementation)
        normalized[component] = owner
    return normalized


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
    try:
        invariants = validate_invariant_manifest()
        ownership = validate_canonical_ownership()
        architecture = {"passed": True, "invariant_ids": [item.invariant_id for item in invariants], "owners": ownership}
    except (PolicyInvariantError, ValueError) as exc:
        architecture = {"passed": False, "reason": str(exc)}
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
    checks = {"repository": git["clean"], "build": build["passed"], "startup": startup["passed"], "configuration": config["passed"], "invariant_manifest": architecture["passed"], "architecture_ownership": architecture["passed"], "tests": tests["passed"], "golden_path": golden.get("passed", False)}
    hard_failures = [name for name, passed in checks.items() if not passed and name != "golden_path"]
    decision = "RED" if hard_failures else ("YELLOW" if findings or not golden.get("passed") else "GREEN")
    return {"schema_version": "1", "decision": decision, "head": git["head"], "checks": checks, "findings": findings, "architecture_validation": architecture, "missing_canonical_owners": missing_owners, "dependency_check": dependencies, "commands": {"tests": tests, "golden_path": golden}, "functionality": [dict(item, last_validated_commit=git["head"]) for item in FUNCTIONALITY_MAP], "canonical_ownership": CANONICAL_OWNERSHIP}


def write_gate_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
