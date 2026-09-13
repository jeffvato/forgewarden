"""FW-INTEGRITY product gate and coherence evidence.

The gate is intentionally evidence-producing and conservative.  It does not
declare a roadmap item Proven because a unit test happens to pass.
"""
from __future__ import annotations

import json
import io
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from .policy_gate import PolicyInvariantError, validate_invariant_manifest


_CLEAN_REQUIRED_FILES = frozenset({
    "swarm/__init__.py", "swarm/core.py", "swarm/policy_gate.py",
    "swarm/integrity.py", "swarm/console.py", "console/index.html",
    "console/app.js", "console/styles.css", "config/readiness.yaml",
    "config/llm-profiles.json", "policies/risk-policy.yaml",
    "requirements-test.txt", "scripts/run-product-golden-path.sh",
    "tests/test_product_golden_path.py",
})
_CLEAN_DECLARED_DEPENDENCIES = frozenset({"cryptography", "jsonschema", "psutil", "pytest", "pyyaml", "tzdata"})
_CLEAN_SECRET = re.compile(
    rb"(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|bearer\s+[A-Za-z0-9._-]{20,}|"
    rb"sk-[A-Za-z0-9_-]{24,}|AIza[A-Za-z0-9_-]{24,}|ya29\.[A-Za-z0-9._-]{20,}|"
    rb"(?:api[_-]?key|client[_-]?secret|access[_-]?token|password)\s*[:=]\s*[\"'][^\"']{16,}[\"'])"
)
_CLEAN_SHA = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class InvariantMutation:
    """One fixed source mutation and the existing test that must detect it."""

    mutation_id: str
    invariant_id: str
    owner: str
    path: str
    original: str
    replacement: str
    test_selector: str


@dataclass(frozen=True)
class _MutationProcessResult:
    returncode: int | None
    output: bytes
    timed_out: bool = False


INVARIANT_MUTATIONS: tuple[InvariantMutation, ...] = (
    InvariantMutation(
        "FW-MUT-SELF-AUTHORITY", "FW-INV-001", "FW-HARNESS/FW-ROOT",
        "swarm/harness_authority.py",
        'or decision["authority_expanded"] is not False',
        "or False",
        "tests/test_harness_authority.py::test_unsafe_stale_or_unconsumed_decision_denies",
    ),
    InvariantMutation(
        "FW-MUT-TENANT-ISOLATION", "FW-INV-003", "FW-ID/FW-EVID",
        "swarm/evidence.py",
        "if self.actor_tenant_id != tenant or self.subject_tenant_id != tenant:",
        "if self.actor_tenant_id != tenant and self.subject_tenant_id != tenant:",
        "tests/test_evidence.py::test_invalid_or_cross_tenant_evidence_metadata_fails_closed",
    ),
    InvariantMutation(
        "FW-MUT-EVIDENCE-IMMUTABILITY", "FW-INV-004", "FW-EVID",
        "swarm/evidence.py",
        "@dataclass(frozen=True)\nclass EvidenceEnvelope:",
        "@dataclass()\nclass EvidenceEnvelope:",
        "tests/test_evidence.py::test_canonical_evidence_envelope_is_exact_immutable_and_payload_free",
    ),
    InvariantMutation(
        "FW-MUT-INDEPENDENT-REVIEW", "FW-INV-006", "FW-HARNESS",
        "swarm/review_handoff.py",
        "if set(cycle.reviews) != required:",
        "if not set(cycle.reviews).issubset(required):",
        "tests/test_review_handoff.py::test_completion_requires_configured_reviewers_and_string_findings",
    ),
    InvariantMutation(
        "FW-MUT-ASSURANCE-DOWNGRADE", "FW-INV-007", "Model Broker",
        "swarm/harness_models.py",
        "and item.assurance_tier >= risk.tier and role in item.allowed_roles",
        "and item.assurance_tier <= risk.tier and role in item.allowed_roles",
        "tests/test_harness_models.py::test_security_tier_cannot_route_weaker_or_unapproved_model",
    ),
    InvariantMutation(
        "FW-MUT-MCP-AUTHORITY", "FW-INV-008", "MCP Gateway",
        "swarm/mcp_gateway.py",
        "if grant not in self._grants or grant in self._revoked:",
        "if grant in self._revoked:",
        "tests/test_mcp_gateway.py::test_admission_requires_evidence_and_exact_grant_fields",
    ),
    InvariantMutation(
        "FW-MUT-KILL-SWITCH", "FW-INV-005", "FW-OPS/FW-ROOT",
        "swarm/policy_gate.py",
        "allowed_kill_switch = {KILL_SWITCH_ENGAGED}",
        "allowed_kill_switch = {KILL_SWITCH_ENGAGED, KILL_SWITCH_CLEARED_FOR_DRY_RUN}",
        "tests/test_policy_gate.py::test_unsafe_evidence_fails_closed",
    ),
    InvariantMutation(
        "FW-MUT-DEPLOYMENT", "FW-INV-005", "FW-OPS/FW-ROOT",
        "swarm/policy_gate.py",
        "if deployment != DEPLOYMENT_DISABLED:",
        "if deployment == DEPLOYMENT_DISABLED:",
        "tests/test_policy_gate.py::test_unsafe_evidence_fails_closed",
    ),
)

_MUTATION_ID = re.compile(r"^FW-MUT-[A-Z0-9-]{3,64}$")
_MUTATION_INVARIANT = re.compile(r"^FW-INV-\d{3}$")
_MUTATION_SELECTOR = re.compile(r"^tests/test_[a-z0-9_]+\.py::test_[a-z0-9_]+$")
_MUTATION_MAX_OUTPUT = 64 * 1024


def _validate_mutation_manifest(mutations: tuple[InvariantMutation, ...]) -> tuple[InvariantMutation, ...]:
    if (
        not isinstance(mutations, tuple) or not 1 <= len(mutations) <= 16
        or not all(isinstance(item, InvariantMutation) for item in mutations)
    ):
        raise ValueError("mutation manifest must be a bounded tuple")
    ids = [item.mutation_id for item in mutations]
    if len(ids) != len(set(ids)):
        raise ValueError("mutation manifest IDs must be unique")
    for item in mutations:
        relative = _clean_archive_name(item.path)
        if relative.as_posix() != item.path or not item.path.startswith("swarm/") or relative.suffix != ".py":
            raise ValueError("mutation target path is outside the bounded source scope")
        if not _MUTATION_ID.fullmatch(item.mutation_id) or not _MUTATION_INVARIANT.fullmatch(item.invariant_id):
            raise ValueError("mutation identity is malformed")
        if (
            not isinstance(item.owner, str) or not item.owner.strip() or len(item.owner) > 128
            or not isinstance(item.original, str) or not item.original or len(item.original.encode("utf-8")) > 2048
            or not isinstance(item.replacement, str) or item.replacement == item.original
            or len(item.replacement.encode("utf-8")) > 2048
            or not _MUTATION_SELECTOR.fullmatch(item.test_selector)
        ):
            raise ValueError("mutation manifest entry is malformed")
    return mutations


def _extract_mutation_archive(archived: bytes, checkout: Path) -> None:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(archived), mode="r:")
    except tarfile.TarError as exc:
        raise ValueError("mutation archive is malformed") from exc
    with archive:
        members = archive.getmembers()
        if not 1 <= len(members) <= 5000:
            raise ValueError("mutation archive member count is invalid")
        seen: set[str] = set()
        for member in members:
            relative = _clean_archive_name(member.name)
            normalized = relative.as_posix()
            if normalized in seen:
                raise ValueError("mutation archive contains duplicate paths")
            seen.add(normalized)
            target = checkout / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile() or member.issym() or member.islnk():
                raise ValueError("mutation archive contains a link or special file")
            if member.size < 0 or member.size > 2 * 1024 * 1024:
                raise ValueError("mutation archive member size is invalid")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("mutation archive member is unreadable")
            content = source.read(2 * 1024 * 1024 + 1)
            if len(content) != member.size:
                raise ValueError("mutation archive member is truncated")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)


def _apply_invariant_mutation(checkout: Path, mutation: InvariantMutation) -> None:
    target = checkout / mutation.path
    try:
        source = target.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError("mutation target is unavailable") from exc
    if source.count(mutation.original) != 1:
        raise ValueError("mutation target must occur exactly once")
    mutated = source.replace(mutation.original, mutation.replacement, 1)
    if mutated.count(mutation.replacement) != source.count(mutation.replacement) + 1:
        raise ValueError("mutation replacement is ambiguous")
    target.write_text(mutated, encoding="utf-8")


def _run_mutation_test(checkout: Path, selector: str, timeout_seconds: int) -> _MutationProcessResult:
    environment = {
        key: value for key, value in os.environ.items()
        if key not in {"PYTHONPATH", "PYTEST_ADDOPTS"}
    }
    environment.update({"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", selector], cwd=checkout,
            env=environment, capture_output=True, timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"") + (exc.stderr or b"")
        return _MutationProcessResult(None, output, True)
    except OSError as exc:
        raise ValueError("mutation test process is unavailable") from exc
    return _MutationProcessResult(result.returncode, result.stdout + result.stderr)


def _validated_mutation_result(result: _MutationProcessResult) -> dict[str, Any]:
    if not isinstance(result, _MutationProcessResult):
        raise ValueError("mutation test result is malformed")
    if result.timed_out:
        raise ValueError("mutation test timed out")
    if len(result.output) > _MUTATION_MAX_OUTPUT:
        raise ValueError("mutation test output exceeds the bounded limit")
    if _CLEAN_SECRET.search(result.output):
        raise ValueError("mutation test output contains secret-bearing content")
    if result.returncode is None or not isinstance(result.returncode, int) or isinstance(result.returncode, bool):
        raise ValueError("mutation test return code is invalid")
    if result.returncode == 0:
        raise ValueError("critical invariant mutant survived")
    return {
        "result": "KILLED",
        "returncode": result.returncode,
        "output_retained": False,
    }


def run_mutation_resistance_proof(root: Path, expected_commit: str) -> dict[str, Any]:
    """Kill fixed critical-invariant mutants in disposable exact-commit archives."""
    root = root.resolve()
    if not _CLEAN_SHA.fullmatch(expected_commit):
        raise ValueError("mutation proof expected commit is invalid")
    mutations = _validate_mutation_manifest(INVARIANT_MUTATIONS)

    def exact_head() -> str:
        try:
            return subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True,
                capture_output=True, timeout=10, check=True,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError("mutation proof Git state is unavailable") from exc

    if exact_head() != expected_commit:
        raise ValueError("mutation proof current commit mismatch")
    try:
        archived = subprocess.run(
            ["git", "archive", "--format=tar", expected_commit], cwd=root,
            capture_output=True, timeout=30, check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("mutation proof archive is unavailable") from exc
    if not archived or len(archived) > 64 * 1024 * 1024:
        raise ValueError("mutation proof archive size is invalid")

    results: list[dict[str, Any]] = []
    for mutation in mutations:
        if exact_head() != expected_commit:
            raise ValueError("mutation proof source commit changed")
        with tempfile.TemporaryDirectory(prefix="forgewarden-invariant-mutant-") as temporary:
            checkout = Path(temporary).resolve()
            _extract_mutation_archive(archived, checkout)
            _apply_invariant_mutation(checkout, mutation)
            outcome = _validated_mutation_result(
                _run_mutation_test(checkout, mutation.test_selector, 45)
            )
            results.append({
                "mutation_id": mutation.mutation_id,
                "invariant_id": mutation.invariant_id,
                "owner": mutation.owner,
                "path": mutation.path,
                "test_selector": mutation.test_selector,
                **outcome,
            })
        if Path(temporary).exists():
            raise ValueError("mutation checkout cleanup failed")
    if exact_head() != expected_commit:
        raise ValueError("mutation proof source commit changed")
    return {
        "schema_version": 1,
        "proof": "CRITICAL_INVARIANT_MUTATION_RESISTANCE",
        "commit": expected_commit,
        "mutants": results,
        "summary": {"defined": len(mutations), "killed": len(results), "survived": 0},
        "temporary_checkouts_removed": True,
        "mode": "DRY_RUN",
        "deployment": "DISABLED",
        "kill_switch": "ENGAGED",
        "live_enabled": False,
        "production_ready": False,
        "authority_granted": False,
    }


def _clean_archive_name(name: str) -> Path:
    """Return a safe relative archive path or fail before extraction."""
    if not isinstance(name, str) or not name or "\\" in name:
        raise ValueError("clean archive member name is malformed")
    parts = Path(name).parts
    if name.startswith("/") or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("clean archive member path is unsafe")
    return Path(*parts)


def validate_clean_checkout(root: Path, expected_commit: str) -> dict[str, Any]:
    """Validate a disposable exact-commit archive without installing anything."""
    root = root.resolve()
    if not _CLEAN_SHA.fullmatch(expected_commit):
        raise ValueError("clean checkout expected commit is invalid")
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True,
            capture_output=True, timeout=10, check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("clean checkout Git state is unavailable") from exc
    if head != expected_commit:
        raise ValueError("clean checkout current commit mismatch")
    try:
        archived = subprocess.run(
            ["git", "archive", "--format=tar", expected_commit], cwd=root,
            capture_output=True, timeout=30, check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("clean checkout archive is unavailable") from exc
    if not archived or len(archived) > 64 * 1024 * 1024:
        raise ValueError("clean checkout archive size is invalid")

    file_hashes: list[tuple[str, str]] = []
    declared: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="forgewarden-clean-checkout-") as temporary:
        checkout = Path(temporary).resolve()
        try:
            archive = tarfile.open(fileobj=io.BytesIO(archived), mode="r:")
        except tarfile.TarError as exc:
            raise ValueError("clean checkout archive is malformed") from exc
        with archive:
            members = archive.getmembers()
            if not 1 <= len(members) <= 5000:
                raise ValueError("clean checkout archive member count is invalid")
            seen: set[str] = set()
            for member in members:
                relative = _clean_archive_name(member.name)
                normalized = relative.as_posix()
                if normalized in seen:
                    raise ValueError("clean checkout archive contains duplicate paths")
                seen.add(normalized)
                target = checkout / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile() or member.issym() or member.islnk():
                    raise ValueError("clean checkout archive contains a link or special file")
                if member.size < 0 or member.size > 2 * 1024 * 1024:
                    raise ValueError("clean checkout archive member size is invalid")
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("clean checkout archive member is unreadable")
                content = source.read(2 * 1024 * 1024 + 1)
                if len(content) != member.size:
                    raise ValueError("clean checkout archive member is truncated")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                file_hashes.append((normalized, hashlib.sha256(content).hexdigest()))
                if normalized.startswith(("swarm/", "console/", "config/", "policies/")) and _CLEAN_SECRET.search(content):
                    raise ValueError("clean checkout contains secret-bearing packaged content")

        missing = sorted(_CLEAN_REQUIRED_FILES - {name for name, _digest in file_hashes})
        if missing:
            raise ValueError("clean checkout is missing required tracked artifacts: " + ", ".join(missing))
        forbidden = {".git", ".swarm-state", ".pytest_cache", "__pycache__"}
        if any(part in forbidden for name, _digest in file_hashes for part in Path(name).parts):
            raise ValueError("clean checkout contains developer-local or runtime state")

        requirement_lines = (checkout / "requirements-test.txt").read_text(encoding="utf-8").splitlines()
        for line in requirement_lines:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            if value.count("==") != 1:
                raise ValueError("clean checkout dependency is not exactly pinned")
            name, version = value.split("==")
            if not name or not version or not re.fullmatch(r"[A-Za-z0-9_.+-]+", version):
                raise ValueError("clean checkout dependency declaration is malformed")
            declared.add(name.lower())
        if not _CLEAN_DECLARED_DEPENDENCIES.issubset(declared):
            raise ValueError("clean checkout runtime or proof dependency is undeclared")

        import_script = (
            "import json, pathlib, swarm.core, swarm.console, swarm.integrity, swarm.policy_gate; "
            "root=pathlib.Path.cwd().resolve(); modules=(swarm.core,swarm.console,swarm.integrity,swarm.policy_gate); "
            "assert all(pathlib.Path(m.__file__).resolve().is_relative_to(root) for m in modules); "
            "print(json.dumps([m.__name__ for m in modules]))"
        )
        environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        build = subprocess.run(
            [sys.executable, "-m", "compileall", "-q", "swarm"], cwd=checkout,
            env=environment, text=True, capture_output=True, timeout=60, check=False,
        )
        startup = subprocess.run(
            [sys.executable, "-c", import_script], cwd=checkout,
            env=environment, text=True, capture_output=True, timeout=30, check=False,
        )
        if build.returncode != 0 or startup.returncode != 0:
            raise ValueError("clean checkout build or startup failed")
        try:
            import yaml
            readiness = yaml.safe_load((checkout / "config/readiness.yaml").read_text(encoding="utf-8"))
            profiles = json.loads((checkout / "config/llm-profiles.json").read_text(encoding="utf-8"))
            policy = yaml.safe_load((checkout / "policies/risk-policy.yaml").read_text(encoding="utf-8"))
        except (ImportError, OSError, ValueError, TypeError) as exc:
            raise ValueError("clean checkout configuration failed closed") from exc
        if (
            not isinstance(readiness, dict) or readiness.get("mode") != "DRY_RUN"
            or readiness.get("deployment", {}).get("enabled") is not False
            or readiness.get("deployment", {}).get("adapter") != "DISABLED"
            or readiness.get("deployment", {}).get("credentials") != "NOT_CONFIGURED"
            or not isinstance(profiles, dict) or not isinstance(profiles.get("profiles"), list)
            or not isinstance(policy, dict) or policy.get("automatic_deployment", {}).get("enabled_initially") is not False
        ):
            raise ValueError("clean checkout safety configuration is unsupported")
        tree_sha256 = hashlib.sha256(
            json.dumps(sorted(file_hashes), separators=(",", ":"), ensure_ascii=True).encode("ascii")
        ).hexdigest()

    return {
        "schema_version": 1,
        "proof": "CLEAN_TRACKED_COMMIT",
        "commit": expected_commit,
        "tree_sha256": tree_sha256,
        "tracked_files": len(file_hashes),
        "required_files": len(_CLEAN_REQUIRED_FILES),
        "declared_dependencies": sorted(declared),
        "build": "PASS",
        "startup": "PASS",
        "startup_modules": ["swarm.core", "swarm.console", "swarm.integrity", "swarm.policy_gate"],
        "temporary_checkout_removed": True,
        "mode": "DRY_RUN",
        "deployment": "DISABLED",
        "kill_switch": "ENGAGED",
        "live_enabled": False,
        "production_ready": False,
        "authority_granted": False,
    }


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
    "operations": {"owner": "FW-OPS", "implementation": "swarm.operations / swarm.operations_capacity / swarm.mission_control.OperationsContinuityView", "status": "IMPLEMENTED"},
}


def _capability(
    requirement_id: str,
    component: str,
    dependencies: list[str],
    user_surface: str,
    golden_path: str,
    limitations: str,
    *,
    state: str = "Proven",
    implementation_status: str = "IMPLEMENTED",
    integration_status: str = "INTEGRATED",
    proof_status: str = "ACCEPTED_BOUNDED",
    demo_available: bool = False,
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "state": state,
        "component": component,
        "dependencies": dependencies,
        "user_surface": user_surface,
        "unit_tests": "PASS",
        "integration_tests": "PASS" if integration_status == "INTEGRATED" else "PARTIAL",
        "golden_path": golden_path,
        "limitations": limitations,
        "implementation_status": implementation_status,
        "integration_status": integration_status,
        "proof_status": proof_status,
        "demo_available": demo_available,
        "operating_mode": "DRY_RUN",
        "live_enabled": False,
        "production_ready": False,
    }


FUNCTIONALITY_MAP: tuple[dict[str, Any], ...] = (
    _capability("FW-CORE", "swarm.core / swarm.autonomous_loop", ["policy_gate", "AuditLog", "Git"], "local runner and console", "PASS: bounded dry-run/review control path", "No production deployment or live mutation"),
    _capability("FW-ASOC", "swarm.asoc", ["FW-ID", "FW-ROOT", "Action Tickets", "Model Broker", "MCP Gateway", "FW-EVID"], "internal authorization interface", "PASS: authorization, aggregate budgets, delegation, replay, recovery, kill-switch, and cross-tenant denials", "In-memory single-process DRY_RUN registries; no full external orchestration or Z3 solver"),
    _capability("FW-ID", "swarm.identity", ["FW-KEYS", "FW-EVID", "FW-HARNESS"], "internal identity and worker-binding interface", "PASS: tenant identity lifecycle, worker admission, revocation, and replay denial", "In-memory metadata only; no live authentication, federation, OAuth exchange, or device trust"),
    _capability("FW-KEYS", "swarm.keys", ["FW-ID", "FW-EVID", "trusted backend boundary"], "internal opaque-handle interface", "PASS: handle registration, binding, invalidation, and replay denial", "No vault/HSM backend, material resolution, signing, encryption, or live credentials"),
    _capability("FW-EVID", "swarm.evidence / swarm.core.AuditLog", ["domain validators", "tenant identity"], "internal canonical Evidence lifecycle", "PASS: tenant chain, durable append, restart reconstruction, replay, and tamper denial", "Local unsigned Evidence; no external storage, replication, cryptographic signing, or export"),
    _capability("FW-REC", "swarm.recovery", ["FW-EVID", "Git facts", "kill switch"], "internal recovery-admission metadata", "PASS: checkpoint persistence, reconstruction, exact resume admission, and tamper denial", "Metadata coordination only; no restore, rollback, restart, repair, or recovery execution"),
    _capability("FW-COMP", "swarm.compliance", ["FW-ID", "FW-EVID", "policy/test references"], "internal compliance mapping metadata", "PASS: mapping, Evidence admission, assessment, replay, expiry, and durability denial", "No certification, attestation, external reporting, or control execution"),
    _capability("FW-HARNESS", "swarm.harness_controller / swarm.harness_task / swarm.harness_context", ["FW-ID", "FW-KEYS", "FW-EVID", "Model Broker", "Git controller"], "Mission Control and internal controller", "PASS: persistent task, context, budgets, worker/reviewer, validation, escalation, and resume contracts", "Bounded local engineering harness; provider invocations remain adapter-controlled and deployment disabled", demo_available=True),
    _capability("FW-AID", "swarm.ai_agent_defense / swarm.normalized_events", ["FW-ENDPOINT", "FW-ID", "FW-KEYS", "FW-SOC", "FW-EVID", "FW-HARNESS"], "Mission Control AI Security", "PASS: fixture attribution through detection, correlation, proposal, Evidence, and projection", "Caller-supplied metadata only; no live sensor, enforcement, containment, or recovery execution", demo_available=True),
    _capability("FW-API", "swarm.api_contract", ["FW-ID", "policy", "leases", "FW-EVID"], "internal read-only admission contract", "PASS: versioned tenant-bound read admission and fail-closed mutation/authority denials", "No listener, remote transport, response handler, authentication exchange, or mutation API"),
    _capability("FW-MCP", "swarm.mcp_gateway", ["FW-ID", "policy", "leases", "FW-EVID"], "internal MCP admission interface", "PASS: registered tool admission, tenant/capability binding, replay, and kill-switch denial", "No arbitrary tool execution, live discovery, credential resolution, or external MCP transport"),
    _capability("FW-UX", "swarm.console / swarm.mission_control / console", ["FW-HARNESS", "FW-AID", "FW-SOC", "FW-EVID"], "ForgeWarden Mission Control", "PASS: demo separation plus canonical read-only provider lifecycle and tenant denial", "Loopback read-only console; most operational scenario data remains clearly labeled DEMO", demo_available=True),
    _capability("FW-SOC", "swarm.soc", ["NormalizedEventStore", "FW-AID", "FW-EVID", "Action Tickets"], "Mission Control incident projection", "PASS: normalized alert, correlated attack story, inert playbook proposal, and Evidence lifecycle", "Caller-supplied metadata only; no live SIEM ingestion, case service, or response execution", demo_available=True),
    _capability("FW-ENDPOINT", "swarm.endpoint_fixtures / swarm.sensor_adapter / swarm.normalized_events", ["FW-ID", "FW-EVID", "FW-AID"], "internal endpoint fixture pipeline", "PASS: Windows/Linux/macOS/Android fixtures, batching, correlation, recovery replay, and AI attribution", "No installed MicroSensor, platform hook, live collection, process control, or endpoint response"),
    _capability("FW-RANSOM", "swarm.ransomware", ["FW-ENDPOINT", "FW-EVID", "Action Tickets"], "internal RansomGuard detector and proposal", "PASS: supplied behavioral detection, correlation, inert containment proposal, and false-positive proof", "No live filesystem sensor, isolation, snapshot, rollback, or remediation execution", demo_available=True),
    _capability("FW-BME", "swarm.browser_email", ["FW-AID", "FW-SOC", "FW-EVID"], "internal browser/email detection interface", "PASS: caller-supplied content metadata, classification, correlation, and inert response proposal", "No browser extension, mail transport, content retrieval, account action, or network enforcement"),
    _capability("FW-SAAS", "swarm.saas_security", ["FW-ID", "FW-KEYS", "FW-EVID", "FW-SOC"], "internal SaaS security lifecycle", "PASS: supplied posture facts, risk, ownership binding, proposal, and Mission Control projection", "No SaaS discovery, provider API, OAuth exchange, mutation, or response execution"),
    _capability("FW-SUPPLY", "swarm.supply_chain", ["FW-KEYS", "TrustedSignatureCatalog", "FW-EVID", "FW-SOC"], "internal supply-chain lifecycle", "PASS: supplied artifact facts, risk, provenance binding, proposal, and projection", "No repository scanner, package retrieval, CI/CD integration, signing, or deployment enforcement"),
    _capability("FW-NET", "swarm.network_security", ["FW-ENDPOINT", "FW-ID", "FW-EVID", "FW-SOC"], "internal network security lifecycle", "PASS: supplied observation, classification, owner binding, proposal, and projection", "No packet/DNS sensor, socket, NAC, firewall change, containment, or network response"),
    _capability("FW-ASM", "swarm.attack_surface", ["FW-ENDPOINT", "FW-NET", "FW-SAAS", "FW-EVID"], "internal attack-surface lifecycle", "PASS: supplied external-asset facts, classification, owner binding, proposal, and projection", "No discovery, DNS resolution, scan, cloud query, exploit, takedown, or remediation"),
    _capability("FW-DSPM", "swarm.data_security", ["FW-ENDPOINT", "FW-SAAS", "FW-SUPPLY", "FW-EVID"], "internal data-security lifecycle", "PASS: supplied posture facts, classification, owner binding, DLP proposal, and projection", "No content discovery, inspection, query, data movement, DLP enforcement, or remediation"),
    _capability("FW-GOV", "swarm.high_assurance", ["Approved Model Registry", "Model Broker", "FW-EVID", "Mission Control"], "internal high-assurance admission and projection", "PASS: profile, exact model admission, approved-equivalent failover, Evidence, and projection", "No provider invocation, sovereign infrastructure, ATO/certification, credential resolution, or deployment"),
    _capability("FW-OPS", "swarm.operations / swarm.operations_capacity", ["FW-EVID", "FW-REC", "FW-ENDPOINT"], "Mission Control operations continuity", "PASS: health/capacity Evidence, reconstruction, resume admission, and projection", "Caller-supplied local metadata; no live telemetry, HA/DR control, retention movement, or service operation"),
    _capability("FW-INTEGRITY", "swarm.integrity", ["Git", "Python", "pytest", "invariant manifest", "WORK_QUEUE"], "integrity gate and capability-status report", "PASS: build/startup/configuration/invariants/tests/Golden Path plus accepted-work traceability", "Current proof is repository-local; clean packaging, mutation testing, and broader production-like execution remain", state="Implemented", proof_status="CURRENT_REPOSITORY_VALIDATION"),
)


_REQUIREMENT_HEADING = re.compile(r"^### (FW-(?!Q-)[A-Z0-9-]+) — .+$", re.MULTILINE)
_COMMIT_REFERENCE = re.compile(r"(?<![0-9a-f])[0-9a-f]{7,64}(?![0-9a-f])")
_REPOSITORY_PATH = re.compile(
    r"(?<![A-Za-z0-9_.-])((?:(?:swarm|tests|docs|console|config|policies|scripts)/"
    r"[A-Za-z0-9_./*?-]+)|(?:ROADMAP|WORK_QUEUE|SWARM_STATUS|BLOCKERS|DECISIONS|AGENTS)\.md)"
)
_REALITY_REQUIRED_FIELDS = ("State", "Allowed paths", "Completion evidence")


def _family_id(requirement_id: str) -> str:
    parts = requirement_id.split("-")
    return "-".join(parts[:2])


def _extract_field(body: str, field: str) -> str | None:
    match = re.search(rf"^- {re.escape(field)}: *(.*)$", body, flags=re.MULTILINE)
    return match.group(1).strip() if match else None


def _extract_paths(value: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(match.group(1).rstrip(".,;:") for match in _REPOSITORY_PATH.finditer(value)))


def audit_completed_requirement_work(root: Path) -> dict[str, Any]:
    """Reconcile accepted requirement records with repository artifacts.

    This is a traceability audit, not a substitute for executing tests or for
    exact-commit review. It proves that a DONE record points at surviving
    implementation/documentation, validation files, and a commit that exists
    in the current repository. Runtime assurance remains the responsibility
    of the Product Integrity Gate and the recorded exact review.
    """
    root = root.resolve()
    queue_path = root / "WORK_QUEUE.md"
    try:
        queue = queue_path.read_text(encoding="utf-8")
    except OSError as exc:
        return {
            "schema_version": 1,
            "assessment": "UNAVAILABLE",
            "assurance": "TRACEABILITY_ONLY",
            "reason": type(exc).__name__,
            "tasks": [],
            "summary": {"accepted": 0, "traceable": 0, "unsupported": 0},
            "unmapped_accepted_families": [],
        }

    headings = list(_REQUIREMENT_HEADING.finditer(queue))
    all_references = tuple(dict.fromkeys(_COMMIT_REFERENCE.findall(queue)))
    try:
        resolved = subprocess.run(
            ["git", "cat-file", "--batch-check=%(objectname) %(objecttype)"],
            cwd=root,
            input="\n".join(all_references) + "\n",
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        resolved_commits_by_reference = {
            reference: line.split()[0]
            for reference, line in zip(all_references, resolved.stdout.splitlines())
            if len(line.split()) == 2 and line.split()[1] == "commit"
        }
    except (OSError, subprocess.TimeoutExpired):
        resolved_commits_by_reference = {}
    tasks: list[dict[str, Any]] = []
    for index, heading in enumerate(headings):
        requirement_id = heading.group(1)
        body = queue[heading.end() : headings[index + 1].start() if index + 1 < len(headings) else len(queue)]
        fields = {field: _extract_field(body, field) for field in _REALITY_REQUIRED_FIELDS}
        if fields["State"] != "DONE":
            continue
        allowed_paths = _extract_paths(fields["Allowed paths"] or "")
        test_command = _extract_field(body, "Test command") or ""
        test_paths = tuple(path for path in _extract_paths(test_command) if path.startswith(("tests/", "scripts/")))
        completion = fields["Completion evidence"] or ""
        evidence_paths = tuple(path for path in _extract_paths(completion) if path.startswith("docs/"))
        commit_references = tuple(dict.fromkeys(_COMMIT_REFERENCE.findall(completion)))

        missing_fields = tuple(field for field, value in fields.items() if not value)
        referenced_paths = (*allowed_paths, *test_paths, *evidence_paths)
        unsafe_paths = tuple(
            path for path in referenced_paths
            if Path(path).is_absolute() or ".." in Path(path).parts
        )
        safe_paths = tuple(path for path in referenced_paths if path not in unsafe_paths)
        missing_paths = tuple(dict.fromkeys(
            path for path in safe_paths
            if not (list(root.glob(path)) if "*" in path else (root / path).exists())
        ))
        resolved_commits = [
            resolved_commits_by_reference[reference]
            for reference in commit_references
            if reference in resolved_commits_by_reference
        ]
        documentation_only = bool(allowed_paths) and all(
            path.endswith((".md", ".json", ".yaml", ".yml")) for path in allowed_paths
        )
        reasons: list[str] = []
        if missing_fields:
            reasons.append("MISSING_REQUIRED_QUEUE_FIELDS")
        if not allowed_paths:
            reasons.append("NO_TRACEABLE_ALLOWED_PATHS")
        if not documentation_only and not test_paths:
            reasons.append("NO_TRACEABLE_TEST_PATHS")
        if missing_paths:
            reasons.append("REFERENCED_ARTIFACT_MISSING")
        if unsafe_paths:
            reasons.append("UNSAFE_REFERENCED_PATH")
        if not commit_references or not resolved_commits:
            reasons.append("NO_RESOLVABLE_COMPLETION_COMMIT")
        tasks.append(
            {
                "requirement_id": requirement_id,
                "family_id": _family_id(requirement_id),
                "kind": "DOCUMENTATION_ONLY" if documentation_only else "IMPLEMENTATION",
                "traceability": "TRACEABLE" if not reasons else "UNSUPPORTED_CLAIM",
                "reasons": reasons,
                "allowed_paths": list(allowed_paths),
                "test_paths": list(test_paths),
                "evidence_paths": list(evidence_paths),
                "commit_references": list(commit_references),
                "resolved_commits": list(dict.fromkeys(resolved_commits)),
                "missing_paths": list(missing_paths),
            }
        )

    accepted_families = {_family_id(task["requirement_id"]) for task in tasks}
    mapped_families = {_family_id(item["requirement_id"]) for item in FUNCTIONALITY_MAP}
    unsupported = [task for task in tasks if task["traceability"] != "TRACEABLE"]
    unmapped = sorted(accepted_families - mapped_families)
    return {
        "schema_version": 1,
        "assessment": "TRACEABLE" if not unsupported else "UNSUPPORTED_CLAIMS",
        "assurance": "TRACEABILITY_ONLY",
        "runtime_validation": "NOT_RUN_BY_THIS_AUDIT",
        "production_readiness_inferred": False,
        "tasks": tasks,
        "summary": {
            "accepted": len(tasks),
            "traceable": len(tasks) - len(unsupported),
            "unsupported": len(unsupported),
            "accepted_families": len(accepted_families),
        },
        "unmapped_accepted_families": unmapped,
    }


_FUNCTIONALITY_REQUIRED_FIELDS = frozenset({
    "requirement_id", "state", "component", "dependencies", "user_surface",
    "unit_tests", "integration_tests", "golden_path", "limitations",
    "implementation_status", "integration_status", "proof_status",
    "demo_available", "operating_mode", "live_enabled", "production_ready",
})


def validate_functionality_map(
    reality: dict[str, Any],
    functionality: tuple[dict[str, Any], ...] = FUNCTIONALITY_MAP,
) -> dict[str, Any]:
    """Validate one honest capability-status projection against accepted work."""
    if reality.get("assessment") != "TRACEABLE" or reality.get("production_readiness_inferred") is not False:
        raise ValueError("functionality map requires a traceable non-authorizing reality audit")
    if not functionality:
        raise ValueError("functionality map is empty")
    families: dict[str, str] = {}
    for item in functionality:
        if not isinstance(item, dict) or set(item) != _FUNCTIONALITY_REQUIRED_FIELDS:
            raise ValueError("functionality record is malformed")
        requirement_id = item["requirement_id"]
        if not isinstance(requirement_id, str) or not re.fullmatch(r"FW-[A-Z0-9]+", requirement_id):
            raise ValueError("functionality requirement ID is malformed")
        family = _family_id(requirement_id)
        if family in families:
            raise ValueError("functionality map contains duplicate family")
        families[family] = requirement_id
        if item["state"] not in {"Designed", "Implemented", "Integrated", "Proven"}:
            raise ValueError("functionality proof state is malformed")
        if item["implementation_status"] not in {"PARTIAL", "IMPLEMENTED"}:
            raise ValueError("functionality implementation state is malformed")
        if item["integration_status"] not in {"PARTIAL", "INTEGRATED"}:
            raise ValueError("functionality integration state is malformed")
        if item["proof_status"] not in {"ACCEPTED_BOUNDED", "CURRENT_REPOSITORY_VALIDATION"}:
            raise ValueError("functionality proof evidence state is malformed")
        if item["operating_mode"] != "DRY_RUN" or item["live_enabled"] is not False or item["production_ready"] is not False:
            raise ValueError("functionality map claims unsupported live or production authority")
        if not isinstance(item["demo_available"], bool):
            raise ValueError("functionality demo state is malformed")
        for field in ("component", "user_surface", "golden_path", "limitations"):
            if not isinstance(item[field], str) or not item[field].strip() or len(item[field]) > 1024:
                raise ValueError("functionality text field is malformed")
        if not isinstance(item["dependencies"], list) or any(
            not isinstance(value, str) or not value.strip() for value in item["dependencies"]
        ):
            raise ValueError("functionality dependencies are malformed")
        if item["state"] == "Proven" and (
            item["implementation_status"] != "IMPLEMENTED"
            or item["integration_status"] != "INTEGRATED"
            or item["proof_status"] != "ACCEPTED_BOUNDED"
        ):
            raise ValueError("functionality map claims proof stronger than its evidence")
    accepted_families = {task["family_id"] for task in reality["tasks"]}
    missing = sorted(accepted_families - set(families))
    if missing:
        raise ValueError("functionality map omits accepted families: " + ", ".join(missing))
    return {
        "passed": True,
        "accepted_family_count": len(accepted_families),
        "mapped_family_count": len(families),
        "extra_foundational_families": sorted(set(families) - accepted_families),
        "operating_mode": "DRY_RUN",
        "live_enabled": False,
        "production_ready": False,
    }


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
    reality = audit_completed_requirement_work(root)
    try:
        invariants = validate_invariant_manifest()
        ownership = validate_canonical_ownership()
        functionality_validation = validate_functionality_map(reality)
        architecture = {"passed": True, "invariant_ids": [item.invariant_id for item in invariants], "owners": ownership, "functionality_map": functionality_validation}
    except (PolicyInvariantError, ValueError) as exc:
        architecture = {"passed": False, "reason": str(exc)}
    tests = _run(list(test_command or [sys.executable, "-m", "pytest", "-q"]), root, 300)
    golden = _run(
        list(golden_command or ["bash", "scripts/run-product-golden-path.sh"]), root, 180,
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
    if reality["summary"]["unsupported"]:
        findings.append({"severity": "RED", "area": "product_reality", "reason": "accepted queue records lack traceable implementation, test, Evidence, or commit artifacts"})
    if reality["unmapped_accepted_families"]:
        findings.append({"severity": "YELLOW", "area": "product_reality", "reason": "accepted families are absent from the functionality map: " + ", ".join(reality["unmapped_accepted_families"])})
    checks = {"repository": git["clean"], "build": build["passed"], "startup": startup["passed"], "configuration": config["passed"], "invariant_manifest": architecture["passed"], "architecture_ownership": architecture["passed"], "functionality_map": architecture["passed"], "completion_traceability": reality["assessment"] == "TRACEABLE", "tests": tests["passed"], "golden_path": golden.get("passed", False)}
    hard_failures = [name for name, passed in checks.items() if not passed and name != "golden_path"]
    decision = "RED" if hard_failures else ("YELLOW" if findings or not golden.get("passed") else "GREEN")
    return {"schema_version": "1", "decision": decision, "head": git["head"], "checks": checks, "findings": findings, "architecture_validation": architecture, "reality_audit": reality, "missing_canonical_owners": missing_owners, "dependency_check": dependencies, "commands": {"tests": tests, "golden_path": golden}, "functionality": [dict(item, last_validated_commit=git["head"]) for item in FUNCTIONALITY_MAP], "canonical_ownership": CANONICAL_OWNERSHIP}


def write_gate_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
