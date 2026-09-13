import json
import subprocess
import sys
from pathlib import Path

from swarm.integrity import CANONICAL_OWNERSHIP, FUNCTIONALITY_MAP, audit_completed_requirement_work, run_product_integrity_gate, validate_canonical_ownership


ROOT = Path(__file__).resolve().parents[1]


def test_canonical_ownership_validation_detects_duplicate_implementations():
    assert validate_canonical_ownership()["model_selection"] == "Model Broker"
    altered = {key: dict(value) for key, value in CANONICAL_OWNERSHIP.items()}
    altered["identity"]["implementation"] = altered["model_selection"]["implementation"]
    try:
        validate_canonical_ownership(altered)
    except ValueError as exc:
        assert "duplicate canonical implementation" in str(exc)
    else:
        raise AssertionError("duplicate canonical implementation was accepted")


def test_canonical_ownership_validation_rejects_malformed_records():
    for malformed in (
        {},
        {"identity": {"owner": "FW-ID", "implementation": "swarm.identity.IdentityRecord"}},
        {"identity": {"owner": "FW-ID", "implementation": "x" * 513, "status": "IMPLEMENTED"}},
        {"identity": {"owner": " ", "implementation": "swarm.identity.IdentityRecord", "status": "IMPLEMENTED"}},
    ):
        try:
            validate_canonical_ownership(malformed)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed canonical ownership was accepted")


def test_functionality_map_distinguishes_proven_from_not_yet_proven():
    states = {item["requirement_id"]: item["state"] for item in FUNCTIONALITY_MAP}
    assert states["FW-CORE"] == "Proven"
    assert states["FW-ASOC-01"] == "Proven"
    assert states["FW-ASOC-02"] == "Proven"
    assert states["FW-ID"] == "Proven"
    assert states["FW-KEYS"] == "Proven"
    assert states["FW-EVID"] == "Proven"
    assert states["FW-REC"] == "Proven"
    assert states["FW-COMP"] == "Proven"
    assert states["FW-OPS"] == "Proven"
    assert states["FW-INTEGRITY"] == "Implemented"


def test_canonical_ownership_exposes_missing_roadmap_primitives_honestly():
    assert CANONICAL_OWNERSHIP["agent_authority"]["implementation"] == "swarm.asoc.CapabilityAuthorizer"
    assert CANONICAL_OWNERSHIP["model_selection"]["implementation"] == "swarm.model_broker.ModelBroker"
    assert CANONICAL_OWNERSHIP["mcp_access"]["implementation"] == "swarm.mcp_gateway.MCPGateway"
    assert CANONICAL_OWNERSHIP["identity"]["implementation"] == "swarm.identity.IdentityRecord"
    assert CANONICAL_OWNERSHIP["identity"]["status"] == "IMPLEMENTED_PARTIAL"
    assert CANONICAL_OWNERSHIP["evidence"]["implementation"].startswith("swarm.evidence.EvidenceEnvelope")
    assert CANONICAL_OWNERSHIP["evidence"]["status"] == "IMPLEMENTED"
    assert CANONICAL_OWNERSHIP["cryptographic_authority"]["implementation"].startswith("swarm.keys.SecretHandleRegistry")
    assert CANONICAL_OWNERSHIP["cryptographic_authority"]["status"] == "IMPLEMENTED_PARTIAL"
    assert CANONICAL_OWNERSHIP["normalized_events"]["implementation"] == "swarm.normalized_events.NormalizedEventStore"
    assert CANONICAL_OWNERSHIP["normalized_events"]["status"] == "IMPLEMENTED_PARTIAL"
    assert CANONICAL_OWNERSHIP["soc_incidents"]["implementation"] == "swarm.soc.SOCIncidentProjection"
    assert CANONICAL_OWNERSHIP["soc_incidents"]["status"] == "IMPLEMENTED_PARTIAL"
    assert CANONICAL_OWNERSHIP["compliance"]["implementation"].startswith("swarm.compliance ControlMapping")
    assert CANONICAL_OWNERSHIP["compliance"]["status"] == "IMPLEMENTED"
    assert CANONICAL_OWNERSHIP["ai_agent_defense"]["implementation"].startswith("swarm.ai_agent_defense")
    assert CANONICAL_OWNERSHIP["ai_agent_defense"]["status"] == "IMPLEMENTED"
    assert CANONICAL_OWNERSHIP["operations"]["owner"] == "FW-OPS"
    assert CANONICAL_OWNERSHIP["operations"]["status"] == "IMPLEMENTED"


def test_standing_gate_documents_ownership_graph_and_product_map():
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    decisions = (ROOT / "DECISIONS.md").read_text(encoding="utf-8")
    assert "FW-INTEGRITY" in roadmap
    assert "standing product gate" in decisions
    assert (ROOT / "docs/fw-integrity-dependency-graph.md").is_file()
    assert (ROOT / "docs/fw-integrity-functionality-map.md").is_file()


def test_test_dependencies_are_declared_and_pinned():
    requirements = (ROOT / "requirements-test.txt").read_text(encoding="utf-8")
    for package in ("jsonschema==", "psutil==", "pytest==", "PyYAML==", "tzdata=="):
        assert package in requirements


def test_integrity_gate_cli_is_documented_by_help():
    result = subprocess.run([sys.executable, "-m", "swarm.cli", "--help"], cwd=ROOT, text=True, capture_output=True, check=False)
    assert result.returncode == 0
    assert "integrity-gate" in result.stdout


def test_gate_reports_current_repository_health_and_dependency_risk():
    report = run_product_integrity_gate(
        ROOT,
        test_command=[sys.executable, "-m", "pytest", "-q", "tests/test_swarm.py", "tests/test_phase2a.py", "tests/test_phase2b_profiles.py", "tests/test_console.py"],
        golden_command=[sys.executable, "-m", "pytest", "-q", "tests/test_swarm.py"],
        check_dependencies=True,
    )
    assert report["checks"]["build"]
    assert report["checks"]["startup"]
    assert report["checks"]["configuration"]
    assert report["checks"]["invariant_manifest"]
    assert report["checks"]["architecture_ownership"]
    assert report["checks"]["tests"]
    assert report["checks"]["golden_path"]
    assert report["head"]
    assert report["missing_canonical_owners"] == []
    assert not any(item["area"] == "architecture" for item in report["findings"])


def test_gate_runs_the_canonical_golden_path_by_default():
    report = run_product_integrity_gate(
        ROOT, test_command=[sys.executable, "-c", "pass"], check_dependencies=False,
    )
    assert report["checks"]["golden_path"]


def test_gate_fails_repository_check_when_worktree_is_dirty(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "README").write_text("x", encoding="utf-8")
    subprocess.run(["git", "add", "README"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.test", "commit", "-qm", "initial"], cwd=tmp_path, check=True)
    (tmp_path / "dirty").write_text("x", encoding="utf-8")
    report = run_product_integrity_gate(tmp_path, test_command=[sys.executable, "-c", "pass"], golden_command=[sys.executable, "-c", "pass"], check_dependencies=False)
    assert report["decision"] == "RED"
    assert any(item["area"] == "repository" for item in report["findings"])



def test_reality_audit_traces_accepted_work_without_inferring_runtime_or_production():
    report = audit_completed_requirement_work(ROOT)
    assert report["assessment"] == "TRACEABLE"
    assert report["summary"]["accepted"] >= 114
    assert report["summary"]["unsupported"] == 0
    assert report["runtime_validation"] == "NOT_RUN_BY_THIS_AUDIT"
    assert report["production_readiness_inferred"] is False
    assert {"FW-HARNESS", "FW-UX", "FW-GOV"}.issubset(report["unmapped_accepted_families"])
    endpoint = next(item for item in report["tasks"] if item["requirement_id"] == "FW-AID-009")
    assert "swarm/endpoint_fixtures.py" in endpoint["allowed_paths"]
    assert endpoint["traceability"] == "TRACEABLE"


def test_reality_audit_fails_closed_when_a_recorded_artifact_disappears(tmp_path):
    (tmp_path / "swarm").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "swarm/example.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "tests/test_example.py").write_text("def test_value(): assert True\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.test", "commit", "-qm", "initial"],
        cwd=tmp_path,
        check=True,
    )
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True, capture_output=True, check=True,
    ).stdout.strip()
    (tmp_path / "WORK_QUEUE.md").write_text(
        "### FW-TEST-001 — Synthetic accepted work\n"
        "- State: DONE\n"
        "- Allowed paths: swarm/example.py, tests/test_example.py\n"
        "- Test command: python3 -m pytest -q tests/test_example.py\n"
        f"- Completion evidence: exact candidate `{commit}`; focused validation passed.\n",
        encoding="utf-8",
    )
    traceable = audit_completed_requirement_work(tmp_path)
    assert traceable["assessment"] == "TRACEABLE"
    assert traceable["summary"] == {
        "accepted": 1, "traceable": 1, "unsupported": 0, "accepted_families": 1,
    }

    (tmp_path / "tests/test_example.py").unlink()
    unsupported = audit_completed_requirement_work(tmp_path)
    assert unsupported["assessment"] == "UNSUPPORTED_CLAIMS"
    assert unsupported["summary"]["unsupported"] == 1
    assert unsupported["tasks"][0]["reasons"] == ["REFERENCED_ARTIFACT_MISSING"]
    assert unsupported["tasks"][0]["missing_paths"] == ["tests/test_example.py"]

    (tmp_path / "WORK_QUEUE.md").write_text(
        "### FW-TEST-001 — Synthetic accepted work\n"
        "- State: DONE\n"
        "- Allowed paths: swarm/../../outside, tests/test_example.py\n"
        "- Test command: python3 -m pytest -q tests/test_example.py\n"
        f"- Completion evidence: exact candidate `{commit}`; focused validation passed.\n",
        encoding="utf-8",
    )
    unsafe = audit_completed_requirement_work(tmp_path)
    assert "UNSAFE_REFERENCED_PATH" in unsafe["tasks"][0]["reasons"]


def test_integrity_gate_exposes_completion_traceability():
    report = run_product_integrity_gate(
        ROOT,
        test_command=[sys.executable, "-c", "pass"],
        golden_command=[sys.executable, "-c", "pass"],
        check_dependencies=False,
    )
    assert report["checks"]["completion_traceability"]
    assert report["reality_audit"]["assessment"] == "TRACEABLE"
    assert report["reality_audit"]["production_readiness_inferred"] is False
    assert any(item["area"] == "product_reality" for item in report["findings"])
