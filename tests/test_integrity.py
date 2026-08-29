import json
import subprocess
import sys
from pathlib import Path

from swarm.integrity import CANONICAL_OWNERSHIP, FUNCTIONALITY_MAP, run_product_integrity_gate


ROOT = Path(__file__).resolve().parents[1]


def test_functionality_map_distinguishes_proven_from_not_yet_proven():
    states = {item["requirement_id"]: item["state"] for item in FUNCTIONALITY_MAP}
    assert states["FW-CORE"] == "Proven"
    assert states["FW-ASOC-01"] == "Implemented"
    assert states["FW-INTEGRITY"] == "Implemented"


def test_canonical_ownership_exposes_missing_roadmap_primitives_honestly():
    assert CANONICAL_OWNERSHIP["agent_authority"]["implementation"] == "swarm.asoc.CapabilityAuthorizer"
    assert CANONICAL_OWNERSHIP["identity"]["status"] == "DEFINED"
    assert CANONICAL_OWNERSHIP["normalized_events"]["status"] == "DEFINED"


def test_standing_gate_documents_ownership_graph_and_product_map():
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    decisions = (ROOT / "DECISIONS.md").read_text(encoding="utf-8")
    assert "FW-INTEGRITY" in roadmap
    assert "standing product gate" in decisions
    assert (ROOT / "docs/fw-integrity-dependency-graph.md").is_file()
    assert (ROOT / "docs/fw-integrity-functionality-map.md").is_file()


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
    assert report["checks"]["tests"]
    assert report["checks"]["golden_path"]
    assert report["head"]
    assert any(item["area"] == "architecture" for item in report["findings"])


def test_gate_fails_repository_check_when_worktree_is_dirty(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "README").write_text("x", encoding="utf-8")
    subprocess.run(["git", "add", "README"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.test", "commit", "-qm", "initial"], cwd=tmp_path, check=True)
    (tmp_path / "dirty").write_text("x", encoding="utf-8")
    report = run_product_integrity_gate(tmp_path, test_command=[sys.executable, "-c", "pass"], golden_command=[sys.executable, "-c", "pass"], check_dependencies=False)
    assert report["decision"] == "RED"
    assert any(item["area"] == "repository" for item in report["findings"])
