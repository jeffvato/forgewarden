import json
import subprocess
import tempfile
from pathlib import Path

import pytest

import swarm.integrity as integrity
from swarm.integrity import (
    _PERFORMANCE_SCENARIOS,
    _validated_performance_result,
    run_control_performance_baseline,
)


ROOT = Path(__file__).resolve().parents[1]


def head() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
        capture_output=True, check=True,
    ).stdout.strip()


def test_exact_commit_control_plane_performance_baseline():
    report = run_control_performance_baseline(ROOT, head())
    assert report["commit"] == head()
    assert report["summary"] == {"defined": 5, "passed": 5, "failed": 0}
    assert [item["scenario_id"] for item in report["scenarios"]] == list(_PERFORMANCE_SCENARIOS)
    assert all(item["result"] == "PASS" and item["output_retained"] is False for item in report["scenarios"])
    assert report["assurance"] == "LOCAL_REGRESSION_ONLY"
    assert report["production_capacity_inferred"] is False
    assert report["service_level_inferred"] is False
    assert report["temporary_checkout_removed"] is True
    assert report["mode"] == "DRY_RUN" and report["deployment"] == "DISABLED"
    assert report["kill_switch"] == "ENGAGED" and report["authority_granted"] is False
    print("FW_PERFORMANCE_BASELINE=" + json.dumps(report, sort_keys=True, separators=(",", ":")))


def sample_result(**changes):
    value = {
        "schema_version": 1, "scenario_id": "identity_policy", "iterations": 10,
        "operations": 10, "wall_ms": 1.0, "peak_kib": 1, "processes": 1,
        "checksum": 10, "mode": "DRY_RUN", "deployment": "DISABLED",
        "authority_granted": False,
    }
    value.update(changes)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def sample_policy():
    return {
        "scenario_id": "identity_policy", "iterations": 10, "max_wall_ms": 100,
        "max_peak_kib": 1024, "timeout_seconds": 1, "max_output_bytes": 256,
        "max_processes": 1,
    }


@pytest.mark.parametrize(
    "returncode,output,timed_out,match",
    [
        (None, b"", True, "timed out"),
        (1, b"", False, "process failed"),
        (0, b"x" * 257, False, "exceeds"),
        (0, b"Bearer abcdefghijklmnopqrstuvwxyz", False, "secret-bearing"),
        (0, b"not-json", False, "malformed"),
    ],
)
def test_result_rejects_timeout_crash_excessive_secret_or_malformed_output(returncode, output, timed_out, match):
    with pytest.raises(ValueError, match=match):
        _validated_performance_result(sample_policy(), returncode, output, timed_out=timed_out)


@pytest.mark.parametrize(
    "change",
    [
        {"scenario_id": "evidence_hash"}, {"iterations": 11}, {"operations": 9},
        {"wall_ms": 101}, {"peak_kib": 1025}, {"processes": 2},
        {"mode": "LIVE"}, {"deployment": "ENABLED"}, {"authority_granted": True},
    ],
)
def test_result_rejects_binding_threshold_process_and_safety_violations(change):
    with pytest.raises(ValueError, match="exceeded"):
        _validated_performance_result(sample_policy(), 0, sample_result(**change))


def test_validated_result_retains_no_child_output():
    result = _validated_performance_result(sample_policy(), 0, sample_result())
    assert result["result"] == "PASS" and result["output_retained"] is False
    assert "checksum" not in result


def test_proof_rejects_non_exact_or_changed_commit():
    with pytest.raises(ValueError, match="invalid"):
        run_control_performance_baseline(ROOT, "short")
    wrong = "0" * 40 if head() != "0" * 40 else "1" * 40
    with pytest.raises(ValueError, match="current commit mismatch"):
        run_control_performance_baseline(ROOT, wrong)


def test_performance_checkout_is_removed_when_result_validation_fails(monkeypatch):
    temporary_root = Path(tempfile.gettempdir())
    before = {path.resolve() for path in temporary_root.glob("forgewarden-performance-*")}

    def fail(*_args, **_kwargs):
        raise ValueError("synthetic performance failure")

    monkeypatch.setattr(integrity, "_validated_performance_result", fail)
    with pytest.raises(ValueError, match="synthetic performance failure"):
        integrity.run_control_performance_baseline(ROOT, head())
    after = {path.resolve() for path in temporary_root.glob("forgewarden-performance-*")}
    assert after == before
