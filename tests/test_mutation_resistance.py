import dataclasses
import json
import subprocess
from pathlib import Path

import pytest

from swarm.integrity import (
    INVARIANT_MUTATIONS,
    InvariantMutation,
    _MutationProcessResult,
    _apply_invariant_mutation,
    _validate_mutation_manifest,
    _validated_mutation_result,
    run_mutation_resistance_proof,
)


ROOT = Path(__file__).resolve().parents[1]


def head() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
        capture_output=True, check=True,
    ).stdout.strip()


def status() -> str:
    return subprocess.run(
        ["git", "status", "--porcelain=v1"], cwd=ROOT, text=True,
        capture_output=True, check=True,
    ).stdout


def test_exact_commit_mutation_proof_kills_all_critical_invariant_mutants():
    before_head, before_status = head(), status()
    report = run_mutation_resistance_proof(ROOT, before_head)
    assert report["commit"] == before_head
    assert report["proof"] == "CRITICAL_INVARIANT_MUTATION_RESISTANCE"
    assert report["summary"] == {"defined": 8, "killed": 8, "survived": 0}
    assert [item["mutation_id"] for item in report["mutants"]] == [
        item.mutation_id for item in INVARIANT_MUTATIONS
    ]
    assert all(item["result"] == "KILLED" and item["returncode"] == 1 for item in report["mutants"])
    assert all(item["output_retained"] is False for item in report["mutants"])
    assert report["temporary_checkouts_removed"] is True
    assert report["mode"] == "DRY_RUN" and report["deployment"] == "DISABLED"
    assert report["kill_switch"] == "ENGAGED" and report["authority_granted"] is False
    assert head() == before_head and status() == before_status
    print("FW_MUTATION_RESISTANCE=" + json.dumps(report, sort_keys=True, separators=(",", ":")))


def test_manifest_is_fixed_bounded_unique_and_immutable():
    assert _validate_mutation_manifest(INVARIANT_MUTATIONS) is INVARIANT_MUTATIONS
    assert len({item.invariant_id for item in INVARIANT_MUTATIONS}) == 7
    assert {item.owner for item in INVARIANT_MUTATIONS} >= {
        "FW-HARNESS/FW-ROOT", "FW-ID/FW-EVID", "FW-EVID", "FW-HARNESS",
        "Model Broker", "MCP Gateway", "FW-OPS/FW-ROOT",
    }
    with pytest.raises(dataclasses.FrozenInstanceError):
        INVARIANT_MUTATIONS[0].path = "swarm/unsafe.py"  # type: ignore[misc]


@pytest.mark.parametrize(
    "mutations,match",
    [
        ((), "bounded tuple"),
        (INVARIANT_MUTATIONS + (INVARIANT_MUTATIONS[0],), "unique"),
        ((dataclasses.replace(INVARIANT_MUTATIONS[0], path="../outside.py"),), "unsafe"),
        ((dataclasses.replace(INVARIANT_MUTATIONS[0], test_selector="tests/test_x.py -k all"),), "malformed"),
        ((dataclasses.replace(INVARIANT_MUTATIONS[0], original="same", replacement="same"),), "malformed"),
    ],
)
def test_manifest_rejects_unbounded_unsafe_or_ambiguous_entries(mutations, match):
    with pytest.raises(ValueError, match=match):
        _validate_mutation_manifest(mutations)


def test_mutation_target_must_be_present_exactly_once(tmp_path):
    target = tmp_path / "swarm/example.py"
    target.parent.mkdir()
    mutation = InvariantMutation(
        "FW-MUT-EXAMPLE", "FW-INV-001", "FW-ROOT", "swarm/example.py",
        "DENY", "ALLOW", "tests/test_example.py::test_denies",
    )
    target.write_text("UNCHANGED\n", encoding="utf-8")
    with pytest.raises(ValueError, match="exactly once"):
        _apply_invariant_mutation(tmp_path, mutation)
    target.write_text("DENY\nDENY\n", encoding="utf-8")
    with pytest.raises(ValueError, match="exactly once"):
        _apply_invariant_mutation(tmp_path, mutation)
@pytest.mark.parametrize(
    "result,match",
    [
        (_MutationProcessResult(0, b"1 passed"), "survived"),
        (_MutationProcessResult(None, b"partial", True), "timed out"),
        (_MutationProcessResult(1, b"x" * (64 * 1024 + 1)), "bounded limit"),
        (_MutationProcessResult(1, b"Bearer abcdefghijklmnopqrstuvwxyz"), "secret-bearing"),
        (_MutationProcessResult(None, b""), "return code"),
        (_MutationProcessResult(True, b""), "return code"),
    ],
)
def test_mutant_result_fails_closed_on_survival_timeout_output_or_invalid_status(result, match):
    with pytest.raises(ValueError, match=match):
        _validated_mutation_result(result)


def test_mutant_result_retains_no_raw_test_output():
    result = _validated_mutation_result(_MutationProcessResult(1, b"bounded assertion failure"))
    assert result == {"result": "KILLED", "returncode": 1, "output_retained": False}


def test_proof_rejects_non_exact_or_changed_source_commit():
    with pytest.raises(ValueError, match="invalid"):
        run_mutation_resistance_proof(ROOT, "short")
    wrong = "0" * 40 if head() != "0" * 40 else "1" * 40
    with pytest.raises(ValueError, match="current commit mismatch"):
        run_mutation_resistance_proof(ROOT, wrong)
