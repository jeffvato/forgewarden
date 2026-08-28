from __future__ import annotations

import json

import pytest
import swarm.work_checkpoint as checkpoint_module

from swarm.work_checkpoint import CheckpointError, MAX_CHECKPOINT_BYTES, WorkUnitCheckpoint, load_checkpoint, reconcile_checkpoint, write_checkpoint


SHA_A = "a" * 40
SHA_B = "b" * 40


def _checkpoint(**changes) -> WorkUnitCheckpoint:
    values = dict(active_phase="ForgeWarden Core", task_id="FWQ-0003", starting_commit=SHA_A, candidate_commit=None, accepted_commit=None, changed_files=("swarm/work_checkpoint.py",), deterministic_validation=("pytest",), claude_review="APPROVED", gemini_review="APPROVED", unresolved_findings=(), blocker=None, next_action="continue safely")
    values.update(changes)
    return WorkUnitCheckpoint(**values)


def test_atomic_checkpoint_round_trip_and_reconciliation(tmp_path):
    path = tmp_path / "checkpoint.json"
    checkpoint = _checkpoint(candidate_commit=SHA_B, accepted_commit=SHA_B)
    write_checkpoint(path, checkpoint)

    assert load_checkpoint(path) == checkpoint
    assert reconcile_checkpoint(checkpoint, SHA_B)["task_id"] == "FWQ-0003"


def test_corruption_and_interrupted_write_are_not_accepted(tmp_path):
    path = tmp_path / "checkpoint.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(CheckpointError, match="corrupt or incomplete"):
        load_checkpoint(path)

    write_checkpoint(path, _checkpoint())
    data = json.loads(path.read_text(encoding="utf-8"))
    data["checkpoint"]["task_id"] = "FWQ-9999"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(CheckpointError, match="integrity hash mismatch"):
        load_checkpoint(path)


def test_stale_commit_and_invalid_transitions_fail_closed(tmp_path):
    checkpoint = _checkpoint(candidate_commit=SHA_B)
    with pytest.raises(CheckpointError, match="not accepted"):
        reconcile_checkpoint(checkpoint, SHA_A)
    with pytest.raises(CheckpointError, match="accepted commit must equal"):
        write_checkpoint(tmp_path / "checkpoint.json", _checkpoint(candidate_commit=SHA_A, accepted_commit=SHA_B))
    with pytest.raises(CheckpointError, match="without traversal"):
        write_checkpoint(tmp_path / "checkpoint.json", _checkpoint(changed_files=("../escape",)))


def test_candidate_only_checkpoint_cannot_reconcile_as_accepted():
    checkpoint = _checkpoint(candidate_commit=SHA_B)
    with pytest.raises(CheckpointError, match="not accepted"):
        reconcile_checkpoint(checkpoint, SHA_B)


def test_stale_review_labels_cannot_make_an_accepted_checkpoint_valid():
    checkpoint = _checkpoint(candidate_commit=SHA_B, accepted_commit=SHA_B, claude_review="not started")
    with pytest.raises(CheckpointError, match="stale or mismatched"):
        reconcile_checkpoint(checkpoint, SHA_B)


def test_unresolved_findings_cannot_make_an_accepted_checkpoint_valid():
    checkpoint = _checkpoint(candidate_commit=SHA_B, accepted_commit=SHA_B, unresolved_findings=("finding",))
    with pytest.raises(CheckpointError, match="stale or mismatched"):
        reconcile_checkpoint(checkpoint, SHA_B)


def test_findings_review_requires_finding_evidence():
    checkpoint = _checkpoint(candidate_commit=SHA_B, accepted_commit=SHA_B, claude_review="FINDINGS")
    with pytest.raises(CheckpointError, match="stale or mismatched"):
        reconcile_checkpoint(checkpoint, SHA_B)


def test_no_change_accepted_checkpoint_reconciles_at_current_head():
    checkpoint = _checkpoint(
        candidate_commit=SHA_A,
        accepted_commit=SHA_A,
        changed_files=(),
        deterministic_validation=("pytest",),
    )
    assert reconcile_checkpoint(checkpoint, SHA_A)["expected_commit"] == SHA_A


@pytest.mark.parametrize(
    "changes",
    (
        {"starting_commit": SHA_A, "accepted_commit": SHA_A, "changed_files": ("swarm/work_checkpoint.py",)},
        {"starting_commit": SHA_A, "accepted_commit": SHA_B, "changed_files": ()},
    ),
)
def test_commit_references_must_match_changed_files(changes):
    checkpoint = _checkpoint(candidate_commit=changes["accepted_commit"], **changes)
    with pytest.raises(CheckpointError, match="commit references do not match changed files"):
        reconcile_checkpoint(checkpoint, changes["accepted_commit"])


def test_duplicate_changed_file_evidence_fails_closed():
    checkpoint = _checkpoint(
        candidate_commit=SHA_B,
        accepted_commit=SHA_B,
        changed_files=("swarm/work_checkpoint.py", "swarm/work_checkpoint.py"),
    )
    with pytest.raises(CheckpointError, match="changed files"):
        reconcile_checkpoint(checkpoint, SHA_B)


def test_unsafe_checkpoint_path_and_schema_fail_closed(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("x", encoding="utf-8")
    link = tmp_path / "checkpoint.json"
    link.symlink_to(target)
    with pytest.raises(CheckpointError, match="unsafe checkpoint target"):
        write_checkpoint(link, _checkpoint())
def test_oversized_and_symlink_replacement_loads_fail_closed(tmp_path):
    path=tmp_path/"checkpoint.json"; path.write_bytes(b"x"*(MAX_CHECKPOINT_BYTES+1))
    with pytest.raises(CheckpointError): load_checkpoint(path)
    target=tmp_path/"target"; target.write_text("{}",encoding="utf-8"); path.unlink(); path.symlink_to(target)
    with pytest.raises(CheckpointError): load_checkpoint(path)
def test_symlinked_parent_checkpoint_path_fails_closed(tmp_path):
    real=tmp_path/"real"; real.mkdir(); linked=tmp_path/"linked"; linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(CheckpointError, match="symlink"):
        write_checkpoint(linked/"checkpoint.json", _checkpoint())
def test_write_requires_no_follow_primitive(tmp_path, monkeypatch):
    monkeypatch.delattr(checkpoint_module.os, "O_NOFOLLOW", raising=False)
    with pytest.raises(CheckpointError, match="primitive"):
        write_checkpoint(tmp_path/"checkpoint.json", _checkpoint())
