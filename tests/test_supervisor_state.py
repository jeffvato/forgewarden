from __future__ import annotations

import os
from pathlib import Path

import pytest

from swarm.supervisor_state import (
    CONTROL_FILE_REQUIREMENTS,
    MAX_CONTROL_FILE_BYTES,
    ControlStateError,
    load_supervisor_state,
)


SHA_A = "a" * 40
SHA_B = "b" * 40


def _write_control_files(
    root: Path,
    *,
    task_id: str = "none",
    starting: str = "none",
    candidate: str = "none",
    accepted: str = "none",
) -> None:
    contents = {
        name: "\n".join(headings) + "\n"
        for name, headings in CONTROL_FILE_REQUIREMENTS.items()
        if name != "SWARM_STATUS.md"
    }
    contents["AGENTS.md"] += "`DRY_RUN` remains enforced\nDeployment remains disabled\n"
    contents["SWARM_STATUS.md"] = "\n".join(CONTROL_FILE_REQUIREMENTS["SWARM_STATUS.md"][:4]) + "\n" + "\n".join(
        (
            "- Repository safety mode: DRY_RUN",
            "- Deployment: disabled",
            "- Task ID: " + task_id,
            "- Starting commit: " + starting,
            "- Candidate commit: " + candidate,
            "- Accepted commit: " + accepted,
            "- Files changed: none",
            "- Deterministic validation: not started",
            "- Claude review: not started",
            "- Gemini review: not started",
            "- Unresolved findings: none",
            "- Blocker: none",
            "- Next action: continue safely",
        )
    ) + "\n" + CONTROL_FILE_REQUIREMENTS["SWARM_STATUS.md"][4] + "\n"
    contents["WORK_QUEUE.md"] += "\n".join(
        (
            "### FWQ-0001 — Fixture task",
            "- Requirement: Core supervisor",
            "- State: READY",
            "- Priority: P0",
            "- Dependencies: none",
            "- Description: deterministic fixture",
            "",
        )
    )
    for name, content in contents.items():
        (root / name).write_text(content, encoding="utf-8")


def test_loads_fixed_control_files_read_only_and_records_hashes(tmp_path):
    _write_control_files(tmp_path)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    state = load_supervisor_state(tmp_path)

    assert tuple(state.files) == tuple(CONTROL_FILE_REQUIREMENTS)
    assert state.repository_root == tmp_path
    assert state.resume.interrupted is False
    assert all(len(control_file.sha256) == 64 for control_file in state.files.values())
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before
    with pytest.raises(TypeError):
        state.files["unexpected.md"] = state.files["AGENTS.md"]


def test_missing_required_file_fails_with_explicit_diagnostic(tmp_path):
    _write_control_files(tmp_path)
    (tmp_path / "DECISIONS.md").unlink()

    with pytest.raises(ControlStateError, match="missing required control file: DECISIONS.md"):
        load_supervisor_state(tmp_path)


def test_malformed_document_structure_fails_closed(tmp_path):
    _write_control_files(tmp_path)
    path = tmp_path / "ROADMAP.md"
    path.write_text(path.read_text(encoding="utf-8").replace("## Core trust model\n", ""), encoding="utf-8")

    with pytest.raises(ControlStateError, match="required heading must appear exactly once"):
        load_supervisor_state(tmp_path)


def test_malformed_work_queue_task_fails_closed(tmp_path):
    _write_control_files(tmp_path)
    path = tmp_path / "WORK_QUEUE.md"
    path.write_text(path.read_text(encoding="utf-8").replace("- Priority: P0\n", ""), encoding="utf-8")

    with pytest.raises(ControlStateError, match="FWQ-0001: missing field.*Priority"):
        load_supervisor_state(tmp_path)


def test_malformed_checkpoint_fails_with_explicit_diagnostic(tmp_path):
    _write_control_files(tmp_path)
    status = tmp_path / "SWARM_STATUS.md"
    status.write_text(status.read_text(encoding="utf-8").replace("- Next action: continue safely\n", ""), encoding="utf-8")

    with pytest.raises(ControlStateError, match="missing field.*Next action"):
        load_supervisor_state(tmp_path)


def test_duplicate_checkpoint_field_fails_closed(tmp_path):
    _write_control_files(tmp_path)
    status = tmp_path / "SWARM_STATUS.md"
    status.write_text(status.read_text(encoding="utf-8").replace("- Next action: continue safely", "- Task ID: FWQ-0001\n- Next action: continue safely"), encoding="utf-8")

    with pytest.raises(ControlStateError, match="duplicate field: Task ID"):
        load_supervisor_state(tmp_path)


@pytest.mark.parametrize("value", ["short", "g" * 40, "a" * 64])
def test_task_commits_must_be_full_sha1_hashes(tmp_path, value):
    _write_control_files(tmp_path, task_id="FWQ-0001", starting=value)

    with pytest.raises(ControlStateError, match="Starting commit must be none or a full Git SHA-1"):
        load_supervisor_state(tmp_path)


def test_taskless_checkpoint_cannot_contain_any_task_specific_commit(tmp_path):
    _write_control_files(tmp_path, starting=SHA_A)

    with pytest.raises(ControlStateError, match="taskless checkpoints cannot contain task-specific commits"):
        load_supervisor_state(tmp_path)


def test_active_checkpoint_requires_starting_commit(tmp_path):
    _write_control_files(tmp_path, task_id="FWQ-0001")

    with pytest.raises(ControlStateError, match="active tasks require a starting commit"):
        load_supervisor_state(tmp_path)


def test_accepted_checkpoint_requires_matching_candidate_commit(tmp_path):
    _write_control_files(tmp_path, task_id="FWQ-0001", starting=SHA_A, accepted=SHA_A)

    with pytest.raises(ControlStateError, match="accepted commits require a candidate commit"):
        load_supervisor_state(tmp_path)

    _write_control_files(tmp_path, task_id="FWQ-0001", starting=SHA_A, candidate=SHA_A, accepted=SHA_B)
    with pytest.raises(ControlStateError, match="accepted commit must equal candidate commit"):
        load_supervisor_state(tmp_path)


def test_restart_of_unaccepted_valid_task_is_classified_as_interrupted(tmp_path):
    _write_control_files(tmp_path, task_id="FWQ-0001", starting=SHA_A, candidate=SHA_B)

    state = load_supervisor_state(tmp_path)

    assert state.resume.interrupted is True
    assert state.resume.checkpoint["Task ID"] == "FWQ-0001"


def test_accepted_valid_task_is_not_classified_as_interrupted(tmp_path):
    _write_control_files(tmp_path, task_id="FWQ-0001", starting=SHA_A, candidate=SHA_B, accepted=SHA_B)

    assert load_supervisor_state(tmp_path).resume.interrupted is False


def test_leaf_symlink_is_rejected(tmp_path):
    _write_control_files(tmp_path)
    path = tmp_path / "AGENTS.md"
    replacement = tmp_path / "replacement.md"
    replacement.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(replacement)

    with pytest.raises(ControlStateError, match="unable to read control file safely: AGENTS.md"):
        load_supervisor_state(tmp_path)


def test_parent_symlink_in_repository_root_is_rejected(tmp_path):
    parent = tmp_path / "real-parent"
    root = parent / "repository"
    root.mkdir(parents=True)
    _write_control_files(root)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(parent, target_is_directory=True)

    with pytest.raises(ControlStateError, match="repository root path contains symlink"):
        load_supervisor_state(linked_parent / "repository")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO fixtures require POSIX")
def test_special_file_is_rejected_without_blocking(tmp_path):
    _write_control_files(tmp_path)
    path = tmp_path / "AGENTS.md"
    path.unlink()
    os.mkfifo(path)

    with pytest.raises(ControlStateError, match="control file must be a regular file: AGENTS.md"):
        load_supervisor_state(tmp_path)


def test_invalid_utf8_is_rejected(tmp_path):
    _write_control_files(tmp_path)
    (tmp_path / "AGENTS.md").write_bytes(b"\xff\xfe")

    with pytest.raises(ControlStateError, match="control file is not valid UTF-8: AGENTS.md"):
        load_supervisor_state(tmp_path)


def test_oversized_input_is_rejected(tmp_path):
    _write_control_files(tmp_path)
    (tmp_path / "AGENTS.md").write_bytes(b"x" * (MAX_CONTROL_FILE_BYTES + 1))

    with pytest.raises(ControlStateError, match="control file exceeds"):
        load_supervisor_state(tmp_path)
