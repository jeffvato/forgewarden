"""Atomic, evidence-only work-unit checkpoints for the local supervisor."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping


_SHA1 = re.compile(r"[0-9a-fA-F]{40}")
_TASK_ID = re.compile(r"FWQ-[0-9]{4}")
_VERSION = 1
MAX_CHECKPOINT_BYTES = 1_048_576


class CheckpointError(ValueError):
    """Raised for invalid, corrupted, stale, or unsafe checkpoint evidence."""


@dataclass(frozen=True)
class WorkUnitCheckpoint:
    active_phase: str
    task_id: str
    starting_commit: str
    candidate_commit: str | None
    accepted_commit: str | None
    changed_files: tuple[str, ...]
    deterministic_validation: tuple[str, ...]
    claude_review: str
    gemini_review: str
    unresolved_findings: tuple[str, ...]
    blocker: str | None
    next_action: str


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _validate(checkpoint: WorkUnitCheckpoint) -> None:
    if not checkpoint.active_phase or not _TASK_ID.fullmatch(checkpoint.task_id):
        raise CheckpointError("checkpoint requires an active phase and FWQ task ID")
    for field, value in (("starting", checkpoint.starting_commit), ("candidate", checkpoint.candidate_commit), ("accepted", checkpoint.accepted_commit)):
        if value is not None and not _SHA1.fullmatch(value):
            raise CheckpointError(f"{field} commit must be a full Git SHA-1 or null")
    if checkpoint.accepted_commit is not None and checkpoint.candidate_commit != checkpoint.accepted_commit:
        raise CheckpointError("accepted commit must equal candidate commit")
    if any(not item or Path(item).is_absolute() or ".." in Path(item).parts for item in checkpoint.changed_files):
        raise CheckpointError("changed files must be non-empty relative paths without traversal")
    if any(not item for item in checkpoint.deterministic_validation) or not checkpoint.claude_review or not checkpoint.gemini_review or not checkpoint.next_action:
        raise CheckpointError("checkpoint evidence fields must be non-empty")
    if any(not item for item in checkpoint.unresolved_findings):
        raise CheckpointError("unresolved findings must be non-empty strings")


def _safe_parent(path: Path) -> None:
    if not path.is_absolute() or not path.parent.is_dir():
        raise CheckpointError("checkpoint path must be under an existing absolute directory")
    current = Path(path.anchor)
    for part in path.parent.parts[1:]:
        current /= part
        if current.is_symlink():
            raise CheckpointError(f"checkpoint path contains symlink: {current}")


def _payload(checkpoint: WorkUnitCheckpoint) -> dict[str, object]:
    return {"version": _VERSION, "checkpoint": asdict(checkpoint)}


def write_checkpoint(path: Path, checkpoint: WorkUnitCheckpoint) -> None:
    """Durably replace one checkpoint; incomplete writes are never valid JSON evidence."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise CheckpointError("safe checkpoint write primitive unavailable")
    _validate(checkpoint)
    path = Path(path)
    _safe_parent(path)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise CheckpointError(f"unsafe checkpoint target: {path}")
    payload = _payload(checkpoint)
    envelope = {**payload, "sha256": hashlib.sha256(_canonical(payload)).hexdigest()}
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_canonical(envelope))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def load_checkpoint(path: Path) -> WorkUnitCheckpoint:
    """Load a complete checkpoint envelope and verify its integrity before use."""
    path = Path(path)
    _safe_parent(path)
    if not hasattr(os, "O_NOFOLLOW") or path.is_symlink() or not path.is_file():
        raise CheckpointError(f"checkpoint is missing or unsafe: {path}")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_CHECKPOINT_BYTES:
                raise CheckpointError("checkpoint is missing or unsafe")
            raw = os.read(descriptor, MAX_CHECKPOINT_BYTES + 1)
            if len(raw) > MAX_CHECKPOINT_BYTES:
                raise CheckpointError("checkpoint is corrupt or incomplete")
        finally:
            os.close(descriptor)
        envelope = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CheckpointError("checkpoint is corrupt or incomplete") from exc
    if not isinstance(envelope, dict) or set(envelope) != {"version", "checkpoint", "sha256"} or envelope["version"] != _VERSION:
        raise CheckpointError("checkpoint has invalid envelope")
    payload = {"version": envelope["version"], "checkpoint": envelope["checkpoint"]}
    if not isinstance(envelope["sha256"], str) or envelope["sha256"] != hashlib.sha256(_canonical(payload)).hexdigest():
        raise CheckpointError("checkpoint integrity hash mismatch")
    try:
        checkpoint_data = envelope["checkpoint"]
        if not isinstance(checkpoint_data, dict):
            raise TypeError
        checkpoint = WorkUnitCheckpoint(
            active_phase=checkpoint_data["active_phase"], task_id=checkpoint_data["task_id"], starting_commit=checkpoint_data["starting_commit"],
            candidate_commit=checkpoint_data["candidate_commit"], accepted_commit=checkpoint_data["accepted_commit"],
            changed_files=tuple(checkpoint_data["changed_files"]), deterministic_validation=tuple(checkpoint_data["deterministic_validation"]),
            claude_review=checkpoint_data["claude_review"], gemini_review=checkpoint_data["gemini_review"],
            unresolved_findings=tuple(checkpoint_data["unresolved_findings"]), blocker=checkpoint_data["blocker"], next_action=checkpoint_data["next_action"],
        )
    except (KeyError, TypeError) as exc:
        raise CheckpointError("checkpoint has invalid schema") from exc
    _validate(checkpoint)
    return checkpoint


def reconcile_checkpoint(checkpoint: WorkUnitCheckpoint, repository_head: str) -> Mapping[str, str]:
    """Reconcile checkpoint claims with deterministic, caller-provided Git evidence."""
    _validate(checkpoint)
    if not _SHA1.fullmatch(repository_head):
        raise CheckpointError("repository head must be a full Git SHA-1")
    expected = checkpoint.candidate_commit or checkpoint.starting_commit
    if repository_head.lower() != expected.lower():
        raise CheckpointError(f"checkpoint commit mismatch: expected {expected}, got {repository_head}")
    return MappingProxyType({"task_id": checkpoint.task_id, "repository_head": repository_head, "expected_commit": expected})
