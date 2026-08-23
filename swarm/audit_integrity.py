"""Read-only validation for the local audit evidence stream."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import re
from pathlib import Path
from typing import Any

from .core import redact


class AuditIntegrityError(ValueError):
    """Raised when audit evidence is malformed, unsafe, or inconsistent."""


VALID_STATES = frozenset({
    "RECEIVED", "CLASSIFIED", "WORKTREE_READY", "QUEUED", "RUNNING",
    "CODEX_RUNNING", "CHECKS_RUNNING", "GEMINI_REVIEWING", "CLAUDE_REVIEWING",
    "REVISION_REQUIRED", "READY_TO_DEPLOY", "AWAITING_JEFF", "DEPLOYING",
    "VERIFYING_PRODUCTION", "SUCCEEDED", "ROLLED_BACK", "FAILED", "CANCELLED",
    "ABANDONED", "RECOVERED_ABANDONED",
})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SENSITIVE_KEY = re.compile(
    r"(?i)(credential|secret|token|password|authorization|customer|order|distributor|"
    r"email|phone|address|card|cookie|session|payload|prompt|output|reasoning|summary|root[_-]?cause|key)"
)

MAX_BYTES = 4 * 1024 * 1024
MAX_LINES = 4096
MAX_LINE_BYTES = 64 * 1024
MAX_KEYS = 64
MAX_DEPTH = 5
TERMINAL_STATES = frozenset({"SUCCEEDED", "FAILED", "CANCELLED", "ABANDONED", "RECOVERED_ABANDONED", "ROLLED_BACK"})


def _reject_symlinks(path: Path, root: Path | None) -> None:
    path = path.absolute()
    if root is None:
        from .paths import audit_root
        root = audit_root()
    root = root.absolute()
    if root.is_symlink():
        raise AuditIntegrityError("configured audit root is a symlink")
    current = path
    while current != current.parent:
        if current.is_symlink():
            raise AuditIntegrityError("symlinks are not allowed in audit paths")
        current = current.parent
    resolved_root = root.resolve(strict=False)
    resolved_path = path.resolve(strict=False)
    if resolved_path == resolved_root or resolved_root not in resolved_path.parents:
        raise AuditIntegrityError("audit path is outside the configured audit root")


def _safe_value(value: Any, key: str, depth: int = 0) -> Any:
    if _SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if depth > MAX_DEPTH:
        raise AuditIntegrityError("audit value nesting exceeds limit")
    if isinstance(value, dict):
        if len(value) > MAX_KEYS:
            raise AuditIntegrityError("audit object has too many fields")
        return {str(k): _safe_value(v, str(k), depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        if len(value) > MAX_KEYS:
            raise AuditIntegrityError("audit list has too many entries")
        return [_safe_value(v, key, depth + 1) for v in value]
    if isinstance(value, str):
        return redact(value)[:512]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise AuditIntegrityError("audit contains an unsupported value")


def _validate_record(record: Any, expected_job_id: str | None) -> dict[str, Any]:
    if not isinstance(record, dict) or len(record) > MAX_KEYS:
        raise AuditIntegrityError("audit record must be a bounded object")
    required = {"timestamp", "job_id", "state", "event"}
    if not required.issubset(record):
        raise AuditIntegrityError("audit record is missing required fields")
    timestamp, job_id, state, event = (record[k] for k in ("timestamp", "job_id", "state", "event"))
    if not isinstance(timestamp, str) or not _TIMESTAMP.fullmatch(timestamp):
        raise AuditIntegrityError("invalid audit timestamp")
    if not isinstance(job_id, str) or not _IDENTIFIER.fullmatch(job_id):
        raise AuditIntegrityError("invalid audit job id")
    if expected_job_id is not None and job_id != expected_job_id:
        raise AuditIntegrityError("audit job id does not match the requested job")
    if not isinstance(state, str) or state not in VALID_STATES:
        raise AuditIntegrityError("invalid audit state")
    if not isinstance(event, str) or not _IDENTIFIER.fullmatch(event):
        raise AuditIntegrityError("invalid audit event")
    for key in ("previous_event_sha256", "event_sha256"):
        if key in record and (not isinstance(record[key], str) or not _SHA256.fullmatch(record[key])):
            raise AuditIntegrityError("invalid audit hash link")
    # A sensitive field may only be represented by the writer's redaction marker.
    for key, value in record.items():
        if _SENSITIVE_KEY.search(str(key)) and value != "[REDACTED]":
            raise AuditIntegrityError("unredacted sensitive audit field")
    return record


def _event_hash(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "event_sha256"}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def read_audit_events(path: Path, *, expected_job_id: str | None = None, audit_root: Path | None = None) -> tuple[dict[str, Any], ...]:
    """Validate and return redacted audit summaries without modifying the source."""
    path = Path(path)
    _reject_symlinks(path, audit_root)
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise AuditIntegrityError("audit path is not a regular file")
        if metadata.st_size > MAX_BYTES:
            raise AuditIntegrityError("audit file exceeds size limit")
        raw = os.read(fd, MAX_BYTES + 1)
    except OSError as exc:
        if getattr(exc, "errno", None) == 2:
            return ()
        raise AuditIntegrityError("audit file cannot be read") from exc
    finally:
        if fd is not None:
            os.close(fd)
    if len(raw) > MAX_BYTES or (raw and not raw.endswith(b"\n")):
        raise AuditIntegrityError("audit file is truncated")
    lines = raw.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    if len(lines) > MAX_LINES:
        raise AuditIntegrityError("audit file has too many records")
    records: list[dict[str, Any]] = []
    chain_mode: bool | None = None
    previous_hash: str | None = None
    terminal_signatures: set[tuple[str, str, str]] = set()
    for line in lines:
        if not line or len(line) > MAX_LINE_BYTES:
            raise AuditIntegrityError("audit contains an empty or oversized line")
        try:
            record = _validate_record(json.loads(line.decode("utf-8")), expected_job_id)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuditIntegrityError("audit contains malformed JSON") from exc
        has_hash = "event_sha256" in record or "previous_event_sha256" in record
        if chain_mode is None:
            chain_mode = has_hash
        elif has_hash != chain_mode:
            raise AuditIntegrityError("audit hash chain is incomplete")
        if chain_mode:
            if "event_sha256" not in record or "previous_event_sha256" not in record:
                raise AuditIntegrityError("audit hash chain is incomplete")
            if records and record.get("previous_event_sha256") != previous_hash:
                raise AuditIntegrityError("audit hash chain is broken")
            if not records and record.get("previous_event_sha256") not in (None, ""):
                raise AuditIntegrityError("audit hash chain has an invalid first link")
            if record.get("event_sha256") != _event_hash(record):
                raise AuditIntegrityError("audit event hash does not match content")
            previous_hash = record["event_sha256"]
        elif chain_mode:
            raise AuditIntegrityError("audit hash chain is incomplete")
        signature = (record["job_id"], record["state"], record["event"])
        if record["state"] in TERMINAL_STATES:
            if signature in terminal_signatures:
                raise AuditIntegrityError("duplicate terminal audit event")
            terminal_signatures.add(signature)
        records.append(record)
    return tuple(_safe_value(record, "") for record in records)
