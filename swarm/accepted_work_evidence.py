"""Create-once, redacted evidence for accepted local dry-run work units."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .core import (
    SwarmError,
    ensure_private_directory,
    read_mailbox_json,
    redact,
    write_mailbox_json,
)


class AcceptedEvidenceError(SwarmError):
    """Raised when accepted-work evidence is malformed, unsafe, or stale."""


_JOB_ID = re.compile(r"^phase2a-[a-z0-9]{24}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_SCHEMA_VERSION = "1"
_MODE = "ACCEPTED_DRY_RUN_WORK_EVIDENCE"
_POLICY = {"mode": "DRY_RUN", "deployment": "DISABLED", "kill_switch": "ENGAGED", "mutation_allowed": False}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _string(value: object, label: str, *, max_length: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length or redact(value) != value:
        raise AcceptedEvidenceError(f"unsafe {label}")
    return value


def _commit(value: object, label: str) -> str:
    value = _string(value, label, max_length=40).lower()
    if not _SHA.fullmatch(value):
        raise AcceptedEvidenceError(f"{label} must be a full commit SHA-1")
    return value


def _review(review: Mapping[str, Any], commit: str, role: str) -> dict[str, Any]:
    if not isinstance(review, Mapping):
        raise AcceptedEvidenceError(f"{role} review is not an object")
    if set(review) == {"reviewed_commit", "verdict", "risk", "blocking_finding_count", "missing_test_count"}:
        reviewed_commit = _commit(review["reviewed_commit"], f"{role} reviewed commit")
        if reviewed_commit != commit or review["verdict"] != "APPROVE" or review["risk"] != "LOW" or review["blocking_finding_count"] != 0 or review["missing_test_count"] != 0:
            raise AcceptedEvidenceError(f"{role} review summary is not an approval for the accepted commit")
        return dict(review)
    required = ("reviewed_commit", "verdict", "risk", "blocking_findings", "tests_missing")
    if any(key not in review for key in required):
        raise AcceptedEvidenceError(f"{role} review is incomplete")
    reviewed_commit = _commit(review["reviewed_commit"], f"{role} reviewed commit")
    if reviewed_commit != commit or review["verdict"] != "APPROVE" or review["risk"] != "LOW":
        raise AcceptedEvidenceError(f"{role} review is not an approval for the accepted commit")
    for key in ("blocking_findings", "tests_missing"):
        if not isinstance(review[key], list) or review[key]:
            raise AcceptedEvidenceError(f"{role} review contains unresolved {key}")
    return {
        "reviewed_commit": reviewed_commit,
        "verdict": "APPROVE",
        "risk": "LOW",
        "blocking_finding_count": 0,
        "missing_test_count": 0,
    }


def _body(bundle: Mapping[str, Any]) -> dict[str, Any]:
    return {key: bundle[key] for key in bundle if key not in {"evidence_sha256", "event_sha256"}}


def _validate(bundle: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "schema_version", "mode", "job_id", "candidate_commit", "accepted_commit",
        "changed_files", "deterministic_validation", "claude_review", "gemini_review",
        "policy", "previous_event_sha256", "evidence_sha256", "event_sha256",
    }
    if not isinstance(bundle, Mapping) or set(bundle) != required:
        raise AcceptedEvidenceError("accepted evidence has an invalid envelope")
    if bundle["schema_version"] != _SCHEMA_VERSION or bundle["mode"] != _MODE:
        raise AcceptedEvidenceError("accepted evidence has an invalid version or mode")
    job_id = _string(bundle["job_id"], "job ID", max_length=32)
    if not _JOB_ID.fullmatch(job_id):
        raise AcceptedEvidenceError("invalid Phase 2A job ID")
    candidate = _commit(bundle["candidate_commit"], "candidate commit")
    accepted = _commit(bundle["accepted_commit"], "accepted commit")
    if candidate != accepted:
        raise AcceptedEvidenceError("candidate and accepted commits must match")
    files = bundle["changed_files"]
    if not isinstance(files, list) or not files or len(set(files)) != len(files):
        raise AcceptedEvidenceError("changed files must be a unique non-empty list")
    for path in files:
        value = _string(path, "changed file", max_length=512)
        parts = Path(value).parts
        if Path(value).is_absolute() or "\\" in value or any(part in {"", ".", ".."} for part in parts):
            raise AcceptedEvidenceError("changed files must be safe relative paths")
    validation = bundle["deterministic_validation"]
    if not isinstance(validation, list) or not validation or any(not isinstance(item, str) for item in validation):
        raise AcceptedEvidenceError("deterministic validation must be a non-empty string list")
    validation = [_string(item, "validation result") for item in validation]
    if bundle["policy"] != _POLICY:
        raise AcceptedEvidenceError("accepted evidence has an unsafe policy state")
    if bundle["previous_event_sha256"] is not None and not _HASH.fullmatch(str(bundle["previous_event_sha256"])):
        raise AcceptedEvidenceError("invalid previous event hash")
    claude = _review(bundle["claude_review"], accepted, "Claude")
    gemini = _review(bundle["gemini_review"], accepted, "Gemini")
    body = {
        "schema_version": _SCHEMA_VERSION,
        "mode": _MODE,
        "job_id": job_id,
        "candidate_commit": candidate,
        "accepted_commit": accepted,
        "changed_files": list(files),
        "deterministic_validation": validation,
        "claude_review": claude,
        "gemini_review": gemini,
        "policy": dict(_POLICY),
        "previous_event_sha256": bundle["previous_event_sha256"],
    }
    evidence_hash = hashlib.sha256(_canonical(body)).hexdigest()
    if bundle["evidence_sha256"] != evidence_hash:
        raise AcceptedEvidenceError("accepted evidence hash mismatch")
    event_payload = {**body, "evidence_sha256": evidence_hash}
    event_hash = hashlib.sha256(_canonical(event_payload)).hexdigest()
    if bundle["event_sha256"] != event_hash:
        raise AcceptedEvidenceError("accepted evidence event hash mismatch")
    return dict(bundle)


def build_accepted_evidence(
    *,
    job_id: str,
    candidate_commit: str,
    accepted_commit: str,
    changed_files: Sequence[str],
    deterministic_validation: Sequence[str],
    claude_review: Mapping[str, Any],
    gemini_review: Mapping[str, Any],
    previous_event_sha256: str | None = None,
) -> dict[str, Any]:
    """Build a strict evidence bundle without retaining provider prose or commands."""
    accepted = _commit(accepted_commit, "accepted commit")
    candidate = _commit(candidate_commit, "candidate commit")
    body: dict[str, Any] = {
        "schema_version": _SCHEMA_VERSION,
        "mode": _MODE,
        "job_id": job_id,
        "candidate_commit": candidate,
        "accepted_commit": accepted,
        "changed_files": list(changed_files),
        "deterministic_validation": list(deterministic_validation),
        "claude_review": _review(claude_review, accepted, "Claude"),
        "gemini_review": _review(gemini_review, accepted, "Gemini"),
        "policy": dict(_POLICY),
        "previous_event_sha256": previous_event_sha256,
    }
    evidence_hash = hashlib.sha256(_canonical(body)).hexdigest()
    event_hash = hashlib.sha256(_canonical({**body, "evidence_sha256": evidence_hash})).hexdigest()
    return _validate({**body, "evidence_sha256": evidence_hash, "event_sha256": event_hash})


def write_accepted_evidence(path: Path, bundle: Mapping[str, Any]) -> None:
    """Create one private evidence record; an existing record is never replaced."""
    validated = _validate(bundle)
    path = Path(path)
    ensure_private_directory(path.parent, "accepted evidence directory")
    try:
        write_mailbox_json(path, validated, "accepted work evidence")
    except SwarmError as exc:
        raise AcceptedEvidenceError(str(exc)) from exc


def read_accepted_evidence(path: Path) -> dict[str, Any]:
    """Read and revalidate one immutable accepted-work evidence record."""
    try:
        return _validate(read_mailbox_json(Path(path), "accepted work evidence"))
    except SwarmError as exc:
        raise AcceptedEvidenceError(str(exc)) from exc
