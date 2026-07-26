"""Independent, one-time approval records for review evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any


def _safe_path(path: Path) -> Path:
    path = path.expanduser()
    if path.is_symlink() or any(parent.is_symlink() for parent in (path.parent, *path.parent.parents)):
        raise ValueError(f"refusing symlink approval path: {path}")
    return path


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    path = _safe_path(path)
    raw = path.read_bytes()
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError(f"approval input must be a JSON object: {path}")
    return payload, raw


def create_approval_record(
    evidence_path: Path,
    output_path: Path,
    *,
    job_id: str,
    reviewer: str,
    decision: str,
    ttl_seconds: int = 3600,
) -> dict[str, Any]:
    if not job_id.strip() or not reviewer.strip():
        raise ValueError("approval requires a job ID and reviewer")
    if decision not in {"APPROVED", "REJECTED"}:
        raise ValueError("approval decision must be APPROVED or REJECTED")
    if ttl_seconds <= 0 or ttl_seconds > 86400:
        raise ValueError("approval TTL must be between 1 and 86400 seconds")
    evidence_path = _safe_path(evidence_path)
    output_path = _safe_path(output_path)
    raw = evidence_path.read_bytes()
    now = int(time.time())
    record = {
        "schema_version": "1",
        "mode": "INDEPENDENT_APPROVAL",
        "approval_id": uuid.uuid4().hex,
        "job_id": job_id,
        "reviewer": reviewer,
        "decision": decision,
        "evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "issued_at": now,
        "expires_at": now + ttl_seconds,
        "one_time": True,
        "consumed": False,
        "mutation_allowed": False,
        "deployment": "DISABLED",
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.chmod(0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(output_path, flags, 0o600)
    except FileExistsError as exc:
        raise ValueError(f"approval output already exists: {output_path}") from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    output_path.chmod(0o600)
    return record


def verify_approval(
    approval_path: Path,
    evidence_path: Path,
    *,
    expected_job_id: str,
    consume: bool = False,
) -> dict[str, Any]:
    approval_path = _safe_path(approval_path)
    if approval_path.stat().st_mode & 0o777 != 0o600:
        raise ValueError("approval record must be mode 0600")
    if approval_path.parent.stat().st_mode & 0o777 != 0o700:
        raise ValueError("approval directory must be mode 0700")
    record, _ = _read_json(approval_path)
    evidence = _safe_path(evidence_path).read_bytes()
    required = {"schema_version", "mode", "approval_id", "job_id", "reviewer", "decision", "evidence_sha256", "issued_at", "expires_at", "one_time", "consumed", "mutation_allowed", "deployment"}
    if not required.issubset(record):
        raise ValueError("approval record is incomplete")
    if record["schema_version"] != "1" or record["mode"] != "INDEPENDENT_APPROVAL":
        raise ValueError("unsupported approval record")
    if record["job_id"] != expected_job_id:
        raise ValueError("approval job ID mismatch")
    if record["decision"] != "APPROVED":
        raise ValueError("approval decision is not APPROVED")
    if record["mutation_allowed"] is not False or record["deployment"] != "DISABLED":
        raise ValueError("approval record is not non-authorizing")
    if hashlib.sha256(evidence).hexdigest() != record["evidence_sha256"]:
        raise ValueError("approval evidence hash mismatch")
    if int(time.time()) >= int(record["expires_at"]):
        raise ValueError("approval record has expired")
    marker = approval_path.parent / f".{record['approval_id']}.consumed"
    consumed = marker.exists()
    if consumed or record.get("consumed") is True:
        raise ValueError("approval record has already been consumed")
    if consume:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(marker, flags, 0o600)
        except FileExistsError as exc:
            raise ValueError("approval record replay detected") from exc
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(str(int(time.time())) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        marker.chmod(0o600)
        consumed = True
    return {
        "schema_version": "1",
        "mode": "APPROVAL_VERIFICATION",
        "approval_id": record["approval_id"],
        "job_id": expected_job_id,
        "evidence_sha256": record["evidence_sha256"],
        "decision": record["decision"],
        "verified": True,
        "consumed": consumed,
        "replay_protected": True,
        "mutation_allowed": False,
        "deployment": "DISABLED",
    }


def reconcile_approval(
    approval_path: Path,
    evidence_path: Path,
    audit_path: Path,
    *,
    expected_job_id: str,
) -> dict[str, Any]:
    """Reconcile a consumed approval with its durable application audit event."""
    approval_path = _safe_path(approval_path)
    audit_path = _safe_path(audit_path)
    if approval_path.stat().st_mode & 0o777 != 0o600 or approval_path.parent.stat().st_mode & 0o777 != 0o700:
        raise ValueError("approval record permissions are not restricted")
    if not audit_path.is_file() or audit_path.stat().st_mode & 0o777 != 0o600 or audit_path.parent.stat().st_mode & 0o777 != 0o700:
        raise ValueError("audit permissions are not restricted")
    record, _ = _read_json(approval_path)
    evidence_hash = hashlib.sha256(_safe_path(evidence_path).read_bytes()).hexdigest()
    if record.get("job_id") != expected_job_id or record.get("decision") != "APPROVED":
        raise ValueError("approval cannot be reconciled for this job")
    if record.get("evidence_sha256") != evidence_hash:
        raise ValueError("approval evidence hash mismatch")
    marker = approval_path.parent / f".{record.get('approval_id')}.consumed"
    if not marker.is_file():
        raise ValueError("approval has not been consumed")
    matching: list[dict[str, Any]] = []
    for line in audit_path.read_bytes().splitlines():
        try:
            event = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if (
            isinstance(event, dict)
            and event.get("event") == "safe_application_completed"
            and event.get("job_id") == expected_job_id
            and event.get("approval_id") == record.get("approval_id")
            and event.get("approval_evidence_sha256") == evidence_hash
        ):
            matching.append(event)
    if not matching:
        raise ValueError("no matching SAFE application audit event")
    return {
        "schema_version": "1",
        "mode": "APPROVAL_AUDIT_RECONCILIATION",
        "approval_id": record["approval_id"],
        "job_id": expected_job_id,
        "evidence_sha256": evidence_hash,
        "audit_state": matching[-1].get("state"),
        "reconciled": True,
        "replay_protected": True,
        "mutation_allowed": False,
        "deployment": "DISABLED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create or verify one-time non-authorizing review approvals")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--evidence", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--job-id", required=True)
    create.add_argument("--reviewer", required=True)
    create.add_argument("--decision", choices=["APPROVED", "REJECTED"], required=True)
    create.add_argument("--ttl-seconds", type=int, default=3600)
    verify = sub.add_parser("verify")
    verify.add_argument("--approval", type=Path, required=True)
    verify.add_argument("--evidence", type=Path, required=True)
    verify.add_argument("--job-id", required=True)
    verify.add_argument("--consume", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            result = create_approval_record(args.evidence, args.output, job_id=args.job_id, reviewer=args.reviewer, decision=args.decision, ttl_seconds=args.ttl_seconds)
        else:
            result = verify_approval(args.approval, args.evidence, expected_job_id=args.job_id, consume=args.consume)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
