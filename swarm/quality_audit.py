"""Read-only consumer for SAFE application audit evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FINDING_ID_RE = re.compile(r"^[0-9a-f]{16}$")


def _valid_completion_event(event: dict[str, Any]) -> bool:
    required = {
        "job_id", "event", "state", "repository", "applied_finding_ids", "changed_files",
        "verification_passed", "verification_exit_code", "rollback_performed", "before_sha256", "after_sha256",
    }
    if not required.issubset(event):
        return False
    if event["event"] != "safe_application_completed" or not isinstance(event["job_id"], str):
        return False
    state = event["state"]
    if state not in {"APPLIED_VERIFIED", "ROLLED_BACK_VERIFICATION_FAILED"}:
        return False
    if not isinstance(event["applied_finding_ids"], list) or not all(
        isinstance(item, str) and _FINDING_ID_RE.fullmatch(item) for item in event["applied_finding_ids"]
    ):
        return False
    if not isinstance(event["changed_files"], list) or not all(isinstance(item, str) and not item.startswith("/") for item in event["changed_files"]):
        return False
    if not isinstance(event["before_sha256"], dict) or not isinstance(event["after_sha256"], dict):
        return False
    if not all(isinstance(key, str) and isinstance(value, str) and _SHA256_RE.fullmatch(value) for key, value in event["before_sha256"].items()):
        return False
    if not all(isinstance(key, str) and isinstance(value, str) and _SHA256_RE.fullmatch(value) for key, value in event["after_sha256"].items()):
        return False
    if not isinstance(event["verification_passed"], bool) or not isinstance(event["rollback_performed"], bool):
        return False
    if state == "APPLIED_VERIFIED":
        return event["verification_passed"] is True and event["rollback_performed"] is False
    return event["verification_passed"] is False and event["rollback_performed"] is True


def _safe_path(path: Path) -> Path:
    path = path.expanduser()
    if path.is_symlink() or any(parent.is_symlink() for parent in (path.parent, *path.parent.parents)):
        raise ValueError(f"refusing symlink audit path: {path}")
    return path


def review_audit(audit_path: Path, job_id: str) -> dict[str, Any]:
    """Summarize one application audit without exposing its event contents."""
    if not job_id.strip():
        raise ValueError("audit review requires a non-empty job ID")
    path = _safe_path(audit_path)
    if not path.is_file():
        raise ValueError(f"audit file does not exist: {path}")
    if path.stat().st_mode & 0o777 != 0o600:
        raise ValueError("audit file must be mode 0600")
    if path.parent.stat().st_mode & 0o777 != 0o700:
        raise ValueError("audit directory must be mode 0700")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    events_seen = 0
    matching: list[tuple[dict[str, Any], bytes]] = []
    malformed = 0
    for line in raw.splitlines():
        if not line.strip():
            continue
        events_seen += 1
        try:
            event = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            malformed += 1
            continue
        if not isinstance(event, dict) or event.get("job_id") != job_id:
            continue
        if event.get("event") == "safe_application_completed" and event.get("job_id") == job_id:
            if _valid_completion_event(event):
                matching.append((event, line))
            else:
                malformed += 1
    latest_pair = matching[-1] if matching else None
    latest = latest_pair[0] if latest_pair else None
    if malformed:
        integrity = "INVALID"
        review_reason = "audit contains malformed records"
    elif latest is None:
        integrity = "INCOMPLETE"
        review_reason = "no completed SAFE application event found for this job"
    else:
        integrity = "VALID"
        review_reason = "completed SAFE application event is available for human review"
    state = latest.get("state") if latest else None
    if state == "ROLLED_BACK_VERIFICATION_FAILED":
        review_reason = "verification failed and the isolated worktree was rolled back"
    return {
        "schema_version": "1",
        "mode": "READ_ONLY_AUDIT_REVIEW",
        "job_id": job_id,
        "audit_sha256": digest,
        "events_seen": events_seen,
        "matching_event_count": len(matching),
        "latest_event_sha256": hashlib.sha256(latest_pair[1]).hexdigest() if latest_pair else None,
        "integrity": integrity,
        "latest_state": state,
        "verification_passed": latest.get("verification_passed") if latest else None,
        "rollback_performed": latest.get("rollback_performed") if latest else None,
        "review_required": True,
        "review_reason": review_reason,
        "mutation_allowed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize SAFE application audit evidence without exposing contents")
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--job-id", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(review_audit(args.audit, args.job_id), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError) as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
