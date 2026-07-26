"""Build a redacted, read-only evidence package for human/Gemini review."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def _load(path: Path) -> tuple[dict[str, Any], str]:
    path = path.expanduser()
    if path.is_symlink() or any(parent.is_symlink() for parent in (path.parent, *path.parent.parents)):
        raise ValueError(f"refusing symlink evidence input: {path}")
    raw = path.read_bytes()
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError(f"evidence input must be a JSON object: {path}")
    return payload, hashlib.sha256(raw).hexdigest()


def build_review_evidence(
    quality_report_path: Path,
    application_plan_path: Path,
    audit_review_path: Path,
) -> dict[str, Any]:
    quality, quality_hash = _load(quality_report_path)
    plan, plan_hash = _load(application_plan_path)
    audit, audit_hash = _load(audit_review_path)
    if quality.get("schema_version") != "1" or quality.get("mode") != "READ_ONLY" or quality.get("auto_apply_enabled") is not False:
        raise ValueError("quality report is not read-only")
    if (
        plan.get("schema_version") != "1"
        or plan.get("mode") != "EXPLICIT_SAFE_ONLY"
        or plan.get("mutation_allowed") is not False
        or plan.get("requires_explicit_invocation") is not True
        or plan.get("committed") is not False
        or plan.get("pushed") is not False
    ):
        raise ValueError("application plan is not non-mutating")
    if (
        audit.get("schema_version") != "1"
        or audit.get("mode") != "READ_ONLY_AUDIT_REVIEW"
        or audit.get("mutation_allowed") is not False
        or audit.get("review_required") is not True
    ):
        raise ValueError("audit review is not read-only")
    if not isinstance(audit.get("job_id"), str) or not audit["job_id"]:
        raise ValueError("audit review has no job ID")
    reasons = ["SAFE application remains explicitly invoked and non-mutating"]
    if audit.get("integrity") != "VALID":
        reasons.append("audit integrity is not VALID")
    if audit.get("rollback_performed") is True:
        reasons.append("application was rolled back")
    return {
        "schema_version": "1",
        "mode": "READ_ONLY_COMBINED_REVIEW_EVIDENCE",
        "job_id": audit["job_id"],
        "quality_report_sha256": quality_hash,
        "application_plan_sha256": plan_hash,
        "audit_review_sha256": audit_hash,
        "quality_counts": quality.get("counts", {}),
        "quality_source_files_scanned": quality.get("source_files_scanned", 0),
        "safe_candidate_count": len(plan.get("eligible_finding_ids", [])),
        "blocked_finding_count": len(plan.get("blocked_finding_ids", [])),
        "audit_integrity": audit.get("integrity"),
        "audit_latest_state": audit.get("latest_state"),
        "audit_latest_event_sha256": audit.get("latest_event_sha256"),
        "verification_passed": audit.get("verification_passed"),
        "rollback_performed": audit.get("rollback_performed"),
        "review_required": True,
        "approval_status": "HUMAN_REVIEW_REQUIRED",
        "review_reasons": reasons,
        "mutation_allowed": False,
        "deployment": "DISABLED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build read-only combined quality evidence")
    parser.add_argument("--quality-report", type=Path, required=True)
    parser.add_argument("--application-plan", type=Path, required=True)
    parser.add_argument("--audit-review", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = build_review_evidence(args.quality_report, args.application_plan, args.audit_review)
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
