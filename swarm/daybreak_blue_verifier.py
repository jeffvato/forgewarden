"""Daybreak Blue exact-commit verification contract.

This module defines the provider-neutral request/response boundary for OpenAI
Daybreak Blue code verification. It performs no HTTP request and resolves no
credentials. Network transport and FW-KEYS resolution remain separate owners.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


DAYBREAK_BLUE_MODEL = "gpt-daybreak-blue-latest"
DAYBREAK_BLUE_ACCESS_PROGRAM = "daybreak_blue"
DAYBREAK_BLUE_REVIEWER = "DAYBREAK_BLUE"


class DaybreakBlueVerificationError(ValueError):
    """Daybreak Blue verification input or output violated the exact contract."""


@dataclass(frozen=True)
class DaybreakBlueReviewRequest:
    job_id: str
    reviewed_commit: str
    instructions: str
    model: str = DAYBREAK_BLUE_MODEL
    access_program: str = DAYBREAK_BLUE_ACCESS_PROGRAM
    read_only: bool = True
    deployment_authority: str = "DISABLED"


def build_daybreak_blue_request(
    *,
    job_id: str,
    reviewed_commit: str,
    review_context: str,
) -> tuple[DaybreakBlueReviewRequest, dict[str, Any]]:
    if not isinstance(job_id, str) or not job_id:
        raise DaybreakBlueVerificationError("review job ID is required")
    if (
        not isinstance(reviewed_commit, str)
        or len(reviewed_commit) not in (40, 64)
        or any(ch not in "0123456789abcdefABCDEF" for ch in reviewed_commit)
    ):
        raise DaybreakBlueVerificationError("reviewed commit must be an exact Git SHA")
    if not isinstance(review_context, str) or not review_context.strip():
        raise DaybreakBlueVerificationError("review context is required")

    request = DaybreakBlueReviewRequest(
        job_id=job_id,
        reviewed_commit=reviewed_commit.lower(),
        instructions=review_context,
    )
    prompt = (
        "You are the independent read-only ForgeWarden code verifier. "
        f"Review only exact commit {request.reviewed_commit}. "
        "Do not write files, create commits, merge, deploy, change policy, "
        "resolve credentials, invoke tools, or authorize follow-on actions. "
        "Return JSON only with: job_id, reviewed_commit, verdict, risk, "
        "blocking_findings, non_blocking_notes, tests_missing, reasoning_summary, "
        "and proposed_rules. APPROVE only if the exact commit has no blocking "
        "finding and required deterministic tests are sufficient.\n\n"
        + request.instructions
    )
    wire = {
        "model": request.model,
        "input": prompt,
        "access_programs": {"cyber": request.access_program},
    }
    return request, wire


def validate_daybreak_blue_result(
    request: DaybreakBlueReviewRequest,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(request, DaybreakBlueReviewRequest):
        raise DaybreakBlueVerificationError("Daybreak Blue request is invalid")
    if not isinstance(payload, Mapping):
        raise DaybreakBlueVerificationError("Daybreak Blue result must be an object")
    required = {
        "job_id", "reviewed_commit", "verdict", "risk", "blocking_findings",
        "non_blocking_notes", "tests_missing", "reasoning_summary", "proposed_rules",
    }
    if set(payload) != required:
        raise DaybreakBlueVerificationError("Daybreak Blue result field set is invalid")
    if payload["job_id"] != request.job_id:
        raise DaybreakBlueVerificationError("Daybreak Blue result job binding mismatch")
    if str(payload["reviewed_commit"]).lower() != request.reviewed_commit:
        raise DaybreakBlueVerificationError("Daybreak Blue result commit binding mismatch")
    if payload["verdict"] not in {"APPROVE", "REJECT", "HUMAN_REQUIRED"}:
        raise DaybreakBlueVerificationError("Daybreak Blue verdict is invalid")
    if payload["risk"] not in {"LOW", "MEDIUM", "HIGH"}:
        raise DaybreakBlueVerificationError("Daybreak Blue risk is invalid")
    for field in ("blocking_findings", "non_blocking_notes", "tests_missing", "proposed_rules"):
        if not isinstance(payload[field], list):
            raise DaybreakBlueVerificationError(f"Daybreak Blue {field} must be a list")
    if len(payload["blocking_findings"]) > 32 or len(payload["non_blocking_notes"]) > 32 or len(payload["tests_missing"]) > 32:
        raise DaybreakBlueVerificationError("Daybreak Blue finding list exceeds bounds")
    if len(payload["proposed_rules"]) > 1:
        raise DaybreakBlueVerificationError("Daybreak Blue proposed rule count exceeds bounds")
    if not isinstance(payload["reasoning_summary"], str) or not payload["reasoning_summary"].strip():
        raise DaybreakBlueVerificationError("Daybreak Blue reasoning summary is required")

    # Verification remains fail-closed. Approval cannot coexist with blockers
    # or missing tests, and medium/high-risk approval is not accepted.
    if payload["verdict"] == "APPROVE" and (
        payload["blocking_findings"]
        or payload["tests_missing"]
        or payload["risk"] != "LOW"
    ):
        raise DaybreakBlueVerificationError("Daybreak Blue approval violates acceptance policy")
    return dict(payload)
