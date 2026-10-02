import pytest

from swarm.daybreak_blue_verifier import (
    DAYBREAK_BLUE_ACCESS_PROGRAM,
    DAYBREAK_BLUE_MODEL,
    DaybreakBlueVerificationError,
    build_daybreak_blue_request,
    validate_daybreak_blue_result,
)


SHA = "a" * 40


def valid_payload(**changes):
    value = {
        "job_id": "review-001",
        "reviewed_commit": SHA,
        "verdict": "APPROVE",
        "risk": "LOW",
        "blocking_findings": [],
        "non_blocking_notes": [],
        "tests_missing": [],
        "reasoning_summary": "exact commit is acceptable",
        "proposed_rules": [],
    }
    value.update(changes)
    return value


def test_request_uses_exact_daybreak_blue_alias_and_access_program():
    request, wire = build_daybreak_blue_request(
        job_id="review-001",
        reviewed_commit=SHA,
        review_context="Review exact patch evidence only.",
    )
    assert request.model == DAYBREAK_BLUE_MODEL == "gpt-daybreak-blue-latest"
    assert request.access_program == DAYBREAK_BLUE_ACCESS_PROGRAM == "daybreak_blue"
    assert request.read_only is True
    assert request.deployment_authority == "DISABLED"
    assert wire["model"] == "gpt-daybreak-blue-latest"
    assert wire["access_programs"] == {"cyber": "daybreak_blue"}
    assert "Do not write files" in wire["input"]


def test_exact_commit_and_job_binding_are_required():
    request, _ = build_daybreak_blue_request(
        job_id="review-001", reviewed_commit=SHA, review_context="context"
    )
    with pytest.raises(DaybreakBlueVerificationError, match="job binding"):
        validate_daybreak_blue_result(request, valid_payload(job_id="other"))
    with pytest.raises(DaybreakBlueVerificationError, match="commit binding"):
        validate_daybreak_blue_result(request, valid_payload(reviewed_commit="b" * 40))


def test_approval_requires_low_risk_no_blockers_and_no_missing_tests():
    request, _ = build_daybreak_blue_request(
        job_id="review-001", reviewed_commit=SHA, review_context="context"
    )
    assert validate_daybreak_blue_result(request, valid_payload())["verdict"] == "APPROVE"
    for payload in (
        valid_payload(risk="MEDIUM"),
        valid_payload(blocking_findings=["blocker"]),
        valid_payload(tests_missing=["missing test"]),
    ):
        with pytest.raises(DaybreakBlueVerificationError, match="acceptance policy"):
            validate_daybreak_blue_result(request, payload)


def test_malformed_or_unbounded_result_fails_closed():
    request, _ = build_daybreak_blue_request(
        job_id="review-001", reviewed_commit=SHA, review_context="context"
    )
    bad = valid_payload()
    bad["unexpected"] = True
    with pytest.raises(DaybreakBlueVerificationError, match="field set"):
        validate_daybreak_blue_result(request, bad)
    with pytest.raises(DaybreakBlueVerificationError, match="exceeds bounds"):
        validate_daybreak_blue_result(
            request, valid_payload(blocking_findings=["x"] * 33, verdict="REJECT")
        )
