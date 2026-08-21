from __future__ import annotations

import json

import pytest

from swarm.stop_conditions import StopConditionError, StopContext, evaluate_stop_conditions, persist_stop_decision


@pytest.mark.parametrize(
    "flag, expected",
    (
        ("all_active_work_complete", "ALL_ACTIVE_WORK_COMPLETE"),
        ("requires_customer_authority", "CUSTOMER_AUTHORITY_REQUIRED"),
        ("policy_invariant_conflict", "POLICY_INVARIANT_CONFLICT"),
        ("repository_unsafe_or_ambiguous", "UNSAFE_REPOSITORY"),
        ("platform_resource_limit", "PLATFORM_RESOURCE_LIMIT"),
        ("supervisor_terminated", "SUPERVISOR_TERMINATED"),
    ),
)
def test_each_approved_stop_condition_is_distinct(flag, expected):
    decision = evaluate_stop_conditions(StopContext(**{flag: True}))
    assert decision.should_stop is True
    assert decision.reason == expected
    assert decision.first_resume_action


def test_resource_stop_requires_no_safe_independent_work():
    assert evaluate_stop_conditions(StopContext(required_resource_unavailable=True)).should_stop is False
    assert evaluate_stop_conditions(StopContext(required_resource_unavailable=True, safe_independent_work_available=False)).reason == "REQUIRED_RESOURCE_UNAVAILABLE"


def test_ordinary_failures_and_completion_do_not_stop_work():
    assert evaluate_stop_conditions(StopContext()).should_stop is False


def test_unsafe_repository_wins_deterministically():
    decision = evaluate_stop_conditions(StopContext(requires_customer_authority=True, repository_unsafe_or_ambiguous=True))
    assert decision.reason == "UNSAFE_REPOSITORY"
    assert evaluate_stop_conditions(StopContext(repository_unsafe_or_ambiguous=True, required_resource_unavailable=True, safe_independent_work_available=False)).reason == "UNSAFE_REPOSITORY"


def test_stop_record_persists_reason_and_resume_action(tmp_path):
    path = tmp_path / "stop.json"
    decision = evaluate_stop_conditions(StopContext(policy_invariant_conflict=True))
    persist_stop_decision(path, decision)
    assert json.loads(path.read_text(encoding="utf-8"))["reason"] == "POLICY_INVARIANT_CONFLICT"
    with pytest.raises(StopConditionError):
        persist_stop_decision(path, evaluate_stop_conditions(StopContext()))
def test_symlinked_parent_stop_record_path_fails_closed(tmp_path):
    real=tmp_path/"real"; real.mkdir(); linked=tmp_path/"linked"; linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(StopConditionError, match="symlink"):
        persist_stop_decision(linked/"stop.json", evaluate_stop_conditions(StopContext(policy_invariant_conflict=True)))
