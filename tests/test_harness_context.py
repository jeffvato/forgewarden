from dataclasses import replace

import pytest

from swarm.harness_context import BudgetLedger, BudgetLimits, BudgetRequest, ContextItem, HarnessContextError, build_context_packet
from swarm.harness_task import HarnessTask, TaskStatus


NOW = "2026-09-09T12:00:00+00:00"


def task():
    return HarnessTask(task_id="FWQ-0067", requirement_id="FW-HARNESS-003", title="Context", description="Bound context", status=TaskStatus.READY, priority=0, assigned_role="CODEX", assigned_model="approved-model", repository="/repo", created_at=NOW, relevant_files=("swarm/harness_context.py",))


def items():
    return (
        ContextItem("requirement", "FW-HARNESS-003", "Build bounded context."),
        ContextItem("architecture_constraint", "D-023", "AI never owns authority."),
        ContextItem("task_state", "FWQ-0067", "ready"),
        ContextItem("relevant_file", "swarm/harness_context.py", "caller supplied excerpt"),
        ContextItem("forbidden_change", "deployment", "Deployment remains disabled."),
    )


def test_context_packet_is_deterministic_bounded_and_auditable():
    first = build_context_packet(task(), items())
    second = build_context_packet(task(), items())
    assert first == second
    assert len(first.sha256) == 64 and first.byte_count > 0
    assert first.selected_references[-1] == "forbidden_change:deployment"


def test_context_hash_binds_task_state_and_selected_content():
    first = build_context_packet(task(), items())
    changed = list(items())
    changed[2] = ContextItem("task_state", "FWQ-0067", "blocked")
    assert build_context_packet(task(), tuple(changed)).sha256 != first.sha256
    assert build_context_packet(replace(task(), priority=1), items()).sha256 != first.sha256


@pytest.mark.parametrize("bad,match", [
    ((ContextItem("relevant_file", "../secret", "x"),), "outside"),
    ((ContextItem("recent_commit", "main", "x"),), "exact Git"),
    ((ContextItem("requirement", "FW-HARNESS-999", "x"),), "does not match"),
    ((ContextItem("model_instruction", "x", "deploy"),), "kind"),
])
def test_unapproved_context_material_fails_closed(bad, match):
    with pytest.raises(HarnessContextError, match=match):
        build_context_packet(task(), bad + items()[1:3] + items()[-1:])


def test_context_requires_forbidden_and_architecture_boundaries():
    with pytest.raises(HarnessContextError, match="requires architecture"):
        build_context_packet(task(), items()[:1])


def test_context_count_and_byte_limits_are_enforced():
    with pytest.raises(HarnessContextError, match="item count"):
        build_context_packet(task(), items(), max_items=2)
    oversized = items() + (ContextItem("review_finding", "f1", "x" * 101),)
    with pytest.raises(HarnessContextError, match="item exceeds"):
        build_context_packet(task(), oversized, max_item_bytes=100, max_bytes=1000)


def limits(calls=2, tokens=100, retries=1, elapsed=10, tools=2, cost=1000):
    return BudgetLimits(calls, tokens, retries, elapsed, tools, cost)


def test_budget_admission_is_atomic_across_task_and_session():
    ledger = BudgetLedger(limits(calls=2), {"FWQ-0067": limits(calls=1), "FWQ-0068": limits(calls=2)})
    admitted = ledger.admit("FWQ-0067", "CODEX", BudgetRequest(tokens=20))
    assert admitted.task_usage.model_calls == 1 and admitted.session_usage.tokens == 20
    with pytest.raises(HarnessContextError, match="task:model_calls"):
        ledger.admit("FWQ-0067", "CODEX", BudgetRequest(tokens=30))
    snapshot = ledger.snapshot()
    assert snapshot["session"].model_calls == 1 and snapshot["session"].tokens == 20


def test_session_exhaustion_stops_a_different_task_without_consumption():
    ledger = BudgetLedger(limits(calls=1), {"FWQ-0067": limits(), "FWQ-0068": limits()})
    ledger.admit("FWQ-0067", "CODEX", BudgetRequest())
    with pytest.raises(HarnessContextError, match="session:model_calls"):
        ledger.admit("FWQ-0068", "CODEX", BudgetRequest())
    assert ledger.snapshot()["tasks"]["FWQ-0068"].model_calls == 0


@pytest.mark.parametrize("usage_request,reason", [
    (BudgetRequest(tokens=101), "tokens"),
    (BudgetRequest(retries=2), "retries"),
    (BudgetRequest(elapsed_seconds=11), "elapsed_seconds"),
    (BudgetRequest(tool_calls=3), "tool_calls"),
    (BudgetRequest(cost_microunits=1001), "cost_microunits"),
])
def test_each_task_budget_dimension_is_enforced(usage_request, reason):
    ledger = BudgetLedger(limits(), {"FWQ-0067": limits()})
    with pytest.raises(HarnessContextError, match=reason):
        ledger.admit("FWQ-0067", "CODEX", usage_request)


def test_unregistered_task_worker_and_invalid_limits_fail_closed():
    ledger = BudgetLedger(limits(), {"FWQ-0067": limits()})
    with pytest.raises(HarnessContextError, match="not registered"):
        ledger.admit("FWQ-9999", "CODEX", BudgetRequest())
    with pytest.raises(HarnessContextError, match="not registered"):
        ledger.admit("FWQ-0067", "codex; shell", BudgetRequest())
    with pytest.raises(HarnessContextError, match="non-negative"):
        BudgetLimits(-1, 0, 0, 0)
