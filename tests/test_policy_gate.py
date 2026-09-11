import pytest

from swarm.policy_gate import (
    CORE_INVARIANTS,
    CoreInvariant,
    DeterministicPolicy,
    PolicyContext,
    PolicyInvariantError,
    PolicyRule,
    validate_safety_evidence,
    validate_invariant_manifest,
)


def test_core_invariant_manifest_is_complete_unique_and_immutable():
    assert validate_invariant_manifest() is CORE_INVARIANTS
    assert [item.invariant_id for item in CORE_INVARIANTS] == [f"FW-INV-{index:03d}" for index in range(1, 10)]
    with pytest.raises(AttributeError):
        CORE_INVARIANTS[0].owner = "AI"  # type: ignore[misc]


def test_core_invariant_manifest_rejects_duplicates_and_missing_rules():
    with pytest.raises(PolicyInvariantError, match="unique"):
        validate_invariant_manifest(CORE_INVARIANTS[:-1] + (CORE_INVARIANTS[0],))
    with pytest.raises(PolicyInvariantError, match="incomplete"):
        validate_invariant_manifest(CORE_INVARIANTS[:-1])
    with pytest.raises(PolicyInvariantError, match="non-empty tuple"):
        validate_invariant_manifest([])  # type: ignore[arg-type]


def test_core_invariant_rejects_unversioned_id():
    with pytest.raises(PolicyInvariantError, match="ID"):
        CoreInvariant("AI-CAN-DECIDE", "FW-ROOT", "unsafe", "DENY")


@pytest.mark.parametrize("field,value", [("owner", None), ("statement", " "), ("enforcement", "x" * 257)])
def test_core_invariant_rejects_malformed_bounded_fields(field, value):
    values = {"owner": "FW-ROOT", "statement": "AI is bounded", "enforcement": "DENY"}
    values[field] = value
    with pytest.raises(PolicyInvariantError, match="non-empty bounded string"):
        CoreInvariant("FW-INV-010", **values)


def evidence(**overrides):
    result = {
        "mode": "DRY_RUN",
        "deployment": "DISABLED",
        "kill_switch": "ENGAGED",
    }
    result.update(overrides)
    return result


def test_safe_evidence_is_normalized_without_mutation():
    value = evidence(mutation_allowed=False, extra="untrusted")
    before = dict(value)
    assert validate_safety_evidence(value, require_kill_switch=True) == {
        "mode": "DRY_RUN",
        "deployment": "DISABLED",
        "kill_switch": "ENGAGED",
    }
    assert value == before


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("mode", "LIVE", "DRY_RUN"),
        ("deployment", "ENABLED", "deployment"),
        ("kill_switch", "CLEARED_FOR_DRY_RUN", "kill switch"),
        ("mutation_allowed", True, "mutation"),
    ],
)
def test_unsafe_evidence_fails_closed(field, value, message):
    with pytest.raises(PolicyInvariantError, match=message):
        validate_safety_evidence(evidence(**{field: value}), require_kill_switch=True)


def test_missing_evidence_fails_closed():
    with pytest.raises(PolicyInvariantError, match="missing"):
        validate_safety_evidence({"mode": "DRY_RUN"}, require_kill_switch=True)


def test_malformed_evidence_fails_closed():
    with pytest.raises(PolicyInvariantError, match="string"):
        validate_safety_evidence(evidence(deployment=False), require_kill_switch=True)


def test_non_mapping_evidence_fails_closed():
    with pytest.raises(PolicyInvariantError, match="mapping"):
        validate_safety_evidence(None, require_kill_switch=True)


def test_status_reporting_can_report_cleared_dry_run_switch_without_authorizing_it():
    assert validate_safety_evidence(
        evidence(kill_switch="CLEARED_FOR_DRY_RUN"),
        require_kill_switch=False,
    )["kill_switch"] == "CLEARED_FOR_DRY_RUN"


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "1"])
def test_policy_rejects_invalid_model_token_work_limits(value):
    with pytest.raises(PolicyInvariantError, match="max_model_tokens_per_work"):
        PolicyRule(
            "tenant-a", "telemetry.read", "endpoint-123", "READ", "FW-ASOC-01-v1",
            max_model_tokens_per_work=value,
        )


def test_policy_returns_the_exact_model_token_work_limit_for_a_scope():
    context = PolicyContext(
        "tenant-a", "agent-a", "telemetry.read", "endpoint-123", "READ", "FW-ASOC-01-v1",
    )
    policy = DeterministicPolicy([PolicyRule(
        "tenant-a", "telemetry.read", "endpoint-123", "READ", "FW-ASOC-01-v1",
        max_model_tokens_per_work=512, max_tenant_model_tokens=1024,
    )])
    assert policy.model_tokens_per_work_limit(context) == 512
    assert policy.tenant_model_tokens_limit(context) == 1024


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "1"])
def test_policy_rejects_invalid_tenant_model_token_limits(value):
    with pytest.raises(PolicyInvariantError, match="max_tenant_model_tokens"):
        PolicyRule(
            "tenant-a", "telemetry.read", "endpoint-123", "READ", "FW-ASOC-01-v1",
            max_tenant_model_tokens=value,
        )
