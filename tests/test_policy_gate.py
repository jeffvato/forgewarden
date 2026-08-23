import pytest

from swarm.policy_gate import PolicyInvariantError, validate_safety_evidence


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
