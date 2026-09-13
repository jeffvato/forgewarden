import json
from pathlib import Path

import pytest

from swarm.integrity import _PERFORMANCE_SCENARIOS, validate_performance_policy


ROOT = Path(__file__).resolve().parents[1]


def tracked_policy():
    return json.loads((ROOT / "config/integrity-performance.json").read_text(encoding="utf-8"))


def test_tracked_policy_is_complete_conservative_and_command_free():
    policies = validate_performance_policy(tracked_policy())
    assert tuple(item["scenario_id"] for item in policies) == _PERFORMANCE_SCENARIOS
    assert all(set(item) == {
        "scenario_id", "iterations", "max_wall_ms", "max_peak_kib",
        "timeout_seconds", "max_output_bytes", "max_processes",
    } for item in policies)
    assert all(item["max_processes"] == 1 and item["timeout_seconds"] <= 30 for item in policies)
    assert not any(any(word in key for word in ("command", "shell", "network", "credential")) for item in policies for key in item)


@pytest.mark.parametrize(
    "change,match",
    [
        ({"schema_version": 2}, "identity"),
        ({"scenarios": []}, "incomplete"),
        ({"scenarios": None}, "incomplete"),
    ],
)
def test_policy_rejects_wrong_identity_or_incomplete_scenarios(change, match):
    value = tracked_policy()
    value.update(change)
    with pytest.raises(ValueError, match=match):
        validate_performance_policy(value)


@pytest.mark.parametrize(
    "field,value,match",
    [
        ("scenario_id", "shell", "unsupported"),
        ("iterations", 0, "unsafe"),
        ("max_wall_ms", 99, "unsafe"),
        ("max_peak_kib", 131073, "unsafe"),
        ("timeout_seconds", 31, "unsafe"),
        ("max_output_bytes", 9000, "unsafe"),
        ("max_processes", 2, "process"),
    ],
)
def test_policy_rejects_unknown_scenarios_and_unsafe_thresholds(field, value, match):
    policy = tracked_policy()
    policy["scenarios"][0][field] = value
    with pytest.raises(ValueError, match=match):
        validate_performance_policy(policy)


def test_policy_rejects_duplicate_reordered_and_extra_fields():
    duplicate = tracked_policy()
    duplicate["scenarios"][1]["scenario_id"] = duplicate["scenarios"][0]["scenario_id"]
    with pytest.raises(ValueError, match="complete, unique, and ordered"):
        validate_performance_policy(duplicate)
    reordered = tracked_policy()
    reordered["scenarios"][0], reordered["scenarios"][1] = reordered["scenarios"][1], reordered["scenarios"][0]
    with pytest.raises(ValueError, match="complete, unique, and ordered"):
        validate_performance_policy(reordered)
    extra = tracked_policy()
    extra["scenarios"][0]["command"] = "python"
    with pytest.raises(ValueError, match="malformed"):
        validate_performance_policy(extra)
