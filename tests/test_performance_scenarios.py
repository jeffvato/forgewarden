import pytest

from swarm.integrity import _PERFORMANCE_SCENARIOS, _run_control_performance_scenario


@pytest.mark.parametrize("scenario_id", _PERFORMANCE_SCENARIOS)
def test_each_fixed_control_scenario_has_a_safe_bounded_result(scenario_id):
    result = _run_control_performance_scenario(scenario_id, 10)
    assert set(result) == {
        "schema_version", "scenario_id", "iterations", "operations", "wall_ms",
        "peak_kib", "processes", "checksum", "mode", "deployment", "authority_granted",
    }
    assert result["scenario_id"] == scenario_id and result["operations"] == 10
    assert result["processes"] == 1 and result["mode"] == "DRY_RUN"
    assert result["deployment"] == "DISABLED" and result["authority_granted"] is False


@pytest.mark.parametrize("scenario_id,iterations", [("shell", 10), ("identity_policy", 9), ("identity_policy", True)])
def test_fixed_scenarios_reject_unknown_or_unbounded_input(scenario_id, iterations):
    with pytest.raises(ValueError, match="unsupported|iterations"):
        _run_control_performance_scenario(scenario_id, iterations)
