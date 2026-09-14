import pytest
from swarm.resource_validation import DEFAULT_BUDGETS, ResourceBudget, ResourceValidationError, validate_cross_platform_budgets

def test_cross_platform_defaults_are_bounded():
    value=validate_cross_platform_budgets()
    assert set(value)=={"WINDOWS", "LINUX"}
    assert all(item.cpu_percent == 50 and item.memory_mb == 1024 and item.process_limit == 32 for item in value.values())

@pytest.mark.parametrize("budgets", [(), (DEFAULT_BUDGETS[0],), (DEFAULT_BUDGETS[0], DEFAULT_BUDGETS[0])])
def test_cross_platform_requires_exact_platform_coverage(budgets):
    with pytest.raises(ResourceValidationError): validate_cross_platform_budgets(budgets)

@pytest.mark.parametrize("field,value", [("cpu_percent",0),("memory_mb",8),("runtime_seconds",0),("process_limit",129),("file_limit",10001)])
def test_resource_limits_fail_closed(field,value):
    values=DEFAULT_BUDGETS[0].__dict__ | {field:value}
    with pytest.raises(ResourceValidationError): ResourceBudget(**values)
