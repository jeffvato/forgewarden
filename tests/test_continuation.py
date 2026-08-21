from swarm.continuation import plan_continuation
from swarm.stop_conditions import StopContext
from test_task_selection import _state, _task
def test_plan_selects_one_ready_task_without_dispatching():
    plan=plan_continuation(_state(_task("FWQ-0001")),StopContext())
    assert plan.selection.selected.task_id == "FWQ-0001"; assert "DRY_RUN" in plan.next_action
def test_stop_prevents_selection():
    plan=plan_continuation(_state(_task("FWQ-0001")),StopContext(policy_invariant_conflict=True))
    assert plan.selection is None and plan.stop.should_stop
def test_no_ready_work_stops_with_explicit_reason():
    plan=plan_continuation(_state(_task("FWQ-0001",state="DONE")),StopContext())
    assert plan.stop.reason == "ALL_ACTIVE_WORK_COMPLETE"
