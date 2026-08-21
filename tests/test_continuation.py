from swarm.continuation import plan_continuation
from swarm.stop_conditions import StopContext
from swarm.continuation import WorkUnitResult, run_bounded_work_unit
from swarm.review_handoff import ReviewResult
SHA="a"*40
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
def test_blocked_ready_work_does_not_claim_completion():
    plan=plan_continuation(_state(_task("FWQ-0001",state="BLOCKED"),_task("FWQ-0002",dependencies="FWQ-0001")),StopContext())
    assert plan.stop.should_stop is False
def test_full_loop_success_and_review_failures(tmp_path):
    state=_state(_task("FWQ-0001"))
    result=WorkUnitResult(SHA,("x",),("ok",))
    reviews=lambda sha:(ReviewResult("CLAUDE",sha,(),"LOW","APPROVED","ok"),ReviewResult("GEMINI",sha,(),"LOW","APPROVED","ok"))
    assert run_bounded_work_unit(state,StopContext(),tmp_path/"c.json",SHA,lambda _:result,lambda _:True,reviews).next_action == "accepted; advance queue"
    assert run_bounded_work_unit(state,StopContext(),tmp_path/"d.json",SHA,lambda _:object(),lambda _:True,reviews).stop.reason == "DISPATCH_RESULT_INVALID"
def test_loop_missing_review_repair_and_restart(tmp_path):
    state=_state(_task("FWQ-0001")); bad=lambda sha:(ReviewResult("CLAUDE",sha,(),"LOW","APPROVED","ok"),)
    result=WorkUnitResult(SHA,("x",),("ok",))
    assert run_bounded_work_unit(state,StopContext(),tmp_path/"c.json",SHA,lambda _:result,lambda _:True,bad).stop.reason == "REVIEW_REPAIR_REQUIRED"
