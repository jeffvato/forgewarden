import pytest
from swarm.continuation import ContinuationReplayDenied, ContinuationReplayGuard, plan_continuation
from swarm.stop_conditions import StopContext
from swarm.continuation import WorkUnitResult, run_bounded_work_unit
from swarm.review_handoff import ReviewResult
from swarm.work_checkpoint import load_checkpoint
SHA="a"*40
CANDIDATE_SHA="b"*40
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
    assert plan.stop.reason == "NO_EXECUTABLE_READY_TASKS"
def test_full_loop_success_and_review_failures(tmp_path):
    state=_state(_task("FWQ-0001"))
    result=WorkUnitResult(CANDIDATE_SHA,("x",),("ok",))
    reviews=lambda sha:(ReviewResult("CLAUDE",sha,(),"LOW","APPROVED","ok"),ReviewResult("GEMINI",sha,(),"LOW","APPROVED","ok"))
    assert run_bounded_work_unit(state,StopContext(),tmp_path/"c.json",SHA,lambda _:result,lambda _:True,reviews).next_action == "accepted; advance queue"
    assert run_bounded_work_unit(state,StopContext(),tmp_path/"d.json",SHA,lambda _:object(),lambda _:True,reviews).stop.reason == "DISPATCH_RESULT_INVALID"
def test_loop_missing_review_repair_and_restart(tmp_path):
    state=_state(_task("FWQ-0001")); bad=lambda sha:(ReviewResult("CLAUDE",sha,(),"LOW","APPROVED","ok"),)
    result=WorkUnitResult(SHA,("x",),("ok",))
    assert run_bounded_work_unit(state,StopContext(),tmp_path/"c.json",SHA,lambda _:result,lambda _:True,bad).stop.reason == "REVIEW_REPAIR_REQUIRED"
def test_repair_review_failure_is_auditable(tmp_path):
    state=_state(_task("FWQ-0001")); result=WorkUnitResult(SHA,("x",),("ok",))
    bad=lambda sha:(ReviewResult("CLAUDE",sha,(),"LOW","REJECTED","no"),ReviewResult("GEMINI",sha,(),"LOW","APPROVED","ok"))
    assert run_bounded_work_unit(state,StopContext(),tmp_path/"c.json",SHA,lambda _:result,lambda _:True,bad,lambda value:value).stop.reason == "REPAIR_REVIEW_FAILED"
def test_accepted_checkpoint_preserves_actual_review_evidence(tmp_path):
    state=_state(_task("FWQ-0001")); result=WorkUnitResult(CANDIDATE_SHA,("x",),("ok",)); path=tmp_path/"c.json"
    reviews=lambda sha:(ReviewResult("CLAUDE",sha,("low-note",),"LOW","FINDINGS","ok"),ReviewResult("GEMINI",sha,("gemini-note",),"LOW","APPROVED","ok"))
    assert run_bounded_work_unit(state,StopContext(),path,SHA,lambda _:result,lambda _:True,reviews).next_action == "accepted; advance queue"
    checkpoint=load_checkpoint(path)
    assert checkpoint.claude_review == "FINDINGS" and checkpoint.gemini_review == "APPROVED"
    assert checkpoint.unresolved_findings == ("CLAUDE|FINDINGS|LOW|ok|low-note", "GEMINI|APPROVED|LOW|ok|gemini-note")
def test_callback_exceptions_are_structured_stops(tmp_path):
    state=_state(_task("FWQ-0001")); result=WorkUnitResult(SHA,("x",),("ok",)); ok=lambda sha:()
    assert run_bounded_work_unit(state,StopContext(),tmp_path/"a",SHA,lambda _:(_ for _ in ()).throw(RuntimeError()),lambda _:True,ok).stop.reason == "DISPATCH_EXCEPTION"
    assert run_bounded_work_unit(state,StopContext(),tmp_path/"b",SHA,lambda _:result,lambda _:(_ for _ in ()).throw(RuntimeError()),ok).stop.reason == "VALIDATION_EXCEPTION"
    assert run_bounded_work_unit(state,StopContext(),tmp_path/"c",SHA,lambda _:result,lambda _:True,lambda _:(_ for _ in ()).throw(RuntimeError())).stop.reason == "REVIEW_REPAIR_REQUIRED"
def test_initial_record_review_error_is_structured(tmp_path):
    state=_state(_task("FWQ-0001")); result=WorkUnitResult(SHA,("x",),("ok",))
    bad=lambda sha:(ReviewResult("CLAUDE","b"*40,(),"LOW","APPROVED","ok"),)
    assert run_bounded_work_unit(state,StopContext(),tmp_path/"c",SHA,lambda _:result,lambda _:True,bad).stop.reason == "REVIEW_REPAIR_REQUIRED"


def test_continuation_replay_guard_binds_and_consumes_once():
    guard = ContinuationReplayGuard()
    transition = guard.issue("FWQ-0001", SHA, "FWQ-0002")
    assert guard.consume(transition, completed_task="FWQ-0001", accepted_commit=SHA, next_task="FWQ-0002") == transition
    with pytest.raises(ContinuationReplayDenied, match="CONTINUATION_REPLAY"):
        guard.consume(transition, completed_task="FWQ-0001", accepted_commit=SHA, next_task="FWQ-0002")


def test_continuation_replay_guard_rejects_mismatch_and_capacity():
    guard = ContinuationReplayGuard(max_entries=1)
    transition = guard.issue("FWQ-0001", SHA, "FWQ-0002")
    with pytest.raises(ContinuationReplayDenied, match="CONTINUATION_MISMATCH"):
        guard.consume(transition, completed_task="FWQ-0001", accepted_commit=CANDIDATE_SHA, next_task="FWQ-0002")
    guard.consume(transition, completed_task="FWQ-0001", accepted_commit=SHA, next_task="FWQ-0002")
    second = guard.issue("FWQ-0002", SHA, "FWQ-0003")
    with pytest.raises(ContinuationReplayDenied, match="CONTINUATION_CAPACITY"):
        guard.consume(second, completed_task="FWQ-0002", accepted_commit=SHA, next_task="FWQ-0003")
