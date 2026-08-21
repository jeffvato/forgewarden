"""Bounded, dry-run continuation planning for the supervisor."""
from __future__ import annotations
from dataclasses import dataclass
from .stop_conditions import StopContext, StopDecision, evaluate_stop_conditions
from .supervisor_state import SupervisorState
from .task_selection import SelectionDecision, select_ready_task
from .work_checkpoint import WorkUnitCheckpoint, load_checkpoint, reconcile_checkpoint, write_checkpoint
from .review_handoff import ReviewCycle, ReviewResult, complete_review_cycle, create_review_cycle, record_review

@dataclass(frozen=True)
class ContinuationPlan:
    stop: StopDecision
    selection: SelectionDecision | None
    next_action: str

@dataclass(frozen=True)
class WorkUnitResult:
    candidate_commit: str
    changed_files: tuple[str, ...]
    validation: tuple[str, ...]

def run_bounded_work_unit(state: SupervisorState, stop_context: StopContext, checkpoint_path, repository_head: str, dispatch, validate, reviews, repair=None) -> ContinuationPlan:
    """Run one injected local dry-run unit; callbacks supply no authority themselves."""
    plan = plan_continuation(state, stop_context)
    if plan.stop.should_stop or plan.selection is None or plan.selection.selected is None:
        return plan
    task = plan.selection.selected
    prior = WorkUnitCheckpoint("ForgeWarden Core", task.task_id, repository_head, None, None, (), (), "PENDING", "PENDING", (), None, "dispatch")
    write_checkpoint(checkpoint_path, prior)
    reconcile_checkpoint(load_checkpoint(checkpoint_path), repository_head)
    result = dispatch(task)
    if not isinstance(result, WorkUnitResult):
        return ContinuationPlan(StopDecision(True, "DISPATCH_RESULT_INVALID", "repair dispatch result"), plan.selection, "stop")
    if not validate(result):
        return ContinuationPlan(StopDecision(True, "VALIDATION_FAILED", "repair and revalidate"), plan.selection, "stop")
    cycle = create_review_cycle(result.candidate_commit)
    for review in reviews(result.candidate_commit): cycle = record_review(cycle, review)
    try:
        complete_review_cycle(cycle)
    except Exception:
        if repair is None: return ContinuationPlan(StopDecision(True, "REVIEW_REPAIR_REQUIRED", "repair and obtain fresh reviews"), plan.selection, "stop")
        result = repair(result)
        if not isinstance(result, WorkUnitResult) or not validate(result): return ContinuationPlan(StopDecision(True, "REPAIR_VALIDATION_FAILED", "repair and revalidate"), plan.selection, "stop")
        cycle = create_review_cycle(result.candidate_commit)
        for review in reviews(result.candidate_commit): cycle = record_review(cycle, review)
        complete_review_cycle(cycle)
    accepted = WorkUnitCheckpoint("ForgeWarden Core", task.task_id, repository_head, result.candidate_commit, result.candidate_commit, result.changed_files, result.validation, "APPROVED", "APPROVED", (), None, "advance queue")
    write_checkpoint(checkpoint_path, accepted)
    reconcile_checkpoint(load_checkpoint(checkpoint_path), result.candidate_commit)
    return ContinuationPlan(StopDecision(False, None, None), plan.selection, "accepted; advance queue")

def plan_continuation(state: SupervisorState, stop_context: StopContext) -> ContinuationPlan:
    """Plan one local dry-run transition; never dispatches agents or mutates state."""
    stop = evaluate_stop_conditions(stop_context)
    if stop.should_stop:
        return ContinuationPlan(stop, None, stop.first_resume_action or "stop")
    selection = select_ready_task(state)
    if selection.selected is None:
        if selection.ineligible:
            return ContinuationPlan(StopDecision(False, None, None), selection, "await dependency resolution or safe independent work")
        return ContinuationPlan(StopDecision(True, "ALL_ACTIVE_WORK_COMPLETE", "await explicit activation of further approved work"), selection, "stop")
    return ContinuationPlan(stop, selection, f"inspect and dispatch {selection.selected.task_id} in DRY_RUN mode")
