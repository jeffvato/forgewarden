"""Bounded, dry-run continuation planning for the supervisor."""
from __future__ import annotations
from dataclasses import dataclass
from .stop_conditions import StopContext, StopDecision, evaluate_stop_conditions
from .supervisor_state import SupervisorState
from .task_selection import SelectionDecision, select_ready_task

@dataclass(frozen=True)
class ContinuationPlan:
    stop: StopDecision
    selection: SelectionDecision | None
    next_action: str

def plan_continuation(state: SupervisorState, stop_context: StopContext) -> ContinuationPlan:
    """Plan one local dry-run transition; never dispatches agents or mutates state."""
    stop = evaluate_stop_conditions(stop_context)
    if stop.should_stop:
        return ContinuationPlan(stop, None, stop.first_resume_action or "stop")
    selection = select_ready_task(state)
    if selection.selected is None:
        return ContinuationPlan(StopDecision(True, "ALL_ACTIVE_WORK_COMPLETE", "await explicit activation of further approved work"), selection, "stop")
    return ContinuationPlan(stop, selection, f"inspect and dispatch {selection.selected.task_id} in DRY_RUN mode")
