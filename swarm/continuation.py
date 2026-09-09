"""Bounded, dry-run continuation planning for the supervisor."""
from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass
from .stop_conditions import StopContext, StopDecision, evaluate_stop_conditions
from .supervisor_state import SupervisorState
from .task_selection import SelectionDecision, select_ready_task
from .work_checkpoint import WorkUnitCheckpoint, load_checkpoint, reconcile_checkpoint, write_checkpoint
from .review_handoff import ReviewCycle, ReviewResult, complete_review_cycle, create_review_cycle, record_review

_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_TASK = re.compile(r"^FWQ-[0-9]{4}$")
MAX_CONTINUATIONS = 128


class ContinuationReplayDenied(ValueError):
    """A continuation transition is invalid, mismatched, or already consumed."""


@dataclass(frozen=True)
class ContinuationTransition:
    completed_task: str
    accepted_commit: str
    next_task: str
    active_phase: str = "ForgeWarden Core"
    token: str = ""


class ContinuationReplayGuard:
    """Bounded exact-once consumer for untrusted continuation transitions."""

    def __init__(self, *, max_entries: int = MAX_CONTINUATIONS) -> None:
        if not isinstance(max_entries, int) or isinstance(max_entries, bool) or not 1 <= max_entries <= MAX_CONTINUATIONS:
            raise ValueError("invalid continuation replay capacity")
        self._max_entries = max_entries
        self._consumed: set[str] = set()

    @staticmethod
    def issue(completed_task: str, accepted_commit: str, next_task: str, *, active_phase: str = "ForgeWarden Core") -> ContinuationTransition:
        if not _TASK.fullmatch(completed_task) or not _TASK.fullmatch(next_task) or not _SHA.fullmatch(accepted_commit) or active_phase != "ForgeWarden Core":
            raise ContinuationReplayDenied("CONTINUATION_INVALID")
        material = f"{active_phase}|{completed_task}|{accepted_commit.lower()}|{next_task}".encode("ascii")
        token = hashlib.sha256(material).hexdigest()
        return ContinuationTransition(completed_task, accepted_commit.lower(), next_task, active_phase, token)

    def consume(self, transition: ContinuationTransition, *, completed_task: str, accepted_commit: str, next_task: str, active_phase: str = "ForgeWarden Core") -> ContinuationTransition:
        if not isinstance(transition, ContinuationTransition):
            raise ContinuationReplayDenied("CONTINUATION_INVALID")
        expected = self.issue(completed_task, accepted_commit, next_task, active_phase=active_phase)
        if transition != expected:
            raise ContinuationReplayDenied("CONTINUATION_MISMATCH")
        if transition.token in self._consumed:
            raise ContinuationReplayDenied("CONTINUATION_REPLAY")
        if len(self._consumed) >= self._max_entries:
            raise ContinuationReplayDenied("CONTINUATION_CAPACITY")
        self._consumed.add(transition.token)
        return transition

    def admit(self, transition: ContinuationTransition, *, completed_task: str, accepted_commit: str,
              next_task: str, ready_tasks: tuple[str, ...], dependencies_complete: bool,
              active_phase: str = "ForgeWarden Core") -> "ContinuationAdmission":
        """Consume a transition only when its successor is the sole READY task."""
        if not isinstance(ready_tasks, tuple) or not ready_tasks:
            raise ContinuationReplayDenied("CONTINUATION_NEXT_TASK_NOT_READY")
        if any(not isinstance(item, str) or not _TASK.fullmatch(item) for item in ready_tasks):
            raise ContinuationReplayDenied("CONTINUATION_READY_TASK_INVALID")
        if len(set(ready_tasks)) != len(ready_tasks):
            raise ContinuationReplayDenied("CONTINUATION_READY_TASK_DUPLICATE")
        if len(ready_tasks) != 1:
            raise ContinuationReplayDenied("CONTINUATION_NEXT_TASK_AMBIGUOUS")
        if not isinstance(dependencies_complete, bool) or not dependencies_complete:
            raise ContinuationReplayDenied("CONTINUATION_DEPENDENCY_INCOMPLETE")
        if next_task != ready_tasks[0]:
            raise ContinuationReplayDenied("CONTINUATION_NEXT_TASK_MISMATCH")
        consumed = self.consume(transition, completed_task=completed_task,
                                accepted_commit=accepted_commit, next_task=next_task,
                                active_phase=active_phase)
        return ContinuationAdmission(consumed.completed_task, consumed.accepted_commit,
                                     consumed.next_task, consumed.active_phase, "ADMITTED")


@dataclass(frozen=True)
class ContinuationAdmission:
    """Redacted result of bounded continuation admission; not execution authority."""
    completed_task: str
    accepted_commit: str
    next_task: str
    active_phase: str
    decision: str

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
    try:
        result = dispatch(task)
    except Exception:
        return ContinuationPlan(StopDecision(True, "DISPATCH_EXCEPTION", "repair dispatch callback"), plan.selection, "stop")
    if not isinstance(result, WorkUnitResult):
        return ContinuationPlan(StopDecision(True, "DISPATCH_RESULT_INVALID", "repair dispatch result"), plan.selection, "stop")
    try:
        valid = validate(result)
    except Exception:
        return ContinuationPlan(StopDecision(True, "VALIDATION_EXCEPTION", "repair validation callback"), plan.selection, "stop")
    if not valid:
        return ContinuationPlan(StopDecision(True, "VALIDATION_FAILED", "repair and revalidate"), plan.selection, "stop")
    try:
        cycle = create_review_cycle(result.candidate_commit)
        for review in reviews(result.candidate_commit): cycle = record_review(cycle, review)
        complete_review_cycle(cycle)
    except Exception:
        if repair is None: return ContinuationPlan(StopDecision(True, "REVIEW_REPAIR_REQUIRED", "repair and obtain fresh reviews"), plan.selection, "stop")
        try:
            result = repair(result)
            valid = isinstance(result, WorkUnitResult) and validate(result)
        except Exception:
            return ContinuationPlan(StopDecision(True, "REPAIR_VALIDATION_FAILED", "repair and revalidate"), plan.selection, "stop")
        if not valid: return ContinuationPlan(StopDecision(True, "REPAIR_VALIDATION_FAILED", "repair and revalidate"), plan.selection, "stop")
        try:
            cycle = create_review_cycle(result.candidate_commit)
            for review in reviews(result.candidate_commit): cycle = record_review(cycle, review)
            complete_review_cycle(cycle)
        except Exception:
            return ContinuationPlan(StopDecision(True, "REPAIR_REVIEW_FAILED", "repair and obtain fresh reviews"), plan.selection, "stop")
    evidence = {role: review for role, review in cycle.reviews.items()}
    findings = tuple(f"{role}|{review.disposition}|{review.severity}|{review.rationale}|{finding}" for role, review in sorted(evidence.items()) for finding in (review.findings or ("",)))
    accepted = WorkUnitCheckpoint("ForgeWarden Core", task.task_id, repository_head, result.candidate_commit, result.candidate_commit, result.changed_files, result.validation, evidence["CLAUDE"].disposition, evidence["GEMINI"].disposition, findings, None, "advance queue")
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
            return ContinuationPlan(StopDecision(True, "NO_EXECUTABLE_READY_TASKS", "resolve blocked dependencies or activate safe independent work"), selection, "stop")
        return ContinuationPlan(StopDecision(True, "ALL_ACTIVE_WORK_COMPLETE", "await explicit activation of further approved work"), selection, "stop")
    return ContinuationPlan(stop, selection, f"inspect and dispatch {selection.selected.task_id} in DRY_RUN mode")
