"""Deterministic Monitor -> Repair -> Review records for FW-HARNESS."""
from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")


class HarnessRecoveryError(ValueError):
    """Monitor or recovery evidence failed deterministic governance."""


class Anomaly(str, Enum):
    NONE = "none"
    KILL_SWITCH = "kill_switch"
    EVIDENCE_FAILURE = "evidence_failure"
    IDENTITY_SUBSTITUTION = "identity_substitution"
    FILE_SCOPE_ESCAPE = "file_scope_escape"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    RETRY_EXHAUSTION = "retry_exhaustion"
    STUCK_WORKFLOW = "stuck_workflow"
    TEST_DEGRADATION = "test_degradation"


@dataclass(frozen=True)
class MonitorSnapshot:
    tenant_id: str
    task_id: str
    worker_id: str
    model_id: str
    stage: str
    elapsed_seconds: float
    stage_limit_seconds: float
    retry_count: int
    retry_limit: int
    budget_exhausted: bool
    identity_matches: bool
    evidence_healthy: bool
    kill_switch: str
    changed_files: tuple[str, ...]
    allowed_files: tuple[str, ...]
    tests_passed: bool


@dataclass(frozen=True)
class MonitorDecision:
    tenant_id: str
    task_id: str
    anomaly: Anomaly
    disposition: str
    repair_allowed: bool
    evidence_reference: str
    mode: str = "DRY_RUN"
    deployment: str = "DISABLED"
    authority_expanded: bool = False


@dataclass(frozen=True)
class RepairRequest:
    repair_id: str
    tenant_id: str
    task_id: str
    anomaly: Anomaly
    worker_id: str
    model_id: str
    allowed_files: tuple[str, ...]
    retry_count: int
    retry_limit: int
    action: str = "REQUEST_ONLY"
    executed: bool = False
    authority_expanded: bool = False


@dataclass(frozen=True)
class RecoveryReview:
    repair_id: str
    tenant_id: str
    task_id: str
    candidate_commit: str
    checkpoint_reference: str
    validation: str
    reviewer_verdict: str
    reviewer_risk: str
    final_status: str
    evidence_reference: str
    rollback_executed: bool = False
    deployment: str = "DISABLED"


def _path_set(values: tuple[str, ...], field: str) -> tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) > 256 or len(set(values)) != len(values):
        raise HarnessRecoveryError(f"{field} is malformed or excessive")
    for value in values:
        path = Path(value)
        if not isinstance(value, str) or not value or path.is_absolute() or ".." in path.parts:
            raise HarnessRecoveryError(f"{field} contains an escaping path")
    return values


def monitor(snapshot: MonitorSnapshot, *, evidence_sink: Callable[[str, dict[str, Any]], None]) -> MonitorDecision:
    """Classify one bounded observation and write canonical Evidence first."""
    if not isinstance(snapshot, MonitorSnapshot) or any(not _ID.fullmatch(value) for value in (snapshot.tenant_id, snapshot.task_id, snapshot.worker_id, snapshot.model_id, snapshot.stage)):
        raise HarnessRecoveryError("monitor identity is malformed")
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in (snapshot.retry_count, snapshot.retry_limit)):
        raise HarnessRecoveryError("monitor retry bounds are malformed")
    if any(not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value < 0 for value in (snapshot.elapsed_seconds, snapshot.stage_limit_seconds)):
        raise HarnessRecoveryError("monitor time bounds are malformed")
    if any(type(value) is not bool for value in (snapshot.budget_exhausted, snapshot.identity_matches, snapshot.evidence_healthy, snapshot.tests_passed)):
        raise HarnessRecoveryError("monitor boolean evidence is malformed")
    changed, allowed = _path_set(snapshot.changed_files, "changed_files"), _path_set(snapshot.allowed_files, "allowed_files")
    escaped = any(not any(path == root or path.startswith(root.rstrip("/") + "/") for root in allowed) for path in changed)
    if snapshot.kill_switch != "ENGAGED": anomaly, disposition = Anomaly.KILL_SWITCH, "STOP"
    elif not snapshot.evidence_healthy: anomaly, disposition = Anomaly.EVIDENCE_FAILURE, "STOP"
    elif not snapshot.identity_matches: anomaly, disposition = Anomaly.IDENTITY_SUBSTITUTION, "ESCALATE"
    elif escaped: anomaly, disposition = Anomaly.FILE_SCOPE_ESCAPE, "ESCALATE"
    elif snapshot.budget_exhausted: anomaly, disposition = Anomaly.RESOURCE_EXHAUSTION, "STOP"
    elif snapshot.retry_count >= snapshot.retry_limit and snapshot.retry_limit > 0: anomaly, disposition = Anomaly.RETRY_EXHAUSTION, "ESCALATE"
    elif snapshot.elapsed_seconds > snapshot.stage_limit_seconds: anomaly, disposition = Anomaly.STUCK_WORKFLOW, "REPAIR_REQUEST"
    elif not snapshot.tests_passed: anomaly, disposition = Anomaly.TEST_DEGRADATION, "REPAIR_REQUEST"
    else: anomaly, disposition = Anomaly.NONE, "CONTINUE"
    repair_allowed = disposition == "REPAIR_REQUEST"
    reference = f"fw-evid://{snapshot.tenant_id}/{snapshot.task_id}/{anomaly.value}"
    decision = MonitorDecision(snapshot.tenant_id, snapshot.task_id, anomaly, disposition, repair_allowed, reference)
    if not callable(evidence_sink):
        raise HarnessRecoveryError("canonical Evidence sink is unavailable")
    try:
        evidence_sink("fw_harness_monitor", {**asdict(decision), "anomaly": anomaly.value, "worker_id": snapshot.worker_id, "model_id": snapshot.model_id, "stage": snapshot.stage})
    except Exception as exc:
        raise HarnessRecoveryError("monitor Evidence write failed") from exc
    return decision


def request_repair(snapshot: MonitorSnapshot, decision: MonitorDecision, *, repair_id: str) -> RepairRequest:
    """Create an inert bounded repair request; execution remains externally gated."""
    if not _ID.fullmatch(repair_id) or decision.tenant_id != snapshot.tenant_id or decision.task_id != snapshot.task_id or not decision.repair_allowed or decision.disposition != "REPAIR_REQUEST":
        raise HarnessRecoveryError("monitor decision does not authorize a repair request")
    return RepairRequest(repair_id, snapshot.tenant_id, snapshot.task_id, decision.anomaly, snapshot.worker_id, snapshot.model_id, _path_set(snapshot.allowed_files, "allowed_files"), snapshot.retry_count, snapshot.retry_limit)


def review_recovery(
    repair: RepairRequest, *, candidate_commit: str, checkpoint_reference: str,
    validation: str, reviewer_verdict: str, reviewer_risk: str,
    evidence_sink: Callable[[str, dict[str, Any]], None],
) -> RecoveryReview:
    """Review exact recovery evidence without executing recovery or rollback."""
    if not isinstance(repair, RepairRequest) or not _SHA.fullmatch(candidate_commit) or not _ID.fullmatch(checkpoint_reference):
        raise HarnessRecoveryError("recovery review binding is malformed")
    if validation not in {"PASSED", "FAILED"} or reviewer_verdict not in {"APPROVE", "REJECT", "HUMAN_REQUIRED"} or reviewer_risk not in {"LOW", "MEDIUM", "HIGH"}:
        raise HarnessRecoveryError("recovery validation or review result is invalid")
    accepted = validation == "PASSED" and reviewer_verdict == "APPROVE" and reviewer_risk == "LOW"
    status = "RECOVERED" if accepted else "ESCALATED"
    reference = f"fw-evid://{repair.tenant_id}/{repair.task_id}/{repair.repair_id}"
    result = RecoveryReview(repair.repair_id, repair.tenant_id, repair.task_id, candidate_commit, checkpoint_reference, validation, reviewer_verdict, reviewer_risk, status, reference)
    if not callable(evidence_sink):
        raise HarnessRecoveryError("canonical Evidence sink is unavailable")
    try:
        evidence_sink("fw_harness_recovery_review", asdict(result))
    except Exception as exc:
        raise HarnessRecoveryError("recovery review Evidence write failed") from exc
    return result
