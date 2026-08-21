"""Deterministic, evidence-only evaluation of ForgeWarden stop conditions."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path


class StopConditionError(ValueError):
    pass


@dataclass(frozen=True)
class StopContext:
    all_active_work_complete: bool = False
    requires_customer_authority: bool = False
    required_resource_unavailable: bool = False
    safe_independent_work_available: bool = True
    policy_invariant_conflict: bool = False
    repository_unsafe_or_ambiguous: bool = False
    platform_resource_limit: bool = False
    supervisor_terminated: bool = False


@dataclass(frozen=True)
class StopDecision:
    should_stop: bool
    reason: str | None
    first_resume_action: str | None


_REASONS = (
    ("repository_unsafe_or_ambiguous", "UNSAFE_REPOSITORY", "reconstruct a safe repository state before resuming"),
    ("policy_invariant_conflict", "POLICY_INVARIANT_CONFLICT", "resolve the policy conflict without weakening invariants"),
    ("supervisor_terminated", "SUPERVISOR_TERMINATED", "restart under explicit supervisor control"),
    ("requires_customer_authority", "CUSTOMER_AUTHORITY_REQUIRED", "obtain Jeff/Customer Root authorization"),
    ("platform_resource_limit", "PLATFORM_RESOURCE_LIMIT", "restore the required platform resource"),
    ("all_active_work_complete", "ALL_ACTIVE_WORK_COMPLETE", "await explicit activation of further approved work"),
)


def evaluate_stop_conditions(context: StopContext) -> StopDecision:
    """Return one deterministic approved stop decision; ordinary failures never stop work."""
    for attribute, reason, resume in _REASONS:
        if getattr(context, attribute):
            return StopDecision(True, reason, resume)
    if context.required_resource_unavailable and not context.safe_independent_work_available:
        return StopDecision(True, "REQUIRED_RESOURCE_UNAVAILABLE", "restore the required resource or identify safe independent work")
    return StopDecision(False, None, None)


def persist_stop_decision(path: Path, decision: StopDecision) -> None:
    """Atomically persist only a genuine stop decision and its resume action."""
    if not decision.should_stop or not decision.reason or not decision.first_resume_action:
        raise StopConditionError("only complete stop decisions may be persisted")
    path = Path(path)
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise StopConditionError("safe stop-record primitives unavailable")
    if not path.is_absolute() or not path.parent.is_dir() or path.is_symlink():
        raise StopConditionError("stop-record path must be an absolute non-symlink path in an existing directory")
    current = Path(path.anchor)
    for part in path.parent.parts[1:]:
        current /= part
        if current.is_symlink():
            raise StopConditionError("stop-record path contains symlink")
    payload = json.dumps(asdict(decision), sort_keys=True).encode("utf-8")
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
