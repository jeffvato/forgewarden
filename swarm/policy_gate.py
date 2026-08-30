"""Immutable, read-only safety invariant contract for ForgeWarden Core."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


class PolicyInvariantError(ValueError):
    """Raised when safety evidence cannot prove the required invariants."""


SAFE_MODE = "DRY_RUN"
DEPLOYMENT_DISABLED = "DISABLED"
KILL_SWITCH_ENGAGED = "ENGAGED"
KILL_SWITCH_CLEARED_FOR_DRY_RUN = "CLEARED_FOR_DRY_RUN"


def _policy_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise PolicyInvariantError(f"{field} must be a non-empty bounded string")
    return value.strip()


@dataclass(frozen=True)
class PolicyContext:
    """The stable, tenant-bound input to deterministic authorization policy."""

    tenant_id: str
    subject_agent_id: str
    capability: str
    resource: str
    action_class: str
    policy_version: str

    def __post_init__(self) -> None:
        for field in ("tenant_id", "subject_agent_id", "capability", "resource", "action_class", "policy_version"):
            object.__setattr__(self, field, _policy_text(getattr(self, field), field))


@dataclass(frozen=True)
class PolicyRule:
    """An exact, versioned authorization allow rule; everything else is denied."""

    tenant_id: str
    capability: str
    resource: str
    action_class: str
    policy_version: str

    def __post_init__(self) -> None:
        for field in ("tenant_id", "capability", "resource", "action_class", "policy_version"):
            object.__setattr__(self, field, _policy_text(getattr(self, field), field))


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise PolicyInvariantError("policy decision allowed must be boolean")
        object.__setattr__(self, "reason", _policy_text(self.reason, "reason"))


class DeterministicPolicy:
    """Canonical fail-closed policy evaluator for explicit ASOC allow rules."""

    def __init__(self, rules: tuple[PolicyRule, ...] | list[PolicyRule]):
        if not isinstance(rules, (tuple, list)) or not all(isinstance(rule, PolicyRule) for rule in rules):
            raise PolicyInvariantError("policy rules must be PolicyRule values")
        self._rules = frozenset(rules)

    def evaluate(self, context: PolicyContext) -> PolicyDecision:
        if not isinstance(context, PolicyContext):
            raise PolicyInvariantError("policy context is invalid")
        matches = any(
            rule.tenant_id == context.tenant_id
            and rule.capability == context.capability
            and rule.resource == context.resource
            and rule.action_class == context.action_class
            and rule.policy_version == context.policy_version
            for rule in self._rules
        )
        return PolicyDecision(matches, "RULE_MATCH" if matches else "RULE_NOT_FOUND")


def validate_safety_evidence(
    evidence: Mapping[str, Any],
    *,
    require_kill_switch: bool,
) -> dict[str, str]:
    """Validate and normalize safety evidence without changing external state.

    ``require_kill_switch=False`` is only for read-only status reporting, where
    a cleared dry-run switch is reported as evidence rather than authorized.
    Admission callers must require the engaged switch.
    """
    if not isinstance(evidence, Mapping):
        raise PolicyInvariantError("safety invariant evidence must be a mapping")
    required = {"mode", "deployment", "kill_switch"}
    missing = sorted(required - evidence.keys())
    if missing:
        raise PolicyInvariantError(f"missing safety invariant evidence: {', '.join(missing)}")

    mode = evidence["mode"]
    deployment = evidence["deployment"]
    kill_switch = evidence["kill_switch"]
    if not all(isinstance(value, str) for value in (mode, deployment, kill_switch)):
        raise PolicyInvariantError("safety invariant evidence must use string values")
    if mode != SAFE_MODE:
        raise PolicyInvariantError("DRY_RUN mode is required")
    if deployment != DEPLOYMENT_DISABLED:
        raise PolicyInvariantError("deployment must remain disabled")
    allowed_kill_switch = {KILL_SWITCH_ENGAGED}
    if not require_kill_switch:
        allowed_kill_switch.add(KILL_SWITCH_CLEARED_FOR_DRY_RUN)
    if kill_switch not in allowed_kill_switch:
        raise PolicyInvariantError("kill switch state is not safe for this operation")
    if "mutation_allowed" in evidence and evidence["mutation_allowed"] is not False:
        raise PolicyInvariantError("mutation must remain disallowed")

    return {
        "mode": mode,
        "deployment": deployment,
        "kill_switch": kill_switch,
    }
