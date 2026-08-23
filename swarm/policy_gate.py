"""Immutable, read-only safety invariant contract for ForgeWarden Core."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class PolicyInvariantError(ValueError):
    """Raised when safety evidence cannot prove the required invariants."""


SAFE_MODE = "DRY_RUN"
DEPLOYMENT_DISABLED = "DISABLED"
KILL_SWITCH_ENGAGED = "ENGAGED"
KILL_SWITCH_CLEARED_FOR_DRY_RUN = "CLEARED_FOR_DRY_RUN"


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
