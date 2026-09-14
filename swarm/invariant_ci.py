"""Deterministic CI validation for ForgeWarden safety invariants."""
from .policy_gate import CORE_INVARIANTS, DEPLOYMENT_DISABLED, KILL_SWITCH_ENGAGED, SAFE_MODE, PolicyInvariantError, validate_invariant_manifest, validate_safety_evidence

def validate_manifest(invariants=CORE_INVARIANTS):
    validated = validate_invariant_manifest(invariants)
    if len(validated) != len(CORE_INVARIANTS):
        raise PolicyInvariantError("invariant manifest count is invalid")
    return validated

def run() -> int:
    try:
        invariants = validate_manifest()
        validate_safety_evidence({"mode": SAFE_MODE, "deployment": DEPLOYMENT_DISABLED, "kill_switch": KILL_SWITCH_ENGAGED, "mutation_allowed": False}, require_kill_switch=True)
    except PolicyInvariantError as exc:
        print(f"invariant validation failed: {exc}")
        return 1
    print(f"validated {len(invariants)} ForgeWarden safety invariants")
    return 0
