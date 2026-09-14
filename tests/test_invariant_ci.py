import pytest

from swarm.invariant_ci import validate_manifest, run
from swarm.policy_gate import CORE_INVARIANTS, PolicyInvariantError


def test_validator_accepts_canonical_manifest():
    assert validate_manifest() == CORE_INVARIANTS
    assert run() == 0


@pytest.mark.parametrize("manifest", [(), CORE_INVARIANTS[:-1], CORE_INVARIANTS + (CORE_INVARIANTS[0],)])
def test_validator_rejects_empty_partial_and_duplicate_manifests(manifest):
    with pytest.raises(PolicyInvariantError):
        validate_manifest(manifest)
