from dataclasses import replace

import pytest

from swarm.operations import OperationalHealthProjection, OperationsContractError
from swarm.operations_capacity import CapacityAssessmentRegistry, CapacityPolicy


def projection(index, *, health="HEALTHY", queue=1000, budget=1000, tenant="tenant-a"):
    return OperationalHealthProjection(
        f"snapshot-{index}", tenant, health, 1, int(health == "HEALTHY"),
        int(health == "DEGRADED"), int(health == "UNHEALTHY"),
        int(health == "UNAVAILABLE"), queue, budget,
        f"fw-evid/{tenant}/ops/snapshot-{index}", 100 + index,
    )


def registry(policy=CapacityPolicy(), evidence=None):
    events = []
    sink = evidence or (
        lambda event, payload: events.append((event, payload))
        or "fw-evid/tenant-a/ops/capacity-1"
    )
    return CapacityAssessmentRegistry(sink, policy), events


@pytest.mark.parametrize(
    "items,expected",
    [
        ((projection(1),), "NORMAL"),
        ((projection(1, queue=8000),), "ELEVATED"),
        ((projection(1, queue=8000), projection(2, budget=8000)), "SUSTAINED"),
        ((projection(1, health="DEGRADED"), projection(2)), "ELEVATED"),
        ((projection(1, health="UNHEALTHY"),), "CRITICAL"),
        ((projection(1, budget=10000),), "CRITICAL"),
    ],
)
def test_capacity_pressure_classification(items, expected):
    store, events = registry()
    result = store.assess("capacity-1", "tenant-a", items, now_epoch=110, max_age_seconds=20)
    assert result.pressure == expected
    assert result.action == "OBSERVE_ONLY"
    assert result.throttle_executed is result.recovery_invoked is result.authority_granted is False
    assert events[0][0] == "fw_ops_capacity_assessed"
    assert "snapshot_id" not in events[0][1]


def test_capacity_policy_is_bounded_and_configurable():
    policy = CapacityPolicy(6000, 9000, 3)
    store, _ = registry(policy)
    items = tuple(projection(index, queue=6000) for index in range(1, 4))
    assert store.assess("capacity-1", "tenant-a", items, now_epoch=110, max_age_seconds=20).pressure == "SUSTAINED"
    for values in ((0, 9000, 2), (9000, 9000, 2), (8000, 10001, 2)):
        with pytest.raises(OperationsContractError):
            CapacityPolicy(*values)


@pytest.mark.parametrize(
    "items,match",
    [
        ((projection(1, tenant="tenant-b"),), "binding"),
        ((replace(projection(1), authority_granted=True),), "binding"),
        ((replace(projection(1), deployment="ENABLED"),), "binding"),
        ((replace(projection(1), evidence_reference="fw-evid/tenant-b/ops/1"),), "binding"),
        ((projection(2), projection(1)), "chronology"),
        ((projection(1), projection(1)), "chronology"),
    ],
)
def test_capacity_rejects_cross_tenant_unsafe_and_invalid_chronology(items, match):
    store, _ = registry()
    with pytest.raises(OperationsContractError, match=match):
        store.assess("capacity-1", "tenant-a", items, now_epoch=110, max_age_seconds=20)


def test_capacity_rejects_stale_future_replay_and_malformed_limits():
    store, _ = registry()
    item = (projection(1),)
    with pytest.raises(OperationsContractError, match="stale"):
        store.assess("capacity-1", "tenant-a", item, now_epoch=130, max_age_seconds=20)
    with pytest.raises(OperationsContractError, match="stale"):
        store.assess("capacity-1", "tenant-a", item, now_epoch=100, max_age_seconds=20)
    with pytest.raises(OperationsContractError, match="malformed"):
        store.assess("capacity-1", "tenant-a", item, now_epoch=110, max_age_seconds=0)
    store.assess("capacity-1", "tenant-a", item, now_epoch=110, max_age_seconds=20)
    with pytest.raises(OperationsContractError, match="replay"):
        store.assess("capacity-1", "tenant-a", item, now_epoch=110, max_age_seconds=20)


def test_capacity_evidence_failure_and_foreign_reference_fail_closed_and_retry():
    calls = []
    def sink(_event, _payload):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("offline")
        return "fw-evid/tenant-a/ops/capacity-1"
    store, _ = registry(evidence=sink)
    item = (projection(1),)
    with pytest.raises(OperationsContractError, match="Evidence write failed"):
        store.assess("capacity-1", "tenant-a", item, now_epoch=110, max_age_seconds=20)
    assert store.assess("capacity-1", "tenant-a", item, now_epoch=110, max_age_seconds=20).pressure == "NORMAL"

    foreign, _ = registry(evidence=lambda *_args: "fw-evid/tenant-b/ops/capacity-1")
    with pytest.raises(OperationsContractError, match="Evidence reference"):
        foreign.assess("capacity-1", "tenant-a", item, now_epoch=110, max_age_seconds=20)
