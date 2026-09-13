from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError

import pytest

from swarm.operations import (
    MAX_COMPONENTS,
    OperationalHealthRegistry,
    OperationsContractError,
    validate_operational_snapshot,
)


def component(**changes):
    value = {
        "component_id": "endpoint-pipeline",
        "tenant_id": "tenant-a",
        "state": "HEALTHY",
        "queue_depth": 2,
        "queue_limit": 10,
        "budget_used": 3,
        "budget_limit": 10,
    }
    value.update(changes)
    return value


def snapshot(**changes):
    value = {
        "schema_version": "1",
        "snapshot_id": "ops-snapshot-1",
        "tenant_id": "tenant-a",
        "observed_at_epoch": 100,
        "expires_at_epoch": 200,
        "components": [component()],
        "mode": "DRY_RUN",
        "deployment": "DISABLED",
        "kill_switch": "ENGAGED",
    }
    value.update(changes)
    return value


def registry(evidence=None):
    events = []
    sink = evidence or (
        lambda event, payload: events.append((event, payload))
        or "fw-evid/tenant-a/ops/snapshot-1"
    )
    return OperationalHealthRegistry(sink), events


def test_health_projection_is_evidence_first_immutable_and_authority_free():
    store, events = registry()
    result = store.project(validate_operational_snapshot(snapshot()), tenant_id="tenant-a", now_epoch=150)
    assert result.health == "HEALTHY"
    assert result.component_count == result.healthy_count == 1
    assert result.peak_queue_basis_points == 2000
    assert result.peak_budget_basis_points == 3000
    assert result.mode == "DRY_RUN" and result.deployment == "DISABLED"
    assert result.action == "OBSERVE_ONLY"
    assert result.recovery_invoked is result.authority_granted is False
    assert events[0][0] == "fw_ops_health_projected"
    assert events[0][1]["authority_granted"] is False
    assert "component_id" not in events[0][1]
    with pytest.raises(FrozenInstanceError):
        result.health = "UNHEALTHY"


@pytest.mark.parametrize(
    "components,expected",
    [
        ([component(queue_depth=8)], "DEGRADED"),
        ([component(budget_used=10)], "UNHEALTHY"),
        ([component(state="UNAVAILABLE")], "DEGRADED"),
        ([component(state="UNHEALTHY")], "UNHEALTHY"),
    ],
)
def test_health_classification_is_deterministic(components, expected):
    store, _ = registry()
    result = store.project(
        validate_operational_snapshot(snapshot(components=components)),
        tenant_id="tenant-a",
        now_epoch=150,
    )
    assert result.health == expected


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": "2"},
        {"snapshot_id": ""},
        {"snapshot_id": "api_key=secret-value"},
        {"tenant_id": "Tenant A"},
        {"observed_at_epoch": True},
        {"expires_at_epoch": 100},
        {"components": []},
        {"components": [component(), component()]},
        {"mode": "LIVE"},
        {"deployment": "ENABLED"},
        {"kill_switch": "CLEARED_FOR_DRY_RUN"},
        {"extra": "field"},
    ],
)
def test_snapshot_rejects_malformed_secret_duplicate_and_unsafe_input(change):
    with pytest.raises(OperationsContractError):
        validate_operational_snapshot(snapshot(**change))


def test_snapshot_rejects_cross_tenant_excessive_and_invalid_component_input():
    with pytest.raises(OperationsContractError, match="cross-tenant"):
        validate_operational_snapshot(snapshot(components=[component(tenant_id="tenant-b")]))
    with pytest.raises(OperationsContractError, match="excessive"):
        validate_operational_snapshot(
            snapshot(components=[component(component_id=f"component-{index}") for index in range(MAX_COMPONENTS + 1)])
        )
    with pytest.raises(OperationsContractError, match="field set"):
        validate_operational_snapshot(snapshot(components=[component() | {"raw_log": "content"}]))
    with pytest.raises(OperationsContractError, match="exceeds"):
        validate_operational_snapshot(snapshot(components=[component(queue_depth=11)]))


def test_projection_rejects_cross_tenant_stale_replay_and_evidence_failure():
    value = validate_operational_snapshot(snapshot())
    store, _ = registry()
    with pytest.raises(OperationsContractError, match="binding"):
        store.project(value, tenant_id="tenant-b", now_epoch=150)
    with pytest.raises(OperationsContractError, match="stale"):
        store.project(value, tenant_id="tenant-a", now_epoch=200)
    store.project(value, tenant_id="tenant-a", now_epoch=150)
    with pytest.raises(OperationsContractError, match="replay"):
        store.project(value, tenant_id="tenant-a", now_epoch=150)

    failed, _ = registry(evidence=lambda *_args: (_ for _ in ()).throw(OSError("offline")))
    with pytest.raises(OperationsContractError, match="Evidence write failed"):
        failed.project(value, tenant_id="tenant-a", now_epoch=150)

    foreign, _ = registry(evidence=lambda *_args: "fw-evid/tenant-b/ops/snapshot-1")
    with pytest.raises(OperationsContractError, match="Evidence reference"):
        foreign.project(value, tenant_id="tenant-a", now_epoch=150)


def test_evidence_failure_does_not_poison_retry():
    calls = []
    def sink(_event, _payload):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("temporary")
        return "fw-evid/tenant-a/ops/snapshot-1"
    store, _ = registry(evidence=sink)
    value = validate_operational_snapshot(snapshot())
    with pytest.raises(OperationsContractError, match="Evidence write failed"):
        store.project(value, tenant_id="tenant-a", now_epoch=150)
    assert store.project(value, tenant_id="tenant-a", now_epoch=150).health == "HEALTHY"


def test_concurrent_duplicate_writes_evidence_once():
    calls = []
    def sink(_event, _payload):
        calls.append(1)
        return "fw-evid/tenant-a/ops/snapshot-1"
    store, _ = registry(evidence=sink)
    value = validate_operational_snapshot(snapshot())
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(store.project, value, tenant_id="tenant-a", now_epoch=150) for _ in range(2)]
    outcomes = []
    for future in futures:
        try:
            outcomes.append(future.result().health)
        except OperationsContractError as exc:
            outcomes.append(str(exc))
    assert outcomes.count("HEALTHY") == 1
    assert sum("replay denied" in outcome for outcome in outcomes) == 1
    assert len(calls) == 1
