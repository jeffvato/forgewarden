import pytest

from swarm.endpoint_fixtures import EndpointFixtureDenied
from swarm.normalized_events import NormalizedEventStore


def _fixture(event_id="event-1", tenant_id="tenant-a", device_id="device-a"):
    return {
        "event_id": event_id, "tenant_id": tenant_id, "device_id": device_id,
        "observed_at_epoch": 100, "event_type": "PROCESS_START", "source": "LINUX_SENSOR",
        "process": {"pid": "42"}, "evidence_ref": "evidence-1",
        "process_ancestry": [], "related_indicators": [],
    }


def test_normalized_event_store_writes_evidence_before_enqueue_and_is_tenant_bound():
    events = []
    store = NormalizedEventStore(lambda *args: events.append(args), max_queued_events_per_device=2)
    observation = store.admit_fixture(_fixture(), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    assert observation.mode == "DRY_RUN"
    assert observation.action == "DETECT_ONLY"
    assert events[0][0] == "endpoint_event_admitted"
    assert store.queued_count(tenant_id="tenant-a", device_id="device-a") == 1
    assert store.queued_count(tenant_id="tenant-b", device_id="device-a") == 0


def test_normalized_event_store_denies_duplicate_event_ids_before_second_evidence():
    events = []
    store = NormalizedEventStore(lambda *args: events.append(args), max_queued_events_per_device=2)
    store.admit_fixture(_fixture(), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    with pytest.raises(EndpointFixtureDenied, match="EVENT_ID_DUPLICATE"):
        store.admit_fixture(_fixture(), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    assert len(events) == 1


def test_normalized_event_store_enforces_queue_backpressure_and_releases_queue_slot():
    store = NormalizedEventStore(lambda *_args: None, max_queued_events_per_device=1)
    store.admit_fixture(_fixture("event-1"), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    with pytest.raises(EndpointFixtureDenied, match="EVENT_QUEUE_FULL"):
        store.admit_fixture(_fixture("event-2"), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    assert store.dequeue(tenant_id="tenant-a", device_id="device-a").event_id == "event-1"
    assert store.admit_fixture(_fixture("event-2"), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150).event_id == "event-2"


def test_normalized_event_store_fails_closed_on_evidence_failure_without_enqueue():
    def fail(*_args):
        raise OSError("sink unavailable")

    store = NormalizedEventStore(fail)
    with pytest.raises(EndpointFixtureDenied, match="EVIDENCE_WRITE_FAILED"):
        store.admit_fixture(_fixture(), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    assert store.queued_count(tenant_id="tenant-a", device_id="device-a") == 0
