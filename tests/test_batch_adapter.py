import pytest

from swarm.endpoint_fixtures import EndpointFixtureDenied
from swarm.normalized_events import NormalizedEventStore
from swarm.sensor_adapter import MAX_ADAPTER_BATCH, SensorAdapterDenied, adapt_batch


def _record(event_id="event-1", tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR"):
    return {
        "event_id": event_id, "tenant_id": tenant_id, "device_id": device_id,
        "observed_at_epoch": 100, "event_type": "PROCESS_START", "source": source,
        "metadata": {"pid": "42"}, "process_ancestry": [], "related_indicators": [],
        "evidence_ref": "evidence-1",
    }


def test_batch_preflights_and_admits_atomically_through_canonical_store():
    records = [_record("event-1"), _record("event-2")]
    fixtures = adapt_batch(records, source="LINUX_SENSOR", tenant_id="tenant-a", device_id="device-a")
    events = []
    observations = NormalizedEventStore(lambda *args: events.append(args)).admit_batch(
        fixtures, tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150,
    )
    assert [item.event_id for item in observations] == ["event-1", "event-2"]
    assert events[0][0] == "endpoint_events_batch_admitted"


@pytest.mark.parametrize("records, reason", [
    ([_record("event-1"), _record("event-1")], "EVENT_ID_DUPLICATE"),
    ([_record("event-1", tenant_id="tenant-b")], "TENANT_OR_DEVICE_MISMATCH"),
    ([_record("event-1")] * (MAX_ADAPTER_BATCH + 1), "BATCH_INVALID"),
])
def test_batch_adapter_rejects_duplicate_cross_tenant_and_oversized_input(records, reason):
    with pytest.raises(SensorAdapterDenied, match=reason):
        adapt_batch(records, source="LINUX_SENSOR", tenant_id="tenant-a", device_id="device-a")


def test_batch_admission_preflights_queue_and_preserves_state_on_evidence_failure():
    events = []
    def audit(*args):
        events.append(args)
        raise OSError("sink unavailable")
    store = NormalizedEventStore(audit, max_queued_events_per_device=2)
    fixtures = adapt_batch([_record("event-1"), _record("event-2")], source="LINUX_SENSOR", tenant_id="tenant-a", device_id="device-a")
    with pytest.raises(EndpointFixtureDenied, match="EVIDENCE_WRITE_FAILED"):
        store.admit_batch(fixtures, tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    assert store.queued_count(tenant_id="tenant-a", device_id="device-a") == 0

    healthy = NormalizedEventStore(lambda *_args: None, max_queued_events_per_device=1)
    with pytest.raises(EndpointFixtureDenied, match="EVENT_QUEUE_FULL"):
        healthy.admit_batch(fixtures, tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)


def test_batch_admission_denies_cross_batch_duplicate_and_empty_direct_batch():
    store = NormalizedEventStore(lambda *_args: None)
    fixtures = adapt_batch([_record("event-1")], source="LINUX_SENSOR", tenant_id="tenant-a", device_id="device-a")
    store.admit_batch(fixtures, tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    with pytest.raises(EndpointFixtureDenied, match="EVENT_ID_DUPLICATE"):
        store.admit_batch(fixtures, tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    with pytest.raises(EndpointFixtureDenied, match="BATCH_INVALID"):
        store.admit_batch([], tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)


def test_batch_admission_enforces_direct_canonical_batch_cap():
    store = NormalizedEventStore(lambda *_args: None, max_queued_events_per_device=1024)
    fixtures = adapt_batch([_record(f"event-{index}") for index in range(128)], source="LINUX_SENSOR", tenant_id="tenant-a", device_id="device-a")
    with pytest.raises(EndpointFixtureDenied, match="BATCH_INVALID"):
        store.admit_batch(fixtures + [adapt_batch([_record("event-over")], source="LINUX_SENSOR", tenant_id="tenant-a", device_id="device-a")[0]], tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
