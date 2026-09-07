import pytest
from concurrent.futures import ThreadPoolExecutor

from swarm.endpoint_fixtures import EndpointFixtureDenied
from swarm.normalized_events import MAX_QUEUED_EVENTS_PER_DEVICE, NormalizedEventStore


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


def test_normalized_event_store_peek_is_retry_safe_and_acknowledges_before_removal():
    events = []
    store = NormalizedEventStore(lambda *args: events.append(args))
    admitted = store.admit_fixture(_fixture(), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    assert store.peek_next(tenant_id="tenant-a", device_id="device-a") == admitted
    assert store.acknowledge(admitted) == admitted
    assert events[-1][0] == "endpoint_event_acknowledged"
    assert store.peek_next(tenant_id="tenant-a", device_id="device-a") is None


def test_normalized_event_store_pending_snapshot_is_bounded_fifo_and_non_mutating():
    store = NormalizedEventStore(lambda *_args: None, max_queued_events_per_device=3)
    first = store.admit_fixture(_fixture("event-1"), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    second = store.admit_fixture(_fixture("event-2"), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    third = store.admit_fixture(_fixture("event-3"), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    assert store.pending_events(tenant_id="tenant-a", device_id="device-a", limit=2) == (first, second)
    assert store.queued_count(tenant_id="tenant-a", device_id="device-a") == 3
    assert store.pending_events(tenant_id="tenant-b", device_id="device-a") == ()
    assert store.dequeue(tenant_id="tenant-a", device_id="device-a") == first
    assert store.pending_events(tenant_id="tenant-a", device_id="device-a") == (second, third)


def test_normalized_event_store_acknowledge_batch_replays_exact_fifo_prefix():
    events = []
    store = NormalizedEventStore(lambda *args: events.append(args), max_queued_events_per_device=3)
    first = store.admit_fixture(_fixture("event-1"), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    second = store.admit_fixture(_fixture("event-2"), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    third = store.admit_fixture(_fixture("event-3"), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    assert store.acknowledge_batch((first, second)) == (first, second)
    assert events[-1][0] == "endpoint_events_batch_acknowledged"
    assert store.pending_events(tenant_id="tenant-a", device_id="device-a") == (third,)


def test_normalized_event_store_acknowledge_batch_rejects_non_prefix_without_mutation():
    store = NormalizedEventStore(lambda *_args: None)
    first = store.admit_fixture(_fixture("event-1"), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    second = store.admit_fixture(_fixture("event-2"), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    with pytest.raises(EndpointFixtureDenied, match="EVENT_NOT_QUEUE_PREFIX"):
        store.acknowledge_batch((second,))
    assert store.pending_events(tenant_id="tenant-a", device_id="device-a") == (first, second)


def test_normalized_event_store_acknowledge_batch_evidence_failure_retains_prefix():
    calls = []
    def audit(*args):
        calls.append(args)
        if args[0] == "endpoint_events_batch_acknowledged":
            raise OSError("sink unavailable")
    store = NormalizedEventStore(audit)
    first = store.admit_fixture(_fixture("event-1"), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    second = store.admit_fixture(_fixture("event-2"), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    with pytest.raises(EndpointFixtureDenied, match="EVIDENCE_WRITE_FAILED"):
        store.acknowledge_batch((first, second))
    assert store.pending_events(tenant_id="tenant-a", device_id="device-a") == (first, second)


@pytest.mark.parametrize("limit", [0, -1, MAX_QUEUED_EVENTS_PER_DEVICE + 1, True, "2"])
def test_normalized_event_store_rejects_unbounded_pending_snapshot_limit(limit):
    store = NormalizedEventStore(lambda *_args: None)
    with pytest.raises(EndpointFixtureDenied, match="EVENT_SNAPSHOT_LIMIT_INVALID"):
        store.pending_events(tenant_id="tenant-a", device_id="device-a", limit=limit)


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


def test_normalized_event_store_ack_evidence_failure_retains_event_for_retry():
    calls = []
    def audit(*args):
        calls.append(args)
        if args[0] == "endpoint_event_acknowledged":
            raise OSError("sink unavailable")

    store = NormalizedEventStore(audit)
    admitted = store.admit_fixture(_fixture(), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    with pytest.raises(EndpointFixtureDenied, match="EVIDENCE_WRITE_FAILED"):
        store.acknowledge(admitted)
    assert store.peek_next(tenant_id="tenant-a", device_id="device-a") == admitted


def test_normalized_event_store_ack_requires_current_tenant_device_queue_head():
    store = NormalizedEventStore(lambda *_args: None)
    admitted = store.admit_fixture(_fixture(), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    with pytest.raises(EndpointFixtureDenied, match="EVENT_NOT_QUEUE_HEAD"):
        store.acknowledge(type(admitted)(admitted.event_id, "tenant-b", admitted.device_id, admitted.observed_at_epoch, admitted.event_type, admitted.source, admitted.metadata, admitted.process_ancestry, admitted.related_indicators, admitted.evidence_ref))


def test_normalized_event_store_concurrent_dequeue_has_one_atomic_consumer():
    store = NormalizedEventStore(lambda *_args: None)
    admitted = store.admit_fixture(_fixture(), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: store.dequeue(tenant_id="tenant-a", device_id="device-a"), (0, 1)))
    assert [result for result in results if result is not None] == [admitted]
    assert store.queued_count(tenant_id="tenant-a", device_id="device-a") == 0


def test_normalized_event_store_caps_duplicate_tombstones_per_device():
    store = NormalizedEventStore(lambda *_args: None, max_queued_events_per_device=1024)
    for index in range(1024):
        store.admit_fixture(_fixture(f"event-{index}"), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
        assert store.dequeue(tenant_id="tenant-a", device_id="device-a") is not None
    with pytest.raises(EndpointFixtureDenied, match="EVENT_ID_CAPACITY"):
        store.admit_fixture(_fixture("event-over-cap"), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
