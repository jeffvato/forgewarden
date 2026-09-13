import pytest

from swarm.endpoint_fixtures import EndpointFixtureDenied
from swarm.macos_fixtures import (
    MACOS_SOURCE, MacOSFixtureDenied, adapt_macos_record,
    ingest_macos_batch, ingest_macos_fixture,
)
from swarm.normalized_events import NormalizedEventStore


def _record(**overrides):
    record = {
        "event_id": "mac-1", "tenant_id": "tenant-a", "device_id": "mac-1",
        "observed_at_epoch": 100, "event_type": "PROCESS_START",
        "source": MACOS_SOURCE, "metadata": {"pid": "42", "name": "builder"},
        "process_ancestry": ["launchd"], "related_indicators": [],
        "evidence_ref": "fixture-ref",
    }
    record.update(overrides)
    return record


def test_macos_fixture_uses_canonical_store_and_fixed_authority():
    evidence = []
    store = NormalizedEventStore(lambda *args: evidence.append(args))
    observation = ingest_macos_fixture(
        store, _record(), tenant_id="tenant-a", device_id="mac-1", now_epoch=150,
    )
    assert observation.source == MACOS_SOURCE
    assert dict(observation.metadata) == {"name": "builder", "pid": "42"}
    assert observation.mode == "DRY_RUN" and observation.action == "DETECT_ONLY"
    assert evidence[0][0] == "endpoint_event_admitted"


@pytest.mark.parametrize("record,reason", [
    (_record(source="LINUX_SENSOR"), "SOURCE_MISMATCH"),
    (_record(event_type="UNKNOWN"), "EVENT_TYPE_INVALID"),
    (_record(metadata={}), "METADATA_INVALID"),
    (_record(extra="value"), "RECORD_INVALID"),
])
def test_macos_fixture_rejects_untrusted_shape(record, reason):
    with pytest.raises(MacOSFixtureDenied, match=reason):
        adapt_macos_record(record, tenant_id="tenant-a", device_id="mac-1")


def test_macos_fixture_rejects_cross_tenant_and_invalid_store():
    with pytest.raises(MacOSFixtureDenied, match="TENANT_OR_DEVICE_MISMATCH"):
        adapt_macos_record(_record(), tenant_id="tenant-b", device_id="mac-1")
    with pytest.raises(MacOSFixtureDenied, match="STORE_INVALID"):
        ingest_macos_fixture(object(), _record(), tenant_id="tenant-a", device_id="mac-1", now_epoch=150)


def test_macos_batch_is_ordered_and_atomically_admitted():
    evidence = []
    store = NormalizedEventStore(lambda *args: evidence.append(args))
    admitted = ingest_macos_batch(
        store,
        [_record(event_id="later", observed_at_epoch=120), _record(event_id="earlier", observed_at_epoch=110)],
        tenant_id="tenant-a", device_id="mac-1", now_epoch=150,
    )
    assert tuple(item.event_id for item in admitted) == ("earlier", "later")
    assert len(evidence) == 1
    assert evidence[0][0] == "endpoint_events_batch_admitted"
    assert evidence[0][1]["event_ids"] == ["earlier", "later"]


def test_macos_batch_denies_duplicates_bounds_and_store_pressure():
    store = NormalizedEventStore(lambda *_args: None, max_queued_events_per_device=1)
    with pytest.raises(MacOSFixtureDenied, match="EVENT_ID_DUPLICATE"):
        ingest_macos_batch(store, [_record(), _record()], tenant_id="tenant-a", device_id="mac-1", now_epoch=150)
    with pytest.raises(MacOSFixtureDenied, match="BATCH_INVALID"):
        ingest_macos_batch(store, [], tenant_id="tenant-a", device_id="mac-1", now_epoch=150)
    ingest_macos_fixture(store, _record(), tenant_id="tenant-a", device_id="mac-1", now_epoch=150)
    with pytest.raises(EndpointFixtureDenied, match="EVENT_QUEUE_FULL"):
        ingest_macos_fixture(store, _record(event_id="next"), tenant_id="tenant-a", device_id="mac-1", now_epoch=150)


def test_macos_evidence_failure_leaves_no_queued_event():
    def unavailable(*_args):
        raise RuntimeError("evidence unavailable")

    store = NormalizedEventStore(unavailable)
    with pytest.raises(EndpointFixtureDenied, match="EVIDENCE_WRITE_FAILED"):
        ingest_macos_fixture(store, _record(), tenant_id="tenant-a", device_id="mac-1", now_epoch=150)
    assert store.pending_events(tenant_id="tenant-a", device_id="mac-1") == ()
