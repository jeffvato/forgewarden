from swarm.android_fixtures import ANDROID_SOURCE, AndroidFixtureDenied, adapt_android_record, ingest_android_batch, ingest_android_fixture
from swarm.normalized_events import NormalizedEventStore
from swarm.endpoint_fixtures import EndpointFixtureDenied
import pytest


def _record(**overrides):
    record = {
        "event_id": "android-1", "tenant_id": "tenant-a", "device_id": "phone-1",
        "observed_at_epoch": 100, "event_type": "APP_STATE", "package_name": "com.example.app",
        "app_label": "Example", "version_name": "1.2.3", "version_code": "123",
        "permissions": ["android.permission.INTERNET"], "related_indicators": [], "evidence_ref": "fixture-ref",
    }
    record.update(overrides)
    return record


def test_android_fixture_maps_identity_permissions_and_uses_canonical_store():
    events = []
    store = NormalizedEventStore(lambda *args: events.append(args))
    observation = ingest_android_fixture(store, _record(), tenant_id="tenant-a", device_id="phone-1", now_epoch=150)
    assert observation.source == ANDROID_SOURCE
    assert dict(observation.metadata)["package_name"] == "com.example.app"
    assert dict(observation.metadata)["permissions"] == "android.permission.INTERNET"
    assert observation.mode == "DRY_RUN" and observation.action == "DETECT_ONLY"
    assert events[0][0] == "endpoint_event_admitted"


def test_android_fixture_rejects_cross_tenant_and_permission_overflow():
    try:
        adapt_android_record(_record(), tenant_id="tenant-b", device_id="phone-1")
    except AndroidFixtureDenied as exc:
        assert exc.reason == "TENANT_OR_DEVICE_MISMATCH"
    else:
        raise AssertionError("cross-tenant fixture accepted")
    try:
        adapt_android_record(_record(permissions=[f"p{i}" for i in range(65)]), tenant_id="tenant-a", device_id="phone-1")
    except AndroidFixtureDenied as exc:
        assert exc.reason == "PERMISSIONS_INVALID"
    else:
        raise AssertionError("oversized permission list accepted")


def test_android_fixture_rejects_missing_or_extra_fields():
    missing = _record()
    missing.pop("evidence_ref")
    with pytest.raises(AndroidFixtureDenied, match="RECORD_INVALID"):
        adapt_android_record(missing, tenant_id="tenant-a", device_id="phone-1")
    with pytest.raises(AndroidFixtureDenied, match="RECORD_INVALID"):
        adapt_android_record(_record(unexpected="value"), tenant_id="tenant-a", device_id="phone-1")


def test_android_fixture_rejects_invalid_event_type():
    with pytest.raises(AndroidFixtureDenied, match="EVENT_TYPE_INVALID"):
        adapt_android_record(_record(event_type="PROCESS_START"), tenant_id="tenant-a", device_id="phone-1")


def test_android_fixture_rejects_empty_or_malformed_permissions():
    for permissions in ([], [""], [None]):
        with pytest.raises(AndroidFixtureDenied, match="PERMISSIONS_INVALID"):
            adapt_android_record(_record(permissions=permissions), tenant_id="tenant-a", device_id="phone-1")


def test_android_fixture_rejects_invalid_store():
    with pytest.raises(AndroidFixtureDenied, match="STORE_INVALID"):
        ingest_android_fixture(object(), _record(), tenant_id="tenant-a", device_id="phone-1", now_epoch=150)


def test_android_batch_is_deterministic_and_atomically_admitted():
    events = []
    store = NormalizedEventStore(lambda *args: events.append(args))
    records = [_record(event_id="later", observed_at_epoch=120), _record(event_id="earlier", observed_at_epoch=110)]
    admitted = ingest_android_batch(store, records, tenant_id="tenant-a", device_id="phone-1", now_epoch=150)
    assert tuple(item.event_id for item in admitted) == ("earlier", "later")
    assert events[-1][0] == "endpoint_events_batch_admitted"
    assert events[-1][1]["mode"] == "DRY_RUN" and events[-1][1]["action"] == "DETECT_ONLY"


def test_android_batch_rejects_duplicate_and_over_cap_inputs():
    store = NormalizedEventStore(lambda *_args: None)
    with pytest.raises(AndroidFixtureDenied, match="EVENT_ID_DUPLICATE"):
        ingest_android_batch(store, [_record(), _record()], tenant_id="tenant-a", device_id="phone-1", now_epoch=150)
    with pytest.raises(AndroidFixtureDenied, match="BATCH_INVALID"):
        ingest_android_batch(store, [_record(event_id=f"event-{i}") for i in range(129)], tenant_id="tenant-a", device_id="phone-1", now_epoch=150)


def test_android_batch_preserves_tenant_and_queue_fail_closed():
    store = NormalizedEventStore(lambda *_args: None, max_queued_events_per_device=1)
    ingest_android_batch(store, [_record()], tenant_id="tenant-a", device_id="phone-1", now_epoch=150)
    with pytest.raises(EndpointFixtureDenied, match="EVENT_QUEUE_FULL"):
        ingest_android_batch(store, [_record(event_id="next")], tenant_id="tenant-a", device_id="phone-1", now_epoch=150)
