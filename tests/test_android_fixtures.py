from swarm.android_fixtures import ANDROID_SOURCE, AndroidFixtureDenied, adapt_android_record, ingest_android_fixture
from swarm.normalized_events import NormalizedEventStore


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
