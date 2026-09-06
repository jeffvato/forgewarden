import pytest

from swarm.endpoint_fixtures import EndpointFixtureDenied, normalize_fixture


def _fixture(**overrides):
    value = {
        "event_id": "event-1", "tenant_id": "tenant-a", "device_id": "device-a",
        "observed_at_epoch": 100, "event_type": "PROCESS_START", "source": "LINUX_SENSOR", "process": {"pid": "42"},
        "evidence_ref": "evidence-1", "process_ancestry": ["init"], "related_indicators": [],
    }
    value.update(overrides)
    return value


def test_fixture_normalization_is_tenant_bound_and_evidence_first():
    events = []
    observation = normalize_fixture(_fixture(), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150, audit=lambda *args: events.append(args))
    assert observation.mode == "DRY_RUN"
    assert observation.action == "DETECT_ONLY"
    assert observation.source == "LINUX_SENSOR"
    assert events[0][0] == "endpoint_fixture_normalized"


@pytest.mark.parametrize(("field", "value", "reason"), [
    ("tenant_id", "tenant-b", "TENANT_OR_DEVICE_MISMATCH"),
    ("event_type", "UNKNOWN", "EVENT_TYPE_INVALID"),
    ("source", "WINDOWS_SENSOR", "SOURCE_MISMATCH"),
    ("observed_at_epoch", 151, "OBSERVED_AT_INVALID"),
    ("evidence_ref", "", "evidence_ref_INVALID"),
])
def test_fixture_normalization_denies_invalid_boundaries(field, value, reason):
    with pytest.raises(EndpointFixtureDenied, match=reason):
        normalize_fixture(_fixture(**{field: value}), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150, audit=lambda *_args: None)


def test_fixture_normalization_denies_oversized_ancestry_and_evidence_failure():
    with pytest.raises(EndpointFixtureDenied, match="FIXTURE_TOO_LARGE"):
        normalize_fixture(_fixture(untrusted_payload="x" * 70_000), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150, audit=lambda *_args: None)
    with pytest.raises(EndpointFixtureDenied, match="PROCESS_ANCESTRY_INVALID"):
        normalize_fixture(_fixture(process_ancestry=["x"] * 33), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150, audit=lambda *_args: None)
    with pytest.raises(EndpointFixtureDenied, match="EVIDENCE_WRITE_FAILED"):
        normalize_fixture(_fixture(), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150, audit=lambda *_args: (_ for _ in ()).throw(OSError()))


def test_fixture_normalization_denies_unexpected_top_level_key_at_normal_size():
    with pytest.raises(EndpointFixtureDenied, match="FIXTURE_INVALID"):
        normalize_fixture(_fixture(unexpected="ordinary-size"), tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150, audit=lambda *_args: None)
