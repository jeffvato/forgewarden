import pytest

from swarm.endpoint_fixtures import EndpointFixtureDenied
from swarm.normalized_events import NormalizedEventStore
from swarm.sensor_adapter import SensorAdapterDenied, adapt_record


def _record(source="LINUX_SENSOR", event_type="PROCESS_START"):
    return {
        "event_id": "event-1", "tenant_id": "tenant-a", "device_id": "device-a",
        "observed_at_epoch": 100, "event_type": event_type, "source": source,
        "metadata": {"pid": "42"}, "process_ancestry": [], "related_indicators": [],
        "evidence_ref": "evidence-1",
    }


def test_adapter_maps_explicit_process_and_artifact_records_to_canonical_owner():
    process = adapt_record(_record(), source="LINUX_SENSOR")
    artifact = adapt_record(_record(event_type="FILE_LIFECYCLE"), source="LINUX_SENSOR")
    assert process["process"] == {"pid": "42"}
    assert "artifact" not in process
    assert artifact["artifact"] == {"pid": "42"}
    assert "process" not in artifact
    events = []
    store = NormalizedEventStore(lambda *args: events.append(args))
    admitted = store.admit_fixture(process, tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
    assert admitted.event_id == "event-1"
    assert events[0][0] == "endpoint_event_admitted"


@pytest.mark.parametrize("bad", [
    {"extra": "field"},
    {"source": "WINDOWS_SENSOR"},
])
def test_adapter_rejects_untrusted_shape_or_source_binding(bad):
    value = _record()
    value.update(bad)
    with pytest.raises(SensorAdapterDenied, match="RECORD_INVALID"):
        adapt_record(value, source="LINUX_SENSOR")


def test_adapter_rejects_unknown_event_and_empty_metadata():
    with pytest.raises(SensorAdapterDenied, match="EVENT_TYPE_INVALID"):
        adapt_record(_record(event_type="UNKNOWN"), source="LINUX_SENSOR")
    with pytest.raises(SensorAdapterDenied, match="METADATA_INVALID"):
        adapt_record(_record().copy() | {"metadata": {}}, source="LINUX_SENSOR")


def test_adapter_preserves_canonical_fail_closed_validation():
    value = adapt_record(_record(), source="LINUX_SENSOR")
    value["tenant_id"] = "tenant-b"
    with pytest.raises(EndpointFixtureDenied, match="TENANT_OR_DEVICE_MISMATCH"):
        NormalizedEventStore(lambda *_args: None).admit_fixture(value, tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)
