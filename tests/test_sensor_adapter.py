import pytest

from swarm.endpoint_fixtures import EndpointFixtureDenied
from swarm.normalized_events import NormalizedEventStore
from swarm.sensor_adapter import DryRunSensorPipeline, SensorAdapterDenied, adapt_record


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


def test_adapter_maps_and_admits_windows_record_through_same_canonical_owner():
    record = _record(source="WINDOWS_SENSOR")
    fixture = adapt_record(record, source="WINDOWS_SENSOR")
    observation = NormalizedEventStore(lambda *_args: None).admit_fixture(
        fixture, tenant_id="tenant-a", device_id="device-a", source="WINDOWS_SENSOR", now_epoch=150,
    )
    assert observation.source == "WINDOWS_SENSOR"


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


@pytest.mark.parametrize("record", [None, _record().copy() | {"evidence_ref": None}, _record().copy() | {"process_ancestry": None}, _record().copy() | {"related_indicators": None}])
def test_adapter_rejects_non_mapping_or_missing_required_passthrough(record):
    with pytest.raises(SensorAdapterDenied, match="RECORD_INVALID"):
        adapt_record(record, source="LINUX_SENSOR")


def test_adapter_preserves_canonical_fail_closed_validation():
    value = adapt_record(_record(), source="LINUX_SENSOR")
    value["tenant_id"] = "tenant-b"
    with pytest.raises(EndpointFixtureDenied, match="TENANT_OR_DEVICE_MISMATCH"):
        NormalizedEventStore(lambda *_args: None).admit_fixture(value, tenant_id="tenant-a", device_id="device-a", source="LINUX_SENSOR", now_epoch=150)


def test_dry_run_pipeline_composes_adapter_and_canonical_store_for_windows_and_linux():
    events = []
    pipeline = DryRunSensorPipeline(NormalizedEventStore(lambda *args: events.append(args)))
    linux = pipeline.ingest_record(
        _record(event_type="PROCESS_START"), source="LINUX_SENSOR",
        tenant_id="tenant-a", device_id="device-a", now_epoch=150,
    )
    windows_record = _record(source="WINDOWS_SENSOR", event_type="FILE_LIFECYCLE") | {"event_id": "event-2"}
    windows = pipeline.ingest_record(
        windows_record, source="WINDOWS_SENSOR",
        tenant_id="tenant-a", device_id="device-a", now_epoch=150,
    )
    assert [item.source for item in (linux, windows)] == ["LINUX_SENSOR", "WINDOWS_SENSOR"]
    assert all(item.mode == "DRY_RUN" and item.action == "DETECT_ONLY" for item in (linux, windows))
    assert [event[0] for event in events] == ["endpoint_event_admitted", "endpoint_event_admitted"]


def test_dry_run_pipeline_batch_is_atomic_on_adapter_or_store_denial():
    events = []
    pipeline = DryRunSensorPipeline(NormalizedEventStore(lambda *args: events.append(args), max_queued_events_per_device=2))
    records = [_record(), _record() | {"event_id": "event-2"}]
    admitted = pipeline.ingest_batch(
        records, source="LINUX_SENSOR", tenant_id="tenant-a", device_id="device-a", now_epoch=150,
    )
    assert [item.event_id for item in admitted] == ["event-1", "event-2"]
    with pytest.raises(EndpointFixtureDenied, match="EVENT_QUEUE_FULL"):
        pipeline.ingest_batch(
            [_record() | {"event_id": "event-3"}], source="LINUX_SENSOR", tenant_id="tenant-a", device_id="device-a", now_epoch=150,
        )
    assert len(events) == 1
    with pytest.raises(SensorAdapterDenied, match="EVENT_ID_DUPLICATE"):
        pipeline.ingest_batch(
            [_record() | {"event_id": "event-4"}, _record() | {"event_id": "event-4"}], source="LINUX_SENSOR", tenant_id="tenant-a", device_id="device-a", now_epoch=150,
        )
    assert len(events) == 1


def test_dry_run_pipeline_exposes_bounded_deterministic_resource_metrics():
    pipeline = DryRunSensorPipeline(NormalizedEventStore(lambda *_args: None, max_queued_events_per_device=3))
    pipeline.ingest_record(
        _record(), source="LINUX_SENSOR", tenant_id="tenant-a", device_id="device-a", now_epoch=150,
    )
    pipeline.ingest_batch(
        [_record() | {"event_id": "event-2"}, _record() | {"event_id": "event-3"}],
        source="LINUX_SENSOR", tenant_id="tenant-a", device_id="device-a", now_epoch=150,
    )
    with pytest.raises(EndpointFixtureDenied, match="EVENT_QUEUE_FULL"):
        pipeline.ingest_record(
            _record() | {"event_id": "event-4"}, source="LINUX_SENSOR",
            tenant_id="tenant-a", device_id="device-a", now_epoch=150,
        )
    with pytest.raises(SensorAdapterDenied, match="EVENT_TYPE_INVALID"):
        pipeline.ingest_record(
            _record() | {"event_id": "event-5", "event_type": "UNKNOWN"}, source="LINUX_SENSOR",
            tenant_id="tenant-a", device_id="device-a", now_epoch=150,
        )

    metrics = pipeline.metrics()
    assert metrics.accepted_records == 3
    assert metrics.accepted_batches == 1
    assert metrics.rejected_records == 2
    assert metrics.rejected_batches == 0
    assert metrics.peak_batch_size == 2
    assert metrics.peak_queued_events == 3
    assert metrics.mode == "DRY_RUN"
    assert metrics.action == "DETECT_ONLY"
