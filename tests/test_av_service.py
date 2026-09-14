import hashlib

import pytest

from swarm.av_service import AVProtectionService, AVServiceContractError, AVServiceProfile
from swarm.anti_malware import AcceptedCatalogScanner, ScanFinding
from swarm.endpoint_fixtures import EndpointFixtureDenied
from swarm.normalized_events import NormalizedEventStore
from swarm.sensor_adapter import DryRunSensorPipeline


def profile(*, enterprise=True):
    return AVServiceProfile(
        tenant_id="tenant-a", device_id="device-a", platform="WINDOWS",
        enterprise_managed=enterprise,
        tray_mode="STATUS_ONLY" if enterprise else "LIMITED_PREFERENCES",
    )


def test_service_profile_enforces_low_resource_and_tray_policy():
    assert profile().tray_mode == "STATUS_ONLY"
    assert profile(enterprise=False).tray_mode == "LIMITED_PREFERENCES"
    with pytest.raises(AVServiceContractError, match="tray_mode"):
        AVServiceProfile("tenant-a", "device-a", "WINDOWS", True, "LIMITED_PREFERENCES")
    with pytest.raises(AVServiceContractError, match="max_memory_mb"):
        AVServiceProfile("tenant-a", "device-a", "WINDOWS", True, "STATUS_ONLY", max_memory_mb=257)
    with pytest.raises(AVServiceContractError, match="blocking"):
        AVServiceProfile("tenant-a", "device-a", "WINDOWS", True, "STATUS_ONLY", automatic_blocking=True)


def test_service_reuses_canonical_fixture_pipeline_and_exposes_status_only():
    service = AVProtectionService(profile(), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    record = {
        "event_id": "event-1", "tenant_id": "tenant-a", "device_id": "device-a",
        "observed_at_epoch": 10, "event_type": "FILE_LIFECYCLE", "source": "WINDOWS_SENSOR",
        "metadata": {"operation": "CREATE"}, "process_ancestry": [],
        "related_indicators": [], "evidence_ref": "fw-evid/tenant-a/event-1",
    }
    service.ingest(record, source="WINDOWS_SENSOR", now_epoch=10)
    status = service.status()
    assert status["mode"] == "DRY_RUN"
    assert status["action"] == "DETECT_ONLY"
    assert status["automatic_blocking"] is False
    assert status["quarantine_execution"] is False
    assert status["service_control"] == "CENTRAL_ONLY"
    assert status["local_stop_allowed"] is False
    assert status["local_policy_change_allowed"] is False
    assert status["metrics"].accepted_records == 1


def test_service_scan_artifact_requires_canonical_scanner_and_audit():
    service = AVProtectionService(profile(), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    with pytest.raises(AVServiceContractError, match="scanner is invalid"):
        service.scan_artifact(object(), artifact_id="artifact-1", content=b"fixture", report_id="report-1", audit=lambda *_: None, now_epoch=10)
    with pytest.raises(AVServiceContractError, match="scanner is invalid"):
        service.scan_artifact(object(), artifact_id="artifact-1", content=b"fixture", report_id="report-1", audit=None, now_epoch=10)


def test_service_scan_artifact_returns_canonical_dry_run_report_and_records_evidence():
    service = AVProtectionService(profile(), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    scanner = object.__new__(AcceptedCatalogScanner)
    content = b"fixture"
    scanner.scan = lambda **kwargs: ScanFinding(
        tenant_id=kwargs["tenant_id"], artifact_id=kwargs["artifact_id"],
        sha256=hashlib.sha256(kwargs["content"]).hexdigest(), byte_count=len(kwargs["content"]),
        status="CLEAN", signature_ids=(), content_indicator_ids=(), catalog_id="catalog",
        catalog_version="1.0.0", catalog_snapshot_sha256="a" * 64, publishers=("FW Labs",),
    )
    events = []
    report = service.scan_artifact(
        scanner, artifact_id="artifact-1", content=content, report_id="report-1",
        audit=lambda event, evidence: events.append((event, evidence)), now_epoch=10,
    )
    assert report.tenant_id == "tenant-a"
    assert report.status == "CLEAN"
    assert report.mode == "DRY_RUN"
    assert report.action == "DETECT_ONLY"
    assert events[0][0] == "anti_malware_scan_report_created"
    assert events[0][1]["tenant_id"] == "tenant-a"

    with pytest.raises(AVServiceContractError, match="audit sink is invalid"):
        service.scan_artifact(
            scanner, artifact_id="artifact-2", content=content, report_id="report-2",
            audit=None, now_epoch=10,
        )

def test_endpoint_fixture_admission_fails_closed_on_tamper_and_replay():
    service = AVProtectionService(profile(), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    fixture = {
        "event_id": "replay-1", "tenant_id": "tenant-a", "device_id": "device-a",
        "observed_at_epoch": 10, "event_type": "FILE_LIFECYCLE", "source": "WINDOWS_SENSOR",
        "artifact": {"name": "sample.bin", "operation": "CREATE"},
        "process_ancestry": [], "related_indicators": [], "evidence_ref": "fw-evid/tenant-a/replay-1",
    }
    service.ingest_fixture(fixture, source="WINDOWS_SENSOR", now_epoch=10)
    with pytest.raises(EndpointFixtureDenied, match="EVENT_ID_DUPLICATE"):
        service.ingest_fixture(fixture, source="WINDOWS_SENSOR", now_epoch=10)
    tampered = dict(fixture, event_id="tampered-1", artifact={"name": "sample.bin", "unexpected": "value"})
    with pytest.raises(EndpointFixtureDenied, match="metadata_INVALID"):
        service.ingest_fixture(tampered, source="WINDOWS_SENSOR", now_epoch=10)
    assert service.status()["metrics"].accepted_records == 1
    assert service.status()["metrics"].rejected_records == 2


def test_activation_readiness_gate_fails_closed_without_authority():
    service = AVProtectionService(profile(), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    gate = service.activation_readiness_gate(rollback_checkpoint="REC-001", approval_reference="APR-001")
    assert gate["decision"] == "NOT_READY"
    assert gate["reason"] == "ACTIVATION_REQUIRES_SEPARATE_AUTHORIZATION"
    assert gate["service_installation"] == "NOT_AUTHORIZED"
    assert gate["launch"] == "NOT_AUTHORIZED"
    assert gate["blocking"] == "POLICY_GATE_REQUIRED"
    assert gate["quarantine"] == "PROPOSAL_ONLY"
    assert gate["kill_switch"] == "ENGAGED"
    with pytest.raises(AVServiceContractError, match="rollback checkpoint"):
        service.activation_readiness_gate(rollback_checkpoint="", approval_reference="APR-001")
    with pytest.raises(AVServiceContractError, match="approval reference"):
        service.activation_readiness_gate(rollback_checkpoint="REC-001", approval_reference="")


def test_release_readiness_projection_is_honest_and_activation_disabled():
    service = AVProtectionService(profile(), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    projection = service.release_readiness_projection()
    assert projection["implementation"] == "TESTED"
    assert projection["security_validation"] == "FIXTURE_ONLY"
    assert projection["production_readiness"] == "NOT_READY"
    assert projection["live_sensors"] == "DISABLED"
    assert projection["automatic_blocking"] == "DISABLED"
    assert projection["quarantine_execution"] == "DISABLED"
    assert projection["deployment"] == "DISABLED"
    assert projection["kill_switch"] == "ENGAGED"


def test_mission_control_projection_is_labeled_read_only_and_safe():
    service = AVProtectionService(profile(), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    projection = service.mission_control_projection()
    assert projection["data_mode"] == "LIVE_BACKEND_NOT_CONNECTED"
    assert projection["phase"] == "DRY_RUN_DETECT_ONLY"
    assert projection["service"]["installation"] == "NOT_AUTHORIZED"
    assert projection["response"]["blocking"] == "POLICY_GATE_REQUIRED"
    assert projection["operator_controls"] == {"read_only": True, "stop_allowed": False, "policy_change_allowed": False}


def test_response_contract_projection_is_inert_and_policy_gated():
    service = AVProtectionService(profile(), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    projection = service.response_contract_projection()
    assert projection == {
        "mode": "DRY_RUN", "action": "DETECT_ONLY",
        "automatic_blocking": False, "quarantine_execution": False,
        "blocking": "POLICY_GATE_REQUIRED", "quarantine": "PROPOSAL_ONLY",
        "activation": "DISABLED", "deployment": "DISABLED", "kill_switch": "ENGAGED",
    }


def test_service_readiness_projection_is_platform_bound_and_non_installing():
    windows = AVProtectionService(profile(), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    linux = AVProtectionService(
        AVServiceProfile("tenant-a", "device-a", "LINUX", True, "STATUS_ONLY"),
        DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)),
    )
    for service, manager, run_as in (
        (windows, "SCM", "NT AUTHORITY\\LocalService"),
        (linux, "SYSTEMD", "forgewarden-sentinel"),
    ):
        projection = service.service_readiness_projection()
        assert projection["service_name"] == "ForgeWardenSentinel"
        assert projection["manager"] == manager
        assert projection["run_as"] == run_as
        if manager == "SCM":
            assert projection["run_as"].count("\\") == 1
        assert projection["startup"] == "DISABLED"
        assert projection["restart_policy"] == "BOUNDED_ON_FAILURE"
        assert projection["max_restart_attempts"] == 3
        assert projection["installation"] == "NOT_AUTHORIZED"
        assert projection["launch"] == "NOT_AUTHORIZED"
        assert projection["manifest_digest"] == service.packaging_manifest_digest()

def test_service_rejects_sensor_source_for_wrong_platform():
    service = AVProtectionService(profile(), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    record = {
        "event_id": "wrong-source", "tenant_id": "tenant-a", "device_id": "device-a",
        "observed_at_epoch": 10, "event_type": "FILE_LIFECYCLE", "source": "LINUX_SENSOR",
        "metadata": {"operation": "CREATE"}, "process_ancestry": [],
        "related_indicators": [], "evidence_ref": "fw-evid/tenant-a/wrong-source",
    }
    with pytest.raises(AVServiceContractError, match="source does not match"):
        service.ingest(record, source="LINUX_SENSOR", now_epoch=10)
    with pytest.raises(AVServiceContractError, match="source does not match"):
        service.ingest_batch([record], source="LINUX_SENSOR", now_epoch=10)

def test_service_ingest_fixture_reuses_canonical_normalized_event_store():
    events = []
    service = AVProtectionService(profile(), DryRunSensorPipeline(NormalizedEventStore(lambda event, data: events.append((event, data)))))
    fixture = {
        "event_id": "fixture-1", "tenant_id": "tenant-a", "device_id": "device-a",
        "observed_at_epoch": 10, "event_type": "FILE_LIFECYCLE", "source": "WINDOWS_SENSOR",
        "artifact": {"name": "sample.bin", "operation": "CREATE"},
        "process_ancestry": [], "related_indicators": [], "evidence_ref": "fw-evid/tenant-a/fixture-1",
    }
    observation = service.ingest_fixture(fixture, source="WINDOWS_SENSOR", now_epoch=10)
    assert observation.event_id == "fixture-1"
    assert observation.mode == "DRY_RUN"
    assert observation.action == "DETECT_ONLY"
    assert events[0][0] == "endpoint_event_admitted"
    with pytest.raises(AVServiceContractError, match="source does not match"):
        service.ingest_fixture(fixture, source="LINUX_SENSOR", now_epoch=10)


def test_service_ingest_batch_reuses_bounded_pipeline_and_tenant_binding():
    service = AVProtectionService(profile(), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    records = [
        {
            "event_id": f"batch-{index}", "tenant_id": "tenant-a", "device_id": "device-a",
            "observed_at_epoch": 10 + index, "event_type": "FILE_LIFECYCLE", "source": "WINDOWS_SENSOR",
            "metadata": {"operation": "CREATE"}, "process_ancestry": [],
            "related_indicators": [], "evidence_ref": f"fw-evid/tenant-a/batch-{index}",
        }
        for index in range(2)
    ]
    observations = service.ingest_batch(records, source="WINDOWS_SENSOR", now_epoch=20)
    assert len(observations) == 2
    assert service.status()["metrics"].accepted_batches == 1
    records[1]["tenant_id"] = "tenant-b"
    with pytest.raises(Exception):
        service.ingest_batch(records, source="WINDOWS_SENSOR", now_epoch=20)

def test_local_user_mode_allows_preferences_but_never_service_stop():
    service = AVProtectionService(profile(enterprise=False), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    status = service.status()
    assert status["service_control"] == "LOCAL_POLICY_LIMITED"
    assert status["local_stop_allowed"] is False
    assert status["local_policy_change_allowed"] is True


def test_tray_projection_is_labeled_and_never_exposes_stop_or_execution_controls():
    enterprise = AVProtectionService(profile(), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    local = AVProtectionService(profile(enterprise=False), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    assert enterprise.tray_projection()["product"] == "ForgeWarden Sentinel"
    assert enterprise.tray_projection()["mode"] == "DEMO/DRY_RUN"
    assert enterprise.tray_projection()["show_preferences"] is False
    assert local.tray_projection()["show_preferences"] is True
    for projection in (enterprise.tray_projection(), local.tray_projection()):
        assert projection["show_stop_control"] is False
        assert projection["show_quarantine_execution"] is False
        assert projection["show_deployment_control"] is False


def test_packaging_manifest_is_staged_and_activation_disabled():
    service = AVProtectionService(profile(), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    manifest = service.packaging_manifest()
    assert manifest["product"] == "ForgeWarden Sentinel"
    assert manifest["activation"] == "DISABLED"
    assert manifest["service_installation"] == "NOT_AUTHORIZED"
    assert manifest["mode"] == "DRY_RUN"
    assert manifest["action"] == "DETECT_ONLY"


def test_packaging_manifest_validation_rejects_tampering_and_accepts_exact_profile():
    service = AVProtectionService(profile(), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    manifest = service.packaging_manifest()
    assert service.validate_packaging_manifest(manifest) == manifest
    altered = dict(manifest)
    altered["activation"] = "ENABLED"
    with pytest.raises(AVServiceContractError, match="does not match"):
        service.validate_packaging_manifest(altered)
    with pytest.raises(AVServiceContractError, match="manifest is invalid"):
        service.validate_packaging_manifest([("product", "ForgeWarden Sentinel")])
    digest = service.packaging_manifest_digest()
    assert len(digest) == 64
    assert digest == service.packaging_manifest_digest()
    assert digest == "1665fe746aee77cd77b6c3a48eb4145ce69665cac095b866fcb1dc2b8e05b261"
    projection = service.installer_artifact_projection()
    assert projection["artifact_name"] == "forgewarden-sentinel-windows-dry-run.manifest"
    assert projection["manifest_digest"] == digest
    assert projection["activation"] == "DISABLED"
    assert projection["service_installation"] == "NOT_AUTHORIZED"
    assert projection["deployment"] == "DISABLED"


def test_service_resource_limits_and_invalid_profile_fail_closed():
    with pytest.raises(AVServiceContractError, match="max_queue_events"):
        AVServiceProfile("tenant-a", "device-a", "LINUX", True, "STATUS_ONLY", max_queue_events=1025)
    with pytest.raises(AVServiceContractError, match="profile"):
        AVProtectionService(object(), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))


def test_service_rejects_cross_tenant_observation():
    service = AVProtectionService(profile(), DryRunSensorPipeline(NormalizedEventStore(lambda *_: None)))
    record = {
        "event_id": "event-2", "tenant_id": "tenant-b", "device_id": "device-a",
        "observed_at_epoch": 10, "event_type": "FILE_LIFECYCLE", "source": "WINDOWS_SENSOR",
        "metadata": {"operation": "CREATE"}, "process_ancestry": [],
        "related_indicators": [], "evidence_ref": "fw-evid/tenant-b/event-2",
    }
    with pytest.raises(Exception):
        service.ingest(record, source="WINDOWS_SENSOR", now_epoch=10)
