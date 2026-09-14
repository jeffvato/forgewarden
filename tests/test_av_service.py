import pytest

from swarm.av_service import AVProtectionService, AVServiceContractError, AVServiceProfile
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
