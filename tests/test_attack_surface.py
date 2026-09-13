from dataclasses import FrozenInstanceError

import pytest

from swarm.attack_surface import AttackSurfaceObservationDenied, normalize_attack_surface_observation


def fixture(**overrides):
    value = {
        "event_id": "asm-1", "tenant_id": "tenant-a", "observed_at_epoch": 100,
        "asset_type": "WEBSITE", "asset_ref": "fw-asset/tenant-a/site-1",
        "exposure_ref": "fw-exposure/tenant-a/site-1", "service": "HTTP",
        "protocol": "HTTPS", "port": 443, "ownership_state": "KNOWN",
        "visibility_state": "PUBLIC", "evidence_ref": "fw-evid/tenant-a/asm-1",
    }
    value.update(overrides)
    return value


def test_attack_surface_observation_is_immutable_evidence_first_and_minimized():
    evidence = []
    value = normalize_attack_surface_observation(
        fixture(), tenant_id="tenant-a", now_epoch=150,
        audit=lambda *args: evidence.append(args),
    )
    assert value.asset_type == "WEBSITE" and value.visibility_state == "PUBLIC"
    assert value.trust == "UNTRUSTED_DATA"
    assert value.mode == "DRY_RUN" and value.action == "DETECT_ONLY"
    assert value.authority_granted is False
    assert evidence[0][0] == "attack_surface_observation_normalized"
    assert evidence[0][1]["deployment"] == "DISABLED"
    assert not {"asset_ref", "exposure_ref"} & evidence[0][1].keys()
    with pytest.raises(FrozenInstanceError):
        value.port = 80


@pytest.mark.parametrize("value,reason", [
    (fixture(tenant_id="tenant-b"), "TENANT_MISMATCH"),
    (fixture(asset_ref="fw-asset/tenant-b/site-1"), "ASSET_REF_INVALID"),
    (fixture(exposure_ref="fw-exposure/tenant-b/site-1"), "EXPOSURE_REF_INVALID"),
    (fixture(evidence_ref="fw-evid/tenant-b/asm-1"), "EVIDENCE_REF_INVALID"),
    (fixture(asset_type="HOST"), "ASSET_TYPE_INVALID"),
    (fixture(service="SHELL"), "SERVICE_INVALID"),
    (fixture(protocol="https"), "PROTOCOL_INVALID"),
    (fixture(ownership_state="CLAIMED"), "OWNERSHIP_STATE_INVALID"),
    (fixture(visibility_state="HIDDEN"), "VISIBILITY_STATE_INVALID"),
    (fixture(port=True), "PORT_INVALID"),
    (fixture(port=65536), "PORT_INVALID"),
    (fixture(observed_at_epoch=151), "OBSERVED_AT_INVALID"),
    (fixture(extra="value"), "FIXTURE_INVALID"),
])
def test_attack_surface_observation_rejects_invalid_or_cross_tenant_input(value, reason):
    evidence = []
    with pytest.raises(AttackSurfaceObservationDenied, match=reason):
        normalize_attack_surface_observation(
            value, tenant_id="tenant-a", now_epoch=150,
            audit=lambda *args: evidence.append(args),
        )
    assert evidence == []


def test_attack_surface_observation_accepts_port_boundaries_and_denies_evidence_failure():
    for port in (0, 65535):
        assert normalize_attack_surface_observation(
            fixture(port=port), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: None,
        ).port == port
    with pytest.raises(AttackSurfaceObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        normalize_attack_surface_observation(
            fixture(), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
        )
