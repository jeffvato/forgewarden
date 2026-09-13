from dataclasses import FrozenInstanceError

import pytest

from swarm.data_security import DataSecurityObservationDenied, normalize_data_security_observation


def fixture(**overrides):
    value = {
        "event_id": "dspm-1", "tenant_id": "tenant-a", "observed_at_epoch": 100,
        "data_asset_ref": "fw-data/tenant-a/customer-records",
        "location_asset_ref": "fw-asset/tenant-a/database-1",
        "classification": "RESTRICTED", "location_class": "DATABASE",
        "owner_identity_ref": "fw-id/tenant-a.data-owner",
        "access_path": "SHARED", "copy_count": 3,
        "encryption_state": "ENCRYPTED", "ai_access_state": "NONE",
        "policy_state": "COMPLIANT", "evidence_ref": "fw-evid/tenant-a/dspm-1",
    }
    value.update(overrides)
    return value


def test_data_security_observation_is_immutable_evidence_first_and_minimized():
    evidence = []
    value = normalize_data_security_observation(
        fixture(), tenant_id="tenant-a", now_epoch=150,
        audit=lambda *args: evidence.append(args),
    )
    assert value.classification == "RESTRICTED" and value.copy_count == 3
    assert value.trust == "UNTRUSTED_DATA"
    assert value.mode == "DRY_RUN" and value.action == "DETECT_ONLY"
    assert value.authority_granted is False
    assert evidence[0][1]["deployment"] == "DISABLED"
    assert "owner_identity_ref" not in evidence[0][1]
    with pytest.raises(FrozenInstanceError):
        value.copy_count = 4


@pytest.mark.parametrize("value,reason", [
    (fixture(tenant_id="tenant-b"), "TENANT_MISMATCH"),
    (fixture(data_asset_ref="fw-data/tenant-b/customer-records"), "DATA_ASSET_REF_INVALID"),
    (fixture(location_asset_ref="fw-asset/tenant-b/database-1"), "LOCATION_ASSET_REF_INVALID"),
    (fixture(owner_identity_ref="fw-id/tenant-b.data-owner"), "OWNER_IDENTITY_REF_INVALID"),
    (fixture(evidence_ref="fw-evid/tenant-b/dspm-1"), "EVIDENCE_REF_INVALID"),
    (fixture(classification="SECRET"), "CLASSIFICATION_INVALID"),
    (fixture(location_class="INTERNET"), "LOCATION_CLASS_INVALID"),
    (fixture(access_path="ROOT"), "ACCESS_PATH_INVALID"),
    (fixture(encryption_state="DECRYPTED"), "ENCRYPTION_STATE_INVALID"),
    (fixture(ai_access_state="ADMIN"), "AI_ACCESS_STATE_INVALID"),
    (fixture(policy_state="BYPASSED"), "POLICY_STATE_INVALID"),
    (fixture(copy_count=True), "COPY_COUNT_INVALID"),
    (fixture(copy_count=100001), "COPY_COUNT_INVALID"),
    (fixture(observed_at_epoch=151), "OBSERVED_AT_INVALID"),
    (fixture(extra="content"), "FIXTURE_INVALID"),
])
def test_data_security_observation_denies_invalid_or_cross_tenant_input(value, reason):
    evidence = []
    with pytest.raises(DataSecurityObservationDenied, match=reason):
        normalize_data_security_observation(
            value, tenant_id="tenant-a", now_epoch=150,
            audit=lambda *args: evidence.append(args),
        )
    assert evidence == []


@pytest.mark.parametrize("copy_count", [0, 100000])
def test_data_security_observation_accepts_copy_count_boundaries(copy_count):
    assert normalize_data_security_observation(
        fixture(copy_count=copy_count), tenant_id="tenant-a", now_epoch=150,
        audit=lambda *_args: None,
    ).copy_count == copy_count


def test_data_security_observation_denies_non_json_and_evidence_failure():
    with pytest.raises(DataSecurityObservationDenied, match="FIXTURE_INVALID"):
        normalize_data_security_observation(
            fixture(copy_count={3}), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: None,
        )
    with pytest.raises(DataSecurityObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        normalize_data_security_observation(
            fixture(), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
        )


@pytest.mark.parametrize("tenant_id,now_epoch,reason", [
    ("", 150, "TENANT_INVALID"),
    ("tenant-a", True, "OBSERVED_AT_INVALID"),
    ("tenant-a", -1, "OBSERVED_AT_INVALID"),
])
def test_data_security_observation_denies_invalid_expected_boundary(tenant_id, now_epoch, reason):
    with pytest.raises(DataSecurityObservationDenied, match=reason):
        normalize_data_security_observation(
            fixture(), tenant_id=tenant_id, now_epoch=now_epoch,
            audit=lambda *_args: None,
        )
