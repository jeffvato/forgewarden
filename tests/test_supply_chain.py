from dataclasses import FrozenInstanceError

import pytest

from swarm.supply_chain import SupplyChainObservationDenied, normalize_supply_chain_observation


def fixture(**overrides):
    value = {
        "event_id": "supply-1", "tenant_id": "tenant-a",
        "observed_at_epoch": 100, "component_ref": "component:requests",
        "ecosystem": "PYPI", "package_name": "requests", "version": "2.32.5",
        "artifact_sha256": "a" * 64, "source_ref": "source:pypi/requests",
        "provenance_ref": "provenance:build/001",
        "evidence_ref": "evidence:supply-1",
    }
    value.update(overrides)
    return value


def test_supply_observation_is_immutable_evidence_first_and_minimized():
    evidence = []
    observation = normalize_supply_chain_observation(
        fixture(), tenant_id="tenant-a", now_epoch=150,
        audit=lambda *args: evidence.append(args),
    )
    assert observation.package_name == "requests" and observation.version == "2.32.5"
    assert observation.trust == "UNTRUSTED_DATA"
    assert observation.mode == "DRY_RUN" and observation.action == "DETECT_ONLY"
    assert evidence[0][0] == "supply_chain_observation_normalized"
    assert evidence[0][1]["deployment"] == "DISABLED"
    assert not {"package_name", "version", "source_ref", "provenance_ref"} & evidence[0][1].keys()
    with pytest.raises(FrozenInstanceError):
        observation.version = "3.0.0"


@pytest.mark.parametrize("value,reason", [
    (fixture(tenant_id="tenant-b"), "TENANT_MISMATCH"),
    (fixture(ecosystem="UNKNOWN"), "ECOSYSTEM_INVALID"),
    (fixture(package_name="bad package"), "PACKAGE_NAME_INVALID"),
    (fixture(version="bad version"), "VERSION_INVALID"),
    (fixture(artifact_sha256="A" * 64), "ARTIFACT_SHA256_INVALID"),
    (fixture(artifact_sha256="a" * 63), "ARTIFACT_SHA256_INVALID"),
    (fixture(observed_at_epoch=151), "OBSERVED_AT_INVALID"),
    (fixture(source_ref="contains whitespace"), "SOURCE_REF_INVALID"),
    (fixture(extra="value"), "FIXTURE_INVALID"),
])
def test_supply_observation_rejects_malformed_or_cross_tenant_input(value, reason):
    evidence = []
    with pytest.raises(SupplyChainObservationDenied, match=reason):
        normalize_supply_chain_observation(
            value, tenant_id="tenant-a", now_epoch=150,
            audit=lambda *args: evidence.append(args),
        )
    assert evidence == []


def test_supply_observation_rejects_invalid_time_type_and_evidence_failure():
    with pytest.raises(SupplyChainObservationDenied, match="OBSERVED_AT_INVALID"):
        normalize_supply_chain_observation(
            fixture(observed_at_epoch=True), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: None,
        )
    with pytest.raises(SupplyChainObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        normalize_supply_chain_observation(
            fixture(), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
        )
