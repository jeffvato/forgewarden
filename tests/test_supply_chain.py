from dataclasses import FrozenInstanceError, replace

import pytest

from swarm.supply_chain import SupplyChainObservationDenied, bind_supply_chain_references, classify_supply_chain_observation, normalize_supply_chain_observation


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


def observation():
    return normalize_supply_chain_observation(
        fixture(), tenant_id="tenant-a", now_epoch=150, audit=lambda *_args: None,
    )


@pytest.mark.parametrize("indicators,risk,recommendations", [
    (("VERIFIED_PROVENANCE",), "LOW", ("WARN",)),
    (("KNOWN_VULNERABILITY",), "MEDIUM", ("WARN",)),
    (("DEPENDENCY_CONFUSION",), "HIGH", ("WARN", "PROPOSE_BLOCK")),
    (("TYPOSQUAT", "UNVERIFIED_PROVENANCE"), "HIGH", ("WARN", "PROPOSE_BLOCK")),
    (("DIGEST_MISMATCH",), "CRITICAL", ("WARN", "PROPOSE_BLOCK")),
    (("KNOWN_EXPLOITED",), "CRITICAL", ("WARN", "PROPOSE_BLOCK")),
])
def test_supply_classifier_is_exact_deterministic_and_non_executing(indicators, risk, recommendations):
    evidence = []
    finding = classify_supply_chain_observation(
        observation(), tenant_id="tenant-a", indicators=indicators,
        audit=lambda *args: evidence.append(args),
    )
    assert finding.indicators == indicators and finding.risk == risk
    assert finding.recommendations == recommendations
    assert finding.mode == "DRY_RUN" and finding.action == "DETECT_ONLY"
    assert evidence[0][1]["response_executed"] is False
    assert evidence[0][1]["deployment"] == "DISABLED"


@pytest.mark.parametrize("indicators", [
    (), ("UNKNOWN",), ("KNOWN_EXPLOITED", "KNOWN_EXPLOITED"),
    ("UNVERIFIED_PROVENANCE", "VERIFIED_PROVENANCE"),
    tuple("KNOWN_VULNERABILITY" for _ in range(17)),
])
def test_supply_classifier_rejects_invalid_indicators(indicators):
    with pytest.raises(SupplyChainObservationDenied, match="INDICATORS_INVALID"):
        classify_supply_chain_observation(
            observation(), tenant_id="tenant-a", indicators=indicators,
            audit=lambda *_args: None,
        )


def test_supply_classifier_revalidates_tenant_authority_and_evidence():
    value = observation()
    with pytest.raises(SupplyChainObservationDenied, match="TENANT_MISMATCH"):
        classify_supply_chain_observation(
            value, tenant_id="tenant-b", indicators=("VERIFIED_PROVENANCE",),
            audit=lambda *_args: None,
        )
    with pytest.raises(SupplyChainObservationDenied, match="OBSERVATION_AUTHORITY_INVALID"):
        classify_supply_chain_observation(
            replace(value, action="INSTALL"), tenant_id="tenant-a",
            indicators=("KNOWN_VULNERABILITY",), audit=lambda *_args: None,
        )
    with pytest.raises(SupplyChainObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        classify_supply_chain_observation(
            value, tenant_id="tenant-a", indicators=("KNOWN_VULNERABILITY",),
            audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
        )


def finding():
    return classify_supply_chain_observation(
        observation(), tenant_id="tenant-a", indicators=("KNOWN_EXPLOITED",),
        audit=lambda *_args: None,
    )


def binding_args(**overrides):
    values = dict(
        tenant_id="tenant-a",
        vulnerability_refs=("fw-vuln/tenant-a/osv-1",),
        catalog_ref="fw-catalog/tenant-a/addon-1",
        signature_ref="fw-signature/tenant-a/publisher-1",
        evidence_refs=("fw-evid/tenant-a/supply-1",),
        audit=lambda *_args: None,
    )
    values.update(overrides)
    return values


def test_supply_reference_binding_is_immutable_evidence_first_and_inert():
    evidence = []
    value = bind_supply_chain_references(
        finding(), **binding_args(audit=lambda *args: evidence.append(args)),
    )
    assert value.risk == "CRITICAL"
    assert value.vulnerability_refs == ("fw-vuln/tenant-a/osv-1",)
    assert value.action == "CORRELATE_ONLY" and value.mode == "DRY_RUN"
    assert evidence[0][1]["response_executed"] is False
    assert evidence[0][1]["deployment"] == "DISABLED"
    with pytest.raises(FrozenInstanceError):
        value.risk = "LOW"


@pytest.mark.parametrize("overrides,reason", [
    ({"tenant_id": "tenant-b"}, "TENANT_MISMATCH"),
    ({"vulnerability_refs": ()}, "VULNERABILITY_REFS_INVALID"),
    ({"vulnerability_refs": ("fw-vuln/tenant-b/osv-1",)}, "VULNERABILITY_REFS_INVALID"),
    ({"vulnerability_refs": ("fw-vuln/tenant-a/osv-1", "fw-vuln/tenant-a/osv-1")}, "VULNERABILITY_REFS_INVALID"),
    ({"catalog_ref": "fw-signature/tenant-a/addon-1"}, "OWNER_REF_INVALID"),
    ({"signature_ref": "fw-signature/tenant-b/publisher-1"}, "OWNER_REF_INVALID"),
    ({"evidence_refs": ()}, "EVIDENCE_REFS_INVALID"),
    ({"evidence_refs": ("fw-evid/tenant-a/supply-1", "fw-evid/tenant-a/supply-1")}, "EVIDENCE_REFS_INVALID"),
    ({"evidence_refs": ("fw-evid/tenant-b/supply-1",)}, "EVIDENCE_REFS_INVALID"),
    ({"evidence_refs": ("fw-vuln/tenant-a/osv-1",)}, "EVIDENCE_REFS_INVALID"),
    ({"evidence_refs": tuple(f"fw-evid/tenant-a/{index}" for index in range(17))}, "EVIDENCE_REFS_INVALID"),
])
def test_supply_reference_binding_rejects_malformed_cross_tenant_or_replay(overrides, reason):
    with pytest.raises(SupplyChainObservationDenied, match=reason):
        bind_supply_chain_references(finding(), **binding_args(**overrides))


def test_supply_reference_binding_revalidates_finding_and_evidence():
    with pytest.raises(SupplyChainObservationDenied, match="FINDING_INVALID"):
        bind_supply_chain_references(
            replace(finding(), action="BLOCK"), **binding_args(),
        )
    with pytest.raises(SupplyChainObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        bind_supply_chain_references(
            finding(), **binding_args(
                audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
            ),
        )
