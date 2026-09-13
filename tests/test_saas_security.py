from dataclasses import FrozenInstanceError, replace

import pytest

from swarm.saas_security import (
    SaaSObservationDenied,
    bind_saas_correlation_references,
    classify_saas_observation,
    normalize_saas_observation,
)


def _fixture(**overrides):
    fixture = {
        "event_id": "saas-1", "tenant_id": "tenant-a",
        "observed_at_epoch": 100, "provider": "MICROSOFT_365",
        "application_ref": "app:finance", "principal_ref": "identity:user-1",
        "target_ref": "resource:ledger", "observation_type": "OAUTH_APP_POSTURE",
        "related_indicators": ["RISKY_OAUTH_CONSENT", "EXCESSIVE_PRIVILEGE"],
        "evidence_ref": "evidence:saas-1",
    }
    fixture.update(overrides)
    return fixture


def test_saas_observation_is_immutable_evidence_first_and_minimized():
    evidence = []
    observation = normalize_saas_observation(
        _fixture(), tenant_id="tenant-a", now_epoch=150,
        audit=lambda *args: evidence.append(args),
    )
    assert observation.related_indicators == ("EXCESSIVE_PRIVILEGE", "RISKY_OAUTH_CONSENT")
    assert observation.trust == "UNTRUSTED_DATA"
    assert observation.mode == "DRY_RUN" and observation.action == "DETECT_ONLY"
    assert evidence[0][0] == "saas_observation_normalized"
    assert evidence[0][1]["deployment"] == "DISABLED"
    assert not {"application_ref", "principal_ref", "target_ref"} & evidence[0][1].keys()
    with pytest.raises(FrozenInstanceError):
        observation.provider = "SALESFORCE"


@pytest.mark.parametrize("fixture,reason", [
    (_fixture(tenant_id="tenant-b"), "TENANT_MISMATCH"),
    (_fixture(provider="UNKNOWN"), "PROVIDER_INVALID"),
    (_fixture(observation_type="UNKNOWN"), "OBSERVATION_TYPE_INVALID"),
    (_fixture(related_indicators=[]), "INDICATORS_INVALID"),
    (_fixture(related_indicators=["SUSPICIOUS_SIGN_IN", "SUSPICIOUS_SIGN_IN"]), "INDICATORS_INVALID"),
    (_fixture(related_indicators=["UNKNOWN"]), "INDICATORS_INVALID"),
    (_fixture(extra="value"), "FIXTURE_INVALID"),
    (_fixture(principal_ref="contains whitespace"), "PRINCIPAL_REF_INVALID"),
    (_fixture(observed_at_epoch=151), "OBSERVED_AT_INVALID"),
])
def test_saas_observation_rejects_untrusted_boundaries(fixture, reason):
    evidence = []
    with pytest.raises(SaaSObservationDenied, match=reason):
        normalize_saas_observation(
            fixture, tenant_id="tenant-a", now_epoch=150,
            audit=lambda *args: evidence.append(args),
        )
    assert evidence == []


def test_saas_observation_evidence_failure_denies_output():
    with pytest.raises(SaaSObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        normalize_saas_observation(
            _fixture(), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
        )


@pytest.mark.parametrize("indicators,confidence", [
    (["DORMANT_ACCOUNT"], "LOW"),
    (["UNSAFE_THIRD_PARTY_APP"], "MEDIUM"),
    (["RISKY_OAUTH_CONSENT", "EXCESSIVE_PRIVILEGE"], "HIGH"),
    (["AI_APP_DATA_ACCESS", "PUBLIC_SHARE"], "HIGH"),
    (["SUSPICIOUS_SIGN_IN", "EXCESSIVE_PRIVILEGE"], "HIGH"),
    (["SUSPICIOUS_SIGN_IN", "UNSAFE_THIRD_PARTY_APP"], "MEDIUM"),
])
def test_saas_classifier_is_exact_deterministic_and_warn_only(indicators, confidence):
    evidence = []
    observation = normalize_saas_observation(
        _fixture(related_indicators=indicators), tenant_id="tenant-a",
        now_epoch=150, audit=lambda *_args: None,
    )
    finding = classify_saas_observation(
        observation, tenant_id="tenant-a", audit=lambda *args: evidence.append(args),
    )
    assert finding.signals == tuple(sorted(indicators))
    assert finding.confidence == confidence and finding.recommendations == ("WARN",)
    assert finding.mode == "DRY_RUN" and finding.action == "DETECT_ONLY"
    assert evidence[0][1]["response_executed"] is False
    assert evidence[0][1]["deployment"] == "DISABLED"
    assert not {"application_ref", "principal_ref", "target_ref"} & evidence[0][1].keys()


def test_saas_classifier_revalidates_tenant_authority_shape_and_evidence():
    observation = normalize_saas_observation(
        _fixture(), tenant_id="tenant-a", now_epoch=150, audit=lambda *_args: None,
    )
    with pytest.raises(SaaSObservationDenied, match="TENANT_MISMATCH"):
        classify_saas_observation(observation, tenant_id="tenant-b", audit=lambda *_args: None)
    with pytest.raises(SaaSObservationDenied, match="OBSERVATION_AUTHORITY_INVALID"):
        classify_saas_observation(replace(observation, action="DISABLE_APP"), tenant_id="tenant-a", audit=lambda *_args: None)
    with pytest.raises(SaaSObservationDenied, match="OBSERVATION_INVALID"):
        classify_saas_observation(replace(observation, related_indicators=("UNKNOWN",)), tenant_id="tenant-a", audit=lambda *_args: None)
    for indicators in ((), tuple("DORMANT_ACCOUNT" for _ in range(17))):
        with pytest.raises(SaaSObservationDenied, match="OBSERVATION_INVALID"):
            classify_saas_observation(
                replace(observation, related_indicators=indicators),
                tenant_id="tenant-a", audit=lambda *_args: None,
            )
    with pytest.raises(SaaSObservationDenied, match="OBSERVATION_INVALID"):
        classify_saas_observation(replace(observation, observed_at_epoch=True), tenant_id="tenant-a", audit=lambda *_args: None)
    with pytest.raises(SaaSObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        classify_saas_observation(
            observation, tenant_id="tenant-a",
            audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
        )


def _finding():
    observation = normalize_saas_observation(
        _fixture(), tenant_id="tenant-a", now_epoch=150, audit=lambda *_args: None,
    )
    return classify_saas_observation(
        observation, tenant_id="tenant-a", audit=lambda *_args: None,
    )


def test_saas_correlation_binds_canonical_references_evidence_first_and_inert():
    evidence = []
    result = bind_saas_correlation_references(
        _finding(), tenant_id="tenant-a",
        soc_incident_ref="fw-incident/tenant-a/saas-1",
        aid_finding_ref="fw-finding/tenant-a/saas-1",
        evidence_refs=("fw-evid/tenant-a/saas-1",),
        audit=lambda *args: evidence.append(args),
    )
    assert result.action == "CORRELATE_ONLY" and result.mode == "DRY_RUN"
    assert result.soc_incident_ref == "fw-incident/tenant-a/saas-1"
    assert result.aid_finding_ref == "fw-finding/tenant-a/saas-1"
    assert evidence[0][1]["response_executed"] is False
    assert evidence[0][1]["deployment"] == "DISABLED"


@pytest.mark.parametrize("kwargs,reason", [
    ({"tenant_id": "tenant-b"}, "TENANT_MISMATCH"),
    ({"soc_incident_ref": "fw-incident/tenant-b/saas-1"}, "CORRELATION_REF_INVALID"),
    ({"aid_finding_ref": "fw-incident/tenant-a/saas-1"}, "CORRELATION_REF_INVALID"),
    ({"evidence_refs": ()}, "EVIDENCE_REFS_INVALID"),
    ({"evidence_refs": ("fw-evid/tenant-a/saas-1", "fw-evid/tenant-a/saas-1")}, "EVIDENCE_REFS_INVALID"),
    ({"evidence_refs": tuple(f"fw-evid/tenant-a/saas-{index}" for index in range(17))}, "EVIDENCE_REFS_INVALID"),
    ({"evidence_refs": ("fw-evid/tenant-b/saas-1",)}, "EVIDENCE_REFS_INVALID"),
])
def test_saas_correlation_rejects_cross_tenant_or_malformed_references(kwargs, reason):
    values = {
        "tenant_id": "tenant-a",
        "soc_incident_ref": "fw-incident/tenant-a/saas-1",
        "aid_finding_ref": "fw-finding/tenant-a/saas-1",
        "evidence_refs": ("fw-evid/tenant-a/saas-1",),
        "audit": lambda *_args: None,
    }
    values.update(kwargs)
    with pytest.raises(SaaSObservationDenied, match=reason):
        bind_saas_correlation_references(_finding(), **values)


def test_saas_correlation_revalidates_finding_and_denies_evidence_failure():
    finding = _finding()
    values = dict(
        tenant_id="tenant-a",
        soc_incident_ref="fw-incident/tenant-a/saas-1",
        aid_finding_ref="fw-finding/tenant-a/saas-1",
        evidence_refs=("fw-evid/tenant-a/saas-1",),
    )
    with pytest.raises(SaaSObservationDenied, match="FINDING_INVALID"):
        bind_saas_correlation_references(
            replace(finding, action="RESPOND"), audit=lambda *_args: None, **values,
        )
    with pytest.raises(SaaSObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        bind_saas_correlation_references(
            finding,
            audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
            **values,
        )
