from dataclasses import FrozenInstanceError

import pytest

from swarm.saas_security import SaaSObservationDenied, normalize_saas_observation


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
