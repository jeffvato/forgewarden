from dataclasses import FrozenInstanceError, replace

import pytest

from swarm.network_security import NetworkObservationDenied, classify_network_observation, normalize_network_observation


def fixture(**overrides):
    value = {
        "event_id": "network-1", "tenant_id": "tenant-a",
        "device_ref": "fw-asset/tenant-a/device-1", "observed_at_epoch": 100,
        "source_ref": "fw-network/tenant-a/source-1",
        "destination_ref": "fw-network/tenant-a/destination-1",
        "protocol": "TLS", "port": 443, "direction": "OUTBOUND",
        "indicators": ["DNS_ANOMALY", "UNAUTHORIZED_EGRESS"],
        "evidence_ref": "fw-evid/tenant-a/network-1",
    }
    value.update(overrides)
    return value


def test_network_observation_is_immutable_evidence_first_and_minimized():
    evidence = []
    value = normalize_network_observation(
        fixture(), tenant_id="tenant-a", now_epoch=150,
        audit=lambda *args: evidence.append(args),
    )
    assert value.indicators == ("DNS_ANOMALY", "UNAUTHORIZED_EGRESS")
    assert value.trust == "UNTRUSTED_DATA"
    assert value.mode == "DRY_RUN" and value.action == "DETECT_ONLY"
    assert value.authority_granted is False
    assert evidence[0][0] == "network_observation_normalized"
    assert evidence[0][1]["deployment"] == "DISABLED"
    assert evidence[0][1]["response_executed"] is False
    assert not {"source_ref", "destination_ref", "indicators"} & evidence[0][1].keys()
    with pytest.raises(FrozenInstanceError):
        value.port = 22


@pytest.mark.parametrize("value,reason", [
    (fixture(tenant_id="tenant-b"), "TENANT_MISMATCH"),
    (fixture(device_ref="fw-asset/tenant-b/device-1"), "DEVICE_REF_INVALID"),
    (fixture(source_ref="fw-network/tenant-b/source-1"), "SOURCE_REF_INVALID"),
    (fixture(destination_ref="fw-asset/tenant-a/destination-1"), "DESTINATION_REF_INVALID"),
    (fixture(evidence_ref="fw-evid/tenant-b/network-1"), "EVIDENCE_REF_INVALID"),
    (fixture(protocol="tls"), "PROTOCOL_INVALID"),
    (fixture(direction="outbound"), "DIRECTION_INVALID"),
    (fixture(port=True), "PORT_INVALID"),
    (fixture(port=65536), "PORT_INVALID"),
    (fixture(observed_at_epoch=151), "OBSERVED_AT_INVALID"),
    (fixture(indicators=["UNAUTHORIZED_EGRESS", "DNS_ANOMALY"]), "INDICATORS_INVALID"),
    (fixture(indicators=["UNKNOWN"]), "INDICATORS_INVALID"),
    (fixture(extra="value"), "FIXTURE_INVALID"),
])
def test_network_observation_rejects_invalid_or_cross_tenant_input(value, reason):
    evidence = []
    with pytest.raises(NetworkObservationDenied, match=reason):
        normalize_network_observation(
            value, tenant_id="tenant-a", now_epoch=150,
            audit=lambda *args: evidence.append(args),
        )
    assert evidence == []


def test_network_observation_rejects_invalid_time_type_and_evidence_failure():
    with pytest.raises(NetworkObservationDenied, match="OBSERVED_AT_INVALID"):
        normalize_network_observation(
            fixture(observed_at_epoch=True), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: None,
        )
    with pytest.raises(NetworkObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        normalize_network_observation(
            fixture(), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
        )


@pytest.mark.parametrize("port", [0, 65535])
def test_network_observation_accepts_port_boundaries(port):
    value = normalize_network_observation(
        fixture(port=port, indicators=[]), tenant_id="tenant-a", now_epoch=150,
        audit=lambda *_args: None,
    )
    assert value.port == port
    assert value.indicators == ()


@pytest.mark.parametrize("now_epoch", [-1, None])
def test_network_observation_rejects_invalid_current_time(now_epoch):
    with pytest.raises(NetworkObservationDenied, match="OBSERVED_AT_INVALID"):
        normalize_network_observation(
            fixture(), tenant_id="tenant-a", now_epoch=now_epoch,
            audit=lambda *_args: None,
        )


@pytest.mark.parametrize("field,value,reason", [
    ("device_ref", "device-1", "DEVICE_REF_INVALID"),
    ("source_ref", "fw-network/tenant-a/contains whitespace", "SOURCE_REF_INVALID"),
    ("destination_ref", "fw-network/tenant-a/", "DESTINATION_REF_INVALID"),
    ("evidence_ref", "fw-evid/tenant-a/../network-1", "EVIDENCE_REF_INVALID"),
])
def test_network_observation_rejects_malformed_owner_references(field, value, reason):
    with pytest.raises(NetworkObservationDenied, match=reason):
        normalize_network_observation(
            fixture(**{field: value}), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: None,
        )


def observation(**overrides):
    return normalize_network_observation(
        fixture(**overrides), tenant_id="tenant-a", now_epoch=150,
        audit=lambda *_args: None,
    )


@pytest.mark.parametrize("overrides,risk,recommendations", [
    ({"protocol": "DNS", "port": 53, "indicators": ["DNS_ANOMALY"]}, "MEDIUM", ("WARN",)),
    ({"indicators": ["NETWORK_PROBE"]}, "MEDIUM", ("WARN",)),
    ({"indicators": ["UNAUTHORIZED_EGRESS"]}, "HIGH", ("WARN", "PROPOSE_BLOCK")),
    ({"direction": "EAST_WEST", "indicators": ["LATERAL_MOVEMENT"]}, "HIGH", ("WARN", "PROPOSE_BLOCK")),
    ({"indicators": ["C2_PATTERN"]}, "CRITICAL", ("WARN", "PROPOSE_BLOCK")),
    ({"indicators": ["EXFILTRATION_PATTERN"]}, "CRITICAL", ("WARN", "PROPOSE_BLOCK")),
])
def test_network_classifier_is_exact_deterministic_and_non_executing(overrides, risk, recommendations):
    evidence = []
    finding = classify_network_observation(
        observation(**overrides), tenant_id="tenant-a",
        audit=lambda *args: evidence.append(args),
    )
    assert finding.risk == risk and finding.recommendations == recommendations
    assert finding.mode == "DRY_RUN" and finding.action == "DETECT_ONLY"
    assert finding.authority_granted is False
    assert evidence[0][0] == "network_threat_classified"
    assert evidence[0][1]["response_executed"] is False
    with pytest.raises(FrozenInstanceError):
        finding.risk = "LOW"


@pytest.mark.parametrize("overrides", [
    {"indicators": []},
    {"direction": "INBOUND", "indicators": ["UNAUTHORIZED_EGRESS"]},
    {"direction": "OUTBOUND", "indicators": ["LATERAL_MOVEMENT"]},
    {"protocol": "TLS", "indicators": ["SMB_WRITE"]},
    {"protocol": "TLS", "indicators": ["DNS_ANOMALY"]},
])
def test_network_classifier_rejects_empty_or_contradictory_facts(overrides):
    with pytest.raises(NetworkObservationDenied, match="INDICATORS_INVALID|INDICATOR_CONTEXT_INVALID"):
        classify_network_observation(
            observation(**overrides), tenant_id="tenant-a", audit=lambda *_args: None,
        )


def test_network_classifier_revalidates_tenant_authority_and_evidence():
    value = observation(indicators=["UNAUTHORIZED_EGRESS"])
    with pytest.raises(NetworkObservationDenied, match="TENANT_MISMATCH"):
        classify_network_observation(value, tenant_id="tenant-b", audit=lambda *_args: None)
    with pytest.raises(NetworkObservationDenied, match="OBSERVATION_AUTHORITY_INVALID"):
        classify_network_observation(
            replace(value, action="BLOCK"), tenant_id="tenant-a", audit=lambda *_args: None,
        )
    with pytest.raises(NetworkObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        classify_network_observation(
            value, tenant_id="tenant-a",
            audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
        )


@pytest.mark.parametrize("direction", ["INBOUND", "OUTBOUND", "EAST_WEST"])
def test_network_probe_is_direction_neutral_metadata(direction):
    finding = classify_network_observation(
        observation(direction=direction, indicators=["NETWORK_PROBE"]),
        tenant_id="tenant-a", audit=lambda *_args: None,
    )
    assert finding.risk == "MEDIUM"


def test_network_classifier_uses_highest_risk_for_combined_consistent_facts():
    finding = classify_network_observation(
        observation(
            protocol="DNS", port=53, direction="OUTBOUND",
            indicators=["C2_PATTERN", "DNS_ANOMALY"],
        ),
        tenant_id="tenant-a", audit=lambda *_args: None,
    )
    assert finding.risk == "CRITICAL"
    assert finding.recommendations == ("WARN", "PROPOSE_BLOCK")
