from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace

import pytest

from swarm.api_contract import APIContractError, APIReadAdmissionRegistry, validate_api_read_request
from swarm.asoc import CapabilityLease, HMACLeaseSigner, KillSwitch, LeaseRegistry
from swarm.identity import IdentityRegistry, validate_identity_record
from swarm.policy_gate import DeterministicPolicy, PolicyRule


def request(**changes):
    value = {"schema_version": "1", "request_id": "api-request-1", "tenant_id": "tenant-a", "requester_identity_id": "fw-id/api-reader-1", "purpose": "read endpoint security posture", "capability": "telemetry.read", "resource": "endpoint-123", "action_class": "READ", "policy_version": "FW-API-001-v1", "lease_id": "lease-api-1", "issued_at_epoch": 100, "expires_at_epoch": 200, "data_classification": "INTERNAL"}
    value.update(changes)
    return value


def identity(**changes):
    value = {"schema_version": "1", "identity_id": "fw-id/api-reader-1", "tenant_id": "tenant-a", "identity_kind": "SERVICE", "owner_identity_ref": "fw-id/human-owner-1", "purpose": "bounded read-only API access", "lifecycle_state": "ACTIVE", "created_at_epoch": 50, "lifecycle_changed_at_epoch": 50, "expires_at_epoch": 250, "provider_subject_ref": None, "credential_handle_ref": None}
    value.update(changes)
    return validate_identity_record(value)


def dependencies(*, evidence=None, identity_value=None, policy_rule=None, lease_changes=None):
    identities = IdentityRegistry(lambda *_args: None)
    identities.register(identity_value or identity())
    switch = KillSwitch(engaged=False)
    signer = HMACLeaseSigner({"fw-keys/api-test": b"test-only-api-lease-key"})
    leases = LeaseRegistry(signer, switch)
    values = dict(lease_id="lease-api-1", subject_agent_id="fw-id/api-reader-1", issuer_identity="fw-id/human-owner-1", tenant_id="tenant-a", granted_capabilities=("telemetry.read",), allowed_tools=("api.read",), allowed_resources=("endpoint-123",), allowed_data_classifications=("INTERNAL",), allowed_action_classes=("READ",), max_blast_radius=0, delegation_allowed=False, delegation_depth=0, valid_from=90, expires_at=210, policy_version="FW-API-001-v1", approval_reference="approval-api-1", action_ticket_reference="ticket-not-used-read-only", creation_reason="bounded read-only API", key_reference="fw-keys/api-test")
    values.update(lease_changes or {})
    leases.issue(CapabilityLease(**values))
    rule = policy_rule or PolicyRule("tenant-a", "telemetry.read", "endpoint-123", "READ", "FW-API-001-v1")
    events = []
    sink = evidence or (lambda event, payload: events.append((event, payload)) or "fw-evid/tenant-a/api/request-1")
    return APIReadAdmissionRegistry(identities, DeterministicPolicy((rule,)), leases, sink), events


def test_read_request_admission_is_evidence_first_immutable_and_authority_free():
    registry, events = dependencies()
    result = registry.admit(validate_api_read_request(request()), now_epoch=150)
    assert events[0][0] == "fw_api_read_admitted"
    assert events[0][1]["handler_invoked"] is False and events[0][1]["authority_granted"] is False
    assert "purpose" not in events[0][1] and "data_classification" not in events[0][1]
    assert result.action == "ADMIT_READ_ONLY" and result.handler_invoked is False
    assert result.mode == "DRY_RUN" and result.deployment == "DISABLED" and result.authority_granted is False
    with pytest.raises(FrozenInstanceError):
        result.action = "EXECUTE"


@pytest.mark.parametrize("change", [
    {"schema_version": "2"}, {"request_id": ""}, {"tenant_id": "Tenant A"},
    {"requester_identity_id": "reader"}, {"purpose": ""}, {"action_class": "WRITE"},
    {"issued_at_epoch": True}, {"expires_at_epoch": 100}, {"data_classification": "TOP_SECRET"},
    {"extra": "field"},
])
def test_request_contract_rejects_malformed_version_mutation_and_extra_fields(change):
    with pytest.raises(APIContractError):
        validate_api_read_request(request(**change))


@pytest.mark.parametrize("field,value", [("purpose", "api_key=secret-value"), ("resource", "Bearer abcdefghijklmnop")])
def test_request_contract_rejects_secret_material(field, value):
    with pytest.raises(APIContractError, match="secret-bearing"):
        validate_api_read_request(request(**{field: value}))


def test_admission_rejects_stale_replay_and_unsafe_runtime_state():
    registry, _ = dependencies()
    value = validate_api_read_request(request())
    with pytest.raises(APIContractError, match="stale"):
        registry.admit(value, now_epoch=200)
    with pytest.raises(APIContractError, match="safety"):
        registry.admit(value, now_epoch=150, kill_switch="CLEARED")
    with pytest.raises(APIContractError, match="safety"):
        registry.admit(value, now_epoch=150, deployment="ENABLED")
    registry.admit(value, now_epoch=150)
    with pytest.raises(APIContractError, match="replay"):
        registry.admit(value, now_epoch=150)


def test_admission_rejects_identity_policy_lease_and_evidence_mismatch():
    inactive, _ = dependencies(identity_value=identity(lifecycle_state="REVOKED"))
    with pytest.raises(APIContractError, match="not active"):
        inactive.admit(validate_api_read_request(request()), now_epoch=150)
    denied, _ = dependencies(policy_rule=PolicyRule("tenant-a", "evidence.read", "endpoint-123", "READ", "FW-API-001-v1"))
    with pytest.raises(APIContractError, match="policy denied"):
        denied.admit(validate_api_read_request(request()), now_epoch=150)
    mismatched, _ = dependencies(lease_changes={"allowed_resources": ("endpoint-456",)})
    with pytest.raises(APIContractError, match="binding mismatch"):
        mismatched.admit(validate_api_read_request(request()), now_epoch=150)
    failed, _ = dependencies(evidence=lambda *_args: (_ for _ in ()).throw(OSError("offline")))
    with pytest.raises(APIContractError, match="Evidence write failed"):
        failed.admit(validate_api_read_request(request()), now_epoch=150)
    foreign, _ = dependencies(evidence=lambda *_args: "fw-evid/tenant-b/api/request-1")
    with pytest.raises(APIContractError, match="Evidence reference"):
        foreign.admit(validate_api_read_request(request()), now_epoch=150)



@pytest.mark.parametrize("change", [
    {"requester_identity_id": "fw-id/unknown-reader"},
    {"tenant_id": "tenant-b"},
])
def test_admission_rejects_unknown_identity_and_cross_tenant_request(change):
    registry, _ = dependencies()
    with pytest.raises(APIContractError, match="identity admission denied"):
        registry.admit(validate_api_read_request(request(**change)), now_epoch=150)


def test_admission_rejects_missing_and_expired_lease():
    registry, _ = dependencies()
    with pytest.raises(APIContractError, match="policy or lease validation failed"):
        registry.admit(
            validate_api_read_request(request(lease_id="lease-missing")),
            now_epoch=150,
        )

    expired, _ = dependencies(lease_changes={"expires_at": 140})
    with pytest.raises(APIContractError, match="lease is not active"):
        expired.admit(validate_api_read_request(request()), now_epoch=150)

def test_concurrent_duplicate_is_denied_before_second_evidence_write():
    calls = []
    def sink(_event, _payload):
        calls.append(1)
        return "fw-evid/tenant-a/api/request-1"
    registry, _ = dependencies(evidence=sink)
    value = validate_api_read_request(request())
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [pool.submit(registry.admit, value, now_epoch=150) for _ in range(2)]
    outcomes = []
    for future in results:
        try:
            outcomes.append(future.result().request_id)
        except APIContractError as exc:
            outcomes.append(str(exc))
    assert outcomes.count("api-request-1") == 1
    assert sum("replay denied" in item for item in outcomes) == 1
    assert len(calls) == 1
