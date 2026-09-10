from dataclasses import FrozenInstanceError

import pytest

from swarm.identity import IDENTITY_KINDS, IdentityContractError, validate_identity_record


def record(**changes):
    value = {"schema_version": "1", "identity_id": "fw-id/agent-codex-1", "tenant_id": "tenant-a", "identity_kind": "AI_AGENT", "owner_identity_ref": "fw-id/human-owner-1", "purpose": "bounded ForgeWarden code work", "lifecycle_state": "ACTIVE", "created_at_epoch": 100, "expires_at_epoch": 200, "provider_subject_ref": "provider/openai-codex", "credential_handle_ref": "fwkeys://tenant-a/provider/openai-codex"}
    value.update(changes)
    return value


def test_identity_contract_is_immutable_tenant_bound_metadata_without_authority():
    identity = validate_identity_record(record())
    assert identity.identity_id == "fw-id/agent-codex-1"
    assert identity.tenant_id == "tenant-a" and identity.identity_kind == "AI_AGENT"
    assert identity.credential_handle_ref.startswith("fwkeys://tenant-a/")
    assert not hasattr(identity, "capabilities") and not hasattr(identity, "permissions")
    with pytest.raises(FrozenInstanceError):
        identity.lifecycle_state = "REVOKED"


@pytest.mark.parametrize("kind", sorted(IDENTITY_KINDS))
def test_identity_contract_supports_exact_bounded_identity_kinds(kind):
    assert validate_identity_record(record(identity_kind=kind)).identity_kind == kind


@pytest.mark.parametrize("change", [
    {"schema_version": "2"}, {"identity_id": "agent-codex-1"}, {"tenant_id": "Tenant A"},
    {"identity_kind": "SUPERUSER"}, {"owner_identity_ref": "root"}, {"purpose": ""},
    {"lifecycle_state": "DISABLED"}, {"created_at_epoch": True}, {"expires_at_epoch": 100},
    {"provider_subject_ref": "raw subject"}, {"credential_handle_ref": "secret-value"},
    {"credential_handle_ref": "fwkeys://tenant-b/provider/openai-codex"}, {"extra": "field"},
])
def test_identity_contract_denies_malformed_or_authority_shaped_input(change):
    with pytest.raises(IdentityContractError):
        validate_identity_record(record(**change))


@pytest.mark.parametrize("field,value", [("purpose", "Bearer abcdefghijklmnop"), ("provider_subject_ref", "provider/sk-abcdefghijk")])
def test_identity_contract_denies_credential_material(field, value):
    with pytest.raises(IdentityContractError, match="credential material"):
        validate_identity_record(record(**{field: value}))


def test_identity_contract_allows_no_provider_or_credential_for_local_human():
    identity = validate_identity_record(record(identity_id="fw-id/human-owner-1", identity_kind="HUMAN", owner_identity_ref="fw-id/human-owner-1", provider_subject_ref=None, credential_handle_ref=None, expires_at_epoch=None))
    assert identity.provider_subject_ref is None and identity.credential_handle_ref is None
