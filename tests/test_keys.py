from dataclasses import FrozenInstanceError, asdict

import pytest

from swarm.keys import KeyContractError, SecretHandleRecord, validate_secret_handle_record


def record(**changes):
    value = {
        "schema_version": "1",
        "handle_id": "fwkeys://tenant-a/provider/openai-codex",
        "tenant_id": "tenant-a",
        "credential_class": "OAUTH_TOKEN_SET",
        "owner_identity_ref": "fw-id/agent-codex-1",
        "purpose": "bounded provider authentication reference",
        "backend_reference_class": "TRUSTED_ADAPTER",
        "lifecycle_state": "ACTIVE",
        "created_at_epoch": 100,
        "lifecycle_changed_at_epoch": 110,
        "expires_at_epoch": 200,
        "generation": 1,
        "export_policy": "NON_EXPORTABLE",
    }
    value.update(changes)
    return value


def test_canonical_secret_handle_record_is_exact_immutable_and_authority_free():
    value = validate_secret_handle_record(record())
    assert isinstance(value, SecretHandleRecord)
    assert asdict(value) == record()
    with pytest.raises(FrozenInstanceError):
        value.lifecycle_state = "REVOKED"
    assert not any(hasattr(value, name) for name in (
        "resolve", "read", "export", "authenticate", "authorize", "deploy", "execute",
    ))


@pytest.mark.parametrize("change,match", [
    ({"schema_version": "2"}, "schema version"),
    ({"handle_id": "secret-value"}, "opaque FW-KEYS"),
    ({"handle_id": "fwkeys://tenant-b/provider/openai-codex"}, "tenant mismatch"),
    ({"tenant_id": "Tenant A"}, "tenant_id"),
    ({"credential_class": "PASSWORD"}, "credential_class"),
    ({"owner_identity_ref": "agent-codex-1"}, "owner_identity_ref"),
    ({"purpose": ""}, "purpose"),
    ({"backend_reference_class": "ENVIRONMENT_VARIABLE"}, "backend_reference_class"),
    ({"lifecycle_state": "ENABLED"}, "lifecycle_state"),
    ({"created_at_epoch": True}, "created_at_epoch"),
    ({"lifecycle_changed_at_epoch": 99}, "lifecycle_changed_at_epoch"),
    ({"expires_at_epoch": 100}, "expires_at_epoch"),
    ({"generation": 0}, "generation"),
    ({"export_policy": "EXPORTABLE"}, "non-exportable"),
])
def test_invalid_metadata_fails_closed(change, match):
    with pytest.raises(KeyContractError, match=match):
        validate_secret_handle_record(record(**change))


@pytest.mark.parametrize("change", [
    {"handle_id": "fwkeys://tenant-a/provider/sk-123456789"},
    {"purpose": "Bearer token-value"},
    {"purpose": "api_key=fixture-secret"},
    {"purpose": "-----BEGIN " + "PRIVATE KEY-----"},
])
def test_secret_shaped_values_are_rejected(change):
    with pytest.raises(KeyContractError, match="secret material"):
        validate_secret_handle_record(record(**change))


@pytest.mark.parametrize("extra", [
    {"secret": "value"}, {"api_key": "value"}, {"access_token": "value"},
    {"private_key": "value"}, {"credential": "value"},
])
def test_secret_fields_are_rejected_before_construction(extra):
    with pytest.raises(KeyContractError, match="field set"):
        validate_secret_handle_record(record() | extra)


def test_supported_metadata_classes_are_closed_and_do_not_activate_backends():
    for credential_class in (
        "API_KEY", "OAUTH_TOKEN_SET", "SERVICE_PRINCIPAL",
        "SIGNING_KEY", "ENCRYPTION_KEY", "HMAC_KEY", "TRUST_ANCHOR",
    ):
        value = validate_secret_handle_record(record(credential_class=credential_class))
        assert value.export_policy == "NON_EXPORTABLE"
    for backend in ("TRUSTED_ADAPTER", "LOCAL_KEYSTORE", "HSM", "EXTERNAL_VAULT"):
        value = validate_secret_handle_record(record(backend_reference_class=backend))
        assert value.backend_reference_class == backend


def test_expiration_is_optional_but_never_grants_lifecycle_authority():
    value = validate_secret_handle_record(record(expires_at_epoch=None, lifecycle_state="PROVISIONED"))
    assert value.expires_at_epoch is None
