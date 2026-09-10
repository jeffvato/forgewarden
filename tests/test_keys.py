from dataclasses import FrozenInstanceError, asdict
from threading import Event, Thread

import pytest

from swarm.keys import (
    KeyContractError, SecretHandleRecord, SecretHandleRegistry,
    validate_secret_handle_record,
)


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


def key(**changes):
    return validate_secret_handle_record(record(**changes))


def test_registry_is_create_once_tenant_scoped_and_evidence_excludes_handles():
    events = []
    registry = SecretHandleRegistry(lambda event, evidence: events.append((event, evidence)))
    first = registry.register(key())
    second = registry.register(key(
        handle_id="fwkeys://tenant-a/signing/catalog",
        credential_class="SIGNING_KEY",
    ))
    assert registry.get(first.handle_id, tenant_id="tenant-a") == first
    assert registry.tenant_snapshot("tenant-a") == (first, second)
    assert registry.tenant_snapshot("tenant-b") == ()
    assert events[0][0] == "fw_keys_handle_registered"
    assert "handle_id" not in events[0][1]
    assert "backend_reference_class" not in events[0][1]
    assert "purpose" not in events[0][1]
    assert events[0][1]["credential_resolved"] is False
    with pytest.raises(KeyContractError, match="already registered"):
        registry.register(first)
    with pytest.raises(KeyContractError, match="tenant mismatch"):
        registry.get(first.handle_id, tenant_id="tenant-b")


def test_evidence_failure_prevents_registration_and_transition():
    def deny(*_args):
        raise RuntimeError("sink unavailable")

    registry = SecretHandleRegistry(deny)
    value = key(lifecycle_state="PROVISIONED", lifecycle_changed_at_epoch=100)
    with pytest.raises(KeyContractError, match="Evidence write failed"):
        registry.register(value)
    with pytest.raises(KeyContractError, match="not registered"):
        registry.get(value.handle_id, tenant_id=value.tenant_id)

    events = []
    registry = SecretHandleRegistry(lambda *args: events.append(args))
    registry.register(value)
    registry._audit = deny
    with pytest.raises(KeyContractError, match="Evidence write failed"):
        registry.activate(value.handle_id, tenant_id=value.tenant_id, now_epoch=110)
    assert registry.get(value.handle_id, tenant_id=value.tenant_id).lifecycle_state == "PROVISIONED"


def test_lifecycle_is_closed_and_stale_replay_denied():
    registry = SecretHandleRegistry(lambda *_args: None)
    value = registry.register(key(
        lifecycle_state="PROVISIONED", lifecycle_changed_at_epoch=100,
    ))
    active = registry.activate(value.handle_id, tenant_id=value.tenant_id, now_epoch=110)
    assert active.lifecycle_state == "ACTIVE"
    with pytest.raises(KeyContractError, match="transition"):
        registry.activate(value.handle_id, tenant_id=value.tenant_id, now_epoch=111)
    with pytest.raises(KeyContractError, match="has not reached expiration"):
        registry.expire(value.handle_id, tenant_id=value.tenant_id, now_epoch=150)
    revoked = registry.revoke(value.handle_id, tenant_id=value.tenant_id, now_epoch=160)
    assert revoked.lifecycle_state == "REVOKED"
    with pytest.raises(KeyContractError, match="transition"):
        registry.revoke(value.handle_id, tenant_id=value.tenant_id, now_epoch=161)


@pytest.mark.parametrize("expires,now,match", [
    (200, 200, "expired secret handle"),
    (None, 200, "has not reached expiration"),
])
def test_expiration_boundaries_fail_closed(expires, now, match):
    registry = SecretHandleRegistry(lambda *_args: None)
    value = registry.register(key(
        lifecycle_state="PROVISIONED", lifecycle_changed_at_epoch=100,
        expires_at_epoch=expires,
    ))
    operation = registry.activate if expires is not None else registry.expire
    with pytest.raises(KeyContractError, match=match):
        operation(value.handle_id, tenant_id=value.tenant_id, now_epoch=now)


def test_generation_replacement_is_exact_evidence_first_and_replay_safe():
    events = []
    registry = SecretHandleRegistry(lambda *args: events.append(args))
    current = registry.register(key())
    replacement = key(
        lifecycle_state="PROVISIONED",
        created_at_epoch=120,
        lifecycle_changed_at_epoch=120,
        expires_at_epoch=300,
        generation=2,
    )
    updated = registry.replace_generation(
        current.handle_id, replacement, tenant_id="tenant-a", now_epoch=120,
    )
    assert updated == replacement
    assert events[-1][0] == "fw_keys_generation_replaced"
    assert "handle_id" not in events[-1][1]
    with pytest.raises(KeyContractError, match="only an active"):
        registry.replace_generation(
            current.handle_id,
            key(created_at_epoch=130, lifecycle_changed_at_epoch=130, generation=3),
            tenant_id="tenant-a",
            now_epoch=130,
        )


@pytest.mark.parametrize("changes,match", [
    ({"generation": 3}, "generation"),
    ({"handle_id": "fwkeys://tenant-a/provider/replacement"}, "binding mismatch"),
    ({"tenant_id": "tenant-b", "handle_id": "fwkeys://tenant-b/provider/openai-codex"}, "binding mismatch"),
    ({"owner_identity_ref": "fw-id/other-owner"}, "binding mismatch"),
    ({"credential_class": "API_KEY"}, "binding mismatch"),
    ({"backend_reference_class": "HSM"}, "binding mismatch"),
    ({"export_policy": "NON_EXPORTABLE", "purpose": "different purpose"}, "binding mismatch"),
    ({"lifecycle_state": "ACTIVE"}, "generation"),
    ({"created_at_epoch": 119, "lifecycle_changed_at_epoch": 120}, "generation"),
])
def test_generation_replacement_rejects_substitution_and_stale_values(changes, match):
    registry = SecretHandleRegistry(lambda *_args: None)
    current = registry.register(key())
    replacement = record(
        lifecycle_state="PROVISIONED",
        created_at_epoch=120,
        lifecycle_changed_at_epoch=120,
        expires_at_epoch=300,
        generation=2,
    )
    replacement.update(changes)
    with pytest.raises(KeyContractError, match=match):
        registry.replace_generation(
            current.handle_id,
            validate_secret_handle_record(replacement),
            tenant_id="tenant-a",
            now_epoch=120,
        )
    assert registry.get(current.handle_id, tenant_id="tenant-a") == current


def test_reentrant_and_concurrent_operations_fail_closed():
    entered = Event()
    release = Event()
    holder = {}
    errors = []

    def audit(event, _evidence):
        if event == "fw_keys_lifecycle_changed":
            entered.set()
            assert release.wait(2)

    registry = SecretHandleRegistry(audit)
    value = registry.register(key(
        lifecycle_state="PROVISIONED", lifecycle_changed_at_epoch=100,
    ))
    holder["thread"] = Thread(
        target=lambda: registry.activate(
            value.handle_id, tenant_id="tenant-a", now_epoch=110,
        )
    )
    holder["thread"].start()
    assert entered.wait(2)
    with pytest.raises(KeyContractError, match="transition pending"):
        registry.revoke(value.handle_id, tenant_id="tenant-a", now_epoch=111)
    release.set()
    holder["thread"].join(2)
    assert not holder["thread"].is_alive()
    assert registry.get(value.handle_id, tenant_id="tenant-a").lifecycle_state == "ACTIVE"

    reentrant_registry = None
    def reentrant(event, _evidence):
        if event == "fw_keys_handle_registered":
            try:
                reentrant_registry.register(value)
            except KeyContractError as exc:
                errors.append(str(exc))

    reentrant_registry = SecretHandleRegistry(reentrant)
    reentrant_registry.register(value)
    assert errors == ["secret handle already registered or transition pending"]


def test_registry_exposes_no_material_or_authority_methods():
    registry = SecretHandleRegistry(lambda *_args: None)
    assert not any(hasattr(registry, name) for name in (
        "resolve", "read_secret", "export", "sign", "encrypt", "authenticate",
        "authorize", "issue_ticket", "deploy", "execute",
    ))
