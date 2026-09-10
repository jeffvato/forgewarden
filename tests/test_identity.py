from dataclasses import FrozenInstanceError
from threading import Event, Thread

import pytest

from swarm.identity import IDENTITY_KINDS, IdentityContractError, IdentityRegistry, bind_delegated_provider_identity, validate_identity_record
from swarm.keys import SecretHandleRegistry, validate_secret_handle_record


def record(**changes):
    value = {"schema_version": "1", "identity_id": "fw-id/agent-codex-1", "tenant_id": "tenant-a", "identity_kind": "AI_AGENT", "owner_identity_ref": "fw-id/human-owner-1", "purpose": "bounded ForgeWarden code work", "lifecycle_state": "ACTIVE", "created_at_epoch": 100, "lifecycle_changed_at_epoch": 100, "expires_at_epoch": 200, "provider_subject_ref": "provider/openai-codex", "credential_handle_ref": "fwkeys://tenant-a/provider/openai-codex"}
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
    {"lifecycle_state": "DISABLED"}, {"created_at_epoch": True}, {"lifecycle_changed_at_epoch": 99}, {"expires_at_epoch": 100},
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


def test_registry_is_evidence_first_create_once_and_tenant_bound():
    events = []
    registry = IdentityRegistry(lambda *args: events.append(args))
    identity = validate_identity_record(record())
    assert registry.register(identity) is identity
    assert events[0][0] == "fw_id_registered" and not events[0][1]["authority_granted"]
    assert "purpose" not in events[0][1] and "credential_handle_ref" not in events[0][1]
    assert registry.get(identity.identity_id, tenant_id="tenant-a") is identity
    with pytest.raises(FrozenInstanceError):
        registry.get(identity.identity_id, tenant_id="tenant-a").purpose = "changed"
    with pytest.raises(IdentityContractError, match="tenant mismatch"):
        registry.get(identity.identity_id, tenant_id="tenant-b")
    with pytest.raises(IdentityContractError, match="already registered"):
        registry.register(identity)


def test_registry_snapshot_cannot_enumerate_another_tenant():
    registry = IdentityRegistry(lambda *_args: None)
    registry.register(validate_identity_record(record()))
    registry.register(validate_identity_record(record(identity_id="fw-id/service-b", tenant_id="tenant-b", credential_handle_ref="fwkeys://tenant-b/provider/service")))
    assert tuple(item.identity_id for item in registry.tenant_snapshot("tenant-a")) == ("fw-id/agent-codex-1",)
    assert tuple(item.identity_id for item in registry.tenant_snapshot("tenant-b")) == ("fw-id/service-b",)


def test_registry_activation_revocation_and_expiration_are_deterministic_terminal_transitions():
    registry = IdentityRegistry(lambda *_args: None)
    provisioned = validate_identity_record(record(lifecycle_state="PROVISIONED"))
    registry.register(provisioned)
    active = registry.activate(provisioned.identity_id, tenant_id="tenant-a", now_epoch=110)
    assert active.lifecycle_state == "ACTIVE" and active.lifecycle_changed_at_epoch == 110
    revoked = registry.revoke(active.identity_id, tenant_id="tenant-a", now_epoch=120)
    assert revoked.lifecycle_state == "REVOKED"
    with pytest.raises(IdentityContractError, match="transition is invalid"):
        registry.activate(revoked.identity_id, tenant_id="tenant-a", now_epoch=130)

    expiring = validate_identity_record(record(identity_id="fw-id/service-expiring", lifecycle_state="PROVISIONED"))
    registry.register(expiring)
    expired = registry.expire(expiring.identity_id, tenant_id="tenant-a", now_epoch=200)
    assert expired.lifecycle_state == "EXPIRED"


def test_registry_denials_and_evidence_failure_leave_state_unchanged():
    fail = False

    def audit(*_args):
        if fail:
            raise OSError("offline")

    registry = IdentityRegistry(audit)
    identity = validate_identity_record(record(lifecycle_state="PROVISIONED"))
    registry.register(identity)
    fail = True
    with pytest.raises(IdentityContractError, match="Evidence write failed"):
        registry.activate(identity.identity_id, tenant_id="tenant-a", now_epoch=110)
    assert registry.get(identity.identity_id, tenant_id="tenant-a") == identity
    fail = False
    with pytest.raises(IdentityContractError, match="timestamp is stale"):
        registry.activate(identity.identity_id, tenant_id="tenant-a", now_epoch=99)
    with pytest.raises(IdentityContractError, match="has not reached expiration"):
        registry.expire(identity.identity_id, tenant_id="tenant-a", now_epoch=150)
    assert registry.get(identity.identity_id, tenant_id="tenant-a") == identity


def test_registry_reentrant_duplicate_is_denied_without_state_replacement():
    identity = validate_identity_record(record())
    registry = None

    def audit(event, _evidence):
        if event == "fw_id_registered":
            with pytest.raises(IdentityContractError, match="pending"):
                registry.register(identity)

    registry = IdentityRegistry(audit)
    registry.register(identity)
    assert registry.get(identity.identity_id, tenant_id="tenant-a") is identity


def test_concurrent_registration_for_same_identity_is_denied_while_reserved():
    entered, release = Event(), Event()
    identity = validate_identity_record(record())

    def audit(event, _evidence):
        if event == "fw_id_registered":
            entered.set()
            assert release.wait(2)

    registry = IdentityRegistry(audit)
    worker = Thread(target=registry.register, args=(identity,))
    worker.start()
    assert entered.wait(2)
    with pytest.raises(IdentityContractError, match="pending"):
        registry.register(identity)
    release.set()
    worker.join(2)
    assert not worker.is_alive()
    assert registry.get(identity.identity_id, tenant_id="tenant-a") is identity


def test_concurrent_transition_for_same_identity_is_denied_while_reserved():
    entered, release = Event(), Event()
    block_transition = False

    def audit(event, _evidence):
        if event == "fw_id_lifecycle_changed" and block_transition:
            entered.set()
            assert release.wait(2)

    registry = IdentityRegistry(audit)
    identity = validate_identity_record(record(lifecycle_state="PROVISIONED"))
    registry.register(identity)
    block_transition = True
    worker = Thread(target=lambda: registry.activate(identity.identity_id, tenant_id="tenant-a", now_epoch=110))
    worker.start()
    assert entered.wait(2)
    with pytest.raises(IdentityContractError, match="pending"):
        registry.revoke(identity.identity_id, tenant_id="tenant-a", now_epoch=111)
    release.set()
    worker.join(2)
    assert not worker.is_alive()
    assert registry.get(identity.identity_id, tenant_id="tenant-a").lifecycle_state == "ACTIVE"


def provider_registry(audit=lambda *_args: None):
    registry = IdentityRegistry(audit)
    owner = validate_identity_record(record(identity_id="fw-id/human-owner-1", identity_kind="HUMAN", owner_identity_ref="fw-id/human-owner-1", provider_subject_ref=None, credential_handle_ref=None, expires_at_epoch=None))
    subject = validate_identity_record(record())
    registry.register(owner)
    registry.register(subject)
    return registry


def provider_key_registry(audit=lambda *_args: None, *, owner="fw-id/agent-codex-1", credential_class="OAUTH_TOKEN_SET", lifecycle_state="ACTIVE", expires=200):
    registry = SecretHandleRegistry(audit)
    registry.register(validate_secret_handle_record({
        "schema_version": "1", "handle_id": "fwkeys://tenant-a/provider/openai-codex",
        "tenant_id": "tenant-a", "credential_class": credential_class,
        "owner_identity_ref": owner, "purpose": "provider binding",
        "backend_reference_class": "TRUSTED_ADAPTER", "lifecycle_state": lifecycle_state,
        "created_at_epoch": 100, "lifecycle_changed_at_epoch": 100,
        "expires_at_epoch": expires, "generation": 1, "export_policy": "NON_EXPORTABLE",
    }))
    return registry


def binding(**changes):
    value = {"binding_id": "fw-id-binding/codex-openai-1", "tenant_id": "tenant-a", "subject_identity_id": "fw-id/agent-codex-1", "owner_identity_id": "fw-id/human-owner-1", "provider": "OPENAI", "provider_subject_ref": "provider/openai-codex", "consent_ref": "approval/provider-consent-1", "credential_class": "OAUTH_TOKEN_SET", "credential_handle_ref": "fwkeys://tenant-a/provider/openai-codex", "issued_at_epoch": 100, "expires_at_epoch": 200}
    value.update(changes)
    return value


@pytest.mark.parametrize("provider", ["OPENAI", "ANTHROPIC", "GOOGLE", "AZURE"])
def test_delegated_provider_binding_is_immutable_evidence_first_and_authority_free(provider):
    events = []
    result = bind_delegated_provider_identity(binding(provider=provider), registry=provider_registry(), key_registry=provider_key_registry(), now_epoch=150, audit=lambda *args: events.append(args))
    assert result.provider == provider and result.mode == "DRY_RUN" and not result.authority_granted
    assert events[0][0] == "fw_id_provider_identity_bound"
    assert events[0][1]["credential_resolved"] is False and "credential_handle_ref" not in events[0][1]
    with pytest.raises(FrozenInstanceError):
        result.provider = "OTHER"


@pytest.mark.parametrize("change,reason", [
    ({"tenant_id": "tenant-b"}, "identity tenant mismatch"),
    ({"owner_identity_id": "fw-id/missing"}, "not registered"),
    ({"provider": "OTHER"}, "not approved"),
    ({"credential_class": "PASSWORD"}, "not approved"),
    ({"provider_subject_ref": "provider/other"}, "subject binding mismatch"),
    ({"consent_ref": "raw consent"}, "consent_ref is invalid"),
    ({"credential_handle_ref": "fwkeys://tenant-b/provider/openai-codex"}, "handle binding mismatch"),
    ({"issued_at_epoch": 151}, "stale or expired"),
    ({"expires_at_epoch": 150}, "stale or expired"),
    ({"expires_at_epoch": 201}, "exceeds identity lifetime"),
    ({"extra": "field"}, "binding is invalid"),
])
def test_delegated_provider_binding_denies_malformed_cross_tenant_or_stale_input(change, reason):
    with pytest.raises(IdentityContractError, match=reason):
        bind_delegated_provider_identity(binding(**change), registry=provider_registry(), key_registry=provider_key_registry(), now_epoch=150, audit=lambda *_args: None)


def test_delegated_provider_binding_denies_inactive_subject_owner_mismatch_and_evidence_failure():
    registry = provider_registry()
    registry.revoke("fw-id/agent-codex-1", tenant_id="tenant-a", now_epoch=150)
    with pytest.raises(IdentityContractError, match="must be active"):
        bind_delegated_provider_identity(binding(), registry=registry, key_registry=provider_key_registry(), now_epoch=160, audit=lambda *_args: None)
    mismatched = provider_registry()
    other = validate_identity_record(record(identity_id="fw-id/human-other", identity_kind="HUMAN", owner_identity_ref="fw-id/human-other", provider_subject_ref=None, credential_handle_ref=None, expires_at_epoch=None))
    mismatched.register(other)
    with pytest.raises(IdentityContractError, match="owner mismatch"):
        bind_delegated_provider_identity(binding(owner_identity_id=other.identity_id), registry=mismatched, key_registry=provider_key_registry(), now_epoch=150, audit=lambda *_args: None)
    with pytest.raises(IdentityContractError, match="Evidence write failed"):
        bind_delegated_provider_identity(binding(), registry=provider_registry(), key_registry=provider_key_registry(), now_epoch=150, audit=lambda *_args: (_ for _ in ()).throw(OSError("offline")))


@pytest.mark.parametrize("field,value", [("consent_ref", "approval/Bearer abcdefghijkl"), ("provider_subject_ref", "provider/ya29.abcdefghijk")])
def test_delegated_provider_binding_rejects_raw_credential_material(field, value):
    with pytest.raises(IdentityContractError, match="credential material"):
        bind_delegated_provider_identity(binding(**{field: value}), registry=provider_registry(), key_registry=provider_key_registry(), now_epoch=150, audit=lambda *_args: None)


@pytest.mark.parametrize("keys,match", [
    (SecretHandleRegistry(lambda *_args: None), "admission denied"),
    (provider_key_registry(owner="fw-id/other-agent"), "not active or exact"),
    (provider_key_registry(credential_class="API_KEY"), "not active or exact"),
    (provider_key_registry(lifecycle_state="REVOKED"), "not active or exact"),
    (provider_key_registry(expires=150), "not active or exact"),
])
def test_provider_binding_requires_exact_active_key_registry_record(keys, match):
    with pytest.raises(IdentityContractError, match=match):
        bind_delegated_provider_identity(
            binding(), registry=provider_registry(), key_registry=keys,
            now_epoch=150, audit=lambda *_args: None,
        )
