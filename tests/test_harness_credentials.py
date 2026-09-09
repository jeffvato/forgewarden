from dataclasses import replace

import pytest

from swarm.harness_credentials import (
    AuthMethod, CredentialBroker, CredentialRecord, HarnessCredentialError,
    credential_from_record, credential_record, default_provider_profiles,
)


MODELS = {"openai_model": "gpt-approved", "anthropic_model": "claude-approved", "gemini_model": "gemini-approved"}


def profiles():
    return default_provider_profiles(**MODELS)


def record(**changes):
    base = CredentialRecord(
        "credential-one", "openai-api-key", "openai", "tenant-one", "identity-one",
        "gpt-approved", AuthMethod.API_KEY, (), "fwkeys://tenant-one/openai/key",
        "approval-0011223344556677", 100.0, 200.0, True,
    )
    return replace(base, **changes)


def admit(value=None, **bindings):
    return CredentialBroker(profiles()).admit(
        value or record(), now=150.0, tenant_id=bindings.get("tenant_id", "tenant-one"),
        identity_id=bindings.get("identity_id", "identity-one"), provider=bindings.get("provider", "openai"),
        model_id=bindings.get("model_id", "gpt-approved"),
    )


def test_default_profiles_are_provider_specific_and_gemini_cli_is_agy():
    values = profiles()
    assert {(item.provider, item.method) for item in values} == {
        ("openai", AuthMethod.API_KEY), ("openai", AuthMethod.CLI_MANAGED_OAUTH),
        ("anthropic", AuthMethod.API_KEY), ("anthropic", AuthMethod.CLI_MANAGED_OAUTH),
        ("google", AuthMethod.API_KEY), ("google", AuthMethod.CLI_MANAGED_OAUTH),
    }
    assert next(item for item in values if item.profile_id == "google-gemini-oauth").cli_executable == "agy"


def test_valid_record_round_trips_and_admits_only_sanitized_metadata():
    restored = credential_from_record(credential_record(record()))
    decision = admit(restored)
    assert decision.decision == "ADMITTED" and decision.deployment == "DISABLED"
    assert decision.secret_handle.startswith("fwkeys://")


@pytest.mark.parametrize("field,value", [
    ("profile_id", "unknown-profile"), ("provider", "anthropic"), ("tenant_id", "tenant-two"),
    ("identity_id", "identity-two"), ("model_id", "other-model"),
    ("method", AuthMethod.CLI_MANAGED_OAUTH), ("scopes", ("unexpected",)),
])
def test_profile_and_identity_substitution_denies(field, value):
    with pytest.raises(HarnessCredentialError):
        admit(record(**{field: value}))


@pytest.mark.parametrize("value,match", [
    (record(approved=False), "approval is absent"),
    (record(revoked_at=160.0), "revoked"),
    (record(expires_at=150.0), "expired"),
])
def test_approval_revocation_and_expiry_deny(value, match):
    with pytest.raises(HarnessCredentialError, match=match):
        admit(value)


def test_raw_key_cannot_replace_fwkeys_handle():
    with pytest.raises(HarnessCredentialError, match="opaque FW-KEYS"):
        record(secret_handle="sk-this-is-a-secret")


@pytest.mark.parametrize("extra", [
    {"access_token": "secret"}, {"client_secret": "secret"}, {"api_key": "secret"},
])
def test_persistent_schema_rejects_secret_fields(extra):
    payload = credential_record(record()) | extra
    with pytest.raises(HarnessCredentialError, match="field set"):
        credential_from_record(payload)


def test_persistent_schema_rejects_secret_like_values_outside_handle():
    payload = credential_record(record())
    payload["identity_id"] = "Bearer token-value"
    with pytest.raises(HarnessCredentialError, match="secret material"):
        credential_from_record(payload)


def test_cli_oauth_scope_and_method_cannot_be_inferred_from_api_key_record():
    oauth = next(item for item in profiles() if item.profile_id == "openai-codex-oauth")
    value = record(profile_id=oauth.profile_id, method=AuthMethod.CLI_MANAGED_OAUTH)
    with pytest.raises(HarnessCredentialError, match="approved profile"):
        admit(value)


def test_broker_does_not_expose_mutation_or_secret_resolution_methods():
    broker = CredentialBroker(profiles())
    assert not any(hasattr(broker, name) for name in ("exchange", "refresh", "resolve", "revoke", "create"))
