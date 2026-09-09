"""Deterministic provider-authentication metadata for FW-HARNESS.

This module records approvals and opaque FW-KEYS references.  It performs no
OAuth exchange, token refresh, secret resolution, provider call, or discovery.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping


_ID = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_SUBJECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_HANDLE = re.compile(r"^fwkeys://[A-Za-z0-9_.-]{1,64}/[A-Za-z0-9_.:/-]{1,192}$")
_APPROVAL = re.compile(r"^approval-[a-z0-9]{16,64}$")
_SECRET_NAME = re.compile(r"(?i)(access[_-]?token|refresh[_-]?token|client[_-]?secret|api[_-]?key|authorization|password)")
_SECRET_VALUE = re.compile(r"(?i)(bearer\s+\S+|sk-[A-Za-z0-9_-]{8,}|AIza[A-Za-z0-9_-]{8,}|ya29\.[A-Za-z0-9._-]{8,})")


class HarnessCredentialError(ValueError):
    """Credential metadata failed deterministic admission."""


class AuthMethod(str, Enum):
    API_KEY = "api_key"
    CLI_MANAGED_OAUTH = "cli_managed_oauth"


@dataclass(frozen=True)
class ProviderAuthProfile:
    profile_id: str
    provider: str
    model_ids: tuple[str, ...]
    method: AuthMethod
    credential_class: str
    scopes: tuple[str, ...]
    cli_executable: str | None = None

    def __post_init__(self) -> None:
        if not all(_ID.fullmatch(value) for value in (self.profile_id, self.provider, self.credential_class)):
            raise HarnessCredentialError("provider profile identity is malformed")
        if not self.model_ids or len(set(self.model_ids)) != len(self.model_ids) or any(not _ID.fullmatch(value) for value in self.model_ids):
            raise HarnessCredentialError("provider profile models are malformed")
        if not isinstance(self.method, AuthMethod):
            raise HarnessCredentialError("provider authentication method is unsupported")
        if len(set(self.scopes)) != len(self.scopes) or any(not _SUBJECT.fullmatch(value) for value in self.scopes):
            raise HarnessCredentialError("provider OAuth scopes are malformed")
        if self.method == AuthMethod.API_KEY:
            if self.scopes or self.cli_executable is not None:
                raise HarnessCredentialError("API-key profiles cannot claim OAuth scopes or CLI identity")
        elif not self.scopes or not self.cli_executable or not _ID.fullmatch(self.cli_executable):
            raise HarnessCredentialError("CLI OAuth profiles require exact executable and scopes")


@dataclass(frozen=True)
class CredentialRecord:
    credential_id: str
    profile_id: str
    provider: str
    tenant_id: str
    identity_id: str
    model_id: str
    method: AuthMethod
    scopes: tuple[str, ...]
    secret_handle: str
    approval_id: str
    issued_at: float
    expires_at: float
    approved: bool
    revoked_at: float | None = None

    def __post_init__(self) -> None:
        if not all(_ID.fullmatch(value) for value in (self.credential_id, self.profile_id, self.provider, self.model_id)):
            raise HarnessCredentialError("credential identity is malformed")
        if not _SUBJECT.fullmatch(self.tenant_id) or not _SUBJECT.fullmatch(self.identity_id):
            raise HarnessCredentialError("tenant or FW-ID identity is malformed")
        if not isinstance(self.method, AuthMethod) or len(set(self.scopes)) != len(self.scopes) or any(not _SUBJECT.fullmatch(value) for value in self.scopes):
            raise HarnessCredentialError("credential method or scopes are malformed")
        if not _HANDLE.fullmatch(self.secret_handle):
            raise HarnessCredentialError("credential requires an opaque FW-KEYS handle")
        if not _APPROVAL.fullmatch(self.approval_id):
            raise HarnessCredentialError("credential approval reference is malformed")
        if not isinstance(self.issued_at, (int, float)) or not isinstance(self.expires_at, (int, float)) or self.issued_at < 0 or self.expires_at <= self.issued_at:
            raise HarnessCredentialError("credential timestamps are invalid")
        if type(self.approved) is not bool or (self.revoked_at is not None and (not isinstance(self.revoked_at, (int, float)) or self.revoked_at < self.issued_at)):
            raise HarnessCredentialError("credential approval or revocation is invalid")


@dataclass(frozen=True)
class CredentialAdmission:
    credential_id: str
    profile_id: str
    provider: str
    tenant_id: str
    identity_id: str
    model_id: str
    method: AuthMethod
    secret_handle: str
    expires_at: float
    decision: str = "ADMITTED"
    deployment: str = "DISABLED"


class CredentialBroker:
    """Immutable profile registry and authority-free admission gate."""

    def __init__(self, profiles: tuple[ProviderAuthProfile, ...]):
        if not profiles or any(not isinstance(profile, ProviderAuthProfile) for profile in profiles):
            raise HarnessCredentialError("validated provider profiles are required")
        records = {profile.profile_id: profile for profile in profiles}
        if len(records) != len(profiles):
            raise HarnessCredentialError("provider profile IDs must be unique")
        self._profiles = MappingProxyType(records)

    def admit(self, record: CredentialRecord, *, now: float, tenant_id: str, identity_id: str, provider: str, model_id: str) -> CredentialAdmission:
        if not isinstance(record, CredentialRecord) or not isinstance(now, (int, float)) or now < 0:
            raise HarnessCredentialError("credential admission request is malformed")
        profile = self._profiles.get(record.profile_id)
        if profile is None:
            raise HarnessCredentialError("credential profile is not approved")
        if (
            record.provider != profile.provider or record.provider != provider
            or record.tenant_id != tenant_id or record.identity_id != identity_id
            or record.model_id != model_id or model_id not in profile.model_ids
            or record.method != profile.method or record.scopes != profile.scopes
        ):
            raise HarnessCredentialError("credential binding does not match the approved profile")
        if not record.approved:
            raise HarnessCredentialError("credential approval is absent")
        if record.revoked_at is not None:
            raise HarnessCredentialError("credential is revoked")
        if record.expires_at <= now:
            raise HarnessCredentialError("credential is expired")
        return CredentialAdmission(record.credential_id, record.profile_id, record.provider, record.tenant_id, record.identity_id, record.model_id, record.method, record.secret_handle, record.expires_at)


def default_provider_profiles(*, openai_model: str, anthropic_model: str, gemini_model: str) -> tuple[ProviderAuthProfile, ...]:
    """Declare provider-specific classes without activating or discovering them."""
    return (
        ProviderAuthProfile("openai-api-key", "openai", (openai_model,), AuthMethod.API_KEY, "openai-api-key", ()),
        ProviderAuthProfile("anthropic-api-key", "anthropic", (anthropic_model,), AuthMethod.API_KEY, "anthropic-api-key", ()),
        ProviderAuthProfile("google-gemini-api-key", "google", (gemini_model,), AuthMethod.API_KEY, "google-gemini-api-key", ()),
        ProviderAuthProfile("openai-codex-oauth", "openai", (openai_model,), AuthMethod.CLI_MANAGED_OAUTH, "openai-oauth-token", ("codex.cli",), "codex"),
        ProviderAuthProfile("anthropic-claude-oauth", "anthropic", (anthropic_model,), AuthMethod.CLI_MANAGED_OAUTH, "anthropic-oauth-token", ("claude.cli",), "claude"),
        ProviderAuthProfile("google-gemini-oauth", "google", (gemini_model,), AuthMethod.CLI_MANAGED_OAUTH, "google-oauth-token", ("gemini.cli",), "agy"),
    )


def credential_record(record: CredentialRecord) -> dict[str, Any]:
    """Return the strict persistent form; it contains only an opaque handle."""
    if not isinstance(record, CredentialRecord):
        raise HarnessCredentialError("credential record is malformed")
    payload = asdict(record)
    payload["method"] = record.method.value
    return payload


def credential_from_record(payload: Mapping[str, Any]) -> CredentialRecord:
    """Strictly parse persistent metadata and reject embedded secret material."""
    expected = {field for field in CredentialRecord.__dataclass_fields__}
    if not isinstance(payload, Mapping) or set(payload) != expected:
        raise HarnessCredentialError("persistent credential field set is invalid")
    if any(_SECRET_NAME.search(str(key)) and key != "secret_handle" for key in payload):
        raise HarnessCredentialError("persistent credential contains secret fields")
    for key, value in payload.items():
        if key != "secret_handle" and isinstance(value, str) and _SECRET_VALUE.search(value):
            raise HarnessCredentialError("persistent credential contains secret material")
    normalized = dict(payload)
    normalized["scopes"] = tuple(normalized.get("scopes", ()))
    try:
        normalized["method"] = AuthMethod(normalized["method"])
        return CredentialRecord(**normalized)
    except (TypeError, ValueError) as exc:
        raise HarnessCredentialError("persistent credential is invalid") from exc
