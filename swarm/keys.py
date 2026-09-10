"""Canonical authority-free FW-KEYS secret-handle metadata contract.

The contract describes an opaque reference to material held by a separately
trusted backend. It never accepts, stores, resolves, exports, or uses material.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


CREDENTIAL_CLASSES = frozenset({
    "API_KEY", "OAUTH_TOKEN_SET", "SERVICE_PRINCIPAL",
    "SIGNING_KEY", "ENCRYPTION_KEY", "HMAC_KEY", "TRUST_ANCHOR",
})
BACKEND_REFERENCE_CLASSES = frozenset({
    "TRUSTED_ADAPTER", "LOCAL_KEYSTORE", "HSM", "EXTERNAL_VAULT",
})
LIFECYCLE_STATES = frozenset({"PROVISIONED", "ACTIVE", "REVOKED", "EXPIRED"})
EXPORT_POLICIES = frozenset({"NON_EXPORTABLE"})
_FIELDS = frozenset({
    "schema_version", "handle_id", "tenant_id", "credential_class",
    "owner_identity_ref", "purpose", "backend_reference_class",
    "lifecycle_state", "created_at_epoch", "lifecycle_changed_at_epoch",
    "expires_at_epoch", "generation", "export_policy",
})
_HANDLE = re.compile(r"^fwkeys://[a-z][a-z0-9_.-]{0,127}/[a-z][a-z0-9_.:/-]{0,191}$")
_TENANT = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_IDENTITY = re.compile(r"^fw-id/[a-z][a-z0-9_.-]{0,126}$")
_SECRET = re.compile(
    r"(?i)(bearer\s+\S+|sk-[a-z0-9_-]{8,}|AIza[a-z0-9_-]{8,}|"
    r"ya29\.[a-z0-9._-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:access|refresh)[_-]?token\s*[:=]|(?:api[_-]?key|client[_-]?secret|password)\s*[:=])"
)


class KeyContractError(ValueError):
    """Untrusted key metadata violates the canonical FW-KEYS contract."""


def _safe_text(value: Any, field: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
    ):
        raise KeyContractError(f"{field} is invalid")
    if _SECRET.search(value):
        raise KeyContractError(f"{field} contains secret material")
    return value


@dataclass(frozen=True)
class SecretHandleRecord:
    """Immutable metadata for a non-exportable opaque secret handle."""

    schema_version: str
    handle_id: str
    tenant_id: str
    credential_class: str
    owner_identity_ref: str
    purpose: str
    backend_reference_class: str
    lifecycle_state: str
    created_at_epoch: int
    lifecycle_changed_at_epoch: int
    expires_at_epoch: int | None
    generation: int
    export_policy: str

    def __post_init__(self) -> None:
        if self.schema_version != "1":
            raise KeyContractError("unsupported key schema version")
        _safe_text(self.handle_id, "handle_id", maximum=300)
        if not _HANDLE.fullmatch(self.handle_id):
            raise KeyContractError("handle_id must be an opaque FW-KEYS handle")
        if not isinstance(self.tenant_id, str) or not _TENANT.fullmatch(self.tenant_id):
            raise KeyContractError("tenant_id is invalid")
        if not self.handle_id.startswith(f"fwkeys://{self.tenant_id}/"):
            raise KeyContractError("handle_id tenant mismatch")
        if self.credential_class not in CREDENTIAL_CLASSES:
            raise KeyContractError("credential_class is invalid")
        if not isinstance(self.owner_identity_ref, str) or not _IDENTITY.fullmatch(self.owner_identity_ref):
            raise KeyContractError("owner_identity_ref is invalid")
        _safe_text(self.purpose, "purpose", maximum=512)
        if self.backend_reference_class not in BACKEND_REFERENCE_CLASSES:
            raise KeyContractError("backend_reference_class is invalid")
        if self.lifecycle_state not in LIFECYCLE_STATES:
            raise KeyContractError("lifecycle_state is invalid")
        if (
            not isinstance(self.created_at_epoch, int)
            or isinstance(self.created_at_epoch, bool)
            or self.created_at_epoch < 0
        ):
            raise KeyContractError("created_at_epoch is invalid")
        if (
            not isinstance(self.lifecycle_changed_at_epoch, int)
            or isinstance(self.lifecycle_changed_at_epoch, bool)
            or self.lifecycle_changed_at_epoch < self.created_at_epoch
        ):
            raise KeyContractError("lifecycle_changed_at_epoch is invalid")
        if self.expires_at_epoch is not None and (
            not isinstance(self.expires_at_epoch, int)
            or isinstance(self.expires_at_epoch, bool)
            or self.expires_at_epoch <= self.created_at_epoch
        ):
            raise KeyContractError("expires_at_epoch is invalid")
        if not isinstance(self.generation, int) or isinstance(self.generation, bool) or self.generation < 1:
            raise KeyContractError("generation is invalid")
        if self.export_policy not in EXPORT_POLICIES:
            raise KeyContractError("secret handles must be non-exportable")


def validate_secret_handle_record(value: Mapping[str, Any]) -> SecretHandleRecord:
    """Validate an exact untrusted mapping without copying unknown/secret fields."""
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise KeyContractError("secret-handle record field set is invalid")
    return SecretHandleRecord(**{field: value[field] for field in _FIELDS})
