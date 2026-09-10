"""Canonical authority-free FW-ID identity contract.

Identity records describe who or what an actor is. They do not grant roles,
capabilities, credentials, policy decisions, Action Tickets, or execution.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


IDENTITY_KINDS = frozenset({"HUMAN", "SERVICE", "WORKLOAD", "DEVICE", "AI_AGENT", "OAUTH_CLIENT"})
LIFECYCLE_STATES = frozenset({"PROVISIONED", "ACTIVE", "REVOKED", "EXPIRED"})
_FIELDS = frozenset({"schema_version", "identity_id", "tenant_id", "identity_kind", "owner_identity_ref", "purpose", "lifecycle_state", "created_at_epoch", "expires_at_epoch", "provider_subject_ref", "credential_handle_ref"})
_ID = re.compile(r"^fw-id/[a-z][a-z0-9_.-]{0,126}$")
_TENANT = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_REF = re.compile(r"^[a-z][a-z0-9_.-]{0,31}/[A-Za-z0-9][A-Za-z0-9_.:/-]{0,223}$")
_HANDLE = re.compile(r"^fwkeys://[a-zA-Z0-9_.-]{1,64}/[a-zA-Z0-9_.:/-]{1,192}$")
_SECRET = re.compile(r"(?i)(bearer\s+\S+|sk-[a-z0-9_-]{8,}|AIza[a-z0-9_-]{8,}|ya29\.[a-z0-9._-]{8,})")


class IdentityContractError(ValueError):
    """Untrusted identity input violates the canonical FW-ID contract."""


def _text(value: Any, field: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value.encode("utf-8")) > maximum:
        raise IdentityContractError(f"{field} is invalid")
    if _SECRET.search(value):
        raise IdentityContractError(f"{field} contains credential material")
    return value


@dataclass(frozen=True)
class IdentityRecord:
    schema_version: str
    identity_id: str
    tenant_id: str
    identity_kind: str
    owner_identity_ref: str
    purpose: str
    lifecycle_state: str
    created_at_epoch: int
    expires_at_epoch: int | None
    provider_subject_ref: str | None
    credential_handle_ref: str | None

    def __post_init__(self) -> None:
        if self.schema_version != "1":
            raise IdentityContractError("unsupported identity schema version")
        if not _ID.fullmatch(self.identity_id):
            raise IdentityContractError("identity_id is invalid")
        if not _TENANT.fullmatch(self.tenant_id):
            raise IdentityContractError("tenant_id is invalid")
        if self.identity_kind not in IDENTITY_KINDS:
            raise IdentityContractError("identity_kind is invalid")
        if not _ID.fullmatch(self.owner_identity_ref):
            raise IdentityContractError("owner_identity_ref is invalid")
        _text(self.purpose, "purpose")
        if self.lifecycle_state not in LIFECYCLE_STATES:
            raise IdentityContractError("lifecycle_state is invalid")
        if not isinstance(self.created_at_epoch, int) or isinstance(self.created_at_epoch, bool) or self.created_at_epoch < 0:
            raise IdentityContractError("created_at_epoch is invalid")
        if self.expires_at_epoch is not None and (not isinstance(self.expires_at_epoch, int) or isinstance(self.expires_at_epoch, bool) or self.expires_at_epoch <= self.created_at_epoch):
            raise IdentityContractError("expires_at_epoch is invalid")
        if self.provider_subject_ref is not None:
            _text(self.provider_subject_ref, "provider_subject_ref", maximum=256)
            if not _REF.fullmatch(self.provider_subject_ref):
                raise IdentityContractError("provider_subject_ref is invalid")
        if self.credential_handle_ref is not None:
            if not _HANDLE.fullmatch(self.credential_handle_ref):
                raise IdentityContractError("credential_handle_ref must be an opaque FW-KEYS handle")
            if not self.credential_handle_ref.startswith(f"fwkeys://{self.tenant_id}/"):
                raise IdentityContractError("credential_handle_ref tenant mismatch")


def validate_identity_record(value: Mapping[str, Any]) -> IdentityRecord:
    """Validate an exact untrusted mapping into an immutable identity record."""
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise IdentityContractError("identity record field set is invalid")
    return IdentityRecord(**{field: value[field] for field in _FIELDS})
