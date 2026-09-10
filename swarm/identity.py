"""Canonical authority-free FW-ID identity contract.

Identity records describe who or what an actor is. They do not grant roles,
capabilities, credentials, policy decisions, Action Tickets, or execution.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from threading import Lock
from typing import Any, Callable, Mapping


IDENTITY_KINDS = frozenset({"HUMAN", "SERVICE", "WORKLOAD", "DEVICE", "AI_AGENT", "OAUTH_CLIENT"})
LIFECYCLE_STATES = frozenset({"PROVISIONED", "ACTIVE", "REVOKED", "EXPIRED"})
_FIELDS = frozenset({"schema_version", "identity_id", "tenant_id", "identity_kind", "owner_identity_ref", "purpose", "lifecycle_state", "created_at_epoch", "lifecycle_changed_at_epoch", "expires_at_epoch", "provider_subject_ref", "credential_handle_ref"})
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
    lifecycle_changed_at_epoch: int
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
        if not isinstance(self.lifecycle_changed_at_epoch, int) or isinstance(self.lifecycle_changed_at_epoch, bool) or self.lifecycle_changed_at_epoch < self.created_at_epoch:
            raise IdentityContractError("lifecycle_changed_at_epoch is invalid")
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


class IdentityRegistry:
    """Create-once tenant-bound identity state with Evidence-first transitions."""

    def __init__(self, audit: Callable[[str, dict[str, Any]], None]):
        if not callable(audit):
            raise IdentityContractError("identity registry requires an Evidence sink")
        self._audit = audit
        self._records: dict[str, IdentityRecord] = {}
        self._pending: set[str] = set()
        self._lock = Lock()

    def register(self, record: IdentityRecord) -> IdentityRecord:
        if not isinstance(record, IdentityRecord):
            raise IdentityContractError("validated identity record is required")
        self._reserve(record.identity_id)
        try:
            self._write("fw_id_registered", record, None, record.lifecycle_state, record.lifecycle_changed_at_epoch)
            with self._lock:
                if record.identity_id in self._records:
                    raise IdentityContractError("identity already registered")
                self._records[record.identity_id] = record
        finally:
            self._release(record.identity_id)
        return record

    def get(self, identity_id: str, *, tenant_id: str) -> IdentityRecord:
        if not _ID.fullmatch(identity_id) or not _TENANT.fullmatch(tenant_id):
            raise IdentityContractError("identity lookup is invalid")
        with self._lock:
            record = self._records.get(identity_id)
        if record is None:
            raise IdentityContractError("identity is not registered")
        if record.tenant_id != tenant_id:
            raise IdentityContractError("identity tenant mismatch")
        return record

    def tenant_snapshot(self, tenant_id: str) -> tuple[IdentityRecord, ...]:
        if not _TENANT.fullmatch(tenant_id):
            raise IdentityContractError("tenant_id is invalid")
        with self._lock:
            return tuple(sorted((item for item in self._records.values() if item.tenant_id == tenant_id), key=lambda item: item.identity_id))

    def activate(self, identity_id: str, *, tenant_id: str, now_epoch: int) -> IdentityRecord:
        return self._transition(identity_id, tenant_id, "ACTIVE", now_epoch)

    def revoke(self, identity_id: str, *, tenant_id: str, now_epoch: int) -> IdentityRecord:
        return self._transition(identity_id, tenant_id, "REVOKED", now_epoch)

    def expire(self, identity_id: str, *, tenant_id: str, now_epoch: int) -> IdentityRecord:
        return self._transition(identity_id, tenant_id, "EXPIRED", now_epoch)

    def _transition(self, identity_id: str, tenant_id: str, target: str, now_epoch: int) -> IdentityRecord:
        self._reserve(identity_id, allow_existing=True)
        try:
            current = self.get(identity_id, tenant_id=tenant_id)
            if not isinstance(now_epoch, int) or isinstance(now_epoch, bool) or now_epoch < current.lifecycle_changed_at_epoch:
                raise IdentityContractError("identity transition timestamp is stale")
            allowed = ((current.lifecycle_state == "PROVISIONED" and target in {"ACTIVE", "REVOKED", "EXPIRED"}) or (current.lifecycle_state == "ACTIVE" and target in {"REVOKED", "EXPIRED"}))
            if not allowed:
                raise IdentityContractError("identity lifecycle transition is invalid")
            if target == "ACTIVE" and current.expires_at_epoch is not None and now_epoch >= current.expires_at_epoch:
                raise IdentityContractError("expired identity cannot activate")
            if target == "EXPIRED" and (current.expires_at_epoch is None or now_epoch < current.expires_at_epoch):
                raise IdentityContractError("identity has not reached expiration")
            updated = replace(current, lifecycle_state=target, lifecycle_changed_at_epoch=now_epoch)
            self._write("fw_id_lifecycle_changed", updated, current.lifecycle_state, target, now_epoch)
            with self._lock:
                self._records[identity_id] = updated
        finally:
            self._release(identity_id)
        return updated

    def _reserve(self, identity_id: str, *, allow_existing: bool = False) -> None:
        with self._lock:
            if identity_id in self._pending or (allow_existing and identity_id not in self._records) or (not allow_existing and identity_id in self._records):
                raise IdentityContractError("identity already registered or transition pending")
            self._pending.add(identity_id)

    def _release(self, identity_id: str) -> None:
        with self._lock:
            self._pending.discard(identity_id)

    def _write(self, event: str, record: IdentityRecord, previous: str | None, current: str, at: int) -> None:
        try:
            self._audit(event, {"identity_id": record.identity_id, "tenant_id": record.tenant_id, "identity_kind": record.identity_kind, "previous_state": previous, "lifecycle_state": current, "changed_at_epoch": at, "authority_granted": False, "mode": "DRY_RUN", "deployment": "DISABLED"})
        except Exception as exc:
            raise IdentityContractError("Evidence write failed") from exc
