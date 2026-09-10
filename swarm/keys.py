"""Canonical authority-free FW-KEYS secret-handle metadata contract.

The contract describes an opaque reference to material held by a separately
trusted backend. It never accepts, stores, resolves, exports, or uses material.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from threading import Lock
from typing import Any, Callable, Mapping


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


class SecretHandleRegistry:
    """Create-once tenant state for secret-handle metadata, never material."""

    def __init__(self, audit: Callable[[str, dict[str, Any]], None]):
        if not callable(audit):
            raise KeyContractError("secret-handle registry requires an Evidence sink")
        self._audit = audit
        self._records: dict[str, SecretHandleRecord] = {}
        self._pending: set[str] = set()
        self._lock = Lock()

    def register(self, record: SecretHandleRecord) -> SecretHandleRecord:
        if not isinstance(record, SecretHandleRecord):
            raise KeyContractError("validated secret-handle record is required")
        self._reserve(record.handle_id)
        try:
            self._write("fw_keys_handle_registered", record, None, record.lifecycle_state)
            with self._lock:
                if record.handle_id in self._records:
                    raise KeyContractError("secret handle already registered")
                self._records[record.handle_id] = record
        finally:
            self._release(record.handle_id)
        return record

    def get(self, handle_id: str, *, tenant_id: str) -> SecretHandleRecord:
        self._validate_lookup(handle_id, tenant_id)
        with self._lock:
            record = self._records.get(handle_id)
        if record is None:
            raise KeyContractError("secret handle is not registered")
        if record.tenant_id != tenant_id:
            raise KeyContractError("secret handle tenant mismatch")
        return record

    def tenant_snapshot(self, tenant_id: str) -> tuple[SecretHandleRecord, ...]:
        if not isinstance(tenant_id, str) or not _TENANT.fullmatch(tenant_id):
            raise KeyContractError("tenant_id is invalid")
        with self._lock:
            return tuple(sorted(
                (item for item in self._records.values() if item.tenant_id == tenant_id),
                key=lambda item: item.handle_id,
            ))

    def activate(self, handle_id: str, *, tenant_id: str, now_epoch: int) -> SecretHandleRecord:
        return self._transition(handle_id, tenant_id, "ACTIVE", now_epoch)

    def revoke(self, handle_id: str, *, tenant_id: str, now_epoch: int) -> SecretHandleRecord:
        return self._transition(handle_id, tenant_id, "REVOKED", now_epoch)

    def expire(self, handle_id: str, *, tenant_id: str, now_epoch: int) -> SecretHandleRecord:
        return self._transition(handle_id, tenant_id, "EXPIRED", now_epoch)

    def replace_generation(
        self, current_handle_id: str, replacement: SecretHandleRecord, *,
        tenant_id: str, now_epoch: int,
    ) -> SecretHandleRecord:
        """Replace one active generation without changing the opaque handle."""
        if not isinstance(replacement, SecretHandleRecord):
            raise KeyContractError("validated replacement record is required")
        self._validate_lookup(current_handle_id, tenant_id)
        self._reserve(current_handle_id, allow_existing=True)
        try:
            current = self.get(current_handle_id, tenant_id=tenant_id)
            immutable = (
                "handle_id", "tenant_id", "credential_class", "owner_identity_ref",
                "purpose", "backend_reference_class", "export_policy",
            )
            if any(getattr(replacement, field) != getattr(current, field) for field in immutable):
                raise KeyContractError("replacement binding mismatch")
            if current.lifecycle_state != "ACTIVE":
                raise KeyContractError("only an active secret handle can be replaced")
            if (
                replacement.generation != current.generation + 1
                or replacement.lifecycle_state != "PROVISIONED"
                or replacement.created_at_epoch != now_epoch
                or replacement.lifecycle_changed_at_epoch != now_epoch
                or now_epoch < current.lifecycle_changed_at_epoch
            ):
                raise KeyContractError("replacement generation is stale or invalid")
            self._write("fw_keys_generation_replaced", replacement, current.lifecycle_state, replacement.lifecycle_state)
            with self._lock:
                self._records[current_handle_id] = replacement
        finally:
            self._release(current_handle_id)
        return replacement

    def _transition(
        self, handle_id: str, tenant_id: str, target: str, now_epoch: int,
    ) -> SecretHandleRecord:
        self._validate_lookup(handle_id, tenant_id)
        self._reserve(handle_id, allow_existing=True)
        try:
            current = self.get(handle_id, tenant_id=tenant_id)
            if (
                not isinstance(now_epoch, int)
                or isinstance(now_epoch, bool)
                or now_epoch < current.lifecycle_changed_at_epoch
            ):
                raise KeyContractError("secret-handle transition timestamp is stale")
            allowed = (
                current.lifecycle_state == "PROVISIONED" and target in {"ACTIVE", "REVOKED", "EXPIRED"}
            ) or (
                current.lifecycle_state == "ACTIVE" and target in {"REVOKED", "EXPIRED"}
            )
            if not allowed:
                raise KeyContractError("secret-handle lifecycle transition is invalid")
            if target == "ACTIVE" and current.expires_at_epoch is not None and now_epoch >= current.expires_at_epoch:
                raise KeyContractError("expired secret handle cannot activate")
            if target == "EXPIRED" and (
                current.expires_at_epoch is None or now_epoch < current.expires_at_epoch
            ):
                raise KeyContractError("secret handle has not reached expiration")
            updated = replace(current, lifecycle_state=target, lifecycle_changed_at_epoch=now_epoch)
            self._write("fw_keys_lifecycle_changed", updated, current.lifecycle_state, target)
            with self._lock:
                self._records[handle_id] = updated
        finally:
            self._release(handle_id)
        return updated

    def _validate_lookup(self, handle_id: str, tenant_id: str) -> None:
        if (
            not isinstance(handle_id, str)
            or not _HANDLE.fullmatch(handle_id)
            or not isinstance(tenant_id, str)
            or not _TENANT.fullmatch(tenant_id)
        ):
            raise KeyContractError("secret-handle lookup is invalid")

    def _reserve(self, handle_id: str, *, allow_existing: bool = False) -> None:
        with self._lock:
            if (
                handle_id in self._pending
                or (allow_existing and handle_id not in self._records)
                or (not allow_existing and handle_id in self._records)
            ):
                raise KeyContractError("secret handle already registered or transition pending")
            self._pending.add(handle_id)

    def _release(self, handle_id: str) -> None:
        with self._lock:
            self._pending.discard(handle_id)

    def _write(
        self, event: str, record: SecretHandleRecord,
        previous: str | None, current: str,
    ) -> None:
        evidence = {
            "tenant_id": record.tenant_id,
            "credential_class": record.credential_class,
            "owner_identity_ref": record.owner_identity_ref,
            "previous_state": previous,
            "lifecycle_state": current,
            "lifecycle_changed_at_epoch": record.lifecycle_changed_at_epoch,
            "generation": record.generation,
            "export_policy": record.export_policy,
            "authority_granted": False,
            "credential_resolved": False,
            "mode": "DRY_RUN",
            "deployment": "DISABLED",
        }
        try:
            self._audit(event, evidence)
        except Exception as exc:
            raise KeyContractError("Evidence write failed") from exc
