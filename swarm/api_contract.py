"""Canonical tenant-bound, read-only FW-API request admission."""
from __future__ import annotations

import re
from dataclasses import dataclass
from threading import Lock
from typing import Any, Callable, Mapping

from .asoc import AuthorizationDenied, CapabilityLease, LeaseIntegrityError, LeaseRegistry
from .identity import IdentityContractError, IdentityRegistry
from .policy_gate import DeterministicPolicy, PolicyContext, PolicyInvariantError


class APIContractError(ValueError):
    """Untrusted API metadata cannot be admitted safely."""


_FIELDS = frozenset({"schema_version", "request_id", "tenant_id", "requester_identity_id", "purpose", "capability", "resource", "action_class", "policy_version", "lease_id", "issued_at_epoch", "expires_at_epoch", "data_classification"})
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_IDENTITY = re.compile(r"^fw-id/[a-z][a-z0-9_.-]{0,126}$")
_TENANT = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_EVIDENCE = re.compile(r"^fw-evid/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/-]{0,191}$")
_SECRET = re.compile(r"(?i)(bearer\s+\S+|sk-[a-z0-9_-]{8,}|AIza[a-z0-9_-]{8,}|ya29\.[a-z0-9._-]{8,}|api[_-]?key\s*[:=]|(?:access|refresh)[_-]?token\s*[:=]|client[_-]?secret\s*[:=]|password\s*[:=])")


def _text(value: Any, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value.encode("utf-8")) > maximum or _SECRET.search(value):
        raise APIContractError(f"{field} is invalid or secret-bearing")
    return value


@dataclass(frozen=True)
class APIReadRequest:
    schema_version: str
    request_id: str
    tenant_id: str
    requester_identity_id: str
    purpose: str
    capability: str
    resource: str
    action_class: str
    policy_version: str
    lease_id: str
    issued_at_epoch: int
    expires_at_epoch: int
    data_classification: str

    def __post_init__(self) -> None:
        if self.schema_version != "1":
            raise APIContractError("unsupported API schema version")
        for field in ("request_id", "requester_identity_id", "capability", "resource", "policy_version", "lease_id"):
            if not _ID.fullmatch(_text(getattr(self, field), field, 256)):
                raise APIContractError(f"{field} is invalid")
        if not _IDENTITY.fullmatch(self.requester_identity_id):
            raise APIContractError("requester_identity_id is invalid")
        if not _TENANT.fullmatch(_text(self.tenant_id, "tenant_id", 128)):
            raise APIContractError("tenant_id is invalid")
        _text(self.purpose, "purpose")
        if self.action_class != "READ":
            raise APIContractError("only read-only API requests are supported")
        if self.data_classification not in {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}:
            raise APIContractError("data classification is invalid")
        if any(not isinstance(value, int) or isinstance(value, bool) for value in (self.issued_at_epoch, self.expires_at_epoch)) or self.issued_at_epoch < 0 or self.expires_at_epoch <= self.issued_at_epoch:
            raise APIContractError("request lifetime is invalid")


@dataclass(frozen=True)
class APIReadAdmission:
    request_id: str
    tenant_id: str
    requester_identity_id: str
    capability: str
    resource: str
    policy_version: str
    lease_id: str
    evidence_reference: str
    admitted_at_epoch: int
    mode: str = "DRY_RUN"
    deployment: str = "DISABLED"
    action: str = "ADMIT_READ_ONLY"
    handler_invoked: bool = False
    authority_granted: bool = False


def validate_api_read_request(value: Mapping[str, Any]) -> APIReadRequest:
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise APIContractError("API request field set is invalid")
    return APIReadRequest(**{field: value[field] for field in _FIELDS})


class APIReadAdmissionRegistry:
    """Create-once admission using canonical identity, policy, lease and Evidence owners."""

    def __init__(self, identities: IdentityRegistry, policy: DeterministicPolicy, leases: LeaseRegistry, evidence_sink: Callable[[str, dict[str, Any]], str]):
        if not isinstance(identities, IdentityRegistry) or not isinstance(policy, DeterministicPolicy) or not isinstance(leases, LeaseRegistry) or not callable(evidence_sink):
            raise APIContractError("canonical API dependencies are required")
        self._identities, self._policy, self._leases, self._evidence = identities, policy, leases, evidence_sink
        self._admitted: set[str] = set()
        self._pending: set[str] = set()
        self._lock = Lock()

    def admit(self, request: APIReadRequest, *, now_epoch: int, kill_switch: str = "ENGAGED", deployment: str = "DISABLED") -> APIReadAdmission:
        if not isinstance(request, APIReadRequest) or not isinstance(now_epoch, int) or isinstance(now_epoch, bool):
            raise APIContractError("validated request and time are required")
        if kill_switch != "ENGAGED" or deployment != "DISABLED":
            raise APIContractError("API safety state is invalid")
        if not request.issued_at_epoch <= now_epoch < request.expires_at_epoch:
            raise APIContractError("API request is stale or expired")
        with self._lock:
            if request.request_id in self._admitted or request.request_id in self._pending:
                raise APIContractError("API request replay denied")
            self._pending.add(request.request_id)
        try:
            try:
                identity = self._identities.get(request.requester_identity_id, tenant_id=request.tenant_id)
            except IdentityContractError as exc:
                raise APIContractError("API identity admission denied") from exc
            if identity.lifecycle_state != "ACTIVE" or (identity.expires_at_epoch is not None and now_epoch >= identity.expires_at_epoch):
                raise APIContractError("API identity is not active")
            context = PolicyContext(request.tenant_id, request.requester_identity_id, request.capability, request.resource, request.action_class, request.policy_version)
            try:
                decision = self._policy.evaluate(context)
                lease = self._leases.get(request.lease_id)
                self._leases.verify(lease)
            except (AuthorizationDenied, LeaseIntegrityError, PolicyInvariantError, ValueError) as exc:
                raise APIContractError("API policy or lease validation failed") from exc
            if not decision.allowed:
                raise APIContractError("API policy denied request")
            if lease.revoked_at is not None or not lease.valid_from <= now_epoch < lease.expires_at:
                raise APIContractError("API lease is not active")
            if lease.tenant_id != request.tenant_id or lease.subject_agent_id != request.requester_identity_id or lease.policy_version != request.policy_version or request.capability not in lease.granted_capabilities or request.resource not in lease.allowed_resources or request.action_class not in lease.allowed_action_classes or request.data_classification not in lease.allowed_data_classifications:
                raise APIContractError("API lease binding mismatch")
            evidence_payload = {"request_id": request.request_id, "tenant_id": request.tenant_id, "requester_identity_id": request.requester_identity_id, "capability": request.capability, "resource": request.resource, "action_class": "READ", "policy_version": request.policy_version, "lease_id": request.lease_id, "admitted_at_epoch": now_epoch, "mode": "DRY_RUN", "deployment": "DISABLED", "handler_invoked": False, "authority_granted": False}
            try:
                evidence_reference = self._evidence("fw_api_read_admitted", evidence_payload)
            except Exception as exc:
                raise APIContractError("API Evidence write failed") from exc
            match = _EVIDENCE.fullmatch(evidence_reference) if isinstance(evidence_reference, str) else None
            if match is None or match.group(1) != request.tenant_id:
                raise APIContractError("API Evidence reference is invalid")
            admission = APIReadAdmission(request.request_id, request.tenant_id, request.requester_identity_id, request.capability, request.resource, request.policy_version, request.lease_id, evidence_reference, now_epoch)
            with self._lock:
                self._admitted.add(request.request_id)
            return admission
        finally:
            with self._lock:
                self._pending.discard(request.request_id)
