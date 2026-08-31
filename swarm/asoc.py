"""FW-ASOC-01: tenant-bound agent identity and capability leases.

This module is deliberately a policy boundary, not a second identity system.  It
keeps key material outside identities and leases, and every decision re-checks
the current registry, lease validity, policy, and kill-switch state.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field, replace
from threading import Lock
from typing import Any, Callable, Iterable, Mapping, Protocol

from .action_ticket import ActionTicketError, ActionTicketRegistry
from .core import AuditLog, Job
from .mcp_gateway import MCPGateway
from .model_broker import ModelBroker
from .policy_gate import DeterministicPolicy, PolicyContext, validate_safety_evidence


ROLES = frozenset({
    "SOC Triage Agent", "Threat Hunter", "Incident Investigator",
    "Endpoint Investigator", "Identity Investigator", "Malware Analysis Agent",
    "Browser/Email Security Agent", "SaaS Security Agent", "Threat Intelligence Agent",
    "Security Advisor", "Monitor Agent", "Repair Agent", "Recovery Coordinator",
    "Compliance Agent", "Review/QA Agent",
})
CAPABILITIES = frozenset({
    "telemetry.read", "evidence.read", "threat_intel.read", "endpoint.inspect",
    "identity.inspect", "malware.submit_for_detonation", "incident.create",
    "incident.annotate", "action.request", "endpoint.isolate.request",
    "token.revoke.request", "process.terminate.request", "recovery.request",
})
READ_ONLY_ACTIONS = frozenset({"READ", "ANALYZE", "ANNOTATE", "CREATE_FINDING", "REQUEST"})
MUTATING_ACTIONS = frozenset({"ISOLATE_ENDPOINT", "REVOKE_TOKEN", "TERMINATE_PROCESS", "RECOVER"})
CLASSIFICATION_ORDER = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}
DENIED_CAPABILITY_NAMES = frozenset({"admin", "superuser", "unrestricted", "all_tools", "arbitrary_shell", "arbitrary_filesystem", "bypass_policy"})


class AuthorizationDenied(PermissionError):
    """A bounded, diagnosable fail-closed authorization denial."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class LeaseIntegrityError(ValueError):
    """A lease is malformed or its detached signature cannot be verified."""


class AuditSink(Protocol):
    def __call__(self, event: str, data: Mapping[str, Any]) -> None: ...


def audit_log_sink(audit_log: AuditLog, job: Job) -> AuditSink:
    """Bind ASOC evidence to ForgeWarden's canonical durable audit record."""
    if not isinstance(audit_log, AuditLog) or not isinstance(job, Job):
        raise TypeError("audit_log_sink requires ForgeWarden AuditLog and Job")

    def write(event: str, data: Mapping[str, Any]) -> None:
        audit_log.record(job, event, **dict(data))

    return write


def _text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError(f"{field_name} must be a non-empty bounded string")
    return value.strip()


def _tuple_text(values: Iterable[str], field_name: str) -> tuple[str, ...]:
    result = tuple(_text(value, field_name) for value in values)
    if not result:
        raise ValueError(f"{field_name} must not be empty")
    if any("*" in value or value.startswith("!") for value in result):
        raise ValueError(f"{field_name} cannot contain wildcard or negated authority")
    return tuple(sorted(set(result)))


@dataclass(frozen=True)
class ModelBinding:
    model: str
    provider: str
    deployment: str
    version: str
    approval_version: str
    approved: bool = True

    def __post_init__(self) -> None:
        for name in ("model", "provider", "deployment", "version", "approval_version"):
            object.__setattr__(self, name, _text(getattr(self, name), name))
        if not isinstance(self.approved, bool):
            raise ValueError("approved must be boolean")

    def as_dict(self) -> dict[str, Any]:
        return {"model": self.model, "provider": self.provider, "deployment": self.deployment,
                "version": self.version, "approval_version": self.approval_version, "approved": self.approved}


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    tenant_id: str
    agent_type: str
    role: str
    owner_controller_id: str
    model_identity: ModelBinding | None
    provider_deployment: str
    approved_purpose: str
    trust_level: str
    allowed_data_classifications: tuple[str, ...]
    lifecycle_state: str = "PROVISIONED"
    created_at: int = field(default_factory=lambda: int(time.time()))
    activated_at: int | None = None
    expires_at: int | None = None
    revoked_at: int | None = None
    revocation_reason: str | None = None
    policy_version: str = "FW-ASOC-01-v1"
    model_approval_version: str = ""
    cryptographic_identity_ref: str = ""

    def __post_init__(self) -> None:
        for name in ("agent_id", "tenant_id", "agent_type", "role", "owner_controller_id", "provider_deployment", "approved_purpose", "trust_level", "policy_version", "cryptographic_identity_ref"):
            object.__setattr__(self, name, _text(getattr(self, name), name))
        if self.role not in ROLES:
            raise ValueError("role is not a bounded FW-ASOC role")
        classes = _tuple_text(self.allowed_data_classifications, "allowed_data_classifications")
        if any(value not in CLASSIFICATION_ORDER for value in classes):
            raise ValueError("unsupported data classification")
        object.__setattr__(self, "allowed_data_classifications", classes)
        if self.lifecycle_state not in {"PROVISIONED", "ACTIVE", "REVOKED", "EXPIRED"}:
            raise ValueError("invalid agent lifecycle state")
        if self.expires_at is not None and self.expires_at <= self.created_at:
            raise ValueError("agent expiration must be after creation")
        if self.model_identity:
            expected_deployment = f"{self.model_identity.provider}/{self.model_identity.deployment}"
            if self.provider_deployment != expected_deployment:
                raise ValueError("provider_deployment must match model identity")
            if not self.model_approval_version:
                object.__setattr__(self, "model_approval_version", self.model_identity.approval_version)
            elif self.model_approval_version != self.model_identity.approval_version:
                raise ValueError("model_approval_version must match model identity")

    def as_dict(self) -> dict[str, Any]:
        return {"agent_id": self.agent_id, "tenant_id": self.tenant_id, "agent_type": self.agent_type,
                "role": self.role, "owner_controller_id": self.owner_controller_id,
                "model_identity": self.model_identity.as_dict() if self.model_identity else None,
                "provider_deployment": self.provider_deployment, "approved_purpose": self.approved_purpose,
                "trust_level": self.trust_level, "allowed_data_classifications": list(self.allowed_data_classifications),
                "lifecycle_state": self.lifecycle_state, "created_at": self.created_at, "activated_at": self.activated_at,
                "expires_at": self.expires_at, "revoked_at": self.revoked_at, "revocation_reason": self.revocation_reason,
                "policy_version": self.policy_version, "model_approval_version": self.model_approval_version,
                "cryptographic_identity_ref": self.cryptographic_identity_ref}


@dataclass(frozen=True)
class CapabilityLease:
    lease_id: str
    subject_agent_id: str
    issuer_identity: str
    tenant_id: str
    granted_capabilities: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    allowed_resources: tuple[str, ...]
    allowed_data_classifications: tuple[str, ...]
    allowed_action_classes: tuple[str, ...]
    max_blast_radius: int
    delegation_allowed: bool
    delegation_depth: int
    valid_from: int
    expires_at: int
    policy_version: str
    approval_reference: str
    action_ticket_reference: str
    creation_reason: str
    key_reference: str
    max_concurrent_work: int = 1
    max_model_tokens_per_work: int = 1
    max_delegated_leases: int = 1
    signature: str = ""
    revoked_at: int | None = None
    revocation_reason: str | None = None

    def __post_init__(self) -> None:
        for name in ("lease_id", "subject_agent_id", "issuer_identity", "tenant_id", "policy_version", "approval_reference", "action_ticket_reference", "creation_reason", "key_reference"):
            object.__setattr__(self, name, _text(getattr(self, name), name))
        caps = _tuple_text(self.granted_capabilities, "granted_capabilities")
        if any(cap not in CAPABILITIES or cap in DENIED_CAPABILITY_NAMES for cap in caps):
            raise ValueError("capability is not narrowly defined or is forbidden")
        object.__setattr__(self, "granted_capabilities", caps)
        object.__setattr__(self, "allowed_tools", _tuple_text(self.allowed_tools, "allowed_tools"))
        object.__setattr__(self, "allowed_resources", _tuple_text(self.allowed_resources, "allowed_resources"))
        classes = _tuple_text(self.allowed_data_classifications, "allowed_data_classifications")
        if any(value not in CLASSIFICATION_ORDER for value in classes):
            raise ValueError("unsupported lease data classification")
        object.__setattr__(self, "allowed_data_classifications", classes)
        action_classes = _tuple_text(self.allowed_action_classes, "allowed_action_classes")
        if any(value not in READ_ONLY_ACTIONS | MUTATING_ACTIONS for value in action_classes):
            raise ValueError("unsupported action class")
        object.__setattr__(self, "allowed_action_classes", action_classes)
        if self.max_blast_radius < 0 or self.delegation_depth < 0 or self.valid_from >= self.expires_at:
            raise ValueError("invalid lease bounds")
        if not isinstance(self.max_concurrent_work, int) or isinstance(self.max_concurrent_work, bool) or self.max_concurrent_work <= 0:
            raise ValueError("max_concurrent_work must be a positive integer")
        if (
            not isinstance(self.max_model_tokens_per_work, int)
            or isinstance(self.max_model_tokens_per_work, bool)
            or self.max_model_tokens_per_work <= 0
        ):
            raise ValueError("max_model_tokens_per_work must be a positive integer")
        if not isinstance(self.max_delegated_leases, int) or isinstance(self.max_delegated_leases, bool) or self.max_delegated_leases <= 0:
            raise ValueError("max_delegated_leases must be a positive integer")
        if not isinstance(self.delegation_allowed, bool):
            raise ValueError("delegation_allowed must be boolean")
        if not self.delegation_allowed and self.delegation_depth != 0:
            raise ValueError("non-delegable leases must have zero delegation depth")

    def unsigned_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in (
            "lease_id", "subject_agent_id", "issuer_identity", "tenant_id", "granted_capabilities", "allowed_tools",
            "allowed_resources", "allowed_data_classifications", "allowed_action_classes", "max_blast_radius",
            "delegation_allowed", "delegation_depth", "valid_from", "expires_at", "policy_version",
            "approval_reference", "action_ticket_reference", "creation_reason", "key_reference",
            "max_concurrent_work", "max_model_tokens_per_work", "max_delegated_leases")}

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.unsigned_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def as_dict(self) -> dict[str, Any]:
        result = dict(self.unsigned_dict())
        result.update({"signature": self.signature, "revoked_at": self.revoked_at, "revocation_reason": self.revocation_reason})
        return result


class HMACLeaseSigner:
    """Detached signer; secrets are supplied at runtime and never stored in leases."""

    def __init__(self, keys: Mapping[str, bytes]):
        self._keys = dict(keys)

    def sign(self, lease: CapabilityLease) -> CapabilityLease:
        key = self._keys.get(lease.key_reference)
        if not key:
            raise LeaseIntegrityError("lease signing key reference is unavailable")
        signature = hmac.new(key, lease.canonical_bytes(), hashlib.sha256).hexdigest()
        return replace(lease, signature=signature)

    def verify(self, lease: CapabilityLease) -> None:
        key = self._keys.get(lease.key_reference)
        if not key or not lease.signature:
            raise LeaseIntegrityError("lease signature is missing or unverifiable")
        expected = hmac.new(key, lease.canonical_bytes(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, lease.signature):
            raise LeaseIntegrityError("lease signature mismatch")


class KillSwitch:
    def __init__(self, engaged: bool = True, analytical_actions_allowed: bool = True):
        self.engaged = engaged
        self.analytical_actions_allowed = analytical_actions_allowed

    def engage(self) -> None:
        self.engaged = True

    def clear_for_dry_run(self) -> None:
        self.engaged = False


class AgentRegistry:
    def __init__(self, audit: AuditSink | None = None):
        self._agents: dict[str, AgentIdentity] = {}
        self._audit = audit or (lambda _event, _data: None)

    def register(self, identity: AgentIdentity) -> AgentIdentity:
        if identity.agent_id in self._agents:
            raise ValueError("agent identity already exists")
        self._agents[identity.agent_id] = identity
        self._audit("agent_created", {"agent_id": identity.agent_id, "tenant_id": identity.tenant_id})
        return identity

    def activate(self, agent_id: str, now: int | None = None) -> AgentIdentity:
        identity = self.get(agent_id)
        if identity.lifecycle_state != "PROVISIONED":
            raise ValueError("only provisioned agents can activate")
        activated = replace(identity, lifecycle_state="ACTIVE", activated_at=now or int(time.time()))
        self._agents[agent_id] = activated
        self._audit("agent_activated", {"agent_id": agent_id, "tenant_id": identity.tenant_id})
        return activated

    def get(self, agent_id: str) -> AgentIdentity:
        try:
            return self._agents[agent_id]
        except KeyError as exc:
            raise AuthorizationDenied("AGENT_NOT_FOUND") from exc

    def revoke(self, agent_id: str, reason: str, now: int | None = None) -> None:
        identity = self.get(agent_id)
        revoked = replace(identity, lifecycle_state="REVOKED", revoked_at=now or int(time.time()), revocation_reason=_text(reason, "revocation_reason"))
        self._agents[agent_id] = revoked
        self._audit("agent_revoked", {"agent_id": agent_id, "tenant_id": identity.tenant_id, "reason": reason})

    def revoke_matching(self, *, tenant_id: str | None = None, role: str | None = None, model_deployment: str | None = None, all_agents: bool = False, reason: str = "policy response") -> int:
        targets = [agent for agent in self._agents.values() if all_agents or (tenant_id is not None and agent.tenant_id == tenant_id) or (role is not None and agent.role == role) or (model_deployment is not None and agent.provider_deployment == model_deployment)]
        for agent in targets:
            self.revoke(agent.agent_id, reason)
        return len(targets)

    def ids_matching(self, *, tenant_id: str | None = None, role: str | None = None, model_deployment: str | None = None) -> set[str]:
        return {
            agent.agent_id for agent in self._agents.values()
            if (tenant_id is not None and agent.tenant_id == tenant_id)
            or (role is not None and agent.role == role)
            or (model_deployment is not None and agent.provider_deployment == model_deployment)
        }

    def all_ids(self) -> set[str]:
        """Return registered agent IDs without exposing registry storage."""
        return set(self._agents)

    def ai_ids(self) -> set[str]:
        """Return only identities bound to an AI model deployment."""
        return {
            agent.agent_id
            for agent in self._agents.values()
            if agent.model_identity is not None
        }


class LeaseRegistry:
    def __init__(self, signer: HMACLeaseSigner, kill_switch: KillSwitch, audit: AuditSink | None = None):
        self._signer = signer
        self._kill_switch = kill_switch
        self._leases: dict[str, CapabilityLease] = {}
        self._delegated_children: dict[str, set[str]] = {}
        self._delegation_lock = Lock()
        self._audit = audit or (lambda _event, _data: None)

    def issue(self, lease: CapabilityLease) -> CapabilityLease:
        if self._kill_switch.engaged:
            self._audit("lease_denied", {"lease_id": lease.lease_id, "reason": "KILL_SWITCH_ENGAGED"})
            raise AuthorizationDenied("KILL_SWITCH_ENGAGED")
        if lease.lease_id in self._leases:
            raise ValueError("lease already exists")
        signed = self._signer.sign(lease)
        self._leases[lease.lease_id] = signed
        self._audit("lease_issued", {"lease_id": lease.lease_id, "agent_id": lease.subject_agent_id, "tenant_id": lease.tenant_id})
        return signed

    def issue_delegated(self, parent_lease_id: str, child: CapabilityLease, now: int | None = None) -> CapabilityLease:
        """Issue a child lease only when it is a strict bounded subset of its parent."""
        current = int(time.time()) if now is None else now
        parent = self.get(parent_lease_id)
        self.verify(parent)
        if parent.revoked_at is not None or current >= parent.expires_at:
            raise AuthorizationDenied("PARENT_LEASE_INACTIVE")
        if not parent.delegation_allowed or parent.delegation_depth <= 0:
            raise AuthorizationDenied("DELEGATION_NOT_ALLOWED")
        if child.tenant_id != parent.tenant_id or child.issuer_identity != parent.subject_agent_id:
            raise AuthorizationDenied("DELEGATION_TENANT_OR_ISSUER_MISMATCH")
        if child.valid_from < parent.valid_from or child.expires_at > parent.expires_at or child.delegation_depth >= parent.delegation_depth:
            raise AuthorizationDenied("DELEGATION_LIFETIME_OR_DEPTH_EXCEEDED")
        if child.max_blast_radius > parent.max_blast_radius:
            raise AuthorizationDenied("DELEGATION_BLAST_RADIUS_EXCEEDED")
        if child.max_concurrent_work > parent.max_concurrent_work:
            raise AuthorizationDenied("DELEGATION_WORK_BUDGET_EXCEEDED")
        if child.max_model_tokens_per_work > parent.max_model_tokens_per_work:
            raise AuthorizationDenied("DELEGATION_MODEL_TOKEN_BUDGET_EXCEEDED")
        for child_scope, parent_scope in ((child.granted_capabilities, parent.granted_capabilities), (child.allowed_tools, parent.allowed_tools), (child.allowed_resources, parent.allowed_resources), (child.allowed_data_classifications, parent.allowed_data_classifications), (child.allowed_action_classes, parent.allowed_action_classes)):
            if not set(child_scope).issubset(parent_scope):
                raise AuthorizationDenied("DELEGATION_PRIVILEGE_ESCALATION")
        with self._delegation_lock:
            children = self._delegated_children.setdefault(parent_lease_id, set())
            if len(children) >= parent.max_delegated_leases:
                raise AuthorizationDenied("DELEGATION_FANOUT_EXCEEDED")
            issued = self.issue(child)
            children.add(issued.lease_id)
        self._audit("delegated_lease_issued", {"parent_lease_id": parent_lease_id, "lease_id": issued.lease_id, "agent_id": issued.subject_agent_id, "tenant_id": issued.tenant_id})
        return issued

    def get(self, lease_id: str) -> CapabilityLease:
        try:
            return self._leases[lease_id]
        except KeyError as exc:
            raise AuthorizationDenied("LEASE_NOT_FOUND") from exc

    def for_agent(self, agent_id: str) -> CapabilityLease:
        candidates = [lease for lease in self._leases.values() if lease.subject_agent_id == agent_id]
        if not candidates:
            raise AuthorizationDenied("LEASE_NOT_FOUND")
        return max(candidates, key=lambda lease: lease.valid_from)

    def verify(self, lease: CapabilityLease) -> None:
        self._signer.verify(lease)

    def revoke_agent_ids(self, agent_ids: set[str], reason: str = "policy response") -> int:
        targets = [lease.lease_id for lease in self._leases.values() if lease.subject_agent_id in agent_ids]
        for lease_id in targets:
            self.revoke(lease_id, reason)
        return len(targets)

    def revoke_issued_by(self, issuer_identity: str, reason: str = "parent delegation revoked") -> int:
        issuer_identity = _text(issuer_identity, "issuer_identity")
        targets = [lease.lease_id for lease in self._leases.values() if lease.issuer_identity == issuer_identity]
        for lease_id in targets:
            self.revoke(lease_id, reason)
        return len(targets)

    def revoke(self, lease_id: str, reason: str, now: int | None = None) -> None:
        lease = self.get(lease_id)
        self._leases[lease_id] = replace(lease, revoked_at=now or int(time.time()), revocation_reason=_text(reason, "revocation_reason"))
        self._audit("lease_revoked", {"lease_id": lease_id, "agent_id": lease.subject_agent_id, "reason": reason})

    def revoke_matching(self, *, agent_id: str | None = None, tenant_id: str | None = None, role_agent_ids: set[str] | None = None, all_leases: bool = False, reason: str = "policy response") -> int:
        targets = []
        for lease in self._leases.values():
            if all_leases or (agent_id and lease.subject_agent_id == agent_id) or (tenant_id and lease.tenant_id == tenant_id) or (role_agent_ids and lease.subject_agent_id in role_agent_ids):
                targets.append(lease.lease_id)
        for lease_id in targets:
            self.revoke(lease_id, reason)
        return len(targets)


@dataclass(frozen=True)
class AuthorizationRequest:
    capability: str
    tenant_id: str
    resource: str
    data_classification: str
    action_class: str = "READ"
    tool: str | None = None
    blast_radius: int = 0
    model_identity: ModelBinding | None = None
    policy_version: str = "FW-ASOC-01-v1"
    action_ticket_valid: bool = False
    action_ticket_id: str | None = None
    requested_model_tokens: int = 0

    def __post_init__(self) -> None:
        for field in ("capability", "tenant_id", "resource", "data_classification", "action_class", "policy_version"):
            object.__setattr__(self, field, _text(getattr(self, field), field))
        if self.tool is not None:
            object.__setattr__(self, "tool", _text(self.tool, "tool"))
        if self.action_ticket_id is not None:
            object.__setattr__(self, "action_ticket_id", _text(self.action_ticket_id, "action_ticket_id"))
        if not isinstance(self.blast_radius, int) or isinstance(self.blast_radius, bool) or self.blast_radius < 0:
            raise ValueError("blast_radius must be a non-negative integer")
        if (
            not isinstance(self.requested_model_tokens, int)
            or isinstance(self.requested_model_tokens, bool)
            or self.requested_model_tokens < 0
        ):
            raise ValueError("requested_model_tokens must be a non-negative integer")
        if not isinstance(self.action_ticket_valid, bool):
            raise ValueError("action_ticket_valid must be boolean")
        if self.model_identity is not None and not isinstance(self.model_identity, ModelBinding):
            raise ValueError("model_identity must be a ModelBinding")


class AggregateBlastRadiusLedger:
    """Fail-closed, policy-owned aggregate radius reservations for live leases."""

    def __init__(self) -> None:
        self._reservations: dict[tuple[str, str, str, str, str], list[tuple[str, str, int, int]]] = {}
        self._lock = Lock()

    def reserve(self, request: AuthorizationRequest, lease: CapabilityLease, *, limit: int, now: int) -> int:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise ValueError("aggregate blast radius limit is invalid")
        scope = (request.tenant_id, request.capability, request.resource, request.action_class, request.policy_version)
        with self._lock:
            active = [item for item in self._reservations.get(scope, []) if item[3] > now]
            used = sum(item[2] for item in active)
            if used + request.blast_radius > limit:
                raise AuthorizationDenied("AGGREGATE_BLAST_RADIUS_EXCEEDED")
            active.append((lease.subject_agent_id, lease.lease_id, request.blast_radius, lease.expires_at))
            self._reservations[scope] = active
            return limit - used - request.blast_radius

    def revoke_matching(self, *, tenant_id: str | None = None, agent_id: str | None = None) -> int:
        removed = 0
        with self._lock:
            for scope, entries in tuple(self._reservations.items()):
                if tenant_id is not None and scope[0] != tenant_id:
                    continue
                retained = [entry for entry in entries if agent_id is not None and entry[0] != agent_id]
                if agent_id is None:
                    retained = []
                removed += len(entries) - len(retained)
                if retained:
                    self._reservations[scope] = retained
                else:
                    self._reservations.pop(scope, None)
        return removed

    def release_latest(self, request: AuthorizationRequest, lease: CapabilityLease, *, now: int) -> None:
        scope = (request.tenant_id, request.capability, request.resource, request.action_class, request.policy_version)
        with self._lock:
            active = [item for item in self._reservations.get(scope, []) if item[3] > now]
            for index in range(len(active) - 1, -1, -1):
                if active[index][0] == lease.subject_agent_id and active[index][1] == lease.lease_id and active[index][2] == request.blast_radius:
                    active.pop(index)
                    break
            if active:
                self._reservations[scope] = active
            else:
                self._reservations.pop(scope, None)


class WorkBudgetLedger:
    """Lease-bound concurrent-work admission; capacity is tenant and agent scoped."""

    def __init__(self) -> None:
        self._reservations: dict[tuple[str, str], list[tuple[str, int, int]]] = {}
        self._lock = Lock()

    def admit(self, lease: CapabilityLease, work_id: str, *, limit: int | None = None, tenant_limit: int | None = None, model_tokens: int = 0, tenant_model_token_limit: int | None = None, now: int) -> tuple[int, int | None, int | None]:
        work_id = _text(work_id, "work_id")
        if limit is not None and (
            not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0
        ):
            raise ValueError("work budget limit is invalid")
        if tenant_limit is not None and (
            not isinstance(tenant_limit, int) or isinstance(tenant_limit, bool) or tenant_limit <= 0
        ):
            raise ValueError("tenant work budget limit is invalid")
        if not isinstance(model_tokens, int) or isinstance(model_tokens, bool) or model_tokens < 0:
            raise ValueError("model token budget is invalid")
        if tenant_model_token_limit is not None and (
            not isinstance(tenant_model_token_limit, int)
            or isinstance(tenant_model_token_limit, bool)
            or tenant_model_token_limit <= 0
        ):
            raise ValueError("tenant model token budget limit is invalid")
        effective_limit = lease.max_concurrent_work if limit is None else min(lease.max_concurrent_work, limit)
        scope = (lease.tenant_id, lease.subject_agent_id)
        with self._lock:
            active = [entry for entry in self._reservations.get(scope, []) if entry[1] > now]
            tenant_active = 0
            tenant_model_tokens_used = 0
            for candidate_scope, entries in tuple(self._reservations.items()):
                candidate_active = [entry for entry in entries if entry[1] > now]
                if candidate_active:
                    self._reservations[candidate_scope] = candidate_active
                    if candidate_scope[0] == lease.tenant_id:
                        tenant_active += len(candidate_active)
                        tenant_model_tokens_used += sum(entry[2] for entry in candidate_active)
                else:
                    self._reservations.pop(candidate_scope, None)
            if any(entry[0] == work_id for entry in active):
                raise AuthorizationDenied("WORK_ALREADY_ADMITTED")
            if len(active) >= effective_limit:
                raise AuthorizationDenied("WORK_CONCURRENCY_LIMIT_EXCEEDED")
            if tenant_limit is not None and tenant_active >= tenant_limit:
                raise AuthorizationDenied("TENANT_WORK_CONCURRENCY_LIMIT_EXCEEDED")
            if (
                tenant_model_token_limit is not None
                and tenant_model_tokens_used + model_tokens > tenant_model_token_limit
            ):
                raise AuthorizationDenied("TENANT_MODEL_TOKEN_BUDGET_EXCEEDED")
            active.append((work_id, lease.expires_at, model_tokens))
            self._reservations[scope] = active
            return (
                effective_limit - len(active),
                None if tenant_limit is None else tenant_limit - tenant_active - 1,
                None if tenant_model_token_limit is None else tenant_model_token_limit - tenant_model_tokens_used - model_tokens,
            )

    def release(self, *, tenant_id: str, agent_id: str, work_id: str, now: int) -> bool:
        scope = (_text(tenant_id, "tenant_id"), _text(agent_id, "agent_id"))
        work_id = _text(work_id, "work_id")
        with self._lock:
            active = [entry for entry in self._reservations.get(scope, []) if entry[1] > now]
            retained = [entry for entry in active if entry[0] != work_id]
            released = len(retained) != len(active)
            if retained:
                self._reservations[scope] = retained
            else:
                self._reservations.pop(scope, None)
            return released

    def revoke_matching(self, *, tenant_id: str | None = None, agent_id: str | None = None) -> int:
        removed = 0
        with self._lock:
            for scope, entries in tuple(self._reservations.items()):
                tenant_matches = tenant_id is None or scope[0] == tenant_id
                agent_matches = agent_id is None or scope[1] == agent_id
                if not (tenant_matches and agent_matches):
                    continue
                removed += len(entries)
                self._reservations.pop(scope, None)
        return removed

    def active_count(self, *, tenant_id: str, agent_id: str, now: int) -> int:
        scope = (_text(tenant_id, "tenant_id"), _text(agent_id, "agent_id"))
        with self._lock:
            active = [entry for entry in self._reservations.get(scope, []) if entry[1] > now]
            if active:
                self._reservations[scope] = active
            else:
                self._reservations.pop(scope, None)
            return len(active)

    def active_tenant_count(self, *, tenant_id: str, now: int) -> int:
        tenant_id = _text(tenant_id, "tenant_id")
        with self._lock:
            active_count = 0
            for scope, entries in tuple(self._reservations.items()):
                active = [entry for entry in entries if entry[1] > now]
                if active:
                    self._reservations[scope] = active
                    if scope[0] == tenant_id:
                        active_count += len(active)
                else:
                    self._reservations.pop(scope, None)
            return active_count

    def active_tenant_model_tokens(self, *, tenant_id: str, now: int) -> int:
        tenant_id = _text(tenant_id, "tenant_id")
        with self._lock:
            active_tokens = 0
            for scope, entries in tuple(self._reservations.items()):
                active = [entry for entry in entries if entry[1] > now]
                if active:
                    self._reservations[scope] = active
                    if scope[0] == tenant_id:
                        active_tokens += sum(entry[2] for entry in active)
                else:
                    self._reservations.pop(scope, None)
            return active_tokens


class CapabilityAuthorizer:
    def __init__(self, agents: AgentRegistry, leases: LeaseRegistry, kill_switch: KillSwitch, audit: AuditSink | None = None, policy: Callable[[AgentIdentity, CapabilityLease, AuthorizationRequest], bool] | None = None, action_ticket_validator: Callable[[AgentIdentity, CapabilityLease, AuthorizationRequest], bool] | None = None, action_tickets: ActionTicketRegistry | None = None, policy_engine: DeterministicPolicy | None = None, mcp_tool_validator: Callable[[AgentIdentity, CapabilityLease, AuthorizationRequest], bool] | None = None, mcp_gateway: MCPGateway | None = None, model_binding_validator: Callable[[AgentIdentity, CapabilityLease, AuthorizationRequest], bool] | None = None, model_broker: ModelBroker | None = None, safety_evidence_provider: Callable[[], Mapping[str, Any]] | None = None, blast_radius_ledger: AggregateBlastRadiusLedger | None = None, work_budget_ledger: WorkBudgetLedger | None = None):
        self._agents, self._leases, self._kill_switch = agents, leases, kill_switch
        self._audit = audit or (lambda _event, _data: None)
        # An absent policy must never become implicit authority at this
        # security boundary. The canonical policy engine must be supplied.
        self._policy = policy or (lambda _agent, _lease, _request: False)
        self._policy_engine = policy_engine
        # A caller-provided boolean is not proof of an Action Ticket. The
        # canonical ticket service must validate the request and its binding.
        self._action_ticket_validator = action_ticket_validator or (lambda _agent, _lease, _request: False)
        self._action_tickets = action_tickets
        # Local tool names are not sufficient authority; the canonical MCP
        # Gateway must validate tenant, capability, and tool binding.
        self._mcp_tool_validator = mcp_tool_validator or (lambda _agent, _lease, _request: False)
        self._mcp_gateway = mcp_gateway
        # Exact metadata equality is necessary but not sufficient; the
        # canonical Model Broker must approve the model/deployment binding.
        self._model_binding_validator = model_binding_validator or (lambda _agent, _lease, _request: False)
        self._model_broker = model_broker
        self.blast_radius_ledger = blast_radius_ledger or AggregateBlastRadiusLedger()
        self.work_budget_ledger = work_budget_ledger or WorkBudgetLedger()
        # Reuse FW-ROOT's canonical safety contract rather than duplicating it.
        self._safety_evidence_provider = safety_evidence_provider or (
            lambda: {"mode": "DRY_RUN", "deployment": "DISABLED", "kill_switch": "ENGAGED" if self._kill_switch.engaged else "CLEARED_FOR_DRY_RUN"}
        )

    def _best_effort_audit(self, event: str, data: Mapping[str, Any]) -> None:
        """Keep a failed diagnostic write from masking a fail-closed denial."""
        try:
            self._audit(event, data)
        except Exception:
            pass

    def admit_work(self, agent_id: str, work_id: str, request: AuthorizationRequest | None = None, now: int | None = None) -> dict[str, Any]:
        """Reserve a lease's bounded concurrent-work capacity after authorization."""
        current = int(time.time()) if now is None else now
        lease: CapabilityLease | None = None
        policy_work_limit: int | None = None
        policy_tenant_work_limit: int | None = None
        policy_model_token_limit: int | None = None
        policy_tenant_model_token_limit: int | None = None
        try:
            validate_safety_evidence(self._safety_evidence_provider(), require_kill_switch=False)
            agent = self._agents.get(agent_id)
            lease = self._leases.for_agent(agent_id)
            self._leases.verify(lease)
            if agent.lifecycle_state != "ACTIVE" or agent.revoked_at is not None:
                raise AuthorizationDenied("AGENT_NOT_ACTIVE")
            if agent.expires_at is not None and current >= agent.expires_at:
                raise AuthorizationDenied("AGENT_EXPIRED")
            if lease.revoked_at is not None or current < lease.valid_from or current >= lease.expires_at:
                raise AuthorizationDenied("LEASE_INACTIVE")
            if self._policy_engine is not None:
                if not isinstance(request, AuthorizationRequest):
                    raise AuthorizationDenied("WORK_POLICY_CONTEXT_REQUIRED")
                if request.tenant_id != lease.tenant_id:
                    raise AuthorizationDenied("TENANT_MISMATCH")
                context = PolicyContext(
                    request.tenant_id, agent.agent_id, request.capability, request.resource,
                    request.action_class, request.policy_version,
                )
                if not self._policy_engine.evaluate(context).allowed:
                    raise AuthorizationDenied("WORK_POLICY_DENIED")
                policy_work_limit = self._policy_engine.concurrent_work_limit(context)
                if policy_work_limit is None:
                    raise AuthorizationDenied("WORK_CONCURRENCY_LIMIT_REQUIRED")
                policy_tenant_work_limit = self._policy_engine.tenant_concurrent_work_limit(context)
                if policy_tenant_work_limit is None:
                    raise AuthorizationDenied("TENANT_WORK_CONCURRENCY_LIMIT_REQUIRED")
                if agent.model_identity is not None:
                    if request.model_identity != agent.model_identity:
                        raise AuthorizationDenied("MODEL_BINDING_MISMATCH")
                    if request.requested_model_tokens <= 0:
                        raise AuthorizationDenied("MODEL_TOKEN_BUDGET_REQUIRED")
                    policy_model_token_limit = self._policy_engine.model_tokens_per_work_limit(context)
                    if policy_model_token_limit is None:
                        raise AuthorizationDenied("MODEL_TOKEN_BUDGET_LIMIT_REQUIRED")
                    policy_tenant_model_token_limit = self._policy_engine.tenant_model_tokens_limit(context)
                    if policy_tenant_model_token_limit is None:
                        raise AuthorizationDenied("TENANT_MODEL_TOKEN_BUDGET_LIMIT_REQUIRED")
                    if request.requested_model_tokens > min(
                        lease.max_model_tokens_per_work, policy_model_token_limit,
                    ):
                        raise AuthorizationDenied("MODEL_TOKEN_BUDGET_EXCEEDED")
            remaining, tenant_remaining, tenant_model_tokens_remaining = self.work_budget_ledger.admit(
                lease, work_id, limit=policy_work_limit, tenant_limit=policy_tenant_work_limit,
                model_tokens=0 if request is None else request.requested_model_tokens,
                tenant_model_token_limit=policy_tenant_model_token_limit, now=current,
            )
        except (AuthorizationDenied, LeaseIntegrityError, ValueError) as exc:
            reason = exc.reason if isinstance(exc, AuthorizationDenied) else "WORK_ADMISSION_INVALID"
            self._best_effort_audit("work_admission_denied", {
                "agent_id": agent_id, "work_id": work_id, "reason": reason, "timestamp": current,
            })
            if isinstance(exc, AuthorizationDenied):
                raise
            raise AuthorizationDenied(reason) from exc
        result = {
            "admitted": True, "agent_id": agent_id, "tenant_id": lease.tenant_id,
            "lease_id": lease.lease_id, "work_id": work_id,
            "max_concurrent_work": lease.max_concurrent_work,
            "policy_concurrent_work_limit": policy_work_limit,
            "policy_tenant_concurrent_work_limit": policy_tenant_work_limit,
            "max_model_tokens_per_work": lease.max_model_tokens_per_work,
            "policy_model_tokens_per_work_limit": policy_model_token_limit,
            "policy_tenant_model_tokens_limit": policy_tenant_model_token_limit,
            "requested_model_tokens": 0 if request is None else request.requested_model_tokens,
            "concurrent_work_remaining": remaining, "tenant_concurrent_work_remaining": tenant_remaining,
            "tenant_model_tokens_remaining": tenant_model_tokens_remaining,
            "timestamp": current,
        }
        try:
            self._audit("work_admitted", result)
        except Exception as exc:
            self.work_budget_ledger.release(
                tenant_id=lease.tenant_id, agent_id=agent_id, work_id=work_id, now=current,
            )
            raise AuthorizationDenied("EVIDENCE_WRITE_FAILED") from exc
        return result

    def complete_work(self, agent_id: str, work_id: str, now: int | None = None) -> bool:
        """Release only the caller's tenant-bound admitted work capacity."""
        current = int(time.time()) if now is None else now
        agent = self._agents.get(agent_id)
        released = self.work_budget_ledger.release(
            tenant_id=agent.tenant_id, agent_id=agent_id, work_id=work_id, now=current,
        )
        if released:
            try:
                self._audit("work_completed", {
                    "agent_id": agent_id, "tenant_id": agent.tenant_id,
                    "work_id": work_id, "timestamp": current,
                })
            except Exception as exc:
                raise AuthorizationDenied("EVIDENCE_WRITE_FAILED") from exc
        return released

    def authorize(self, agent_id: str, request: AuthorizationRequest, now: int | None = None) -> dict[str, Any]:
        current = int(time.time()) if now is None else now
        consumed_ticket_id: str | None = None
        policy_decision_reason: str | None = None
        aggregate_blast_radius_limit: int | None = None
        aggregate_blast_radius_remaining: int | None = None
        aggregate_reservation_made = False
        try:
            try:
                validate_safety_evidence(self._safety_evidence_provider(), require_kill_switch=False)
            except Exception as exc:
                self._best_effort_audit("safety_invariant_validation_failed", {"agent_id": agent_id, "reason": type(exc).__name__, "timestamp": current})
                raise AuthorizationDenied("SAFETY_INVARIANT_UNAVAILABLE" if isinstance(exc, (OSError, RuntimeError)) else "SAFETY_INVARIANT_INVALID") from exc
            agent = self._agents.get(agent_id)
            lease = self._leases.for_agent(agent_id)
            self._leases.verify(lease)
            if agent.lifecycle_state != "ACTIVE": raise AuthorizationDenied("AGENT_NOT_ACTIVE")
            if agent.revoked_at is not None: raise AuthorizationDenied("AGENT_REVOKED")
            if agent.expires_at is not None and current >= agent.expires_at:
                raise AuthorizationDenied("AGENT_EXPIRED")
            if agent.tenant_id != request.tenant_id or lease.tenant_id != request.tenant_id: raise AuthorizationDenied("TENANT_MISMATCH")
            if lease.revoked_at is not None: raise AuthorizationDenied("LEASE_REVOKED")
            if current < lease.valid_from: raise AuthorizationDenied("LEASE_NOT_YET_VALID")
            if current >= lease.expires_at:
                self._best_effort_audit("lease_expired", {"lease_id": lease.lease_id, "agent_id": agent_id})
                raise AuthorizationDenied("LEASE_EXPIRED")
            if request.capability not in lease.granted_capabilities: raise AuthorizationDenied("CAPABILITY_NOT_GRANTED")
            if request.resource not in lease.allowed_resources: raise AuthorizationDenied("RESOURCE_OUT_OF_SCOPE")
            if request.data_classification not in lease.allowed_data_classifications or request.data_classification not in agent.allowed_data_classifications: raise AuthorizationDenied("DATA_CLASSIFICATION_DENIED")
            if request.action_class not in lease.allowed_action_classes: raise AuthorizationDenied("ACTION_CLASS_DENIED")
            if request.action_class not in READ_ONLY_ACTIONS | MUTATING_ACTIONS: raise AuthorizationDenied("ACTION_CLASS_UNKNOWN")
            if request.blast_radius > lease.max_blast_radius: raise AuthorizationDenied("BLAST_RADIUS_EXCEEDED")
            if request.tool is not None:
                if request.tool not in lease.allowed_tools: raise AuthorizationDenied("MCP_TOOL_NOT_ALLOWED")
                try:
                    if self._mcp_gateway is not None:
                        tool_allowed = self._mcp_gateway.allows(
                            tenant_id=request.tenant_id, subject_agent_id=agent.agent_id,
                            capability=request.capability, resource=request.resource,
                            tool=request.tool, policy_version=request.policy_version,
                        )
                    else:
                        tool_allowed = self._mcp_tool_validator(agent, lease, request)
                except Exception as exc:
                    self._best_effort_audit("mcp_tool_validation_failed", {"agent_id": agent_id, "lease_id": lease.lease_id, "tool": request.tool, "reason": type(exc).__name__})
                    raise AuthorizationDenied("MCP_GATEWAY_UNAVAILABLE") from exc
                if tool_allowed is not True: raise AuthorizationDenied("MCP_GATEWAY_DENIED")
            if request.policy_version != lease.policy_version or request.policy_version != agent.policy_version: raise AuthorizationDenied("STALE_POLICY_VERSION")
            if agent.model_identity is not None:
                if not agent.model_identity.approved or request.model_identity != agent.model_identity: raise AuthorizationDenied("MODEL_BINDING_MISMATCH")
                try:
                    if self._model_broker is not None:
                        model_allowed = self._model_broker.allows(
                            tenant_id=agent.tenant_id, subject_agent_id=agent.agent_id,
                            model=agent.model_identity.model, provider=agent.model_identity.provider,
                            deployment=agent.model_identity.deployment, version=agent.model_identity.version,
                            approval_version=agent.model_identity.approval_version,
                        )
                    else:
                        model_allowed = self._model_binding_validator(agent, lease, request)
                except Exception as exc:
                    self._best_effort_audit("model_binding_validation_failed", {"agent_id": agent_id, "lease_id": lease.lease_id, "reason": type(exc).__name__})
                    raise AuthorizationDenied("MODEL_BROKER_UNAVAILABLE") from exc
                if model_allowed is not True: raise AuthorizationDenied("MODEL_BROKER_DENIED")
            if request.action_class in MUTATING_ACTIONS:
                if self._kill_switch.engaged: raise AuthorizationDenied("KILL_SWITCH_MUTATION_BLOCKED")
            if request.action_class not in READ_ONLY_ACTIONS and request.action_class not in MUTATING_ACTIONS:
                raise AuthorizationDenied("ACTION_TICKET_REQUIRED")
            try:
                if self._policy_engine is not None:
                    decision = self._policy_engine.evaluate(PolicyContext(
                        request.tenant_id, agent.agent_id, request.capability, request.resource,
                        request.action_class, request.policy_version,
                    ))
                    policy_allows = decision.allowed
                    policy_decision_reason = decision.reason
                else:
                    policy_allows = self._policy(agent, lease, request)
            except Exception as exc:
                self._best_effort_audit("policy_evaluation_failed", {"agent_id": agent_id, "lease_id": lease.lease_id, "reason": type(exc).__name__})
                raise AuthorizationDenied("POLICY_UNAVAILABLE") from exc
            if not isinstance(policy_allows, bool):
                raise AuthorizationDenied("POLICY_RESULT_INVALID")
            if not policy_allows: raise AuthorizationDenied("POLICY_DENIED")
            if request.action_class in MUTATING_ACTIONS and self._action_tickets is not None:
                if request.action_ticket_id != lease.action_ticket_reference:
                    raise AuthorizationDenied("ACTION_TICKET_INVALID")
                try:
                    self._action_tickets.validate(
                        request.action_ticket_id, tenant_id=request.tenant_id, subject_agent_id=agent.agent_id,
                        lease_id=lease.lease_id, capability=request.capability, resource=request.resource,
                        action_class=request.action_class, policy_version=request.policy_version, now=current,
                    )
                except ActionTicketError as exc:
                    raise AuthorizationDenied("ACTION_TICKET_INVALID") from exc
                except Exception as exc:
                    self._best_effort_audit("action_ticket_validation_failed", {"agent_id": agent_id, "lease_id": lease.lease_id, "reason": type(exc).__name__})
                    raise AuthorizationDenied("ACTION_TICKET_UNAVAILABLE") from exc
            if self._policy_engine is not None:
                aggregate_blast_radius_limit = self._policy_engine.aggregate_blast_radius_limit(PolicyContext(
                    request.tenant_id, agent.agent_id, request.capability, request.resource,
                    request.action_class, request.policy_version,
                ))
                if request.blast_radius > 0 and aggregate_blast_radius_limit is None:
                    raise AuthorizationDenied("AGGREGATE_BLAST_RADIUS_LIMIT_REQUIRED")
                if aggregate_blast_radius_limit is not None:
                    aggregate_blast_radius_remaining = self.blast_radius_ledger.reserve(
                        request, lease, limit=aggregate_blast_radius_limit, now=current,
                    )
                    aggregate_reservation_made = True
            if request.action_class in MUTATING_ACTIONS:
                if self._action_tickets is not None:
                    if request.action_ticket_id != lease.action_ticket_reference:
                        raise AuthorizationDenied("ACTION_TICKET_INVALID")
                    try:
                        self._action_tickets.validate_and_consume(
                            request.action_ticket_id,
                            tenant_id=request.tenant_id,
                            subject_agent_id=agent.agent_id,
                            lease_id=lease.lease_id,
                            capability=request.capability,
                            resource=request.resource,
                            action_class=request.action_class,
                            policy_version=request.policy_version,
                            now=current,
                        )
                        consumed_ticket_id = request.action_ticket_id
                    except ActionTicketError as exc:
                        if aggregate_reservation_made:
                            self.blast_radius_ledger.release_latest(request, lease, now=current)
                        raise AuthorizationDenied("ACTION_TICKET_INVALID") from exc
                    except Exception as exc:
                        if aggregate_reservation_made:
                            self.blast_radius_ledger.release_latest(request, lease, now=current)
                        self._best_effort_audit("action_ticket_validation_failed", {"agent_id": agent_id, "lease_id": lease.lease_id, "reason": type(exc).__name__})
                        raise AuthorizationDenied("ACTION_TICKET_UNAVAILABLE") from exc
                else:
                    try:
                        ticket_valid = self._action_ticket_validator(agent, lease, request)
                    except Exception as exc:
                        self._best_effort_audit("action_ticket_validation_failed", {"agent_id": agent_id, "lease_id": lease.lease_id, "reason": type(exc).__name__})
                        raise AuthorizationDenied("ACTION_TICKET_UNAVAILABLE") from exc
                    if ticket_valid is not True: raise AuthorizationDenied("ACTION_TICKET_REQUIRED")
        except (AuthorizationDenied, LeaseIntegrityError, ValueError) as exc:
            if isinstance(exc, AuthorizationDenied):
                reason = exc.reason
            elif isinstance(exc, LeaseIntegrityError):
                reason = "LEASE_INTEGRITY_ERROR"
            else:
                reason = type(exc).__name__.removesuffix("Error").upper() + "_ERROR"
            try:
                self._audit("authorization_denied", {
                    "agent_id": agent_id, "tenant_id": request.tenant_id, "capability": request.capability,
                    "resource": request.resource, "data_classification": request.data_classification,
                    "action_class": request.action_class, "tool": request.tool,
                    "policy_version": request.policy_version, "action_ticket_id": request.action_ticket_id,
                    "blast_radius": request.blast_radius,
                    "aggregate_blast_radius_limit": aggregate_blast_radius_limit,
                    "reason": reason, "timestamp": current,
                })
            except Exception:
                # A failing sink must never turn a bounded denial into a raw
                # exception or implicit authority.
                pass
            if isinstance(exc, AuthorizationDenied):
                raise
            raise AuthorizationDenied(reason) from exc
        result = {
            "authorized": True, "agent_id": agent_id, "lease_id": lease.lease_id,
            "tenant_id": request.tenant_id, "capability": request.capability,
            "resource": request.resource, "data_classification": request.data_classification,
            "action_class": request.action_class, "tool": request.tool,
            "policy_version": request.policy_version, "action_ticket_id": consumed_ticket_id,
            "policy_decision_reason": policy_decision_reason,
            "blast_radius": request.blast_radius,
            "aggregate_blast_radius_limit": aggregate_blast_radius_limit,
            "aggregate_blast_radius_remaining": aggregate_blast_radius_remaining,
            "model_binding": request.model_identity.as_dict() if request.model_identity is not None else None,
            "approved_purpose": agent.approved_purpose,
            "timestamp": current,
        }
        try:
            self._audit("authorization_success", result)
        except Exception as exc:
            # Do not return an authorization result unless its required
            # Evidence record was accepted by the canonical audit boundary.
            raise AuthorizationDenied("EVIDENCE_WRITE_FAILED") from exc
        return result


class ASOCControlPlane:
    """Small coordination boundary for immediate revocation operations."""

    def __init__(self, agents: AgentRegistry, leases: LeaseRegistry, kill_switch: KillSwitch, action_tickets: ActionTicketRegistry | None = None, model_broker: ModelBroker | None = None, mcp_gateway: MCPGateway | None = None, blast_radius_ledger: AggregateBlastRadiusLedger | None = None, work_budget_ledger: WorkBudgetLedger | None = None):
        self.agents, self.leases, self.kill_switch = agents, leases, kill_switch
        self.action_tickets = action_tickets
        self.model_broker = model_broker
        self.mcp_gateway = mcp_gateway
        self.blast_radius_ledger = blast_radius_ledger
        self.work_budget_ledger = work_budget_ledger

    def revoke_agent(self, agent_id: str, reason: str = "agent revoked") -> None:
        self.agents.revoke(agent_id, reason)
        self.leases.revoke_agent_ids({agent_id}, reason)
        self.leases.revoke_issued_by(agent_id, reason)
        if self.action_tickets is not None:
            self.action_tickets.revoke_matching(subject_agent_id=agent_id)
        if self.model_broker is not None:
            self.model_broker.revoke_matching(subject_agent_id=agent_id)
        if self.mcp_gateway is not None:
            self.mcp_gateway.revoke_matching(subject_agent_id=agent_id)
        if self.blast_radius_ledger is not None:
            self.blast_radius_ledger.revoke_matching(agent_id=agent_id)
        if self.work_budget_ledger is not None:
            self.work_budget_ledger.revoke_matching(agent_id=agent_id)

    def revoke_role(self, role: str, reason: str = "role revoked") -> int:
        ids = self.agents.ids_matching(role=role)
        self.agents.revoke_matching(role=role, reason=reason)
        revoked = self.leases.revoke_agent_ids(ids, reason)
        if self.action_tickets is not None:
            for agent_id in ids:
                self.action_tickets.revoke_matching(subject_agent_id=agent_id)
        if self.model_broker is not None:
            for agent_id in ids:
                self.model_broker.revoke_matching(subject_agent_id=agent_id)
        if self.mcp_gateway is not None:
            for agent_id in ids:
                self.mcp_gateway.revoke_matching(subject_agent_id=agent_id)
        if self.blast_radius_ledger is not None:
            for agent_id in ids:
                self.blast_radius_ledger.revoke_matching(agent_id=agent_id)
        if self.work_budget_ledger is not None:
            for agent_id in ids:
                self.work_budget_ledger.revoke_matching(agent_id=agent_id)
        return revoked

    def revoke_model_deployment(self, model_deployment: str, reason: str = "model deployment revoked") -> int:
        ids = self.agents.ids_matching(model_deployment=model_deployment)
        self.agents.revoke_matching(model_deployment=model_deployment, reason=reason)
        revoked = self.leases.revoke_agent_ids(ids, reason)
        if self.action_tickets is not None:
            for agent_id in ids:
                self.action_tickets.revoke_matching(subject_agent_id=agent_id)
        if self.model_broker is not None:
            self.model_broker.revoke_matching(deployment=model_deployment)
        if self.mcp_gateway is not None:
            for agent_id in ids:
                self.mcp_gateway.revoke_matching(subject_agent_id=agent_id)
        if self.blast_radius_ledger is not None:
            for agent_id in ids:
                self.blast_radius_ledger.revoke_matching(agent_id=agent_id)
        if self.work_budget_ledger is not None:
            for agent_id in ids:
                self.work_budget_ledger.revoke_matching(agent_id=agent_id)
        return revoked

    def revoke_tenant(self, tenant_id: str, reason: str = "tenant revoked") -> int:
        ids = self.agents.ids_matching(tenant_id=tenant_id)
        self.agents.revoke_matching(tenant_id=tenant_id, reason=reason)
        revoked = self.leases.revoke_agent_ids(ids, reason)
        if self.action_tickets is not None:
            self.action_tickets.revoke_matching(tenant_id=tenant_id)
        if self.model_broker is not None:
            self.model_broker.revoke_matching(tenant_id=tenant_id)
        if self.mcp_gateway is not None:
            self.mcp_gateway.revoke_matching(tenant_id=tenant_id)
        if self.blast_radius_ledger is not None:
            self.blast_radius_ledger.revoke_matching(tenant_id=tenant_id)
        if self.work_budget_ledger is not None:
            self.work_budget_ledger.revoke_matching(tenant_id=tenant_id)
        return revoked

    def engage_ai_kill_switch(self, reason: str = "AI kill switch") -> int:
        self.kill_switch.engage()
        ai_ids = self.agents.ai_ids()
        for agent_id in ai_ids:
            self.agents.revoke(agent_id, reason)
        revoked = self.leases.revoke_agent_ids(ai_ids, reason)
        if self.action_tickets is not None:
            for agent_id in ai_ids:
                self.action_tickets.revoke_matching(subject_agent_id=agent_id)
        if self.model_broker is not None:
            for agent_id in ai_ids:
                self.model_broker.revoke_matching(subject_agent_id=agent_id)
        if self.mcp_gateway is not None:
            for agent_id in ai_ids:
                self.mcp_gateway.revoke_matching(subject_agent_id=agent_id)
        if self.blast_radius_ledger is not None:
            for agent_id in ai_ids:
                self.blast_radius_ledger.revoke_matching(agent_id=agent_id)
        if self.work_budget_ledger is not None:
            for agent_id in ai_ids:
                self.work_budget_ledger.revoke_matching(agent_id=agent_id)
        return revoked


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"
