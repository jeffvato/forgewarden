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
from typing import Any, Callable, Iterable, Mapping, Protocol

from .policy_gate import validate_safety_evidence


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
        if self.model_identity and not self.model_approval_version:
            object.__setattr__(self, "model_approval_version", self.model_identity.approval_version)

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
        object.__setattr__(self, "allowed_action_classes", _tuple_text(self.allowed_action_classes, "allowed_action_classes"))
        if self.max_blast_radius < 0 or self.delegation_depth < 0 or self.valid_from >= self.expires_at:
            raise ValueError("invalid lease bounds")
        if not isinstance(self.delegation_allowed, bool):
            raise ValueError("delegation_allowed must be boolean")

    def unsigned_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in (
            "lease_id", "subject_agent_id", "issuer_identity", "tenant_id", "granted_capabilities", "allowed_tools",
            "allowed_resources", "allowed_data_classifications", "allowed_action_classes", "max_blast_radius",
            "delegation_allowed", "delegation_depth", "valid_from", "expires_at", "policy_version",
            "approval_reference", "action_ticket_reference", "creation_reason", "key_reference")}

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


class LeaseRegistry:
    def __init__(self, signer: HMACLeaseSigner, kill_switch: KillSwitch, audit: AuditSink | None = None):
        self._signer = signer
        self._kill_switch = kill_switch
        self._leases: dict[str, CapabilityLease] = {}
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

    def revoke_agent_ids(self, agent_ids: set[str], reason: str = "policy response") -> int:
        targets = [lease.lease_id for lease in self._leases.values() if lease.subject_agent_id in agent_ids]
        for lease_id in targets:
            self.revoke(lease_id, reason)
        return len(targets)

    def revoke(self, lease_id: str, reason: str, now: int | None = None) -> None:
        lease = self.get(lease_id)
        self._leases[lease_id] = replace(lease, revoked_at=now or int(time.time()), revocation_reason=_text(reason, "revocation_reason"))
        self._audit("lease_revoked", {"lease_id": lease_id, "agent_id": lease.subject_agent_id, "reason": reason})

    def revoke_matching(self, *, agent_id: str | None = None, tenant_id: str | None = None, role_agent_ids: set[str] | None = None, model_deployment: str | None = None, all_leases: bool = False, reason: str = "policy response") -> int:
        targets = []
        for lease in self._leases.values():
            if all_leases or (agent_id and lease.subject_agent_id == agent_id) or (tenant_id and lease.tenant_id == tenant_id) or (role_agent_ids and lease.subject_agent_id in role_agent_ids) or (model_deployment and lease.key_reference == model_deployment):
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


class CapabilityAuthorizer:
    def __init__(self, agents: AgentRegistry, leases: LeaseRegistry, kill_switch: KillSwitch, audit: AuditSink | None = None, policy: Callable[[AgentIdentity, CapabilityLease, AuthorizationRequest], bool] | None = None, action_ticket_validator: Callable[[AgentIdentity, CapabilityLease, AuthorizationRequest], bool] | None = None):
        self._agents, self._leases, self._kill_switch = agents, leases, kill_switch
        self._audit = audit or (lambda _event, _data: None)
        # An absent policy must never become implicit authority at this
        # security boundary. The canonical policy engine must be supplied.
        self._policy = policy or (lambda _agent, _lease, _request: False)
        # A caller-provided boolean is not proof of an Action Ticket. The
        # canonical ticket service must validate the request and its binding.
        self._action_ticket_validator = action_ticket_validator or (lambda _agent, _lease, _request: False)

    def authorize(self, agent_id: str, request: AuthorizationRequest, now: int | None = None) -> dict[str, Any]:
        current = int(time.time()) if now is None else now
        try:
            agent = self._agents.get(agent_id)
            lease = self._leases.for_agent(agent_id)
            self._leases._signer.verify(lease)
            if agent.lifecycle_state != "ACTIVE": raise AuthorizationDenied("AGENT_NOT_ACTIVE")
            if agent.revoked_at is not None: raise AuthorizationDenied("AGENT_REVOKED")
            if agent.tenant_id != request.tenant_id or lease.tenant_id != request.tenant_id: raise AuthorizationDenied("TENANT_MISMATCH")
            if lease.revoked_at is not None: raise AuthorizationDenied("LEASE_REVOKED")
            if current < lease.valid_from: raise AuthorizationDenied("LEASE_NOT_YET_VALID")
            if current >= lease.expires_at:
                self._audit("lease_expired", {"lease_id": lease.lease_id, "agent_id": agent_id})
                raise AuthorizationDenied("LEASE_EXPIRED")
            if request.capability not in lease.granted_capabilities: raise AuthorizationDenied("CAPABILITY_NOT_GRANTED")
            if request.resource not in lease.allowed_resources: raise AuthorizationDenied("RESOURCE_OUT_OF_SCOPE")
            if request.data_classification not in lease.allowed_data_classifications or request.data_classification not in agent.allowed_data_classifications: raise AuthorizationDenied("DATA_CLASSIFICATION_DENIED")
            if request.action_class not in lease.allowed_action_classes: raise AuthorizationDenied("ACTION_CLASS_DENIED")
            if request.blast_radius > lease.max_blast_radius: raise AuthorizationDenied("BLAST_RADIUS_EXCEEDED")
            if request.tool is not None and request.tool not in lease.allowed_tools: raise AuthorizationDenied("MCP_TOOL_NOT_ALLOWED")
            if request.policy_version != lease.policy_version or request.policy_version != agent.policy_version: raise AuthorizationDenied("STALE_POLICY_VERSION")
            if agent.model_identity is not None:
                if not agent.model_identity.approved or request.model_identity != agent.model_identity: raise AuthorizationDenied("MODEL_BINDING_MISMATCH")
            if request.action_class in MUTATING_ACTIONS:
                if self._kill_switch.engaged: raise AuthorizationDenied("KILL_SWITCH_MUTATION_BLOCKED")
                try:
                    ticket_valid = self._action_ticket_validator(agent, lease, request)
                except Exception as exc:
                    self._audit("action_ticket_validation_failed", {"agent_id": agent_id, "lease_id": lease.lease_id, "reason": type(exc).__name__})
                    raise AuthorizationDenied("ACTION_TICKET_UNAVAILABLE") from exc
                if ticket_valid is not True: raise AuthorizationDenied("ACTION_TICKET_REQUIRED")
            if not self._kill_switch.engaged and request.action_class not in READ_ONLY_ACTIONS and request.action_class not in MUTATING_ACTIONS:
                raise AuthorizationDenied("ACTION_TICKET_REQUIRED")
            validate_safety_evidence({"mode": "DRY_RUN", "deployment": "DISABLED", "kill_switch": "ENGAGED" if self._kill_switch.engaged else "CLEARED_FOR_DRY_RUN"}, require_kill_switch=False)
            try:
                policy_allows = self._policy(agent, lease, request)
            except Exception as exc:
                self._audit("policy_evaluation_failed", {"agent_id": agent_id, "lease_id": lease.lease_id, "reason": type(exc).__name__})
                raise AuthorizationDenied("POLICY_UNAVAILABLE") from exc
            if not isinstance(policy_allows, bool):
                raise AuthorizationDenied("POLICY_RESULT_INVALID")
            if not policy_allows: raise AuthorizationDenied("POLICY_DENIED")
        except (AuthorizationDenied, LeaseIntegrityError, ValueError) as exc:
            if isinstance(exc, AuthorizationDenied):
                reason = exc.reason
            elif isinstance(exc, LeaseIntegrityError):
                reason = "LEASE_INTEGRITY_ERROR"
            else:
                reason = type(exc).__name__.removesuffix("Error").upper() + "_ERROR"
            self._audit("authorization_denied", {"agent_id": agent_id, "capability": request.capability, "reason": reason})
            if isinstance(exc, AuthorizationDenied):
                raise
            raise AuthorizationDenied(reason) from exc
        result = {"authorized": True, "agent_id": agent_id, "lease_id": lease.lease_id, "tenant_id": request.tenant_id, "capability": request.capability, "action_class": request.action_class}
        self._audit("authorization_success", result)
        return result


class ASOCControlPlane:
    """Small coordination boundary for immediate revocation operations."""

    def __init__(self, agents: AgentRegistry, leases: LeaseRegistry, kill_switch: KillSwitch):
        self.agents, self.leases, self.kill_switch = agents, leases, kill_switch

    def revoke_agent(self, agent_id: str, reason: str = "agent revoked") -> None:
        self.agents.revoke(agent_id, reason)
        self.leases.revoke_agent_ids({agent_id}, reason)

    def revoke_role(self, role: str, reason: str = "role revoked") -> int:
        ids = self.agents.ids_matching(role=role)
        self.agents.revoke_matching(role=role, reason=reason)
        return self.leases.revoke_agent_ids(ids, reason)

    def revoke_model_deployment(self, model_deployment: str, reason: str = "model deployment revoked") -> int:
        ids = self.agents.ids_matching(model_deployment=model_deployment)
        self.agents.revoke_matching(model_deployment=model_deployment, reason=reason)
        return self.leases.revoke_agent_ids(ids, reason)

    def revoke_tenant(self, tenant_id: str, reason: str = "tenant revoked") -> int:
        ids = self.agents.ids_matching(tenant_id=tenant_id)
        self.agents.revoke_matching(tenant_id=tenant_id, reason=reason)
        return self.leases.revoke_agent_ids(ids, reason)

    def engage_ai_kill_switch(self, reason: str = "AI kill switch") -> int:
        self.kill_switch.engage()
        self.agents.revoke_matching(all_agents=True, reason=reason)
        return self.leases.revoke_agent_ids(set(self.agents._agents), reason)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"
