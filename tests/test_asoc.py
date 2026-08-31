import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from swarm.action_ticket import ActionTicket, ActionTicketError, ActionTicketRegistry
from swarm.mcp_gateway import MCPGateway, MCPToolGrant
from swarm.model_broker import ApprovedModel, ModelBroker
from swarm.policy_gate import DeterministicPolicy, PolicyRule
from swarm.asoc import (
    ASOCControlPlane,
    AggregateBlastRadiusLedger,
    AgentIdentity,
    AgentRegistry,
    AuthorizationDenied,
    AuthorizationRequest,
    CapabilityAuthorizer,
    CapabilityLease,
    HMACLeaseSigner,
    KillSwitch,
    LeaseIntegrityError,
    LeaseRegistry,
    ModelBinding,
    audit_log_sink,
)
from swarm.core import AuditLog, Job


def make_plane():
    events = []
    audit = lambda event, data: events.append((event, dict(data)))
    switch = KillSwitch(engaged=False)
    signer = HMACLeaseSigner({"fw-keys/asoc-test": b"test-only-key-material"})
    agents = AgentRegistry(audit)
    leases = LeaseRegistry(signer, switch, audit)
    model = ModelBinding("triage-model", "approved-provider", "triage-prod", "2026.08", "model-approval-1")
    agent = AgentIdentity(
        "agent-triage-1", "tenant-a", "soc", "SOC Triage Agent", "human-controller-1", model,
        "approved-provider/triage-prod", "bounded triage", "medium", ("INTERNAL", "CONFIDENTIAL"),
        cryptographic_identity_ref="fw-id/agent-triage-1",
    )
    agents.register(agent)
    agents.activate(agent.agent_id, now=100)
    lease = CapabilityLease(
        "lease-1", agent.agent_id, "human-controller-1", "tenant-a",
        ("telemetry.read", "evidence.read", "action.request"), ("mcp.telemetry.status",),
        ("endpoint-123",), ("INTERNAL",), ("READ", "REQUEST"), 1, False, 0, 100, 200,
        "FW-ASOC-01-v1", "approval-1", "ticket-1", "bounded triage", "fw-keys/asoc-test",
    )
    lease = leases.issue(lease)
    authorizer = CapabilityAuthorizer(
        agents, leases, switch, audit,
        policy=lambda _agent, _lease, _request: True,
        action_ticket_validator=lambda _agent, _lease, request: request.action_ticket_valid,
        mcp_tool_validator=lambda _agent, _lease, request: request.tool == "mcp.telemetry.status",
        model_binding_validator=lambda _agent, _lease, request: request.model_identity is not None and request.model_identity.approved,
    )
    return events, switch, agents, leases, authorizer, model, agent, lease


def request(**overrides):
    value = dict(capability="telemetry.read", tenant_id="tenant-a", resource="endpoint-123", data_classification="INTERNAL")
    value.update(overrides)
    return AuthorizationRequest(**value)


def test_active_lease_authorizes_and_audits():
    events, _, _, _, auth, model, agent, lease = make_plane()
    result = auth.authorize(agent.agent_id, request(model_identity=model), now=150)
    assert result["authorized"] is True
    assert result["lease_id"] == lease.lease_id
    assert events[-1][0] == "authorization_success"
    assert events[-1][1]["resource"] == "endpoint-123"
    assert events[-1][1]["data_classification"] == "INTERNAL"


def test_delegated_lease_is_bounded_by_the_parent_lease():
    events, switch, _, leases, _, _, agent, parent = make_plane()
    switch.clear_for_dry_run()
    delegable = leases.issue(CapabilityLease(
        "lease-parent-delegable", agent.agent_id, parent.issuer_identity, parent.tenant_id,
        parent.granted_capabilities, parent.allowed_tools, parent.allowed_resources,
        parent.allowed_data_classifications, parent.allowed_action_classes, 1, True, 1, 100, 200,
        parent.policy_version, "approval-parent", "ticket-parent", "bounded parent", parent.key_reference,
    ))
    child = CapabilityLease(
        "lease-child", "agent-child", agent.agent_id, parent.tenant_id,
        ("telemetry.read",), parent.allowed_tools, parent.allowed_resources, parent.allowed_data_classifications,
        ("READ",), 1, False, 0, 110, 190, parent.policy_version, "approval-child", "ticket-child", "bounded child", parent.key_reference,
    )
    assert leases.issue_delegated(delegable.lease_id, child, now=150).lease_id == child.lease_id
    assert events[-1] == ("delegated_lease_issued", {"parent_lease_id": delegable.lease_id, "lease_id": child.lease_id, "agent_id": child.subject_agent_id, "tenant_id": child.tenant_id})
    escalated = replace(child, lease_id="lease-child-escalated", max_blast_radius=2)
    with pytest.raises(AuthorizationDenied, match="DELEGATION_BLAST_RADIUS_EXCEEDED"):
        leases.issue_delegated(delegable.lease_id, escalated, now=150)


def test_delegation_denies_non_delegable_parent_and_tenant_mismatch():
    _, switch, _, leases, _, _, agent, parent = make_plane()
    switch.clear_for_dry_run()
    child = CapabilityLease(
        "lease-child-denied", "agent-child", agent.agent_id, "tenant-b", parent.granted_capabilities,
        parent.allowed_tools, parent.allowed_resources, parent.allowed_data_classifications,
        parent.allowed_action_classes, parent.max_blast_radius, False, 0, 110, 190,
        parent.policy_version, "approval-child", "ticket-child", "bounded child", parent.key_reference,
    )
    with pytest.raises(AuthorizationDenied, match="DELEGATION_NOT_ALLOWED"):
        leases.issue_delegated(parent.lease_id, child, now=150)
    delegable = leases.issue(replace(parent, lease_id="lease-parent-tenant", delegation_allowed=True, delegation_depth=1))
    with pytest.raises(AuthorizationDenied, match="DELEGATION_TENANT_OR_ISSUER_MISMATCH"):
        leases.issue_delegated(delegable.lease_id, child, now=150)


@pytest.mark.parametrize("change, reason", [
    ({"expires_at": 201}, "DELEGATION_LIFETIME_OR_DEPTH_EXCEEDED"),
    ({"delegation_allowed": True, "delegation_depth": 1}, "DELEGATION_LIFETIME_OR_DEPTH_EXCEEDED"),
    ({"granted_capabilities": ("telemetry.read", "endpoint.inspect")}, "DELEGATION_PRIVILEGE_ESCALATION"),
    ({"max_concurrent_work": 2}, "DELEGATION_WORK_BUDGET_EXCEEDED"),
])
def test_delegation_denies_lifetime_depth_and_scope_escalation(change, reason):
    _, switch, _, leases, _, _, agent, parent = make_plane()
    switch.clear_for_dry_run()
    delegable = leases.issue(replace(parent, lease_id="lease-parent-negative", delegation_allowed=True, delegation_depth=1))
    child = CapabilityLease(
        "lease-child-negative", "agent-child", agent.agent_id, parent.tenant_id,
        ("telemetry.read",), parent.allowed_tools, parent.allowed_resources,
        parent.allowed_data_classifications, ("READ",), 1, False, 0, 110, 190,
        parent.policy_version, "approval-child", "ticket-child", "bounded child", parent.key_reference,
    )
    with pytest.raises(AuthorizationDenied, match=reason):
        leases.issue_delegated(delegable.lease_id, replace(child, **change), now=150)


def test_delegation_denies_revoked_and_expired_parent_leases():
    _, switch, _, leases, _, _, agent, parent = make_plane()
    switch.clear_for_dry_run()
    delegable = leases.issue(replace(parent, lease_id="lease-parent-inactive", delegation_allowed=True, delegation_depth=1))
    child = CapabilityLease("lease-child-inactive", "agent-child", agent.agent_id, parent.tenant_id, ("telemetry.read",), parent.allowed_tools, parent.allowed_resources, parent.allowed_data_classifications, ("READ",), 1, False, 0, 110, 190, parent.policy_version, "approval-child", "ticket-child", "bounded child", parent.key_reference)
    leases.revoke(delegable.lease_id, "parent recovery", now=120)
    with pytest.raises(AuthorizationDenied, match="PARENT_LEASE_INACTIVE"):
        leases.issue_delegated(delegable.lease_id, child, now=150)
    expired = leases.issue(replace(parent, lease_id="lease-parent-expired", delegation_allowed=True, delegation_depth=1, expires_at=140))
    with pytest.raises(AuthorizationDenied, match="PARENT_LEASE_INACTIVE"):
        leases.issue_delegated(expired.lease_id, child, now=150)


@pytest.mark.parametrize("change", [
    {"allowed_tools": ("mcp.arbitrary",)},
    {"allowed_resources": ("endpoint-999",)},
    {"allowed_data_classifications": ("RESTRICTED",)},
    {"allowed_action_classes": ("ISOLATE_ENDPOINT",)},
])
def test_delegation_denies_tool_resource_data_and_action_expansion(change):
    _, switch, _, leases, _, _, agent, parent = make_plane()
    switch.clear_for_dry_run()
    delegable = leases.issue(replace(parent, lease_id="lease-parent-scope", delegation_allowed=True, delegation_depth=1))
    child = CapabilityLease("lease-child-scope", "agent-child", agent.agent_id, parent.tenant_id, ("telemetry.read",), parent.allowed_tools, parent.allowed_resources, parent.allowed_data_classifications, ("READ",), 1, False, 0, 110, 190, parent.policy_version, "approval-child", "ticket-child", "bounded child", parent.key_reference)
    with pytest.raises(AuthorizationDenied, match="DELEGATION_PRIVILEGE_ESCALATION"):
        leases.issue_delegated(delegable.lease_id, replace(child, **change), now=150)


def test_parent_recovery_revokes_delegated_child_leases():
    _, switch, agents, leases, _, _, agent, parent = make_plane()
    switch.clear_for_dry_run()
    delegable = leases.issue(replace(parent, lease_id="lease-parent-recovery", delegation_allowed=True, delegation_depth=1))
    child = CapabilityLease("lease-child-recovery", "agent-child", agent.agent_id, parent.tenant_id, ("telemetry.read",), parent.allowed_tools, parent.allowed_resources, parent.allowed_data_classifications, ("READ",), 1, False, 0, 110, 190, parent.policy_version, "approval-child", "ticket-child", "bounded child", parent.key_reference)
    leases.issue_delegated(delegable.lease_id, child, now=150)
    ASOCControlPlane(agents, leases, switch).revoke_agent(agent.agent_id)
    assert leases.get(child.lease_id).revoked_at is not None


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"action_ticket_id": " "}, "action_ticket_id"),
        ({"tool": " "}, "tool"),
        ({"blast_radius": -1}, "blast_radius"),
        ({"action_ticket_valid": "true"}, "action_ticket_valid"),
    ],
)
def test_authorization_request_rejects_malformed_boundary_input(overrides, reason):
    with pytest.raises(ValueError, match=reason):
        request(**overrides)


def test_expired_agent_is_denied_even_when_its_lease_is_still_valid():
    events, switch, agents, leases, _, model, agent, _ = make_plane()
    expired = AgentIdentity(
        agent.agent_id, agent.tenant_id, agent.agent_type, agent.role, agent.owner_controller_id,
        agent.model_identity, agent.provider_deployment, agent.approved_purpose, agent.trust_level,
        agent.allowed_data_classifications, lifecycle_state="ACTIVE", created_at=100, activated_at=100,
        expires_at=149, policy_version=agent.policy_version,
        cryptographic_identity_ref=agent.cryptographic_identity_ref,
    )
    agents._agents[agent.agent_id] = expired
    authorizer = CapabilityAuthorizer(
        agents, leases, switch, lambda event, data: events.append((event, dict(data))),
        policy=lambda *_args: True,
        model_binding_validator=lambda *_args: True,
    )
    with pytest.raises(AuthorizationDenied, match="AGENT_EXPIRED"):
        authorizer.authorize(agent.agent_id, request(model_identity=model), now=150)


def test_agent_cannot_claim_a_provider_deployment_different_from_its_model():
    _, _, _, _, _, model, agent, _ = make_plane()
    with pytest.raises(ValueError, match="provider_deployment must match model identity"):
        AgentIdentity(
            "agent-model-mismatch", agent.tenant_id, agent.agent_type, agent.role, agent.owner_controller_id,
            model, "other-provider/other-deployment", agent.approved_purpose, agent.trust_level,
            agent.allowed_data_classifications, cryptographic_identity_ref="fw-id/agent-model-mismatch",
        )


def test_agent_cannot_claim_a_model_approval_version_different_from_its_model():
    _, _, _, _, _, model, agent, _ = make_plane()
    with pytest.raises(ValueError, match="model_approval_version must match model identity"):
        AgentIdentity(
            "agent-approval-mismatch", agent.tenant_id, agent.agent_type, agent.role, agent.owner_controller_id,
            model, agent.provider_deployment, agent.approved_purpose, agent.trust_level,
            agent.allowed_data_classifications, model_approval_version="different-approval",
            cryptographic_identity_ref="fw-id/agent-approval-mismatch",
        )


def test_agent_without_a_model_binding_can_use_a_valid_read_only_lease():
    _, switch, agents, leases, _, _, agent, _ = make_plane()
    unbound = AgentIdentity(
        agent.agent_id, agent.tenant_id, agent.agent_type, agent.role, agent.owner_controller_id,
        None, "human-operated", agent.approved_purpose, agent.trust_level,
        agent.allowed_data_classifications, lifecycle_state="ACTIVE", created_at=100, activated_at=100,
        cryptographic_identity_ref=agent.cryptographic_identity_ref,
    )
    agents._agents[agent.agent_id] = unbound
    authorizer = CapabilityAuthorizer(agents, leases, switch, policy=lambda *_args: True)
    assert authorizer.authorize(agent.agent_id, request(model_identity=None), now=150)["authorized"] is True


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"tenant_id": "tenant-b"}, "TENANT_MISMATCH"),
        ({"capability": "endpoint.inspect"}, "CAPABILITY_NOT_GRANTED"),
        ({"resource": "endpoint-999"}, "RESOURCE_OUT_OF_SCOPE"),
        ({"data_classification": "RESTRICTED"}, "DATA_CLASSIFICATION_DENIED"),
        ({"action_class": "ISOLATE_ENDPOINT"}, "ACTION_CLASS_DENIED"),
        ({"action_class": "UNKNOWN_ACTION"}, "ACTION_CLASS_DENIED"),
        ({"tool": "mcp.arbitrary"}, "MCP_TOOL_NOT_ALLOWED"),
        ({"blast_radius": 2}, "BLAST_RADIUS_EXCEEDED"),
        ({"policy_version": "old-policy"}, "STALE_POLICY_VERSION"),
    ],
)
def test_scope_and_policy_denials_are_explicit(overrides, reason):
    events, _, _, _, auth, model, agent, _ = make_plane()
    overrides = {**overrides, "model_identity": model}
    with pytest.raises(AuthorizationDenied, match=reason):
        auth.authorize(agent.agent_id, request(**overrides), now=150)
    assert events[-1][0] == "authorization_denied"
    denial = events[-1][1]
    assert denial["reason"] == reason
    assert denial["tenant_id"] == overrides.get("tenant_id", "tenant-a")
    assert denial["resource"] == overrides.get("resource", "endpoint-123")
    assert denial["timestamp"] == 150


def test_asoc_golden_path_rejects_cross_tenant_request():
    events, _, _, _, auth, model, agent, _ = make_plane()
    with pytest.raises(AuthorizationDenied, match="TENANT_MISMATCH"):
        auth.authorize(agent.agent_id, request(tenant_id="tenant-b", model_identity=model), now=150)
    assert events[-1][0] == "authorization_denied"
    assert events[-1][1]["reason"] == "TENANT_MISMATCH"
    assert events[-1][1]["tenant_id"] == "tenant-b"


def test_missing_expired_and_revoked_leases_fail_closed():
    _, switch, agents, leases, auth, model, agent, lease = make_plane()
    with pytest.raises(AuthorizationDenied, match="AGENT_NOT_FOUND"):
        auth.authorize(agent.agent_id + "-missing", request(model_identity=model), now=150)
    with pytest.raises(AuthorizationDenied, match="AGENT_NOT_FOUND"):
        auth.authorize("agent-without-lease", request(model_identity=model), now=150)
    expired = CapabilityLease(
        "lease-expired", agent.agent_id, "human-controller-1", "tenant-a", lease.granted_capabilities,
        lease.allowed_tools, lease.allowed_resources, lease.allowed_data_classifications, lease.allowed_action_classes,
        1, False, 0, 100, 101, lease.policy_version, "approval-2", "ticket-2", "expired", lease.key_reference,
    )
    leases.issue(expired)
    with pytest.raises(AuthorizationDenied, match="LEASE_EXPIRED"):
        auth.authorize(agent.agent_id, request(model_identity=model), now=202)
    leases.revoke(lease.lease_id, "incident response", now=151)
    with pytest.raises(AuthorizationDenied, match="LEASE_REVOKED"):
        auth.authorize(agent.agent_id, request(model_identity=model), now=151)
    assert switch.engaged is False


def test_lease_rejects_unknown_action_classes():
    _, _, _, _, _, _, _, lease = make_plane()
    with pytest.raises(ValueError, match="unsupported action class"):
        CapabilityLease(
            "lease-unknown-action", lease.subject_agent_id, lease.issuer_identity, lease.tenant_id,
            lease.granted_capabilities, lease.allowed_tools, lease.allowed_resources,
            lease.allowed_data_classifications, ("UNKNOWN_ACTION",), lease.max_blast_radius,
            False, 0, lease.valid_from, lease.expires_at, lease.policy_version,
            "approval-unknown-action", "ticket-unknown-action", "regression coverage", lease.key_reference,
        )


def test_non_delegable_lease_rejects_positive_delegation_depth():
    _, _, _, _, _, _, _, lease = make_plane()
    with pytest.raises(ValueError, match="non-delegable leases must have zero delegation depth"):
        CapabilityLease(
            "lease-invalid-delegation", lease.subject_agent_id, lease.issuer_identity, lease.tenant_id,
            lease.granted_capabilities, lease.allowed_tools, lease.allowed_resources,
            lease.allowed_data_classifications, lease.allowed_action_classes, lease.max_blast_radius,
            False, 1, lease.valid_from, lease.expires_at, lease.policy_version,
            "approval-invalid-delegation", "ticket-invalid-delegation", "regression coverage", lease.key_reference,
        )


def test_inactive_and_revoked_agents_fail_closed():
    _, _, agents, _, auth, _, agent, _ = make_plane()
    agents.revoke(agent.agent_id, "controller revoked", now=151)
    with pytest.raises(AuthorizationDenied, match="AGENT_NOT_ACTIVE"):
        auth.authorize(agent.agent_id, request(), now=151)


def test_model_deployment_binding_is_exact():
    _, _, _, _, auth, model, agent, _ = make_plane()
    wrong = ModelBinding(model.model, model.provider, "other-deployment", model.version, model.approval_version)
    with pytest.raises(AuthorizationDenied, match="MODEL_BINDING_MISMATCH"):
        auth.authorize(agent.agent_id, request(model_identity=wrong), now=150)


def test_kill_switch_blocks_new_leases_and_mutation_but_keeps_read_path():
    _, switch, agents, leases, auth, model, agent, lease = make_plane()
    human = AgentIdentity(
        "human-admin-1", "tenant-a", "human", "Security Advisor", "human-controller-1",
        None, "human-operated", "deterministic administration", "high", ("INTERNAL",),
        cryptographic_identity_ref="fw-id/human-admin-1",
    )
    agents.register(human)
    agents.activate(human.agent_id, now=100)
    human_lease = leases.issue(CapabilityLease(
        "lease-human-admin-1", human.agent_id, "human-controller-1", "tenant-a",
        ("telemetry.read",), ("mcp.telemetry.status",), ("endpoint-123",), ("INTERNAL",),
        ("READ",), 0, False, 0, 100, 200, "FW-ASOC-01-v1", "approval-human-1",
        "ticket-human-1", "deterministic administration", lease.key_reference,
    ))
    switch.engage()
    with pytest.raises(AuthorizationDenied, match="KILL_SWITCH_ENGAGED"):
        leases.issue(CapabilityLease(
            "lease-new", agent.agent_id, "human-controller-1", "tenant-a", lease.granted_capabilities,
            lease.allowed_tools, lease.allowed_resources, lease.allowed_data_classifications, lease.allowed_action_classes,
            1, False, 0, 150, 250, lease.policy_version, "approval-3", "ticket-3", "new", lease.key_reference,
        ))
    assert auth.authorize(agent.agent_id, request(model_identity=model), now=150)["authorized"]
    with pytest.raises(AuthorizationDenied, match="ACTION_CLASS_DENIED"):
        auth.authorize(agent.agent_id, request(action_class="UNKNOWN_ACTION", model_identity=model), now=150)
    with pytest.raises(AuthorizationDenied, match="ACTION_CLASS_DENIED"):
        auth.authorize(agent.agent_id, request(capability="action.request", action_class="ISOLATE_ENDPOINT", action_ticket_valid=True, model_identity=model), now=150)
    control = ASOCControlPlane(agents, leases, switch)
    assert control.engage_ai_kill_switch() == 1
    assert agents.get(agent.agent_id).lifecycle_state == "REVOKED"
    assert leases.for_agent(agent.agent_id).revoked_at is not None
    assert agents.get(human.agent_id).lifecycle_state == "ACTIVE"
    assert leases.get(human_lease.lease_id).revoked_at is None


def test_role_and_model_deployment_revocation_revoke_bound_leases():
    _, switch, agents, leases, _, model, agent, _ = make_plane()
    control = ASOCControlPlane(agents, leases, switch)
    assert control.revoke_role(agent.role) == 1
    assert agents.get(agent.agent_id).lifecycle_state == "REVOKED"
    assert leases.for_agent(agent.agent_id).revoked_at is not None

    _, switch, agents, leases, _, model, agent, _ = make_plane()
    control = ASOCControlPlane(agents, leases, switch)
    assert control.revoke_model_deployment(f"{model.provider}/{model.deployment}") == 1
    assert agents.get(agent.agent_id).lifecycle_state == "REVOKED"
    assert leases.for_agent(agent.agent_id).revoked_at is not None


def test_tenant_revocation_does_not_cross_tenant_boundaries():
    events, switch, agents, leases, _, model, agent, lease = make_plane()
    other = AgentIdentity(
        "agent-tenant-b", "tenant-b", "soc", "SOC Triage Agent", "human-controller-2", model,
        agent.provider_deployment, "bounded triage", "medium", ("INTERNAL",),
        cryptographic_identity_ref="fw-id/agent-tenant-b",
    )
    agents.register(other)
    agents.activate(other.agent_id, now=100)
    other_lease = leases.issue(CapabilityLease(
        "lease-tenant-b", other.agent_id, "human-controller-2", "tenant-b",
        ("telemetry.read",), ("mcp.telemetry.status",), ("endpoint-456",), ("INTERNAL",),
        ("READ",), 0, False, 0, 100, 200, lease.policy_version, "approval-tenant-b",
        "ticket-tenant-b", "bounded triage", lease.key_reference,
    ))
    control = ASOCControlPlane(agents, leases, switch)

    assert control.revoke_tenant("tenant-a") == 1
    assert agents.get(agent.agent_id).lifecycle_state == "REVOKED"
    assert leases.for_agent(agent.agent_id).revoked_at is not None
    assert agents.get(other.agent_id).lifecycle_state == "ACTIVE"
    assert leases.get(other_lease.lease_id).revoked_at is None


def test_tenant_recovery_revokes_pending_action_tickets():
    _, switch, agents, leases, _, _, agent, lease = make_plane()
    tickets = ActionTicketRegistry(HMACLeaseSigner({lease.key_reference: b"test-only-key-material"}))
    broker = ModelBroker()
    model = agent.model_identity
    assert model is not None
    broker.register(ApprovedModel(
        agent.tenant_id, agent.agent_id, model.model, model.provider, model.deployment,
        model.version, model.approval_version,
    ))
    gateway = MCPGateway()
    gateway.register(MCPToolGrant(
        agent.tenant_id, agent.agent_id, "telemetry.read", "endpoint-123",
        "mcp.telemetry.status", lease.policy_version,
    ))
    tickets.issue(ActionTicket(
        "ticket-recovery", agent.tenant_id, agent.agent_id, lease.lease_id,
        "endpoint.isolate.request", "endpoint-123", "ISOLATE_ENDPOINT", "human-controller-1",
        "approval-recovery", lease.policy_version, 101, 200, lease.key_reference,
    ))
    control = ASOCControlPlane(agents, leases, switch, tickets, broker, gateway)
    assert control.revoke_tenant(agent.tenant_id) == 1
    with pytest.raises(ActionTicketError, match="revoked"):
        tickets.validate_and_consume(
            "ticket-recovery", tenant_id=agent.tenant_id, subject_agent_id=agent.agent_id,
            lease_id=lease.lease_id, capability="endpoint.isolate.request", resource="endpoint-123",
            action_class="ISOLATE_ENDPOINT", policy_version=lease.policy_version, now=150,
        )
    assert not broker.allows(
        tenant_id=agent.tenant_id, subject_agent_id=agent.agent_id, model=model.model,
        provider=model.provider, deployment=model.deployment, version=model.version,
        approval_version=model.approval_version,
    )
    assert not gateway.allows(
        tenant_id=agent.tenant_id, subject_agent_id=agent.agent_id, capability="telemetry.read",
        resource="endpoint-123", tool="mcp.telemetry.status", policy_version=lease.policy_version,
    )


def test_mutating_capability_requires_ticket_and_is_disabled_by_kill_switch():
    _, switch, agents, leases, auth, model, agent, lease = make_plane()
    mutation = lease.__class__(
        "lease-mutation", agent.agent_id, lease.issuer_identity, lease.tenant_id,
        ("endpoint.isolate.request",), lease.allowed_tools, lease.allowed_resources,
        lease.allowed_data_classifications, ("ISOLATE_ENDPOINT",), 1, False, 0, 101, 200,
        lease.policy_version, "approval-mutation", "ticket-mutation", "bounded containment", lease.key_reference,
    )
    mutation = leases.issue(mutation)
    del leases._leases[lease.lease_id]
    with pytest.raises(AuthorizationDenied, match="KILL_SWITCH_MUTATION_BLOCKED"):
        switch.engage()
        auth.authorize(agent.agent_id, request(
            capability="endpoint.isolate.request", action_class="ISOLATE_ENDPOINT",
            action_ticket_valid=True, model_identity=model,
        ), now=150)
    switch.clear_for_dry_run()
    with pytest.raises(AuthorizationDenied, match="ACTION_TICKET_REQUIRED"):
        auth.authorize(agent.agent_id, request(
            capability="endpoint.isolate.request", action_class="ISOLATE_ENDPOINT",
            model_identity=model,
        ), now=150)


def test_lease_signature_tampering_is_rejected():
    _, _, _, leases, auth, _, agent, lease = make_plane()
    tampered = lease.__class__(**{**lease.__dict__, "expires_at": 199})
    leases._leases[lease.lease_id] = tampered
    with pytest.raises(AuthorizationDenied, match="LEASE_INTEGRITY_ERROR"):
        auth.authorize(agent.agent_id, request(), now=150)


def test_forbidden_wildcard_and_unknown_capabilities_are_rejected():
    with pytest.raises(ValueError, match="wildcard"):
        CapabilityLease("l", "a", "i", "t", ("telemetry.*",), ("tool",), ("resource",), ("INTERNAL",), ("READ",), 1, False, 0, 1, 2, "p", "a", "t", "r", "k")
    with pytest.raises(ValueError, match="narrowly defined"):
        CapabilityLease("l", "a", "i", "t", ("admin",), ("tool",), ("resource",), ("INTERNAL",), ("READ",), 1, False, 0, 1, 2, "p", "a", "t", "r", "k")


def test_revocation_by_tenant_is_immediate():
    _, _, agents, leases, auth, _, agent, _ = make_plane()
    control = ASOCControlPlane(agents, leases, KillSwitch(False))
    assert control.revoke_tenant("tenant-a") == 1
    with pytest.raises(AuthorizationDenied):
        auth.authorize(agent.agent_id, request(), now=150)


def test_policy_failure_and_invalid_result_fail_closed():
    events, _, agents, leases, _, model, agent, _ = make_plane()

    def unavailable(_agent, _lease, _request):
        raise RuntimeError("policy service unavailable")

    auth = CapabilityAuthorizer(agents, leases, KillSwitch(False), lambda event, data: events.append((event, dict(data))), policy=unavailable, model_binding_validator=lambda *_args: True)
    with pytest.raises(AuthorizationDenied, match="POLICY_UNAVAILABLE"):
        auth.authorize(agent.agent_id, request(model_identity=model), now=150)
    assert events[-2][0] == "policy_evaluation_failed"
    assert events[-1][0] == "authorization_denied"

    invalid = CapabilityAuthorizer(agents, leases, KillSwitch(False), policy=lambda *_args: "allow", model_binding_validator=lambda *_args: True)
    with pytest.raises(AuthorizationDenied, match="POLICY_RESULT_INVALID"):
        invalid.authorize(agent.agent_id, request(model_identity=model), now=150)


def test_action_ticket_boolean_alone_cannot_authorize_mutation():
    _, switch, agents, leases, _, model, agent, lease = make_plane()
    switch.clear_for_dry_run()
    mutation = CapabilityLease(
        "lease-ticket-bound", agent.agent_id, lease.issuer_identity, lease.tenant_id,
        ("endpoint.isolate.request",), lease.allowed_tools, lease.allowed_resources,
        lease.allowed_data_classifications, ("ISOLATE_ENDPOINT",), 1, False, 0, 101, 200,
        lease.policy_version, "approval-ticket", "ticket-ticket", "bounded containment", lease.key_reference,
    )
    leases.issue(mutation)
    auth = CapabilityAuthorizer(agents, leases, switch, policy=lambda *_args: True, model_binding_validator=lambda *_args: True)
    with pytest.raises(AuthorizationDenied, match="ACTION_TICKET_REQUIRED"):
        auth.authorize(agent.agent_id, request(
            capability="endpoint.isolate.request", action_class="ISOLATE_ENDPOINT",
            action_ticket_valid=True, model_identity=model,
        ), now=150)


def test_signed_action_ticket_is_bound_and_single_use():
    events, switch, agents, leases, _, model, agent, lease = make_plane()
    switch.clear_for_dry_run()
    mutation = CapabilityLease(
        "lease-ticket-canonical", agent.agent_id, lease.issuer_identity, lease.tenant_id,
        ("endpoint.isolate.request",), lease.allowed_tools, lease.allowed_resources,
        lease.allowed_data_classifications, ("ISOLATE_ENDPOINT",), 1, False, 0, 101, 200,
        lease.policy_version, "approval-ticket", "ticket-canonical", "bounded containment", lease.key_reference,
    )
    mutation = leases.issue(mutation)
    del leases._leases[lease.lease_id]
    tickets = ActionTicketRegistry(HMACLeaseSigner({lease.key_reference: b"test-only-key-material"}))
    tickets.issue(ActionTicket(
        "ticket-canonical", agent.tenant_id, agent.agent_id, mutation.lease_id,
        "endpoint.isolate.request", "endpoint-123", "ISOLATE_ENDPOINT", "human-controller-1",
        "approval-ticket", mutation.policy_version, 101, 200, mutation.key_reference,
    ))
    auth = CapabilityAuthorizer(
        agents, leases, switch, lambda event, data: events.append((event, dict(data))), policy=lambda *_args: True,
        model_binding_validator=lambda *_args: True, action_tickets=tickets,
    )
    mutation_request = request(
        capability="endpoint.isolate.request", action_class="ISOLATE_ENDPOINT",
        action_ticket_id="ticket-canonical", model_identity=model,
    )
    assert auth.authorize(agent.agent_id, mutation_request, now=150)["authorized"] is True
    with pytest.raises(AuthorizationDenied, match="ACTION_TICKET_INVALID"):
        auth.authorize(agent.agent_id, mutation_request, now=151)
    assert events[-1][1]["action_ticket_id"] == "ticket-canonical"


def test_policy_denial_does_not_consume_a_canonical_action_ticket():
    _, switch, agents, leases, _, model, agent, lease = make_plane()
    switch.clear_for_dry_run()
    mutation = CapabilityLease(
        "lease-ticket-policy-denied", agent.agent_id, lease.issuer_identity, lease.tenant_id,
        ("endpoint.isolate.request",), lease.allowed_tools, lease.allowed_resources,
        lease.allowed_data_classifications, ("ISOLATE_ENDPOINT",), 1, False, 0, 101, 200,
        lease.policy_version, "approval-ticket", "ticket-policy-denied", "bounded containment", lease.key_reference,
    )
    mutation = leases.issue(mutation)
    del leases._leases[lease.lease_id]
    tickets = ActionTicketRegistry(HMACLeaseSigner({lease.key_reference: b"test-only-key-material"}))
    tickets.issue(ActionTicket(
        "ticket-policy-denied", agent.tenant_id, agent.agent_id, mutation.lease_id,
        "endpoint.isolate.request", "endpoint-123", "ISOLATE_ENDPOINT", "human-controller-1",
        "approval-ticket", mutation.policy_version, 101, 200, mutation.key_reference,
    ))
    auth = CapabilityAuthorizer(
        agents, leases, switch, policy=lambda *_args: False,
        model_binding_validator=lambda *_args: True, action_tickets=tickets,
    )
    mutation_request = request(
        capability="endpoint.isolate.request", action_class="ISOLATE_ENDPOINT",
        action_ticket_id="ticket-policy-denied", model_identity=model,
    )
    with pytest.raises(AuthorizationDenied, match="POLICY_DENIED"):
        auth.authorize(agent.agent_id, mutation_request, now=150)
    assert tickets.validate_and_consume(
        "ticket-policy-denied", tenant_id=agent.tenant_id, subject_agent_id=agent.agent_id,
        lease_id=mutation.lease_id, capability="endpoint.isolate.request", resource="endpoint-123",
        action_class="ISOLATE_ENDPOINT", policy_version=mutation.policy_version, now=150,
    ).consumed_at == 150


def test_canonical_deterministic_policy_is_exact_and_fail_closed():
    _, _, agents, leases, _, model, agent, _ = make_plane()
    policy = DeterministicPolicy([PolicyRule(
        "tenant-a", "telemetry.read", "endpoint-123", "READ", "FW-ASOC-01-v1",
    )])
    auth = CapabilityAuthorizer(
        agents, leases, KillSwitch(False), policy_engine=policy,
        model_binding_validator=lambda *_args: True,
    )
    assert auth.authorize(agent.agent_id, request(model_identity=model), now=150)["authorized"] is True
    with pytest.raises(AuthorizationDenied, match="POLICY_DENIED"):
        auth.authorize(agent.agent_id, request(action_class="REQUEST", model_identity=model), now=150)


def test_authorizer_reuses_canonical_safety_invariant_provider_and_fails_closed():
    events, switch, agents, leases, _, model, agent, _ = make_plane()
    invalid = CapabilityAuthorizer(
        agents, leases, switch, lambda event, data: events.append((event, dict(data))),
        policy=lambda *_args: True,
        model_binding_validator=lambda *_args: True,
        safety_evidence_provider=lambda: {"mode": "LIVE", "deployment": "DISABLED", "kill_switch": "ENGAGED"},
    )
    with pytest.raises(AuthorizationDenied, match="SAFETY_INVARIANT_INVALID"):
        invalid.authorize(agent.agent_id, request(model_identity=model), now=150)


def test_asoc_events_can_use_canonical_durable_audit_log(tmp_path: Path):
    audit_path = tmp_path / "audit.jsonl"
    job = Job("asoc-audit-1", "asoc", tmp_path, "bounded ASOC authorization")
    sink = audit_log_sink(AuditLog(audit_path), job)
    events, switch, agents, leases, _, model, agent, _ = make_plane()
    authorizer = CapabilityAuthorizer(
        agents, leases, switch, sink,
        policy=lambda *_args: True,
        model_binding_validator=lambda *_args: True,
    )
    authorizer.authorize(agent.agent_id, request(model_identity=model), now=150)
    record = json.loads(audit_path.read_text(encoding="utf-8"))
    assert record["job_id"] == job.job_id
    assert record["event"] == "authorization_success"
    assert record["lease_id"] == "lease-1"


def test_authorization_fails_closed_when_required_evidence_write_fails():
    _, switch, agents, leases, _, model, agent, _ = make_plane()
    authorizer = CapabilityAuthorizer(
        agents, leases, switch, lambda *_args: (_ for _ in ()).throw(OSError("audit unavailable")),
        policy=lambda *_args: True,
        model_binding_validator=lambda *_args: True,
    )
    with pytest.raises(AuthorizationDenied, match="EVIDENCE_WRITE_FAILED"):
        authorizer.authorize(agent.agent_id, request(model_identity=model), now=150)


def test_intermediate_audit_failure_cannot_mask_a_policy_denial():
    _, switch, agents, leases, _, model, agent, _ = make_plane()
    authorizer = CapabilityAuthorizer(
        agents, leases, switch, lambda *_args: (_ for _ in ()).throw(OSError("audit unavailable")),
        policy=lambda *_args: (_ for _ in ()).throw(RuntimeError("policy unavailable")),
        model_binding_validator=lambda *_args: True,
    )
    with pytest.raises(AuthorizationDenied, match="POLICY_UNAVAILABLE"):
        authorizer.authorize(agent.agent_id, request(model_identity=model), now=150)


def test_mcp_tool_requires_gateway_validation():
    _, _, agents, leases, _, model, agent, _ = make_plane()
    auth = CapabilityAuthorizer(agents, leases, KillSwitch(False), policy=lambda *_args: True, model_binding_validator=lambda *_args: True)
    with pytest.raises(AuthorizationDenied, match="MCP_GATEWAY_DENIED"):
        auth.authorize(agent.agent_id, request(tool="mcp.telemetry.status", model_identity=model), now=150)


def test_canonical_mcp_gateway_requires_exact_tenant_agent_tool_grant():
    _, _, agents, leases, _, model, agent, _ = make_plane()
    gateway = MCPGateway()
    gateway.register(MCPToolGrant(
        agent.tenant_id, agent.agent_id, "telemetry.read", "endpoint-123",
        "mcp.telemetry.status", "FW-ASOC-01-v1",
    ))
    auth = CapabilityAuthorizer(
        agents, leases, KillSwitch(False), policy=lambda *_args: True,
        model_binding_validator=lambda *_args: True, mcp_gateway=gateway,
    )
    assert auth.authorize(
        agent.agent_id, request(tool="mcp.telemetry.status", model_identity=model), now=150,
    )["authorized"] is True

    denied = CapabilityAuthorizer(
        agents, leases, KillSwitch(False), policy=lambda *_args: True,
        model_binding_validator=lambda *_args: True, mcp_gateway=MCPGateway(),
    )
    with pytest.raises(AuthorizationDenied, match="MCP_GATEWAY_DENIED"):
        denied.authorize(agent.agent_id, request(tool="mcp.telemetry.status", model_identity=model), now=150)


def test_model_binding_requires_broker_validation():
    _, _, agents, leases, _, model, agent, _ = make_plane()
    auth = CapabilityAuthorizer(agents, leases, KillSwitch(False), policy=lambda *_args: True)
    with pytest.raises(AuthorizationDenied, match="MODEL_BROKER_DENIED"):
        auth.authorize(agent.agent_id, request(model_identity=model), now=150)


def test_canonical_model_broker_uses_exact_tenant_agent_model_approval():
    _, _, agents, leases, _, model, agent, _ = make_plane()
    broker = ModelBroker()
    broker.register(ApprovedModel(
        agent.tenant_id, agent.agent_id, model.model, model.provider, model.deployment,
        model.version, model.approval_version,
    ))
    auth = CapabilityAuthorizer(
        agents, leases, KillSwitch(False), policy=lambda *_args: True, model_broker=broker,
    )
    assert auth.authorize(agent.agent_id, request(model_identity=model), now=150)["authorized"] is True

    denied = CapabilityAuthorizer(
        agents, leases, KillSwitch(False), policy=lambda *_args: True, model_broker=ModelBroker(),
    )
    with pytest.raises(AuthorizationDenied, match="MODEL_BROKER_DENIED"):
        denied.authorize(agent.agent_id, request(model_identity=model), now=150)


def test_asoc_canonical_golden_path_uses_policy_broker_gateway_ticket_and_evidence():
    events, switch, agents, leases, _, model, agent, lease = make_plane()
    switch.clear_for_dry_run()
    policy = DeterministicPolicy([
        PolicyRule("tenant-a", "telemetry.read", "endpoint-123", "READ", "FW-ASOC-01-v1"),
        PolicyRule("tenant-a", "endpoint.isolate.request", "endpoint-123", "ISOLATE_ENDPOINT", "FW-ASOC-01-v1"),
    ])
    broker = ModelBroker()
    broker.register(ApprovedModel(
        agent.tenant_id, agent.agent_id, model.model, model.provider, model.deployment,
        model.version, model.approval_version,
    ))
    gateway = MCPGateway()
    gateway.register(MCPToolGrant(
        agent.tenant_id, agent.agent_id, "telemetry.read", "endpoint-123",
        "mcp.telemetry.status", lease.policy_version,
    ))
    tickets = ActionTicketRegistry(HMACLeaseSigner({lease.key_reference: b"test-only-key-material"}))
    auth = CapabilityAuthorizer(
        agents, leases, switch, lambda event, data: events.append((event, dict(data))),
        policy_engine=policy, model_broker=broker, mcp_gateway=gateway, action_tickets=tickets,
    )
    assert auth.authorize(
        agent.agent_id, request(tool="mcp.telemetry.status", model_identity=model), now=150,
    )["authorized"] is True

    mutation = leases.issue(CapabilityLease(
        "lease-canonical-golden", agent.agent_id, lease.issuer_identity, lease.tenant_id,
        ("endpoint.isolate.request",), lease.allowed_tools, lease.allowed_resources,
        lease.allowed_data_classifications, ("ISOLATE_ENDPOINT",), 1, False, 0, 151, 200,
        lease.policy_version, "approval-canonical-golden", "ticket-canonical-golden",
        "bounded containment", lease.key_reference,
    ))
    del leases._leases[lease.lease_id]
    tickets.issue(ActionTicket(
        "ticket-canonical-golden", agent.tenant_id, agent.agent_id, mutation.lease_id,
        "endpoint.isolate.request", "endpoint-123", "ISOLATE_ENDPOINT", "human-controller-1",
        "approval-canonical-golden", mutation.policy_version, 151, 200, mutation.key_reference,
    ))
    mutation_request = request(
        capability="endpoint.isolate.request", action_class="ISOLATE_ENDPOINT",
        action_ticket_id="ticket-canonical-golden", model_identity=model,
    )
    assert auth.authorize(agent.agent_id, mutation_request, now=160)["authorized"] is True
    assert [event for event, _data in events if event == "authorization_success"] == [
        "authorization_success", "authorization_success",
    ]
    assert events[-1][1]["action_ticket_id"] == "ticket-canonical-golden"
    assert events[-1][1]["policy_decision_reason"] == "RULE_MATCH"
    assert events[-1][1]["model_binding"]["approval_version"] == "model-approval-1"
    assert events[-1][1]["approved_purpose"] == "bounded triage"
    with pytest.raises(AuthorizationDenied, match="ACTION_TICKET_INVALID"):
        auth.authorize(agent.agent_id, mutation_request, now=161)
    assert events[-1][0] == "authorization_denied"
    assert events[-1][1]["reason"] == "ACTION_TICKET_INVALID"
    assert events[-1][1]["action_ticket_id"] == "ticket-canonical-golden"


def test_policy_owned_aggregate_blast_radius_blocks_splitting_and_releases_after_expiry():
    events, switch, agents, leases, _, model, agent, lease = make_plane()
    policy = DeterministicPolicy([PolicyRule(
        "tenant-a", "telemetry.read", "endpoint-123", "READ", "FW-ASOC-01-v1", 1,
    )])
    auth = CapabilityAuthorizer(
        agents, leases, switch, lambda event, data: events.append((event, dict(data))),
        policy_engine=policy, model_binding_validator=lambda *_args: True,
    )
    first = request(blast_radius=1, model_identity=model)
    result = auth.authorize(agent.agent_id, first, now=150)
    assert result["authorized"] is True
    assert result["aggregate_blast_radius_limit"] == 1
    assert result["aggregate_blast_radius_remaining"] == 0
    with pytest.raises(AuthorizationDenied, match="AGGREGATE_BLAST_RADIUS_EXCEEDED"):
        auth.authorize(agent.agent_id, first, now=151)
    assert events[-1][1]["blast_radius"] == 1
    assert events[-1][1]["aggregate_blast_radius_limit"] == 1

    renewed = leases.issue(CapabilityLease(
        "lease-radius-renewed", agent.agent_id, lease.issuer_identity, lease.tenant_id,
        lease.granted_capabilities, lease.allowed_tools, lease.allowed_resources,
        lease.allowed_data_classifications, lease.allowed_action_classes, lease.max_blast_radius,
        False, 0, 200, 300, lease.policy_version, "approval-radius-renewed",
        "ticket-radius-renewed", "renewed bounded triage", lease.key_reference,
    ))
    assert auth.authorize(agent.agent_id, first, now=201)["lease_id"] == renewed.lease_id


def test_positive_blast_radius_requires_a_policy_owned_aggregate_limit():
    _, switch, agents, leases, _, model, agent, _ = make_plane()
    policy = DeterministicPolicy([PolicyRule(
        "tenant-a", "telemetry.read", "endpoint-123", "READ", "FW-ASOC-01-v1",
    )])
    auth = CapabilityAuthorizer(agents, leases, switch, policy_engine=policy, model_binding_validator=lambda *_args: True)
    with pytest.raises(AuthorizationDenied, match="AGGREGATE_BLAST_RADIUS_LIMIT_REQUIRED"):
        auth.authorize(agent.agent_id, request(blast_radius=1, model_identity=model), now=150)
    assert auth.authorize(agent.agent_id, request(blast_radius=0, model_identity=model), now=151)["authorized"] is True


def test_agent_recovery_releases_tenant_scope_aggregate_blast_radius_reservations():
    _, switch, agents, leases, _, model, agent, lease = make_plane()
    policy = DeterministicPolicy([PolicyRule(
        "tenant-a", "telemetry.read", "endpoint-123", "READ", "FW-ASOC-01-v1", 1,
    )])
    auth = CapabilityAuthorizer(agents, leases, switch, policy_engine=policy, model_binding_validator=lambda *_args: True)
    assert auth.authorize(agent.agent_id, request(blast_radius=1, model_identity=model), now=150)["authorized"] is True
    second_agent = AgentIdentity(
        "agent-triage-2", agent.tenant_id, agent.agent_type, agent.role, agent.owner_controller_id,
        model, agent.provider_deployment, agent.approved_purpose, agent.trust_level,
        agent.allowed_data_classifications, cryptographic_identity_ref="fw-id/agent-triage-2",
    )
    agents.register(second_agent)
    agents.activate(second_agent.agent_id, now=100)
    leases.issue(CapabilityLease(
        "lease-radius-agent-2", second_agent.agent_id, lease.issuer_identity, lease.tenant_id,
        lease.granted_capabilities, lease.allowed_tools, lease.allowed_resources,
        lease.allowed_data_classifications, lease.allowed_action_classes, lease.max_blast_radius,
        False, 0, 100, 200, lease.policy_version, "approval-radius-agent-2",
        "ticket-radius-agent-2", "bounded triage", lease.key_reference,
    ))
    with pytest.raises(AuthorizationDenied, match="AGGREGATE_BLAST_RADIUS_EXCEEDED"):
        auth.authorize(second_agent.agent_id, request(blast_radius=1, model_identity=model), now=151)
    control = ASOCControlPlane(agents, leases, switch, blast_radius_ledger=auth.blast_radius_ledger)
    control.revoke_agent(agent.agent_id)
    assert auth.authorize(second_agent.agent_id, request(blast_radius=1, model_identity=model), now=152)["authorized"] is True


def test_aggregate_cap_denial_does_not_consume_a_valid_action_ticket():
    _, switch, agents, leases, _, model, agent, lease = make_plane()
    switch.clear_for_dry_run()
    mutation = leases.issue(CapabilityLease(
        "lease-ticket-cap", agent.agent_id, lease.issuer_identity, lease.tenant_id,
        ("endpoint.isolate.request",), lease.allowed_tools, lease.allowed_resources,
        lease.allowed_data_classifications, ("ISOLATE_ENDPOINT",), 1, False, 0, 100, 200,
        lease.policy_version, "approval-ticket-cap", "ticket-cap", "bounded containment", lease.key_reference,
    ))
    del leases._leases[lease.lease_id]
    tickets = ActionTicketRegistry(HMACLeaseSigner({lease.key_reference: b"test-only-key-material"}))
    tickets.issue(ActionTicket(
        "ticket-cap", agent.tenant_id, agent.agent_id, mutation.lease_id,
        "endpoint.isolate.request", "endpoint-123", "ISOLATE_ENDPOINT", "human-controller-1",
        "approval-ticket-cap", mutation.policy_version, 100, 200, mutation.key_reference,
    ))
    policy = DeterministicPolicy([PolicyRule(
        "tenant-a", "endpoint.isolate.request", "endpoint-123", "ISOLATE_ENDPOINT", "FW-ASOC-01-v1", 0,
    )])
    auth = CapabilityAuthorizer(
        agents, leases, switch, policy_engine=policy, action_tickets=tickets,
        model_binding_validator=lambda *_args: True,
    )
    denied = request(
        capability="endpoint.isolate.request", action_class="ISOLATE_ENDPOINT", blast_radius=1,
        action_ticket_id="ticket-cap", model_identity=model,
    )
    with pytest.raises(AuthorizationDenied, match="AGGREGATE_BLAST_RADIUS_EXCEEDED"):
        auth.authorize(agent.agent_id, denied, now=150)
    assert tickets.validate_and_consume(
        "ticket-cap", tenant_id="tenant-a", subject_agent_id=agent.agent_id, lease_id=mutation.lease_id,
        capability="endpoint.isolate.request", resource="endpoint-123", action_class="ISOLATE_ENDPOINT",
        policy_version=mutation.policy_version, now=151,
    ).ticket_id == "ticket-cap"


def test_invalid_action_ticket_is_denied_before_aggregate_reservation():
    _, switch, agents, leases, _, model, agent, lease = make_plane()
    switch.clear_for_dry_run()
    mutation = leases.issue(CapabilityLease(
        "lease-ticket-preflight", agent.agent_id, lease.issuer_identity, lease.tenant_id,
        ("endpoint.isolate.request",), lease.allowed_tools, lease.allowed_resources,
        lease.allowed_data_classifications, ("ISOLATE_ENDPOINT",), 1, False, 0, 100, 200,
        lease.policy_version, "approval-preflight", "ticket-preflight", "bounded containment", lease.key_reference,
    ))
    del leases._leases[lease.lease_id]
    tickets = ActionTicketRegistry(HMACLeaseSigner({lease.key_reference: b"test-only-key-material"}))
    tickets.issue(ActionTicket("ticket-preflight", agent.tenant_id, agent.agent_id, mutation.lease_id, "endpoint.isolate.request", "endpoint-123", "ISOLATE_ENDPOINT", "human-controller-1", "approval-preflight", mutation.policy_version, 100, 200, mutation.key_reference))
    tickets.revoke_matching(subject_agent_id=agent.agent_id)
    policy = DeterministicPolicy([PolicyRule("tenant-a", "endpoint.isolate.request", "endpoint-123", "ISOLATE_ENDPOINT", "FW-ASOC-01-v1", 1)])
    auth = CapabilityAuthorizer(agents, leases, switch, policy_engine=policy, action_tickets=tickets, model_binding_validator=lambda *_args: True)
    auth.blast_radius_ledger.reserve = lambda *_args, **_kwargs: pytest.fail("invalid ticket reserved capacity")
    with pytest.raises(AuthorizationDenied, match="ACTION_TICKET_INVALID"):
        auth.authorize(agent.agent_id, request(capability="endpoint.isolate.request", action_class="ISOLATE_ENDPOINT", blast_radius=1, action_ticket_id="ticket-preflight", model_identity=model), now=150)


def test_aggregate_blast_radius_concurrency_allows_only_one_reservation():
    _, switch, agents, leases, _, model, agent, _ = make_plane()
    policy = DeterministicPolicy([PolicyRule(
        "tenant-a", "telemetry.read", "endpoint-123", "READ", "FW-ASOC-01-v1", 1,
    )])
    auth = CapabilityAuthorizer(agents, leases, switch, policy_engine=policy, model_binding_validator=lambda *_args: True)

    def attempt() -> str:
        try:
            auth.authorize(agent.agent_id, request(blast_radius=1, model_identity=model), now=150)
            return "AUTHORIZED"
        except AuthorizationDenied as exc:
            return exc.reason

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _index: attempt(), range(2)))
    assert sorted(outcomes) == ["AGGREGATE_BLAST_RADIUS_EXCEEDED", "AUTHORIZED"]


@pytest.mark.parametrize("value", [0, -1, True, "1"])
def test_lease_rejects_invalid_concurrent_work_limits(value):
    _, _, _, _, _, _, _, lease = make_plane()
    with pytest.raises(ValueError, match="max_concurrent_work"):
        replace(lease, max_concurrent_work=value)


def test_work_budget_admission_is_bounded_audited_and_released_on_completion_and_recovery():
    events, _, agents, leases, auth, _, agent, lease = make_plane()
    budgeted = leases.issue(replace(
        lease, lease_id="lease-work-budget", valid_from=101, max_concurrent_work=1,
    ))
    first = auth.admit_work(agent.agent_id, "work-1", now=150)
    assert first == {
        "admitted": True, "agent_id": agent.agent_id, "tenant_id": agent.tenant_id,
        "lease_id": budgeted.lease_id, "work_id": "work-1", "max_concurrent_work": 1,
        "policy_concurrent_work_limit": None, "policy_tenant_concurrent_work_limit": None,
        "concurrent_work_remaining": 0, "tenant_concurrent_work_remaining": None, "timestamp": 150,
    }
    with pytest.raises(AuthorizationDenied, match="WORK_CONCURRENCY_LIMIT_EXCEEDED"):
        auth.admit_work(agent.agent_id, "work-2", now=151)
    assert events[-1][0] == "work_admission_denied"
    assert auth.complete_work(agent.agent_id, "work-1", now=152) is True
    assert auth.admit_work(agent.agent_id, "work-2", now=153)["admitted"] is True
    control = ASOCControlPlane(
        agents, leases, KillSwitch(True), work_budget_ledger=auth.work_budget_ledger,
    )
    control.revoke_agent(agent.agent_id)
    assert auth.work_budget_ledger.active_count(
        tenant_id=agent.tenant_id, agent_id=agent.agent_id, now=154,
    ) == 0
    assert [event for event, _data in events if event == "work_admitted"] == ["work_admitted", "work_admitted"]


def test_work_budget_concurrent_admission_allows_only_one_work_item():
    _, _, _, leases, auth, _, agent, lease = make_plane()
    leases.issue(replace(
        lease, lease_id="lease-work-budget-concurrent", valid_from=101, max_concurrent_work=1,
    ))

    def attempt(work_id):
        try:
            auth.admit_work(agent.agent_id, work_id, now=150)
            return "ADMITTED"
        except AuthorizationDenied as exc:
            return exc.reason

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, ("work-a", "work-b")))
    assert sorted(outcomes) == ["ADMITTED", "WORK_CONCURRENCY_LIMIT_EXCEEDED"]
    assert auth.work_budget_ledger.active_count(
        tenant_id=agent.tenant_id, agent_id=agent.agent_id, now=151,
    ) == 1


def test_work_budget_uses_an_explicit_deterministic_policy_limit():
    _, _, agents, leases, _, model, agent, lease = make_plane()
    budgeted = leases.issue(replace(
        lease, lease_id="lease-work-budget-policy", valid_from=101, max_concurrent_work=2,
    ))
    policy = DeterministicPolicy([PolicyRule(
        "tenant-a", "telemetry.read", "endpoint-123", "READ", "FW-ASOC-01-v1",
        max_concurrent_work=1, max_tenant_concurrent_work=1,
    )])
    auth = CapabilityAuthorizer(
        agents, leases, KillSwitch(True), policy_engine=policy,
        model_binding_validator=lambda *_args: True,
    )
    work_request = request(model_identity=model)
    admitted = auth.admit_work(agent.agent_id, "work-policy-1", work_request, now=150)
    assert admitted["lease_id"] == budgeted.lease_id
    assert admitted["policy_concurrent_work_limit"] == 1
    assert admitted["policy_tenant_concurrent_work_limit"] == 1
    with pytest.raises(AuthorizationDenied, match="WORK_CONCURRENCY_LIMIT_EXCEEDED"):
        auth.admit_work(agent.agent_id, "work-policy-2", work_request, now=151)
    missing_limit = CapabilityAuthorizer(
        agents, leases, KillSwitch(True),
        policy_engine=DeterministicPolicy([PolicyRule(
            "tenant-a", "telemetry.read", "endpoint-123", "READ", "FW-ASOC-01-v1",
        )]),
    )
    with pytest.raises(AuthorizationDenied, match="WORK_CONCURRENCY_LIMIT_REQUIRED"):
        missing_limit.admit_work(agent.agent_id, "work-policy-3", work_request, now=152)
    missing_tenant_limit = CapabilityAuthorizer(
        agents, leases, KillSwitch(True),
        policy_engine=DeterministicPolicy([PolicyRule(
            "tenant-a", "telemetry.read", "endpoint-123", "READ", "FW-ASOC-01-v1",
            max_concurrent_work=1,
        )]),
    )
    with pytest.raises(AuthorizationDenied, match="TENANT_WORK_CONCURRENCY_LIMIT_REQUIRED"):
        missing_tenant_limit.admit_work(agent.agent_id, "work-policy-4", work_request, now=152)


def test_tenant_work_budget_prevents_cross_agent_capacity_splitting():
    _, _, agents, leases, _, model, agent, lease = make_plane()
    second_agent = AgentIdentity(
        "agent-work-budget-2", agent.tenant_id, agent.agent_type, agent.role,
        agent.owner_controller_id, model, agent.provider_deployment, agent.approved_purpose,
        agent.trust_level, agent.allowed_data_classifications,
        cryptographic_identity_ref="fw-id/agent-work-budget-2",
    )
    agents.register(second_agent)
    agents.activate(second_agent.agent_id, now=100)
    leases.issue(CapabilityLease(
        "lease-work-budget-2", second_agent.agent_id, lease.issuer_identity, lease.tenant_id,
        lease.granted_capabilities, lease.allowed_tools, lease.allowed_resources,
        lease.allowed_data_classifications, lease.allowed_action_classes, lease.max_blast_radius,
        False, 0, 100, 200, lease.policy_version, "approval-work-budget-2",
        "ticket-work-budget-2", "bounded triage", lease.key_reference,
    ))
    policy = DeterministicPolicy([PolicyRule(
        "tenant-a", "telemetry.read", "endpoint-123", "READ", "FW-ASOC-01-v1",
        max_concurrent_work=1, max_tenant_concurrent_work=1,
    )])
    auth = CapabilityAuthorizer(agents, leases, KillSwitch(True), policy_engine=policy)
    work_request = request(model_identity=model)
    assert auth.admit_work(agent.agent_id, "tenant-work-1", work_request, now=150)["admitted"] is True
    with pytest.raises(AuthorizationDenied, match="TENANT_WORK_CONCURRENCY_LIMIT_EXCEEDED"):
        auth.admit_work(second_agent.agent_id, "tenant-work-2", work_request, now=151)
    assert auth.work_budget_ledger.active_tenant_count(tenant_id="tenant-a", now=151) == 1


def test_work_budget_expiry_releases_capacity_for_a_renewed_lease():
    _, _, _, leases, auth, _, agent, lease = make_plane()
    auth.admit_work(agent.agent_id, "work-expiring", now=150)
    leases.issue(replace(
        lease, lease_id="lease-work-budget-renewed", valid_from=201, expires_at=300,
    ))
    assert auth.admit_work(agent.agent_id, "work-renewed", now=201)["admitted"] is True
    assert auth.complete_work(agent.agent_id, "work-expiring", now=201) is False
    assert auth.work_budget_ledger.active_count(
        tenant_id=agent.tenant_id, agent_id=agent.agent_id, now=201,
    ) == 1


def test_releasing_failed_reservation_preserves_prior_aggregate_reservations():
    _, _, _, _, _, _, _, lease = make_plane()
    ledger = AggregateBlastRadiusLedger()
    reserved = request(blast_radius=1)
    assert ledger.reserve(reserved, lease, limit=2, now=150) == 1
    assert ledger.reserve(reserved, lease, limit=2, now=151) == 0
    ledger.release_latest(reserved, lease, now=151)
    assert ledger.reserve(reserved, lease, limit=2, now=152) == 0
    with pytest.raises(AuthorizationDenied, match="AGGREGATE_BLAST_RADIUS_EXCEEDED"):
        ledger.reserve(reserved, lease, limit=2, now=153)


def test_asoc_golden_path_investigate_then_deny_mutation():
    events, switch, _, leases, auth, model, agent, lease = make_plane()

    result = auth.authorize(
        agent.agent_id,
        request(tool="mcp.telemetry.status", model_identity=model),
        now=150,
    )
    assert result["authorized"] is True
    assert result["lease_id"] == lease.lease_id
    assert events[-1][0] == "authorization_success"
    assert events[-1][1]["tool"] == "mcp.telemetry.status"

    mutation = lease.__class__(
        "lease-golden-mutation", agent.agent_id, lease.issuer_identity, lease.tenant_id,
        ("endpoint.isolate.request",), lease.allowed_tools, lease.allowed_resources,
        lease.allowed_data_classifications, ("ISOLATE_ENDPOINT",), 1, False, 0, 150, 250,
        lease.policy_version, "approval-golden", "ticket-golden", "bounded containment", lease.key_reference,
    )
    leases.issue(mutation)
    switch.engage()
    with pytest.raises(AuthorizationDenied, match="KILL_SWITCH_MUTATION_BLOCKED"):
        auth.authorize(
            agent.agent_id,
            request(
                capability="endpoint.isolate.request",
                action_class="ISOLATE_ENDPOINT",
                action_ticket_valid=True,
                model_identity=model,
            ),
            now=150,
        )
    assert events[-1][0] == "authorization_denied"
    assert events[-1][1]["reason"] == "KILL_SWITCH_MUTATION_BLOCKED"
    assert events[-1][1]["resource"] == "endpoint-123"
