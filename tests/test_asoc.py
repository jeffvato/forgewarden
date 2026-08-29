import time

import pytest

from swarm.asoc import (
    ASOCControlPlane,
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
)


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
    authorizer = CapabilityAuthorizer(agents, leases, switch, audit, policy=lambda _agent, _lease, _request: True)
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


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"tenant_id": "tenant-b"}, "TENANT_MISMATCH"),
        ({"capability": "endpoint.inspect"}, "CAPABILITY_NOT_GRANTED"),
        ({"resource": "endpoint-999"}, "RESOURCE_OUT_OF_SCOPE"),
        ({"data_classification": "RESTRICTED"}, "DATA_CLASSIFICATION_DENIED"),
        ({"action_class": "ISOLATE_ENDPOINT"}, "ACTION_CLASS_DENIED"),
        ({"tool": "mcp.arbitrary"}, "MCP_TOOL_NOT_ALLOWED"),
        ({"blast_radius": 2}, "BLAST_RADIUS_EXCEEDED"),
        ({"policy_version": "old-policy"}, "STALE_POLICY_VERSION"),
    ],
)
def test_scope_and_policy_denials_are_explicit(overrides, reason):
    _, _, _, _, auth, model, agent, _ = make_plane()
    overrides = {**overrides, "model_identity": model}
    with pytest.raises(AuthorizationDenied, match=reason):
        auth.authorize(agent.agent_id, request(**overrides), now=150)


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
    switch.engage()
    with pytest.raises(AuthorizationDenied, match="KILL_SWITCH_ENGAGED"):
        leases.issue(CapabilityLease(
            "lease-new", agent.agent_id, "human-controller-1", "tenant-a", lease.granted_capabilities,
            lease.allowed_tools, lease.allowed_resources, lease.allowed_data_classifications, lease.allowed_action_classes,
            1, False, 0, 150, 250, lease.policy_version, "approval-3", "ticket-3", "new", lease.key_reference,
        ))
    assert auth.authorize(agent.agent_id, request(model_identity=model), now=150)["authorized"]
    with pytest.raises(AuthorizationDenied, match="ACTION_CLASS_DENIED"):
        auth.authorize(agent.agent_id, request(capability="action.request", action_class="ISOLATE_ENDPOINT", action_ticket_valid=True, model_identity=model), now=150)
    control = ASOCControlPlane(agents, leases, switch)
    assert control.engage_ai_kill_switch() == 1


def test_mutating_capability_requires_ticket_and_is_disabled_by_kill_switch():
    _, switch, agents, leases, auth, model, agent, lease = make_plane()
    mutation = lease.__class__(
        "lease-mutation", agent.agent_id, lease.issuer_identity, lease.tenant_id,
        ("endpoint.isolate.request",), lease.allowed_tools, lease.allowed_resources,
        lease.allowed_data_classifications, ("ISOLATE_ENDPOINT",), 1, False, 0, 100, 200,
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
