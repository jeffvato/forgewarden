from concurrent.futures import ThreadPoolExecutor

import pytest

from swarm.mcp_gateway import MCPGateway, MCPGatewayError, MCPToolGrant


def grant(tenant_id: str = "tenant-a", agent_id: str = "agent-a") -> MCPToolGrant:
    return MCPToolGrant(
        tenant_id, agent_id, "telemetry.read", "endpoint-123", "mcp.telemetry.status", "FW-ASOC-01-v1",
    )


def test_mcp_gateway_revocation_is_tenant_scoped_and_fail_closed():
    gateway = MCPGateway()
    gateway.register(grant())
    gateway.register(grant("tenant-b", "agent-b"))
    assert gateway.revoke_matching(tenant_id="tenant-a") == 1
    assert not gateway.allows(
        tenant_id="tenant-a", subject_agent_id="agent-a", capability="telemetry.read",
        resource="endpoint-123", tool="mcp.telemetry.status", policy_version="FW-ASOC-01-v1",
    )
    assert gateway.allows(
        tenant_id="tenant-b", subject_agent_id="agent-b", capability="telemetry.read",
        resource="endpoint-123", tool="mcp.telemetry.status", policy_version="FW-ASOC-01-v1",
    )


def request(gateway, request_id="request-1", **overrides):
    values = {
        "request_id": request_id, "tenant_id": "tenant-a", "subject_agent_id": "agent-a",
        "capability": "telemetry.read", "resource": "endpoint-123",
        "tool": "mcp.telemetry.status", "policy_version": "FW-ASOC-01-v1",
    }
    values.update(overrides)
    return gateway.admit(**values)


def test_exact_request_admission_is_evidence_first_and_does_not_execute_tool():
    evidence = []
    gateway = MCPGateway(lambda *args: evidence.append(args))
    gateway.register(grant())
    admission = request(gateway)
    assert admission.mode == "DRY_RUN" and admission.action == "ADMIT_ONLY"
    assert evidence == [("mcp_tool_request_admitted", {
        "request_id": "request-1", "tenant_id": "tenant-a", "subject_agent_id": "agent-a",
        "capability": "telemetry.read", "resource": "endpoint-123",
        "tool": "mcp.telemetry.status", "policy_version": "FW-ASOC-01-v1",
        "mode": "DRY_RUN", "action": "ADMIT_ONLY", "tool_executed": False,
        "deployment": "DISABLED",
    })]


def test_request_replay_is_single_use_under_concurrency():
    gateway = MCPGateway(lambda *_args: None)
    gateway.register(grant())
    def attempt():
        try:
            request(gateway)
            return "ADMITTED"
        except MCPGatewayError:
            return "DENIED"
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _item: attempt(), range(8)))
    assert results.count("ADMITTED") == 1
    assert results.count("DENIED") == 7


def test_denied_revoked_and_cross_tenant_requests_do_not_consume_request_id():
    gateway = MCPGateway(lambda *_args: None)
    gateway.register(grant())
    with pytest.raises(MCPGatewayError, match="request denied"):
        request(gateway, tenant_id="tenant-b")
    assert request(gateway).request_id == "request-1"
    gateway = MCPGateway(lambda *_args: None)
    gateway.register(grant())
    gateway.revoke_matching(tenant_id="tenant-a")
    with pytest.raises(MCPGatewayError, match="request denied"):
        request(gateway)


def test_evidence_failure_denies_without_consuming_request_id():
    calls = 0
    def fail(*_args):
        nonlocal calls
        calls += 1
        raise RuntimeError("offline")
    gateway = MCPGateway(fail)
    gateway.register(grant())
    with pytest.raises(MCPGatewayError, match="Evidence write failed"):
        request(gateway)
    assert calls == 1
    gateway._audit = lambda *_args: None
    assert request(gateway).request_id == "request-1"


def test_admission_requires_evidence_and_exact_grant_fields():
    gateway = MCPGateway()
    gateway.register(grant())
    with pytest.raises(MCPGatewayError, match="Evidence unavailable"):
        request(gateway)
    gateway = MCPGateway(lambda *_args: None)
    gateway.register(grant())
    with pytest.raises(MCPGatewayError, match="request denied"):
        request(gateway, tool="mcp.telemetry.other")


def test_reentrant_evidence_callback_cannot_admit_the_same_request_twice():
    outcomes = []
    gateway = None
    def audit(*_args):
        try:
            request(gateway)
        except MCPGatewayError as exc:
            outcomes.append(str(exc))
    gateway = MCPGateway(audit)
    gateway.register(grant())
    assert request(gateway).request_id == "request-1"
    assert outcomes == ["MCP request replay detected"]
