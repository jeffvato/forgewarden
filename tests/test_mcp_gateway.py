from swarm.mcp_gateway import MCPGateway, MCPToolGrant


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
