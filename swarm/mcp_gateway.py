"""Canonical, tenant-bound MCP tool admission for ForgeWarden actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class MCPGatewayError(ValueError):
    """An MCP tool grant is invalid or conflicts with an existing grant."""


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise MCPGatewayError(f"{field} must be a non-empty bounded string")
    return value.strip()


@dataclass(frozen=True)
class MCPToolGrant:
    tenant_id: str
    subject_agent_id: str
    capability: str
    resource: str
    tool: str
    policy_version: str

    def __post_init__(self) -> None:
        for field in ("tenant_id", "subject_agent_id", "capability", "resource", "tool", "policy_version"):
            object.__setattr__(self, field, _text(getattr(self, field), field))


class MCPGateway:
    """Fail-closed registry for exact MCP tool requests; no wildcard grants."""

    def __init__(self) -> None:
        self._grants: set[MCPToolGrant] = set()
        self._revoked: set[MCPToolGrant] = set()

    def register(self, grant: MCPToolGrant) -> MCPToolGrant:
        if not isinstance(grant, MCPToolGrant):
            raise MCPGatewayError("grant must be an MCPToolGrant")
        if grant in self._grants:
            raise MCPGatewayError("MCP tool grant already exists")
        self._grants.add(grant)
        return grant

    def revoke_matching(
        self, *, tenant_id: str | None = None, subject_agent_id: str | None = None,
    ) -> int:
        """Invalidate tool grants during tenant or agent recovery."""
        if tenant_id is None and subject_agent_id is None:
            raise MCPGatewayError("revocation selector is required")
        if tenant_id is not None:
            tenant_id = _text(tenant_id, "tenant_id")
        if subject_agent_id is not None:
            subject_agent_id = _text(subject_agent_id, "subject_agent_id")
        matches = {
            grant for grant in self._grants - self._revoked
            if (tenant_id is None or grant.tenant_id == tenant_id)
            and (subject_agent_id is None or grant.subject_agent_id == subject_agent_id)
        }
        self._revoked.update(matches)
        return len(matches)

    def allows(
        self, *, tenant_id: str, subject_agent_id: str, capability: str,
        resource: str, tool: str, policy_version: str,
    ) -> bool:
        grant = MCPToolGrant(
            tenant_id, subject_agent_id, capability, resource, tool, policy_version,
        )
        return grant in self._grants and grant not in self._revoked
