"""Canonical, tenant-bound MCP tool admission for ForgeWarden actions."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any, Callable


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


@dataclass(frozen=True)
class MCPToolAdmission:
    request_id: str
    tenant_id: str
    subject_agent_id: str
    capability: str
    resource: str
    tool: str
    policy_version: str
    mode: str = "DRY_RUN"
    action: str = "ADMIT_ONLY"


class MCPGateway:
    """Fail-closed registry for exact MCP tool requests; no wildcard grants."""

    def __init__(self, audit: Callable[[str, dict[str, Any]], None] | None = None) -> None:
        if audit is not None and not callable(audit):
            raise MCPGatewayError("audit must be callable")
        self._audit = audit
        self._lock = RLock()
        self._grants: set[MCPToolGrant] = set()
        self._revoked: set[MCPToolGrant] = set()
        self._pending_request_ids: set[str] = set()
        self._admitted_request_ids: set[str] = set()

    def register(self, grant: MCPToolGrant) -> MCPToolGrant:
        if not isinstance(grant, MCPToolGrant):
            raise MCPGatewayError("grant must be an MCPToolGrant")
        with self._lock:
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
        with self._lock:
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
        with self._lock:
            return grant in self._grants and grant not in self._revoked

    def admit(
        self, *, request_id: str, tenant_id: str, subject_agent_id: str,
        capability: str, resource: str, tool: str, policy_version: str,
    ) -> MCPToolAdmission:
        """Evidence-log one exact granted request without invoking its tool."""
        request_id = _text(request_id, "request_id")
        grant = MCPToolGrant(
            tenant_id, subject_agent_id, capability, resource, tool, policy_version,
        )
        with self._lock:
            if request_id in self._pending_request_ids or request_id in self._admitted_request_ids:
                raise MCPGatewayError("MCP request replay detected")
            if grant not in self._grants or grant in self._revoked:
                raise MCPGatewayError("MCP request denied")
            if self._audit is None:
                raise MCPGatewayError("MCP admission Evidence unavailable")
            self._pending_request_ids.add(request_id)
            try:
                self._audit("mcp_tool_request_admitted", {
                    "request_id": request_id, "tenant_id": grant.tenant_id,
                    "subject_agent_id": grant.subject_agent_id,
                    "capability": grant.capability, "resource": grant.resource,
                    "tool": grant.tool, "policy_version": grant.policy_version,
                    "mode": "DRY_RUN", "action": "ADMIT_ONLY",
                    "tool_executed": False, "deployment": "DISABLED",
                })
            except Exception as exc:
                self._pending_request_ids.remove(request_id)
                raise MCPGatewayError("MCP admission Evidence write failed") from exc
            self._pending_request_ids.remove(request_id)
            self._admitted_request_ids.add(request_id)
            return MCPToolAdmission(
                request_id, grant.tenant_id, grant.subject_agent_id, grant.capability,
                grant.resource, grant.tool, grant.policy_version,
            )
