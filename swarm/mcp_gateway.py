"""Canonical, tenant-bound MCP tool admission for ForgeWarden actions."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import math
from threading import RLock
from typing import Any, Callable


class MCPGatewayError(ValueError):
    """An MCP tool grant is invalid or conflicts with an existing grant."""


MAX_ADMISSIONS_PER_SCOPE = 1024
MAX_RESULT_BYTES = 64 * 1024
MAX_RESULT_DEPTH = 8
MAX_RESULT_COLLECTION_ITEMS = 128
MAX_RESULT_STRING_BYTES = 4096


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


@dataclass(frozen=True)
class MCPToolResultEnvelope:
    request_id: str
    tenant_id: str
    subject_agent_id: str
    tool: str
    payload_json: str
    payload_sha256: str
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "ENVELOPE_ONLY"


def _validate_result_value(value: Any, *, depth: int = 0, ancestors: frozenset[int] = frozenset()) -> None:
    if depth > MAX_RESULT_DEPTH:
        raise MCPGatewayError("MCP result depth exceeded")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise MCPGatewayError("MCP result contains a non-finite number")
        return
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_RESULT_STRING_BYTES:
            raise MCPGatewayError("MCP result string exceeds bound")
        return
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_RESULT_COLLECTION_ITEMS or id(value) in ancestors:
            raise MCPGatewayError("MCP result collection invalid")
        nested = ancestors | {id(value)}
        for item in value:
            _validate_result_value(item, depth=depth + 1, ancestors=nested)
        return
    if isinstance(value, dict):
        if len(value) > MAX_RESULT_COLLECTION_ITEMS or id(value) in ancestors:
            raise MCPGatewayError("MCP result collection invalid")
        nested = ancestors | {id(value)}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key.encode("utf-8")) > 256:
                raise MCPGatewayError("MCP result key invalid")
            _validate_result_value(item, depth=depth + 1, ancestors=nested)
        return
    raise MCPGatewayError("MCP result type invalid")


class MCPGateway:
    """Fail-closed registry for exact MCP tool requests; no wildcard grants."""

    def __init__(
        self, audit: Callable[[str, dict[str, Any]], None] | None = None, *,
        max_admissions_per_scope: int = MAX_ADMISSIONS_PER_SCOPE,
    ) -> None:
        if audit is not None and not callable(audit):
            raise MCPGatewayError("audit must be callable")
        if isinstance(max_admissions_per_scope, bool) or not isinstance(max_admissions_per_scope, int) or not 1 <= max_admissions_per_scope <= MAX_ADMISSIONS_PER_SCOPE:
            raise MCPGatewayError("max admissions per scope must be a positive bounded integer")
        self._audit = audit
        self._max_admissions_per_scope = max_admissions_per_scope
        self._lock = RLock()
        self._grants: set[MCPToolGrant] = set()
        self._revoked: set[MCPToolGrant] = set()
        self._pending_request_ids: set[str] = set()
        self._admitted_request_ids: set[str] = set()
        self._admission_counts: dict[tuple[str, str, str], int] = {}
        self._admissions: dict[str, MCPToolAdmission] = {}
        self._pending_result_ids: set[str] = set()
        self._completed_request_ids: set[str] = set()

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
            budget_scope = (grant.tenant_id, grant.subject_agent_id, grant.tool)
            if request_id in self._pending_request_ids or request_id in self._admitted_request_ids:
                raise MCPGatewayError("MCP request replay detected")
            if grant not in self._grants or grant in self._revoked:
                raise MCPGatewayError("MCP request denied")
            if self._admission_counts.get(budget_scope, 0) >= self._max_admissions_per_scope:
                raise MCPGatewayError("MCP admission budget exhausted")
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
                    "budget_used": self._admission_counts.get(budget_scope, 0) + 1,
                    "budget_limit": self._max_admissions_per_scope,
                })
            except Exception as exc:
                self._pending_request_ids.remove(request_id)
                raise MCPGatewayError("MCP admission Evidence write failed") from exc
            self._pending_request_ids.remove(request_id)
            self._admitted_request_ids.add(request_id)
            self._admission_counts[budget_scope] = self._admission_counts.get(budget_scope, 0) + 1
            admission = MCPToolAdmission(
                request_id, grant.tenant_id, grant.subject_agent_id, grant.capability,
                grant.resource, grant.tool, grant.policy_version,
            )
            self._admissions[request_id] = admission
            return admission

    def wrap_result(self, admission: MCPToolAdmission, payload: Any) -> MCPToolResultEnvelope:
        """Wrap one admitted caller-supplied result as untrusted data without interpreting it."""
        if not isinstance(admission, MCPToolAdmission):
            raise MCPGatewayError("MCP admission invalid")
        _validate_result_value(payload)
        try:
            payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError, OverflowError) as exc:
            raise MCPGatewayError("MCP result serialization failed") from exc
        encoded = payload_json.encode("utf-8")
        if len(encoded) > MAX_RESULT_BYTES:
            raise MCPGatewayError("MCP result exceeds byte bound")
        digest = sha256(encoded).hexdigest()
        with self._lock:
            if self._admissions.get(admission.request_id) != admission:
                raise MCPGatewayError("MCP result admission mismatch")
            if admission.request_id in self._pending_result_ids or admission.request_id in self._completed_request_ids:
                raise MCPGatewayError("MCP result replay detected")
            grant = MCPToolGrant(
                admission.tenant_id, admission.subject_agent_id, admission.capability,
                admission.resource, admission.tool, admission.policy_version,
            )
            if grant in self._revoked:
                raise MCPGatewayError("MCP result grant revoked")
            if self._audit is None:
                raise MCPGatewayError("MCP result Evidence unavailable")
            self._pending_result_ids.add(admission.request_id)
            try:
                self._audit("mcp_tool_result_enveloped", {
                    "request_id": admission.request_id, "tenant_id": admission.tenant_id,
                    "subject_agent_id": admission.subject_agent_id, "tool": admission.tool,
                    "payload_sha256": digest, "payload_bytes": len(encoded),
                    "trust": "UNTRUSTED_DATA", "mode": "DRY_RUN",
                    "action": "ENVELOPE_ONLY", "interpreted": False,
                    "tool_executed_by_gateway": False, "deployment": "DISABLED",
                })
            except Exception as exc:
                self._pending_result_ids.remove(admission.request_id)
                raise MCPGatewayError("MCP result Evidence write failed") from exc
            self._pending_result_ids.remove(admission.request_id)
            self._completed_request_ids.add(admission.request_id)
            return MCPToolResultEnvelope(
                admission.request_id, admission.tenant_id, admission.subject_agent_id,
                admission.tool, payload_json, digest,
            )
