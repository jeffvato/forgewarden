"""Canonical, tenant-bound approvals for models used by ForgeWarden agents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class ModelBrokerError(ValueError):
    """A model approval record is invalid or conflicts with an existing one."""


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ModelBrokerError(f"{field} must be a non-empty bounded string")
    return value.strip()


@dataclass(frozen=True)
class ApprovedModel:
    tenant_id: str
    subject_agent_id: str
    model: str
    provider: str
    deployment: str
    version: str
    approval_version: str

    def __post_init__(self) -> None:
        for field in (
            "tenant_id", "subject_agent_id", "model", "provider", "deployment",
            "version", "approval_version",
        ):
            object.__setattr__(self, field, _text(getattr(self, field), field))


class ModelBroker:
    """Fail-closed model approval registry; approvals are exact and tenant-bound."""

    def __init__(self) -> None:
        self._approvals: dict[tuple[str, str], ApprovedModel] = {}
        self._revoked: set[tuple[str, str]] = set()

    def register(self, approval: ApprovedModel) -> ApprovedModel:
        if not isinstance(approval, ApprovedModel):
            raise ModelBrokerError("approval must be an ApprovedModel")
        key = (approval.tenant_id, approval.subject_agent_id)
        if key in self._approvals:
            raise ModelBrokerError("model approval already exists")
        self._approvals[key] = approval
        return approval

    def revoke_matching(
        self, *, tenant_id: str | None = None, subject_agent_id: str | None = None,
        deployment: str | None = None,
    ) -> int:
        """Invalidate approvals during tenant, agent, or deployment recovery."""
        if tenant_id is None and subject_agent_id is None and deployment is None:
            raise ModelBrokerError("revocation selector is required")
        if tenant_id is not None:
            tenant_id = _text(tenant_id, "tenant_id")
        if subject_agent_id is not None:
            subject_agent_id = _text(subject_agent_id, "subject_agent_id")
        if deployment is not None:
            deployment = _text(deployment, "deployment")
        revoked = 0
        for key, approval in self._approvals.items():
            if key in self._revoked:
                continue
            if tenant_id is not None and approval.tenant_id != tenant_id:
                continue
            if subject_agent_id is not None and approval.subject_agent_id != subject_agent_id:
                continue
            if deployment is not None and approval.deployment != deployment:
                continue
            self._revoked.add(key)
            revoked += 1
        return revoked

    def allows(
        self, *, tenant_id: str, subject_agent_id: str, model: str, provider: str,
        deployment: str, version: str, approval_version: str,
    ) -> bool:
        approval = self._approvals.get((tenant_id, subject_agent_id))
        if approval is None or (tenant_id, subject_agent_id) in self._revoked:
            return False
        return (
            approval.model == model and approval.provider == provider
            and approval.deployment == deployment and approval.version == version
            and approval.approval_version == approval_version
        )
