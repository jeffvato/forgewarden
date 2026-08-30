"""Canonical, signed, single-use Action Tickets for bounded ForgeWarden actions."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, replace
from typing import Any, Protocol


class ActionTicketError(ValueError):
    """An Action Ticket is malformed, expired, mismatched, or replayed."""


class TicketSigner(Protocol):
    def sign(self, ticket: "ActionTicket") -> "ActionTicket": ...
    def verify(self, ticket: "ActionTicket") -> None: ...


def _bounded_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ActionTicketError(f"{field} must be a non-empty bounded string")
    return value.strip()


@dataclass(frozen=True)
class ActionTicket:
    ticket_id: str
    tenant_id: str
    subject_agent_id: str
    lease_id: str
    capability: str
    resource: str
    action_class: str
    issued_by: str
    approval_reference: str
    policy_version: str
    issued_at: int
    expires_at: int
    key_reference: str
    signature: str = ""
    consumed_at: int | None = None

    def __post_init__(self) -> None:
        for field in (
            "ticket_id", "tenant_id", "subject_agent_id", "lease_id", "capability",
            "resource", "action_class", "issued_by", "approval_reference",
            "policy_version", "key_reference",
        ):
            object.__setattr__(self, field, _bounded_text(getattr(self, field), field))
        if not isinstance(self.issued_at, int) or not isinstance(self.expires_at, int):
            raise ActionTicketError("ticket timestamps must be integers")
        if self.issued_at >= self.expires_at:
            raise ActionTicketError("ticket expiration must follow issuance")
        if self.consumed_at is not None and not isinstance(self.consumed_at, int):
            raise ActionTicketError("ticket consumption timestamp must be an integer")

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "tenant_id": self.tenant_id,
            "subject_agent_id": self.subject_agent_id,
            "lease_id": self.lease_id,
            "capability": self.capability,
            "resource": self.resource,
            "action_class": self.action_class,
            "issued_by": self.issued_by,
            "approval_reference": self.approval_reference,
            "policy_version": self.policy_version,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "key_reference": self.key_reference,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.unsigned_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")


class ActionTicketRegistry:
    """Issues and consumes signed Action Tickets without granting authority itself."""

    def __init__(self, signer: TicketSigner):
        self._signer = signer
        self._tickets: dict[str, ActionTicket] = {}

    def issue(self, ticket: ActionTicket) -> ActionTicket:
        if ticket.ticket_id in self._tickets:
            raise ActionTicketError("ticket already exists")
        signed = self._signer.sign(ticket)
        self._tickets[signed.ticket_id] = signed
        return signed

    def validate_and_consume(
        self,
        ticket_id: str,
        *,
        tenant_id: str,
        subject_agent_id: str,
        lease_id: str,
        capability: str,
        resource: str,
        action_class: str,
        policy_version: str,
        now: int | None = None,
    ) -> ActionTicket:
        ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise ActionTicketError("ticket not found")
        self._signer.verify(ticket)
        current = int(time.time()) if now is None else now
        if ticket.consumed_at is not None:
            raise ActionTicketError("ticket replay detected")
        if current < ticket.issued_at or current >= ticket.expires_at:
            raise ActionTicketError("ticket is not currently valid")
        expected = {
            "tenant_id": tenant_id,
            "subject_agent_id": subject_agent_id,
            "lease_id": lease_id,
            "capability": capability,
            "resource": resource,
            "action_class": action_class,
            "policy_version": policy_version,
        }
        if any(getattr(ticket, field) != value for field, value in expected.items()):
            raise ActionTicketError("ticket binding mismatch")
        consumed = replace(ticket, consumed_at=current)
        self._tickets[ticket_id] = consumed
        return consumed
