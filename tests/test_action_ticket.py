from dataclasses import replace

import pytest

from swarm.action_ticket import ActionTicket, ActionTicketError, ActionTicketRegistry
from swarm.asoc import HMACLeaseSigner, LeaseIntegrityError


def make_ticket(ticket_id: str = "ticket-1") -> ActionTicket:
    return ActionTicket(
        ticket_id, "tenant-a", "agent-a", "lease-a", "endpoint.isolate.request",
        "endpoint-123", "ISOLATE_ENDPOINT", "human-controller", "approval-a",
        "FW-ASOC-01-v1", 100, 200, "fw-keys/test",
    )


def make_registry() -> ActionTicketRegistry:
    return ActionTicketRegistry(HMACLeaseSigner({"fw-keys/test": b"test-key-material"}))


def validate(registry: ActionTicketRegistry, ticket_id: str, now: int = 150):
    return registry.validate_and_consume(
        ticket_id, tenant_id="tenant-a", subject_agent_id="agent-a", lease_id="lease-a",
        capability="endpoint.isolate.request", resource="endpoint-123",
        action_class="ISOLATE_ENDPOINT", policy_version="FW-ASOC-01-v1", now=now,
    )


def test_ticket_is_signed_bound_and_consumed_once():
    registry = make_registry()
    registry.issue(make_ticket())
    assert validate(registry, "ticket-1").consumed_at == 150
    with pytest.raises(ActionTicketError, match="replay"):
        validate(registry, "ticket-1", now=151)


def test_ticket_rejects_binding_mismatch_and_expiry():
    registry = make_registry()
    registry.issue(make_ticket())
    with pytest.raises(ActionTicketError, match="binding mismatch"):
        registry.validate_and_consume(
            "ticket-1", tenant_id="tenant-b", subject_agent_id="agent-a", lease_id="lease-a",
            capability="endpoint.isolate.request", resource="endpoint-123",
            action_class="ISOLATE_ENDPOINT", policy_version="FW-ASOC-01-v1", now=150,
        )
    with pytest.raises(ActionTicketError, match="not currently valid"):
        validate(registry, "ticket-1", now=200)


def test_ticket_signature_tampering_is_rejected():
    registry = make_registry()
    signed = registry.issue(make_ticket())
    registry._tickets[signed.ticket_id] = replace(signed, resource="endpoint-999")
    with pytest.raises(LeaseIntegrityError, match="signature mismatch"):
        validate(registry, signed.ticket_id)
