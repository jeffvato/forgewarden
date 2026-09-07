import hashlib

import pytest

from swarm.quarantine import (
    MAX_QUARANTINE_ENTRIES,
    MAX_QUARANTINE_TOTAL_BYTES,
    InMemoryQuarantineVault,
    QuarantineProposal,
    QuarantineProposalDenied,
    propose_quarantine,
    propose_quarantine_with_ticket,
)
from swarm.action_ticket import ActionTicket, ActionTicketRegistry
from swarm.asoc import HMACLeaseSigner


def _kwargs(audit):
    return dict(
        tenant_id="tenant-a", device_id="device-a", detection_id="det-1",
        provenance="trusted-catalog:v1", confidence="HIGH", trusted_content=True,
        policy_decision="ALLOW_QUARANTINE", audit=audit, kill_switch_state="ENGAGED",
    )


def test_quarantine_proposal_is_bounded_evidence_first_and_non_executing():
    events = []
    proposal = propose_quarantine(b"fixture-malware", **_kwargs(lambda *args: events.append(args)))
    assert proposal.content_sha256 == hashlib.sha256(b"fixture-malware").hexdigest()
    assert proposal.content_bytes == len(b"fixture-malware")
    assert proposal.mode == "DRY_RUN"
    assert proposal.action == "DETECT_ONLY"
    assert proposal.disposition == "PROPOSED"
    assert events[0][0] == "quarantine_proposed"


@pytest.mark.parametrize("overrides", [
    {"confidence": "MEDIUM"},
    {"trusted_content": False},
    {"policy_decision": "DENY"},
])
def test_quarantine_proposal_denies_without_evidence_for_unsafe_policy(overrides):
    events = []
    values = _kwargs(lambda *args: events.append(args))
    values.update(overrides)
    with pytest.raises(QuarantineProposalDenied, match="QUARANTINE_POLICY_DENIED"):
        propose_quarantine(b"fixture", **values)
    assert events == []


def test_quarantine_proposal_fails_closed_when_evidence_is_unavailable():
    def fail(*_args):
        raise OSError("sink unavailable")
    with pytest.raises(QuarantineProposalDenied, match="EVIDENCE_WRITE_FAILED"):
        propose_quarantine(b"fixture", **_kwargs(fail))


def test_quarantine_proposal_requires_engaged_kill_switch():
    events = []
    values = _kwargs(lambda *args: events.append(args))
    values["kill_switch_state"] = "CLEARED_FOR_DRY_RUN"
    with pytest.raises(QuarantineProposalDenied, match="KILL_SWITCH_BLOCKED"):
        propose_quarantine(b"fixture", **values)
    assert events == []


def test_in_memory_vault_stores_exact_fixture_after_evidence_and_is_tenant_bound():
    events = []
    proposal = propose_quarantine(b"fixture", **_kwargs(lambda *args: events.append(args)))
    vault = InMemoryQuarantineVault(lambda *args: events.append(args))
    entry = vault.admit(proposal, b"fixture")
    assert entry.content_bytes == b"fixture"
    assert vault.inspect(tenant_id="tenant-a", device_id="device-a", detection_id="det-1") == entry
    assert vault.inspect(tenant_id="tenant-b", device_id="device-a", detection_id="det-1") is None
    assert events[-1][0] == "quarantine_fixture_stored"
    assert vault.count() == 1


def test_in_memory_vault_inspection_is_isolated_by_device_and_detection_and_empty_is_safe():
    vault = InMemoryQuarantineVault(lambda *_args: None)
    assert vault.inspect(tenant_id="tenant-a", device_id="device-a", detection_id="det-1") is None
    proposal = propose_quarantine(b"fixture", **_kwargs(lambda *_args: None))
    vault.admit(proposal, b"fixture")
    assert vault.inspect(tenant_id="tenant-a", device_id="device-b", detection_id="det-1") is None
    assert vault.inspect(tenant_id="tenant-a", device_id="device-a", detection_id="det-2") is None


def test_in_memory_vault_rejects_invalid_admission_inputs_without_mutation():
    vault = InMemoryQuarantineVault(lambda *_args: None)
    with pytest.raises(QuarantineProposalDenied, match="VAULT_INPUT_INVALID"):
        vault.admit(object(), b"fixture")
    with pytest.raises(QuarantineProposalDenied, match="VAULT_INPUT_INVALID"):
        vault.admit(QuarantineProposal("tenant-a", "device-a", "det-1", "0" * 64, 1, "fixture"), "fixture")
    assert vault.count() == 0


def test_in_memory_vault_enforces_entry_capacity():
    vault = InMemoryQuarantineVault(lambda *_args: None)
    for index in range(MAX_QUARANTINE_ENTRIES):
        values = _kwargs(lambda *_args: None)
        values["detection_id"] = f"det-{index}"
        proposal = propose_quarantine(b"x", **values)
        vault.admit(proposal, b"x")
    values = _kwargs(lambda *_args: None)
    values["detection_id"] = "det-over-cap"
    proposal = propose_quarantine(b"x", **values)
    with pytest.raises(QuarantineProposalDenied, match="VAULT_CAPACITY"):
        vault.admit(proposal, b"x")
    assert vault.count() == MAX_QUARANTINE_ENTRIES


def test_in_memory_vault_enforces_total_byte_capacity():
    vault = InMemoryQuarantineVault(lambda *_args: None)
    content = b"x" * (MAX_QUARANTINE_TOTAL_BYTES // 4)
    for index in range(4):
        values = _kwargs(lambda *_args: None)
        values["detection_id"] = f"bytes-{index}"
        proposal = propose_quarantine(content, **values)
        vault.admit(proposal, content)
    values = _kwargs(lambda *_args: None)
    values["detection_id"] = "bytes-over-cap"
    proposal = propose_quarantine(b"x", **values)
    with pytest.raises(QuarantineProposalDenied, match="VAULT_CAPACITY"):
        vault.admit(proposal, b"x")
    assert vault.count() == 4


def test_quarantine_proposal_can_bind_to_existing_signed_action_ticket():
    signer = HMACLeaseSigner({"key-1": b"test-only-key-material"})
    tickets = ActionTicketRegistry(signer)
    tickets.issue(ActionTicket(
        "ticket-1", "tenant-a", "agent-1", "lease-1", "endpoint.quarantine.propose",
        "det-1", "QUARANTINE_PROPOSAL", "human-1", "approval-1", "policy-1",
        100, 200, "key-1",
    ))
    events = []
    proposal = propose_quarantine_with_ticket(
        b"fixture", **_kwargs(lambda *args: events.append(args)),
        tickets=tickets, ticket_id="ticket-1", subject_agent_id="agent-1",
        lease_id="lease-1", policy_version="policy-1", now=150,
    )
    assert proposal.detection_id == "det-1"
    assert events[-1][0] == "quarantine_proposed"
    validated = tickets.validate(
        "ticket-1", tenant_id="tenant-a", subject_agent_id="agent-1", lease_id="lease-1",
        capability="endpoint.quarantine.propose", resource="det-1",
        action_class="QUARANTINE_PROPOSAL", policy_version="policy-1", now=150,
    )
    assert validated.consumed_at is None


def test_quarantine_proposal_denies_ticket_scope_or_replay_without_evidence():
    signer = HMACLeaseSigner({"key-1": b"test-only-key-material"})
    tickets = ActionTicketRegistry(signer)
    tickets.issue(ActionTicket(
        "ticket-1", "tenant-a", "agent-1", "lease-1", "endpoint.quarantine.propose",
        "det-1", "QUARANTINE_PROPOSAL", "human-1", "approval-1", "policy-1",
        100, 200, "key-1",
    ))
    events = []
    values = _kwargs(lambda *args: events.append(args))
    values["detection_id"] = "det-other"
    with pytest.raises(QuarantineProposalDenied, match="ACTION_TICKET_DENIED"):
        propose_quarantine_with_ticket(
            b"fixture", **values, tickets=tickets, ticket_id="ticket-1",
            subject_agent_id="agent-1", lease_id="lease-1", policy_version="policy-1", now=150,
        )
    assert events == []


def test_quarantine_proposal_rejects_invalid_ticket_registry():
    events = []
    values = _kwargs(lambda *args: events.append(args))
    with pytest.raises(QuarantineProposalDenied, match="ACTION_TICKET_INVALID"):
        propose_quarantine_with_ticket(
            b"fixture", **values, tickets=object(), ticket_id="ticket-1",
            subject_agent_id="agent-1", lease_id="lease-1", policy_version="policy-1", now=150,
        )
    assert events == []


def test_in_memory_vault_rejects_mismatch_duplicate_and_evidence_failure_without_mutation():
    proposal = propose_quarantine(b"fixture", **_kwargs(lambda *_args: None))
    vault = InMemoryQuarantineVault(lambda *_args: None)
    with pytest.raises(QuarantineProposalDenied, match="CONTENT_PROPOSAL_MISMATCH"):
        vault.admit(proposal, b"tampered")
    vault.admit(proposal, b"fixture")
    with pytest.raises(QuarantineProposalDenied, match="VAULT_ENTRY_DUPLICATE"):
        vault.admit(proposal, b"fixture")
    failing = InMemoryQuarantineVault(lambda *_args: (_ for _ in ()).throw(OSError("sink unavailable")))
    proposal2 = propose_quarantine(b"other", **_kwargs(lambda *_args: None) | {"detection_id": "det-2"})
    with pytest.raises(QuarantineProposalDenied, match="EVIDENCE_WRITE_FAILED"):
        failing.admit(proposal2, b"other")
    assert failing.count() == 0


@pytest.mark.parametrize("content", [b"", b"x" * (1024 * 1024 + 1), "not-bytes"])
def test_quarantine_proposal_rejects_invalid_content_before_evidence(content):
    events = []
    with pytest.raises(QuarantineProposalDenied, match="CONTENT_INVALID"):
        propose_quarantine(content, **_kwargs(lambda *args: events.append(args)))
    assert events == []


@pytest.mark.parametrize("field", ["tenant_id", "device_id", "detection_id", "provenance"])
def test_quarantine_proposal_rejects_invalid_identity_before_evidence(field):
    events = []
    values = _kwargs(lambda *args: events.append(args))
    values[field] = " "
    with pytest.raises(QuarantineProposalDenied, match="IDENTITY_INVALID"):
        propose_quarantine(b"fixture", **values)
    assert events == []
