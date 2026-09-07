import hashlib

import pytest

from swarm.quarantine import (
    MAX_QUARANTINE_ENTRIES,
    MAX_QUARANTINE_TOTAL_BYTES,
    InMemoryQuarantineVault,
    QuarantineEntry,
    QuarantineRecoveryProposal,
    QuarantineProposal,
    QuarantineProposalDenied,
    propose_quarantine,
    propose_quarantine_with_ticket,
    propose_quarantine_recovery_with_ticket,
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


def test_in_memory_vault_admission_requires_signed_ticket_and_preserves_ticket():
    signer = HMACLeaseSigner({"key-1": b"test-only-key-material"})
    tickets = ActionTicketRegistry(signer)
    tickets.issue(ActionTicket(
        "ticket-vault", "tenant-a", "agent-1", "lease-1", "endpoint.quarantine.propose",
        "det-1", "QUARANTINE_PROPOSAL", "human-1", "approval-1", "policy-1", 100, 200, "key-1",
    ))
    proposal = propose_quarantine(b"fixture", **_kwargs(lambda *_args: None))
    vault = InMemoryQuarantineVault(lambda *_args: None)
    entry = vault.admit_with_ticket(
        proposal, b"fixture", tickets=tickets, ticket_id="ticket-vault",
        subject_agent_id="agent-1", lease_id="lease-1", policy_version="policy-1", now=150,
    )
    assert entry.detection_id == "det-1"
    assert tickets.validate(
        "ticket-vault", tenant_id="tenant-a", subject_agent_id="agent-1", lease_id="lease-1",
        capability="endpoint.quarantine.propose", resource="det-1", action_class="QUARANTINE_PROPOSAL",
        policy_version="policy-1", now=150,
    ).consumed_at is None


def test_in_memory_vault_ticket_denial_precedes_storage_and_evidence():
    signer = HMACLeaseSigner({"key-1": b"test-only-key-material"})
    tickets = ActionTicketRegistry(signer)
    tickets.issue(ActionTicket(
        "ticket-vault", "tenant-a", "agent-1", "lease-1", "endpoint.quarantine.propose",
        "det-1", "QUARANTINE_PROPOSAL", "human-1", "approval-1", "policy-1", 100, 200, "key-1",
    ))
    proposal = propose_quarantine(b"fixture", **_kwargs(lambda *_args: None))
    events = []
    vault = InMemoryQuarantineVault(lambda *args: events.append(args))
    with pytest.raises(QuarantineProposalDenied, match="ACTION_TICKET_DENIED"):
        vault.admit_with_ticket(
            proposal, b"fixture", tickets=tickets, ticket_id="ticket-vault",
            subject_agent_id="agent-1", lease_id="lease-1", policy_version="policy-wrong", now=150,
        )
    assert vault.count() == 0
    assert events == []


def test_in_memory_vault_snapshot_and_recovery_are_deterministic_and_evidence_first():
    events = []
    proposal = propose_quarantine(b"fixture", **_kwargs(lambda *_args: None))
    vault = InMemoryQuarantineVault(lambda *args: events.append(args))
    entry = vault.admit(proposal, b"fixture")
    snapshot = vault.snapshot()
    recovered = InMemoryQuarantineVault(lambda *args: events.append(args))
    assert recovered.recover(snapshot) == snapshot
    assert recovered.inspect(tenant_id="tenant-a", device_id="device-a", detection_id="det-1") == entry
    assert events[-1][0] == "quarantine_vault_recovered"


def test_in_memory_vault_recovery_rejects_tampered_snapshot_without_replacement():
    events = []
    proposal = propose_quarantine(b"fixture", **_kwargs(lambda *_args: None))
    vault = InMemoryQuarantineVault(lambda *args: events.append(args))
    entry = vault.admit(proposal, b"fixture")
    tampered = type(entry)(entry.tenant_id, entry.device_id, entry.detection_id, "0" * 64, entry.content_bytes, entry.provenance)
    with pytest.raises(QuarantineProposalDenied, match="RECOVERY_DIGEST_MISMATCH"):
        vault.recover((tampered,))
    assert vault.snapshot() == (entry,)


def test_in_memory_vault_recovery_rejects_invalid_shape_policy_and_duplicates():
    vault = InMemoryQuarantineVault(lambda *_args: None)
    proposal = propose_quarantine(b"fixture", **_kwargs(lambda *_args: None))
    entry = QuarantineEntry(
        proposal.tenant_id, proposal.device_id, proposal.detection_id,
        proposal.content_sha256, b"fixture", proposal.provenance,
    )
    for invalid, reason in [
        ([], "RECOVERY_SNAPSHOT_INVALID"),
        ((object(),), "RECOVERY_SNAPSHOT_INVALID"),
        ((QuarantineEntry("tenant-a", "device-a", "det-1", proposal.content_sha256, b"", proposal.provenance),), "RECOVERY_SNAPSHOT_INVALID"),
        ((QuarantineEntry("tenant-a", "device-a", "det-1", proposal.content_sha256, b"fixture", proposal.provenance, action="QUARANTINE"),), "RECOVERY_POLICY_INVALID"),
        ((entry, entry), "RECOVERY_DUPLICATE"),
    ]:
        with pytest.raises(QuarantineProposalDenied, match=reason):
            vault.recover(invalid)
    assert vault.snapshot() == ()


def test_in_memory_vault_recovery_rejects_total_capacity_and_is_atomic():
    content = b"x" * (MAX_QUARANTINE_TOTAL_BYTES // 4)
    entries = tuple(
        QuarantineEntry(
            "tenant-a", "device-a", f"det-{index}", hashlib.sha256(content).hexdigest(),
            content, "fixture",
        ) for index in range(5)
    )
    vault = InMemoryQuarantineVault(lambda *_args: None)
    with pytest.raises(QuarantineProposalDenied, match="VAULT_CAPACITY"):
        vault.recover(entries)
    assert vault.snapshot() == ()


def test_in_memory_vault_recovery_covers_entry_cap_content_type_and_mode():
    digest = hashlib.sha256(b"x").hexdigest()
    too_many = tuple(
        QuarantineEntry("tenant-a", "device-a", f"det-{index}", digest, b"x", "fixture")
        for index in range(MAX_QUARANTINE_ENTRIES + 1)
    )
    vault = InMemoryQuarantineVault(lambda *_args: None)
    with pytest.raises(QuarantineProposalDenied, match="RECOVERY_SNAPSHOT_INVALID"):
        vault.recover(too_many)
    with pytest.raises(QuarantineProposalDenied, match="RECOVERY_SNAPSHOT_INVALID"):
        vault.recover((QuarantineEntry("tenant-a", "device-a", "det-type", digest, "not-bytes", "fixture"),))
    with pytest.raises(QuarantineProposalDenied, match="RECOVERY_POLICY_INVALID"):
        vault.recover((QuarantineEntry("tenant-a", "device-a", "det-mode", digest, b"x", "fixture", mode="LIVE"),))
    assert vault.snapshot() == ()


def test_in_memory_vault_recovery_evidence_failure_preserves_existing_state():
    proposal = propose_quarantine(b"old", **_kwargs(lambda *_args: None))
    events = []
    vault = InMemoryQuarantineVault(lambda *args: events.append(args))
    existing = vault.admit(proposal, b"old")
    replacement = QuarantineEntry(
        "tenant-a", "device-a", "det-new", hashlib.sha256(b"new").hexdigest(), b"new", "fixture",
    )
    def fail_recovery(event, payload):
        if event == "quarantine_vault_recovered":
            raise OSError("sink unavailable")
        events.append((event, payload))
    vault._audit = fail_recovery
    with pytest.raises(QuarantineProposalDenied, match="EVIDENCE_WRITE_FAILED"):
        vault.recover((replacement,))
    assert vault.snapshot() == (existing,)


def test_quarantine_recovery_proposal_is_ticket_bound_evidence_first_and_consuming():
    signer = HMACLeaseSigner({"key-1": b"test-only-key-material"})
    tickets = ActionTicketRegistry(signer)
    tickets.issue(ActionTicket(
        "ticket-recover", "tenant-a", "agent-1", "lease-1", "endpoint.quarantine.recover",
        "device-a:det-1", "QUARANTINE_RECOVERY", "human-1", "approval-1", "policy-1", 100, 200, "key-1",
    ))
    entry = QuarantineEntry(
        "tenant-a", "device-a", "det-1", hashlib.sha256(b"fixture").hexdigest(), b"fixture", "fixture",
    )
    events = []
    proposal = propose_quarantine_recovery_with_ticket(
        entry, tickets=tickets, ticket_id="ticket-recover", subject_agent_id="agent-1",
        lease_id="lease-1", policy_version="policy-1", now=150,
        audit=lambda *args: events.append(args), kill_switch_state="ENGAGED",
    )
    assert isinstance(proposal, QuarantineRecoveryProposal)
    assert proposal.mode == "DRY_RUN" and proposal.action == "DETECT_ONLY"
    assert events[0][0] == "quarantine_recovery_proposed"
    with pytest.raises(QuarantineProposalDenied, match="RECOVERY_TICKET_DENIED"):
        propose_quarantine_recovery_with_ticket(
            entry, tickets=tickets, ticket_id="ticket-recover", subject_agent_id="agent-1",
            lease_id="lease-1", policy_version="policy-1", now=150, audit=lambda *_args: None,
            kill_switch_state="ENGAGED",
        )


def test_quarantine_recovery_proposal_denies_tamper_scope_and_evidence_failure():
    signer = HMACLeaseSigner({"key-1": b"test-only-key-material"})
    tickets = ActionTicketRegistry(signer)
    tickets.issue(ActionTicket(
        "ticket-recover", "tenant-a", "agent-1", "lease-1", "endpoint.quarantine.recover",
        "device-a:det-1", "QUARANTINE_RECOVERY", "human-1", "approval-1", "policy-1", 100, 200, "key-1",
    ))
    entry = QuarantineEntry("tenant-a", "device-a", "det-1", "0" * 64, b"fixture", "fixture")
    with pytest.raises(QuarantineProposalDenied, match="RECOVERY_DIGEST_MISMATCH"):
        propose_quarantine_recovery_with_ticket(
            entry, tickets=tickets, ticket_id="ticket-recover", subject_agent_id="agent-1",
            lease_id="lease-1", policy_version="policy-1", now=150, audit=lambda *_args: None,
            kill_switch_state="ENGAGED",
        )
    valid = QuarantineEntry("tenant-a", "device-a", "det-1", hashlib.sha256(b"fixture").hexdigest(), b"fixture", "fixture")
    with pytest.raises(QuarantineProposalDenied, match="EVIDENCE_WRITE_FAILED"):
        propose_quarantine_recovery_with_ticket(
            valid, tickets=tickets, ticket_id="ticket-recover", subject_agent_id="agent-1",
            lease_id="lease-1", policy_version="policy-1", now=150,
            audit=lambda *_args: (_ for _ in ()).throw(OSError("sink unavailable")),
            kill_switch_state="ENGAGED",
        )
    assert tickets.validate(
        "ticket-recover", tenant_id="tenant-a", subject_agent_id="agent-1", lease_id="lease-1",
        capability="endpoint.quarantine.recover", resource="device-a:det-1", action_class="QUARANTINE_RECOVERY",
        policy_version="policy-1", now=150,
    ).consumed_at is None


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
