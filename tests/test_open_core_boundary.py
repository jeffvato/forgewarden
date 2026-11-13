from dataclasses import replace

import pytest

from swarm.action_ticket import ActionTicket
from swarm.asoc import HMACLeaseSigner
from swarm.open_core_boundary import (
    OpenCoreBoundaryError,
    PublicActionVerifier,
    SignedActionEnvelope,
)


TICKET_KEY = "fw-keys/action-ticket-test"
ENVELOPE_KEY = "fw-keys/open-core-envelope-test"
AUTHORITY = "fw-root/private-core"


def make_signer():
    return HMACLeaseSigner(
        {
            TICKET_KEY: b"ticket-test-key-material",
            ENVELOPE_KEY: b"envelope-test-key-material",
        }
    )


def make_ticket(**overrides):
    values = dict(
        ticket_id="ticket-1",
        tenant_id="tenant-a",
        subject_agent_id="agent-a",
        lease_id="lease-a",
        capability="endpoint.isolate.request",
        resource="endpoint-123",
        action_class="ISOLATE_ENDPOINT",
        issued_by="human-controller",
        approval_reference="approval-a",
        policy_version="FW-ASOC-01-v1",
        issued_at=100,
        expires_at=200,
        key_reference=TICKET_KEY,
    )
    values.update(overrides)
    signer = make_signer()
    return signer.sign(ActionTicket(**values))


def make_envelope(ticket=None, **overrides):
    values = dict(
        schema_version="1",
        action_id="action-1",
        authority_id=AUTHORITY,
        key_reference=ENVELOPE_KEY,
        nonce="nonce-1",
        ticket=ticket or make_ticket(),
    )
    values.update(overrides)
    signer = make_signer()
    return signer.sign(SignedActionEnvelope(**values))


def make_verifier():
    signer = make_signer()
    return PublicActionVerifier(
        envelope_signer=signer,
        ticket_verifier=signer,
        trusted_authority_id=AUTHORITY,
        trusted_envelope_key_reference=ENVELOPE_KEY,
        trusted_ticket_key_reference=TICKET_KEY,
    )


def verify(verifier, envelope, **overrides):
    values = dict(
        tenant_id="tenant-a",
        subject_agent_id="agent-a",
        lease_id="lease-a",
        capability="endpoint.isolate.request",
        resource="endpoint-123",
        action_class="ISOLATE_ENDPOINT",
        policy_version="FW-ASOC-01-v1",
        now=150,
        safety_evidence={
            "mode": "DRY_RUN",
            "deployment": "DISABLED",
            "kill_switch": "ENGAGED",
            "mutation_allowed": False,
        },
    )
    values.update(overrides)
    return verifier.verify(envelope, **values)


def test_valid_private_core_action_is_admitted_but_not_executable():
    admission = verify(make_verifier(), make_envelope())

    assert admission.authority_valid is True
    assert admission.execution_permitted is False
    assert admission.mode == "DRY_RUN"
    assert admission.deployment == "DISABLED"
    assert admission.ticket_id == "ticket-1"


def test_unsigned_action_envelope_is_rejected():
    envelope = replace(make_envelope(), signature="")

    with pytest.raises(OpenCoreBoundaryError, match="envelope signature"):
        verify(make_verifier(), envelope)


def test_tampered_action_envelope_is_rejected():
    envelope = replace(make_envelope(), nonce="nonce-tampered")

    with pytest.raises(OpenCoreBoundaryError, match="envelope signature"):
        verify(make_verifier(), envelope)


def test_unsigned_or_tampered_action_ticket_is_rejected():
    unsigned = replace(make_ticket(), signature="")
    with pytest.raises(OpenCoreBoundaryError, match="Ticket signature"):
        verify(make_verifier(), make_envelope(ticket=unsigned))

    tampered = replace(make_ticket(), resource="endpoint-999")
    with pytest.raises(OpenCoreBoundaryError, match="Ticket signature"):
        verify(make_verifier(), make_envelope(ticket=tampered))


def test_unknown_authority_and_key_references_are_rejected():
    with pytest.raises(OpenCoreBoundaryError, match="authority"):
        verify(make_verifier(), make_envelope(authority_id="fw-root/unknown"))

    envelope = replace(make_envelope(), key_reference="fw-keys/unknown")
    with pytest.raises(OpenCoreBoundaryError, match="action signing key"):
        verify(make_verifier(), envelope)

    ticket = replace(make_ticket(), key_reference="fw-keys/unknown")
    envelope = replace(make_envelope(), ticket=ticket)
    with pytest.raises(OpenCoreBoundaryError, match="ticket signing key"):
        verify(make_verifier(), envelope)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tenant_id", "tenant-b"),
        ("subject_agent_id", "agent-b"),
        ("lease_id", "lease-b"),
        ("capability", "action.request"),
        ("resource", "endpoint-999"),
        ("action_class", "TERMINATE_PROCESS"),
        ("policy_version", "FW-ASOC-01-v2"),
    ],
)
def test_ticket_binding_mismatches_fail_closed(field, value):
    with pytest.raises(OpenCoreBoundaryError, match="binding mismatch"):
        verify(make_verifier(), make_envelope(), **{field: value})


def test_expired_or_not_yet_valid_ticket_is_rejected():
    with pytest.raises(OpenCoreBoundaryError, match="not currently valid"):
        verify(make_verifier(), make_envelope(), now=200)

    with pytest.raises(OpenCoreBoundaryError, match="not currently valid"):
        verify(make_verifier(), make_envelope(), now=99)


def test_action_and_ticket_replay_are_rejected():
    verifier = make_verifier()
    envelope = make_envelope()
    verify(verifier, envelope)

    with pytest.raises(OpenCoreBoundaryError, match="action replay"):
        verify(verifier, envelope)

    second = make_envelope(ticket=envelope.ticket, action_id="action-2", nonce="nonce-2")
    with pytest.raises(OpenCoreBoundaryError, match="Ticket replay"):
        verify(verifier, second)


@pytest.mark.parametrize(
    "safety",
    [
        {"mode": "LIVE", "deployment": "DISABLED", "kill_switch": "ENGAGED"},
        {"mode": "DRY_RUN", "deployment": "ENABLED", "kill_switch": "ENGAGED"},
        {"mode": "DRY_RUN", "deployment": "DISABLED", "kill_switch": "CLEARED_FOR_DRY_RUN"},
        {
            "mode": "DRY_RUN",
            "deployment": "DISABLED",
            "kill_switch": "ENGAGED",
            "mutation_allowed": True,
        },
    ],
)
def test_unsafe_runtime_state_is_rejected(safety):
    with pytest.raises(OpenCoreBoundaryError, match="safety state"):
        verify(make_verifier(), make_envelope(), safety_evidence=safety)


def test_consumed_ticket_is_rejected_even_with_valid_outer_signature():
    signer = make_signer()
    ticket = replace(make_ticket(), consumed_at=149)
    # consumed_at is intentionally not part of the canonical ticket signature;
    # the public boundary must independently reject it.
    envelope = signer.sign(
        SignedActionEnvelope(
            "1", "action-1", AUTHORITY, ENVELOPE_KEY, "nonce-1", ticket
        )
    )

    with pytest.raises(OpenCoreBoundaryError, match="consumed"):
        verify(make_verifier(), envelope)
