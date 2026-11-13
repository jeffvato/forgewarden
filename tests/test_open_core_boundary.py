from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from swarm.action_ticket import ActionTicket
from swarm.open_core_boundary import (
    OpenCoreBoundaryError,
    PublicActionVerifier,
    SignedActionEnvelope,
)


TICKET_KEY = "fw-keys/action-ticket-test"
ENVELOPE_KEY = "fw-keys/open-core-envelope-test"
AUTHORITY = "fw-root/private-core"


class PrivateEd25519Signer:
    """Test-only private-Core signer. Never passed to PublicActionVerifier."""

    def __init__(self, private_key):
        self._private_key = private_key

    def sign(self, value):
        return replace(value, signature=self._private_key.sign(value.canonical_bytes()).hex())


class PublicEd25519Verifier:
    """Verification-only public-side trust anchor."""

    def __init__(self, public_key: Ed25519PublicKey):
        self._public_key = public_key

    def verify(self, value):
        if not isinstance(value.signature, str) or not value.signature:
            raise InvalidSignature("signature missing")
        try:
            signature = bytes.fromhex(value.signature)
        except ValueError as exc:
            raise InvalidSignature("signature encoding invalid") from exc
        self._public_key.verify(signature, value.canonical_bytes())


@pytest.fixture
def crypto_material():
    ticket_private = Ed25519PrivateKey.generate()
    envelope_private = Ed25519PrivateKey.generate()
    return {
        "ticket_signer": PrivateEd25519Signer(ticket_private),
        "ticket_verifier": PublicEd25519Verifier(ticket_private.public_key()),
        "envelope_signer": PrivateEd25519Signer(envelope_private),
        "envelope_verifier": PublicEd25519Verifier(envelope_private.public_key()),
    }


def make_ticket(crypto_material, **overrides):
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
    return crypto_material["ticket_signer"].sign(ActionTicket(**values))


def make_envelope(crypto_material, ticket=None, **overrides):
    values = dict(
        schema_version="1",
        action_id="action-1",
        authority_id=AUTHORITY,
        key_reference=ENVELOPE_KEY,
        nonce="nonce-1",
        ticket=ticket or make_ticket(crypto_material),
    )
    values.update(overrides)
    return crypto_material["envelope_signer"].sign(SignedActionEnvelope(**values))


def make_verifier(crypto_material):
    return PublicActionVerifier(
        envelope_verifier=crypto_material["envelope_verifier"],
        ticket_verifier=crypto_material["ticket_verifier"],
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


def test_public_boundary_rejects_signer_capable_crypto_objects(crypto_material):
    with pytest.raises(OpenCoreBoundaryError, match="verification-only"):
        PublicActionVerifier(
            envelope_verifier=crypto_material["envelope_signer"],
            ticket_verifier=crypto_material["ticket_verifier"],
            trusted_authority_id=AUTHORITY,
            trusted_envelope_key_reference=ENVELOPE_KEY,
            trusted_ticket_key_reference=TICKET_KEY,
        )
    with pytest.raises(OpenCoreBoundaryError, match="verification-only"):
        PublicActionVerifier(
            envelope_verifier=crypto_material["envelope_verifier"],
            ticket_verifier=crypto_material["ticket_signer"],
            trusted_authority_id=AUTHORITY,
            trusted_envelope_key_reference=ENVELOPE_KEY,
            trusted_ticket_key_reference=TICKET_KEY,
        )


def test_valid_private_core_action_is_admitted_but_not_executable(crypto_material):
    admission = verify(
        make_verifier(crypto_material), make_envelope(crypto_material)
    )

    assert admission.authority_valid is True
    assert admission.execution_permitted is False
    assert admission.mode == "DRY_RUN"
    assert admission.deployment == "DISABLED"
    assert admission.ticket_id == "ticket-1"


def test_unsigned_action_envelope_is_rejected(crypto_material):
    envelope = replace(make_envelope(crypto_material), signature="")

    with pytest.raises(OpenCoreBoundaryError, match="envelope signature"):
        verify(make_verifier(crypto_material), envelope)


def test_tampered_action_envelope_is_rejected(crypto_material):
    envelope = replace(make_envelope(crypto_material), nonce="nonce-tampered")

    with pytest.raises(OpenCoreBoundaryError, match="envelope signature"):
        verify(make_verifier(crypto_material), envelope)


def test_unsigned_or_tampered_action_ticket_is_rejected(crypto_material):
    unsigned = replace(make_ticket(crypto_material), signature="")
    with pytest.raises(OpenCoreBoundaryError, match="Ticket signature"):
        verify(
            make_verifier(crypto_material),
            make_envelope(crypto_material, ticket=unsigned),
        )

    tampered = replace(make_ticket(crypto_material), resource="endpoint-999")
    with pytest.raises(OpenCoreBoundaryError, match="Ticket signature"):
        verify(
            make_verifier(crypto_material),
            make_envelope(crypto_material, ticket=tampered),
        )


def test_unknown_authority_and_key_references_are_rejected(crypto_material):
    with pytest.raises(OpenCoreBoundaryError, match="authority"):
        verify(
            make_verifier(crypto_material),
            make_envelope(crypto_material, authority_id="fw-root/unknown"),
        )

    envelope = replace(
        make_envelope(crypto_material), key_reference="fw-keys/unknown"
    )
    with pytest.raises(OpenCoreBoundaryError, match="action signing key"):
        verify(make_verifier(crypto_material), envelope)

    ticket = replace(
        make_ticket(crypto_material), key_reference="fw-keys/unknown"
    )
    envelope = replace(make_envelope(crypto_material), ticket=ticket)
    with pytest.raises(OpenCoreBoundaryError, match="ticket signing key"):
        verify(make_verifier(crypto_material), envelope)


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
def test_ticket_binding_mismatches_fail_closed(crypto_material, field, value):
    with pytest.raises(OpenCoreBoundaryError, match="binding mismatch"):
        verify(
            make_verifier(crypto_material),
            make_envelope(crypto_material),
            **{field: value},
        )


def test_expired_or_not_yet_valid_ticket_is_rejected(crypto_material):
    with pytest.raises(OpenCoreBoundaryError, match="not currently valid"):
        verify(
            make_verifier(crypto_material), make_envelope(crypto_material), now=200
        )

    with pytest.raises(OpenCoreBoundaryError, match="not currently valid"):
        verify(
            make_verifier(crypto_material), make_envelope(crypto_material), now=99
        )


def test_action_and_ticket_replay_are_rejected(crypto_material):
    verifier = make_verifier(crypto_material)
    envelope = make_envelope(crypto_material)
    verify(verifier, envelope)

    with pytest.raises(OpenCoreBoundaryError, match="action replay"):
        verify(verifier, envelope)

    second = make_envelope(
        crypto_material,
        ticket=envelope.ticket,
        action_id="action-2",
        nonce="nonce-2",
    )
    with pytest.raises(OpenCoreBoundaryError, match="Ticket replay"):
        verify(verifier, second)


@pytest.mark.parametrize(
    "safety",
    [
        {"mode": "LIVE", "deployment": "DISABLED", "kill_switch": "ENGAGED"},
        {"mode": "DRY_RUN", "deployment": "ENABLED", "kill_switch": "ENGAGED"},
        {
            "mode": "DRY_RUN",
            "deployment": "DISABLED",
            "kill_switch": "CLEARED_FOR_DRY_RUN",
        },
        {
            "mode": "DRY_RUN",
            "deployment": "DISABLED",
            "kill_switch": "ENGAGED",
            "mutation_allowed": True,
        },
    ],
)
def test_unsafe_runtime_state_is_rejected(crypto_material, safety):
    with pytest.raises(OpenCoreBoundaryError, match="safety state"):
        verify(
            make_verifier(crypto_material),
            make_envelope(crypto_material),
            safety_evidence=safety,
        )


def test_consumed_ticket_is_rejected_even_with_valid_outer_signature(crypto_material):
    ticket = replace(make_ticket(crypto_material), consumed_at=149)
    # consumed_at is intentionally not part of the canonical ticket signature;
    # the public boundary must independently reject it.
    envelope = crypto_material["envelope_signer"].sign(
        SignedActionEnvelope(
            "1", "action-1", AUTHORITY, ENVELOPE_KEY, "nonce-1", ticket
        )
    )

    with pytest.raises(OpenCoreBoundaryError, match="consumed"):
        verify(make_verifier(crypto_material), envelope)


def test_concurrent_replay_allows_exactly_one_admission(crypto_material):
    verifier = make_verifier(crypto_material)
    envelope = make_envelope(crypto_material)

    def admit(_value):
        try:
            verify(verifier, envelope)
            return True
        except OpenCoreBoundaryError:
            return False

    with ThreadPoolExecutor(max_workers=2) as workers:
        assert sum(workers.map(admit, range(2))) == 1
