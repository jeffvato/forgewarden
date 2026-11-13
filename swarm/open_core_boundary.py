"""Public-side verification boundary for proprietary ForgeWarden Core actions.

This module intentionally owns no policy decision, ticket issuance, key material,
or execution authority. It verifies a privately produced signed envelope and the
canonical Action Ticket it carries, then returns a dry-run admission record.

The design keeps ForgeWarden's public edge useful without allowing the public
component to manufacture privileged authority.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from threading import Lock
from typing import Any, Mapping, Protocol

from .action_ticket import ActionTicket
from .policy_gate import validate_safety_evidence


class OpenCoreBoundaryError(ValueError):
    """A Core-originated action cannot be admitted at the public boundary."""


class ActionEnvelopeSigner(Protocol):
    def sign(self, envelope: "SignedActionEnvelope") -> "SignedActionEnvelope": ...
    def verify(self, envelope: "SignedActionEnvelope") -> None: ...


class ActionTicketVerifier(Protocol):
    def verify(self, ticket: ActionTicket) -> None: ...


def _text(value: Any, field: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
    ):
        raise OpenCoreBoundaryError(f"{field} must be a non-empty bounded string")
    return value


@dataclass(frozen=True)
class SignedActionEnvelope:
    """Detached signed wrapper around an already-signed canonical Action Ticket."""

    schema_version: str
    action_id: str
    authority_id: str
    key_reference: str
    nonce: str
    ticket: ActionTicket
    signature: str = ""

    def __post_init__(self) -> None:
        if self.schema_version != "1":
            raise OpenCoreBoundaryError("unsupported action-envelope schema version")
        for field in ("action_id", "authority_id", "key_reference", "nonce"):
            object.__setattr__(self, field, _text(getattr(self, field), field))
        if not isinstance(self.ticket, ActionTicket):
            raise OpenCoreBoundaryError("canonical Action Ticket is required")
        if not isinstance(self.signature, str):
            raise OpenCoreBoundaryError("action envelope signature must be text")

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "action_id": self.action_id,
            "authority_id": self.authority_id,
            "key_reference": self.key_reference,
            "nonce": self.nonce,
            "ticket": {
                **self.ticket.unsigned_dict(),
                "signature": self.ticket.signature,
            },
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.unsigned_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")


@dataclass(frozen=True)
class PublicActionAdmission:
    action_id: str
    ticket_id: str
    tenant_id: str
    subject_agent_id: str
    lease_id: str
    capability: str
    resource: str
    action_class: str
    policy_version: str
    authority_id: str
    admitted_at: int
    mode: str = "DRY_RUN"
    deployment: str = "DISABLED"
    authority_valid: bool = True
    execution_permitted: bool = False


class PublicActionVerifier:
    """Fail-closed public verifier for actions produced by the private Core.

    Successful verification consumes the action/ticket identifiers in this
    verifier instance to prevent local replay. It still grants no execution
    authority while ForgeWarden is in its current dry-run deployment posture.
    """

    def __init__(
        self,
        *,
        envelope_signer: ActionEnvelopeSigner,
        ticket_verifier: ActionTicketVerifier,
        trusted_authority_id: str,
        trusted_envelope_key_reference: str,
        trusted_ticket_key_reference: str,
    ):
        if not hasattr(envelope_signer, "verify") or not hasattr(ticket_verifier, "verify"):
            raise OpenCoreBoundaryError("cryptographic verifiers are required")
        self._envelope_signer = envelope_signer
        self._ticket_verifier = ticket_verifier
        self._trusted_authority_id = _text(trusted_authority_id, "trusted_authority_id")
        self._trusted_envelope_key_reference = _text(
            trusted_envelope_key_reference, "trusted_envelope_key_reference"
        )
        self._trusted_ticket_key_reference = _text(
            trusted_ticket_key_reference, "trusted_ticket_key_reference"
        )
        self._consumed_action_ids: set[str] = set()
        self._consumed_ticket_ids: set[str] = set()
        self._lock = Lock()

    def verify(
        self,
        envelope: SignedActionEnvelope,
        *,
        tenant_id: str,
        subject_agent_id: str,
        lease_id: str,
        capability: str,
        resource: str,
        action_class: str,
        policy_version: str,
        now: int,
        safety_evidence: Mapping[str, Any],
    ) -> PublicActionAdmission:
        if not isinstance(envelope, SignedActionEnvelope):
            raise OpenCoreBoundaryError("validated signed action envelope is required")
        if not isinstance(now, int) or isinstance(now, bool):
            raise OpenCoreBoundaryError("deterministic verification time is required")
        expected = {
            "tenant_id": _text(tenant_id, "tenant_id"),
            "subject_agent_id": _text(subject_agent_id, "subject_agent_id"),
            "lease_id": _text(lease_id, "lease_id"),
            "capability": _text(capability, "capability"),
            "resource": _text(resource, "resource"),
            "action_class": _text(action_class, "action_class"),
            "policy_version": _text(policy_version, "policy_version"),
        }

        if envelope.authority_id != self._trusted_authority_id:
            raise OpenCoreBoundaryError("action authority is not trusted")
        if envelope.key_reference != self._trusted_envelope_key_reference:
            raise OpenCoreBoundaryError("action signing key reference is not trusted")
        if envelope.ticket.key_reference != self._trusted_ticket_key_reference:
            raise OpenCoreBoundaryError("ticket signing key reference is not trusted")

        try:
            self._envelope_signer.verify(envelope)
        except Exception as exc:
            raise OpenCoreBoundaryError("action envelope signature verification failed") from exc
        try:
            self._ticket_verifier.verify(envelope.ticket)
        except Exception as exc:
            raise OpenCoreBoundaryError("Action Ticket signature verification failed") from exc

        ticket = envelope.ticket
        if ticket.consumed_at is not None:
            raise OpenCoreBoundaryError("consumed Action Ticket rejected")
        if now < ticket.issued_at or now >= ticket.expires_at:
            raise OpenCoreBoundaryError("Action Ticket is not currently valid")
        if any(getattr(ticket, field) != value for field, value in expected.items()):
            raise OpenCoreBoundaryError("Action Ticket binding mismatch")

        try:
            safety = validate_safety_evidence(safety_evidence, require_kill_switch=True)
        except Exception as exc:
            raise OpenCoreBoundaryError("public action safety state rejected") from exc

        with self._lock:
            if envelope.action_id in self._consumed_action_ids:
                raise OpenCoreBoundaryError("action replay rejected")
            if ticket.ticket_id in self._consumed_ticket_ids:
                raise OpenCoreBoundaryError("Action Ticket replay rejected")
            self._consumed_action_ids.add(envelope.action_id)
            self._consumed_ticket_ids.add(ticket.ticket_id)

        return PublicActionAdmission(
            action_id=envelope.action_id,
            ticket_id=ticket.ticket_id,
            tenant_id=ticket.tenant_id,
            subject_agent_id=ticket.subject_agent_id,
            lease_id=ticket.lease_id,
            capability=ticket.capability,
            resource=ticket.resource,
            action_class=ticket.action_class,
            policy_version=ticket.policy_version,
            authority_id=envelope.authority_id,
            admitted_at=now,
            mode=safety["mode"],
            deployment=safety["deployment"],
        )
