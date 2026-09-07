"""Non-executing, caller-supplied quarantine proposal boundary.

This module records only a bounded dry-run proposal.  It never opens paths,
stores or moves files, invokes endpoint APIs, or performs containment.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from threading import RLock
from typing import Any, Mapping

from .asoc import AuditSink
from .action_ticket import ActionTicketRegistry, ActionTicketError


MAX_QUARANTINE_PROPOSAL_BYTES = 1024 * 1024
MAX_QUARANTINE_ENTRIES = 128
MAX_QUARANTINE_TOTAL_BYTES = 4 * 1024 * 1024


class QuarantineProposalDenied(PermissionError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class QuarantineProposal:
    tenant_id: str
    device_id: str
    detection_id: str
    content_sha256: str
    content_bytes: int
    provenance: str
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"
    disposition: str = "PROPOSED"


@dataclass(frozen=True)
class QuarantineEntry:
    tenant_id: str
    device_id: str
    detection_id: str
    content_sha256: str
    content_bytes: bytes
    provenance: str
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"


class InMemoryQuarantineVault:
    """Bounded fixture-only vault; never touches a filesystem or endpoint."""

    def __init__(self, audit: AuditSink) -> None:
        if not callable(audit):
            raise ValueError("vault requires an audit sink")
        self._audit = audit
        self._lock = RLock()
        self._entries: dict[tuple[str, str, str], QuarantineEntry] = {}
        self._total_bytes = 0

    def admit(self, proposal: QuarantineProposal, content: bytes) -> QuarantineEntry:
        """Evidence-log then retain one exact proposal-bound fixture in memory."""
        if not isinstance(proposal, QuarantineProposal) or not isinstance(content, bytes):
            raise QuarantineProposalDenied("VAULT_INPUT_INVALID")
        if not content or len(content) > MAX_QUARANTINE_PROPOSAL_BYTES:
            raise QuarantineProposalDenied("CONTENT_INVALID")
        digest = hashlib.sha256(content).hexdigest()
        if digest != proposal.content_sha256 or len(content) != proposal.content_bytes:
            raise QuarantineProposalDenied("CONTENT_PROPOSAL_MISMATCH")
        key = (proposal.tenant_id, proposal.device_id, proposal.detection_id)
        with self._lock:
            if key in self._entries:
                raise QuarantineProposalDenied("VAULT_ENTRY_DUPLICATE")
            if len(self._entries) >= MAX_QUARANTINE_ENTRIES or self._total_bytes + len(content) > MAX_QUARANTINE_TOTAL_BYTES:
                raise QuarantineProposalDenied("VAULT_CAPACITY")
            entry = QuarantineEntry(
                tenant_id=proposal.tenant_id, device_id=proposal.device_id,
                detection_id=proposal.detection_id, content_sha256=digest,
                content_bytes=bytes(content), provenance=proposal.provenance,
            )
            try:
                self._audit("quarantine_fixture_stored", {
                    "tenant_id": entry.tenant_id, "device_id": entry.device_id,
                    "detection_id": entry.detection_id, "content_sha256": entry.content_sha256,
                    "content_bytes": len(entry.content_bytes), "provenance": entry.provenance,
                    "mode": entry.mode, "action": entry.action, "disposition": "STORED_IN_MEMORY",
                })
            except Exception as exc:
                raise QuarantineProposalDenied("EVIDENCE_WRITE_FAILED") from exc
            self._entries[key] = entry
            self._total_bytes += len(content)
            return entry

    def admit_with_ticket(
        self, proposal: QuarantineProposal, content: bytes, *,
        tickets: ActionTicketRegistry, ticket_id: str, subject_agent_id: str,
        lease_id: str, policy_version: str, now: int,
    ) -> QuarantineEntry:
        """Validate an existing signed ticket before simulated vault storage."""
        if not isinstance(tickets, ActionTicketRegistry):
            raise QuarantineProposalDenied("ACTION_TICKET_INVALID")
        try:
            tickets.validate(
                ticket_id, tenant_id=proposal.tenant_id, subject_agent_id=subject_agent_id,
                lease_id=lease_id, capability="endpoint.quarantine.propose",
                resource=proposal.detection_id, action_class="QUARANTINE_PROPOSAL",
                policy_version=policy_version, now=now,
            )
        except ActionTicketError as exc:
            raise QuarantineProposalDenied("ACTION_TICKET_DENIED") from exc
        return self.admit(proposal, content)

    def inspect(self, *, tenant_id: str, device_id: str, detection_id: str) -> QuarantineEntry | None:
        """Inspect one tenant/device-bound fixture without mutating vault state."""
        with self._lock:
            return self._entries.get((tenant_id, device_id, detection_id))

    def count(self) -> int:
        with self._lock:
            return len(self._entries)


def propose_quarantine(
    content: bytes, *, tenant_id: str, device_id: str, detection_id: str,
    provenance: str, confidence: str, trusted_content: bool,
    policy_decision: str, audit: AuditSink, kill_switch_state: str,
) -> QuarantineProposal:
    """Validate and Evidence-log a high-confidence proposal without containment."""
    if not isinstance(content, bytes) or not content or len(content) > MAX_QUARANTINE_PROPOSAL_BYTES:
        raise QuarantineProposalDenied("CONTENT_INVALID")
    if not callable(audit):
        raise QuarantineProposalDenied("EVIDENCE_UNAVAILABLE")
    values = {"tenant_id": tenant_id, "device_id": device_id, "detection_id": detection_id, "provenance": provenance}
    if any(not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 256 for value in values.values()):
        raise QuarantineProposalDenied("IDENTITY_INVALID")
    if confidence != "HIGH" or trusted_content is not True or policy_decision != "ALLOW_QUARANTINE":
        raise QuarantineProposalDenied("QUARANTINE_POLICY_DENIED")
    if kill_switch_state != "ENGAGED":
        raise QuarantineProposalDenied("KILL_SWITCH_BLOCKED")
    proposal = QuarantineProposal(
        tenant_id=tenant_id.strip(), device_id=device_id.strip(), detection_id=detection_id.strip(),
        content_sha256=hashlib.sha256(content).hexdigest(), content_bytes=len(content), provenance=provenance.strip(),
    )
    try:
        audit("quarantine_proposed", {
            "tenant_id": proposal.tenant_id, "device_id": proposal.device_id,
            "detection_id": proposal.detection_id, "content_sha256": proposal.content_sha256,
            "content_bytes": proposal.content_bytes, "provenance": proposal.provenance,
            "confidence": confidence, "trusted_content": trusted_content,
            "policy_decision": policy_decision, "mode": proposal.mode,
            "action": proposal.action, "disposition": proposal.disposition,
            "deployment": "DISABLED", "kill_switch": kill_switch_state,
        })
    except Exception as exc:
        raise QuarantineProposalDenied("EVIDENCE_WRITE_FAILED") from exc
    return proposal


def propose_quarantine_with_ticket(
    content: bytes, *, tenant_id: str, device_id: str, detection_id: str,
    provenance: str, confidence: str, trusted_content: bool,
    policy_decision: str, audit: AuditSink, kill_switch_state: str,
    tickets: ActionTicketRegistry, ticket_id: str, subject_agent_id: str,
    lease_id: str, policy_version: str, now: int,
) -> QuarantineProposal:
    """Validate a canonical ticket before recording a dry-run proposal."""
    if not isinstance(tickets, ActionTicketRegistry):
        raise QuarantineProposalDenied("ACTION_TICKET_INVALID")
    try:
        tickets.validate(
            ticket_id, tenant_id=tenant_id, subject_agent_id=subject_agent_id,
            lease_id=lease_id, capability="endpoint.quarantine.propose",
            resource=detection_id, action_class="QUARANTINE_PROPOSAL",
            policy_version=policy_version, now=now,
        )
    except ActionTicketError as exc:
        raise QuarantineProposalDenied("ACTION_TICKET_DENIED") from exc
    return propose_quarantine(
        content, tenant_id=tenant_id, device_id=device_id, detection_id=detection_id,
        provenance=provenance, confidence=confidence, trusted_content=trusted_content,
        policy_decision=policy_decision, audit=audit, kill_switch_state=kill_switch_state,
    )
