"""Non-executing, caller-supplied quarantine proposal boundary.

This module records only a bounded dry-run proposal.  It never opens paths,
stores or moves files, invokes endpoint APIs, or performs containment.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Mapping

from .asoc import AuditSink


MAX_QUARANTINE_PROPOSAL_BYTES = 1024 * 1024


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
