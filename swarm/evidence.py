"""Canonical authority-free FW-EVID envelope metadata contract.

Payload producers retain ownership of their schemas.  This envelope binds a
payload digest and bounded references without storing the payload or granting
append, signing, export, policy, or response authority.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping


CLASSIFICATIONS = frozenset({"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"})
_FIELDS = frozenset({
    "schema_version", "evidence_id", "tenant_id", "event_type", "actor_ref",
    "actor_tenant_id", "subject_ref", "subject_tenant_id", "occurred_at",
    "classification", "payload_schema_id", "payload_sha256",
    "previous_record_sha256", "correlation_id", "evidence_references",
    "mode", "deployment", "authority_granted",
})
_TENANT = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_EVIDENCE = re.compile(r"^fw-evid/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/-]{0,191}$")
_CORRELATION = re.compile(r"^fw-corr/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/-]{0,191}$")
_REF = re.compile(r"^fw-(?:id|task|resource|incident|action|model)/[a-z][a-z0-9_.:/-]{0,191}$")
_EVENT = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_SCHEMA = re.compile(r"^fw-schema/[a-z][a-z0-9_.:/-]{0,191}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SECRET = re.compile(
    r"(?i)(bearer\s+\S+|sk-[a-z0-9_-]{8,}|AIza[a-z0-9_-]{8,}|"
    r"ya29\.[a-z0-9._-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:access|refresh)[_-]?token\s*[:=]|(?:api[_-]?key|client[_-]?secret|password)\s*[:=])"
)


class EvidenceContractError(ValueError):
    """Untrusted metadata violates the canonical FW-EVID envelope contract."""


def _text(value: Any, field: str, pattern: re.Pattern[str], maximum: int = 256) -> str:
    if (
        not isinstance(value, str) or not value or value != value.strip()
        or len(value.encode("utf-8")) > maximum or not pattern.fullmatch(value)
        or _SECRET.search(value)
    ):
        raise EvidenceContractError(f"{field} is invalid or secret-bearing")
    return value


@dataclass(frozen=True)
class EvidenceEnvelope:
    schema_version: str
    evidence_id: str
    tenant_id: str
    event_type: str
    actor_ref: str
    actor_tenant_id: str
    subject_ref: str
    subject_tenant_id: str
    occurred_at: str
    classification: str
    payload_schema_id: str
    payload_sha256: str
    previous_record_sha256: str | None
    correlation_id: str | None
    evidence_references: tuple[str, ...]
    mode: str
    deployment: str
    authority_granted: bool

    def __post_init__(self) -> None:
        if self.schema_version != "1":
            raise EvidenceContractError("unsupported Evidence schema version")
        tenant = _text(self.tenant_id, "tenant_id", _TENANT, 128)
        evidence_match = _EVIDENCE.fullmatch(_text(self.evidence_id, "evidence_id", _EVIDENCE))
        assert evidence_match is not None
        if evidence_match.group(1) != tenant:
            raise EvidenceContractError("evidence_id tenant mismatch")
        _text(self.event_type, "event_type", _EVENT, 128)
        _text(self.actor_ref, "actor_ref", _REF)
        _text(self.subject_ref, "subject_ref", _REF)
        if self.actor_tenant_id != tenant or self.subject_tenant_id != tenant:
            raise EvidenceContractError("actor or subject tenant mismatch")
        if not _TIMESTAMP.fullmatch(self.occurred_at):
            raise EvidenceContractError("occurred_at must be canonical UTC")
        try:
            datetime.strptime(self.occurred_at, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise EvidenceContractError("occurred_at is invalid") from exc
        if self.classification not in CLASSIFICATIONS:
            raise EvidenceContractError("classification is invalid")
        _text(self.payload_schema_id, "payload_schema_id", _SCHEMA)
        if not isinstance(self.payload_sha256, str) or not _SHA256.fullmatch(self.payload_sha256):
            raise EvidenceContractError("payload_sha256 is invalid")
        if self.previous_record_sha256 is not None and (
            not isinstance(self.previous_record_sha256, str)
            or not _SHA256.fullmatch(self.previous_record_sha256)
        ):
            raise EvidenceContractError("previous_record_sha256 is invalid")
        if self.correlation_id is not None:
            correlation = _CORRELATION.fullmatch(_text(self.correlation_id, "correlation_id", _CORRELATION))
            assert correlation is not None
            if correlation.group(1) != tenant:
                raise EvidenceContractError("correlation_id tenant mismatch")
        if (
            not isinstance(self.evidence_references, tuple)
            or len(self.evidence_references) > 128
            or len(set(self.evidence_references)) != len(self.evidence_references)
            or tuple(sorted(self.evidence_references)) != self.evidence_references
        ):
            raise EvidenceContractError("evidence_references must be a bounded unique sorted tuple")
        for reference in self.evidence_references:
            matched = _EVIDENCE.fullmatch(_text(reference, "evidence reference", _EVIDENCE))
            assert matched is not None
            if matched.group(1) != tenant:
                raise EvidenceContractError("evidence reference tenant mismatch")
        if self.mode != "DRY_RUN" or self.deployment != "DISABLED" or self.authority_granted is not False:
            raise EvidenceContractError("Evidence envelope cannot grant authority")


def validate_evidence_envelope(value: Mapping[str, Any]) -> EvidenceEnvelope:
    """Validate an exact untrusted mapping without retaining unknown or raw payload fields."""
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise EvidenceContractError("Evidence envelope field set is invalid")
    return EvidenceEnvelope(**{field: value[field] for field in _FIELDS})
