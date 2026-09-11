"""Canonical authority-free FW-EVID envelope metadata contract.

Payload producers retain ownership of their schemas.  This envelope binds a
payload digest and bounded references without storing the payload or granting
append, signing, export, policy, or response authority.
"""
from __future__ import annotations

import re
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping
from threading import Lock


MAX_LEDGER_BYTES = 4 * 1024 * 1024
MAX_LEDGER_RECORDS = 4096
MAX_LEDGER_LINE_BYTES = 64 * 1024
_DURABLE_FIELDS = frozenset({"record_type", "envelope", "record_sha256"})


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


@dataclass(frozen=True)
class EvidenceRecord:
    """One immutable envelope and its deterministic content digest."""

    envelope: EvidenceEnvelope
    record_sha256: str


def evidence_record_sha256(envelope: EvidenceEnvelope) -> str:
    """Hash every canonical envelope field without accepting a raw payload."""
    if not isinstance(envelope, EvidenceEnvelope):
        raise EvidenceContractError("validated Evidence envelope is required")
    body = {field: getattr(envelope, field) for field in sorted(_FIELDS)}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


class EvidenceLedger:
    """Create-once tenant ledger with write-before-state chain admission."""

    def __init__(self, tenant_id: str, durability_sink: Any):
        self.tenant_id = _text(tenant_id, "tenant_id", _TENANT, 128)
        if not callable(durability_sink):
            raise EvidenceContractError("Evidence ledger requires a durability sink")
        self._durability_sink = durability_sink
        self._records: list[EvidenceRecord] = []
        self._evidence_ids: set[str] = set()
        self._record_hashes: set[str] = set()
        self._pending = False
        self._lock = Lock()

    def append(self, envelope: EvidenceEnvelope) -> EvidenceRecord:
        if not isinstance(envelope, EvidenceEnvelope):
            raise EvidenceContractError("validated Evidence envelope is required")
        if envelope.tenant_id != self.tenant_id:
            raise EvidenceContractError("Evidence ledger tenant mismatch")
        digest = evidence_record_sha256(envelope)
        with self._lock:
            if self._pending:
                raise EvidenceContractError("Evidence append is already pending")
            expected_previous = self._records[-1].record_sha256 if self._records else None
            if envelope.previous_record_sha256 != expected_previous:
                raise EvidenceContractError("Evidence previous-record link is stale or forked")
            if envelope.evidence_id in self._evidence_ids or digest in self._record_hashes:
                raise EvidenceContractError("Evidence record is a duplicate or replay")
            self._pending = True
        record = EvidenceRecord(envelope, digest)
        try:
            try:
                self._durability_sink(envelope, digest)
            except Exception as exc:
                raise EvidenceContractError("Evidence durability write failed") from exc
            with self._lock:
                expected_previous = self._records[-1].record_sha256 if self._records else None
                if envelope.previous_record_sha256 != expected_previous:
                    raise EvidenceContractError("Evidence chain changed during append")
                self._records.append(record)
                self._evidence_ids.add(envelope.evidence_id)
                self._record_hashes.add(digest)
        finally:
            with self._lock:
                self._pending = False
        return record

    def tenant_snapshot(self, tenant_id: str) -> tuple[EvidenceRecord, ...]:
        if tenant_id != self.tenant_id:
            raise EvidenceContractError("Evidence ledger tenant mismatch")
        with self._lock:
            return tuple(self._records)

    def _recover(self, records: tuple[EvidenceRecord, ...]) -> None:
        """Install an already-verified chain into a new empty ledger."""
        with self._lock:
            if self._records or self._pending:
                raise EvidenceContractError("Evidence ledger recovery requires empty state")
            self._records.extend(records)
            self._evidence_ids.update(record.envelope.evidence_id for record in records)
            self._record_hashes.update(record.record_sha256 for record in records)


class CanonicalAuditEvidenceStore:
    """Existing private AuditLog adapted as canonical ledger durability."""

    def __init__(self, audit_log: Any):
        from .core import AuditLog
        if not isinstance(audit_log, AuditLog):
            raise EvidenceContractError("canonical Evidence requires the trusted AuditLog")
        self.audit_log = audit_log

    def __call__(self, envelope: EvidenceEnvelope, record_sha256: str) -> None:
        try:
            self.audit_log.record_canonical_evidence(envelope, record_sha256)
        except Exception as exc:
            raise EvidenceContractError("canonical AuditLog write failed") from exc

    def recover(self, tenant_id: str) -> EvidenceLedger:
        records = read_canonical_audit_records(self.audit_log.path, tenant_id)
        ledger = EvidenceLedger(tenant_id, self)
        ledger._recover(records)
        return ledger


def read_canonical_audit_records(path: Any, tenant_id: str) -> tuple[EvidenceRecord, ...]:
    """Read and verify an exact canonical-only AuditLog stream for restart recovery."""
    from .core import read_restricted_bytes
    tenant = _text(tenant_id, "tenant_id", _TENANT, 128)
    path = Path(path)
    if not path.exists():
        return ()
    try:
        raw = read_restricted_bytes(path, "canonical Evidence audit")
    except Exception as exc:
        raise EvidenceContractError("canonical Evidence audit cannot be read") from exc
    if len(raw) > MAX_LEDGER_BYTES or (raw and not raw.endswith(b"\n")):
        raise EvidenceContractError("canonical Evidence audit is oversized or truncated")
    lines = raw.splitlines()
    if len(lines) > MAX_LEDGER_RECORDS:
        raise EvidenceContractError("canonical Evidence audit has too many records")
    records: list[EvidenceRecord] = []
    ids: set[str] = set()
    hashes: set[str] = set()
    previous: str | None = None
    for line in lines:
        if not line or len(line) > MAX_LEDGER_LINE_BYTES:
            raise EvidenceContractError("canonical Evidence audit contains an invalid line")
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise EvidenceContractError("canonical Evidence audit contains malformed JSON") from exc
        if not isinstance(value, Mapping) or set(value) != _DURABLE_FIELDS or value.get("record_type") != "fw_evidence_v1":
            raise EvidenceContractError("canonical Evidence audit contains mixed or substituted records")
        envelope_value = value.get("envelope")
        if isinstance(envelope_value, Mapping) and isinstance(envelope_value.get("evidence_references"), list):
            envelope_value = dict(envelope_value)
            envelope_value["evidence_references"] = tuple(envelope_value["evidence_references"])
        envelope = validate_evidence_envelope(envelope_value)
        digest = evidence_record_sha256(envelope)
        if value.get("record_sha256") != digest:
            raise EvidenceContractError("canonical Evidence audit record digest mismatch")
        if envelope.tenant_id != tenant or envelope.previous_record_sha256 != previous:
            raise EvidenceContractError("canonical Evidence audit tenant or chain mismatch")
        if envelope.evidence_id in ids or digest in hashes:
            raise EvidenceContractError("canonical Evidence audit contains duplicate or replayed records")
        records.append(EvidenceRecord(envelope, digest))
        ids.add(envelope.evidence_id)
        hashes.add(digest)
        previous = digest
    return tuple(records)
