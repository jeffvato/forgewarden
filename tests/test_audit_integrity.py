import hashlib
import json
from pathlib import Path

import pytest

from swarm.audit_integrity import AuditIntegrityError, read_audit_events


def _record(event="queued", state="QUEUED", **extra):
    value = {"timestamp": "2026-08-23T12:00:00Z", "job_id": "phase2a-fwq000900000000000000000", "state": state, "event": event}
    value.update(extra)
    return value


def _write(path: Path, records):
    path.write_bytes(b"".join(json.dumps(record, separators=(",", ":")).encode() + b"\n" for record in records))


def test_reads_bounded_redacted_summaries_without_mutating_source(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, [_record(data="api_token=secret")])
    before = path.read_bytes()
    result = read_audit_events(path, audit_root=tmp_path)
    assert result[0]["data"] == "api_token=[REDACTED]"
    assert path.read_bytes() == before


def test_rejects_malformed_truncated_and_mixed_job_records(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"not-json\n")
    with pytest.raises(AuditIntegrityError):
        read_audit_events(path, audit_root=tmp_path)
    path.write_bytes(json.dumps(_record()).encode())
    with pytest.raises(AuditIntegrityError, match="truncated"):
        read_audit_events(path, audit_root=tmp_path)
    _write(path, [_record(), {**_record(event="started"), "job_id": "phase2a-other00000000000000000000"}])
    with pytest.raises(AuditIntegrityError, match="job id"):
        read_audit_events(path, expected_job_id="phase2a-fwq000900000000000000000", audit_root=tmp_path)


def test_rejects_symlink_and_duplicate_terminal_event(tmp_path):
    path = tmp_path / "audit.jsonl"
    target = tmp_path / "real.jsonl"
    _write(target, [_record(event="done", state="SUCCEEDED"), _record(event="done", state="SUCCEEDED")])
    path.symlink_to(target)
    with pytest.raises(AuditIntegrityError, match="symlink"):
        read_audit_events(path, audit_root=tmp_path)
    path.unlink()
    path.write_bytes(target.read_bytes())
    with pytest.raises(AuditIntegrityError, match="duplicate terminal"):
        read_audit_events(path, audit_root=tmp_path)


def test_valid_hash_chain_is_accepted_and_broken_chain_rejected(tmp_path):
    first = _record()
    first["event_sha256"] = hashlib.sha256(json.dumps(first, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    second = _record(event="started", state="RUNNING", previous_event_sha256=first["event_sha256"])
    second["event_sha256"] = hashlib.sha256(json.dumps(second, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    path = tmp_path / "audit.jsonl"
    _write(path, [first, second])
    assert len(read_audit_events(path, audit_root=tmp_path)) == 2
    second["previous_event_sha256"] = "0" * 64
    _write(path, [first, second])
    with pytest.raises(AuditIntegrityError, match="chain"):
        read_audit_events(path, audit_root=tmp_path)
