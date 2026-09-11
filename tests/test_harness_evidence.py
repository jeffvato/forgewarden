from dataclasses import replace

import pytest

from swarm.harness_context import ContextItem, build_context_packet
from swarm.evidence import EvidenceLedger
from swarm.harness_evidence import (
    HarnessEvidenceError,
    HarnessLifecycleEvidence,
    append_harness_evidence,
    emit_harness_evidence,
    harness_lifecycle_payload_sha256,
)
from swarm.harness_task import HarnessTask, TaskStatus
from swarm.harness_worker import WorkerOutput, WorkerRegistration, WorkerRole, WorkerTransport


NOW = "2026-09-09T00:00:00Z"


def task(**changes):
    value = HarnessTask(
        "FWQ-0074", "FW-HARNESS-009", "Evidence", "lifecycle evidence",
        TaskStatus.AWAITING_REVIEW, 0, "CODEX", "gpt-approved", "/repo", NOW,
        authorized_capabilities=("source.write",), relevant_files=("swarm/harness_evidence.py",),
        validation_requirements=("pytest",), retry_limit=1,
    )
    return replace(value, **changes)


def context(value):
    return build_context_packet(value, (
        ContextItem("architecture_constraint", "harness", "AI has no authority"),
        ContextItem("forbidden_change", "deployment", "deployment remains disabled"),
    ))


def worker():
    return WorkerRegistration("codex-cli", "openai", "gpt-approved", WorkerTransport.CLI, (WorkerRole.CODE_WRITER,), True, executable="codex")


def output(value, packet, **changes):
    base = WorkerOutput(value.task_id, "codex-cli", packet.sha256, "a" * 40, ("swarm/harness_evidence.py",), ("edit scoped source",), (), "bounded change")
    return replace(base, **changes)


def emit(**changes):
    value = changes.pop("task", task())
    packet = changes.pop("context", context(value))
    sink = changes.pop("evidence_sink", lambda event, payload: None)
    args = dict(event="review_completed", tenant_id="tenant-one", task_tenant_id="tenant-one", actor_id="controller-one", task=value, context=packet,
                evidence_sink=sink, worker=worker(), worker_output=output(value, packet), tests_executed=("pytest",),
                test_results=("119 passed",), reviewer_findings=("APPROVE LOW",), policy_decision="PASSED",
                acceptance_decision="ACCEPTED", timestamp=NOW, resulting_commit="a" * 40,
                checkpoint_references=("docs/checkpoint.json",))
    args.update(changes)
    return emit_harness_evidence(**args)


def test_valid_lifecycle_is_written_once_before_success_returns():
    calls = []
    result = emit(evidence_sink=lambda event, payload: calls.append((event, payload)))
    assert result.task_id == "FWQ-0074" and result.deployment == "DISABLED"
    assert result.context_sha256 == calls[0][1]["context_sha256"]
    assert len(calls) == 1 and calls[0][0] == "fw_harness_lifecycle"


def test_evidence_failure_denies_without_result():
    def fail(event, payload):
        raise RuntimeError("offline")
    with pytest.raises(HarnessEvidenceError, match="write failed"):
        emit(evidence_sink=fail)


def test_task_context_binding_mismatch_denies_before_sink():
    first = task()
    mismatched = replace(context(first), task_id="FWQ-9999")
    calls = []
    with pytest.raises(HarnessEvidenceError, match="do not match"):
        emit(task=first, context=mismatched, evidence_sink=lambda *args: calls.append(args))
    assert calls == []


@pytest.mark.parametrize("changes,match", [
    ({"tenant_id": "bad tenant"}, "tenant"),
    ({"event": "model_says_complete"}, "event"),
    ({"policy_decision": "MODEL_APPROVED"}, "decision"),
    ({"acceptance_decision": "CONFIDENT"}, "decision"),
    ({"timestamp": "2026-09-09"}, "timezone"),
    ({"resulting_commit": "HEAD"}, "commit"),
])
def test_malformed_authority_facts_deny(changes, match):
    with pytest.raises(HarnessEvidenceError, match=match):
        emit(**changes)


def test_worker_task_and_context_substitution_denies():
    value = task()
    packet = context(value)
    bad = output(value, packet, worker_id="other-worker")
    with pytest.raises(HarnessEvidenceError, match="binding"):
        emit(task=value, context=packet, worker_output=bad)


def test_cross_tenant_task_binding_denies():
    with pytest.raises(HarnessEvidenceError, match="tenant"):
        emit(task_tenant_id="tenant-two")


def test_worker_candidate_must_match_resulting_commit():
    value = task()
    packet = context(value)
    bad = output(value, packet, candidate_commit="b" * 40)
    with pytest.raises(HarnessEvidenceError, match="candidate"):
        emit(task=value, context=packet, worker_output=bad)


def test_changed_file_scope_escape_denies_before_sink():
    value = task()
    packet = context(value)
    bad = output(value, packet, changed_files=("swarm/other.py",))
    calls = []
    with pytest.raises(HarnessEvidenceError, match="outside"):
        emit(task=value, context=packet, worker_output=bad, evidence_sink=lambda *args: calls.append(args))
    assert calls == []


@pytest.mark.parametrize("field,value", [
    ("reviewer_findings", ("Bearer abc.def",)),
    ("test_results", ("api_key=secret-value",)),
    ("checkpoint_references", ("../outside.json",)),
])
def test_secret_and_path_escape_input_denies(field, value):
    with pytest.raises(HarnessEvidenceError):
        emit(**{field: value})


def test_worker_model_substitution_denies_without_output():
    value = task()
    wrong = replace(worker(), model_id="other-model")
    with pytest.raises(HarnessEvidenceError, match="model"):
        emit_harness_evidence(event="task_started", tenant_id="tenant-one", task_tenant_id="tenant-one", actor_id="controller-one", task=value,
                              context=context(value), evidence_sink=lambda *args: None, worker=wrong, timestamp=NOW)


def test_lifecycle_collections_are_bounded():
    with pytest.raises(HarnessEvidenceError, match="excessive"):
        emit(test_results=tuple(f"result-{index}" for index in range(257)))


def test_canonical_adapter_binds_exact_payload_and_chain():
    durable = []
    ledger = EvidenceLedger("tenant-one", lambda envelope, digest: durable.append((envelope, digest)))
    first = emit()
    first_record = append_harness_evidence(
        first, ledger=ledger, correlation_id="fw-corr/tenant-one/fwq-0074",
    )
    assert first_record.envelope.payload_sha256 == harness_lifecycle_payload_sha256(first)
    assert first_record.envelope.actor_ref == "fw-id/controller-one"
    assert first_record.envelope.subject_ref == "fw-task/fwq-0074"
    assert first_record.envelope.previous_record_sha256 is None
    second = replace(first, event="task_checkpointed", timestamp="2026-09-09T00:00:01Z")
    second_record = append_harness_evidence(second, ledger=ledger)
    assert second_record.envelope.previous_record_sha256 == first_record.record_sha256
    assert tuple(record.record_sha256 for record in ledger.tenant_snapshot("tenant-one")) == (
        first_record.record_sha256, second_record.record_sha256,
    )
    assert len(durable) == 2


def test_canonical_adapter_rejects_replay_cross_tenant_and_invalid_payload():
    ledger = EvidenceLedger("tenant-one", lambda *_args: None)
    lifecycle = emit()
    append_harness_evidence(lifecycle, ledger=ledger)
    with pytest.raises(HarnessEvidenceError, match="admission"):
        append_harness_evidence(lifecycle, ledger=ledger)
    other = EvidenceLedger("tenant-two", lambda *_args: None)
    with pytest.raises(HarnessEvidenceError, match="tenant"):
        append_harness_evidence(lifecycle, ledger=other)
    fabricated = replace(lifecycle, mode="LIVE")
    with pytest.raises(HarnessEvidenceError, match="cannot grant authority"):
        append_harness_evidence(fabricated, ledger=ledger)
    with pytest.raises(HarnessEvidenceError, match="required"):
        append_harness_evidence({"tenant_id": "tenant-one"}, ledger=ledger)  # type: ignore[arg-type]


def test_canonical_adapter_denies_durability_failure_without_admission():
    def fail(_envelope, _digest):
        raise RuntimeError("offline")
    ledger = EvidenceLedger("tenant-one", fail)
    with pytest.raises(HarnessEvidenceError, match="admission"):
        append_harness_evidence(emit(), ledger=ledger)
    assert ledger.tenant_snapshot("tenant-one") == ()


@pytest.mark.parametrize("changes", [
    {"classification": "SECRET"},
    {"correlation_id": "fw-corr/tenant-two/fwq-0074"},
    {"evidence_references": ("fw-evid/tenant-two/other",)},
])
def test_canonical_adapter_denies_metadata_substitution(changes):
    ledger = EvidenceLedger("tenant-one", lambda *_args: None)
    with pytest.raises((HarnessEvidenceError, ValueError)):
        append_harness_evidence(emit(), ledger=ledger, **changes)


def test_canonical_adapter_retains_no_raw_payload_or_secret_material():
    ledger = EvidenceLedger("tenant-one", lambda *_args: None)
    lifecycle = emit(reviewer_findings=("bounded result",))
    record = append_harness_evidence(lifecycle, ledger=ledger)
    envelope_text = repr(record.envelope)
    assert "bounded result" not in envelope_text
    assert not hasattr(record.envelope, "payload")
    assert record.envelope.authority_granted is False
