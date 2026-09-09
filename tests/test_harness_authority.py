from dataclasses import asdict, replace

import pytest

from swarm.harness_authority import HarnessAuthorityError, HarnessAuthorityRequest, HarnessOperation, admit_harness_authority
from swarm.harness_task import HarnessTask, TaskStatus
from swarm.harness_worker import WorkerRegistration, WorkerRole, WorkerTransport


def task():
    return HarnessTask("FWQ-0075", "FW-HARNESS-010", "Authority", "admission", TaskStatus.READY, 0, "CODEX", "gpt-approved", "/repo", "2026-09-09T00:00:00Z", authorized_capabilities=("source.write", "source.read"), relevant_files=("swarm/harness_authority.py",), token_budget=100, retry_limit=1)


def worker(read_only=False):
    return WorkerRegistration("claude-cli" if read_only else "codex-cli", "anthropic" if read_only else "openai", "claude-approved" if read_only else "gpt-approved", WorkerTransport.CLI, (WorkerRole.READ_ONLY_REVIEWER,) if read_only else (WorkerRole.CODE_WRITER,), True, executable="claude" if read_only else "codex")


def request(operation=HarnessOperation.WRITE, **changes):
    value = HarnessAuthorityRequest("request-one", "tenant-one", "FWQ-0075", "agent-one", "codex-cli", "openai", "gpt-approved", "source.write", "swarm/harness_authority.py", operation, 50, "policy-v1", "ticket-one" if operation == HarnessOperation.WRITE else None)
    return replace(value, **changes)


def decision(value):
    payload = asdict(value)
    payload["operation"] = value.operation.value
    payload.update(lease_id="lease-one", expires_at=200, evidence_reference="evidence/one", ticket_consumed=value.operation == HarnessOperation.WRITE, admitted=True, kill_switch="ENGAGED", deployment="DISABLED", authority_expanded=False)
    return payload


def admit(value=None, *, selected_worker=None, mutate=None):
    value = value or request()
    return admit_harness_authority(task(), selected_worker or worker(), value, now=100, authority_resolver=lambda payload: (mutate or (lambda item: item))(decision(value)))


def test_exact_existing_decision_admits_without_issuing_authority():
    result = admit()
    assert result.admitted and result.ticket_consumed
    assert result.kill_switch == "ENGAGED" and result.deployment == "DISABLED" and not result.authority_expanded


@pytest.mark.parametrize("field,value", [("task_id", "FWQ-9999"), ("worker_id", "other"), ("provider", "anthropic"), ("model_id", "other"), ("capability", "policy.write"), ("resource", "swarm/other.py")])
def test_identity_scope_and_capability_substitution_denies_before_resolver(field, value):
    calls = []
    with pytest.raises(HarnessAuthorityError):
        admit_harness_authority(task(), worker(), replace(request(), **{field: value}), now=100, authority_resolver=lambda payload: calls.append(payload))
    assert calls == []


def test_read_only_worker_cannot_request_mutation():
    value = request(worker_id="claude-cli", provider="anthropic", model_id="claude-approved")
    with pytest.raises(HarnessAuthorityError, match="read-only"):
        admit_harness_authority(replace(task(), assigned_model="claude-approved"), worker(True), value, now=100, authority_resolver=lambda payload: decision(value))


def test_mutation_requires_ticket_and_read_only_cannot_consume_one():
    with pytest.raises(HarnessAuthorityError, match="requires an Action Ticket"):
        admit(request(action_ticket_reference=None))
    with pytest.raises(HarnessAuthorityError, match="cannot consume"):
        admit(request(HarnessOperation.READ, capability="source.read", action_ticket_reference="ticket-one"))


def test_operation_class_and_task_token_budget_cannot_be_widened():
    with pytest.raises(HarnessAuthorityError, match="capability class"):
        admit(request(HarnessOperation.READ, capability="source.write", action_ticket_reference=None))
    with pytest.raises(HarnessAuthorityError, match="token budget"):
        admit(request(requested_tokens=101))


@pytest.mark.parametrize("field,value,match", [("expires_at", 100, "expired"), ("admitted", False, "safety"), ("kill_switch", "DISENGAGED", "safety"), ("deployment", "ENABLED", "safety"), ("authority_expanded", True, "safety"), ("ticket_consumed", False, "Ticket")])
def test_unsafe_stale_or_unconsumed_decision_denies(field, value, match):
    with pytest.raises(HarnessAuthorityError, match=match):
        admit(mutate=lambda item: {**item, field: value})


def test_decision_replay_or_binding_change_is_rejected_by_exact_request_match():
    with pytest.raises(HarnessAuthorityError, match="binding mismatch"):
        admit(mutate=lambda item: {**item, "request_id": "old-request"})


def test_missing_evidence_reference_denies():
    with pytest.raises(HarnessAuthorityError, match="Evidence"):
        admit(mutate=lambda item: {**item, "evidence_reference": ""})


def test_resolver_failure_denies_without_fallback():
    def fail(payload):
        raise RuntimeError("offline")
    with pytest.raises(HarnessAuthorityError, match="resolver failed"):
        admit_harness_authority(task(), worker(), request(), now=100, authority_resolver=fail)


def test_read_only_admission_requires_no_ticket_and_no_mutation():
    value = request(HarnessOperation.READ, capability="source.read", action_ticket_reference=None)
    result = admit(value)
    assert result.operation == HarnessOperation.READ and not result.ticket_consumed
