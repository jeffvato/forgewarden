from dataclasses import asdict, replace

import pytest

from swarm.harness_context import ContextItem, build_context_packet
from swarm.harness_models import HarnessModelError, HarnessModelRequest, admit_harness_model
from swarm.harness_task import HarnessTask, TaskStatus
from swarm.harness_worker import WorkerRegistration, WorkerRole, WorkerTransport


def task(model="gpt-approved"):
    return HarnessTask("FWQ-0076", "FW-HARNESS-011", "Models", "model admission", TaskStatus.READY, 0, "CODEX", model, "/repo", "2026-09-09T00:00:00Z", authorized_capabilities=("source.read",), relevant_files=("swarm/harness_models.py",), token_budget=100, cost_budget=2.0, retry_limit=1)


def context(value):
    return build_context_packet(value, (ContextItem("architecture_constraint", "model", "registry owns selection"), ContextItem("forbidden_change", "provider", "no silent substitution")))


def worker(worker_id="codex-cli", provider="openai", model="gpt-approved"):
    return WorkerRegistration(worker_id, provider, model, WorkerTransport.CLI, (WorkerRole.CODE_WRITER,), True, executable="codex")


def request(value, packet, selected, **changes):
    base = HarnessModelRequest("request-one", "tenant-one", value.task_id, "agent-one", selected.worker_id, selected.provider, selected.model_id, "deployment-one", "version-one", "approval-one", WorkerRole.CODE_WRITER, "INTERNAL", ("source.read",), packet.sha256, packet.byte_count, 100, 2_000_000)
    return replace(base, **changes)


def decision(value):
    payload = asdict(value)
    payload["role"] = value.role.value
    payload["tool_permissions"] = list(value.tool_permissions)
    payload.update(registry_evidence_reference="evidence/model-one", valid_until=200, reliability_score=.99, reliability_samples=100, approved=True, deployment_authority="DISABLED")
    return payload


def admit(req=None, *, value=None, packet=None, selected=None, mutate=None, primary=None):
    value = value or task(); packet = packet or context(value); selected = selected or worker(); req = req or request(value, packet, selected)
    return admit_harness_model(value, packet, selected, req, now=100, model_resolver=lambda wire: (mutate or (lambda item: item))(decision(req)), primary_admission=primary)


def test_exact_registry_decision_admits_without_routing_or_activation():
    result = admit()
    assert result.approved and result.deployment_authority == "DISABLED"
    assert result.reliability_score == .99 and result.fallback_rank == 0


@pytest.mark.parametrize("field,value", [("task_id", "FWQ-9999"), ("worker_id", "other"), ("provider", "anthropic"), ("model_id", "other"), ("role", WorkerRole.READ_ONLY_REVIEWER), ("context_sha256", "a" * 64), ("context_bytes", 1)])
def test_task_context_worker_and_model_substitution_denies(field, value):
    base, packet, selected = task(), None, worker()
    packet = context(base)
    with pytest.raises(HarnessModelError):
        admit(request(base, packet, selected, **{field: value}), value=base, packet=packet, selected=selected)


def test_tool_and_resource_budgets_cannot_expand():
    value, selected = task(), worker(); packet = context(value)
    with pytest.raises(HarnessModelError, match="tool permissions"):
        admit(request(value, packet, selected, tool_permissions=("source.write",)), value=value, packet=packet, selected=selected)
    with pytest.raises(HarnessModelError, match="task budget"):
        admit(request(value, packet, selected, token_budget=101), value=value, packet=packet, selected=selected)


@pytest.mark.parametrize("field,value,match", [("approved", False, "not approved"), ("deployment_authority", "ENABLED", "deployment"), ("valid_until", 100, "stale"), ("reliability_score", 2.0, "reliability"), ("registry_evidence_reference", "", "Evidence")])
def test_unapproved_stale_or_malformed_registry_decision_denies(field, value, match):
    with pytest.raises(HarnessModelError, match=match):
        admit(mutate=lambda item: {**item, field: value})


def test_silent_fallback_is_denied_without_preceding_admission():
    value, selected = task(), worker(); packet = context(value)
    fallback = request(value, packet, selected, fallback_rank=1, fallback_for="request-primary")
    with pytest.raises(HarnessModelError, match="preceding"):
        admit(fallback, value=value, packet=packet, selected=selected)


def test_explicit_ordered_equivalent_fallback_is_separately_admitted():
    primary = admit()
    value = task(); packet = context(value); selected = worker("claude-cli", "anthropic", "claude-approved")
    fallback = request(value, packet, selected, request_id="request-two", fallback_rank=1, fallback_for=primary.request_id)
    result = admit(fallback, value=value, packet=packet, selected=selected, primary=primary)
    assert result.provider == "anthropic" and result.fallback_rank == 1


def test_fallback_cannot_change_data_tools_or_budget():
    primary = admit()
    value = task(); packet = context(value); selected = worker("claude-cli", "anthropic", "claude-approved")
    fallback = request(value, packet, selected, request_id="request-two", fallback_rank=1, fallback_for=primary.request_id, data_classification="PUBLIC")
    with pytest.raises(HarnessModelError, match="equivalent"):
        admit(fallback, value=value, packet=packet, selected=selected, primary=primary)


def test_registry_failure_denies_without_fallback():
    value, selected = task(), worker(); packet = context(value); req = request(value, packet, selected)
    def fail(wire): raise RuntimeError("offline")
    with pytest.raises(HarnessModelError, match="resolver failed"):
        admit_harness_model(value, packet, selected, req, now=100, model_resolver=fail)
