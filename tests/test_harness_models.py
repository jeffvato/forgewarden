from dataclasses import asdict, replace

import pytest

from swarm.harness_context import ContextItem, build_context_packet
from swarm.harness_models import (ApprovedModelCandidate, HarnessModelError, HarnessModelRequest, admit_harness_model, route_approved_model)
from swarm.harness_risk import AssuranceTier, RiskDecision
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


def risk(tier=AssuranceTier.T1, disposition="CLASSIFIED", human=False):
    return RiskDecision("FWQ-0083", "tenant-one", 20, tier, disposition, (), human)


def candidate(identifier, tier, cost, **changes):
    values = dict(
        candidate_id=identifier, tenant_id="tenant-one", provider="provider",
        model_id=identifier + "-model", environment="local",
        assurance_tier=tier, allowed_roles=(WorkerRole.CODE_WRITER,),
        allowed_data_classifications=("INTERNAL",),
        allowed_tools=("source.read", "source.write"),
        estimated_cost_microunits=cost,
        registry_evidence_reference="evidence/model/" + identifier,
        approved=True, available=True,
    )
    values.update(changes)
    return ApprovedModelCandidate(**values)


def route(value, choices, **changes):
    args = dict(
        task_id="FWQ-0083", tenant_id="tenant-one",
        role=WorkerRole.CODE_WRITER, data_classification="INTERNAL",
        required_tools=("source.read",), environment="local",
    )
    args.update(changes)
    return route_approved_model(value, choices, **args)


def test_routes_lowest_cost_eligible_registry_candidate():
    choices = (
        candidate("balanced", AssuranceTier.T1, 20),
        candidate("cheap", AssuranceTier.T1, 10),
        candidate("strong", AssuranceTier.T3, 30),
    )
    result = route(risk(), choices)
    assert result.candidate_id == "cheap"
    assert result.required_tier is AssuranceTier.T1
    assert not result.invocation_authorized
    assert result.deployment_authority == "DISABLED"


def test_security_tier_cannot_route_weaker_or_unapproved_model():
    choices = (
        candidate("weak", AssuranceTier.T2, 1),
        candidate("unapproved", AssuranceTier.T3, 1, approved=False),
        candidate("secure", AssuranceTier.T3, 20),
    )
    assert route(risk(AssuranceTier.T3), choices).candidate_id == "secure"


@pytest.mark.parametrize("value", [
    risk(AssuranceTier.T4),
    risk(AssuranceTier.T3, "DENIED_POLICY_INVARIANT", True),
    risk(AssuranceTier.T3, "HUMAN_AUTHORIZATION_REQUIRED", True),
])
def test_t4_human_and_denied_decisions_select_no_model(value):
    with pytest.raises(HarnessModelError, match="does not permit"):
        route(value, (candidate("strong", AssuranceTier.T4, 1),))


@pytest.mark.parametrize("changes", [
    {"tenant_id": "tenant-two"},
    {"environment": "government"},
    {"allowed_roles": (WorkerRole.READ_ONLY_REVIEWER,)},
    {"allowed_data_classifications": ("PUBLIC",)},
    {"allowed_tools": ("source.write",)},
    {"approved": False},
    {"available": False},
])
def test_exact_tenant_environment_role_data_tool_and_state_constraints(changes):
    with pytest.raises(HarnessModelError, match="NO_APPROVED"):
        route(risk(), (candidate("only", AssuranceTier.T1, 1, **changes),))


def test_provider_failure_uses_only_same_or_higher_approved_equivalent():
    choices = (
        candidate("primary", AssuranceTier.T2, 1),
        candidate("downgrade", AssuranceTier.T1, 2),
        candidate("equivalent", AssuranceTier.T2, 3),
    )
    result = route(
        risk(AssuranceTier.T2), choices,
        failed_candidate_ids=("primary",),
    )
    assert result.candidate_id == "equivalent" and result.fallback
    with pytest.raises(HarnessModelError, match="NO_APPROVED"):
        route(
            risk(AssuranceTier.T2), choices[:2],
            failed_candidate_ids=("primary",),
        )


def test_no_eligible_candidate_fails_closed_with_exact_reason():
    with pytest.raises(
        HarnessModelError,
        match="NO_APPROVED_MODEL_AVAILABLE_FOR_REQUIRED_ASSURANCE_LEVEL",
    ):
        route(risk(AssuranceTier.T3), (candidate("routine", AssuranceTier.T1, 1),))


def test_risk_and_registry_binding_cannot_be_substituted():
    choices = (candidate("only", AssuranceTier.T1, 1),)
    with pytest.raises(HarnessModelError, match="binding"):
        route(replace(risk(), tenant_id="tenant-two"), choices)
    with pytest.raises(HarnessModelError, match="failed candidate"):
        route(risk(), choices, failed_candidate_ids=("unknown",))
    with pytest.raises(HarnessModelError, match="candidate set"):
        route(risk(), (choices[0], choices[0]))
