from dataclasses import replace

import pytest

from swarm.harness_cloud_plan import CloudInvocationPlanError, plan_cloud_model_invocation
from swarm.harness_models import ApprovedModelCandidate
from swarm.harness_risk import AssuranceTier, RiskDecision
from swarm.harness_spend import FreeCreditGrant
from swarm.harness_worker import WorkerRole


def risk(tier=AssuranceTier.T1):
    return RiskDecision("FWQ-0110", "tenant-one", 10, tier, "CLASSIFIED", (), False)


def candidate(identifier, provider, tier, cost, **changes):
    values = dict(
        candidate_id=identifier,
        tenant_id="tenant-one",
        provider=provider,
        model_id=identifier + "-model",
        environment="github",
        assurance_tier=tier,
        allowed_roles=(WorkerRole.CODE_WRITER,),
        allowed_data_classifications=("INTERNAL",),
        allowed_tools=("source.read",),
        estimated_cost_microunits=cost,
        registry_evidence_reference="evidence/model/" + identifier,
        approved=True,
        available=True,
    )
    values.update(changes)
    return ApprovedModelCandidate(**values)


def grant(provider="anthropic", remaining=1_000_000, **changes):
    values = dict(
        grant_id="grant-startup-001",
        tenant_id="tenant-one",
        provider=provider,
        currency="USD",
        remaining_microunits=remaining,
        valid_until=200,
        evidence_reference="evidence/credits/startup-001",
    )
    values.update(changes)
    return FreeCreditGrant(**values)


def plan(choices, credit, **changes):
    args = dict(
        task_id="FWQ-0110",
        tenant_id="tenant-one",
        role=WorkerRole.CODE_WRITER,
        data_classification="INTERNAL",
        required_tools=("source.read",),
        environment="github",
        now=100,
    )
    args.update(changes)
    return plan_cloud_model_invocation(risk(), choices, credit, **args)


def test_cloud_plan_routes_then_requires_exact_free_credit_coverage():
    choices = (
        candidate("anthropic-claude", "anthropic", AssuranceTier.T1, 250_000),
        candidate("openai-codex", "openai", AssuranceTier.T1, 500_000),
    )
    result = plan(choices, grant())
    assert result.provider == "anthropic"
    assert result.invocation_authorized is True
    assert result.billing_mode == "PROMOTIONAL_CREDITS_ONLY"
    assert result.remaining_after_microunits == 750_000
    assert result.paid_fallback_allowed is False
    assert result.mutation_authorized is False
    assert result.credential_material_present is False
    assert result.deployment_authority == "DISABLED"


def test_cheapest_model_is_not_usable_when_credits_bind_to_another_provider():
    choices = (
        candidate("openai-cheap", "openai", AssuranceTier.T1, 10),
        candidate("anthropic-covered", "anthropic", AssuranceTier.T1, 20),
    )
    with pytest.raises(CloudInvocationPlanError, match="bind"):
        plan(choices, grant("anthropic"))


def test_insufficient_or_expired_free_credits_fail_closed():
    choices = (candidate("anthropic-claude", "anthropic", AssuranceTier.T1, 250_000),)
    with pytest.raises(CloudInvocationPlanError, match="insufficient free credits"):
        plan(choices, grant(remaining=249_999))
    with pytest.raises(CloudInvocationPlanError, match="expired"):
        plan(choices, grant(valid_until=100))


def test_failed_candidate_fallback_still_requires_credit_provider_match():
    choices = (
        candidate("primary", "anthropic", AssuranceTier.T1, 10),
        candidate("fallback", "anthropic", AssuranceTier.T1, 20),
    )
    result = plan(choices, grant(), failed_candidate_ids=("primary",))
    assert result.candidate_id == "fallback"
    assert result.provider == "anthropic"


def test_higher_assurance_requirement_cannot_be_downgraded_for_free_cost():
    choices = (
        candidate("free-weak", "anthropic", AssuranceTier.T1, 0),
        candidate("covered-strong", "anthropic", AssuranceTier.T3, 300_000),
    )
    result = plan_cloud_model_invocation(
        risk(AssuranceTier.T3),
        choices,
        grant(),
        task_id="FWQ-0110",
        tenant_id="tenant-one",
        role=WorkerRole.CODE_WRITER,
        data_classification="INTERNAL",
        required_tools=("source.read",),
        environment="github",
        now=100,
    )
    assert result.candidate_id == "covered-strong"
