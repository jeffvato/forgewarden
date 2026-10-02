from dataclasses import replace

import pytest

from swarm.harness_models import ModelRoute
from swarm.harness_risk import AssuranceTier
from swarm.harness_spend import (
    FreeCreditGrant,
    HarnessSpendError,
    admit_free_credit_spend,
    authorize_credit_backed_route,
)


def route(**changes):
    value = ModelRoute(
        task_id="FWQ-0100",
        tenant_id="tenant-one",
        candidate_id="anthropic-claude",
        provider="anthropic",
        model_id="claude-approved",
        environment="cloud",
        assurance_tier=AssuranceTier.T2,
        required_tier=AssuranceTier.T2,
        estimated_cost_microunits=250_000,
        registry_evidence_reference="evidence/model/anthropic-claude",
        fallback=False,
    )
    return replace(value, **changes)


def grant(**changes):
    values = dict(
        grant_id="grant-anthropic-startup-001",
        tenant_id="tenant-one",
        provider="anthropic",
        currency="USD",
        remaining_microunits=1_000_000,
        valid_until=200,
        evidence_reference="evidence/credits/anthropic-startup-001",
        promotional_only=True,
        paid_fallback_allowed=False,
    )
    values.update(changes)
    return FreeCreditGrant(**values)


def test_free_credit_grant_authorizes_only_exact_bounded_route():
    selected = route()
    admission = admit_free_credit_spend(selected, grant(), now=100)
    assert admission.billing_mode == "PROMOTIONAL_CREDITS_ONLY"
    assert admission.remaining_before_microunits == 1_000_000
    assert admission.remaining_after_microunits == 750_000
    assert admission.paid_fallback_allowed is False
    authorized = authorize_credit_backed_route(selected, admission)
    assert authorized.invocation_authorized is True
    assert authorized.deployment_authority == "DISABLED"


@pytest.mark.parametrize(
    "changes,match",
    [
        ({"provider": "openai"}, "bind"),
        ({"tenant_id": "tenant-two"}, "bind"),
        ({"valid_until": 100}, "expired"),
        ({"remaining_microunits": 249_999}, "insufficient free credits"),
    ],
)
def test_mismatched_expired_or_insufficient_credit_denies(changes, match):
    with pytest.raises(HarnessSpendError, match=match):
        admit_free_credit_spend(route(), grant(**changes), now=100)


@pytest.mark.parametrize(
    "changes,match",
    [
        ({"promotional_only": False}, "promotional"),
        ({"paid_fallback_allowed": True}, "paid fallback"),
    ],
)
def test_paid_or_non_promotional_grants_are_not_representable(changes, match):
    with pytest.raises(HarnessSpendError, match=match):
        grant(**changes)


def test_pre_authorized_or_deployment_enabled_route_is_rejected():
    with pytest.raises(HarnessSpendError, match="already authorized"):
        admit_free_credit_spend(
            route(invocation_authorized=True),
            grant(),
            now=100,
        )
    with pytest.raises(HarnessSpendError, match="deployment"):
        admit_free_credit_spend(
            route(deployment_authority="ENABLED"),
            grant(),
            now=100,
        )


def test_admission_cannot_authorize_a_different_route():
    admission = admit_free_credit_spend(route(), grant(), now=100)
    with pytest.raises(HarnessSpendError, match="exact model route"):
        authorize_credit_backed_route(
            route(candidate_id="different"),
            admission,
        )
