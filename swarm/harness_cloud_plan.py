"""Deterministic cloud model invocation planning for FW-HARNESS.

This layer composes approved model routing with the credits-only spend gate.
It performs no network request, secret resolution, repository mutation,
provider invocation, deployment, or fallback to paid billing.
"""
from __future__ import annotations

from dataclasses import dataclass

from .harness_models import ApprovedModelCandidate, ModelRoute, route_approved_model
from .harness_risk import RiskDecision
from .harness_spend import (
    FreeCreditGrant,
    SpendAdmission,
    admit_free_credit_spend,
    authorize_credit_backed_route,
)
from .harness_worker import WorkerRole


class CloudInvocationPlanError(ValueError):
    """The cloud invocation plan could not satisfy all deterministic gates."""


@dataclass(frozen=True)
class CloudInvocationPlan:
    task_id: str
    tenant_id: str
    candidate_id: str
    provider: str
    model_id: str
    environment: str
    estimated_cost_microunits: int
    grant_id: str
    remaining_after_microunits: int
    billing_mode: str
    invocation_authorized: bool
    paid_fallback_allowed: bool
    mutation_authorized: bool = False
    credential_material_present: bool = False
    deployment_authority: str = "DISABLED"


def plan_cloud_model_invocation(
    risk: RiskDecision,
    candidates: tuple[ApprovedModelCandidate, ...],
    grant: FreeCreditGrant,
    *,
    task_id: str,
    tenant_id: str,
    role: WorkerRole,
    data_classification: str,
    required_tools: tuple[str, ...],
    environment: str,
    now: int,
    failed_candidate_ids: tuple[str, ...] = (),
) -> CloudInvocationPlan:
    """Build an exact, credits-backed cloud invocation plan without executing it."""
    try:
        route = route_approved_model(
            risk,
            candidates,
            task_id=task_id,
            tenant_id=tenant_id,
            role=role,
            data_classification=data_classification,
            required_tools=required_tools,
            environment=environment,
            failed_candidate_ids=failed_candidate_ids,
        )
        spend = admit_free_credit_spend(route, grant, now=now)
        admitted = authorize_credit_backed_route(route, spend)
    except (TypeError, ValueError) as exc:
        raise CloudInvocationPlanError(str(exc)) from exc

    _validate_authorized_route(admitted, spend)
    return CloudInvocationPlan(
        task_id=admitted.task_id,
        tenant_id=admitted.tenant_id,
        candidate_id=admitted.candidate_id,
        provider=admitted.provider,
        model_id=admitted.model_id,
        environment=admitted.environment,
        estimated_cost_microunits=admitted.estimated_cost_microunits,
        grant_id=spend.grant_id,
        remaining_after_microunits=spend.remaining_after_microunits,
        billing_mode=spend.billing_mode,
        invocation_authorized=True,
        paid_fallback_allowed=False,
    )


def _validate_authorized_route(route: ModelRoute, spend: SpendAdmission) -> None:
    if route.invocation_authorized is not True:
        raise CloudInvocationPlanError("model invocation was not authorized")
    if route.deployment_authority != "DISABLED":
        raise CloudInvocationPlanError("deployment authority must remain disabled")
    if spend.billing_mode != "PROMOTIONAL_CREDITS_ONLY":
        raise CloudInvocationPlanError("cloud model invocation is not credits-only")
    if spend.paid_fallback_allowed is not False:
        raise CloudInvocationPlanError("paid fallback is forbidden")
