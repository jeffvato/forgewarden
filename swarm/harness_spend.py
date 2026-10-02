"""Fail-closed free-credit admission for FW-HARNESS model invocation.

This module does not call providers, resolve billing accounts, or purchase
capacity. It admits only an already-routed model request when an explicit,
current promotional-credit grant covers the entire estimated request cost.
Paid fallback is never represented as an allowed state.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace

from .harness_models import ModelRoute


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,511}$")


class HarnessSpendError(ValueError):
    """A model invocation was not covered by an admissible free-credit grant."""


@dataclass(frozen=True)
class FreeCreditGrant:
    grant_id: str
    tenant_id: str
    provider: str
    currency: str
    remaining_microunits: int
    valid_until: int
    evidence_reference: str
    promotional_only: bool = True
    paid_fallback_allowed: bool = False

    def __post_init__(self) -> None:
        for value in (self.grant_id, self.tenant_id, self.provider, self.currency):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise HarnessSpendError("credit grant identity is malformed")
        if (
            type(self.remaining_microunits) is not int
            or self.remaining_microunits < 0
            or type(self.valid_until) is not int
            or self.valid_until < 0
        ):
            raise HarnessSpendError("credit grant amount or expiry is malformed")
        if (
            not isinstance(self.evidence_reference, str)
            or not _REF.fullmatch(self.evidence_reference)
        ):
            raise HarnessSpendError("credit grant Evidence reference is invalid")
        if self.promotional_only is not True:
            raise HarnessSpendError("only promotional credit grants are admissible")
        if self.paid_fallback_allowed is not False:
            raise HarnessSpendError("paid fallback is forbidden")


@dataclass(frozen=True)
class SpendAdmission:
    task_id: str
    tenant_id: str
    candidate_id: str
    provider: str
    model_id: str
    grant_id: str
    estimated_cost_microunits: int
    remaining_before_microunits: int
    remaining_after_microunits: int
    evidence_reference: str
    billing_mode: str = "PROMOTIONAL_CREDITS_ONLY"
    paid_fallback_allowed: bool = False
    invocation_authorized: bool = True
    deployment_authority: str = "DISABLED"


def admit_free_credit_spend(
    route: ModelRoute,
    grant: FreeCreditGrant,
    *,
    now: int,
) -> SpendAdmission:
    """Authorize one bounded model invocation only against free credits."""
    if not isinstance(route, ModelRoute) or not isinstance(grant, FreeCreditGrant):
        raise HarnessSpendError("spend admission input is malformed")
    if type(now) is not int or now < 0:
        raise HarnessSpendError("spend admission time is malformed")
    if route.invocation_authorized is not False:
        raise HarnessSpendError("route was already authorized outside the spend gate")
    if route.deployment_authority != "DISABLED":
        raise HarnessSpendError("route exceeds the deployment boundary")
    if route.tenant_id != grant.tenant_id or route.provider != grant.provider:
        raise HarnessSpendError("credit grant does not bind to routed tenant and provider")
    if grant.valid_until <= now:
        raise HarnessSpendError("free-credit grant is expired")
    if (
        type(route.estimated_cost_microunits) is not int
        or route.estimated_cost_microunits < 0
    ):
        raise HarnessSpendError("routed estimated cost is malformed")
    if route.estimated_cost_microunits > grant.remaining_microunits:
        raise HarnessSpendError("insufficient free credits; paid fallback is forbidden")

    return SpendAdmission(
        task_id=route.task_id,
        tenant_id=route.tenant_id,
        candidate_id=route.candidate_id,
        provider=route.provider,
        model_id=route.model_id,
        grant_id=grant.grant_id,
        estimated_cost_microunits=route.estimated_cost_microunits,
        remaining_before_microunits=grant.remaining_microunits,
        remaining_after_microunits=(
            grant.remaining_microunits - route.estimated_cost_microunits
        ),
        evidence_reference=grant.evidence_reference,
    )


def authorize_credit_backed_route(
    route: ModelRoute,
    admission: SpendAdmission,
) -> ModelRoute:
    """Bind the spend admission to the exact route without provider execution."""
    if not isinstance(route, ModelRoute) or not isinstance(admission, SpendAdmission):
        raise HarnessSpendError("route authorization input is malformed")
    expected = (
        route.task_id,
        route.tenant_id,
        route.candidate_id,
        route.provider,
        route.model_id,
        route.estimated_cost_microunits,
    )
    actual = (
        admission.task_id,
        admission.tenant_id,
        admission.candidate_id,
        admission.provider,
        admission.model_id,
        admission.estimated_cost_microunits,
    )
    if expected != actual:
        raise HarnessSpendError("spend admission does not match the exact model route")
    if (
        admission.billing_mode != "PROMOTIONAL_CREDITS_ONLY"
        or admission.paid_fallback_allowed is not False
        or admission.invocation_authorized is not True
        or admission.deployment_authority != "DISABLED"
    ):
        raise HarnessSpendError("spend admission violates the credits-only boundary")
    return replace(route, invocation_authorized=True)
