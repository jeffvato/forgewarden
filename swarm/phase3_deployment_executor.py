"""Guarded Phase 3 executor contract; real deployment remains disabled."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping

from .core import SwarmError


PROFILE_ID = "forgewarden_synthetic_service_deployment_v1"
SERVICE = "forgewarden-synthetic-fixture-v1"
APPROVED_COMMIT = "06a22f1c431867cede1265bae7edf706e5a5ae04"


@dataclass(frozen=True)
class DeploymentRequest:
    profile_id: str
    job_id: str
    service: str
    approved_commit: str
    evidence_sha256: str


class GuardedDeploymentExecutor:
    """Validate a fixed deployment request, then fail closed before mutation."""

    @staticmethod
    def preflight(request: DeploymentRequest, approval: Mapping[str, object]) -> dict[str, object]:
        if request.profile_id != PROFILE_ID or request.service != SERVICE:
            raise SwarmError("deployment request is outside the fixed Phase 3 profile")
        if request.approved_commit != APPROVED_COMMIT or not re.fullmatch(r"[0-9a-f]{64}", request.evidence_sha256):
            raise SwarmError("deployment request is not bound to the approved commit or evidence")
        expected = {"job_id": request.job_id, "service": request.service, "approved_commit": request.approved_commit, "evidence_sha256": request.evidence_sha256, "decision": "APPROVED", "one_time": True, "consumed": False, "deployment": "DISABLED"}
        if any(approval.get(key) != value for key, value in expected.items()):
            raise SwarmError("deployment approval binding mismatch")
        return {"state": "READY_FOR_SEPARATE_DEPLOYMENT_AUTHORIZATION", "profile_id": PROFILE_ID, "service": SERVICE, "approved_commit": APPROVED_COMMIT, "mutation_allowed": False, "deployment": "DISABLED"}

    def execute(self, *_args, **_kwargs) -> None:
        raise SwarmError("real Phase 3 deployment executor is disabled")
