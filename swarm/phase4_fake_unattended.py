"""Disposable-only Phase 4 coordinator contract; unattended enablement disabled."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .core import SwarmError


PROFILE_ID = "forgewarden_low_risk_unattended_v1"
SERVICE = "forgewarden-synthetic-fixture-v1"


@dataclass(frozen=True)
class Prerequisites:
    phase2a_connection_replay: bool
    supervised_worker: bool
    human_deployment: bool
    rollback: bool


class FakeUnattendedCoordinator:
    """Evaluate a fixed Phase 4 plan without starting or enabling a worker."""

    @staticmethod
    def preflight(service: str, risk: str, prerequisites: Prerequisites, approval: Mapping[str, object], *, kill_switch: bool, active_workers: int) -> dict[str, object]:
        if service != SERVICE or risk != "LOW":
            raise SwarmError("Phase 4 permits only the fixed low-risk service")
        if not all((prerequisites.phase2a_connection_replay, prerequisites.supervised_worker, prerequisites.human_deployment, prerequisites.rollback)):
            raise SwarmError("Phase 4 prerequisites are incomplete")
        if not kill_switch:
            raise SwarmError("Phase 4 requires an engaged kill switch")
        if active_workers != 0:
            raise SwarmError("Phase 4 rejects duplicate or active workers")
        expected = {"profile_id": PROFILE_ID, "service": SERVICE, "risk": "LOW", "one_time": True, "consumed": False, "deployment": "DISABLED"}
        if any(approval.get(key) != value for key, value in expected.items()):
            raise SwarmError("Phase 4 approval binding mismatch")
        return {"state": "READY_FOR_SEPARATE_ENABLEMENT_AUTHORIZATION", "profile_id": PROFILE_ID, "service": SERVICE, "risk": "LOW", "worker_started": False, "deployment": "DISABLED", "kill_switch": "ENGAGED"}

    def enable(self, *_args, **_kwargs) -> None:
        raise SwarmError("Phase 4 unattended enablement is disabled")
