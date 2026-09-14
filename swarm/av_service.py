"""Bounded FW-AV protection-service contract.

This module defines the policy and resource seam for a future Windows/Linux
service. It does not install a service, open platform hooks, or execute
blocking/quarantine actions. Runtime observations are still caller-supplied
and flow through the canonical ``DryRunSensorPipeline``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .sensor_adapter import DryRunSensorPipeline, SensorAdapterDenied

MAX_MEMORY_MB = 256
MAX_CPU_PERCENT = 20
MAX_QUEUE_EVENTS = 1024


class AVServiceContractError(ValueError):
    """A service policy or observation violates the bounded contract."""


@dataclass(frozen=True)
class AVServiceProfile:
    tenant_id: str
    device_id: str
    platform: str
    enterprise_managed: bool
    tray_mode: str
    max_memory_mb: int = 128
    max_cpu_percent: int = 5
    max_queue_events: int = 1024
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"
    automatic_blocking: bool = False
    quarantine_execution: bool = False

    def __post_init__(self) -> None:
        for name, value in (("tenant_id", self.tenant_id), ("device_id", self.device_id)):
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise AVServiceContractError(f"{name} must be a non-empty bounded string")
        if self.platform not in {"WINDOWS", "LINUX"}:
            raise AVServiceContractError("platform is unsupported")
        if not isinstance(self.enterprise_managed, bool):
            raise AVServiceContractError("enterprise_managed must be boolean")
        expected_tray = "STATUS_ONLY" if self.enterprise_managed else "LIMITED_PREFERENCES"
        if self.tray_mode != expected_tray:
            raise AVServiceContractError("tray_mode does not match management policy")
        if not 1 <= self.max_memory_mb <= MAX_MEMORY_MB:
            raise AVServiceContractError("max_memory_mb exceeds service bound")
        if not 1 <= self.max_cpu_percent <= MAX_CPU_PERCENT:
            raise AVServiceContractError("max_cpu_percent exceeds service bound")
        if not 1 <= self.max_queue_events <= MAX_QUEUE_EVENTS:
            raise AVServiceContractError("max_queue_events exceeds service bound")
        if self.mode != "DRY_RUN" or self.action != "DETECT_ONLY":
            raise AVServiceContractError("service contract must remain DRY_RUN/DETECT_ONLY")
        if self.automatic_blocking or self.quarantine_execution:
            raise AVServiceContractError("blocking and quarantine execution require a later activation gate")


class AVProtectionService:
    """Policy-gated caller-supplied observation seam for future AV services."""

    def __init__(self, profile: AVServiceProfile, pipeline: DryRunSensorPipeline):
        if not isinstance(profile, AVServiceProfile):
            raise AVServiceContractError("profile is invalid")
        if not isinstance(pipeline, DryRunSensorPipeline):
            raise AVServiceContractError("pipeline is invalid")
        self.profile = profile
        self._pipeline = pipeline

    def ingest(self, record: Mapping[str, Any], *, source: str, now_epoch: int):
        """Ingest one explicit observation without platform access or response."""
        try:
            return self._pipeline.ingest_record(
                record,
                source=source,
                tenant_id=self.profile.tenant_id,
                device_id=self.profile.device_id,
                now_epoch=now_epoch,
            )
        except SensorAdapterDenied:
            raise

    def status(self) -> dict[str, Any]:
        metrics = self._pipeline.metrics()
        return {
            "tenant_id": self.profile.tenant_id,
            "device_id": self.profile.device_id,
            "platform": self.profile.platform,
            "enterprise_managed": self.profile.enterprise_managed,
            "tray_mode": self.profile.tray_mode,
            "service_control": "CENTRAL_ONLY" if self.profile.enterprise_managed else "LOCAL_POLICY_LIMITED",
            "local_stop_allowed": False,
            "local_policy_change_allowed": not self.profile.enterprise_managed,
            "mode": self.profile.mode,
            "action": self.profile.action,
            "automatic_blocking": False,
            "quarantine_execution": False,
            "resource_budget": {
                "max_memory_mb": self.profile.max_memory_mb,
                "max_cpu_percent": self.profile.max_cpu_percent,
                "max_queue_events": self.profile.max_queue_events,
            },
            "metrics": metrics,
        }

    def tray_projection(self) -> dict[str, Any]:
        """Return a labeled tray view with policy-limited controls."""
        status = self.status()
        return {
            "product": "ForgeWarden Sentinel",
            "mode": "DEMO/DRY_RUN",
            "tenant_id": status["tenant_id"],
            "device_id": status["device_id"],
            "platform": status["platform"],
            "protection_state": "DETECT_ONLY",
            "management": status["service_control"],
            "show_preferences": status["local_policy_change_allowed"],
            "show_stop_control": False,
            "show_quarantine_execution": False,
            "show_deployment_control": False,
        }
