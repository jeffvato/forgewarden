"""Bounded FW-AV protection-service contract.

This module defines the policy and resource seam for a future Windows/Linux
service. It does not install a service, open platform hooks, or execute
blocking/quarantine actions. Runtime observations are still caller-supplied
and flow through the canonical ``DryRunSensorPipeline``.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
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
        if source != f"{self.profile.platform}_SENSOR":
            raise AVServiceContractError("sensor source does not match service platform")
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

    def ingest_fixture(self, fixture: Mapping[str, Any], *, source: str, now_epoch: int):
        """Admit one explicit normalized endpoint fixture through the canonical pipeline."""
        if source != f"{self.profile.platform}_SENSOR":
            raise AVServiceContractError("sensor source does not match service platform")
        try:
            return self._pipeline.ingest_fixture(
                fixture, source=source, tenant_id=self.profile.tenant_id,
                device_id=self.profile.device_id, now_epoch=now_epoch,
            )
        except SensorAdapterDenied:
            raise

    def ingest_batch(self, records: list[Mapping[str, Any]], *, source: str, now_epoch: int):
        """Ingest one bounded caller-supplied batch through the canonical pipeline."""
        if source != f"{self.profile.platform}_SENSOR":
            raise AVServiceContractError("sensor source does not match service platform")
        try:
            return self._pipeline.ingest_batch(
                records,
                source=source,
                tenant_id=self.profile.tenant_id,
                device_id=self.profile.device_id,
                now_epoch=now_epoch,
            )
        except SensorAdapterDenied:
            raise

    def scan_artifact(
        self,
        scanner: object,
        *,
        artifact_id: str,
        content: bytes,
        report_id: str,
        audit: Any,
        now_epoch: int,
    ):
        """Scan caller-supplied bytes through the canonical scanner and report owner."""
        from .anti_malware import AcceptedCatalogScanner, create_scan_report
        if not isinstance(scanner, AcceptedCatalogScanner):
            raise AVServiceContractError("scanner is invalid")
        if not callable(audit):
            raise AVServiceContractError("audit sink is invalid")
        finding = scanner.scan(
            tenant_id=self.profile.tenant_id,
            artifact_id=artifact_id,
            content=content,
            now_epoch=now_epoch,
        )
        return create_scan_report(
            tenant_id=self.profile.tenant_id,
            report_id=report_id,
            findings=(finding,),
            audit=audit,
        )

    def activation_readiness_gate(self, *, rollback_checkpoint: str, approval_reference: str, manifest: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Evaluate activation prerequisites without granting activation authority."""
        if not isinstance(rollback_checkpoint, str) or not rollback_checkpoint.strip():
            raise AVServiceContractError("rollback checkpoint is required")
        if not isinstance(approval_reference, str) or not approval_reference.strip():
            raise AVServiceContractError("approval reference is required")
        if manifest is not None:
            self.validate_packaging_manifest(manifest)
        service = self.service_readiness_projection()
        response = self.response_contract_projection()
        return {
            "decision": "NOT_READY",
            "reason": "ACTIVATION_REQUIRES_SEPARATE_AUTHORIZATION",
            "manifest_digest": self.packaging_manifest_digest(),
            "rollback_checkpoint": rollback_checkpoint.strip(),
            "approval_reference": approval_reference.strip(),
            "service_installation": service["installation"],
            "launch": service["launch"],
            "blocking": response["blocking"],
            "quarantine": response["quarantine"],
            "kill_switch": response["kill_switch"],
            "deployment": response["deployment"],
            "mode": response["mode"],
            "action": response["action"],
        }

    def release_readiness_projection(self) -> dict[str, Any]:
        """Return explicit Sentinel release status without implying production readiness."""
        return {
            "component": "ForgeWarden Sentinel",
            "implementation": "TESTED",
            "security_validation": "FIXTURE_ONLY",
            "production_readiness": "NOT_READY",
            "live_sensors": "DISABLED",
            "service_installation": "NOT_AUTHORIZED",
            "automatic_blocking": "DISABLED",
            "quarantine_execution": "DISABLED",
            "deployment": "DISABLED",
            "kill_switch": "ENGAGED",
            "mode": "DRY_RUN",
            "action": "DETECT_ONLY",
        }

    def mission_control_projection(self) -> dict[str, Any]:
        """Return a read-only, clearly labeled Sentinel operator projection."""
        status = self.status()
        return {
            "product": "ForgeWarden Sentinel",
            "data_mode": "LIVE_BACKEND_NOT_CONNECTED",
            "phase": "DRY_RUN_DETECT_ONLY",
            "platform": status["platform"],
            "tenant_id": status["tenant_id"],
            "device_id": status["device_id"],
            "service": self.service_readiness_projection(),
            "response": self.response_contract_projection(),
            "resource_budget": status["resource_budget"],
            "metrics": status["metrics"],
            "operator_controls": {"read_only": True, "stop_allowed": False, "policy_change_allowed": False},
        }

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

    def packaging_manifest(self) -> dict[str, Any]:
        """Describe a staged Sentinel package without authorizing installation."""
        return {
            "product": "ForgeWarden Sentinel",
            "manifest_version": 1,
            "platform": self.profile.platform,
            "management": "ENTERPRISE_CENTRAL" if self.profile.enterprise_managed else "LOCAL_LIMITED",
            "tray_mode": self.profile.tray_mode,
            "mode": "DRY_RUN",
            "action": "DETECT_ONLY",
            "activation": "DISABLED",
            "service_installation": "NOT_AUTHORIZED",
            "resource_budget": {
                "max_memory_mb": self.profile.max_memory_mb,
                "max_cpu_percent": self.profile.max_cpu_percent,
                "max_queue_events": self.profile.max_queue_events,
            },
        }

    def validate_packaging_manifest(self, manifest: Mapping[str, Any]) -> dict[str, Any]:
        """Validate staged metadata against this profile without installing it."""
        expected = self.packaging_manifest()
        if not isinstance(manifest, Mapping):
            raise AVServiceContractError("packaging manifest is invalid")
        if dict(manifest) != expected:
            raise AVServiceContractError("packaging manifest does not match service profile")
        return dict(expected)

    def packaging_manifest_digest(self) -> str:
        """Return a stable digest for the validated staged manifest."""
        manifest = self.validate_packaging_manifest(self.packaging_manifest())
        encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def service_readiness_projection(self) -> dict[str, Any]:
        """Describe platform service readiness without installing or launching it."""
        manifest = self.validate_packaging_manifest(self.packaging_manifest())
        windows = manifest["platform"] == "WINDOWS"
        return {
            "service_name": "ForgeWardenSentinel",
            "manager": "SCM" if windows else "SYSTEMD",
            "run_as": "NT AUTHORITY\\LocalService" if windows else "forgewarden-sentinel",
            "startup": "DISABLED",
            "restart_policy": "BOUNDED_ON_FAILURE",
            "max_restart_attempts": 3,
            "installation": "NOT_AUTHORIZED",
            "launch": "NOT_AUTHORIZED",
            "manifest_digest": self.packaging_manifest_digest(),
        }

    def response_contract_projection(self) -> dict[str, Any]:
        """Describe inert policy-gated response contracts without executing them."""
        return {
            "mode": self.profile.mode,
            "action": self.profile.action,
            "automatic_blocking": False,
            "quarantine_execution": False,
            "blocking": "POLICY_GATE_REQUIRED",
            "quarantine": "PROPOSAL_ONLY",
            "activation": "DISABLED",
            "deployment": "DISABLED",
            "kill_switch": "ENGAGED",
        }

    def installer_artifact_projection(self) -> dict[str, Any]:
        """Describe a staged artifact binding without creating or installing it."""
        manifest = self.validate_packaging_manifest(self.packaging_manifest())
        return {
            "artifact_name": f"forgewarden-sentinel-{manifest['platform'].lower()}-dry-run.manifest",
            "manifest_digest": self.packaging_manifest_digest(),
            "activation": manifest["activation"],
            "service_installation": manifest["service_installation"],
            "deployment": "DISABLED",
        }
