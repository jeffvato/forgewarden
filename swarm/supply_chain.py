"""Bounded caller-supplied software supply-chain observation contracts."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Callable, Mapping


MAX_SUPPLY_FIXTURE_BYTES = 32 * 1024
MAX_SUPPLY_TEXT_BYTES = 256
MAX_SUPPLY_INDICATORS = 16
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$")
_PACKAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@/+-]{0,255}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TENANT_REF = re.compile(
    r"^fw-(vuln|catalog|signature|evid)/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/+-]{0,191}$"
)
_ECOSYSTEMS = frozenset({"CONTAINER", "GENERIC", "MAVEN", "NPM", "NUGET", "PYPI"})
_INDICATORS = frozenset({
    "DEPENDENCY_CONFUSION", "DIGEST_MISMATCH", "KNOWN_EXPLOITED",
    "KNOWN_VULNERABILITY", "TYPOSQUAT", "UNTRUSTED_PUBLISHER",
    "UNVERIFIED_PROVENANCE", "VERIFIED_PROVENANCE",
})
_REQUIRED = frozenset({
    "event_id", "tenant_id", "observed_at_epoch", "component_ref",
    "ecosystem", "package_name", "version", "artifact_sha256",
    "source_ref", "provenance_ref", "evidence_ref",
})


class SupplyChainObservationDenied(PermissionError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _reference(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > MAX_SUPPLY_TEXT_BYTES
        or not _REF.fullmatch(value)
    ):
        raise SupplyChainObservationDenied(f"{field}_INVALID")
    return value


@dataclass(frozen=True)
class SupplyChainObservation:
    event_id: str
    tenant_id: str
    observed_at_epoch: int
    component_ref: str
    ecosystem: str
    package_name: str
    version: str
    artifact_sha256: str
    source_ref: str
    provenance_ref: str
    evidence_ref: str
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"


@dataclass(frozen=True)
class SupplyChainFinding:
    event_id: str
    tenant_id: str
    component_ref: str
    ecosystem: str
    indicators: tuple[str, ...]
    risk: str
    recommendations: tuple[str, ...]
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"


@dataclass(frozen=True)
class SupplyChainReferenceBinding:
    event_id: str
    tenant_id: str
    component_ref: str
    risk: str
    indicators: tuple[str, ...]
    vulnerability_refs: tuple[str, ...]
    catalog_ref: str
    signature_ref: str
    evidence_refs: tuple[str, ...]
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "CORRELATE_ONLY"


def normalize_supply_chain_observation(
    fixture: Mapping[str, Any], *, tenant_id: str, now_epoch: int,
    audit: Callable[[str, dict[str, Any]], None],
) -> SupplyChainObservation:
    """Validate one exact component metadata fixture and record Evidence first."""
    if not isinstance(fixture, Mapping) or not callable(audit):
        raise SupplyChainObservationDenied("FIXTURE_INVALID")
    try:
        size = len(json.dumps(
            fixture, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise SupplyChainObservationDenied("FIXTURE_INVALID") from exc
    if size > MAX_SUPPLY_FIXTURE_BYTES or set(fixture) != _REQUIRED:
        raise SupplyChainObservationDenied("FIXTURE_INVALID")
    expected_tenant = _reference(tenant_id, "TENANT")
    if fixture.get("tenant_id") != expected_tenant:
        raise SupplyChainObservationDenied("TENANT_MISMATCH")
    observed = fixture.get("observed_at_epoch")
    if (
        not isinstance(observed, int) or isinstance(observed, bool)
        or not isinstance(now_epoch, int) or isinstance(now_epoch, bool)
        or observed < 0 or observed > now_epoch
    ):
        raise SupplyChainObservationDenied("OBSERVED_AT_INVALID")
    ecosystem = fixture.get("ecosystem")
    if ecosystem not in _ECOSYSTEMS:
        raise SupplyChainObservationDenied("ECOSYSTEM_INVALID")
    package_name = fixture.get("package_name")
    version = fixture.get("version")
    digest = fixture.get("artifact_sha256")
    if not isinstance(package_name, str) or not _PACKAGE.fullmatch(package_name):
        raise SupplyChainObservationDenied("PACKAGE_NAME_INVALID")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise SupplyChainObservationDenied("VERSION_INVALID")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise SupplyChainObservationDenied("ARTIFACT_SHA256_INVALID")
    event_id = _reference(fixture.get("event_id"), "EVENT_ID")
    component_ref = _reference(fixture.get("component_ref"), "COMPONENT_REF")
    source_ref = _reference(fixture.get("source_ref"), "SOURCE_REF")
    provenance_ref = _reference(fixture.get("provenance_ref"), "PROVENANCE_REF")
    evidence_ref = _reference(fixture.get("evidence_ref"), "EVIDENCE_REF")
    try:
        audit("supply_chain_observation_normalized", {
            "event_id": event_id,
            "tenant_id": expected_tenant,
            "observed_at_epoch": observed,
            "component_ref": component_ref,
            "ecosystem": ecosystem,
            "artifact_sha256": digest,
            "evidence_ref": evidence_ref,
            "trust": "UNTRUSTED_DATA",
            "mode": "DRY_RUN",
            "action": "DETECT_ONLY",
            "deployment": "DISABLED",
        })
    except Exception as exc:
        raise SupplyChainObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    return SupplyChainObservation(
        event_id, expected_tenant, observed, component_ref, ecosystem,
        package_name, version, digest, source_ref, provenance_ref, evidence_ref,
    )


def classify_supply_chain_observation(
    observation: SupplyChainObservation, *, tenant_id: str,
    indicators: tuple[str, ...],
    audit: Callable[[str, dict[str, Any]], None],
) -> SupplyChainFinding:
    """Classify exact supplied vulnerability/provenance facts without fetching."""
    if not isinstance(observation, SupplyChainObservation) or not callable(audit):
        raise SupplyChainObservationDenied("OBSERVATION_INVALID")
    expected_tenant = _reference(tenant_id, "TENANT")
    if observation.tenant_id != expected_tenant:
        raise SupplyChainObservationDenied("TENANT_MISMATCH")
    if (
        observation.trust != "UNTRUSTED_DATA"
        or observation.mode != "DRY_RUN"
        or observation.action != "DETECT_ONLY"
    ):
        raise SupplyChainObservationDenied("OBSERVATION_AUTHORITY_INVALID")
    if (
        observation.ecosystem not in _ECOSYSTEMS
        or not _PACKAGE.fullmatch(observation.package_name)
        or not _VERSION.fullmatch(observation.version)
        or not _SHA256.fullmatch(observation.artifact_sha256)
        or not isinstance(observation.observed_at_epoch, int)
        or isinstance(observation.observed_at_epoch, bool)
        or observation.observed_at_epoch < 0
    ):
        raise SupplyChainObservationDenied("OBSERVATION_INVALID")
    for value, field in (
        (observation.event_id, "EVENT_ID"),
        (observation.component_ref, "COMPONENT_REF"),
        (observation.source_ref, "SOURCE_REF"),
        (observation.provenance_ref, "PROVENANCE_REF"),
        (observation.evidence_ref, "EVIDENCE_REF"),
    ):
        _reference(value, field)
    if (
        not isinstance(indicators, tuple)
        or not 1 <= len(indicators) <= MAX_SUPPLY_INDICATORS
        or tuple(sorted(set(indicators))) != indicators
        or any(item not in _INDICATORS for item in indicators)
        or ("VERIFIED_PROVENANCE" in indicators and "UNVERIFIED_PROVENANCE" in indicators)
    ):
        raise SupplyChainObservationDenied("INDICATORS_INVALID")
    facts = set(indicators)
    if "KNOWN_EXPLOITED" in facts or "DIGEST_MISMATCH" in facts:
        risk = "CRITICAL"
    elif facts & {"DEPENDENCY_CONFUSION", "TYPOSQUAT", "UNTRUSTED_PUBLISHER"}:
        risk = "HIGH"
    elif facts & {"KNOWN_VULNERABILITY", "UNVERIFIED_PROVENANCE"}:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    recommendations = ("WARN", "PROPOSE_BLOCK") if risk in {"HIGH", "CRITICAL"} else ("WARN",)
    try:
        audit("supply_chain_observation_classified", {
            "event_id": observation.event_id,
            "tenant_id": expected_tenant,
            "component_ref": observation.component_ref,
            "ecosystem": observation.ecosystem,
            "indicators": list(indicators),
            "risk": risk,
            "recommendations": list(recommendations),
            "trust": "UNTRUSTED_DATA",
            "mode": "DRY_RUN",
            "action": "DETECT_ONLY",
            "response_executed": False,
            "deployment": "DISABLED",
        })
    except Exception as exc:
        raise SupplyChainObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    return SupplyChainFinding(
        observation.event_id, expected_tenant, observation.component_ref,
        observation.ecosystem, indicators, risk, recommendations,
    )


def bind_supply_chain_references(
    finding: SupplyChainFinding, *, tenant_id: str,
    vulnerability_refs: tuple[str, ...], catalog_ref: str,
    signature_ref: str, evidence_refs: tuple[str, ...],
    audit: Callable[[str, dict[str, Any]], None],
) -> SupplyChainReferenceBinding:
    """Bind existing canonical owners without creating a competing registry."""
    if not isinstance(finding, SupplyChainFinding) or not callable(audit):
        raise SupplyChainObservationDenied("FINDING_INVALID")
    expected_tenant = _reference(tenant_id, "TENANT")
    if finding.tenant_id != expected_tenant:
        raise SupplyChainObservationDenied("TENANT_MISMATCH")
    if (
        finding.risk not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        or finding.trust != "UNTRUSTED_DATA"
        or finding.mode != "DRY_RUN"
        or finding.action != "DETECT_ONLY"
        or not isinstance(finding.indicators, tuple)
        or not 1 <= len(finding.indicators) <= MAX_SUPPLY_INDICATORS
        or tuple(sorted(set(finding.indicators))) != finding.indicators
        or any(item not in _INDICATORS for item in finding.indicators)
    ):
        raise SupplyChainObservationDenied("FINDING_INVALID")
    _reference(finding.event_id, "EVENT_ID")
    _reference(finding.component_ref, "COMPONENT_REF")
    groups = (
        (vulnerability_refs, "vuln", "VULNERABILITY_REFS"),
        (evidence_refs, "evid", "EVIDENCE_REFS"),
    )
    for values, kind, field in groups:
        if (
            not isinstance(values, tuple) or not 1 <= len(values) <= 16
            or tuple(sorted(set(values))) != values
        ):
            raise SupplyChainObservationDenied(f"{field}_INVALID")
        for value in values:
            match = _TENANT_REF.fullmatch(value) if isinstance(value, str) else None
            if match is None or match.group(1) != kind or match.group(2) != expected_tenant:
                raise SupplyChainObservationDenied(f"{field}_INVALID")
    for value, kind in ((catalog_ref, "catalog"), (signature_ref, "signature")):
        match = _TENANT_REF.fullmatch(value) if isinstance(value, str) else None
        if match is None or match.group(1) != kind or match.group(2) != expected_tenant:
            raise SupplyChainObservationDenied("OWNER_REF_INVALID")
    try:
        audit("supply_chain_references_bound", {
            "event_id": finding.event_id,
            "tenant_id": expected_tenant,
            "component_ref": finding.component_ref,
            "risk": finding.risk,
            "indicators": list(finding.indicators),
            "vulnerability_refs": list(vulnerability_refs),
            "catalog_ref": catalog_ref,
            "signature_ref": signature_ref,
            "evidence_refs": list(evidence_refs),
            "trust": "UNTRUSTED_DATA",
            "mode": "DRY_RUN",
            "action": "CORRELATE_ONLY",
            "response_executed": False,
            "deployment": "DISABLED",
        })
    except Exception as exc:
        raise SupplyChainObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    return SupplyChainReferenceBinding(
        finding.event_id, expected_tenant, finding.component_ref, finding.risk,
        finding.indicators, vulnerability_refs, catalog_ref, signature_ref,
        evidence_refs,
    )
