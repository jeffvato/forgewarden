"""Bounded caller-supplied browser and email fixture normalization.

This module has no browser, mailbox, DNS, HTTP, filesystem, endpoint,
credential, deployment, quarantine, remediation, or response access.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Callable, Mapping

MAX_BME_FIXTURE_BYTES = 64 * 1024
MAX_BME_STRING_BYTES = 1024
MAX_BME_URLS = 32
MAX_BME_INDICATORS = 32
_SOURCES = frozenset({"BROWSER_FIXTURE", "EMAIL_FIXTURE"})
_EVENT_TYPES = frozenset({"NAVIGATION", "MESSAGE"})
_FIXTURE_KEYS = frozenset({
    "event_id", "tenant_id", "observed_at_epoch", "source", "event_type",
    "sender", "urls", "authentication_results", "related_indicators",
    "evidence_ref",
})
_AUTH_KEYS = frozenset({"SPF", "DKIM", "DMARC"})
_AUTH_VALUES = frozenset({"PASS", "FAIL", "NONE", "TEMPERROR"})
_INDICATORS = frozenset({
    "BEC_DISPLAY_NAME", "DANGEROUS_DOWNLOAD", "HTML_SMUGGLING",
    "LOOKALIKE_DOMAIN", "OAUTH_CONSENT_ABUSE", "PHISHING_DOMAIN",
    "PROMPT_INJECTION", "QR_PHISHING", "REDIRECT_CHAIN",
})


class BrowserEmailFixtureDenied(PermissionError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or len(value.encode("utf-8")) > MAX_BME_STRING_BYTES:
        raise BrowserEmailFixtureDenied(f"{field}_INVALID")
    return value


@dataclass(frozen=True)
class BrowserEmailObservation:
    event_id: str
    tenant_id: str
    observed_at_epoch: int
    source: str
    event_type: str
    sender: str | None
    urls: tuple[str, ...]
    authentication_results: tuple[tuple[str, str], ...]
    related_indicators: tuple[str, ...]
    evidence_ref: str
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"


@dataclass(frozen=True)
class BrowserEmailFinding:
    event_id: str
    tenant_id: str
    signals: tuple[str, ...]
    confidence: str
    recommendations: tuple[str, ...] = ("WARN",)
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"


def normalize_browser_email_fixture(
    fixture: Mapping[str, Any], *, tenant_id: str, now_epoch: int,
    audit: Callable[[str, dict[str, Any]], None],
) -> BrowserEmailObservation:
    """Validate and Evidence-log one fixture before returning an observation."""
    if not isinstance(fixture, Mapping) or not callable(audit):
        raise BrowserEmailFixtureDenied("FIXTURE_INVALID")
    try:
        encoded = json.dumps(fixture, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise BrowserEmailFixtureDenied("FIXTURE_INVALID") from exc
    if len(encoded) > MAX_BME_FIXTURE_BYTES or set(fixture) - _FIXTURE_KEYS:
        raise BrowserEmailFixtureDenied("FIXTURE_INVALID")
    expected_tenant = _text(tenant_id, "TENANT")
    if fixture.get("tenant_id") != expected_tenant:
        raise BrowserEmailFixtureDenied("TENANT_MISMATCH")
    source = fixture.get("source")
    event_type = fixture.get("event_type")
    if source not in _SOURCES or event_type not in _EVENT_TYPES:
        raise BrowserEmailFixtureDenied("SOURCE_OR_EVENT_TYPE_INVALID")
    if (source, event_type) not in {("BROWSER_FIXTURE", "NAVIGATION"), ("EMAIL_FIXTURE", "MESSAGE")}:
        raise BrowserEmailFixtureDenied("SOURCE_EVENT_MISMATCH")
    observed = fixture.get("observed_at_epoch")
    if not isinstance(observed, int) or isinstance(observed, bool) or not isinstance(now_epoch, int) or isinstance(now_epoch, bool) or observed < 0 or observed > now_epoch:
        raise BrowserEmailFixtureDenied("OBSERVED_AT_INVALID")
    event_id = _text(fixture.get("event_id"), "EVENT_ID")
    evidence_ref = _text(fixture.get("evidence_ref"), "EVIDENCE_REF")
    urls_value = fixture.get("urls")
    if not isinstance(urls_value, (list, tuple)) or not 1 <= len(urls_value) <= MAX_BME_URLS:
        raise BrowserEmailFixtureDenied("URLS_INVALID")
    urls = tuple(_text(item, "URL") for item in urls_value)
    if len(set(urls)) != len(urls):
        raise BrowserEmailFixtureDenied("URL_DUPLICATE")
    indicators_value = fixture.get("related_indicators", ())
    if not isinstance(indicators_value, (list, tuple)) or len(indicators_value) > MAX_BME_INDICATORS:
        raise BrowserEmailFixtureDenied("INDICATORS_INVALID")
    indicators = tuple(_text(item, "INDICATOR") for item in indicators_value)
    if len(set(indicators)) != len(indicators) or any(item not in _INDICATORS for item in indicators):
        raise BrowserEmailFixtureDenied("INDICATORS_INVALID")

    sender_value = fixture.get("sender")
    auth_value = fixture.get("authentication_results")
    if source == "EMAIL_FIXTURE":
        sender = _text(sender_value, "SENDER")
        if not isinstance(auth_value, Mapping) or set(auth_value) != _AUTH_KEYS:
            raise BrowserEmailFixtureDenied("AUTHENTICATION_RESULTS_INVALID")
        auth = tuple(sorted((key, value) for key, value in auth_value.items()))
        if any(value not in _AUTH_VALUES for _, value in auth):
            raise BrowserEmailFixtureDenied("AUTHENTICATION_RESULTS_INVALID")
    else:
        if sender_value is not None or auth_value is not None:
            raise BrowserEmailFixtureDenied("BROWSER_METADATA_INVALID")
        sender = None
        auth = ()
    try:
        audit("browser_email_fixture_normalized", {
            "event_id": event_id, "tenant_id": expected_tenant,
            "observed_at_epoch": observed, "source": source,
            "event_type": event_type, "url_count": len(urls),
            "indicator_count": len(indicators), "evidence_ref": evidence_ref,
            "trust": "UNTRUSTED_DATA", "mode": "DRY_RUN",
            "action": "DETECT_ONLY", "deployment": "DISABLED",
        })
    except Exception as exc:
        raise BrowserEmailFixtureDenied("EVIDENCE_WRITE_FAILED") from exc
    return BrowserEmailObservation(
        event_id, expected_tenant, observed, source, event_type, sender, urls,
        auth, indicators, evidence_ref,
    )


def classify_phishing_spoof(
    observation: BrowserEmailObservation, *, tenant_id: str,
    audit: Callable[[str, dict[str, Any]], None],
) -> BrowserEmailFinding | None:
    """Classify exact fixture signals without interpreting content or taking action."""
    expected_tenant, indicator_signals, auth_failures = _validated_observation(observation, tenant_id, audit)
    signals = indicator_signals | auth_failures

    threat_signals = signals & {
        "BEC_DISPLAY_NAME", "LOOKALIKE_DOMAIN", "PHISHING_DOMAIN", "QR_PHISHING",
        "REDIRECT_CHAIN",
    }
    confidence: str | None = None
    if len(threat_signals) >= 2 or (threat_signals and "DMARC_FAIL" in auth_failures):
        confidence = "HIGH"
    elif threat_signals or len(auth_failures) >= 2:
        confidence = "MEDIUM"
    elif auth_failures:
        confidence = "LOW"
    if confidence is None:
        return None
    ordered_signals = tuple(sorted(signals))
    try:
        audit("browser_email_phishing_classified", {
            "event_id": observation.event_id, "tenant_id": expected_tenant,
            "signals": list(ordered_signals), "confidence": confidence,
            "recommendations": ["WARN"], "trust": "UNTRUSTED_DATA",
            "mode": "DRY_RUN", "action": "DETECT_ONLY",
            "response_executed": False, "deployment": "DISABLED",
        })
    except Exception as exc:
        raise BrowserEmailFixtureDenied("EVIDENCE_WRITE_FAILED") from exc
    return BrowserEmailFinding(
        observation.event_id, expected_tenant, ordered_signals, confidence,
    )


def _validated_observation(
    observation: BrowserEmailObservation, tenant_id: str,
    audit: Callable[[str, dict[str, Any]], None],
) -> tuple[str, set[str], set[str]]:
    """Revalidate one immutable untrusted observation at each classifier seam."""
    if not isinstance(observation, BrowserEmailObservation) or not callable(audit):
        raise BrowserEmailFixtureDenied("OBSERVATION_INVALID")
    expected_tenant = _text(tenant_id, "TENANT")
    if observation.tenant_id != expected_tenant:
        raise BrowserEmailFixtureDenied("TENANT_MISMATCH")
    if observation.trust != "UNTRUSTED_DATA" or observation.mode != "DRY_RUN" or observation.action != "DETECT_ONLY":
        raise BrowserEmailFixtureDenied("OBSERVATION_AUTHORITY_INVALID")
    if (observation.source, observation.event_type) not in {("BROWSER_FIXTURE", "NAVIGATION"), ("EMAIL_FIXTURE", "MESSAGE")}:
        raise BrowserEmailFixtureDenied("OBSERVATION_INVALID")
    if not isinstance(observation.observed_at_epoch, int) or isinstance(observation.observed_at_epoch, bool) or observation.observed_at_epoch < 0:
        raise BrowserEmailFixtureDenied("OBSERVATION_INVALID")
    _text(observation.event_id, "EVENT_ID")
    _text(observation.evidence_ref, "EVIDENCE_REF")
    if not isinstance(observation.urls, tuple) or not 1 <= len(observation.urls) <= MAX_BME_URLS or len(set(observation.urls)) != len(observation.urls):
        raise BrowserEmailFixtureDenied("OBSERVATION_INVALID")
    for url in observation.urls:
        _text(url, "URL")
    if not isinstance(observation.related_indicators, tuple) or len(observation.related_indicators) > MAX_BME_INDICATORS or len(set(observation.related_indicators)) != len(observation.related_indicators) or any(item not in _INDICATORS for item in observation.related_indicators):
        raise BrowserEmailFixtureDenied("OBSERVATION_INVALID")

    signals = set(observation.related_indicators)
    auth_failures: set[str] = set()
    if observation.source == "EMAIL_FIXTURE":
        auth = dict(observation.authentication_results)
        if observation.sender is None or set(auth) != _AUTH_KEYS or any(value not in _AUTH_VALUES for value in auth.values()):
            raise BrowserEmailFixtureDenied("OBSERVATION_INVALID")
        _text(observation.sender, "SENDER")
        auth_failures.update(f"{key}_FAIL" for key, value in auth.items() if value == "FAIL")
    elif observation.sender is not None or observation.authentication_results:
        raise BrowserEmailFixtureDenied("OBSERVATION_INVALID")
    return expected_tenant, signals, auth_failures


def classify_dangerous_delivery(
    observation: BrowserEmailObservation, *, tenant_id: str,
    audit: Callable[[str, dict[str, Any]], None],
) -> BrowserEmailFinding | None:
    """Classify exact delivery indicators without opening or fetching content."""
    expected_tenant, indicators, _auth_failures = _validated_observation(observation, tenant_id, audit)
    signals = indicators & {
        "DANGEROUS_DOWNLOAD", "HTML_SMUGGLING", "PROMPT_INJECTION", "REDIRECT_CHAIN",
    }
    if not signals:
        return None
    confidence = "LOW" if len(signals) == 1 else "MEDIUM" if len(signals) == 2 else "HIGH"
    ordered_signals = tuple(sorted(signals))
    try:
        audit("browser_email_dangerous_delivery_classified", {
            "event_id": observation.event_id, "tenant_id": expected_tenant,
            "signals": list(ordered_signals), "confidence": confidence,
            "recommendations": ["WARN"], "trust": "UNTRUSTED_DATA",
            "mode": "DRY_RUN", "action": "DETECT_ONLY",
            "response_executed": False, "deployment": "DISABLED",
        })
    except Exception as exc:
        raise BrowserEmailFixtureDenied("EVIDENCE_WRITE_FAILED") from exc
    return BrowserEmailFinding(
        observation.event_id, expected_tenant, ordered_signals, confidence,
    )


def classify_oauth_consent_abuse(
    observation: BrowserEmailObservation, *, tenant_id: str,
    audit: Callable[[str, dict[str, Any]], None],
) -> BrowserEmailFinding | None:
    """Classify an exact caller-supplied OAuth-consent indicator without acting."""
    expected_tenant, indicators, _auth_failures = _validated_observation(
        observation, tenant_id, audit,
    )
    if "OAUTH_CONSENT_ABUSE" not in indicators:
        return None
    try:
        audit("browser_email_oauth_consent_abuse_classified", {
            "event_id": observation.event_id,
            "tenant_id": expected_tenant,
            "signals": ["OAUTH_CONSENT_ABUSE"],
            "confidence": "HIGH",
            "recommendations": ["WARN"],
            "trust": "UNTRUSTED_DATA",
            "mode": "DRY_RUN",
            "action": "DETECT_ONLY",
            "response_executed": False,
            "deployment": "DISABLED",
        })
    except Exception as exc:
        raise BrowserEmailFixtureDenied("EVIDENCE_WRITE_FAILED") from exc
    return BrowserEmailFinding(
        observation.event_id, expected_tenant, ("OAUTH_CONSENT_ABUSE",), "HIGH",
    )
