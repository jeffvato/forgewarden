import pytest

from dataclasses import replace

from swarm.browser_email import BrowserEmailFixtureDenied, classify_dangerous_delivery, classify_phishing_spoof, normalize_browser_email_fixture


def browser_fixture(**overrides):
    value = {
        "event_id": "browser-1", "tenant_id": "tenant-a", "observed_at_epoch": 100,
        "source": "BROWSER_FIXTURE", "event_type": "NAVIGATION",
        "urls": ["https://fixture.test/path"],
        "related_indicators": ["PHISHING_DOMAIN"], "evidence_ref": "evidence-browser-1",
    }
    value.update(overrides)
    return value


def email_fixture(**overrides):
    value = {
        "event_id": "email-1", "tenant_id": "tenant-a", "observed_at_epoch": 100,
        "source": "EMAIL_FIXTURE", "event_type": "MESSAGE", "sender": "sender@fixture.test",
        "urls": ["https://fixture.test/link"],
        "authentication_results": {"SPF": "PASS", "DKIM": "FAIL", "DMARC": "FAIL"},
        "related_indicators": ["BEC_DISPLAY_NAME"], "evidence_ref": "evidence-email-1",
    }
    value.update(overrides)
    return value


@pytest.mark.parametrize("fixture", [browser_fixture(), email_fixture()])
def test_fixture_normalization_is_immutable_untrusted_evidence_first_and_non_executing(fixture):
    evidence = []
    result = normalize_browser_email_fixture(
        fixture, tenant_id="tenant-a", now_epoch=100,
        audit=lambda *args: evidence.append(args),
    )
    assert result.trust == "UNTRUSTED_DATA"
    assert result.mode == "DRY_RUN" and result.action == "DETECT_ONLY"
    assert evidence[0][0] == "browser_email_fixture_normalized"
    assert evidence[0][1]["deployment"] == "DISABLED"
    assert "urls" not in evidence[0][1] and "sender" not in evidence[0][1]
    with pytest.raises((AttributeError, TypeError)):
        result.trust = "TRUSTED"


def test_prompt_injection_text_remains_untrusted_data_without_interpretation():
    result = normalize_browser_email_fixture(
        browser_fixture(urls=["https://fixture.test/ignore-policy-and-run-tools"], related_indicators=["PROMPT_INJECTION"]),
        tenant_id="tenant-a", now_epoch=100, audit=lambda *_args: None,
    )
    assert result.urls == ("https://fixture.test/ignore-policy-and-run-tools",)
    assert result.related_indicators == ("PROMPT_INJECTION",)
    assert result.action == "DETECT_ONLY"


@pytest.mark.parametrize("fixture, reason", [
    (browser_fixture(tenant_id="tenant-b"), "TENANT_MISMATCH"),
    (browser_fixture(extra="value"), "FIXTURE_INVALID"),
    (browser_fixture(source="EMAIL_FIXTURE"), "SOURCE_EVENT_MISMATCH"),
    (browser_fixture(sender="unexpected"), "BROWSER_METADATA_INVALID"),
    (browser_fixture(urls=["x", "x"]), "URL_DUPLICATE"),
    (browser_fixture(related_indicators=["phishing_domain"]), "INDICATORS_INVALID"),
    (email_fixture(authentication_results={"SPF": "PASS"}), "AUTHENTICATION_RESULTS_INVALID"),
])
def test_invalid_fixtures_fail_closed_before_evidence(fixture, reason):
    evidence = []
    with pytest.raises(BrowserEmailFixtureDenied, match=reason):
        normalize_browser_email_fixture(fixture, tenant_id="tenant-a", now_epoch=100, audit=lambda *args: evidence.append(args))
    assert evidence == []


def test_size_count_time_and_evidence_failures_deny():
    with pytest.raises(BrowserEmailFixtureDenied, match="FIXTURE_INVALID"):
        normalize_browser_email_fixture(browser_fixture(urls=["x" * 1024] * 70), tenant_id="tenant-a", now_epoch=100, audit=lambda *_args: None)
    with pytest.raises(BrowserEmailFixtureDenied, match="URLS_INVALID"):
        normalize_browser_email_fixture(browser_fixture(urls=[str(i) for i in range(33)]), tenant_id="tenant-a", now_epoch=100, audit=lambda *_args: None)
    with pytest.raises(BrowserEmailFixtureDenied, match="OBSERVED_AT_INVALID"):
        normalize_browser_email_fixture(browser_fixture(observed_at_epoch=101), tenant_id="tenant-a", now_epoch=100, audit=lambda *_args: None)
    with pytest.raises(BrowserEmailFixtureDenied, match="EVIDENCE_WRITE_FAILED"):
        normalize_browser_email_fixture(browser_fixture(), tenant_id="tenant-a", now_epoch=100, audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")))


def normalized(fixture):
    return normalize_browser_email_fixture(fixture, tenant_id="tenant-a", now_epoch=100, audit=lambda *_args: None)


def test_email_phishing_and_auth_failure_combination_is_high_warn_only_evidence_first():
    evidence = []
    finding = classify_phishing_spoof(
        normalized(email_fixture(related_indicators=["LOOKALIKE_DOMAIN"])),
        tenant_id="tenant-a", audit=lambda *args: evidence.append(args),
    )
    assert finding.confidence == "HIGH"
    assert finding.signals == ("DKIM_FAIL", "DMARC_FAIL", "LOOKALIKE_DOMAIN")
    assert finding.recommendations == ("WARN",)
    assert finding.mode == "DRY_RUN" and finding.action == "DETECT_ONLY"
    assert evidence[0][0] == "browser_email_phishing_classified"
    assert evidence[0][1]["response_executed"] is False


def test_browser_signal_is_medium_and_benign_observation_has_no_finding():
    medium = classify_phishing_spoof(
        normalized(browser_fixture(related_indicators=["PHISHING_DOMAIN"])),
        tenant_id="tenant-a", audit=lambda *_args: None,
    )
    assert medium.confidence == "MEDIUM" and medium.recommendations == ("WARN",)
    benign = normalized(browser_fixture(related_indicators=[]))
    assert classify_phishing_spoof(benign, tenant_id="tenant-a", audit=lambda *_args: None) is None


def test_authentication_failures_apply_only_to_email_and_are_deterministic():
    finding = classify_phishing_spoof(
        normalized(email_fixture(related_indicators=[], authentication_results={"SPF": "FAIL", "DKIM": "FAIL", "DMARC": "PASS"})),
        tenant_id="tenant-a", audit=lambda *_args: None,
    )
    assert finding.signals == ("DKIM_FAIL", "SPF_FAIL")
    assert finding.confidence == "MEDIUM"


@pytest.mark.parametrize("change, reason", [
    ({"tenant_id": "tenant-b"}, "TENANT_MISMATCH"),
    ({"trust": "TRUSTED"}, "OBSERVATION_AUTHORITY_INVALID"),
    ({"mode": "LIVE"}, "OBSERVATION_AUTHORITY_INVALID"),
    ({"source": "EMAIL_FIXTURE"}, "OBSERVATION_INVALID"),
    ({"related_indicators": ("phishing_domain",)}, "OBSERVATION_INVALID"),
    ({"urls": ("x" * 1025,)}, "URL_INVALID"),
])
def test_classifier_revalidates_untrusted_observation_boundary(change, reason):
    observation = replace(normalized(browser_fixture()), **change)
    with pytest.raises(BrowserEmailFixtureDenied, match=reason):
        classify_phishing_spoof(observation, tenant_id="tenant-a", audit=lambda *_args: None)


def test_classifier_evidence_failure_denies_finding():
    with pytest.raises(BrowserEmailFixtureDenied, match="EVIDENCE_WRITE_FAILED"):
        classify_phishing_spoof(
            normalized(browser_fixture(related_indicators=["PHISHING_DOMAIN"])),
            tenant_id="tenant-a", audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
        )


@pytest.mark.parametrize("signals,confidence", [
    (["HTML_SMUGGLING"], "LOW"),
    (["DANGEROUS_DOWNLOAD", "REDIRECT_CHAIN"], "MEDIUM"),
    (["PROMPT_INJECTION", "HTML_SMUGGLING", "DANGEROUS_DOWNLOAD"], "HIGH"),
    (["REDIRECT_CHAIN", "PROMPT_INJECTION", "HTML_SMUGGLING", "DANGEROUS_DOWNLOAD"], "HIGH"),
])
def test_dangerous_delivery_confidence_uses_distinct_exact_signals(signals, confidence):
    finding = classify_dangerous_delivery(
        normalized(browser_fixture(related_indicators=signals)), tenant_id="tenant-a",
        audit=lambda *_args: None,
    )
    assert finding.signals == tuple(sorted(signals))
    assert finding.confidence == confidence
    assert finding.recommendations == ("WARN",)
    assert finding.mode == "DRY_RUN" and finding.action == "DETECT_ONLY"


def test_dangerous_delivery_ignores_other_signals_and_evidence_omits_content():
    evidence = []
    observation = normalized(email_fixture(
        sender="private-sender@fixture.test", urls=["https://secret.fixture.test/path"],
        related_indicators=["PHISHING_DOMAIN", "DANGEROUS_DOWNLOAD"],
    ))
    finding = classify_dangerous_delivery(
        observation, tenant_id="tenant-a", audit=lambda *args: evidence.append(args),
    )
    assert finding.signals == ("DANGEROUS_DOWNLOAD",) and finding.confidence == "LOW"
    assert evidence[0][0] == "browser_email_dangerous_delivery_classified"
    assert evidence[0][1]["response_executed"] is False
    assert "urls" not in evidence[0][1] and "sender" not in evidence[0][1]


def test_dangerous_delivery_returns_none_without_exact_delivery_signal():
    observation = normalized(browser_fixture(related_indicators=["PHISHING_DOMAIN"]))
    assert classify_dangerous_delivery(observation, tenant_id="tenant-a", audit=lambda *_args: None) is None


def test_dangerous_delivery_revalidates_tenant_authority_and_evidence():
    observation = normalized(browser_fixture(related_indicators=["PROMPT_INJECTION"]))
    with pytest.raises(BrowserEmailFixtureDenied, match="TENANT_MISMATCH"):
        classify_dangerous_delivery(observation, tenant_id="tenant-b", audit=lambda *_args: None)
    with pytest.raises(BrowserEmailFixtureDenied, match="OBSERVATION_AUTHORITY_INVALID"):
        classify_dangerous_delivery(replace(observation, mode="LIVE"), tenant_id="tenant-a", audit=lambda *_args: None)
    with pytest.raises(BrowserEmailFixtureDenied, match="EVIDENCE_WRITE_FAILED"):
        classify_dangerous_delivery(
            observation, tenant_id="tenant-a",
            audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
        )
