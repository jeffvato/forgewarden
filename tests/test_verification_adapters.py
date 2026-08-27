from __future__ import annotations

import json
import urllib.error
from pathlib import Path

import pytest

from swarm.verification_adapters import VerificationAdapter, nvidia_adapter, openrouter_adapter


JOB = "phase2a-0123456789abcdef01234567"
COMMIT = "a" * 40


def test_provider_defaults_pin_models_and_endpoints():
    assert openrouter_adapter().model == "z-ai/glm-5.2:free"
    assert openrouter_adapter().endpoint == "https://openrouter.ai/api/v1/chat/completions"
    assert nvidia_adapter().model == "mistralai/mistral-nemotron"
    assert nvidia_adapter().endpoint == "https://integrate.api.nvidia.com/v1/chat/completions"


def test_provider_requires_local_api_key(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="API key is unavailable"):
        openrouter_adapter().run(tmp_path, JOB, COMMIT, "review")


def test_provider_posts_schema_bound_review_and_validates_response(tmp_path: Path, monkeypatch):
    captured = {}
    result = {
        "job_id": JOB,
        "reviewed_commit": COMMIT,
        "verdict": "APPROVE",
        "risk": "LOW",
        "blocking_findings": [],
        "non_blocking_notes": [],
        "tests_missing": [],
        "reasoning_summary": "verified",
        "proposed_rules": [],
    }

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, limit): return json.dumps({"choices": [{"message": {"content": json.dumps(result)}}]}).encode()

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
    monkeypatch.setattr("swarm.verification_adapters.urllib.request.urlopen", fake_urlopen)
    assert nvidia_adapter().run(tmp_path, JOB, COMMIT, "review")["verdict"] == "APPROVE"
    body = json.loads(captured["request"].data)
    assert body["model"] == "mistralai/mistral-nemotron"
    assert body["response_format"]["type"] == "json_schema"
    assert captured["request"].get_header("Authorization") == "Bearer test-key"


@pytest.mark.parametrize("failure", [urllib.error.HTTPError("https://example.test", 429, "rate limited", {}, None), TimeoutError("timed out")])
def test_provider_retries_bounded_transient_failures(tmp_path: Path, monkeypatch, failure):
    result = {
        "job_id": JOB, "reviewed_commit": COMMIT, "verdict": "APPROVE", "risk": "LOW",
        "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [],
        "reasoning_summary": "verified", "proposed_rules": [],
    }

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, limit): return json.dumps({"choices": [{"message": {"content": json.dumps(result)}}]}).encode()

    calls = 0
    def fake_urlopen(request, timeout):
        nonlocal calls
        calls += 1
        if calls < 3:
            raise failure
        return Response()

    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setattr("swarm.verification_adapters.urllib.request.urlopen", fake_urlopen)
    adapter = VerificationAdapter("OpenRouter", "https://example.test", "test-model", "OPENROUTER_API_KEY", max_attempts=3, backoff_seconds=0)
    assert adapter.run(tmp_path, JOB, COMMIT, "review")["verdict"] == "APPROVE"
    assert calls == 3


def test_provider_honors_retry_after_without_exceeding_window(tmp_path: Path, monkeypatch):
    result = {
        "job_id": JOB, "reviewed_commit": COMMIT, "verdict": "APPROVE", "risk": "LOW",
        "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [],
        "reasoning_summary": "verified", "proposed_rules": [],
    }

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, limit): return json.dumps({"choices": [{"message": {"content": json.dumps(result)}}]}).encode()

    delays = []
    monkeypatch.setattr("swarm.verification_adapters.time.sleep", delays.append)
    calls = 0
    def fake_urlopen(request, timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise urllib.error.HTTPError("https://example.test", 429, "rate limited", {"Retry-After": "7"}, None)
        return Response()

    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setattr("swarm.verification_adapters.urllib.request.urlopen", fake_urlopen)
    adapter = VerificationAdapter("OpenRouter", "https://example.test", "test-model", "OPENROUTER_API_KEY", max_attempts=2, backoff_seconds=1, retry_window_seconds=10)
    assert adapter.run(tmp_path, JOB, COMMIT, "review")["verdict"] == "APPROVE"
    assert delays == [7]
