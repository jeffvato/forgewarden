from __future__ import annotations

import json
import urllib.error
from pathlib import Path

import pytest

from swarm.verification_adapters import DaybreakReviewer, VerificationAdapter, daybreak_adapter, nvidia_adapter, openrouter_adapter


JOB = "phase2a-0123456789abcdef01234567"
COMMIT = "a" * 40


def test_provider_defaults_pin_models_and_endpoints():
    assert openrouter_adapter().model == "z-ai/glm-5.2:free"
    assert openrouter_adapter().endpoint == "https://openrouter.ai/api/v1/chat/completions"
    assert nvidia_adapter().model == "mistralai/mistral-nemotron"
    assert nvidia_adapter().endpoint == "https://integrate.api.nvidia.com/v1/chat/completions"
    assert daybreak_adapter().model == "gpt-daybreak-blue-latest"
    assert daybreak_adapter().endpoint == "https://api.openai.com/v1/responses"


def test_daybreak_posts_responses_api_request_with_strict_commit_bound_schema(tmp_path: Path, monkeypatch):
    captured = {}
    result = {
        "job_id": JOB, "reviewed_commit": COMMIT, "verdict": "APPROVE", "risk": "LOW",
        "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [],
        "reasoning_summary": "verified", "proposed_rules": [],
    }

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, limit):
            assert limit == 131_072
            return json.dumps({"status": "completed", "output_text": json.dumps(result)}).encode()

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["body"] = json.loads(request.data)
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setenv("OPENAI_API_KEY", "mock-daybreak-key")
    monkeypatch.setattr("swarm.verification_adapters.urllib.request.urlopen", fake_urlopen)
    assert daybreak_adapter().run(tmp_path, JOB, COMMIT, "review exact patch") == result
    body = captured["body"]
    assert body["model"] == "gpt-daybreak-blue-latest"
    assert body["access_programs"] == {"cyber": "daybreak_blue"}
    assert body["input"][0]["content"] == "review exact patch\nReturn only the JSON review object."
    assert body["text"]["format"]["type"] == "json_schema"
    assert body["text"]["format"]["strict"] is True
    assert body["text"]["format"]["schema"]["properties"]["reviewed_commit"]["enum"] == [COMMIT]
    assert captured["request"].get_header("Authorization") == "Bearer mock-daybreak-key"


def test_daybreak_missing_key_and_invalid_binding_fail_closed(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="Daybreak OpenAI API key is unavailable"):
        daybreak_adapter().run(tmp_path, JOB, COMMIT, "review")
    monkeypatch.setenv("OPENAI_API_KEY", "mock-daybreak-key")

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, limit):
            return json.dumps({"status": "completed", "output_text": json.dumps({"job_id": JOB, "reviewed_commit": "b" * 40})}).encode()

    monkeypatch.setattr("swarm.verification_adapters.urllib.request.urlopen", lambda *_args, **_kwargs: Response())
    with pytest.raises(RuntimeError, match="invalid structured|missing required|commit mismatch"):
        daybreak_adapter().run(tmp_path, JOB, COMMIT, "review")


def test_daybreak_rejects_incomplete_and_oversized_responses_without_retry(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "mock-daybreak-key")
    calls = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, limit): return json.dumps({"status": "incomplete"}).encode()
    monkeypatch.setattr("swarm.verification_adapters.urllib.request.urlopen", lambda *_args, **_kwargs: calls.append(1) or Response())
    with pytest.raises(RuntimeError, match="incomplete review"):
        daybreak_adapter().run(tmp_path, JOB, COMMIT, "review")
    assert calls == [1]
    with pytest.raises(RuntimeError, match="24 KB inline bound"):
        daybreak_adapter().run(tmp_path, JOB, COMMIT, "x" * 24_001)
    assert calls == [1]


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


def test_openrouter_daily_call_limit_counts_attempts_and_fails_closed(tmp_path: Path, monkeypatch):
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
        return Response()

    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setattr("swarm.verification_adapters.urllib.request.urlopen", fake_urlopen)
    adapter = VerificationAdapter("OpenRouter", "https://example.test", "test-model", "OPENROUTER_API_KEY", max_attempts=1, daily_call_limit=2, rate_limit_state_path=tmp_path / "rate.json")
    assert adapter.run(tmp_path, JOB, COMMIT, "review")["verdict"] == "APPROVE"
    assert adapter.run(tmp_path, JOB, COMMIT, "review")["verdict"] == "APPROVE"
    with pytest.raises(RuntimeError, match="daily call limit reached"):
        adapter.run(tmp_path, JOB, COMMIT, "review")
    assert calls == 2
    assert json.loads((tmp_path / "rate.json").read_text())["calls"] == 2
