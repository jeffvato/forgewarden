import json
import time
import urllib.request
from pathlib import Path

import pytest

from swarm.azure_foundry_adapter import AzureCreditEvidence, AzureCreditGuard, AzureFoundryConfig, AzureFoundryError, AzureFoundryReviewer, azure_cli_token

JOB = "phase2a-" + "a" * 24
COMMIT = "b" * 40


def approval():
    return {"job_id": JOB, "reviewed_commit": COMMIT, "verdict": "APPROVE", "risk": "LOW", "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [], "reasoning_summary": "bounded review", "proposed_rules": []}


class Response:
    def __init__(self, body): self.body = body
    def __enter__(self): return self
    def __exit__(self, *_args): return None
    def read(self, _limit): return self.body


def evidence(now=None, **changes):
    current = time.time() if now is None else now
    values = dict(remaining_microusd=900_000_000, expires_at_epoch=current + 86_400, verified_at_epoch=current, credit_only=True, spending_protection=True)
    values.update(changes)
    return AzureCreditEvidence(**values)


def guard(tmp_path: Path, current=None, **kwargs):
    fixed = time.time() if current is None else current
    return AzureCreditGuard(tmp_path / "ledger.json", lambda: evidence(fixed), per_call_ceiling_microusd=1_000_000, reserve_microusd=100_000_000, **kwargs)


def test_foundry_review_uses_v1_route_entra_and_exact_schema(tmp_path: Path):
    captured = {}
    body = json.dumps({"choices": [{"message": {"content": json.dumps(approval())}}]}).encode()
    def opener(request: urllib.request.Request, timeout: int):
        captured.update(url=request.full_url, headers=dict(request.header_items()), payload=json.loads(request.data), timeout=timeout)
        return Response(body)
    reviewer = AzureFoundryReviewer(AzureFoundryConfig("https://forgewarden.openai.azure.com", "review-model"), lambda: "opaque-token", guard(tmp_path), opener=opener)
    assert reviewer.run(None, JOB, COMMIT, "exact patch")["verdict"] == "APPROVE"
    assert captured["url"] == "https://forgewarden.openai.azure.com/openai/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer opaque-token"
    assert captured["payload"]["model"] == "review-model" and captured["payload"]["max_completion_tokens"] == 4000
    assert "opaque-token" not in json.dumps(captured["payload"])


def test_api_key_header_is_transport_only(tmp_path: Path):
    captured = {}
    body = json.dumps({"choices": [{"message": {"content": approval()}}]}).encode()
    def opener(request, timeout):
        captured.update(headers=dict(request.header_items()), payload=request.data)
        return Response(body)
    config = AzureFoundryConfig("https://forgewarden.services.ai.azure.com/openai/v1", "review-model", auth_method="api_key")
    AzureFoundryReviewer(config, lambda: "opaque-api-key", guard(tmp_path), opener=opener).run(None, JOB, COMMIT, "review")
    assert captured["headers"]["Api-key"] == "opaque-api-key"
    assert b"opaque-api-key" not in captured["payload"]


@pytest.mark.parametrize("endpoint", ["http://forgewarden.openai.azure.com", "https://evil.example.com", "https://user:pass@forgewarden.openai.azure.com", "https://forgewarden.openai.azure.com/other"])
def test_endpoint_allowlist_blocks_unsafe_routes(endpoint):
    with pytest.raises(AzureFoundryError, match="endpoint"):
        AzureFoundryConfig(endpoint, "model")


def test_credit_guard_denies_stale_expired_paygo_or_low_balance(tmp_path: Path):
    now = 2_000_000_000.0
    cases = [evidence(now, verified_at_epoch=now - 901), evidence(now, expires_at_epoch=now), evidence(now, credit_only=False), evidence(now, spending_protection=False), evidence(now, remaining_microusd=100_500_000)]
    for index, proof in enumerate(cases):
        gate = AzureCreditGuard(tmp_path / f"ledger-{index}.json", lambda proof=proof: proof, per_call_ceiling_microusd=1_000_000, reserve_microusd=100_000_000)
        with pytest.raises(AzureFoundryError): gate.reserve(now=now)


def test_credit_guard_reserves_worst_case_and_enforces_daily_limit(tmp_path: Path):
    now = 2_000_000_000.0
    gate = AzureCreditGuard(tmp_path / "ledger.json", lambda: evidence(now), per_call_ceiling_microusd=2_000_000, reserve_microusd=100_000_000, daily_call_limit=1)
    gate.reserve(now=now)
    state = json.loads((tmp_path / "ledger.json").read_text())
    assert state["calls"] == 1 and state["reserved_microusd"] == 2_000_000
    with pytest.raises(AzureFoundryError, match="daily"): gate.reserve(now=now)


def test_malformed_or_mismatched_provider_output_is_rejected(tmp_path: Path):
    wrong = approval(); wrong["reviewed_commit"] = "c" * 40
    body = json.dumps({"choices": [{"message": {"content": json.dumps(wrong)}}]}).encode()
    reviewer = AzureFoundryReviewer(AzureFoundryConfig("https://forgewarden.openai.azure.com", "model"), lambda: "token", guard(tmp_path), opener=lambda *_args, **_kwargs: Response(body))
    with pytest.raises(Exception, match="commit"): reviewer.run(None, JOB, COMMIT, "review")


def test_azure_cli_token_uses_cognitive_scope_and_redacts_failures():
    calls = []
    class Completed: returncode = 0; stdout = "opaque-token\n"; stderr = ""
    def runner(command, **kwargs): calls.append((command, kwargs)); return Completed()
    assert azure_cli_token(runner=runner) == "opaque-token"
    assert "https://cognitiveservices.azure.com/.default" in calls[0][0]
    class Failed: returncode = 1; stdout = ""; stderr = "Bearer sk-abcdefghijk"
    with pytest.raises(AzureFoundryError) as error: azure_cli_token(runner=lambda *_args, **_kwargs: Failed())
    assert "sk-abcdefghijk" not in str(error.value)
