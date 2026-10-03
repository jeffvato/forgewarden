"""Read-only OpenAI-compatible verification providers."""
from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None

from .claude_verifier import schema
from .core import SwarmError, redact, validate_contract


class DaybreakReviewer:
    """Read-only exact-commit reviewer using OpenAI Responses and Daybreak Blue."""

    endpoint = "https://api.openai.com/v1/responses"
    model = "gpt-daybreak-blue-latest"

    def __init__(self, timeout: int = 90):
        self.timeout = timeout

    @staticmethod
    def _schema(job_id: str, commit: str) -> dict[str, Any]:
        return {
            "type": "object", "additionalProperties": False,
            "required": ["job_id", "reviewed_commit", "verdict", "risk", "blocking_findings", "non_blocking_notes", "tests_missing", "reasoning_summary", "proposed_rules"],
            "properties": {
                "job_id": {"type": "string", "enum": [job_id]},
                "reviewed_commit": {"type": "string", "enum": [commit]},
                "verdict": {"type": "string", "enum": ["APPROVE", "REJECT", "HUMAN_REQUIRED"]},
                "risk": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH"]},
                "blocking_findings": {"type": "array", "items": {"type": "string"}},
                "non_blocking_notes": {"type": "array", "items": {"type": "string"}},
                "tests_missing": {"type": "array", "items": {"type": "string"}},
                "reasoning_summary": {"type": "string"},
                "proposed_rules": {"type": "array", "items": {"type": "string"}},
            },
        }

    def run(self, snapshot: Path, job_id: str, commit: str, prompt: str) -> dict[str, Any]:
        del snapshot
        if len(prompt.encode("utf-8")) > 24_000:
            raise SwarmError("Daybreak review input exceeds the 24 KB inline bound")
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            raise SwarmError("Daybreak OpenAI API key is unavailable")
        # Singleton enums bind job/SHA while using the strict-output subset.
        contract = self._schema(job_id, commit)
        payload = {
            "model": self.model,
            "access_programs": {"cyber": "daybreak_blue"},
            "input": [{"role": "user", "content": prompt + "\nReturn only the JSON review object."}],
            "text": {"format": {"type": "json_schema", "name": "forgewarden_exact_review", "strict": True, "schema": contract}},
            "max_output_tokens": 1800,
        }
        request = urllib.request.Request(
            self.endpoint, data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read(131_072).decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise SwarmError(f"Daybreak Responses request failed: {redact(str(exc))[:400]}") from exc
        if not isinstance(body, dict) or body.get("status") != "completed":
            raise SwarmError("Daybreak Responses returned an incomplete review")
        output = body.get("output_text")
        if not isinstance(output, str):
            chunks = [
                part.get("text") for item in body.get("output", []) if isinstance(item, dict)
                for part in item.get("content", []) if isinstance(part, dict) and part.get("type") == "output_text"
            ]
            output = "".join(value for value in chunks if isinstance(value, str))
        try:
            result = json.loads(output)
        except (TypeError, json.JSONDecodeError) as exc:
            raise SwarmError("Daybreak returned invalid structured review output") from exc
        if not isinstance(result, dict):
            raise SwarmError("Daybreak returned a non-object review")
        validate_contract(result, "claude", expected_job_id=job_id, expected_commit=commit)
        return result


def daybreak_adapter() -> DaybreakReviewer:
    return DaybreakReviewer()


class VerificationAdapter:
    """Call an OpenAI-compatible reviewer without granting repository access."""

    def __init__(self, provider: str, endpoint: str, model: str, api_key_name: str, timeout: int = 60, max_attempts: int = 3, backoff_seconds: float = 1.0, retry_window_seconds: float = 90.0, daily_call_limit: int | None = None, rate_limit_state_path: Path | None = None):
        self.provider = provider
        self.endpoint = endpoint
        self.model = model
        self.api_key_name = api_key_name
        self.timeout = timeout
        self.max_attempts = max(1, max_attempts)
        self.backoff_seconds = max(0.0, backoff_seconds)
        self.retry_window_seconds = max(0.0, retry_window_seconds)
        self.daily_call_limit = daily_call_limit if daily_call_limit is None else max(0, daily_call_limit)
        self.rate_limit_state_path = rate_limit_state_path or Path(os.environ.get("FORGEWARDEN_OPENROUTER_RATE_LIMIT_STATE", "~/.cache/forgewarden/openrouter-rate-limit.json")).expanduser()

    def _reserve_daily_call(self) -> None:
        if self.daily_call_limit is None:
            return
        path = self.rate_limit_state_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a+", encoding="utf-8") as state_file:
            if fcntl is not None:
                fcntl.flock(state_file.fileno(), fcntl.LOCK_EX)
            try:
                state_file.seek(0)
                raw = state_file.read().strip()
                state = json.loads(raw) if raw else {}
                today = time.strftime("%Y-%m-%d", time.gmtime())
                if state.get("date") != today:
                    state = {"date": today, "calls": 0}
                calls = int(state.get("calls", 0))
                if calls >= self.daily_call_limit:
                    raise SwarmError(f"{self.provider} daily call limit reached ({self.daily_call_limit})")
                state["calls"] = calls + 1
                state_file.seek(0)
                state_file.truncate()
                json.dump(state, state_file)
                state_file.flush()
            finally:
                if fcntl is not None:
                    fcntl.flock(state_file.fileno(), fcntl.LOCK_UN)

    def run(self, snapshot: Path, job_id: str, commit: str, prompt: str) -> dict[str, Any]:
        del snapshot  # The exact patch is already included in the bounded prompt.
        api_key = os.environ.get(self.api_key_name, "")
        if not api_key:
            raise SwarmError(f"{self.provider} API key is unavailable")
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt + "\nReturn only the JSON review object."}],
            "temperature": 0,
            "response_format": {"type": "json_schema", "json_schema": {"name": "review", "strict": True, "schema": schema(job_id, commit)}},
        }
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        last_error: Exception | None = None
        deadline = time.monotonic() + self.retry_window_seconds
        for attempt in range(self.max_attempts):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                self._reserve_daily_call()
                with urllib.request.urlopen(request, timeout=min(self.timeout, remaining)) as response:
                    body = json.loads(response.read(2_000_000).decode("utf-8"))
                last_error = None
                break
            except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
                last_error = exc
                retryable = isinstance(exc, (TimeoutError, socket.timeout, urllib.error.URLError))
                if isinstance(exc, urllib.error.HTTPError):
                    retryable = exc.code == 429 or 500 <= exc.code < 600
                elif isinstance(exc, urllib.error.URLError):
                    retryable = isinstance(exc.reason, (TimeoutError, socket.timeout, ConnectionError))
                if not retryable or attempt + 1 >= self.max_attempts:
                    break
                delay = self.backoff_seconds * (2**attempt)
                if isinstance(exc, urllib.error.HTTPError):
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    try:
                        delay = max(delay, float(retry_after)) if retry_after is not None else delay
                    except (TypeError, ValueError):
                        pass
                time.sleep(min(delay, max(0.0, deadline - time.monotonic())))
        else:
            last_error = RuntimeError("retry loop exhausted")
        if last_error is not None:
            raise SwarmError(f"{self.provider} request failed: {redact(str(last_error))[:500]}") from last_error
        try:
            content = body["choices"][0]["message"]["content"]
            result = json.loads(content) if isinstance(content, str) else content
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise SwarmError(f"{self.provider} returned an invalid review response") from exc
        if not isinstance(result, dict):
            raise SwarmError(f"{self.provider} returned a non-object review")
        validate_contract(result, "claude", expected_job_id=job_id, expected_commit=commit)
        return result


def openrouter_adapter() -> VerificationAdapter:
    return VerificationAdapter("OpenRouter", "https://openrouter.ai/api/v1/chat/completions", "z-ai/glm-5.2:free", "OPENROUTER_API_KEY", daily_call_limit=1000)


def nvidia_adapter() -> VerificationAdapter:
    return VerificationAdapter("NVIDIA", "https://integrate.api.nvidia.com/v1/chat/completions", "mistralai/mistral-nemotron", "NVIDIA_API_KEY")
