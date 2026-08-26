"""Read-only OpenAI-compatible verification providers."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .claude_verifier import schema
from .core import SwarmError, redact, validate_contract


class VerificationAdapter:
    """Call an OpenAI-compatible reviewer without granting repository access."""

    def __init__(self, provider: str, endpoint: str, model: str, api_key_name: str, timeout: int = 60):
        self.provider = provider
        self.endpoint = endpoint
        self.model = model
        self.api_key_name = api_key_name
        self.timeout = timeout

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
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read(2_000_000).decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise SwarmError(f"{self.provider} request failed: {redact(str(exc))[:500]}") from exc
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
    return VerificationAdapter("OpenRouter", "https://openrouter.ai/api/v1/chat/completions", "z-ai/glm-5.2:free", "OPENROUTER_API_KEY")


def nvidia_adapter() -> VerificationAdapter:
    return VerificationAdapter("NVIDIA", "https://integrate.api.nvidia.com/v1/chat/completions", "google/gemma-4-31b-it", "NVIDIA_API_KEY")
