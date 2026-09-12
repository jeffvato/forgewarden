"""Bounded AnythingLLM/Qwen exact-commit reviewer through Windows loopback."""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .claude_verifier import schema
from .core import SwarmError, validate_contract

_JOB = re.compile(r"^phase2a-[a-z0-9]{24}$")
_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")
_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")


class AnythingLLMError(SwarmError):
    """AnythingLLM review transport or output failed closed."""


@dataclass(frozen=True)
class AnythingLLMConfig:
    workspace: str = "n8n"
    model: str = "qwen/qwen3.8-27b"
    timeout_seconds: int = 180
    max_prompt_bytes: int = 48_000
    max_output_bytes: int = 131_072

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.workspace) or not _NAME.fullmatch(self.model.replace("/", "-")):
            raise AnythingLLMError("AnythingLLM workspace or model identity is invalid")
        if not 1 <= self.timeout_seconds <= 300 or not 1 <= self.max_prompt_bytes <= 64_000 or not 1 <= self.max_output_bytes <= 262_144:
            raise AnythingLLMError("AnythingLLM bounds are invalid")


class AnythingLLMReviewer:
    """Call a fixed, credential-isolating bridge; the model receives no tools."""

    def __init__(self, config: AnythingLLMConfig, *, runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run):
        self.config = config
        self._runner = runner

    def run(self, snapshot: object, job_id: str, commit: str, prompt: str) -> dict[str, Any]:
        del snapshot
        if not _JOB.fullmatch(job_id) or not _SHA.fullmatch(commit):
            raise AnythingLLMError("AnythingLLM review binding is invalid")
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt.encode("utf-8")) > self.config.max_prompt_bytes:
            raise AnythingLLMError("AnythingLLM prompt is missing or exceeds its bound")
        bridge = Path(__file__).resolve().parents[1] / "scripts" / "anythingllm-review-bridge.ps1"
        if not bridge.is_file() or bridge.is_symlink():
            raise AnythingLLMError("AnythingLLM trusted bridge is unavailable")
        parts = bridge.resolve().parts
        if len(parts) < 4 or parts[:3] != ("/", "mnt", "c"):
            raise AnythingLLMError("AnythingLLM bridge must reside on the trusted Windows volume")
        windows_bridge = "C:\\" + "\\".join(parts[3:])
        request = (
            f"You are an independent read-only code reviewer using configured model {self.config.model}. "
            f"Review only Phase 2A job {job_id} and exact commit {commit}. "
            "Return only one JSON object matching this schema; do not use tools, request secrets, mutate files, "
            "authorize deployment, or claim a different model identity.\nSchema:\n"
            + json.dumps(schema(job_id, commit), separators=(",", ":"))
            + "\nReview context:\n" + prompt
        ).encode("utf-8")
        env = {"SystemRoot": os.environ.get("SystemRoot", r"C:\\Windows"), "WINDIR": os.environ.get("WINDIR", r"C:\\Windows")}
        completed = self._runner(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", windows_bridge, "-Workspace", self.config.workspace, "-SessionId", job_id],
            input=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.config.timeout_seconds,
            check=False, env=env,
        )
        if completed.returncode != 0:
            raise AnythingLLMError("AnythingLLM bridge unavailable")
        if len(completed.stdout) > self.config.max_output_bytes:
            raise AnythingLLMError("AnythingLLM response exceeds its bound")
        try:
            result = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AnythingLLMError("AnythingLLM returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise AnythingLLMError("AnythingLLM result is not an object")
        validate_contract(result, "claude", expected_job_id=job_id, expected_commit=commit)
        return result
