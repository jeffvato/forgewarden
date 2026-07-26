"""Explicit, read-only Claude reviewer for sanitized swarm evidence.

This adapter is intentionally separate from Phase 2A, MCP, Codex, and the
Fable credit adapter.  It sends only the context supplied by its caller and
never reads a repository or writes durable provider output.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from .core import SwarmError, redact

CLAUDE = Path("/home/jeff/.local/bin/claude")
DEFAULT_MODEL = "sonnet"
ALLOWED_MODELS = frozenset({"sonnet", "opus", "haiku"})
MAX_TURNS = 3
TIMEOUT_SECONDS = 180
MAX_CONTEXT_BYTES = 24000
MAX_OUTPUT_BYTES = 131072
JOB_RE = re.compile(r"^claude-[a-z0-9]{24}$")


class ClaudeAdapterError(SwarmError):
    """A fail-closed Claude contract or process failure."""


def new_job_id() -> str:
    return "claude-" + uuid.uuid4().hex[:24]


def minimal_environment() -> dict[str, str]:
    # HOME is required for Claude Code's existing user-supported auth path.
    # No credential value is copied into this environment.
    return {
        "HOME": "/home/jeff",
        "PATH": "/home/jeff/.local/bin:/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PYTHONNOUSERSITE": "1",
    }


def sanitize_context(context: str) -> str:
    if not isinstance(context, str) or not context.strip():
        raise ValueError("Claude review context must be non-empty text")
    value = redact(context)
    value = re.sub(r"(?i)(/home/[^\s`]+/\.env|/home/[^\s`]+/\.credentials[^\s`]*)", "[PRIVATE_PATH_REDACTED]", value)
    value = re.sub(r"(?i)(api[_-]?key|token|password|secret|authorization)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]", value)
    encoded = value.encode("utf-8")[:MAX_CONTEXT_BYTES]
    return encoded.decode("utf-8", errors="ignore")


def schema(job_id: str, model: str) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["job_id", "model", "findings", "recommendations", "limitations"],
        "properties": {
            "job_id": {"const": job_id},
            "model": {"const": model},
            "findings": {"type": "array", "maxItems": 12, "items": {"type": "string", "maxLength": 1200}},
            "recommendations": {"type": "array", "maxItems": 12, "items": {"type": "string", "maxLength": 1200}},
            "limitations": {"type": "array", "maxItems": 12, "items": {"type": "string", "maxLength": 800}},
        },
    }


def _extract_result(envelope: Any) -> dict[str, Any]:
    if not isinstance(envelope, dict):
        raise ClaudeAdapterError("Claude output is not a JSON object")
    payload = envelope.get("structured_output", envelope.get("result", envelope))
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ClaudeAdapterError("Claude result is not JSON") from exc
    if not isinstance(payload, dict):
        raise ClaudeAdapterError("Claude structured result is not an object")
    return payload


def validate_result(payload: dict[str, Any], job_id: str, model: str) -> None:
    import jsonschema

    try:
        jsonschema.Draft202012Validator(schema(job_id, model)).validate(payload)
    except jsonschema.ValidationError as exc:
        raise ClaudeAdapterError("Claude structured result failed schema validation") from exc


def run_claude(job_id: str, context: str, *, model: str = DEFAULT_MODEL) -> dict[str, Any]:
    """Run one explicit advisory review; never mutate swarm or project state."""
    if not JOB_RE.fullmatch(job_id):
        raise ValueError("invalid Claude job ID")
    if model not in ALLOWED_MODELS:
        raise ValueError("model must be sonnet, opus, or haiku")
    if not CLAUDE.is_file() or not os.access(CLAUDE, os.X_OK):
        raise ClaudeAdapterError("Claude CLI is unavailable")
    sanitized = sanitize_context(context)
    prompt = (
        f"You are a read-only reviewer for job {job_id}. Return JSON matching the supplied schema. "
        "Do not use tools, shell, files, edits, Git, MCP, agents, deployment, or network resources. "
        "This is advisory evidence only; do not authorize changes or clear safety gates.\n\n"
        + sanitized
    )
    schema_json = json.dumps(schema(job_id, model), separators=(",", ":"), sort_keys=True)
    argv = [
        str(CLAUDE), "-p", prompt, "--model", model, "--output-format", "json",
        "--json-schema", schema_json, "--tools", "", "--permission-mode", "plan",
        "--no-session-persistence", "--max-turns", str(MAX_TURNS),
        "--strict-mcp-config", "--disable-slash-commands", "--no-chrome",
    ]
    try:
        with tempfile.TemporaryDirectory(prefix="hermes-claude-review-", dir="/tmp") as review_dir:
            completed = subprocess.run(
                argv, cwd=review_dir, env=minimal_environment(), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False,
                timeout=TIMEOUT_SECONDS, check=False,
            )
    except subprocess.TimeoutExpired as exc:
        raise ClaudeAdapterError("Claude review timed out") from exc
    if completed.returncode != 0:
        raise ClaudeAdapterError(f"Claude CLI failed with exit code {completed.returncode}")
    try:
        envelope = json.loads(completed.stdout[:MAX_OUTPUT_BYTES])
    except json.JSONDecodeError as exc:
        raise ClaudeAdapterError("Claude CLI returned invalid JSON") from exc
    payload = _extract_result(envelope)
    validate_result(payload, job_id, model)
    return payload
