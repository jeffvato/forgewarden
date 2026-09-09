"""Commit-bound, read-only Claude verification adapter for Phase 2A."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from .claude_adapter import CLAUDE, MODEL_ALIASES, minimal_environment, sanitize_context
from .core import SwarmError, validate_contract

# Exact reviews are deliberately single-turn and tool-free: the bounded patch is
# embedded in the review context, so allowing a tool loop only adds latency and
# makes the verifier appear unavailable when the CLI is otherwise healthy.
MODEL = MODEL_ALIASES["haiku"]
TIMEOUT_SECONDS = 180
MAX_OUTPUT_BYTES = 131072
# Claude's structured-output wrapper accounts for the request and response as
# two turns even when no tools are enabled; two is the smallest reliable bound.
MAX_TURNS = 2


def _write_diagnostic(path: Path | None, payload: dict[str, Any]) -> None:
    if path is None:
        return
    if path.is_symlink() or any(parent.is_symlink() for parent in (path.parent, *path.parent.parents)):
        raise ClaudeVerificationError("Claude diagnostic path is symlinked")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


class ClaudeVerificationError(SwarmError):
    """Claude could not satisfy the commit-bound verification contract."""


def schema(job_id: str, commit: str) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["job_id", "reviewed_commit", "verdict", "risk", "blocking_findings", "non_blocking_notes", "tests_missing", "reasoning_summary", "proposed_rules"],
        "properties": {
            "job_id": {"const": job_id},
            "reviewed_commit": {"const": commit},
            "verdict": {"enum": ["APPROVE", "REJECT", "HUMAN_REQUIRED"]},
            "risk": {"enum": ["LOW", "MEDIUM", "HIGH"]},
            "blocking_findings": {"type": "array", "maxItems": 32},
            "non_blocking_notes": {"type": "array", "maxItems": 32},
            "tests_missing": {"type": "array", "maxItems": 32},
            "reasoning_summary": {"type": "string", "minLength": 1, "maxLength": 4000},
            "proposed_rules": {"type": "array", "maxItems": 1},
        },
    }


def _payload(stdout: str) -> dict[str, Any]:
    if not stdout.strip():
        raise ClaudeVerificationError("Claude verifier returned empty output")
    try:
        envelope = json.loads(stdout[:MAX_OUTPUT_BYTES])
    except json.JSONDecodeError as exc:
        raise ClaudeVerificationError("Claude verifier returned invalid JSON") from exc
    if not isinstance(envelope, dict):
        raise ClaudeVerificationError("Claude verifier returned a non-object")
    if "structured_output" not in envelope and "result" not in envelope:
        raise ClaudeVerificationError("Claude verifier response envelope is missing result")
    result = envelope.get("structured_output", envelope.get("result"))
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except json.JSONDecodeError as exc:
            raise ClaudeVerificationError("Claude verifier result is not JSON") from exc
    if not isinstance(result, dict):
        raise ClaudeVerificationError("Claude verifier structured result is not an object")
    return result


def _sanitize_review_context(prompt: str) -> str:
    """Sanitize instructions without rewriting the exact embedded Git patch."""
    marker = "\n\nExact candidate patch from Git:\n"
    if marker not in prompt:
        return sanitize_context(prompt)
    instructions, patch = prompt.split(marker, 1)
    return sanitize_context(instructions) + marker + patch


def run(snapshot: Path, job_id: str, commit: str, prompt: str, *, diagnostic_path: Path | None = None) -> dict[str, Any]:
    if not re.fullmatch(r"phase2a-[a-z0-9]{24}", job_id):
        raise ClaudeVerificationError("invalid Phase 2A job ID")
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", commit):
        raise ClaudeVerificationError("invalid review commit")
    if not CLAUDE.is_file() or not os.access(CLAUDE, os.X_OK):
        raise ClaudeVerificationError("Claude CLI is unavailable")
    context = _sanitize_review_context(prompt)
    patch_file_mode = "Exact candidate patch is available at EXACT_CANDIDATE.patch." in context
    schema_value = schema(job_id, commit)
    patch_instruction = (
        "The complete exact patch is included in the review context; do not use tools or inspect unrelated files."
        if not patch_file_mode else
        "The complete exact patch is available at EXACT_CANDIDATE.patch; use only the read-only file viewer to inspect it."
    )
    verifier_prompt = (
        f"You are the primary read-only verifier for Phase 2A job {job_id}. "
        f"Review only the exact commit {commit} in this disposable snapshot. "
        "Return one JSON object matching the supplied schema. APPROVE only when the "
        "deterministic checks passed, the patch is narrow, and there are no blocking "
        "findings or missing tests. " + patch_instruction + " Do not use shell, Git, edits, MCP, deployment, "
        "or network resources. Do not authorize any action beyond this verification.\n\n" + context
    )
    argv = [
        str(CLAUDE), "-p", verifier_prompt, "--model", MODEL, "--output-format", "json",
        "--json-schema", json.dumps(schema_value, separators=(",", ":"), sort_keys=True),
        "--tools", "Read" if patch_file_mode else "", "--permission-mode", "plan", "--no-session-persistence",
        "--max-turns", str(MAX_TURNS), "--effort", "low", "--disable-slash-commands", "--no-chrome",
    ]
    if not snapshot.is_dir() or snapshot.is_symlink():
        raise ClaudeVerificationError("Claude verifier snapshot is unavailable")
    started = time.monotonic()
    diagnostic: dict[str, Any] = {
        "job_id": job_id, "reviewed_commit": commit, "model": MODEL,
        "argv": argv[:2] + ["<sanitized-prompt>"] + argv[3:], "snapshot": str(snapshot),
        "status": "STARTED",
    }
    try:
        completed = subprocess.run(
            argv, cwd=snapshot, env=minimal_environment(), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False,
            timeout=TIMEOUT_SECONDS, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        diagnostic.update({"status": "TIMEOUT", "elapsed_seconds": round(time.monotonic() - started, 3), "error": "timeout"})
        _write_diagnostic(diagnostic_path, diagnostic)
        raise ClaudeVerificationError("Claude verifier timed out") from exc
    except OSError as exc:
        diagnostic.update({"status": "LAUNCH_FAILED", "elapsed_seconds": round(time.monotonic() - started, 3), "error": str(exc)[:2000]})
        _write_diagnostic(diagnostic_path, diagnostic)
        raise ClaudeVerificationError(f"Claude verifier could not launch: {exc}") from exc
    diagnostic.update({
        "status": "PROCESS_FAILED" if completed.returncode else "PROCESS_SUCCEEDED",
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "exit_code": completed.returncode,
        "stdout_bytes": len(completed.stdout.encode("utf-8", errors="replace")),
        "stderr_bytes": len(completed.stderr.encode("utf-8", errors="replace")),
        "stderr": completed.stderr[:2000],
    })
    if completed.returncode:
        detail = (completed.stderr or completed.stdout or "no provider output").strip()
        diagnostic["error"] = detail[:2000]
        _write_diagnostic(diagnostic_path, diagnostic)
        raise ClaudeVerificationError(f"Claude verifier failed with exit code {completed.returncode}: {detail[:2000]}")
    try:
        result = _payload(completed.stdout)
    except ClaudeVerificationError as exc:
        diagnostic.update({"status": "SCHEMA_FAILED", "error": str(exc)[:2000]})
        _write_diagnostic(diagnostic_path, diagnostic)
        raise
    try:
        validate_contract(result, "claude", expected_job_id=job_id, expected_commit=commit)
    except SwarmError as exc:
        diagnostic.update({"status": "CONTRACT_FAILED", "error": str(exc)[:2000]})
        _write_diagnostic(diagnostic_path, diagnostic)
        raise ClaudeVerificationError(str(exc)) from exc
    diagnostic.update({
        "status": "VALIDATED",
        "verdict": result["verdict"],
        "risk": result["risk"],
        # Preserve validated provider output as exact-commit repair evidence.
        "review_payload": result,
    })
    _write_diagnostic(diagnostic_path, diagnostic)
    return result
