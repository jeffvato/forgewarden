"""Bounded, read-only Claude Fable 5 analysis adapter.

This adapter is advisory only.  It cannot edit a worktree, invoke agents, or
change swarm state.  Provider authentication remains in Claude Code's normal
user credential mechanism; credential values are never copied into its env or
recorded by this module.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .core import SwarmError, redact
from .paths import project_root

PROJECT_ROOT = project_root()
CLAUDE = Path("/home/jeff/.local/bin/claude")
MODEL = "claude-fable-5"
PROGRAM_VERSION = "fable5-credit-program-v1"
HARD_BUDGET_USD = 100.0
MCP_TARGET_USD = 35.0
MAX_TURNS = 4
TIMEOUT_SECONDS = 300
MAX_OUTPUT_BYTES = 131072
LEDGER = Path("/home/jeff/hermes-swarm-audit/fable-budget.json")
EVIDENCE_DIR = Path("/home/jeff/hermes-swarm-audit/fable-evidence")
JOB_RE = re.compile(r"^fable-[a-z0-9]{24}$")


class FableAdapterError(SwarmError):
    """A fail-closed adapter or contract failure."""


@dataclass(frozen=True)
class FableInvocation:
    job_id: str
    target_usd: float = MCP_TARGET_USD
    model: str = MODEL
    max_turns: int = MAX_TURNS
    timeout_seconds: int = TIMEOUT_SECONDS


def _new_job_id() -> str:
    return "fable-" + uuid.uuid4().hex[:24]


def _minimal_env() -> dict[str, str]:
    # HOME is runtime configuration, not a credential.  Claude Code reads its
    # existing supported auth mechanism from this home; no token is exported.
    return {
        "HOME": "/home/jeff",
        "PATH": "/home/jeff/.local/bin:/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PYTHONNOUSERSITE": "1",
    }


def _schema(job_id: str) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["job_id", "model", "total_cost_usd", "findings", "hypotheses", "tests", "safe_correction_plan", "limitations"],
        "properties": {
            "job_id": {"const": job_id},
            "model": {"const": MODEL},
            "total_cost_usd": {"type": "number", "minimum": 0, "maximum": HARD_BUDGET_USD},
            "findings": {"type": "array", "maxItems": 8, "items": {"type": "string", "maxLength": 1200}},
            "hypotheses": {"type": "array", "maxItems": 8, "items": {"type": "object", "additionalProperties": False, "required": ["rank", "hypothesis", "evidence", "confidence"], "properties": {"rank": {"type": "integer", "minimum": 1}, "hypothesis": {"type": "string", "maxLength": 800}, "evidence": {"type": "string", "maxLength": 800}, "confidence": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH"]}}}},
            "tests": {"type": "array", "maxItems": 12, "items": {"type": "object", "additionalProperties": False, "required": ["name", "discriminates", "expected_signal"], "properties": {"name": {"type": "string", "maxLength": 400}, "discriminates": {"type": "string", "maxLength": 800}, "expected_signal": {"type": "string", "maxLength": 800}}}},
            "safe_correction_plan": {"type": "string", "maxLength": 2000},
            "limitations": {"type": "array", "maxItems": 8, "items": {"type": "string", "maxLength": 800}},
        },
    }


def _schema_json(job_id: str) -> str:
    return json.dumps(_schema(job_id), separators=(",", ":"), sort_keys=True)


def _sanitize_context(text: str) -> str:
    text = redact(text)
    text = re.sub(r"(?i)(/home/[^\s`]+/\.env|/home/[^\s`]+/\.credentials[^\s`]*)", "[PRIVATE_PATH_REDACTED]", text)
    text = re.sub(r"(?i)(api[_-]?key|token|password|secret|authorization)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]", text)
    return text[:50000]


def build_mcp_context() -> str:
    # Fixed, review-only context.  It deliberately excludes audit logs,
    # credentials, protected repositories, and production source.
    parts = [
        "Project: Hermes local coding swarm, Phase 2A readiness diagnosis.",
        "Safety: DRY_RUN only; deployment disabled; autonomous lease disabled; emergency kill switch engaged; no repair authorized.",
        "Question: diagnose the disposable MCPServerTask startup/readiness, keepalive, generation-bound reconnect, and post-reconnect fake enqueue/replay path.",
        "Known evidence: official Hermes MCP discovery succeeds under five seconds with five tools; direct SDK ping/status succeeds; only the disposable MCPServerTask fixture remains unresolved.",
        "Required output: ranked hypotheses, discriminating read-only tests, smallest safe correction plan, limitations. Do not recommend a repair execution or any production action.",
    ]
    for relative in ("docs/mcpserver-task-fixture-postmortem.md", "docs/hermes-mcp-generation-reconnect.md", "tests/test_hermes_mcp_lifecycle.py"):
        path = PROJECT_ROOT / relative
        if path.is_file():
            parts.append(f"\n--- sanitized {relative} ---\n{path.read_text(encoding='utf-8', errors='replace')[:12000]}")
    return _sanitize_context("\n".join(parts))


def _load_ledger() -> dict[str, Any]:
    if not LEDGER.exists():
        return {"version": 1, "hard_budget_usd": HARD_BUDGET_USD, "spent_usd": 0.0, "invocations": []}
    try:
        value = json.loads(LEDGER.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FableAdapterError("Fable budget ledger is invalid") from exc
    if not isinstance(value, dict) or value.get("hard_budget_usd") != HARD_BUDGET_USD or not isinstance(value.get("spent_usd"), (int, float)) or not isinstance(value.get("invocations"), list):
        raise FableAdapterError("Fable budget ledger has an invalid contract")
    return value


def _write_ledger(value: dict[str, Any]) -> None:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    LEDGER.parent.chmod(0o700)
    temporary = LEDGER.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, LEDGER)
    LEDGER.chmod(0o600)


def _reserve(invocation: FableInvocation) -> None:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    lock_path = LEDGER.with_suffix(".lock")
    with lock_path.open("a+", encoding="ascii") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        ledger = _load_ledger()
        remaining = HARD_BUDGET_USD - float(ledger["spent_usd"])
        if invocation.target_usd > remaining + 1e-9:
            raise FableAdapterError("Fable invocation cap exceeds remaining approved budget")
        ledger["reserved_usd"] = float(ledger.get("reserved_usd", 0.0)) + invocation.target_usd
        _write_ledger(ledger)


def _settle(invocation: FableInvocation, actual_cost: float, state: str) -> None:
    if actual_cost < 0 or actual_cost > invocation.target_usd + 1e-9:
        raise FableAdapterError("Fable reported cost exceeds the invocation cap")
    lock_path = LEDGER.with_suffix(".lock")
    with lock_path.open("a+", encoding="ascii") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        ledger = _load_ledger()
        ledger["reserved_usd"] = max(0.0, float(ledger.get("reserved_usd", 0.0)) - invocation.target_usd)
        ledger["spent_usd"] = float(ledger["spent_usd"]) + actual_cost
        ledger["invocations"].append({"job_id": invocation.job_id, "model": MODEL, "target_usd": invocation.target_usd, "actual_cost_usd": actual_cost, "state": state, "timestamp": int(time.time())})
        _write_ledger(ledger)


def _failure_evidence(invocation: FableInvocation, state: str, exit_code: int | None = None, error: str = "") -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.chmod(0o700)
    path = EVIDENCE_DIR / f"{invocation.job_id}.json"
    value = {
        "job_id": invocation.job_id,
        "model": MODEL,
        "state": state,
        "exit_code": exit_code,
        "error": redact(error)[:1000],
        "environment_names": sorted(_minimal_env()),
    }
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _extract_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FableAdapterError("Fable output is not a JSON object")
    payload = value.get("structured_output", value.get("result", value))
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise FableAdapterError("Fable result field is not JSON") from exc
    if not isinstance(payload, dict):
        raise FableAdapterError("Fable structured result is not an object")
    return payload


def _validate(payload: dict[str, Any], invocation: FableInvocation) -> None:
    import jsonschema
    try:
        jsonschema.Draft202012Validator(_schema(invocation.job_id)).validate(payload)
    except jsonschema.ValidationError as exc:
        raise FableAdapterError("Fable structured result failed schema validation") from exc
    if payload["job_id"] != invocation.job_id or payload["model"] != MODEL:
        raise FableAdapterError("Fable job or model binding mismatch")
    if float(payload["total_cost_usd"]) > invocation.target_usd + 1e-9:
        raise FableAdapterError("Fable reported cost exceeds configured task cap")


def run_fable(invocation: FableInvocation | None = None, *, context: str | None = None) -> dict[str, Any]:
    invocation = invocation or FableInvocation(job_id=_new_job_id())
    if invocation.model != MODEL or not JOB_RE.fullmatch(invocation.job_id) or invocation.target_usd <= 0 or invocation.target_usd > HARD_BUDGET_USD:
        raise FableAdapterError("invalid Fable invocation specification")
    if not CLAUDE.is_file() or not os.access(CLAUDE, os.X_OK):
        raise FableAdapterError("Claude CLI is unavailable")
    _reserve(invocation)
    schema = _schema_json(invocation.job_id)
    prompt = (
        f"You are a read-only diagnostic reviewer for job {invocation.job_id}.\n"
        "Return JSON matching the supplied schema. Do not use tools, shell, files, edits, Git, MCP, deployment, or agents.\n"
        "This is advisory evidence only. Do not authorize a repair or clear any safety gate.\n\n"
        f"{_sanitize_context(context) if context is not None else build_mcp_context()}"
    )
    argv = [str(CLAUDE), "-p", prompt, "--model", MODEL, "--output-format", "json", "--json-schema", schema, "--tools", "", "--permission-mode", "plan", "--no-session-persistence", "--max-budget-usd", str(invocation.target_usd)]
    started = time.monotonic()
    completed: subprocess.CompletedProcess[str] | None = None
    settled = False
    try:
        completed = subprocess.run(argv, cwd=PROJECT_ROOT, env=_minimal_env(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False, timeout=invocation.timeout_seconds, check=False)
        stdout = completed.stdout[:MAX_OUTPUT_BYTES]
        stderr = redact(completed.stderr[:MAX_OUTPUT_BYTES])
        if completed.returncode != 0:
            _settle(invocation, 0.0, "FAILED")
            settled = True
            _failure_evidence(invocation, "FAILED", completed.returncode, "provider CLI returned non-zero")
            raise FableAdapterError(f"Fable CLI failed with exit code {completed.returncode}")
        try:
            envelope = json.loads(stdout)
        except json.JSONDecodeError as exc:
            _settle(invocation, 0.0, "INVALID")
            settled = True
            _failure_evidence(invocation, "INVALID", completed.returncode, "provider CLI returned invalid JSON")
            raise FableAdapterError("Fable CLI returned invalid JSON") from exc
        payload = _extract_result(envelope)
        _validate(payload, invocation)
        actual = float(payload["total_cost_usd"])
        _settle(invocation, actual, "SUCCEEDED")
        settled = True
        evidence = {
            "job_id": invocation.job_id,
            "model": MODEL,
            "argv": [str(CLAUDE), "-p", "[PROMPT_REDACTED]", "--model", MODEL, "--output-format", "json", "--json-schema", "[SCHEMA_REDACTED]", "--tools", "", "--permission-mode", "plan", "--no-session-persistence", "--max-budget-usd", str(invocation.target_usd)],
            "cwd": str(PROJECT_ROOT),
            "environment_names": sorted(_minimal_env()),
            "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
            "exit_code": completed.returncode,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "stderr": stderr,
            "result": payload,
        }
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        EVIDENCE_DIR.chmod(0o700)
        evidence_path = EVIDENCE_DIR / f"{invocation.job_id}.json"
        evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        evidence_path.chmod(0o600)
        return payload
    except subprocess.TimeoutExpired as exc:
        _settle(invocation, 0.0, "TIMEOUT")
        settled = True
        _failure_evidence(invocation, "TIMEOUT", None, "provider CLI timeout")
        raise FableAdapterError("Fable CLI timed out") from exc
    except FableAdapterError:
        if not settled:
            _settle(invocation, 0.0, "INVALID")
            _failure_evidence(invocation, "INVALID", completed.returncode if completed else None, "structured result validation failed")
        raise
    except BaseException as exc:
        if not settled:
            _settle(invocation, 0.0, "INTERRUPTED")
            _failure_evidence(invocation, "INTERRUPTED", completed.returncode if completed else None, type(exc).__name__)
        raise
