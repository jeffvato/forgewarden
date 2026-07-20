"""Fail-closed local stdio MCP bridge for the Hermes Desktop coding swarm."""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

from .core import redact

LOG = logging.getLogger("hermes_swarm.desktop_bridge")
LAUNCHER = Path("/home/jeff/.local/bin/hermes-swarm")
RUNTIME_ROOT = Path("/home/jeff/hermes-swarm-runtime")
AUDIT_PATH = Path("/home/jeff/hermes-swarm-audit/audit.jsonl")
PROJECT_ROOT = Path("/home/jeff/hermes-swarm-phase1")
COMMAND_TIMEOUT = 10
JOB_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
SAFE_STATES = {
    "RECEIVED", "CLASSIFIED", "WORKTREE_READY", "CODEX_RUNNING", "CHECKS_RUNNING",
    "GEMINI_REVIEWING", "REVISION_REQUIRED", "READY_TO_DEPLOY", "AWAITING_JEFF",
    "DEPLOYING", "VERIFYING_PRODUCTION", "SUCCEEDED", "ROLLED_BACK", "FAILED",
}


def _minimal_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONNOUSERSITE": "1",
    }


def _run_fixed(argv: list[str]) -> subprocess.CompletedProcess[str]:
    if argv not in ([str(LAUNCHER), "status"], [str(LAUNCHER), "kill-switch"]):
        raise RuntimeError("bridge attempted an unapproved command")
    return subprocess.run(
        argv,
        cwd=PROJECT_ROOT,
        env=_minimal_environment(),
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=COMMAND_TIMEOUT,
        check=False,
    )


def _parse_status(output: str) -> dict[str, str]:
    lines = output.strip().splitlines()
    if len(lines) != 1:
        raise RuntimeError("unexpected swarm status output")
    match = re.fullmatch(
        r"launcher=(hermes-swarm) mode=(DRY_RUN) deployment=(DISABLED) "
        r"kill_switch=(ENGAGED|CLEARED_FOR_DRY_RUN) runtime=(/home/jeff/hermes-swarm-runtime)",
        lines[0],
    )
    if not match:
        raise RuntimeError("unexpected swarm status output")
    return {
        "launcher": match.group(1),
        "mode": match.group(2),
        "deployment": match.group(3),
        "kill_switch": match.group(4),
        "runtime": match.group(5),
    }


def _status() -> dict[str, str]:
    result = _run_fixed([str(LAUNCHER), "status"])
    if result.returncode != 0:
        raise RuntimeError("swarm status command failed")
    if result.stderr.strip():
        raise RuntimeError("swarm status emitted diagnostics")
    return _parse_status(result.stdout)


def _validate_job_id(job_id: str) -> str:
    if not isinstance(job_id, str) or not JOB_ID_RE.fullmatch(job_id):
        raise ValueError("invalid job_id")
    return job_id


def _error_category(value: Any) -> str:
    text = str(value).lower()
    if "schema" in text or "json" in text:
        return "SCHEMA_VALIDATION"
    if "timeout" in text or "timed out" in text:
        return "TIMEOUT"
    if "bus" in text or "systemd" in text:
        return "SYSTEMD"
    if "kill" in text:
        return "KILL_SWITCH"
    if "secret" in text or "credential" in text:
        return "SECRET_POLICY"
    if text:
        return "RECORDED_ERROR"
    return "UNKNOWN_ERROR"


def _safe_record(entry: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in ("timestamp", "job_id", "state", "event"):
        value = entry.get(key)
        if isinstance(value, str):
            result[key] = redact(value)[:256]
    verdict = entry.get("verdict", entry.get("reviewer_decision"))
    if verdict in {"APPROVE", "REJECT", "HUMAN_REQUIRED"}:
        result["verdict"] = verdict
    if entry.get("risk") in {"LOW", "MEDIUM", "HIGH"}:
        result["risk"] = entry["risk"]
    for key in ("repair_commit", "commit", "reviewed_commit"):
        value = entry.get(key)
        if isinstance(value, str) and SHA_RE.fullmatch(value.lower()):
            result["repair_commit"] = value.lower()
            break
    if "error" in entry:
        result["error_category"] = _error_category(entry["error"])
    return result


def _read_audit() -> list[dict[str, Any]]:
    if not AUDIT_PATH.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(AUDIT_PATH.read_text(encoding="utf-8", errors="strict").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError(f"corrupted audit record at line {line_number}") from exc
        if not isinstance(value, dict):
            raise RuntimeError(f"corrupted audit record at line {line_number}")
        records.append(value)
    return records


def status() -> dict[str, str]:
    """Return the fixed dry-run swarm status."""
    return _status()


def job_status(job_id: str) -> dict[str, Any]:
    """Return sanitized audit records for one strictly validated job ID."""
    requested = _validate_job_id(job_id)
    records = [_safe_record(entry) for entry in _read_audit() if entry.get("job_id") == requested]
    return {"job_id": requested, "records": records}


def recent_audit(limit: int = 10) -> dict[str, Any]:
    """Return a bounded, sanitized audit tail."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
        raise ValueError("limit must be an integer from 1 through 20")
    records = [_safe_record(entry) for entry in _read_audit()]
    return {"records": records[-limit:]}


def engage_kill_switch() -> dict[str, str]:
    """Idempotently engage and verify the swarm kill switch."""
    result = _run_fixed([str(LAUNCHER), "kill-switch"])
    if result.returncode != 0:
        raise RuntimeError("kill-switch command failed")
    verified = _status()
    if verified["kill_switch"] != "ENGAGED":
        raise RuntimeError("kill switch verification failed")
    return verified


def create_server() -> "FastMCP":
    from mcp.server.fastmcp import FastMCP
    server = FastMCP("hermes-swarm", instructions="Read-only dry-run swarm status and audit bridge.")
    server.tool(name="status", structured_output=True)(status)
    server.tool(name="job_status", structured_output=True)(job_status)
    server.tool(name="recent_audit", structured_output=True)(recent_audit)
    server.tool(name="engage_kill_switch", structured_output=True)(engage_kill_switch)
    return server


def main() -> None:
    logging.basicConfig(stream=__import__("sys").stderr, level=logging.WARNING)
    create_server().run("stdio")


if __name__ == "__main__":
    main()
