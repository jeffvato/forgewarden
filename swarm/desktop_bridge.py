"""Fail-closed local stdio MCP bridge for the Hermes Desktop coding swarm."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

from .core import redact
from .phase2a import workflow_status as phase2a_workflow_status
from .paths import audit_path, launcher_path, project_root, runtime_root

LOG = logging.getLogger("hermes_swarm.desktop_bridge")
LAUNCHER = launcher_path()
RUNTIME_ROOT = runtime_root()
AUDIT_PATH = audit_path()
PROJECT_ROOT = project_root()
COMMAND_TIMEOUT = 10
JOB_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
SAFE_STATES = {
    "QUEUED", "RUNNING", "ABANDONED", "RECOVERED_ABANDONED", "CANCELLED",
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
        rf"launcher=(hermes-swarm) mode=(DRY_RUN) deployment=(DISABLED) "
        rf"kill_switch=(ENGAGED|CLEARED_FOR_DRY_RUN) runtime=({re.escape(str(RUNTIME_ROOT))})",
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


def workflow_status() -> dict[str, Any]:
    """Return read-only Phase 2A state and stale-marker guidance."""
    return phase2a_workflow_status(RUNTIME_ROOT)


def job_status(job_id: str) -> dict[str, Any]:
    """Return sanitized audit records for one strictly validated job ID."""
    requested = _validate_job_id(job_id)
    records = [_safe_record(entry) for entry in _read_audit() if entry.get("job_id") == requested]
    result: dict[str, Any] = {"job_id": requested, "records": records}
    state_path = RUNTIME_ROOT / "phase2a-state.json"
    if state_path.is_file():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("corrupted Phase 2A state") from exc
        if isinstance(state, dict) and state.get("job_id") == requested:
            state_value = state.get("state")
            if isinstance(state_value, str) and state_value in SAFE_STATES:
                result["state"] = state_value
    return result


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


def run_preapproved_job(
    profile_id: Literal["csv_deadline_dry_run_v1"],
    issue_summary: str,
) -> dict[str, Any]:
    """Run one committed-profile dry-run job after local activation.

    The profile is a literal MCP enum; all repository, command, model,
    writable-path, and environment choices remain server-side constants.
    """
    from .phase2a import run_preapproved_job as execute
    return execute(profile_id, issue_summary)


def submit_preapproved_job(
    profile_id: Literal["csv_deadline_dry_run_v1"],
    issue_summary: str,
) -> dict[str, Any]:
    """Submit one validated job using an internal one-job kill-switch lease."""
    from .phase2a import submit_preapproved_job as execute
    return execute(profile_id, issue_summary)


def create_server() -> "FastMCP":
    from mcp.server.fastmcp import FastMCP
    server = FastMCP("hermes-swarm", instructions="Read-only dry-run swarm status and audit bridge.")
    server.tool(name="status", structured_output=True)(status)
    server.tool(name="workflow_status", structured_output=True)(workflow_status)
    server.tool(name="job_status", structured_output=True)(job_status)
    server.tool(name="recent_audit", structured_output=True)(recent_audit)
    server.tool(name="engage_kill_switch", structured_output=True)(engage_kill_switch)
    server.tool(name="run_preapproved_job", structured_output=True)(run_preapproved_job)
    server.tool(name="submit_preapproved_job", structured_output=True)(submit_preapproved_job)
    return server


@asynccontextmanager
async def _persistent_stdio_server():
    """Use fd I/O for WSL pipes while preserving MCP's normal session streams.

    The pinned MCP release's ``anyio.wrap_file(TextIOWrapper)`` reader does not
    consume this WSL stdio pipe reliably. Readiness-aware fd I/O avoids that
    transport-specific stall without changing MCP framing or exposing any
    additional process capability.
    """
    import anyio
    import mcp.types as types
    from mcp.shared.message import SessionMessage

    read_writer, read_stream = anyio.create_memory_object_stream(0)
    write_stream, write_reader = anyio.create_memory_object_stream(0)

    async def stdin_reader() -> None:
        buffer = b""
        try:
            async with read_writer:
                while True:
                    try:
                        await anyio.wait_readable(0)
                    except PermissionError:
                        # Some launchers attach stdin to /dev/null, which
                        # epoll refuses to register. A direct read is safe for
                        # that EOF-only fallback and preserves clean shutdown.
                        pass
                    chunk = os.read(0, 65536)
                    if not chunk:
                        return
                    buffer += chunk
                    while b"\n" in buffer:
                        raw, buffer = buffer.split(b"\n", 1)
                        if not raw:
                            continue
                        try:
                            message = types.JSONRPCMessage.model_validate_json(raw)
                        except Exception as exc:
                            await read_writer.send(exc)
                            continue
                        await read_writer.send(SessionMessage(message))
        except (anyio.ClosedResourceError, BrokenPipeError, OSError):
            # EOF and a closed peer are normal teardown paths.  Do not emit
            # diagnostics on stdout and do not turn a client cancellation
            # into a process-wide protocol failure.
            await anyio.lowlevel.checkpoint()

    async def stdout_writer() -> None:
        try:
            async with write_reader:
                async for session_message in write_reader:
                    payload = (session_message.message.model_dump_json(by_alias=True, exclude_none=True) + "\n").encode()
                    offset = 0
                    while offset < len(payload):
                        written = os.write(1, payload[offset:])
                        if written <= 0:
                            raise BrokenPipeError("MCP stdout closed")
                        offset += written
        except (anyio.ClosedResourceError, BrokenPipeError, OSError):
            # A disconnected client closes only this session's writer.  The
            # exception is deliberately contained by the transport task.
            await anyio.lowlevel.checkpoint()

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(stdin_reader)
        task_group.start_soon(stdout_writer)
        yield read_stream, write_stream


async def _run_persistent_stdio(server: "FastMCP") -> None:
    async with _persistent_stdio_server() as (read_stream, write_stream):
        await server._mcp_server.run(
            read_stream,
            write_stream,
            server._mcp_server.create_initialization_options(),
        )


def main() -> None:
    logging.basicConfig(stream=__import__("sys").stderr, level=logging.WARNING)
    import anyio

    anyio.run(_run_persistent_stdio, create_server())


if __name__ == "__main__":
    main()
