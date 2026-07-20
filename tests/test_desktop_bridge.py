import json
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from swarm import desktop_bridge as bridge


class DesktopBridgeTests(unittest.TestCase):
    def setUp(self):
        self.audit_dir = TemporaryDirectory(prefix="desktop-bridge-audit-")
        self.audit = Path(self.audit_dir.name) / "audit.jsonl"
        self.addCleanup(self.audit_dir.cleanup)

    def write_audit(self, *entries):
        self.audit.write_text("".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8")

    def test_status_uses_exact_fixed_command_shell_false_minimal_env_and_timeout(self):
        output = "launcher=hermes-swarm mode=DRY_RUN deployment=DISABLED kill_switch=ENGAGED runtime=/home/jeff/hermes-swarm-runtime\n"
        completed = subprocess.CompletedProcess(["fixed"], 0, output, "")
        with patch.object(bridge, "_run_fixed", wraps=bridge._run_fixed) as fixed, patch("swarm.desktop_bridge.subprocess.run", return_value=completed) as run:
            with patch.object(bridge, "AUDIT_PATH", self.audit):
                result = bridge.status()
        self.assertEqual(result["mode"], "DRY_RUN")
        run.assert_called_once()
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["/home/jeff/.local/bin/hermes-swarm", "status"])
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["timeout"], 10)
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "PYTHONNOUSERSITE": "1"})
        fixed.assert_called_once()

    def test_status_rejects_unexpected_output_and_command_failure(self):
        bad = subprocess.CompletedProcess([], 0, "mode=DRY_RUN\n", "")
        with patch("swarm.desktop_bridge.subprocess.run", return_value=bad):
            with self.assertRaises(RuntimeError):
                bridge.status()
        failed = subprocess.CompletedProcess([], 7, "", "failure")
        with patch("swarm.desktop_bridge.subprocess.run", return_value=failed):
            with self.assertRaises(RuntimeError):
                bridge.status()

    def test_job_id_and_audit_limit_bounds_fail_closed(self):
        for bad in ("", "A-job", "job/path", "job space", "../job", "a" * 129, 1):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                bridge.job_status(bad)
        for bad in (0, 21, -1, True, "10"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                bridge.recent_audit(bad)

    def test_audit_is_strictly_allowlisted_redacted_and_categorized(self):
        self.write_audit(
            {"timestamp": "2026-01-01T00:00:00Z", "job_id": "job-1", "state": "FAILED", "event": "failed", "error": "schema token=supersecret", "prompt": "secret prompt", "customer_email": "a@example.test", "repair_commit": "a" * 40},
        )
        with patch.object(bridge, "AUDIT_PATH", self.audit):
            result = bridge.job_status("job-1")
            recent = bridge.recent_audit(1)
        record = result["records"][0]
        self.assertEqual(record["error_category"], "SCHEMA_VALIDATION")
        self.assertEqual(record["repair_commit"], "a" * 40)
        self.assertNotIn("prompt", record)
        self.assertNotIn("customer_email", record)
        self.assertNotIn("supersecret", json.dumps(recent))

    def test_corrupted_audit_fails_without_partial_results(self):
        self.audit.write_text('{"job_id":"job-1"}\nnot-json\n', encoding="utf-8")
        with patch.object(bridge, "AUDIT_PATH", self.audit):
            with self.assertRaises(RuntimeError):
                bridge.recent_audit(10)

    def test_kill_switch_uses_fixed_command_and_verifies_engaged(self):
        output = "launcher=hermes-swarm mode=DRY_RUN deployment=DISABLED kill_switch=ENGAGED runtime=/home/jeff/hermes-swarm-runtime\n"
        calls = [subprocess.CompletedProcess([], 0, "engaged\n", ""), subprocess.CompletedProcess([], 0, output, "")]
        with patch("swarm.desktop_bridge.subprocess.run", side_effect=calls) as run:
            result = bridge.engage_kill_switch()
        self.assertEqual(result["kill_switch"], "ENGAGED")
        self.assertEqual(run.call_args_list[0].args[0], ["/home/jeff/.local/bin/hermes-swarm", "kill-switch"])
        self.assertEqual(run.call_args_list[1].args[0], ["/home/jeff/.local/bin/hermes-swarm", "status"])
        for call in run.call_args_list:
            self.assertFalse(call.kwargs["shell"])
            self.assertEqual(call.kwargs["timeout"], 10)

    def test_kill_switch_post_verification_failure_is_error(self):
        output = "launcher=hermes-swarm mode=DRY_RUN deployment=DISABLED kill_switch=CLEARED_FOR_DRY_RUN runtime=/home/jeff/hermes-swarm-runtime\n"
        calls = [subprocess.CompletedProcess([], 0, "", ""), subprocess.CompletedProcess([], 0, output, "")]
        with patch("swarm.desktop_bridge.subprocess.run", side_effect=calls):
            with self.assertRaises(RuntimeError):
                bridge.engage_kill_switch()

    def test_stdio_handshake_registers_exactly_four_tools_and_no_protocol_corruption(self):
        script = r'''
import asyncio, json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def handshake():
    server = StdioServerParameters(
        command="/home/jeff/.local/bin/hermes-swarm-mcp",
        args=[],
        env={"PYTHONPATH": "/home/jeff/hermes-swarm-phase1"},
        cwd="/home/jeff/hermes-swarm-phase1",
    )
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            return sorted(tool.name for tool in tools.tools)

print(json.dumps(asyncio.run(handshake())))
'''
        result = subprocess.run(
            ["/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python", "-c", script],
            cwd="/home/jeff/hermes-swarm-phase1",
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": "/home/jeff/hermes-swarm-phase1"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        names = json.loads(result.stdout)
        self.assertEqual(names, ["engage_kill_switch", "job_status", "recent_audit", "status"])
        self.assertNotIn("repair", names)
        self.assertNotIn("deploy", names)
        self.assertNotIn("shell", names)
        self.assertNotIn("git", names)

    def test_stdio_session_is_persistent_and_tool_errors_do_not_kill_it(self):
        script = r'''
import asyncio, json, psutil
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def exercise():
    server = StdioServerParameters(
        command="/home/jeff/.local/bin/hermes-swarm-mcp", args=[],
        env={"PYTHONPATH": "/home/jeff/hermes-swarm-phase1"},
        cwd="/home/jeff/hermes-swarm-phase1",
    )
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert sorted(t.name for t in tools.tools) == [
                "engage_kill_switch", "job_status", "recent_audit", "status"
            ]
            modes = []
            for _ in range(3):
                result = await session.call_tool("status", {})
                assert not result.isError
                modes.append(result.structuredContent["mode"])
            bad = await session.call_tool("job_status", {"job_id": "not valid"})
            assert bad.isError
            after_error = await session.call_tool("status", {})
            assert not after_error.isError
            live = [
                p for p in psutil.process_iter(["pid", "cmdline"])
                if p.info.get("cmdline") and "swarm.desktop_bridge" in " ".join(p.info["cmdline"])
            ]
            assert live, "bridge process ended before the session closed"
            return {"calls": len(modes), "mode": modes[-1], "error_is_error": bad.isError}

print(json.dumps(asyncio.run(exercise())))
'''
        result = subprocess.run(
            ["/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python", "-c", script],
            cwd="/home/jeff/hermes-swarm-phase1",
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": "/home/jeff/hermes-swarm-phase1"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, shell=False, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"calls": 3, "mode": "DRY_RUN", "error_is_error": True})

    def test_independent_stdio_session_survives_other_session_close(self):
        script = r'''
import asyncio, json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PARAMS = StdioServerParameters(
    command="/home/jeff/.local/bin/hermes-swarm-mcp", args=[],
    env={"PYTHONPATH": "/home/jeff/hermes-swarm-phase1"},
    cwd="/home/jeff/hermes-swarm-phase1",
)

async def exercise():
    async with stdio_client(PARAMS) as (read_one, write_one):
        async with ClientSession(read_one, write_one) as session_one:
            await session_one.initialize()
            assert not (await session_one.call_tool("status", {})).isError
    async with stdio_client(PARAMS) as (read_two, write_two):
        async with ClientSession(read_two, write_two) as session_two:
            await session_two.initialize()
            result = await session_two.call_tool("status", {})
            assert not result.isError
            return result.structuredContent["kill_switch"]

print(json.dumps(asyncio.run(exercise())))
'''
        result = subprocess.run(
            ["/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python", "-c", script],
            cwd="/home/jeff/hermes-swarm-phase1",
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": "/home/jeff/hermes-swarm-phase1"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, shell=False, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), "ENGAGED")


if __name__ == "__main__":
    unittest.main()
