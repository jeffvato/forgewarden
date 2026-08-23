import json
import os
import subprocess
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from swarm import desktop_bridge as bridge
from tests.host_fixtures import requires_host_fixture


DESKTOP_FIXTURE = (
    "/home/jeff/hermes-swarm-phase1",
    "/home/jeff/.local/bin/hermes-swarm-mcp",
    "/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python",
)


class DesktopBridgeTests(unittest.TestCase):
    def setUp(self):
        self.audit_dir = TemporaryDirectory(prefix="desktop-bridge-audit-")
        self.audit = Path(self.audit_dir.name) / "audit.jsonl"
        self.addCleanup(self.audit_dir.cleanup)
        import psutil
        self._existing_bridge_pids = {
            process.pid
            for process in psutil.process_iter(["name", "cmdline"])
            if process.info.get("cmdline")
            and process.info.get("name") in {"python", "python3", "hermes-swarm-mcp"}
            and "swarm.desktop_bridge" in " ".join(process.info["cmdline"])
        }

    def write_audit(self, *entries):
        self.audit.write_text("".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8")

    def test_status_uses_exact_fixed_command_shell_false_minimal_env_and_timeout(self):
        output = f"launcher=hermes-swarm mode=DRY_RUN deployment=DISABLED kill_switch=ENGAGED runtime={bridge.RUNTIME_ROOT}\n"
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

    def test_job_status_reports_durable_queued_state_after_bridge_restart(self):
        job_id = "phase2a-" + "c" * 24
        self.write_audit({"timestamp": "2026-01-01T00:00:00Z", "job_id": job_id, "state": "QUEUED", "event": "queued"})
        runtime = Path(self.audit_dir.name) / "runtime"
        runtime.mkdir()
        (runtime / "phase2a-state.json").write_text(json.dumps({"job_id": job_id, "state": "QUEUED", "worker_pid": 99999999}), encoding="utf-8")
        with patch.object(bridge, "AUDIT_PATH", self.audit), patch.object(bridge, "RUNTIME_ROOT", runtime):
            result = bridge.job_status(job_id)
        self.assertEqual(result["state"], "QUEUED")
        self.assertEqual(result["records"][0]["state"], "QUEUED")

    def test_workflow_status_is_read_only_and_uses_phase2a_contract(self):
        runtime = Path(self.audit_dir.name) / "runtime"
        runtime.mkdir()
        state = {"job_id": "phase2a-" + "f" * 24, "state": "RECOVERED_ABANDONED"}
        state_path = runtime / "phase2a-state.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        lock_path = runtime / "phase2a-job.lock"
        lock_path.write_text("99999999:1\n", encoding="ascii")
        running_path = runtime / "RUNNING"
        running_path.write_text("1\n", encoding="ascii")
        before = {path: path.read_bytes() for path in (state_path, lock_path, running_path)}
        with patch.object(bridge, "RUNTIME_ROOT", runtime):
            result = bridge.workflow_status()
        self.assertEqual(result["state"], "RECOVERED_ABANDONED")
        self.assertEqual(result["lock"], "STALE")
        self.assertTrue(result["running_marker"])
        self.assertTrue(result["stale_markers"])
        self.assertFalse(result["replay_blocked"])
        self.assertEqual(result["next_action"], "REVIEW_THEN_RUN_GUARDED_TERMINAL_RECOVERY")
        self.assertTrue(result["read_only"])
        self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_job_status_rejects_malformed_state_encoding_and_type(self):
        job_id = "phase2a-" + "e" * 24
        runtime = Path(self.audit_dir.name) / "runtime"
        runtime.mkdir()
        state_path = runtime / "phase2a-state.json"
        with patch.object(bridge, "AUDIT_PATH", self.audit), patch.object(bridge, "RUNTIME_ROOT", runtime):
            state_path.write_text(json.dumps({"job_id": job_id, "state": []}), encoding="utf-8")
            self.assertEqual(bridge.job_status(job_id)["job_id"], job_id)
            state_path.write_bytes(b"{\xff")
            with self.assertRaises(RuntimeError):
                bridge.job_status(job_id)

    def test_corrupted_audit_fails_without_partial_results(self):
        self.audit.write_text('{"job_id":"job-1"}\nnot-json\n', encoding="utf-8")
        with patch.object(bridge, "AUDIT_PATH", self.audit):
            with self.assertRaises(RuntimeError):
                bridge.recent_audit(10)

    def test_audit_symlink_is_rejected(self):
        outside = Path(self.audit_dir.name) / "outside.jsonl"
        outside.write_text('{"job_id":"job-1"}\n', encoding="utf-8")
        self.audit.symlink_to(outside)
        with patch.object(bridge, "AUDIT_PATH", self.audit):
            with self.assertRaises(RuntimeError):
                bridge.recent_audit(1)

    def test_state_symlink_is_rejected(self):
        job_id = "phase2a-" + "d" * 24
        runtime = Path(self.audit_dir.name) / "runtime"
        runtime.mkdir()
        outside = Path(self.audit_dir.name) / "outside-state.json"
        outside.write_text(json.dumps({"job_id": job_id, "state": "QUEUED"}), encoding="utf-8")
        (runtime / "phase2a-state.json").symlink_to(outside)
        with patch.object(bridge, "AUDIT_PATH", self.audit), patch.object(bridge, "RUNTIME_ROOT", runtime):
            with self.assertRaises(RuntimeError):
                bridge.job_status(job_id)

    def test_kill_switch_uses_fixed_command_and_verifies_engaged(self):
        output = f"launcher=hermes-swarm mode=DRY_RUN deployment=DISABLED kill_switch=ENGAGED runtime={bridge.RUNTIME_ROOT}\n"
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
        output = f"launcher=hermes-swarm mode=DRY_RUN deployment=DISABLED kill_switch=CLEARED_FOR_DRY_RUN runtime={bridge.RUNTIME_ROOT}\n"
        calls = [subprocess.CompletedProcess([], 0, "", ""), subprocess.CompletedProcess([], 0, output, "")]
        with patch("swarm.desktop_bridge.subprocess.run", side_effect=calls):
            with self.assertRaises(RuntimeError):
                bridge.engage_kill_switch()

    @requires_host_fixture(DESKTOP_FIXTURE, "desktop MCP bridge integration")
    def test_stdio_handshake_registers_exactly_seven_tools_and_no_protocol_corruption(self):
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
        self.assertEqual(names, ["engage_kill_switch", "job_status", "recent_audit", "run_preapproved_job", "status", "submit_preapproved_job", "workflow_status"])
        self.assertNotIn("repair", names)
        self.assertNotIn("deploy", names)
        self.assertNotIn("shell", names)
        self.assertNotIn("git", names)
        self.assert_no_bridge_children()

    def assert_no_bridge_children(self):
        import psutil
        ancestor_pids = {process.pid for process in psutil.Process().parents()}
        for _ in range(20):
            children = [
                process.pid
                for process in psutil.process_iter(["pid", "name", "cmdline", "status"])
                if process.info.get("cmdline")
                and process.pid not in ancestor_pids
                and process.pid not in self._existing_bridge_pids
                and process.info.get("name") in {"python", "python3", "hermes-swarm-mcp"}
                and process.info.get("status") != psutil.STATUS_ZOMBIE
                and "swarm.desktop_bridge" in " ".join(process.info["cmdline"])
            ]
            if not children:
                return
            time.sleep(0.05)
        self.fail(f"MCP fixture child was not reaped: {children}")

    @requires_host_fixture(DESKTOP_FIXTURE, "desktop MCP bridge integration")
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
                "engage_kill_switch", "job_status", "recent_audit", "run_preapproved_job", "status", "submit_preapproved_job", "workflow_status"
            ]
            modes = []
            for _ in range(3):
                await session.send_ping()
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
        self.assert_no_bridge_children()

    @requires_host_fixture(DESKTOP_FIXTURE, "desktop MCP bridge integration")
    def test_stdio_ping_and_status_repetitions_share_one_session(self):
        script = r'''
import asyncio, json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def exercise():
    params = StdioServerParameters(
        command="/home/jeff/.local/bin/hermes-swarm-mcp", args=[],
        env={"PYTHONPATH": "/home/jeff/hermes-swarm-phase1"},
        cwd="/home/jeff/hermes-swarm-phase1",
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for _ in range(5):
                await session.send_ping()
                result = await session.call_tool("status", {})
                assert not result.isError
                assert result.structuredContent["kill_switch"] == "ENGAGED"
            return True

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
        self.assertEqual(json.loads(result.stdout), True)
        self.assert_no_bridge_children()

    @requires_host_fixture(DESKTOP_FIXTURE, "desktop MCP bridge integration")
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
