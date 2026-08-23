"""Process-level Hermes MCP keepalive and generation-readiness checks."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from tests.host_fixtures import requires_host_fixture


PYTHON = "/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python"
LIFECYCLE_FIXTURE = ("/home/jeff/hermes-swarm-phase1", PYTHON)


class HermesMcpLifecycleTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("HERMES_MCP_LIFECYCLE_REAL") == "1",
        "real WSL MCPServerTask lifecycle is an explicit diagnostic run",
    )
    def test_real_mcp_server_task_survives_three_accelerated_keepalives(self):
        with tempfile.TemporaryDirectory(prefix="hermes-mcp-fixture-") as temp:
            fixture = Path(temp) / "server.py"
            fixture.write_text(
                "import anyio\n"
                "from mcp.server.fastmcp import FastMCP\n"
                "from swarm.desktop_bridge import _persistent_stdio_server\n"
                "import threading\n"
                "jobs = {}\n"
                "server = FastMCP('keepalive-fixture')\n"
                "@server.tool()\n"
                "def status() -> str:\n"
                "    return 'DRY_RUN/DISABLED/ENGAGED'\n"
                "@server.tool()\n"
                "def run_preapproved_job(profile_id: str, issue_summary: str, request_id: str) -> dict:\n"
                "    if request_id in jobs:\n"
                "        return jobs[request_id]\n"
                "    job = {'job_id': 'fake-phase2a-1', 'state': 'QUEUED', 'lease': 'CONSUMED', 'deployment': 'DISABLED', 'kill_switch': 'ENGAGED', 'autonomous_dry_run': 'DISABLED'}\n"
                "    jobs[request_id] = job\n"
                "    threading.Timer(0.2, lambda: job.update(state='SUCCEEDED')).start()\n"
                "    return job\n"
                "@server.tool()\n"
                "def job_status(job_id: str) -> dict:\n"
                "    return next((job for job in jobs.values() if job['job_id'] == job_id), {'state': 'MISSING'})\n"
                "async def main() -> None:\n"
                "    async with _persistent_stdio_server() as (r, w):\n"
                "        await server._mcp_server.run(r, w, server._mcp_server.create_initialization_options())\n"
                "anyio.run(main)\n",
                encoding="utf-8",
            )
            script = r'''
import asyncio, json, os, sys
from pathlib import Path
sys.path.insert(0, "/home/jeff/hermes-swarm-phase1")
import tools.mcp_tool as m

expected_module = Path("/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/lib/python3.12/site-packages/tools/mcp_tool.py")
if Path(m.__file__).resolve() != expected_module:
    raise RuntimeError(f"unexpected tools.mcp_tool module: {m.__file__}")

async def exercise():
    server_config = {
        "command": "/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python",
        "args": ["__FIXTURE__"],
        "env": {
            "PYTHONPATH": "/home/jeff/hermes-swarm-phase1",
            "HERMES_HOME": "/home/jeff/hermes-swarm-desktop-home",
        },
        "connect_timeout": 10,
        "sampling": {"enabled": False},
        "elicitation": {"enabled": False},
        "tools": {"include": ["status", "run_preapproved_job", "job_status"], "resources": False, "prompts": False},
    }
    server_config["keepalive_interval"] = 0.5
    server_config["connect_timeout"] = 10
    task = m.MCPServerTask("coding_swarm")
    await asyncio.wait_for(task.start(server_config), timeout=5)
    first_generation = task._ready_generation
    assert first_generation == task._connection_generation
    for _ in range(3):
        await asyncio.sleep(0.7)
        await task.session.send_ping()
        result = await task.session.call_tool("status", {})
        assert not result.isError
        assert result.content
    # Cancel only the active MCP session task group. This is a transport-level
    # close, not a process kill, and exercises the production reconnect path.
    task.session._task_group.cancel_scope.cancel()
    deadline = asyncio.get_running_loop().time() + 5
    while task._ready_generation <= first_generation:
        assert asyncio.get_running_loop().time() < deadline
        await asyncio.sleep(0.1)
    await task.session.send_ping()
    after_reconnect = await task.session.call_tool("status", {})
    assert not after_reconnect.isError
    lost_response = await task.session.call_tool(
        "run_preapproved_job",
        {"profile_id": "csv_deadline_dry_run_v1", "issue_summary": "fake acceptance", "request_id": "replay-1"},
    )
    assert not lost_response.isError
    lost_job = json.loads(lost_response.content[0].text)
    # Simulate the client losing the first response after durable admission.
    # The replay below must return the same immutable job, not enqueue again.
    replay = await task.session.call_tool(
        "run_preapproved_job",
        {"profile_id": "csv_deadline_dry_run_v1", "issue_summary": "fake acceptance", "request_id": "replay-1"},
    )
    assert not replay.isError
    job = json.loads(replay.content[0].text)
    assert job["job_id"] == lost_job["job_id"]
    assert job["state"] in {"QUEUED", "SUCCEEDED"}
    terminal = None
    for _ in range(15):
        await asyncio.sleep(0.1)
        status_result = await task.session.call_tool("job_status", {"job_id": job["job_id"]})
        terminal = json.loads(status_result.content[0].text)
        if terminal["state"] == "SUCCEEDED":
            break
    assert terminal["state"] == "SUCCEEDED"
    evidence = {
        "initial_generation": first_generation,
        "reconnected_generation": task._ready_generation,
        "ready": task._ready.is_set(),
        "status_after_reconnect": True,
        "replay_same_job": job["job_id"] == lost_job["job_id"],
        "fake_worker_terminal": terminal["state"],
        "lease": terminal["lease"],
        "kill_switch": terminal["kill_switch"],
        "autonomous_dry_run": terminal["autonomous_dry_run"],
        "deployment": terminal["deployment"],
    }
    print(json.dumps(evidence), flush=True)
    await task.shutdown()

try:
    asyncio.run(exercise())
except BaseException as exc:
    print(json.dumps({"error": repr(exc)}), file=sys.stderr, flush=True)
    raise
'''.replace("__FIXTURE__", str(fixture))
            result = subprocess.run(
                [PYTHON, "-c", script],
                cwd="/home/jeff/hermes-swarm-phase1",
                env={
                    "PATH": "/usr/bin:/bin",
                    "HOME": "/home/jeff",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONPATH": "/home/jeff/hermes-swarm-phase1",
                    "HERMES_HOME": "/home/jeff/hermes-swarm-desktop-home",
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                timeout=15,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertNotIn("error", evidence)
        self.assertEqual(evidence["fake_worker_terminal"], "SUCCEEDED")
        self.assertTrue(evidence["replay_same_job"])
        self.assertEqual(evidence["lease"], "CONSUMED")
        self.assertEqual(evidence["kill_switch"], "ENGAGED")
        self.assertEqual(evidence["autonomous_dry_run"], "DISABLED")
        self.assertEqual(evidence["deployment"], "DISABLED")
        ps_output = subprocess.check_output(["ps", "-eo", "comm=,args="], text=True)
        self.assertFalse(any(
            line.split(maxsplit=1)[1].startswith("/home/jeff/.local/bin/hermes-swarm-mcp")
            or (line.split(maxsplit=1)[0] in {"python", "python3"} and "mcp_stdio_watchdog.py" in line)
            for line in ps_output.splitlines()
            if line.strip() and len(line.split(maxsplit=1)) == 2
        ))
        self.assertGreaterEqual(evidence["initial_generation"], 1)
        self.assertGreater(evidence["reconnected_generation"], evidence["initial_generation"])
        self.assertTrue(evidence["ready"])

    @requires_host_fixture(LIFECYCLE_FIXTURE, "Hermes MCP lifecycle integration")
    def test_official_hermes_probe_discovers_seven_tools_under_five_seconds(self):
        env = {
            "PATH": "/usr/bin:/bin",
            "PYTHONNOUSERSITE": "1",
            "HERMES_HOME": "/home/jeff/hermes-swarm-desktop-home",
        }
        result = subprocess.run(
            [
                "/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/hermes",
                "mcp",
                "test",
                "coding_swarm",
            ],
            cwd="/home/jeff/hermes-swarm-phase1",
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Connected (", result.stdout)
        self.assertIn("Tools discovered: 7", result.stdout)

    @requires_host_fixture(LIFECYCLE_FIXTURE, "Hermes MCP lifecycle integration")
    def test_readiness_requires_strictly_newer_generation(self):
        script = r'''
import asyncio, json, sys
sys.path.insert(0, "/home/jeff/hermes-swarm-phase1")
import tools.mcp_tool as m

class Event:
    def __init__(self, value): self.value = value
    def is_set(self): return self.value

class Server:
    _ready = Event(True)
    _ready_generation = 7
    session = object()

async def main():
    stale = m._wait_for_server_session_ready(Server(), old_session=object(), old_generation=7, timeout=0.05)
    fresh = m._wait_for_server_session_ready(Server(), old_session=object(), old_generation=6, timeout=0.05)
    print(json.dumps({"stale": stale, "fresh": fresh}))

asyncio.run(main())
'''
        result = subprocess.run(
            [PYTHON, "-c", script], cwd="/home/jeff/hermes-swarm-phase1",
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": "/home/jeff/hermes-swarm-phase1"},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            shell=False, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"stale": False, "fresh": True})


if __name__ == "__main__":
    unittest.main()
