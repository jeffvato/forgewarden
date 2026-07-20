"""Process-level Hermes MCP keepalive and generation-readiness checks."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


PYTHON = "/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python"


class HermesMcpLifecycleTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("HERMES_MCP_LIFECYCLE_REAL") == "1",
        "real WSL MCPServerTask lifecycle is an explicit diagnostic run",
    )
    def test_real_mcp_server_task_survives_three_accelerated_keepalives(self):
        with tempfile.TemporaryDirectory(prefix="hermes-mcp-fixture-") as temp:
            fixture = Path(temp) / "server.py"
            fixture.write_text(
                "from mcp.server.fastmcp import FastMCP\n"
                "server = FastMCP('keepalive-fixture')\n"
                "@server.tool()\n"
                "def status() -> str:\n"
                "    return 'DRY_RUN/DISABLED/ENGAGED'\n"
                "server.run(transport='stdio')\n",
                encoding="utf-8",
            )
            script = r'''
import asyncio, copy, json, sys, yaml
sys.path.insert(0, "/home/jeff/hermes-swarm-phase1")
import tools.mcp_tool as m

async def exercise():
    server_config = {
        "command": "/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python",
        "args": ["__FIXTURE__"],
        "connect_timeout": 10,
        "tools": {"include": ["status"], "resources": False, "prompts": False},
    }
    server_config["keepalive_interval"] = 5
    server_config["connect_timeout"] = 10
    task = m.MCPServerTask("coding_swarm")
    runner = asyncio.create_task(task.run(server_config))
    await asyncio.wait_for(task._ready.wait(), timeout=30)
    first_generation = task._ready_generation
    assert first_generation == task._connection_generation
    for _ in range(3):
        await asyncio.sleep(5.5)
        await task.session.send_ping()
        result = await task.session.call_tool("status", {})
        assert not result.isError
        assert result.content
    assert not runner.done()
    evidence = {"generation": first_generation, "ready": task._ready.is_set()}
    task._shutdown_event.set()
    task._reconnect_event.set()
    runner.cancel()
    print(json.dumps(evidence), flush=True)
    # The watchdog owns the child process. Exiting this disposable parent
    # after evidence is emitted gives the watchdog its tested parent-death
    # cleanup path and prevents SDK teardown from extending the fixture.
    import os
    os._exit(0)

asyncio.run(exercise())
'''.replace("__FIXTURE__", str(fixture))
            result = subprocess.run(
                [PYTHON, "-c", script],
                cwd="/home/jeff/hermes-swarm-phase1",
                env={"PATH": "/usr/bin:/bin", "PYTHONPATH": "/home/jeff/hermes-swarm-phase1"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                timeout=55,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertGreaterEqual(evidence["generation"], 1)
        self.assertTrue(evidence["ready"])

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
