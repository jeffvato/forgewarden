import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts import hermes_mcp_compat_patch as patch


class HermesMcpCompatPatchTests(unittest.TestCase):
    def test_patch_transform_is_scoped_to_session_expiry_function(self):
        source = (
            b"def other():\n    msg = str(exc).lower()\n\n"
            b"def _is_session_expired_error(exc):\n"
            b"    msg = str(exc).lower()\n"
        )
        result = patch.patched_source(source)
        self.assertIn(b"def other():\n    msg = str(exc).lower()", result)
        self.assertIn(b"def _is_session_expired_error(exc):\n    msg = _exc_str(exc).lower()", result)

    def test_unknown_source_is_refused(self):
        with self.assertRaises(RuntimeError):
            patch.patched_source(b"def _is_session_expired_error(exc):\n    pass\n")

    def test_bare_closed_resource_is_classified_and_reconnect_retries_once(self):
        script = r'''
import asyncio, json
import anyio
import tools.mcp_tool as m

class Loop:
    def is_running(self): return True
class Server:
    def __init__(self): self._reconnect_event = object()

async def check():
    original_signal = m._signal_reconnect_and_wait
    original_servers = m._servers
    original_loop = m._mcp_loop
    calls = []
    try:
        m._servers = {"coding_swarm": Server()}
        m._mcp_loop = Loop()
        m._signal_reconnect_and_wait = lambda *a, **k: True
        def retry():
            calls.append(1)
            return json.dumps({"ok": True})
        classified = m._is_session_expired_error(anyio.ClosedResourceError())
        result = m._handle_session_expired_and_retry(
            "coding_swarm", anyio.ClosedResourceError(), retry, "status"
        )
        return {"classified": classified, "result": result, "retry_calls": len(calls)}
    finally:
        m._signal_reconnect_and_wait = original_signal
        m._servers = original_servers
        m._mcp_loop = original_loop

print(json.dumps(asyncio.run(check())))
'''
        result = subprocess.run(
            [
                "/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python",
                "-c",
                script,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout),
            {"classified": True, "result": '{"ok": true}', "retry_calls": 1},
        )

    def test_patch_cli_has_fixed_hash_contract(self):
        self.assertEqual(len(patch.EXPECTED_PREPATCH_SHA256), 64)
        self.assertEqual(len(patch.EXPECTED_POSTPATCH_SHA256), 64)
        self.assertEqual(patch.TARGET.name, "mcp_tool.py")
        self.assertEqual(patch.EXPECTED_HERMES_VERSION, "0.18.2")


if __name__ == "__main__":
    unittest.main()
