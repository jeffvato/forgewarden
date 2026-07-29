import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import http.client
import socket
import threading
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from swarm.console import dispatch_plan, load_profiles, ConsoleHandler
from swarm.core import SwarmError

class ConsoleTests(unittest.TestCase):
    def test_profiles_are_complete_and_global_guards_are_inherited(self):
        profiles = load_profiles(); self.assertEqual({p["id"] for p in profiles},{"codex-writer","gemini-reviewer","claude-auditor","fable-analyst"})
        for profile in profiles: self.assertTrue({"production","deployment","credentials","databases","remote_hosts"}.issubset(profile["forbidden_actions"]))

    def test_dispatch_plan_is_plan_only_and_model_scoped(self):
        result=dispatch_plan("codex-writer","implement","Harden the local fixture"); self.assertEqual(result["mode"],"PLAN_ONLY"); self.assertFalse(result["execution_started"]); self.assertTrue(result["guardrails"]["local_only"])
        with self.assertRaises(PermissionError): dispatch_plan("gemini-reviewer","implement","Write source")

    def test_profile_registry_rejects_weakened_global_guardrails(self):
        with TemporaryDirectory() as directory:
            path=Path(directory)/"profiles.json"; payload=json.loads((Path(__file__).parents[1]/"config/llm-profiles.json").read_text()); payload["profiles"][0]["forbidden_actions"].remove("production"); path.write_text(json.dumps(payload),encoding="utf-8")
            with self.assertRaises(ValueError): load_profiles(path)

    def test_profile_registry_rejects_symlink(self):
        with TemporaryDirectory() as directory:
            real_path = Path(directory) / "real_profiles.json"
            real_path.write_text((Path(__file__).parents[1] / "config/llm-profiles.json").read_text(), encoding="utf-8")
            symlink_path = Path(directory) / "symlink_profiles.json"
            symlink_path.symlink_to(real_path)
            with self.assertRaises(ValueError):
                load_profiles(symlink_path)

    def test_console_http_endpoints_and_asset_safety(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        server = ThreadingHTTPServer(("127.0.0.1", port), ConsoleHandler)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()

        try:
            conn = http.client.HTTPConnection("127.0.0.1", port)

            # 1. Test GET /api/status
            conn.request("GET", "/api/status")
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.OK)
            data = json.loads(resp.read().decode())
            self.assertIn("safety", data)
            self.assertIn("workflow", data)

            # 2. Test GET /api/models
            conn.request("GET", "/api/models")
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.OK)
            data = json.loads(resp.read().decode())
            self.assertIn("profiles", data)
            self.assertIn("tasks", data)

            # 3. Test POST /api/dispatch-plan
            body = json.dumps({
                "model_id": "codex-writer",
                "task": "implement",
                "objective": "Harden the console server"
            })
            conn.request("POST", "/api/dispatch-plan", body, {"Content-Type": "application/json"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.OK)
            data = json.loads(resp.read().decode())
            self.assertEqual(data["mode"], "PLAN_ONLY")

            # 4. Test GET static assets
            conn.request("GET", "/")
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.OK)
            self.assertEqual(resp.getheader("Content-Type"), "text/html; charset=utf-8")
            self.assertTrue(len(resp.read()) > 0)

        finally:
            conn.close()
            server.shutdown()
            thread.join()
            server.server_close()

    def test_console_http_asset_safety_rejects_symlink(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        with TemporaryDirectory() as directory:
            temp_root = Path(directory)
            real_asset = temp_root / "index.html"
            real_asset.write_text("hello html", encoding="utf-8")

            symlink_asset = temp_root / "styles.css"
            symlink_asset.symlink_to(real_asset)

            from unittest.mock import patch
            with patch("swarm.console.CONSOLE_ROOT", temp_root):
                server = ThreadingHTTPServer(("127.0.0.1", port), ConsoleHandler)
                thread = threading.Thread(target=server.serve_forever)
                thread.daemon = True
                thread.start()

                try:
                    conn = http.client.HTTPConnection("127.0.0.1", port)

                    # GET index.html (real file) -> OK
                    conn.request("GET", "/")
                    resp = conn.getresponse()
                    self.assertEqual(resp.status, HTTPStatus.OK)
                    self.assertEqual(resp.read().decode(), "hello html")

                    # GET styles.css (symlink) -> INTERNAL_SERVER_ERROR
                    conn.request("GET", "/styles.css")
                    resp = conn.getresponse()
                    self.assertEqual(resp.status, HTTPStatus.INTERNAL_SERVER_ERROR)

                finally:
                    conn.close()
                    server.shutdown()
                    thread.join()
                    server.server_close()

if __name__ == "__main__": unittest.main()
