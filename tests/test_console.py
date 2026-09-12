import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import http.client
import socket
import threading
import subprocess
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from swarm.console import addon_audit_snapshot, addon_snapshot, approval_snapshot, dispatch_plan, evidence_snapshot, harness_activity_snapshot, incident_activity_snapshot, installation_snapshot, job_detail, jobs_snapshot, load_profiles, ConsoleHandler
from swarm.core import SwarmError
from swarm.mission_control_demo import DEMO_SCENARIO_ID, mission_control_demo_snapshot

class ConsoleTests(unittest.TestCase):
    def test_harness_activity_provider_has_honest_empty_and_unavailable_states(self):
        self.assertEqual(harness_activity_snapshot()["data_mode"], "EMPTY")
        self.assertEqual(harness_activity_snapshot(lambda: (_ for _ in ()).throw(RuntimeError("offline")))["data_mode"], "UNAVAILABLE")

    def test_incident_activity_provider_has_honest_empty_and_unavailable_states(self):
        self.assertEqual(incident_activity_snapshot()["data_mode"], "EMPTY")
        unavailable = incident_activity_snapshot(lambda: (_ for _ in ()).throw(RuntimeError("offline")))
        self.assertEqual(unavailable["data_mode"], "UNAVAILABLE")
        self.assertFalse(unavailable["safety"]["response_executed"])

    def test_frontend_contract_and_rendering_boundaries(self):
        root = Path(__file__).parents[1]
        result = subprocess.run(["node", "tests/test_console_frontend.js"], cwd=root, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_mission_control_demo_is_explicit_deterministic_and_non_authorizing(self):
        first = mission_control_demo_snapshot()
        second = mission_control_demo_snapshot()
        self.assertEqual(first, second)
        self.assertEqual(first["data_mode"], "DEMO")
        self.assertEqual(first["scenario"]["id"], DEMO_SCENARIO_ID)
        self.assertFalse(first["provenance"]["live_backend_connected"])
        self.assertFalse(first["provenance"]["cryptographic_verification_performed"])
        self.assertFalse(first["safety"]["mutation_allowed"])
        self.assertEqual(first["safety"]["deployment"], "DISABLED")
        self.assertIn("SIMULATED", first["evidence"]["chain_status"])
        self.assertEqual(len(first["incident"]["detections"]), 3)
        self.assertEqual(first["incident"]["recovery"]["execution"], "NOT EXECUTED")
        self.assertEqual(first["ai_security"]["agent"]["authority"], "BOUNDED / REVOKED")
        self.assertEqual(first["ai_security"]["agent"]["proposal"], "REVOKE_LEASE / PROPOSE_ONLY")
        self.assertEqual(len(first["ai_security"]["timeline"]), 6)
        self.assertEqual(first["harness"]["risk_tier"], "T3")
        self.assertEqual(first["harness"]["budget"]["calls"], "2 / 3")
        self.assertIn("Independent", first["harness"]["reviewer"])
        self.assertEqual(first["evidence"]["tenant"], "northstar-demo")
        self.assertEqual(len(first["evidence"]["chronology"]), 4)
        self.assertEqual(first["governance"]["policy"]["decision"], "DENY")
        self.assertIn("NOT EXECUTED", first["governance"]["ticket"]["status"])
        self.assertEqual({item["status"] for item in first["models"]}, {"APPROVED", "RESTRICTED", "UNAVAILABLE"})
        self.assertEqual(first["mcp"][0]["security"], "AUTHORITY EXPANSION BLOCKED")
        self.assertEqual(first["executive"]["recoverability"], "88% / READY")
        self.assertEqual(len(first["executive"]["outcomes"]), 4)
        self.assertEqual([item["step"] for item in first["demo_tour"]], ["01", "02", "03", "04", "05", "06"])
        self.assertEqual(first["demo_tour"][0]["view"], "mission")
        self.assertEqual(first["demo_tour"][-1]["view"], "evidence")
        self.assertTrue(all("T" in item for item in first["incident"]["mitre"]))
        first["assets"][0]["value"] = 0
        self.assertEqual(second["assets"][0]["value"], 1204)

    def test_console_exposes_navigation_and_status_accessibility_hooks(self):
        html = (Path(__file__).parents[1] / "console" / "index.html").read_text(encoding="utf-8")
        script = (Path(__file__).parents[1] / "console" / "app.js").read_text(encoding="utf-8")
        self.assertIn('<nav aria-label="Primary navigation">', html)
        self.assertIn("$('connection').setAttribute('aria-live','polite')", script)
        self.assertIn("setAttribute('aria-current','page')", script)
        self.assertIn("removeAttribute('aria-current')", script)
        self.assertIn("class MissionControlClient", script)
        self.assertIn("function validateSnapshot", script)
        self.assertIn("s.safety?.mutation_allowed!==false", script)
        self.assertIn("DEMO ENVIRONMENT", html)
        self.assertIn("SIMULATED DATA · BACKEND NOT CONNECTED", html)
        self.assertIn("AI Intrusion Defense", html)
        self.assertIn("Evidence Vault", html)
        self.assertIn("Policy & Action Ticket", html)
        self.assertIn("Model Broker", html)
        self.assertIn("MCP Control", html)
        self.assertIn("GUIDED DEMO", html)
        self.assertIn('aria-label="Previous demo step"', html)
        self.assertIn("prefers-reduced-motion", (Path(__file__).parents[1] / "console" / "styles.css").read_text(encoding="utf-8"))
        self.assertIn("UNIFIED ATTACK STORY", html)
        self.assertIn('id="incident-live-state"', html)
        self.assertIn("RESPONSE & RECOVERY", html)
        self.assertIn("DEMO / NOT VERIFIED", html)
    def test_profiles_are_complete_and_global_guards_are_inherited(self):
        profiles = load_profiles(); self.assertEqual({p["id"] for p in profiles},{"codex-writer","gemini-reviewer","claude-verifier","claude-auditor","fable-analyst"})
        for profile in profiles: self.assertTrue({"production","deployment","credentials","databases","remote_hosts"}.issubset(profile["forbidden_actions"]))

    def test_dispatch_plan_is_plan_only_and_model_scoped(self):
        result=dispatch_plan("codex-writer","implement","Harden the local fixture"); self.assertEqual(result["mode"],"PLAN_ONLY"); self.assertFalse(result["execution_started"]); self.assertTrue(result["guardrails"]["local_only"])
        with self.assertRaises(PermissionError): dispatch_plan("gemini-reviewer","implement","Write source")

    def test_addon_and_installation_snapshots_are_read_only_posture(self):
        addons = addon_snapshot()
        self.assertEqual(addons["registry_version"], 1)
        self.assertIn("addons", addons)
        install = installation_snapshot()
        self.assertEqual(install["mode"], "PLAN_ONLY")
        self.assertEqual(install["uninstall"], "CONFIRMATION_REQUIRED")
        self.assertEqual(addon_audit_snapshot()["events"], [])
        self.assertIn("records", jobs_snapshot())
        self.assertIn("records", evidence_snapshot())
        self.assertEqual(approval_snapshot()["records"], [])
        self.assertEqual(job_detail("phase2a-1ab6c00f50704fd782e06e8d")["job_id"], "phase2a-1ab6c00f50704fd782e06e8d")
        with self.assertRaises(ValueError):
            job_detail("not a job")

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

            # 2b. Read-only lifecycle posture endpoints
            conn.request("GET", "/api/addons")
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.OK)
            self.assertIn("addons", json.loads(resp.read().decode()))
            conn.request("GET", "/api/installation")
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.OK)
            self.assertEqual(json.loads(resp.read().decode())["mode"], "PLAN_ONLY")
            conn.request("GET", "/api/audit")
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.OK)
            self.assertIn("events", json.loads(resp.read().decode()))
            conn.request("GET", "/api/jobs")
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.OK)
            self.assertIn("records", json.loads(resp.read().decode()))
            conn.request("GET", "/api/evidence")
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.OK)
            self.assertIn("records", json.loads(resp.read().decode()))
            conn.request("GET", "/api/approvals")
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.OK)
            self.assertIn("records", json.loads(resp.read().decode()))
            conn.request("GET", "/api/mission-control")
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.OK)
            snapshot = json.loads(resp.read().decode())
            self.assertEqual(snapshot["data_mode"], "DEMO")
            self.assertEqual(snapshot["scenario"]["id"], DEMO_SCENARIO_ID)
            conn.request("GET", "/api/harness-activity")
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.OK)
            activity = json.loads(resp.read().decode())
            self.assertEqual(activity["data_mode"], "EMPTY")
            self.assertFalse(activity["safety"]["mutation_allowed"])
            conn.request("GET", "/api/incident-activity")
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.OK)
            incident_activity = json.loads(resp.read().decode())
            self.assertEqual(incident_activity["data_mode"], "EMPTY")
            self.assertFalse(incident_activity["safety"]["response_executed"])
            conn.request("GET", "/api/jobs/not%20a%20job")
            resp = conn.getresponse()
            self.assertEqual(resp.status, HTTPStatus.BAD_REQUEST)

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
