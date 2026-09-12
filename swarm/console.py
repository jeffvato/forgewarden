"""Local Forgewarden management console; plan-only by design."""
from __future__ import annotations
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse
from .paths import runtime_root
from .phase2a import safety_status, workflow_status
from .addons import AddonManager, AddonManifestError
from .desktop_bridge import job_status as bridge_job_status, recent_audit
from .mission_control_demo import mission_control_demo_snapshot
from .mission_control import MissionControlError, serialize_harness_activity, serialize_incident_activity

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "config" / "llm-profiles.json"
CONSOLE_ROOT = ROOT / "console"
TASKS = ("inspect", "implement", "test", "review", "risk_audit", "documentation", "analysis")
GLOBAL_FORBIDDEN = {"production", "deployment", "service_restart", "credentials", "databases", "remote_hosts"}

def addon_snapshot(root: Path | None = None) -> dict[str, Any]:
    """Read the local add-on registry without enabling or executing anything."""
    try:
        return AddonManager(root or (runtime_root() / "addons")).list_installed()
    except AddonManifestError as exc:
        raise ValueError(f"Failed to read add-on registry: {exc}") from exc

def addon_audit_snapshot(root: Path | None = None, limit: int = 50) -> dict[str, Any]:
    audit = AddonManager(root or (runtime_root() / "addons")).audit
    if not audit.exists():
        return {"events": []}
    from .core import read_restricted_bytes, SwarmError
    try:
        lines = read_restricted_bytes(audit, "add-on audit").decode("utf-8").splitlines()
        events = [json.loads(line) for line in lines if line.strip()]
    except (SwarmError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Failed to read add-on audit: {exc}") from exc
    if not all(isinstance(event, dict) for event in events):
        raise ValueError("add-on audit contains an invalid event")
    return {"events": events[-max(1, min(limit, 200)):], "truncated": len(events) > limit}

def installation_snapshot() -> dict[str, Any]:
    return {"mode": "PLAN_ONLY", "installer": "AVAILABLE", "promotion": "EXPLICIT", "rollback": "BACKUP_REQUIRED", "uninstall": "CONFIRMATION_REQUIRED", "production": "DISABLED"}

def jobs_snapshot() -> dict[str, Any]:
    """Return bounded, sanitized durable job records for the console."""
    return recent_audit(20)

def job_detail(job_id: str) -> dict[str, Any]:
    return bridge_job_status(job_id)

def evidence_detail(job_id: str) -> dict[str, Any]:
    result = job_detail(job_id)
    result["records"] = [record for record in result["records"] if any(key in record for key in ("verdict", "risk", "repair_commit"))]
    return result

def evidence_snapshot() -> dict[str, Any]:
    records = recent_audit(20)["records"]
    return {"records": [record for record in records if any(key in record for key in ("verdict", "risk", "repair_commit"))]}

def approval_snapshot(root: Path | None = None) -> dict[str, Any]:
    """Return bounded non-authorizing approval metadata for human review."""
    approval_dir = (root or runtime_root()) / "approvals"
    if not approval_dir.exists():
        return {"records": []}
    from .core import read_restricted_bytes, SwarmError
    records: list[dict[str, Any]] = []
    for path in sorted(approval_dir.glob("*.json")):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"unsafe approval record: {path.name}")
        try:
            value = json.loads(read_restricted_bytes(path, "approval record").decode("utf-8"))
        except (SwarmError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid approval record: {path.name}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"invalid approval record: {path.name}")
        records.append({key: value.get(key) for key in ("approval_id", "job_id", "reviewer", "decision", "expires_at", "consumed", "mutation_allowed", "deployment")})
    return {"records": records[-50:]}

def harness_activity_snapshot(provider: Any = None) -> dict[str, Any]:
    """Read one injected canonical Harness view without granting console authority."""
    if provider is None:
        return serialize_harness_activity(None)
    try:
        return serialize_harness_activity(provider())
    except (MissionControlError, OSError, RuntimeError, TypeError, ValueError):
        return {"schema_version": 1, "data_mode": "UNAVAILABLE", "data_label": "CANONICAL HARNESS ACTIVITY UNAVAILABLE", "view": None, "safety": {"mutation_allowed": False, "deployment": "DISABLED", "kill_switch": "ENGAGED"}}

def incident_activity_snapshot(provider: Any = None) -> dict[str, Any]:
    """Return canonical incident facts or an explicit fail-closed availability state."""
    if provider is None:
        return serialize_incident_activity(None)
    try:
        return serialize_incident_activity(provider())
    except (MissionControlError, RuntimeError, TypeError, ValueError):
        return {"schema_version": 1, "data_mode": "UNAVAILABLE", "data_label": "CANONICAL INCIDENT ACTIVITY UNAVAILABLE", "view": None, "safety": {"mutation_allowed": False, "deployment": "DISABLED", "kill_switch": "ENGAGED", "response_executed": False}}

def load_profiles(path: Path = PROFILE_PATH) -> list[dict[str, Any]]:
    from .core import read_restricted_bytes, SwarmError
    try:
        data = read_restricted_bytes(path, "LLM profile registry").decode("utf-8")
    except SwarmError as exc:
        raise ValueError(f"Failed to read LLM profiles: {exc}") from exc
    payload = json.loads(data)
    profiles = payload.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("LLM profile registry must contain profiles")
    required = {"id", "name", "provider", "role", "allowed_tasks", "forbidden_actions", "requires_human_approval", "description"}
    seen: set[str] = set()
    for profile in profiles:
        if not isinstance(profile, dict) or not required.issubset(profile):
            raise ValueError("LLM profile is incomplete")
        if not isinstance(profile["id"], str) or profile["id"] in seen:
            raise ValueError("LLM profile IDs must be unique strings")
        seen.add(profile["id"])
        if not set(profile["forbidden_actions"]).issuperset(GLOBAL_FORBIDDEN):
            raise ValueError(f"profile {profile['id']} weakens global guardrails")
        if not set(profile["allowed_tasks"]).issubset(TASKS):
            raise ValueError(f"profile {profile['id']} contains an unknown task")
    return profiles

def dispatch_plan(model_id: str, task: str, objective: str, profiles: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if task not in TASKS:
        raise ValueError("unknown task")
    if not isinstance(objective, str) or not objective.strip() or len(objective) > 1000:
        raise ValueError("objective must be non-empty and at most 1000 characters")
    profile = next((item for item in (profiles or load_profiles()) if item["id"] == model_id), None)
    if profile is None:
        raise ValueError("unknown model profile")
    if task not in profile["allowed_tasks"]:
        raise PermissionError(f"{profile['name']} is not allowed to perform {task}")
    return {"mode":"PLAN_ONLY","execution_started":False,"model":{"id":profile["id"],"name":profile["name"],"role":profile["role"]},"task":task,"objective":objective.strip(),"guardrails":{"allowed_tasks":profile["allowed_tasks"],"forbidden_actions":sorted(set(profile["forbidden_actions"]) | GLOBAL_FORBIDDEN),"requires_human_approval":profile["requires_human_approval"],"local_only":True,"deployment":"DISABLED"},"next_step":"Review this plan before wiring an execution adapter."}

class ConsoleHandler(BaseHTTPRequestHandler):
    server_version = "ForgewardenConsole/0.1"
    harness_view_provider = staticmethod(lambda: None)
    incident_view_provider = staticmethod(lambda: None)
    def _send(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status); self.send_header("Content-Type", content_type); self.send_header("Content-Length", str(len(payload))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(payload)
    def _json(self, status: int, payload: Any) -> None:
        self._send(status, json.dumps(payload, sort_keys=True).encode(), "application/json")
    def do_GET(self) -> None:  # noqa: N802
        route = urlparse(self.path).path
        if route == "/api/status": self._json(HTTPStatus.OK, {"safety":safety_status(runtime_root()),"workflow":workflow_status(runtime_root())}); return
        if route == "/api/models": self._json(HTTPStatus.OK, {"profiles":load_profiles(),"tasks":TASKS}); return
        if route == "/api/addons": self._json(HTTPStatus.OK, addon_snapshot()); return
        if route == "/api/installation": self._json(HTTPStatus.OK, installation_snapshot()); return
        if route == "/api/audit": self._json(HTTPStatus.OK, addon_audit_snapshot()); return
        if route == "/api/jobs": self._json(HTTPStatus.OK, jobs_snapshot()); return
        if route == "/api/evidence": self._json(HTTPStatus.OK, evidence_snapshot()); return
        if route.startswith("/api/jobs/"):
            try:
                self._json(HTTPStatus.OK, job_detail(unquote(route.removeprefix("/api/jobs/"))))
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except RuntimeError as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
            return
        if route.startswith("/api/evidence/"):
            try:
                self._json(HTTPStatus.OK, evidence_detail(unquote(route.removeprefix("/api/evidence/"))))
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except RuntimeError as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
            return
        if route == "/api/approvals": self._json(HTTPStatus.OK, approval_snapshot()); return
        if route == "/api/mission-control": self._json(HTTPStatus.OK, mission_control_demo_snapshot()); return
        if route == "/api/harness-activity": self._json(HTTPStatus.OK, harness_activity_snapshot(self.harness_view_provider)); return
        if route == "/api/incident-activity": self._json(HTTPStatus.OK, incident_activity_snapshot(self.incident_view_provider)); return
        assets = {"/":("index.html","text/html; charset=utf-8"),"/styles.css":("styles.css","text/css; charset=utf-8"),"/app.js":("app.js","text/javascript; charset=utf-8")}
        if route not in assets: self._json(HTTPStatus.NOT_FOUND, {"error":"not found"}); return
        filename, content_type = assets[route]
        from .core import read_restricted_bytes, SwarmError
        try:
            content = read_restricted_bytes(CONSOLE_ROOT / filename, "console asset")
        except SwarmError as exc:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
            return
        self._send(HTTPStatus.OK, content, content_type)
    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/api/dispatch-plan": self._json(HTTPStatus.NOT_FOUND, {"error":"not found"}); return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 8192: raise ValueError("request too large")
            payload = json.loads(self.rfile.read(length)); result = dispatch_plan(payload.get("model_id", ""), payload.get("task", ""), payload.get("objective", ""))
        except PermissionError as exc: self._json(HTTPStatus.FORBIDDEN, {"error":str(exc)})
        except (ValueError, TypeError, json.JSONDecodeError) as exc: self._json(HTTPStatus.BAD_REQUEST, {"error":str(exc)})
        else: self._json(HTTPStatus.OK, result)
    def log_message(self, *_args: Any) -> None: return

def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    ThreadingHTTPServer((host, port), ConsoleHandler).serve_forever()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Forgewarden local management console"); parser.add_argument("--host", default="127.0.0.1"); parser.add_argument("--port", type=int, default=8787); args = parser.parse_args(); serve(args.host, args.port)
