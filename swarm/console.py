"""Local Forgewarden management console; plan-only by design."""
from __future__ import annotations
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from .paths import runtime_root
from .phase2a import safety_status, workflow_status

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "config" / "llm-profiles.json"
CONSOLE_ROOT = ROOT / "console"
TASKS = ("inspect", "implement", "test", "review", "risk_audit", "documentation", "analysis")
GLOBAL_FORBIDDEN = {"production", "deployment", "service_restart", "credentials", "databases", "remote_hosts"}

def load_profiles(path: Path = PROFILE_PATH) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
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
    def _send(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status); self.send_header("Content-Type", content_type); self.send_header("Content-Length", str(len(payload))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(payload)
    def _json(self, status: int, payload: Any) -> None:
        self._send(status, json.dumps(payload, sort_keys=True).encode(), "application/json")
    def do_GET(self) -> None:  # noqa: N802
        route = urlparse(self.path).path
        if route == "/api/status": self._json(HTTPStatus.OK, {"safety":safety_status(runtime_root()),"workflow":workflow_status(runtime_root())}); return
        if route == "/api/models": self._json(HTTPStatus.OK, {"profiles":load_profiles(),"tasks":TASKS}); return
        assets = {"/":("index.html","text/html; charset=utf-8"),"/styles.css":("styles.css","text/css; charset=utf-8"),"/app.js":("app.js","text/javascript; charset=utf-8")}
        if route not in assets: self._json(HTTPStatus.NOT_FOUND, {"error":"not found"}); return
        filename, content_type = assets[route]; self._send(HTTPStatus.OK, (CONSOLE_ROOT / filename).read_bytes(), content_type)
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
