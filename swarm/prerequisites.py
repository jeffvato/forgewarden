"""Offline runtime and tool checks for the Forgewarden installer."""
from __future__ import annotations

import importlib.util
import platform
import shutil
import subprocess
import sys
from typing import Any, Iterable


def inspect_prerequisites(tools: Iterable[str] = ()) -> dict[str, Any]:
    python_ok = sys.version_info >= (3, 11)
    report: dict[str, Any] = {
        "python": {"path": sys.executable, "version": platform.python_version(), "ok": python_ok},
        "modules": {"jsonschema": importlib.util.find_spec("jsonschema") is not None},
        "tools": {},
    }
    for requested in tools:
        path = shutil.which(requested)
        if not path:
            report["tools"][requested] = {"status": "MISSING", "ok": False}
            continue
        try:
            result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=5, check=False)
            version = (result.stdout or result.stderr).strip().splitlines()[0] if result.returncode == 0 else ""
            report["tools"][requested] = {"path": path, "version": version, "status": "READY" if result.returncode == 0 else "FAILED", "ok": result.returncode == 0}
        except (OSError, subprocess.SubprocessError) as exc:
            report["tools"][requested] = {"path": path, "status": "FAILED", "ok": False, "error": type(exc).__name__}
    return report


def require_prerequisites(report: dict[str, Any]) -> None:
    failures = []
    if not report.get("python", {}).get("ok"):
        failures.append("Python >= 3.11")
    if not report.get("modules", {}).get("jsonschema"):
        failures.append("Python module jsonschema")
    failures.extend(name for name, value in report.get("tools", {}).items() if not value.get("ok"))
    if failures:
        raise RuntimeError("missing or unusable Forgewarden prerequisites: " + ", ".join(failures))
