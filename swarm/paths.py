"""Trusted paths owned by the checked-out Hermes swarm package."""
from __future__ import annotations

import os
from pathlib import Path


def project_root() -> Path:
    """Return the real repository root containing this ``swarm`` package.

    The source root is derived from the package location, not from the current
    working directory or an ambient environment variable. A malformed copy is
    rejected before it can be used as the swarm implementation.
    """
    root = Path(__file__).resolve().parents[1]
    required = (root / "config", root / "schemas", root / "swarm")
    if not all(path.is_dir() for path in required):
        raise RuntimeError("swarm package is not inside a valid project root")
    return root


def configured_path(name: str, default: str) -> Path:
    """Read an explicitly configured absolute path without PATH lookup."""
    value = os.environ.get(name, default)
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise RuntimeError(f"{name} must be an absolute path")
    return path


def runtime_root() -> Path:
    return configured_path("HERMES_SWARM_RUNTIME_ROOT", "/home/jeff/hermes-swarm-runtime")


def audit_root() -> Path:
    return configured_path("HERMES_SWARM_AUDIT_ROOT", "/home/jeff/hermes-swarm-audit")


def audit_path() -> Path:
    return audit_root() / "audit.jsonl"


def launcher_path() -> Path:
    return configured_path("HERMES_SWARM_LAUNCHER", "/home/jeff/.local/bin/hermes-swarm")
