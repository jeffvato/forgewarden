"""Trusted paths owned by the checked-out Hermes swarm package."""
from __future__ import annotations

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
