"""Availability checks for tests that require the ForgeWarden host installation."""

from pathlib import Path
from typing import Iterable
import unittest


def requires_host_fixture(paths: Iterable[str | Path], reason: str):
    """Skip a host-integration test only when its workstation fixture is absent."""
    missing = [Path(path) for path in paths if not Path(path).exists()]
    detail = ", ".join(str(path) for path in missing)
    return unittest.skipUnless(not missing, f"host fixture unavailable: {detail}; {reason}")

