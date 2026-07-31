"""Disposable-only Phase 3 deployment contract simulator.

This module never starts a service, runs a command, opens a network connection,
or enables deployment. It mutates only a marked temporary fixture so the
approval, backup, health, rollback, and replay contracts can be tested.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from .core import SwarmError, read_restricted_bytes, restore_restricted_bytes, write_restricted_text


EXPECTED_SERVICE = "forgewarden-synthetic-fixture-v1"
FIXTURE_MARKER = ".forgewarden-disposable-fixture"


@dataclass(frozen=True)
class FakeDeploymentRequest:
    job_id: str
    service: str
    approved_commit: str
    evidence_sha256: str
    approval_id: str


class FakeDeploymentAdapter:
    """Run a bounded deployment simulation against a marked temp fixture."""

    def __init__(self, fixture_root: Path):
        self.root = fixture_root
        self.target = fixture_root / "service-state.txt"
        self.backup_dir = fixture_root / ".phase3-backups"
        self.consumed = fixture_root / ".phase3-approval-consumed"

    def _validate_fixture(self) -> None:
        if self.root.is_symlink() or not self.root.is_dir():
            raise SwarmError("fake deployment requires a real fixture directory")
        marker = self.root / FIXTURE_MARKER
        if marker.is_symlink() or not marker.is_file() or read_restricted_bytes(marker, "fixture marker") != b"forgewarden-synthetic-fixture-v1\n":
            raise SwarmError("fake deployment requires the disposable fixture marker")
        if self.target.is_symlink() or self.backup_dir.is_symlink() or self.consumed.is_symlink():
            raise SwarmError("fake deployment rejects symlinked state")

    @staticmethod
    def _validate_approval(request: FakeDeploymentRequest, approval: Mapping[str, object]) -> None:
        required = {"mode", "approval_id", "job_id", "service", "approved_commit", "evidence_sha256", "decision", "one_time", "consumed", "deployment"}
        if set(approval) != required:
            raise SwarmError("fake deployment approval has unexpected fields")
        if approval["mode"] != "FAKE_DEPLOYMENT_SIMULATION" or approval["decision"] != "APPROVED":
            raise SwarmError("fake deployment approval is not approved")
        if approval["one_time"] is not True or approval["consumed"] is not False:
            raise SwarmError("fake deployment approval is replayed or not one-time")
        if approval["deployment"] != "DISABLED":
            raise SwarmError("fake deployment cannot enable deployment")
        for key, expected in (("approval_id", request.approval_id), ("job_id", request.job_id), ("service", request.service), ("approved_commit", request.approved_commit), ("evidence_sha256", request.evidence_sha256)):
            if approval[key] != expected:
                raise SwarmError(f"fake deployment approval mismatch: {key}")

    def execute(self, request: FakeDeploymentRequest, approval: Mapping[str, object], health_check: Callable[[Path], bool], audit: Callable[[str, Mapping[str, object]], None] | None = None) -> dict[str, object]:
        self._validate_fixture()
        if request.service != EXPECTED_SERVICE or not re.fullmatch(r"[0-9a-f]{40}", request.approved_commit) or not re.fullmatch(r"[0-9a-f]{64}", request.evidence_sha256):
            raise SwarmError("fake deployment request is outside the fixed contract")
        self._validate_approval(request, approval)
        if self.consumed.exists():
            raise SwarmError("fake deployment approval replay detected")
        self.consumed.write_text(request.approval_id + "\n", encoding="ascii")
        self.consumed.chmod(0o600)
        previous = read_restricted_bytes(self.target, "fake service state") if self.target.exists() else b""
        self.backup_dir.mkdir(mode=0o700)
        self.backup_dir.chmod(0o700)
        backup = self.backup_dir / f"{request.job_id}.bak"
        write_restricted_text(backup, previous.decode("utf-8"), "fake deployment backup")
        write_restricted_text(self.target, json.dumps({"service": request.service, "commit": request.approved_commit, "simulated": True}, sort_keys=True) + "\n", "fake service state")
        result: dict[str, object]
        try:
            if not health_check(self.target):
                result = {"state": "ROLLED_BACK", "deployment": "DISABLED", "rollback": True, "reason": "health_check_failure", "backup": str(backup)}
            else:
                result = {"state": "SIMULATED_SUCCEEDED", "deployment": "DISABLED", "rollback": False, "backup": str(backup)}
                if audit is not None:
                    audit("simulated_deployment_completed", result)
                return result
        except TimeoutError:
            result = {"state": "ROLLED_BACK", "deployment": "DISABLED", "rollback": True, "reason": "health_check_timeout", "backup": str(backup)}
        except Exception:
            result = {"state": "ROLLED_BACK", "deployment": "DISABLED", "rollback": True, "reason": "audit_or_health_failure", "backup": str(backup)}
        if result["rollback"]:
            restore_restricted_bytes(self.target, previous, "fake service rollback")
        return result
