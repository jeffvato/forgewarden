import json
import unittest
from pathlib import Path
from jsonschema import Draft202012Validator

from swarm.core import SwarmError
from swarm.phase4_fake_unattended import FakeUnattendedCoordinator, Prerequisites, PROFILE_ID, SERVICE


class Phase4FakeUnattendedTests(unittest.TestCase):
    def setUp(self):
        self.prerequisites = Prerequisites(True, True, True, True)
        self.approval = {"profile_id": PROFILE_ID, "service": SERVICE, "risk": "LOW", "one_time": True, "consumed": False, "deployment": "DISABLED"}

    def test_complete_prerequisites_produce_non_starting_plan(self):
        plan = FakeUnattendedCoordinator.preflight(SERVICE, "LOW", self.prerequisites, self.approval, kill_switch=True, active_workers=0)
        self.assertFalse(plan["worker_started"])
        self.assertEqual(plan["deployment"], "DISABLED")

    def test_missing_prerequisite_fails_closed(self):
        with self.assertRaisesRegex(SwarmError, "prerequisites"):
            FakeUnattendedCoordinator.preflight(SERVICE, "LOW", Prerequisites(False, True, True, True), self.approval, kill_switch=True, active_workers=0)

    def test_high_risk_and_duplicate_worker_are_rejected(self):
        with self.assertRaises(SwarmError):
            FakeUnattendedCoordinator.preflight(SERVICE, "HIGH", self.prerequisites, self.approval, kill_switch=True, active_workers=0)
        with self.assertRaisesRegex(SwarmError, "duplicate"):
            FakeUnattendedCoordinator.preflight(SERVICE, "LOW", self.prerequisites, self.approval, kill_switch=True, active_workers=1)

    def test_kill_switch_and_approval_are_required(self):
        with self.assertRaisesRegex(SwarmError, "kill switch"):
            FakeUnattendedCoordinator.preflight(SERVICE, "LOW", self.prerequisites, self.approval, kill_switch=False, active_workers=0)
        bad = dict(self.approval, consumed=True)
        with self.assertRaisesRegex(SwarmError, "approval"):
            FakeUnattendedCoordinator.preflight(SERVICE, "LOW", self.prerequisites, bad, kill_switch=True, active_workers=0)

    def test_enablement_is_mechanically_disabled(self):
        with self.assertRaisesRegex(SwarmError, "disabled"):
            FakeUnattendedCoordinator().enable()

    def test_persisted_coordinator_evidence_is_strict_and_disabled(self):
        root = Path(__file__).resolve().parents[1]
        evidence = json.loads((root / "docs/phase4-coordinator-evidence.json").read_text(encoding="utf-8"))
        schema = json.loads((root / "schemas/phase4-coordinator-evidence.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(evidence)
        self.assertFalse(evidence["worker_started"])
        self.assertEqual(evidence["enablement"], "DISABLED")


if __name__ == "__main__":
    unittest.main()
