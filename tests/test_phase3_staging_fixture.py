import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from swarm.phase3_deployment_executor import GuardedDeploymentExecutor, DeploymentRequest
from swarm.phase3_fake_deployment import FakeDeploymentAdapter, FakeDeploymentRequest


ROOT = Path(__file__).resolve().parents[1]


class Phase3StagingFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="phase3-staging-fixture-")
        self.root = Path(self.temp.name)
        (self.root / ".forgewarden-disposable-fixture").write_text("forgewarden-synthetic-fixture-v1\n", encoding="utf-8")
        (self.root / "service-state.txt").write_text("baseline\n", encoding="utf-8")
        profile = yaml.safe_load((ROOT / "config/phase3-deployment-profile.yaml").read_text(encoding="utf-8"))
        self.request = DeploymentRequest(profile["profile_id"], "phase3-staging-job-1", profile["service"], profile["approved_commit"], hashlib.sha256(b"phase3-evidence").hexdigest())
        self.fake_request = FakeDeploymentRequest(self.request.job_id, self.request.service, self.request.approved_commit, self.request.evidence_sha256, "c" * 32)
        self.approval = {"mode": "FAKE_DEPLOYMENT_SIMULATION", "approval_id": self.fake_request.approval_id, "job_id": self.request.job_id, "service": self.request.service, "approved_commit": self.request.approved_commit, "evidence_sha256": self.request.evidence_sha256, "decision": "APPROVED", "one_time": True, "consumed": False, "deployment": "DISABLED"}
        self.audit = self.root / "audit.jsonl"

    def tearDown(self):
        self.temp.cleanup()

    def _record(self, event, payload):
        with self.audit.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"event": event, **payload}, sort_keys=True) + "\n")

    def test_approved_preflight_and_fake_staging_success_are_audited(self):
        plan = GuardedDeploymentExecutor.preflight(self.request, self.approval)
        self.assertFalse(plan["mutation_allowed"])
        result = FakeDeploymentAdapter(self.root).execute(self.fake_request, self.approval, lambda path: True, self._record)
        self.assertEqual(result["state"], "SIMULATED_SUCCEEDED")
        self._record("staging_simulation_completed", result)
        events = [json.loads(line) for line in self.audit.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([event["event"] for event in events], ["simulated_deployment_completed", "staging_simulation_completed"])
        self.assertTrue(Path(result["backup"]).is_file())

    def test_staging_health_failure_rolls_back_and_records_disabled_state(self):
        result = FakeDeploymentAdapter(self.root).execute(self.fake_request, self.approval, lambda path: False, self._record)
        self.assertEqual(result["state"], "ROLLED_BACK")
        self.assertEqual((self.root / "service-state.txt").read_text(), "baseline\n")
        self._record("staging_simulation_rolled_back", {"state": result["state"], "deployment": result["deployment"]})
        event = json.loads(self.audit.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(event["deployment"], "DISABLED")

    def test_persisted_staging_evidence_is_strict_and_sanitized(self):
        evidence = json.loads((ROOT / "docs/phase3-staging-evidence.json").read_text(encoding="utf-8"))
        schema = json.loads((ROOT / "schemas/phase3-staging-evidence.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(evidence)
        self.assertEqual(evidence["deployment"], "DISABLED")
        self.assertTrue(evidence["fixture_disposable"])


if __name__ == "__main__":
    unittest.main()
