import hashlib
import unittest

from swarm.core import SwarmError
from swarm.phase3_deployment_executor import APPROVED_COMMIT, PROFILE_ID, SERVICE, DeploymentRequest, GuardedDeploymentExecutor


class GuardedDeploymentExecutorTests(unittest.TestCase):
    def setUp(self):
        self.request = DeploymentRequest(PROFILE_ID, "phase3-job-1", SERVICE, APPROVED_COMMIT, hashlib.sha256(b"evidence").hexdigest())
        self.approval = {"job_id": self.request.job_id, "service": self.request.service, "approved_commit": self.request.approved_commit, "evidence_sha256": self.request.evidence_sha256, "decision": "APPROVED", "one_time": True, "consumed": False, "deployment": "DISABLED"}

    def test_preflight_returns_non_mutating_plan(self):
        plan = GuardedDeploymentExecutor.preflight(self.request, self.approval)
        self.assertEqual(plan["state"], "READY_FOR_SEPARATE_DEPLOYMENT_AUTHORIZATION")
        self.assertFalse(plan["mutation_allowed"])
        self.assertEqual(plan["deployment"], "DISABLED")

    def test_wrong_commit_fails_closed(self):
        request = DeploymentRequest(PROFILE_ID, self.request.job_id, SERVICE, "a" * 40, self.request.evidence_sha256)
        with self.assertRaises(SwarmError):
            GuardedDeploymentExecutor.preflight(request, self.approval)

    def test_execute_is_mechanically_disabled(self):
        with self.assertRaisesRegex(SwarmError, "disabled"):
            GuardedDeploymentExecutor().execute(self.request, self.approval)


if __name__ == "__main__":
    unittest.main()
