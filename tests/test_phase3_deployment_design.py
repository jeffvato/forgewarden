import json
from pathlib import Path
from unittest import TestCase

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "config/phase3-deployment-profile.yaml"
SCHEMA = ROOT / "schemas/phase3-deployment-profile.schema.json"
NOTE = ROOT / "docs/phase3-deployment-design.md"


class Phase3DeploymentDesignTests(TestCase):
    def test_profile_is_strict_design_only_and_disabled(self):
        profile = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(profile)
        self.assertEqual(profile["status"], "DESIGN_ONLY")
        self.assertEqual(profile["deployment"], "DISABLED")
        self.assertEqual(profile["approval"]["required"], True)
        self.assertEqual(profile["approval"]["one_time"], True)

    def test_profile_is_not_registered_or_wired(self):
        profile = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
        profile_text = PROFILE.read_text(encoding="utf-8")
        registry = (ROOT / "config/phase2b-profile-registry.yaml").read_text(encoding="utf-8")
        self.assertNotIn("forgewarden_synthetic_service_deployment_v1", registry)
        self.assertFalse((ROOT / "swarm/phase3_deployment.py").exists())
        self.assertNotIn("PENDING_HUMAN_APPROVAL", profile_text)
        self.assertEqual(profile["approved_commit"], "06a22f1c431867cede1265bae7edf706e5a5ae04")
        self.assertEqual(profile["notification"]["channel"], "durable_local_audit")

    def test_design_requires_backup_health_and_rollback(self):
        note = NOTE.read_text(encoding="utf-8")
        for required in ("human approval", "approved commit", "backup", "health check", "rollback", "no-follow", "failure to prove"):
            self.assertIn(required, note.lower())


if __name__ == "__main__":
    import unittest
    unittest.main()
