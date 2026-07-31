import json
from pathlib import Path
from unittest import TestCase

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "config/phase4-unattended-profile.yaml"
SCHEMA = ROOT / "schemas/phase4-unattended-profile.schema.json"
NOTE = ROOT / "docs/phase4-unattended-design.md"


class Phase4UnattendedDesignTests(TestCase):
    def test_profile_is_strict_design_only_and_disabled(self):
        profile = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(profile)
        self.assertEqual(profile["status"], "DESIGN_ONLY")
        self.assertEqual(profile["deployment"], "DISABLED")
        self.assertEqual(profile["allowed_risk"], "LOW")

    def test_profile_is_not_registered_or_wired(self):
        registry = (ROOT / "config/phase2b-profile-registry.yaml").read_text(encoding="utf-8")
        self.assertNotIn("forgewarden_low_risk_unattended_v1", registry)
        self.assertFalse((ROOT / "swarm/phase4_unattended.py").exists())

    def test_design_requires_prerequisites_worker_and_rollback(self):
        note = NOTE.read_text(encoding="utf-8").lower()
        for required in ("connection/replay", "supervised persistent-worker", "human-approved deployment", "rollback", "kill switch", "health timeout", "audit failure"):
            self.assertIn(required, note)


if __name__ == "__main__":
    import unittest
    unittest.main()
