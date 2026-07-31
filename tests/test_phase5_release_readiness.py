import json
from pathlib import Path
from unittest import TestCase

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "config/phase5-release-readiness.yaml"
SCHEMA = ROOT / "schemas/phase5-release-readiness.schema.json"
NOTE = ROOT / "docs/phase5-release-readiness.md"


class Phase5ReleaseReadinessTests(TestCase):
    def test_release_plan_is_strict_planning_only(self):
        profile = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(profile)
        self.assertEqual(profile["status"], "PLANNING_ONLY")
        self.assertEqual(profile["publication"], "DISABLED")

    def test_plan_has_privacy_reproducibility_and_review_gates(self):
        text = NOTE.read_text(encoding="utf-8").lower()
        for required in ("usernames", "credentials", "machine fingerprints", "lockfiles", "security review", "licensing review", "reproducible-build", "ci", "publication", "remains disabled"):
            self.assertIn(required, text)


if __name__ == "__main__":
    import unittest
    unittest.main()
