import json
from pathlib import Path
from unittest import TestCase

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "config/phase2b-audit-review-profile.yaml"
SCHEMA = ROOT / "schemas/phase2b-audit-review-profile.schema.json"
NOTE = ROOT / "docs/phase2b-audit-review-design.md"
EVIDENCE = ROOT / "docs/phase2b-audit-review-evidence.json"
EVIDENCE_SCHEMA = ROOT / "schemas/phase2b-audit-review-evidence.schema.json"


class CandidateBDesignTests(TestCase):
    def test_profile_is_strict_design_only_and_not_registered(self):
        profile = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(profile)
        self.assertEqual(profile["status"], "REGISTERED_DRY_RUN")
        self.assertEqual(profile["deployment"], "forbidden")
        registry = (ROOT / "config/phase2b-profile-registry.yaml").read_text(encoding="utf-8")
        self.assertIn("audit_review_dry_run_v1", registry)

    def test_scope_and_limits_are_fixed(self):
        profile = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
        self.assertEqual(profile["writable"], ["swarm/audit_consumer.py", "tests/swarm_regressions/"])
        self.assertEqual(profile["limits"]["max_concurrent_jobs"], 1)
        self.assertEqual(profile["limits"]["memory_swap_bytes"], 0)
        self.assertFalse(profile["limits"]["symlinks"])
        self.assertEqual(profile["limits"]["network"], "blocked_except_controlled_adapters")

    def test_design_artifacts_are_secret_free_and_threat_model_complete(self):
        forbidden = ("token=", "password=", "api_key=", "begin private key", "customer_email")
        for path in (PROFILE, SCHEMA, NOTE):
            text = path.read_text(encoding="utf-8").lower()
            for term in forbidden:
                self.assertNotIn(term, text, path.name)
        note = NOTE.read_text(encoding="utf-8")
        for required in ("Malformed event acceptance", "Replay acceptance", "Symlink or path escape", "Secret leakage", "Scope expansion", "Resource abuse", "Reviewer confusion", "## Rollback"):
            self.assertIn(required, note)

    def test_fixture_evidence_is_sanitized_and_not_admission(self):
        evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        schema = json.loads(EVIDENCE_SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(evidence)
        self.assertEqual(evidence["repair_commit"], "06a22f1c431867cede1265bae7edf706e5a5ae04")
        self.assertEqual(evidence["reviewed_commit"], evidence["repair_commit"])
        self.assertIn("audit_review_dry_run_v1", (ROOT / "config/phase2b-profile-registry.yaml").read_text(encoding="utf-8"))


if __name__ == "__main__":
    import unittest
    unittest.main()
