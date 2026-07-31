import json
from pathlib import Path
from unittest import TestCase

from swarm.phase2b_profiles import CANDIDATE_A, CANDIDATE_A_SCHEMA, CANDIDATE_B, CANDIDATE_B_SCHEMA, load_design_profile, load_registered_candidate, load_registered_candidate_b


ROOT = Path(__file__).resolve().parents[1]


class CandidateAAdmissionTests(TestCase):
    def test_limits_are_fixed_and_fail_closed(self):
        profile = load_design_profile()
        limits = profile["limits"]
        self.assertEqual(limits["max_concurrent_jobs"], 1)
        self.assertEqual(limits["max_codex_attempts"], 1)
        self.assertEqual(limits["max_gemini_attempts"], 2)
        self.assertEqual(limits["memory_bytes"], 2_147_483_648)
        self.assertEqual(limits["memory_swap_bytes"], 0)
        self.assertEqual(limits["cpu_seconds"], 45)
        self.assertEqual(limits["wall_clock_seconds"], 180)
        self.assertEqual(limits["max_log_bytes"], 256_000)
        self.assertFalse(limits["symlinks"])
        self.assertEqual(limits["network"], "blocked_except_controlled_adapters")

    def test_candidate_files_are_secret_free_and_registry_isolated(self):
        paths = [CANDIDATE_A, CANDIDATE_A_SCHEMA, CANDIDATE_B, CANDIDATE_B_SCHEMA, ROOT / "swarm/phase2b_profiles.py"]
        forbidden = ("token=", "password=", "api_key=", "BEGIN PRIVATE KEY", "customer_email")
        for path in paths:
            text = path.read_text(encoding="utf-8").lower()
            for term in forbidden:
                self.assertNotIn(term.lower(), text, path.name)
        registry = (ROOT / "config/phase2b-profile-registry.yaml").read_text(encoding="utf-8")
        self.assertIn("console_asset_safety_dry_run_v1", registry)
        self.assertEqual(load_registered_candidate()["status"], "REGISTERED_DRY_RUN")
        self.assertEqual(load_registered_candidate_b()["status"], "REGISTERED_DRY_RUN")
        self.assertIn("audit_review_dry_run_v1", registry)
        phase2a_registry = (ROOT / "config/desktop-job-profiles.yaml").read_text(encoding="utf-8")
        self.assertNotIn("console_asset_safety_dry_run_v1", phase2a_registry)

    def test_rollback_note_is_present_and_scope_bounded(self):
        note = (ROOT / "docs/phase2b-console-asset-safety-review.md").read_text(encoding="utf-8")
        self.assertIn("## Rollback", note)
        self.assertIn("registered fixture-only", note)
        self.assertIn("protected repository", note)
        self.assertIn("systemd unit", note)

    def test_schema_is_strict_and_registered_status_is_fixture_only(self):
        schema = json.loads(CANDIDATE_A_SCHEMA.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["status"]["const"], "REGISTERED_DRY_RUN")
        b_schema = json.loads(CANDIDATE_B_SCHEMA.read_text(encoding="utf-8"))
        self.assertFalse(b_schema["additionalProperties"])
        self.assertEqual(b_schema["properties"]["status"]["const"], "REGISTERED_DRY_RUN")


if __name__ == "__main__":
    import unittest
    unittest.main()
