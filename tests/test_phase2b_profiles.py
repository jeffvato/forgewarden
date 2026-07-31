import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from swarm.core import SwarmError
from swarm.phase2b_profiles import CANDIDATE_A, CANDIDATE_A_SCHEMA, load_design_profile, load_registered_candidate


class CandidateAProfileTests(TestCase):
    def test_candidate_a_is_strict_registered_fixture_contract(self):
        profile = load_registered_candidate()
        self.assertEqual(profile["status"], "REGISTERED_DRY_RUN")
        self.assertEqual(profile["deployment"], "forbidden")

    def test_candidate_a_contract_is_fixture_only(self):
        profile = load_design_profile()
        self.assertEqual(profile["profile_id"], "console_asset_safety_dry_run_v1")
        self.assertEqual(profile["status"], "REGISTERED_DRY_RUN")
        self.assertEqual(profile["deployment"], "forbidden")
        self.assertEqual(profile["limits"]["network"], "blocked_except_controlled_adapters")
        self.assertEqual(profile["synthetic_defect"]["sha256"], "PENDING_DISPOSABLE_FIXTURE")

    def test_candidate_a_rejects_profile_mutation(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            profile = dict(load_design_profile())
            profile["profile_id"] = "csv_deadline_dry_run_v1"
            path = root / "profile.yaml"
            import yaml
            path.write_text(yaml.safe_dump(profile), encoding="utf-8")
            with self.assertRaises(SwarmError):
                load_design_profile(path)

    def test_candidate_a_rejects_symlinked_profile_and_schema(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            profile_link = root / "profile.yaml"
            profile_link.symlink_to(CANDIDATE_A)
            with self.assertRaises(SwarmError):
                load_design_profile(profile_link)
            schema_link = root / "schema.json"
            schema_link.symlink_to(CANDIDATE_A_SCHEMA)
            with self.assertRaises(SwarmError):
                load_design_profile(CANDIDATE_A, schema_link)

    def test_candidate_a_rejects_activation_status(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            profile = dict(load_design_profile())
            profile["status"] = "REGISTERED"
            path = root / "profile.yaml"
            import yaml
            path.write_text(yaml.safe_dump(profile), encoding="utf-8")
            with self.assertRaises(SwarmError):
                load_design_profile(path)
