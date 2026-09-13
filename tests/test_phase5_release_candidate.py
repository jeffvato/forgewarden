import json
import tempfile
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from swarm.phase5_release_candidate import (
    _head, _load_contract, _normalize_allowlist, _tracked_blob,
    build_release_candidate,
)


ROOT = Path(__file__).resolve().parents[1]


class Phase5PublicExportPolicyTests(unittest.TestCase):
    def test_exact_public_tracks_are_allowlisted_and_private_core_is_excluded(self):
        policy = yaml.safe_load(
            (ROOT / "config/phase5-public-export.yaml").read_text(encoding="utf-8"))
        schema = json.loads(
            (ROOT / "schemas/phase5-public-export.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(policy)
        self.assertEqual(policy["publication"], "DISABLED")
        self.assertEqual(set(policy["tracks"]), {"PUBLIC_SDK", "SOURCE_AVAILABLE_DEMO"})
        for track in policy["tracks"].values():
            self.assertEqual(track["source_scope"], "EXPLICIT_ALLOWLIST_ONLY")
            self.assertFalse(track["includes_private_core"])
            self.assertTrue(track["allowlist"])
        self.assertIn("PRIVATE_CORE", policy["required_denials"])
        self.assertIn("UNLISTED_FILES", policy["required_denials"])

    def test_export_admission_helpers_bind_policy_paths_and_git(self):
        _, policy, paths = _load_contract("PUBLIC_SDK")
        self.assertEqual(paths, sorted(policy["tracks"]["PUBLIC_SDK"]["allowlist"]))
        head = _head(ROOT)
        self.assertTrue(_tracked_blob(ROOT, head, paths[0]))
        for unsafe in (["../escape.py"], ["docs/a.md", "DOCS/A.MD"], []):
            with self.assertRaises(ValueError):
                _normalize_allowlist(unsafe, policy["limits"])


class Phase5ReleaseCandidateTests(unittest.TestCase):
    def test_candidate_excludes_private_and_generated_content_without_mutating_source(self):
        with tempfile.TemporaryDirectory(prefix="phase5-candidate-source-") as source_temp, tempfile.TemporaryDirectory(prefix="phase5-candidate-dest-") as dest_temp:
            source = Path(source_temp)
            destination = Path(dest_temp) / "candidate"
            (source / "README.md").write_text("Forgewarden\n", encoding="utf-8")
            private = source / "docs" / "n8n-onboarding-report.md"
            ambiguous = source / "config" / "hermes-profile.yaml"
            private.parent.mkdir()
            ambiguous.parent.mkdir()
            private.write_text("customer_data\n", encoding="utf-8")
            ambiguous.write_text("/home/jeff\n", encoding="utf-8")
            generated = source / "__pycache__" / "module.pyc"
            generated.parent.mkdir()
            generated.write_bytes(b"generated")
            metadata = source / "README.md:Zone.Identifier"
            metadata.write_text("Zone.Identifier\n", encoding="utf-8")
            before = private.read_bytes()

            result = build_release_candidate(source, destination)

            self.assertEqual(result["publication"], "DISABLED")
            self.assertFalse(result["mutation_performed"])
            self.assertFalse(result["source_tree_mutated"])
            self.assertTrue((destination / "README.md").is_file())
            self.assertTrue((destination / "docs" / "install.md").is_file())
            self.assertTrue((destination / "docs" / "reproducibility.md").is_file())
            self.assertTrue((destination / "requirements.lock").is_file())
            self.assertFalse((destination / "docs" / "n8n-onboarding-report.md").exists())
            self.assertFalse((destination / "config" / "hermes-profile.yaml").exists())
            self.assertFalse((destination / "__pycache__").exists())
            self.assertFalse((destination / "README.md:Zone.Identifier").exists())
            self.assertEqual(private.read_bytes(), before)

    def test_candidate_refuses_existing_destination(self):
        with tempfile.TemporaryDirectory(prefix="phase5-candidate-source-") as source_temp, tempfile.TemporaryDirectory(prefix="phase5-candidate-dest-") as dest_temp:
            source = Path(source_temp)
            destination = Path(dest_temp) / "candidate"
            destination.mkdir()
            with self.assertRaises(FileExistsError):
                build_release_candidate(source, destination)


if __name__ == "__main__":
    unittest.main()
