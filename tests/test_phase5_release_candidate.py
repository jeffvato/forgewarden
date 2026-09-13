import json
import subprocess
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
    @classmethod
    def setUpClass(cls):
        cls.head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True,
            text=True, check=True,
        ).stdout.strip()
        cls.policy = yaml.safe_load(
            (ROOT / "config/phase5-public-export.yaml").read_text(encoding="utf-8"))

    def test_real_sdk_and_demo_exports_are_exact_allowlisted_candidates(self):
        before = {path: (ROOT / path).read_bytes()
                  for track in self.policy["tracks"].values() for path in track["allowlist"]}
        with tempfile.TemporaryDirectory(prefix="phase5-public-export-") as temp:
            parent = Path(temp)
            for track_name, track in self.policy["tracks"].items():
                destination = parent / track_name
                result = build_release_candidate(
                    ROOT, destination, track=track_name, expected_source_commit=self.head)
                self.assertEqual((result["publication"], result["source_commit"]),
                                 ("DISABLED", self.head))
                self.assertFalse(result["matched_values_included"])
                self.assertEqual([item["path"] for item in result["files"]],
                                 sorted(track["allowlist"]))
                self.assertEqual(result, json.loads(
                    (destination / self.policy["manifest_name"]).read_text(encoding="utf-8")))
                self.assertFalse((destination / ".git").exists())
                self.assertFalse((destination / "WORK_QUEUE.md").exists())
        self.assertEqual(before, {path: (ROOT / path).read_bytes() for path in before})

    def test_existing_destination_private_track_and_wrong_commit_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="phase5-public-denial-") as temp:
            parent = Path(temp)
            existing = parent / "existing"
            existing.mkdir()
            with self.assertRaises(FileExistsError):
                build_release_candidate(
                    ROOT, existing, track="PUBLIC_SDK", expected_source_commit=self.head)
            with self.assertRaisesRegex(ValueError, "unsupported"):
                build_release_candidate(
                    ROOT, parent / "private", track="PRIVATE_CORE",
                    expected_source_commit=self.head)
            with self.assertRaisesRegex(ValueError, "does not match"):
                build_release_candidate(
                    ROOT, parent / "drift", track="PUBLIC_SDK",
                    expected_source_commit="0" * 40)
            self.assertFalse((parent / "private").exists())
            self.assertFalse((parent / "drift").exists())


if __name__ == "__main__":
    unittest.main()
