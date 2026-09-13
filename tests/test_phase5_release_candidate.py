import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from jsonschema import Draft202012Validator

import swarm.phase5_release_candidate as candidate_module
from swarm.phase5_release_candidate import (
    _head, _load_contract, _normalize_allowlist, _tracked_blob,
    _validate_public_content, _validate_public_path,
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

    def test_policy_drift_is_rejected_by_the_exact_schema(self):
        policy = yaml.safe_load(
            (ROOT / "config/phase5-public-export.yaml").read_text(encoding="utf-8"))
        policy["publication"] = "ENABLED"
        with tempfile.TemporaryDirectory(prefix="phase5-policy-drift-") as temp:
            changed = Path(temp) / "policy.yaml"
            changed.write_text(yaml.safe_dump(policy), encoding="utf-8")
            with mock.patch.object(candidate_module, "_EXPORT_POLICY", changed):
                with self.assertRaises(Exception):
                    _load_contract("PUBLIC_SDK")


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

        with tempfile.TemporaryDirectory(prefix="phase5-repeat-") as temp:
            first = build_release_candidate(
                ROOT, Path(temp) / "one", track="PUBLIC_SDK",
                expected_source_commit=self.head)
            second = build_release_candidate(
                ROOT, Path(temp) / "two", track="PUBLIC_SDK",
                expected_source_commit=self.head)
            self.assertEqual(first, second)

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

    def test_identifier_credential_and_control_content_is_rejected_without_echo(self):
        samples = (
            b'owner="Personal Person"\n', b'user@example.invalid\n', b'/home/example/private\n',
            b'tenant_id="private-tenant-01"\n', b'http://host.internal/private\n',
            b'machine_id="machine-private-01"\n', b'a' * 40 + b'\n',
            b'job_id="private-job-01"\n', b'api_key="synthetic-long-secret"\n',
            b'endpoint_id="private-endpoint-01"\n', b'safe\x00control\n',
        )
        for sample in samples:
            with self.subTest(kind=sample[:12]), self.assertRaisesRegex(ValueError, "prohibited|control") as error:
                _validate_public_content(sample)
            self.assertNotIn(sample.decode("utf-8", errors="ignore").strip(), str(error.exception))
        _validate_public_content(b'tenant_id="TENANT-DEMO-01"\njob_id="JOB-DEMO-01"\n')

    def test_private_generated_review_and_unproven_media_paths_are_rejected(self):
        for path in (
            ".git/config", ".swarm-state/run.json", "tests/test_sdk.py",
            "docs/reviewer-result.json", "docs/private-evidence.json", "assets/logo.png",
        ):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "prohibited"):
                _validate_public_path(Path(path))


if __name__ == "__main__":
    unittest.main()
