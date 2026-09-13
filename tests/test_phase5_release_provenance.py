import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from jsonschema import Draft202012Validator, ValidationError

import swarm.phase5_release_provenance as provenance_module
from swarm.phase5_release_candidate import build_release_candidate
from swarm.phase5_release_provenance import (
    _load_policy,
    _scan_file,
    build_release_provenance,
)


ROOT = Path(__file__).resolve().parents[1]


class Phase5ReleaseProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        cls.export_policy = yaml.safe_load(
            (ROOT / "config/phase5-public-export.yaml").read_text(encoding="utf-8"))

    def candidate(self, parent: Path, track: str) -> tuple[Path, str]:
        destination = parent / track
        build_release_candidate(
            ROOT, destination, track=track, expected_source_commit=self.head)
        manifest = destination / self.export_policy["manifest_name"]
        return destination, hashlib.sha256(manifest.read_bytes()).hexdigest()

    def test_policy_is_exact_fail_closed_and_license_unselected(self):
        policy = _load_policy()
        schema = json.loads(
            (ROOT / "schemas/phase5-release-provenance.schema.json").read_text(
                encoding="utf-8"))
        Draft202012Validator(schema).validate(policy)
        self.assertEqual(policy["publication"], "DISABLED")
        self.assertEqual(policy["license_concluded"], "NOASSERTION")
        self.assertEqual(policy["license_declared"], "NOASSERTION")
        self.assertFalse(policy["production_ready"])
        self.assertEqual(set(policy["tracks"]), {"PUBLIC_SDK", "SOURCE_AVAILABLE_DEMO"})

    def test_real_tracks_have_offline_dependency_closure(self):
        with tempfile.TemporaryDirectory(prefix="phase5-provenance-") as temp:
            for track in ("PUBLIC_SDK", "SOURCE_AVAILABLE_DEMO"):
                candidate, manifest_digest = self.candidate(Path(temp), track)
                first = build_release_provenance(
                    candidate, expected_track=track, expected_source_commit=self.head,
                    expected_manifest_sha256=manifest_digest)
                second = build_release_provenance(
                    candidate, expected_track=track, expected_source_commit=self.head,
                    expected_manifest_sha256=manifest_digest)
                self.assertEqual(first, second)
                self.assertEqual(first["dependency_closure"], "VERIFIED_OFFLINE")
                self.assertEqual(first["unresolved_dependencies"], [])
                self.assertEqual(first["publication"], "DISABLED")
                self.assertFalse(first["production_ready"])
                self.assertEqual({item["path"] for item in first["files"]}, {
                    item["path"] for item in json.loads(
                        (candidate / self.export_policy["manifest_name"]).read_text(
                            encoding="utf-8"))["files"]})
                self.assertTrue(all(item["license_concluded"] == "NOASSERTION"
                                    for item in first["files"] + first["references"]))
                self.assertTrue(all(value is False for value in first["safety"].values()))
                encoded = json.dumps(first, sort_keys=True)
                self.assertNotIn(self.head, encoded)
                self.assertNotIn("source_commit", first)
                self.assertFalse(first["matched_values_included"])

    def test_sdk_is_explicitly_documentation_and_schema_only(self):
        with tempfile.TemporaryDirectory(prefix="phase5-sdk-provenance-") as temp:
            candidate, digest = self.candidate(Path(temp), "PUBLIC_SDK")
            result = build_release_provenance(
                candidate, expected_track="PUBLIC_SDK", expected_source_commit=self.head,
                expected_manifest_sha256=digest)
        self.assertEqual(result["standalone_class"], "DOCUMENTATION_AND_SCHEMA_ONLY")
        self.assertEqual({item["classification"] for item in result["references"]}, {
            "NON_LOADING_SCHEMA_IDENTIFIER"})
        self.assertNotIn("swarm.addon_sdk", json.dumps(result))

    def test_demo_classifies_local_stdlib_and_optional_api_references(self):
        with tempfile.TemporaryDirectory(prefix="phase5-demo-provenance-") as temp:
            candidate, digest = self.candidate(Path(temp), "SOURCE_AVAILABLE_DEMO")
            result = build_release_provenance(
                candidate, expected_track="SOURCE_AVAILABLE_DEMO",
                expected_source_commit=self.head, expected_manifest_sha256=digest)
        classes = {item["classification"] for item in result["references"]}
        self.assertEqual(classes, {
            "STANDARD_LIBRARY", "LOCAL_INCLUDED", "DECLARED_OPTIONAL_API_INTERFACE"})
        self.assertIn("console/demo-data.json", {item["target"] for item in result["references"]})
        self.assertEqual(
            {item["target"] for item in result["references"]
             if item["classification"] == "DECLARED_OPTIONAL_API_INTERFACE"},
            {"/api/mission-control", "/api/status", "/api/canonical-activity",
             "/api/capability-status"},
        )

    def test_manifest_digest_commit_track_and_policy_bindings_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="phase5-binding-denial-") as temp:
            candidate, digest = self.candidate(Path(temp), "PUBLIC_SDK")
            cases = (
                {"expected_manifest_sha256": "0" * 64},
                {"expected_source_commit": "0" * 40},
                {"expected_track": "SOURCE_AVAILABLE_DEMO"},
            )
            for changes in cases:
                values = {
                    "expected_track": "PUBLIC_SDK",
                    "expected_source_commit": self.head,
                    "expected_manifest_sha256": digest,
                    **changes,
                }
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    build_release_provenance(candidate, **values)

    def test_tampered_extra_symlink_and_manifest_shape_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="phase5-candidate-denial-") as temp:
            parent = Path(temp)
            candidate, digest = self.candidate(parent, "PUBLIC_SDK")
            (candidate / "docs/add-on-sdk.md").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "digest"):
                build_release_provenance(
                    candidate, expected_track="PUBLIC_SDK", expected_source_commit=self.head,
                    expected_manifest_sha256=digest)

            candidate, digest = self.candidate(parent, "SOURCE_AVAILABLE_DEMO")
            (candidate / "extra.txt").write_text("extra\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "extra"):
                build_release_provenance(
                    candidate, expected_track="SOURCE_AVAILABLE_DEMO",
                    expected_source_commit=self.head, expected_manifest_sha256=digest)

        with tempfile.TemporaryDirectory(prefix="phase5-link-denial-") as temp:
            candidate, digest = self.candidate(Path(temp), "PUBLIC_SDK")
            target = candidate / "docs/add-on-sdk.md"
            target.unlink()
            target.symlink_to(candidate / "schemas/addon-manifest.schema.json")
            with self.assertRaisesRegex(ValueError, "regular"):
                build_release_provenance(
                    candidate, expected_track="PUBLIC_SDK", expected_source_commit=self.head,
                    expected_manifest_sha256=digest)

        with tempfile.TemporaryDirectory(prefix="phase5-manifest-shape-") as temp:
            candidate, _ = self.candidate(Path(temp), "PUBLIC_SDK")
            manifest_path = candidate / self.export_policy["manifest_name"]
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["source_commit"] = self.head
            raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
            manifest_path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "shape"):
                build_release_provenance(
                    candidate, expected_track="PUBLIC_SDK", expected_source_commit=self.head,
                    expected_manifest_sha256=hashlib.sha256(raw).hexdigest())

    def test_python_markdown_javascript_html_css_and_schema_attacks_deny(self):
        policy = _load_policy()
        demo = policy["tracks"]["SOURCE_AVAILABLE_DEMO"]
        sdk = policy["tracks"]["PUBLIC_SDK"]
        included = set(demo["file_roles"])
        schema_ids = set(policy["allowed_schema_identifiers"])
        cases = (
            ("bad.py", b"import subprocess\n", demo),
            ("bad.py", b"from .local import value\n", demo),
            ("bad.py", b"eval('1')\n", demo),
            ("bad.md", b"```python\nimport swarm\n```\n", sdk),
            ("bad.js", b"fetch('https://outside.invalid/x')", demo),
            ("bad.js", b"fetch(target)", demo),
            ("bad.js", b"import('./plugin.js')", demo),
            ("bad.html", b'<script src="/missing.js"></script>', demo),
            ("bad.html", b'<script>fetch("/demo-data.json")</script>', demo),
            ("bad.css", b'@import "missing.css";', demo),
            ("bad.json", b'{"$ref":"https://outside.invalid/schema"}', sdk),
            ("bad.json", b'{"$schema":"https://outside.invalid/schema"}', sdk),
            ("bad.json", b'{"value":NaN}', sdk),
        )
        for source, data, track_policy in cases:
            with self.subTest(source=source, data=data), self.assertRaises(ValueError):
                _scan_file(
                    source, data, track_policy=track_policy, included=included,
                    allowed_schema_identifiers=schema_ids)

    def test_policy_drift_is_rejected_by_exact_schema(self):
        policy = yaml.safe_load(
            (ROOT / "config/phase5-release-provenance.yaml").read_text(encoding="utf-8"))
        policy["publication"] = "ENABLED"
        with tempfile.TemporaryDirectory(prefix="phase5-provenance-policy-") as temp:
            changed = Path(temp) / "policy.yaml"
            changed.write_text(yaml.safe_dump(policy), encoding="utf-8")
            with mock.patch.object(provenance_module, "_POLICY", changed):
                with self.assertRaises(ValidationError):
                    _load_policy()

    def test_implementation_has_no_network_package_git_or_provider_executor(self):
        source = (ROOT / "swarm/phase5_release_provenance.py").read_text(encoding="utf-8")
        for forbidden in (
            "subprocess", "requests", "urllib", "socket", "pip ", "npm ",
            "git push", "create_remote", "api_key", "access_token",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
