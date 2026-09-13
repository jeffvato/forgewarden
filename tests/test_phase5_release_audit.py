import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from swarm.phase5_release_audit import HistoryReleaseAudit, ReleaseAudit


class Phase5ReleaseAuditTests(unittest.TestCase):
    def test_release_audit_wrapper_is_read_only_and_documented(self):
        root = Path(__file__).resolve().parents[1]
        wrapper = root / "packaging/forgewarden-release-audit"
        self.assertTrue(wrapper.is_file())
        self.assertIn("never edits, publishes, deploys, or removes", wrapper.read_text(encoding="utf-8"))

    def test_clean_candidate_has_no_findings_and_does_not_mutate(self):
        with tempfile.TemporaryDirectory(prefix="phase5-clean-") as temp:
            root = Path(temp)
            target = root / "README.md"
            target.write_text("Forgewarden release template\n", encoding="utf-8")
            before = target.read_bytes()
            result = ReleaseAudit(root).scan()
            self.assertTrue(result["clean"])
            self.assertFalse(result["mutation_performed"])
            self.assertEqual(target.read_bytes(), before)

    def test_private_paths_credentials_audits_and_fingerprints_are_reported(self):
        with tempfile.TemporaryDirectory(prefix="phase5-dirty-") as temp:
            root = Path(temp)
            (root / "private.md").write_text("/home/jeff token=SECRET_VALUE audit.jsonl Ubuntu-24.04\n", encoding="utf-8")
            result = ReleaseAudit(root).scan()
            categories = {item["category"] for item in result["findings"]}
            self.assertFalse(result["clean"])
            self.assertTrue({"user_home_path", "credential_assignment", "private_audit", "machine_fingerprint"} <= categories)
            self.assertEqual(result["publication"], "DISABLED")

    def test_symlinked_files_are_not_followed(self):
        with tempfile.TemporaryDirectory(prefix="phase5-symlink-") as temp:
            root = Path(temp)
            outside = root.parent / "phase5-outside-secret.txt"
            outside.write_text("token=SECRET\n", encoding="utf-8")
            (root / "link.md").symlink_to(outside)
            result = ReleaseAudit(root).scan()
            self.assertTrue(result["clean"])
            outside.unlink()

    def test_persisted_repository_result_is_sanitized_and_publication_disabled(self):
        root = Path(__file__).resolve().parents[1]
        result = json.loads((root / "docs/phase5-release-audit-result.json").read_text(encoding="utf-8"))
        schema = json.loads((root / "schemas/phase5-release-audit-result.schema.json").read_text(encoding="utf-8"))
        from jsonschema import Draft202012Validator
        Draft202012Validator(schema).validate(result)
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(result["publication"], "DISABLED")

    def test_inventory_requires_explicit_classification_without_mutating(self):
        with tempfile.TemporaryDirectory(prefix="phase5-inventory-") as temp:
            root = Path(temp)
            target = root / "private.md"
            target.write_text("/home/jeff\n", encoding="utf-8")
            before = target.read_bytes()
            result = ReleaseAudit(root).inventory()
            self.assertFalse(result["clean"])
            self.assertFalse(result["mutation_performed"])
            self.assertEqual(result["publication"], "DISABLED")
            self.assertEqual(result["findings"], [{
                "category": "user_home_path",
                "path": "private.md",
                "ownership": "PROJECT_OWNED",
                "intended_public_status": "REVIEW_REQUIRED",
            }])
            self.assertEqual(target.read_bytes(), before)

    def test_inventory_classifies_only_known_generated_paths(self):
        with tempfile.TemporaryDirectory(prefix="phase5-generated-") as temp:
            root = Path(temp)
            generated = root / ".pytest_cache" / "cache"
            generated.parent.mkdir()
            generated.write_text("/home/jeff\n", encoding="utf-8")
            result = ReleaseAudit(root).inventory()
            self.assertEqual(result["findings"], [{
                "category": "user_home_path",
                "path": ".pytest_cache/cache",
                "ownership": "PROJECT_GENERATED",
                "intended_public_status": "EXCLUDE_FROM_RELEASE",
            }])

    def test_inventory_excludes_the_protected_project_record(self):
        with tempfile.TemporaryDirectory(prefix="phase5-record-") as temp:
            root = Path(temp)
            record = root / "Hermes-Codex-Gemini-Swarm-Master-Project-Record.md"
            record.write_text("/home/jeff\n", encoding="utf-8")
            result = ReleaseAudit(root).inventory()
            self.assertEqual(result["findings"][0]["ownership"], "LOCAL_PROJECT_RECORD")
            self.assertEqual(result["findings"][0]["intended_public_status"], "EXCLUDE_FROM_RELEASE")

    def test_inventory_labels_test_paths_without_clearing_release_review(self):
        with tempfile.TemporaryDirectory(prefix="phase5-test-fixture-") as temp:
            root = Path(temp)
            fixture = root / "tests" / "test_fixture.py"
            fixture.parent.mkdir()
            fixture.write_text("token=synthetic-fixture\n", encoding="utf-8")
            result = ReleaseAudit(root).inventory()
            finding = result["findings"][0]
            self.assertEqual(finding["ownership"], "PROJECT_TEST_FIXTURE")
            self.assertEqual(finding["intended_public_status"], "REVIEW_REQUIRED")

    def test_inventory_excludes_known_private_artifacts_and_backups(self):
        with tempfile.TemporaryDirectory(prefix="phase5-private-") as temp:
            root = Path(temp)
            private_doc = root / "docs" / "n8n-onboarding-report.md"
            backup = root / "notes.md.save"
            private_doc.parent.mkdir()
            private_doc.write_text("customer_data\n", encoding="utf-8")
            backup.write_text("/home/jeff\n", encoding="utf-8")
            result = ReleaseAudit(root).inventory()
            by_path = {item["path"]: item for item in result["findings"]}
            self.assertEqual(by_path["docs/n8n-onboarding-report.md"]["ownership"], "PRIVATE_PROJECT_ARTIFACT")
            self.assertEqual(by_path["docs/n8n-onboarding-report.md"]["intended_public_status"], "EXCLUDE_FROM_RELEASE")
            self.assertEqual(by_path["notes.md.save"]["ownership"], "PRIVATE_PROJECT_ARTIFACT")
            self.assertEqual(by_path["notes.md.save"]["intended_public_status"], "EXCLUDE_FROM_RELEASE")

    def test_cli_release_inventory_is_read_only_json(self):
        with tempfile.TemporaryDirectory(prefix="phase5-cli-") as temp:
            root = Path(temp)
            target = root / "README.md"
            target.write_text("Forgewarden\n", encoding="utf-8")
            before = target.read_bytes()
            result = subprocess.run(
                [sys.executable, "-m", "swarm.cli", "release-inventory", "--repository", str(root)],
                cwd=Path(__file__).resolve().parents[1],
                env={"PYTHONPATH": str(Path(__file__).resolve().parents[1])},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["clean"])
            self.assertEqual(target.read_bytes(), before)

    def test_cli_release_inventory_writes_only_requested_output(self):
        with tempfile.TemporaryDirectory(prefix="phase5-cli-output-") as temp:
            root = Path(temp)
            target = root / "README.md"
            output = root / "inventory.json"
            target.write_text("Forgewarden\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "swarm.cli", "release-inventory", "--repository", str(root), "--output", str(output)],
                cwd=Path(__file__).resolve().parents[1],
                env={"PYTHONPATH": str(Path(__file__).resolve().parents[1])},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertTrue(json.loads(output.read_text(encoding="utf-8"))["clean"])


class Phase5HistoryReleaseAuditTests(unittest.TestCase):
    @staticmethod
    def git(root: Path, *args: str) -> str:
        result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)
        return result.stdout.strip()

    def repository(self, root: Path) -> str:
        self.git(root, "init", "-b", "main")
        self.git(root, "config", "user.name", "Synthetic Reviewer")
        self.git(root, "config", "user.email", "reviewer@example.invalid")
        (root / "README.md").write_text("Synthetic release fixture\n", encoding="utf-8")
        self.git(root, "add", "README.md")
        self.git(root, "commit", "-m", "initial")
        return self.git(root, "rev-parse", "HEAD")

    def test_reachable_removed_secret_ref_tag_and_metadata_are_sanitized(self):
        from jsonschema import Draft202012Validator

        with tempfile.TemporaryDirectory(prefix="phase5-history-") as temp:
            root = Path(temp)
            head = self.repository(root)
            self.git(root, "switch", "-c", "historical-fixture")
            self.git(root, "config", "user.email", "reviewer@private.invalid")
            fixture = root / "fixtures" / "removed.txt"
            fixture.parent.mkdir()
            matched_value = "synthetic-" + "fixture-material"
            fixture.write_text(f'token = "{matched_value}"\n', encoding="utf-8")
            self.git(root, "add", "fixtures/removed.txt")
            self.git(root, "commit", "-m", "historical fixture")
            first_commit = self.git(root, "rev-parse", "HEAD")
            self.git(root, "tag", "retained-history")
            self.git(root, "switch", "main")

            audit = HistoryReleaseAudit(root)
            result = audit.scan(expected_head=head, strategy="PRESERVE_HISTORY")
            schema_root = Path(__file__).resolve().parents[1]
            schema = json.loads(
                (schema_root / "schemas/phase5-release-audit-result.schema.json").read_text())
            Draft202012Validator(schema).validate(result)
            secret = next(item for item in result["findings"]
                          if item["category"] == "credential_material")
            self.assertEqual((secret["scope"], secret["first_commit"]), ("HISTORY_ONLY", first_commit))
            self.assertEqual(result["disposition"], "DENIED")
            self.assertFalse(result["matched_values_included"])
            self.assertNotIn(matched_value, json.dumps(result))
            self.assertIn("identifying_git_identity",
                          {item["category"] for item in result["findings"]})

            sanitized = audit.scan(expected_head=head, strategy="SANITIZED_SINGLE_COMMIT")
            self.assertEqual(sanitized["disposition"], "CANDIDATE_PROOF_REQUIRED")
            self.assertTrue(sanitized["candidate_proof_required"])
            self.assertEqual(result["ref_set_sha256"], sanitized["ref_set_sha256"])
            self.assertEqual(result["policy_sha256"], sanitized["policy_sha256"])

    def test_exact_head_git_and_path_failures_are_closed(self):
        with tempfile.TemporaryDirectory(prefix="phase5-drift-") as temp:
            root = Path(temp)
            old_head = self.repository(root)
            (root / "README.md").write_text("Changed fixture\n", encoding="utf-8")
            self.git(root, "add", "README.md")
            self.git(root, "commit", "-m", "drift")
            with self.assertRaisesRegex(ValueError, "exact candidate"):
                HistoryReleaseAudit(root).scan(expected_head=old_head, strategy="PRESERVE_HISTORY")
        with tempfile.TemporaryDirectory(prefix="phase5-not-git-") as temp:
            with self.assertRaisesRegex(ValueError, "Git operation failed"):
                HistoryReleaseAudit(Path(temp)).scan(
                    expected_head="0" * 40, strategy="PRESERVE_HISTORY")
        for unsafe in ("../escape", "/absolute"):
            with self.assertRaisesRegex(ValueError, "unsafe repository path"):
                HistoryReleaseAudit._path(unsafe)


if __name__ == "__main__":
    unittest.main()
