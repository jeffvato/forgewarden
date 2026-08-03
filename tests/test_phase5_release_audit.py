import json
import tempfile
import unittest
from pathlib import Path

from swarm.phase5_release_audit import ReleaseAudit


class Phase5ReleaseAuditTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
