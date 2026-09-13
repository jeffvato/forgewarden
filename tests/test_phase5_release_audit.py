import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from swarm.phase5_release_audit import _LIMITS, HistoryReleaseAudit, ReleaseAudit


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
            fixture.write_text("temporary clean revision\n", encoding="utf-8")
            self.git(root, "commit", "-am", "replace historical fixture")
            fixture.write_text(f'token = "{matched_value}"\n', encoding="utf-8")
            self.git(root, "commit", "-am", "repeat historical fixture")
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

    def test_content_batches_split_in_stable_object_order(self):
        blob_size = _LIMITS["blob_bytes"]
        object_ids = [f"{index:040x}" for index in range(1, 6)]
        sizes = {oid: blob_size for oid in reversed(object_ids)}
        with tempfile.TemporaryDirectory(prefix="phase5-batch-order-") as temp:
            audit = HistoryReleaseAudit(Path(temp))
            calls = []
            audit._read_blob_batch = lambda batch: calls.append(list(batch)) or {}
            list(audit._content_batches(sizes))
        self.assertEqual(calls, [object_ids[:4], object_ids[4:]])

    def test_per_batch_and_overall_blob_ceilings_fail_closed(self):
        blob_size = _LIMITS["blob_bytes"]
        batch_count = _LIMITS["batch_blob_bytes"] // blob_size + 1
        batch = {f"{index:040x}": blob_size for index in range(batch_count)}
        total_count = _LIMITS["total_blob_bytes"] // blob_size + 1
        total = {f"{index:040x}": blob_size for index in range(total_count)}
        with tempfile.TemporaryDirectory(prefix="phase5-blob-ceilings-") as temp:
            audit = HistoryReleaseAudit(Path(temp))
            with self.assertRaisesRegex(ValueError, "blob batch budget exceeded"):
                audit._read_blob_batch(batch)
            with self.assertRaisesRegex(ValueError, "aggregate blob budget exceeded"):
                list(audit._content_batches(total))

    def test_malformed_blob_data_in_later_batch_fails_closed(self):
        first, second = "1" * 40, "2" * 40
        valid = f"{first} blob 3\nabc\n".encode()
        responses = iter((valid, b"unexpected-line\n"))
        with tempfile.TemporaryDirectory(prefix="phase5-malformed-batch-") as temp:
            audit = HistoryReleaseAudit(Path(temp))
            audit._git = lambda *args, **kwargs: next(responses)
            with patch.dict(_LIMITS, {"blob_bytes": 4, "batch_blob_bytes": 4,
                                      "total_blob_bytes": 10}):
                batches = audit._content_batches({second: 3, first: 3})
                self.assertEqual(next(batches), {first: b"abc"})
                with self.assertRaisesRegex(ValueError, "malformed blob data"):
                    next(batches)

    def test_provenance_maps_earliest_duplicate_with_one_fixed_git_pass(self):
        commits = ("a" * 40, "b" * 40, "c" * 40)
        blob, other, zeros = "d" * 40, "e" * 40, "0" * 40
        raw = (
            f"commit:{commits[0]}\n\n"
            f":000000 100644 {zeros} {blob} A\tpath.txt\n"
            f"commit:{commits[1]}\n\n"
            f":100644 100644 {blob} {other} M\tpath.txt\n"
            f"commit:{commits[2]}\n\n"
            f":100644 100644 {other} {blob} M\tpath.txt\n"
        ).encode()
        with tempfile.TemporaryDirectory(prefix="phase5-provenance-") as temp:
            audit = HistoryReleaseAudit(Path(temp))
            calls = []
            audit._git = lambda *args, **kwargs: calls.append(args) or raw
            result = audit._provenance({(blob, "path.txt")}, set(commits))
        self.assertEqual(result, {(blob, "path.txt"): commits[0]})
        self.assertEqual(calls, [(
            "log", "--all", "--reverse", "--root", "-m", "--raw",
            "--no-abbrev", "--no-renames", "--format=commit:%H",
        )])

    def test_provenance_missing_and_malformed_data_fail_closed(self):
        commit, blob = "a" * 40, "b" * 40
        with tempfile.TemporaryDirectory(prefix="phase5-provenance-failure-") as temp:
            audit = HistoryReleaseAudit(Path(temp))
            audit._git = lambda *args, **kwargs: f"commit:{commit}\n".encode()
            with self.assertRaisesRegex(ValueError, "could not bind"):
                audit._provenance({(blob, "path.txt")}, {commit})
            audit._git = lambda *args, **kwargs: (
                f"commit:{commit}\nunexpected raw output\n".encode())
            with self.assertRaisesRegex(ValueError, "malformed provenance"):
                audit._provenance({(blob, "path.txt")}, {commit})

    def test_git_output_and_overall_scan_time_are_bounded(self):
        completed = subprocess.CompletedProcess([], 0, b"12345", b"")
        with tempfile.TemporaryDirectory(prefix="phase5-operation-bounds-") as temp:
            audit = HistoryReleaseAudit(Path(temp))
            with patch.dict(_LIMITS, {"git_output": 4}), patch(
                "swarm.phase5_release_audit.subprocess.run", return_value=completed
            ):
                with self.assertRaisesRegex(ValueError, "Git operation failed"):
                    audit._git("status")
            audit._deadline = 0.0
            with patch("swarm.phase5_release_audit.subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "scan deadline exceeded"):
                    audit._git("status")
                run.assert_not_called()

    def test_repo_above_old_aggregate_limit_scans_in_bounded_batches(self):
        with tempfile.TemporaryDirectory(prefix="phase5-batched-repo-") as temp:
            root = Path(temp)
            self.repository(root)
            payloads = root / "payloads"
            payloads.mkdir()
            for index in range(33):
                with (payloads / f"blob-{index:02d}.bin").open("wb") as handle:
                    handle.seek(1024 * 1024)
                    handle.write(bytes((index,)))
            self.git(root, "add", "payloads")
            self.git(root, "commit", "-m", "batched synthetic blobs")
            head = self.git(root, "rev-parse", "HEAD")
            result = HistoryReleaseAudit(root).scan(
                expected_head=head, strategy="PRESERVE_HISTORY")
            self.assertGreaterEqual(result["blobs_scanned"], 33)
            self.assertEqual(result["blocking_finding_count"], 0)
            self.assertFalse(result["matched_values_included"])

    def test_malformed_git_line_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="phase5-malformed-git-") as temp:
            audit = HistoryReleaseAudit(Path(temp))
            audit._git = lambda *args, **kwargs: b"unexpected-line\n"
            with self.assertRaisesRegex(ValueError, "unsafe ref"):
                audit._refs()

    def test_symlinked_repository_root_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="phase5-symlink-root-") as temp:
            root = Path(temp)
            repository = root / "repository"
            link = root / "repository-link"
            repository.mkdir()
            link.symlink_to(repository, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "real directory"):
                HistoryReleaseAudit(link)

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
