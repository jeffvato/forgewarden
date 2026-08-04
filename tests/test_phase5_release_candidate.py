import tempfile
import unittest
from pathlib import Path

from swarm.phase5_release_candidate import build_release_candidate


class Phase5ReleaseCandidateTests(unittest.TestCase):
    def test_candidate_excludes_private_and_generated_content_without_mutating_source(self):
        with tempfile.TemporaryDirectory(prefix="phase5-candidate-source-") as source_temp, tempfile.TemporaryDirectory(prefix="phase5-candidate-dest-") as dest_temp:
            source = Path(source_temp)
            destination = Path(dest_temp) / "candidate"
            (source / "README.md").write_text("Forgewarden\n", encoding="utf-8")
            private = source / "docs" / "n8n-onboarding-report.md"
            private.parent.mkdir()
            private.write_text("customer_data\n", encoding="utf-8")
            generated = source / "__pycache__" / "module.pyc"
            generated.parent.mkdir()
            generated.write_bytes(b"generated")
            before = private.read_bytes()

            result = build_release_candidate(source, destination)

            self.assertEqual(result["publication"], "DISABLED")
            self.assertFalse(result["mutation_performed"])
            self.assertFalse(result["source_tree_mutated"])
            self.assertTrue((destination / "README.md").is_file())
            self.assertFalse((destination / "docs" / "n8n-onboarding-report.md").exists())
            self.assertFalse((destination / "__pycache__").exists())
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
