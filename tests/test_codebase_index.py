import json
import tempfile
import unittest
from pathlib import Path

from swarm.codebase_index import CodebaseIndex, IndexAccessError, IndexPolicy, IndexPolicyError, StaleIndexError


class CodebaseIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        (self.root / "src").mkdir()
        (self.root / "src/app.py").write_text("def answer(): return 42\n", encoding="utf-8")
        (self.root / "src/copy.py").write_text("def answer(): return 42\n", encoding="utf-8")
        (self.root / ".env").write_text("API_KEY=do-not-index-this\n", encoding="utf-8")
        self.index = CodebaseIndex(self.root, Path(self.temp.name) / "index.json")

    def tearDown(self):
        self.temp.cleanup()

    def test_build_binds_revision_and_hashes_duplicate_content_once_per_path(self):
        result = self.index.build("abc123")
        self.assertEqual(result["entries"], 2)
        document = json.loads(self.index.index_path.read_text(encoding="utf-8"))
        self.assertEqual({entry["path"] for entry in document["entries"]}, {"src/app.py", "src/copy.py"})
        self.assertEqual(document["entries"][0]["file_hash"], document["entries"][1]["file_hash"])

    def test_query_requires_actor_and_is_bounded(self):
        self.index.build("abc123")
        with self.assertRaises(IndexAccessError):
            self.index.query("answer", "abc123", "")
        with self.assertRaises(ValueError):
            self.index.query("answer", "abc123", "tester", limit=51)
        self.assertEqual(len(self.index.query("answer", "abc123", "tester", limit=1)), 1)

    def test_stale_index_fails_closed_or_fresh_scans(self):
        self.index.build("old")
        with self.assertRaises(StaleIndexError):
            self.index.query("answer", "new", "tester", fresh_scan=False)
        self.assertEqual(len(self.index.query("answer", "new", "tester")), 2)

    def test_sensitive_file_and_secret_content_are_not_indexed(self):
        (self.root / "src/token.txt").write_text("client_secret = '123456789012345'\n", encoding="utf-8")
        self.index.build("abc123")
        self.assertEqual(self.index.query("do-not-index-this", "abc123", "tester"), [])
        self.assertEqual(self.index.query("123456789012345", "abc123", "tester"), [])

    def test_symlink_is_rejected_and_delete_is_audited_by_actor_requirement(self):
        (self.root / "linked").symlink_to(self.root / "src", target_is_directory=True)
        with self.assertRaises(IndexPolicyError):
            self.index.build("abc123")
        with self.assertRaises(IndexAccessError):
            self.index.delete("")

    def test_deleted_files_disappear_after_rebuild(self):
        self.index.build("abc123")
        (self.root / "src/app.py").unlink()
        self.index.build("def456")
        results = self.index.query("answer", "def456", "tester")
        self.assertEqual([item["path"] for item in results], ["src/copy.py"])

    def test_policy_rejects_traversal_and_index_is_bound_to_repository(self):
        with self.assertRaises(ValueError):
            IndexPolicy(include=("../*",))
        with self.assertRaises(ValueError):
            CodebaseIndex(self.root, self.root / "index.json")
        self.index.build("abc123")
        other = Path(self.temp.name) / "other"
        other.mkdir()
        (other / "other.py").write_text("different repository\n", encoding="utf-8")
        other_index = CodebaseIndex(other, self.index.index_path)
        with self.assertRaises(StaleIndexError):
            other_index.query("different", "abc123", "tester", fresh_scan=False)

    def test_poisoned_entry_fails_closed(self):
        self.index.build("abc123")
        document = json.loads(self.index.index_path.read_text(encoding="utf-8"))
        document["entries"].append({"path": "../outside.py", "file_hash": "0" * 64, "revision": "abc123", "text": "poison"})
        self.index.index_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(StaleIndexError):
            self.index.query("poison", "abc123", "tester", fresh_scan=False)

    def test_index_storage_symlink_is_rejected(self):
        target = Path(self.temp.name) / "target.json"
        target.write_text("{}", encoding="utf-8")
        link = Path(self.temp.name) / "index-link.json"
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            CodebaseIndex(self.root, link)


if __name__ == "__main__":
    unittest.main()
