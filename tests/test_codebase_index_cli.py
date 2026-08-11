import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from swarm.cli import main


class CodebaseIndexCliTests(unittest.TestCase):
    def run_cli(self, *args):
        output = io.StringIO()
        with patch.object(sys, "argv", ["swarm", *args]), contextlib.redirect_stdout(output):
            self.assertEqual(main(), 0)
        return json.loads(output.getvalue())

    def test_build_query_and_delete_are_explicit_and_read_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "checkout"
            storage = Path(temp) / "index.json"
            root.mkdir()
            (root / "module.py").write_text("def answer(): return 42\n", encoding="utf-8")
            built = self.run_cli("codebase-index-build", "--repository", str(root), "--index-path", str(storage), "--revision", "abc123")
            self.assertEqual(built["entries"], 1)
            queried = self.run_cli("codebase-index-query", "--repository", str(root), "--index-path", str(storage), "--revision", "abc123", "--term", "answer", "--actor", "tester")
            self.assertEqual(queried["results"][0]["path"], "module.py")
            deleted = self.run_cli("codebase-index-delete", "--repository", str(root), "--index-path", str(storage), "--revision", "abc123", "--actor", "tester")
            self.assertEqual(deleted["state"], "DELETED")
            self.assertFalse(storage.exists())
