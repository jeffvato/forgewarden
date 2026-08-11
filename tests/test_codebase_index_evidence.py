import json
import tempfile
import unittest
from pathlib import Path

from codebase_index_evidence import build_index_evidence
from swarm.codebase_index import CodebaseIndex


class CodebaseIndexEvidenceTests(unittest.TestCase):
    def test_evidence_binds_finding_files_to_revision(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            source = root / "module.py"
            source.write_text("def answer(): return 42\n", encoding="utf-8")
            index_path = Path(temp) / "index.json"
            CodebaseIndex(root, index_path).build("rev-1")
            report = Path(temp) / "report.json"
            report.write_text(json.dumps({"findings": [{"file": "module.py"}, {"file": "missing.py"}]}), encoding="utf-8")
            evidence = build_index_evidence(report, root, index_path, "rev-1", "reviewer")
            self.assertEqual(evidence["matched_files"], ["module.py"])
            self.assertEqual(evidence["missing_files"], ["missing.py"])
            self.assertEqual(evidence["revision"], "rev-1")
