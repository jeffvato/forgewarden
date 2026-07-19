import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from swarm.core import DeploymentController, Job, Orchestrator, SwarmError, redact, validate_contract


ROOT = Path(__file__).resolve().parents[1]


class SwarmTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="swarm-fixture-"))
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.repo, check=True)
        (self.repo / "parser.py").write_text("def parse(value):\n    return value.strip()\n", encoding="utf-8")
        (self.repo / "test_parser.py").write_text("from parser import parse\nassert parse(' x ') == 'x'\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "initial"], cwd=self.repo, check=True)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        self.codex = self.scripts / "codex.py"
        self.codex.write_text("""import json, pathlib, subprocess\np=pathlib.Path('parser.py')\np.write_text(p.read_text().replace('return value.strip()', 'return value.strip().lower()'))\npathlib.Path('.swarm').mkdir()\nsubprocess.run(['git','add','parser.py'])\nsubprocess.run(['git','-c','user.name=codex','-c','user.email=codex@example.test','commit','-qm','repair'])\njson.dump({'job_id': 'job-1', 'status':'FIXED','root_cause':'parser omitted normalization','summary':'normalize parser output','changed_files':['parser.py'],'tests_added_or_changed':[],'commands_run':[{'command':'fixture repair','exit_code':0}],'remaining_risks':[],'requires_human_approval':False}, open('.swarm/codex-result.json','w'))\n""", encoding="utf-8")
        self.gemini = self.scripts / "gemini.py"
        self.gemini.write_text("""import json, os, pathlib\npathlib.Path('.swarm').mkdir(exist_ok=True)\njson.dump({'job_id':'job-1','reviewed_commit':os.environ['SWARM_REVIEWED_COMMIT'],'verdict':'APPROVE','risk':'LOW','blocking_findings':[],'non_blocking_notes':[],'tests_missing':[],'reasoning_summary':'fixture patch is narrow and tested','proposed_rules':[]}, open('.swarm/gemini-review.json','w'))\n""", encoding="utf-8")

    def run_job(self, evidence="parser defect"):
        state = self.root / "state"
        return Orchestrator(state).run(Job("job-1", "fixture-parser", self.repo, evidence), ["python3", str(self.codex)], ["python3", "-m", "unittest", "test_parser.py"], ["python3", str(self.gemini)])

    def test_disposable_fixture_dry_run_succeeds(self):
        result = self.run_job()
        self.assertEqual(result["state"], "SUCCEEDED")
        self.assertRegex(result["commit"], r"^[0-9a-f]{40}$")
        self.assertFalse((self.repo / "parser.py").read_text().endswith("lower()\n"))
        self.assertTrue((self.root / "state/audit.jsonl").exists())

    def test_high_risk_requires_jeff(self):
        result = self.run_job("payment checkout issue")
        self.assertEqual(result["state"], "AWAITING_JEFF")

    def test_dirty_repository_is_blocked(self):
        (self.repo / "unrelated.txt").write_text("existing user change", encoding="utf-8")
        with self.assertRaises(SwarmError):
            self.run_job()

    def test_bad_deterministic_check_blocks_model_approval(self):
        result = Orchestrator(self.root / "state-fail").run(Job("job-1", "fixture-parser", self.repo, "parser defect"), ["python3", str(self.codex)], ["python3", "-c", "raise SystemExit(2)"], ["python3", str(self.gemini)])
        self.assertEqual(result["state"], "FAILED")

    def test_schema_rejects_invalid_json_and_stale_review(self):
        with self.assertRaises(SwarmError):
            validate_contract({"job_id": "x"}, "gemini")
        self.gemini.write_text("""import json, pathlib\npathlib.Path('.swarm').mkdir()\njson.dump({'job_id':'job-1','reviewed_commit':'0'*40,'verdict':'APPROVE','risk':'LOW','blocking_findings':[],'non_blocking_notes':[],'tests_missing':[],'reasoning_summary':'stale','proposed_rules':[]}, open('.swarm/gemini-review.json','w'))\n""", encoding="utf-8")
        with self.assertRaises(SwarmError):
            self.run_job()

    def test_deployment_is_mechanically_disabled(self):
        with self.assertRaises(SwarmError):
            DeploymentController().deploy("anything")

    def test_redaction(self):
        self.assertNotIn("supersecret", redact("token=supersecret"))
        self.assertNotIn("4111111111111111", redact("card 4111111111111111"))


if __name__ == "__main__":
    unittest.main()
