import json
import sys
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from swarm.core import Job, Orchestrator


class CandidateBAuditReviewProfileTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="phase2b-audit-fixture-"))
        self.repo = self.root / "repo"
        (self.repo / "swarm").mkdir(parents=True)
        (self.repo / "swarm/__init__.py").write_text("", encoding="utf-8")
        (self.repo / "tests/swarm_regressions").mkdir(parents=True)
        (self.repo / "audit").mkdir()
        (self.repo / "audit/events.jsonl").write_text(
            '{"job_id":"audit-job","type":"completed","state":"SUCCEEDED","commit":"a"}\n',
            encoding="utf-8",
        )
        (self.repo / "audit/replayed.jsonl").write_text(
            '{"job_id":"audit-job","type":"completed","state":"SUCCEEDED","commit":"a"}\n'
            '{"job_id":"audit-job","type":"completed","state":"SUCCEEDED","commit":"a"}\n',
            encoding="utf-8",
        )
        (self.repo / "audit/malformed.jsonl").write_text(
            '{"job_id":"audit-job","type":"completed","state":"SUCCEEDED"}\n',
            encoding="utf-8",
        )
        (self.repo / "audit/private.jsonl").write_text("synthetic-private-audit\n", encoding="utf-8")
        (self.repo / "audit/linked.jsonl").symlink_to(Path("private.jsonl"))
        (self.repo / "swarm/audit_consumer.py").write_text(
            "import json\n"
            "from pathlib import Path\n\n"
            "def consume_completion(path: Path, expected_job_id: str) -> dict:\n"
            "    event = json.loads(path.read_text(encoding='utf-8').splitlines()[-1])\n"
            "    if event.get('job_id') != expected_job_id:\n"
            "        raise ValueError('unexpected audit job')\n"
            "    return event\n",
            encoding="utf-8",
        )
        (self.repo / "tests/swarm_regressions/test_audit_review_contract.py").write_text(
            "import sys\n"
            "from pathlib import Path\n"
            "sys.path.insert(0, str(Path(__file__).resolve().parents[2]))\n"
            "import pytest\n"
            "from swarm.audit_consumer import consume_completion\n\n"
            "ROOT = Path('audit')\n\n"
            "def test_malformed_completion_is_rejected():\n"
            "    with pytest.raises(ValueError, match='malformed completion'):\n"
            "        consume_completion(ROOT / 'malformed.jsonl', 'audit-job')\n\n"
            "def test_replayed_completion_is_rejected():\n"
            "    with pytest.raises(ValueError, match='replayed completion'):\n"
            "        consume_completion(ROOT / 'replayed.jsonl', 'audit-job')\n\n"
            "def test_symlinked_audit_input_is_rejected():\n"
            "    with pytest.raises(ValueError, match='symlinked audit'):\n"
            "        consume_completion(ROOT / 'linked.jsonl', 'audit-job')\n\n"
            "def test_valid_completion_is_accepted():\n"
            "    assert consume_completion(ROOT / 'events.jsonl', 'audit-job')['state'] == 'SUCCEEDED'\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.repo, check=True)
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "baseline"], cwd=self.repo, check=True)
        self.codex = self.root / "fake-codex.py"
        self.codex.write_text(
            "import json, pathlib, subprocess\n"
            "path = pathlib.Path('swarm/audit_consumer.py')\n"
            "path.write_text(\"import json\\nfrom pathlib import Path\\n\\ndef consume_completion(path: Path, expected_job_id: str) -> dict:\\n    if path.is_symlink():\\n        raise ValueError('symlinked audit input')\\n    events = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]\\n    if len(events) > 1:\\n        raise ValueError('replayed completion')\\n    if len(events) != 1 or events[0].get('type') != 'completed' or not events[0].get('commit'):\\n        raise ValueError('malformed completion')\\n    event = events[0]\\n    if event.get('job_id') != expected_job_id:\\n        raise ValueError('unexpected audit job')\\n    return event\\n\")\n"
            "subprocess.run(['git','add','swarm/audit_consumer.py'], check=True)\n"
            "subprocess.run(['git','-c','user.name=codex','-c','user.email=codex@example.test','commit','-qm','harden audit completion consumer'], check=True)\n"
            "pathlib.Path('.swarm').mkdir()\n"
            "json.dump({'job_id':'candidate-b-job','status':'FIXED','root_cause':'consumer accepted malformed completion events','summary':'fail closed on malformed, replayed, and symlinked audit input','changed_files':['swarm/audit_consumer.py'],'tests_added_or_changed':[],'commands_run':[{'command':'pytest','exit_code':0}],'remaining_risks':[],'requires_human_approval':False}, open('.swarm/codex-result.json','w'))\n",
            encoding="utf-8",
        )
        self.gemini = self.root / "fake-gemini.py"
        self.gemini.write_text(
            "import json, os, pathlib\n"
            "pathlib.Path('.swarm').mkdir(exist_ok=True)\n"
            "json.dump({'job_id':'candidate-b-job','reviewed_commit':os.environ['SWARM_REVIEWED_COMMIT'],'verdict':'APPROVE','risk':'LOW','blocking_findings':[],'non_blocking_notes':[],'tests_missing':[],'reasoning_summary':'strict synthetic audit event validation with exact commit binding','proposed_rules':[]}, open('.swarm/gemini-review.json','w'))\n",
            encoding="utf-8",
        )

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_seeded_defect_fails_then_fake_agents_produce_exact_approved_dry_run(self):
        baseline = subprocess.run(
            [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/swarm_regressions/test_audit_review_contract.py"],
            cwd=self.repo, text=True, capture_output=True, check=False,
        )
        self.assertNotEqual(baseline.returncode, 0)
        self.assertIn("malformed completion", baseline.stdout + baseline.stderr)
        result = Orchestrator(self.root / "state").run(
            Job("candidate-b-job", "audit-review", self.repo, "reject malformed audit completion events"),
            [sys.executable, str(self.codex)],
            [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/swarm_regressions/test_audit_review_contract.py"],
            [sys.executable, str(self.gemini)],
        )
        self.assertEqual(result["state"], "SUCCEEDED", result)
        self.assertRegex(result["commit"], r"^[0-9a-f]{40}$")
        self.assertEqual(result["gemini"]["reviewed_commit"], result["commit"])
        self.assertEqual(result["gemini"]["verdict"], "APPROVE")
        self.assertEqual(result["quality_gate"]["decision"], "ALLOW_DRY_RUN")
        self.assertEqual(result["safe_application_plan"]["eligible_finding_ids"], [])
        self.assertFalse((self.repo / "audit/linked.jsonl").resolve() == self.repo / "audit/linked.jsonl")
        print("CANDIDATE_B_EVIDENCE=" + json.dumps({"profile_id": "audit_review_dry_run_v1", "baseline_failure": "malformed completion event was accepted", "repair_commit": result["commit"], "reviewed_commit": result["gemini"]["reviewed_commit"], "changed_files": ["swarm/audit_consumer.py"], "deterministic": "PASSED", "gemini_verdict": result["gemini"]["verdict"], "quality_gate": result["quality_gate"]["decision"], "deployment": "DISABLED", "autonomous_dry_run": "DISABLED", "kill_switch": "ENGAGED", "fixture_disposable": True}), flush=True)

    def test_candidate_b_fixture_is_disposable_and_does_not_touch_source_repo(self):
        self.assertFalse((self.repo / ".git").is_symlink())
        self.assertTrue((self.repo / "audit/linked.jsonl").is_symlink())
        self.assertEqual(subprocess.check_output(["git", "status", "--porcelain"], cwd=self.repo, text=True), "")


if __name__ == "__main__":
    unittest.main()
