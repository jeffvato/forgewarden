import json
import sys
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from swarm.core import Job, Orchestrator, SwarmError


class CandidateAConsoleProfileTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="phase2b-console-fixture-"))
        self.repo = self.root / "repo"
        (self.repo / "swarm").mkdir(parents=True)
        (self.repo / "swarm/__init__.py").write_text("", encoding="utf-8")
        (self.repo / "tests/swarm_regressions").mkdir(parents=True)
        (self.repo / "assets").mkdir()
        (self.repo / "assets/private.txt").write_text("fixture-private-asset\n", encoding="utf-8")
        (self.repo / "assets/logo.svg").symlink_to(Path("private.txt"))
        (self.repo / "swarm/console_asset_loader.py").write_text(
            "from pathlib import Path\n\n"
            "def load_asset(root: Path, name: str) -> str:\n"
            "    return (root / name).read_text(encoding='utf-8')\n",
            encoding="utf-8",
        )
        (self.repo / "tests/swarm_regressions/test_console_asset_safety.py").write_text(
            "import sys\n"
            "from pathlib import Path\n"
            "sys.path.insert(0, str(Path(__file__).resolve().parents[2]))\n"
            "import pytest\n"
            "from swarm.console_asset_loader import load_asset\n\n"
            "def test_symlinked_asset_is_rejected():\n"
            "    with pytest.raises(ValueError, match='symlinked asset'):\n"
            "        load_asset(__import__('pathlib').Path('assets'), 'logo.svg')\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.repo, check=True)
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "baseline"], cwd=self.repo, check=True)
        self.codex = self.root / "fake-codex.py"
        self.codex.write_text(
            "import json, pathlib, subprocess\n"
            "path = pathlib.Path('swarm/console_asset_loader.py')\n"
            "path.write_text(\"from pathlib import Path\\n\\ndef load_asset(root: Path, name: str) -> str:\\n    candidate = root / name\\n    if candidate.is_symlink():\\n        raise ValueError('symlinked asset rejected')\\n    return candidate.read_text(encoding='utf-8')\\n\")\n"
            "pathlib.Path('.swarm').mkdir()\n"
            "subprocess.run(['git','add','swarm/console_asset_loader.py'], check=True)\n"
            "subprocess.run(['git','-c','user.name=codex','-c','user.email=codex@example.test','commit','-qm','repair console asset loader'], check=True)\n"
            "json.dump({'job_id':'candidate-a-job','status':'FIXED','root_cause':'loader followed symlinks','summary':'reject symlinked assets','changed_files':['swarm/console_asset_loader.py'],'tests_added_or_changed':[],'commands_run':[{'command':'pytest','exit_code':0}],'remaining_risks':[],'requires_human_approval':False}, open('.swarm/codex-result.json','w'))\n",
            encoding="utf-8",
        )
        self.gemini = self.root / "fake-gemini.py"
        self.gemini.write_text(
            "import json, os, pathlib\n"
            "pathlib.Path('.swarm').mkdir(exist_ok=True)\n"
            "json.dump({'job_id':'candidate-a-job','reviewed_commit':os.environ['SWARM_REVIEWED_COMMIT'],'verdict':'APPROVE','risk':'LOW','blocking_findings':[],'non_blocking_notes':[],'tests_missing':[],'reasoning_summary':'narrow fixture repair with exact commit binding','proposed_rules':[]}, open('.swarm/gemini-review.json','w'))\n",
            encoding="utf-8",
        )

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_seeded_defect_fails_then_fake_agents_produce_exact_approved_dry_run(self):
        baseline = subprocess.run(
            [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/swarm_regressions/test_console_asset_safety.py"],
            cwd=self.repo,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(baseline.returncode, 0)
        self.assertIn("symlinked asset", baseline.stdout + baseline.stderr)
        result = Orchestrator(self.root / "state").run(
            Job("candidate-a-job", "console-asset-safety", self.repo, "reject symlinked console asset"),
            [sys.executable, str(self.codex)],
            [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/swarm_regressions/test_console_asset_safety.py"],
            [sys.executable, str(self.gemini)],
        )
        self.assertEqual(result["state"], "SUCCEEDED")
        self.assertRegex(result["commit"], r"^[0-9a-f]{40}$")
        self.assertEqual(result["gemini"]["reviewed_commit"], result["commit"])
        self.assertEqual(result["gemini"]["verdict"], "APPROVE")
        self.assertEqual(result["quality_gate"]["decision"], "ALLOW_DRY_RUN")
        self.assertEqual(result["safe_application_plan"]["eligible_finding_ids"], [])
        self.assertFalse((self.repo / "swarm/console_asset_loader.py").read_text(encoding="utf-8").endswith("is_symlink():\\n"))
        print("CANDIDATE_A_EVIDENCE=" + json.dumps({"profile_id": "console_asset_safety_dry_run_v1", "baseline_failure": "symlinked asset was served", "repair_commit": result["commit"], "reviewed_commit": result["gemini"]["reviewed_commit"], "changed_files": ["swarm/console_asset_loader.py"], "deterministic": "PASSED", "gemini_verdict": result["gemini"]["verdict"], "quality_gate": result["quality_gate"]["decision"], "deployment": "DISABLED", "autonomous_dry_run": "DISABLED", "kill_switch": "ENGAGED", "fixture_disposable": True}), flush=True)

    def test_candidate_a_fixture_is_disposable_and_does_not_touch_source_repo(self):
        self.assertFalse((self.repo / ".git").is_symlink())
        self.assertTrue((self.repo / "assets/logo.svg").is_symlink())
        self.assertEqual(subprocess.check_output(["git", "status", "--porcelain"], cwd=self.repo, text=True), "")


if __name__ == "__main__":
    unittest.main()
