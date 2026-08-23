import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from tests.host_fixtures import requires_host_fixture


HERMES = Path("/home/jeff/.local/bin/hermes")
MARKER = "HERMES-SWARM-DISPOSABLE-MARKER-7F4C"


@requires_host_fixture((HERMES,), "installed Hermes profile surface")
class HermesDisposableProfileTests(unittest.TestCase):
    def test_installed_surface_has_no_profile_or_config_subcommand(self):
        result = subprocess.run([str(HERMES), "--help"], text=True, capture_output=True, check=True)
        self.assertNotIn("hermes profile", result.stdout)
        self.assertNotIn("hermes config", result.stdout)

    def test_disposable_wrapper_selects_marker_and_removal_removes_it(self):
        before = hashlib.sha256(HERMES.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory(prefix="hermes-disposable-") as temp:
            root = Path(temp) / "hermes-home"
            (root / "agents").mkdir(parents=True)
            (root / "config").mkdir()
            (root / "review").mkdir()
            (root / "agents/hermes.md").write_text(f"Disposable profile marker: {MARKER}\n", encoding="utf-8")
            (root / "config/policy.yaml").write_text("mode: DRY_RUN\npolicy_marker: SWARM_POLICY_LOADED\n", encoding="utf-8")
            (root / "review/task.md").write_text("Objective: disposable profile proof\n", encoding="utf-8")
            wrapper = Path(temp) / "hermes-disposable"
            text = HERMES.read_text(encoding="utf-8").replace('ROOT="/home/jeff/hermes-sandbox"', f'ROOT="{root}"')
            wrapper.write_text(text, encoding="utf-8")
            wrapper.chmod(0o700)
            rendered = subprocess.run([str(wrapper), "--print-prompt"], text=True, capture_output=True, check=True).stdout
            self.assertIn(MARKER, rendered)
            self.assertIn("SWARM_POLICY_LOADED", rendered)
            self.assertIn("disposable profile proof", rendered)
            shutil.rmtree(root)
            self.assertNotIn(MARKER, "".join(path.read_text(encoding="utf-8", errors="ignore") for path in Path(temp).rglob("*") if path.is_file()))
        after = hashlib.sha256(HERMES.read_bytes()).hexdigest()
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
