import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from swarm.console import dispatch_plan, load_profiles

class ConsoleTests(unittest.TestCase):
    def test_profiles_are_complete_and_global_guards_are_inherited(self):
        profiles = load_profiles(); self.assertEqual({p["id"] for p in profiles},{"codex-writer","gemini-reviewer","claude-auditor","fable-analyst"})
        for profile in profiles: self.assertTrue({"production","deployment","credentials","databases","remote_hosts"}.issubset(profile["forbidden_actions"]))
    def test_dispatch_plan_is_plan_only_and_model_scoped(self):
        result=dispatch_plan("codex-writer","implement","Harden the local fixture"); self.assertEqual(result["mode"],"PLAN_ONLY"); self.assertFalse(result["execution_started"]); self.assertTrue(result["guardrails"]["local_only"])
        with self.assertRaises(PermissionError): dispatch_plan("gemini-reviewer","implement","Write source")
    def test_profile_registry_rejects_weakened_global_guardrails(self):
        with TemporaryDirectory() as directory:
            path=Path(directory)/"profiles.json"; payload=json.loads((Path(__file__).parents[1]/"config/llm-profiles.json").read_text()); payload["profiles"][0]["forbidden_actions"].remove("production"); path.write_text(json.dumps(payload),encoding="utf-8")
            with self.assertRaises(ValueError): load_profiles(path)

if __name__ == "__main__": unittest.main()
