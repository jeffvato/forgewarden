import json
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from swarm.core import (
    AuditLog, DeploymentController, Job, Orchestrator, RuleStore, ServiceLock,
    SwarmError, ensure_mailbox_directory, read_mailbox_json, redact,
    require_exact_commit, validate_contract, validate_snapshot_symlinks, write_mailbox_json,
)


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
        self.gemini.write_text("""import json, os, pathlib\npathlib.Path('.swarm').mkdir(exist_ok=True)\nassert pathlib.Path('.swarm/quality-review.json').is_file()\nassert pathlib.Path('.swarm/quality-application-plan.json').is_file()\njson.dump({'job_id':'job-1','reviewed_commit':os.environ['SWARM_REVIEWED_COMMIT'],'verdict':'APPROVE','risk':'LOW','blocking_findings':[],'non_blocking_notes':[],'tests_missing':[],'reasoning_summary':'fixture patch is narrow and tested','proposed_rules':[]}, open('.swarm/gemini-review.json','w'))\n""", encoding="utf-8")

    def run_job(self, evidence="parser defect"):
        state = self.root / "state"
        check = ["python3", "-c", "from parser import parse; assert parse(' X ') == 'x'"]
        return Orchestrator(state).run(Job("job-1", "fixture-parser", self.repo, evidence), ["python3", str(self.codex)], check, ["python3", str(self.gemini)])

    def test_disposable_fixture_dry_run_succeeds(self):
        result = self.run_job()
        self.assertEqual(result["state"], "SUCCEEDED")
        self.assertEqual(result["quality_review"]["mode"], "READ_ONLY")
        self.assertFalse(result["quality_review"]["auto_apply_enabled"])
        self.assertEqual(result["quality_gate"]["decision"], "ALLOW_DRY_RUN")
        self.assertTrue(result["safe_application_plan"]["requires_explicit_invocation"])
        self.assertEqual(result["safe_application_plan"]["eligible_finding_ids"], [])
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

    def test_structured_mailbox_rejects_symlinks_and_external_snapshot_links(self):
        mailbox = self.root / "mailbox"
        ensure_mailbox_directory(mailbox)
        target = self.root / "outside.json"
        target.write_text('{"outside": true}', encoding="utf-8")
        linked = mailbox / "result.json"
        linked.symlink_to(target)
        with self.assertRaises(SwarmError):
            read_mailbox_json(linked, "fixture result")
        with self.assertRaises(SwarmError):
            write_mailbox_json(linked, {"safe": True}, "fixture result")

        snapshot = self.root / "snapshot"
        snapshot.mkdir()
        (snapshot / "external.txt").symlink_to(target)
        with self.assertRaises(SwarmError):
            validate_snapshot_symlinks(snapshot)

    def test_structured_mailbox_is_created_exclusively_and_restricted(self):
        mailbox = self.root / "mailbox"
        ensure_mailbox_directory(mailbox)
        result = mailbox / "result.json"
        write_mailbox_json(result, {"ok": True}, "fixture result")
        self.assertEqual(read_mailbox_json(result, "fixture result"), {"ok": True})
        self.assertEqual(result.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(SwarmError):
            write_mailbox_json(result, {"replacement": True}, "fixture result")

    def test_audit_log_rejects_symlinked_log_and_lock_paths(self):
        outside = self.root / "outside-audit.jsonl"
        outside.write_text("outside\n", encoding="utf-8")
        linked = self.root / "linked-audit.jsonl"
        linked.symlink_to(outside)
        with self.assertRaises(SwarmError):
            AuditLog(linked)

        audit = self.root / "audit.jsonl"
        lock = self.root / "audit.jsonl.lock"
        lock.symlink_to(outside)
        with self.assertRaises(SwarmError):
            AuditLog(audit)

    def test_one_character_commit_mismatch_blocks_approval(self):
        expected = "a" * 40
        mismatched = "a" * 39 + "b"
        with self.assertRaises(SwarmError):
            require_exact_commit(expected, mismatched)

    def test_deployment_is_mechanically_disabled(self):
        with self.assertRaises(SwarmError):
            DeploymentController().deploy("anything")

    def test_gemini_rejects_deliberately_incorrect_patch(self):
        self.gemini.write_text("""import json, os, pathlib\npathlib.Path('.swarm').mkdir(exist_ok=True)\njson.dump({'job_id':'job-1','reviewed_commit':os.environ['SWARM_REVIEWED_COMMIT'],'verdict':'REJECT','risk':'LOW','blocking_findings':[{'severity':'HIGH','file':'parser.py','line':'1','finding':'incorrect behavior','required_change':'restore expected behavior'}],'non_blocking_notes':[],'tests_missing':['regression'],'reasoning_summary':'incorrect fixture','proposed_rules':[]}, open('.swarm/gemini-review.json','w'))\n""", encoding="utf-8")
        self.assertEqual(self.run_job()["state"], "REVISION_REQUIRED")

    def test_risky_quality_finding_overrides_gemini_approval(self):
        self.codex.write_text("""import json, os, pathlib, subprocess
p=pathlib.Path('parser.py')
p.write_text(p.read_text().replace('return value.strip()', 'return value.strip().lower()') + '\\n_count = 0\\ndef mutate():\\n    global _count\\n    _count += 1\\n')
pathlib.Path('.swarm').mkdir()
subprocess.run(['git','add','parser.py'])
subprocess.run(['git','-c','user.name=codex','-c','user.email=codex@example.test','commit','-qm','risky repair'])
json.dump({'job_id':'job-1','status':'FIXED','root_cause':'fixture','summary':'fixture','changed_files':['parser.py'],'tests_added_or_changed':[],'commands_run':[{'command':'fixture repair','exit_code':0}],'remaining_risks':[],'requires_human_approval':False}, open('.swarm/codex-result.json','w'))
""", encoding="utf-8")

        result = self.run_job()

        self.assertEqual(result["gemini"]["verdict"], "APPROVE")
        self.assertEqual(result["quality_gate"]["decision"], "HUMAN_REQUIRED")
        self.assertEqual(result["state"], "AWAITING_JEFF")

    def test_forbidden_file_change_is_blocked(self):
        self.codex.write_text("""import json, pathlib, subprocess\npathlib.Path('.env').write_text('SECRET=redacted-fixture')\npathlib.Path('.swarm').mkdir(exist_ok=True)\nsubprocess.run(['git','add','.env'])\nsubprocess.run(['git','-c','user.name=codex','-c','user.email=codex@example.test','commit','-qm','bad'])\njson.dump({'job_id':'job-1','status':'FIXED','root_cause':'bad','summary':'bad','changed_files':['.env'],'tests_added_or_changed':[],'commands_run':[{'command':'bad','exit_code':0}],'remaining_risks':[],'requires_human_approval':False}, open('.swarm/codex-result.json','w'))\n""", encoding="utf-8")
        with self.assertRaises(SwarmError):
            self.run_job()

    def test_duplicate_job_is_blocked(self):
        state = self.root / "state"
        with ServiceLock(state / "locks", "fixture-parser"):
            with self.assertRaises(SwarmError):
                self.run_job()

    def test_three_review_cycle_limit(self):
        orchestrator = Orchestrator(self.root / "cycles", max_cycles=3)
        job = Job("cycles", "fixture-parser", self.repo, "parser defect")
        self.assertEqual([orchestrator.begin_review_cycle(job) for _ in range(3)], [1, 2, 3])
        with self.assertRaises(SwarmError):
            orchestrator.begin_review_cycle(job)

    def test_kill_switch_prevents_new_jobs(self):
        state = self.root / "killed"
        state.mkdir()
        (state / "KILL_SWITCH").write_text("disabled\n", encoding="utf-8")
        with self.assertRaises(SwarmError):
            Orchestrator(state).run(Job("killed", "fixture-parser", self.repo, "parser defect"), ["true"], ["true"], ["true"])

    def test_learned_rule_cannot_activate_itself_and_protected_rule_requires_jeff(self):
        store = RuleStore(self.root / "rules")
        job = Job("rule-job", "fixture-parser", self.repo, "parser defect")
        base = {'id':'rule-123','scope':'fixture-parser','trigger':'parser change','rule':'run parser regression tests','enforcement':'python3 -m unittest','evidence':'observed test omission','source_job_id':job.job_id,'confidence':0.99,'status':'PROPOSED'}
        self.assertEqual(store.propose({**base, 'category':'TESTING'}, job), 'PROPOSED_DRY_RUN')
        self.assertFalse(store.active.exists())
        self.assertEqual(store.propose({**base, 'id':'rule-security', 'category':'SECURITY'}, job), 'HUMAN_REQUIRED')

    def test_redaction(self):
        self.assertNotIn("supersecret", redact("token=supersecret"))
        self.assertNotIn("4111111111111111", redact("card 4111111111111111"))
        private_key = "-----BEGIN " + "PRIVATE KEY-----\nprivate-key-secret\n-----END " + "PRIVATE KEY-----"
        value = redact(
            "Authorization: Bearer bearer-secret "
            "Cookie: session-cookie "
            "postgres://user:database-secret@db.example.test/app "
            + private_key
        )
        for secret in ("bearer-secret", "session-cookie", "database-secret", "private-key-secret"):
            self.assertNotIn(secret, value)

    def test_durable_audit_survives_runtime_removal_and_is_restricted(self):
        runtime = self.root / "runtime"
        audit_dir = self.root / "durable-audit"
        job = Job("audit-job", "fixture-parser", self.repo, "parser defect", state="SUCCEEDED")
        AuditLog(audit_dir / "audit.jsonl").record(
            job,
            "dry_run_succeeded",
            commit="a" * 40,
            reviewer_decision="APPROVE",
            checks="PASSED",
            customer_email="customer@example.test",
            output="token=supersecret customer order 123",
        )
        audit = audit_dir / "audit.jsonl"
        self.assertEqual(audit_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual(audit.stat().st_mode & 0o777, 0o600)
        contents = audit.read_text(encoding="utf-8")
        self.assertIn('"commit": "' + "a" * 40 + '"', contents)
        self.assertIn('"reviewer_decision": "APPROVE"', contents)
        self.assertNotIn("customer@example.test", contents)
        self.assertNotIn("supersecret", contents)
        runtime.mkdir()
        (runtime / "KILL_SWITCH").write_text("engaged\n", encoding="utf-8")
        for child in runtime.iterdir():
            child.unlink()
        runtime.rmdir()
        self.assertTrue(audit.exists())

    def test_audit_records_are_serialized_and_fsynced(self):
        audit_dir = self.root / "concurrent-audit"
        audit = audit_dir / "audit.jsonl"
        job = Job("concurrent-audit-job", "fixture-parser", self.repo, "parser defect")
        writers = [AuditLog(audit) for _ in range(4)]

        def write_records(writer_index):
            for record_index in range(10):
                writers[writer_index].record(job, "concurrent_event", writer=writer_index, record=record_index)

        threads = [threading.Thread(target=write_records, args=(index,)) for index in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        lines = audit.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 40)
        self.assertTrue(all(json.loads(line)["event"] == "concurrent_event" for line in lines))
        self.assertEqual(audit.stat().st_mode & 0o777, 0o600)
        self.assertEqual((audit_dir / "audit.jsonl.lock").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
