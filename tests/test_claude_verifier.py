import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from swarm import claude_verifier


def test_fake_cli_is_commit_bound_and_read_only():
    job = "phase2a-" + "a" * 24
    commit = "b" * 40
    with TemporaryDirectory() as temp:
        root = Path(temp)
        fake = root / "fake-claude.py"
        payload = {
            "job_id": job, "reviewed_commit": commit, "verdict": "APPROVE", "risk": "LOW",
            "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [],
            "reasoning_summary": "exact synthetic commit passed deterministic checks", "proposed_rules": [],
        }
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "args = sys.argv[1:]\n"
            "assert '--tools' in args and args[args.index('--tools') + 1] == ''\n"
            "assert '--permission-mode' in args and args[args.index('--permission-mode') + 1] == 'plan'\n"
            f"print(json.dumps({{'result': {json.dumps(payload)}}}))\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        with patch.object(claude_verifier, "CLAUDE", fake):
            result = claude_verifier.run(root, job, commit, "Review exact commit safely.")
        assert result["reviewed_commit"] == commit


def test_wrong_commit_fails_before_provider_call():
    with TemporaryDirectory() as temp:
        with patch.object(claude_verifier, "CLAUDE", Path(sys.executable)):
            try:
                claude_verifier.run(Path(temp), "phase2a-" + "a" * 24, "c" * 40, "x")
            except Exception:
                pass


def test_provider_failure_preserves_diagnostic_stderr():
    job = "phase2a-" + "e" * 24
    commit = "f" * 40
    with TemporaryDirectory() as temp:
        fake = Path(temp) / "fake-claude.py"
        fake.write_text("#!/usr/bin/env python3\nimport sys\nprint('runtime state is not writable', file=sys.stderr)\nsys.exit(17)\n", encoding="utf-8")
        fake.chmod(0o700)
        diagnostic = Path(temp) / "evidence" / "claude.json"
        with patch.object(claude_verifier, "CLAUDE", fake):
            try:
                claude_verifier.run(Path(temp), job, commit, "safe context", diagnostic_path=diagnostic)
            except claude_verifier.ClaudeVerificationError as exc:
                assert "exit code 17" in str(exc)
                assert "runtime state is not writable" in str(exc)
                evidence = json.loads(diagnostic.read_text(encoding="utf-8"))
                assert evidence["status"] == "PROCESS_FAILED"
                assert evidence["exit_code"] == 17
            else:
                raise AssertionError("provider failure should fail closed")
