import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from swarm import claude_verifier


def test_structured_verifier_has_one_bounded_terminal_turn():
    assert claude_verifier.MAX_TURNS == 3


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
            f"assert args[args.index('--max-turns') + 1] == '{claude_verifier.MAX_TURNS}'\n"
            "assert '--effort' in args and args[args.index('--effort') + 1] == 'low'\n"
            "assert '--strict-mcp-config' not in args\n"
            f"print(json.dumps({{'result': {json.dumps(payload)}}}))\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        diagnostic = root / "evidence" / "claude.json"
        with patch.object(claude_verifier, "CLAUDE", fake):
            result = claude_verifier.run(root, job, commit, "Review exact commit safely.", diagnostic_path=diagnostic)
        assert result["reviewed_commit"] == commit
        evidence = json.loads(diagnostic.read_text(encoding="utf-8"))
        assert evidence["status"] == "VALIDATED"
        assert evidence["review_payload"] == payload


def test_wrong_commit_fails_before_provider_call():
    with TemporaryDirectory() as temp:
        with patch.object(claude_verifier, "CLAUDE", Path(sys.executable)), patch.object(claude_verifier.subprocess, "run") as provider:
            with pytest.raises(claude_verifier.ClaudeVerificationError, match="invalid review commit"):
                claude_verifier.run(Path(temp), "phase2a-" + "a" * 24, "c" * 39, "x")
            provider.assert_not_called()


def test_diagnostic_replaces_prompt_and_rejects_symlink(tmp_path):
    job = "phase2a-" + "a" * 24
    commit = "b" * 40
    fake = tmp_path / "fake-claude.py"
    payload = {"job_id": job, "reviewed_commit": commit, "verdict": "APPROVE", "risk": "LOW", "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [], "reasoning_summary": "ok", "proposed_rules": []}
    fake.write_text("#!/usr/bin/env python3\nimport json\nprint(json.dumps({'result': " + repr(payload) + "}))\n", encoding="utf-8")
    fake.chmod(0o700)
    diagnostic = tmp_path / "diagnostic.json"
    with patch.object(claude_verifier, "CLAUDE", fake):
        claude_verifier.run(tmp_path, job, commit, "secret prompt", diagnostic_path=diagnostic)
    evidence = json.loads(diagnostic.read_text(encoding="utf-8"))
    assert evidence["argv"][2] == "<sanitized-prompt>"
    assert "secret prompt" not in json.dumps(evidence)
    assert evidence["argv"][-1] == "--no-chrome"
    link = tmp_path / "diagnostic-link.json"
    link.symlink_to(diagnostic)
    with patch.object(claude_verifier, "CLAUDE", fake), pytest.raises(claude_verifier.ClaudeVerificationError, match="symlinked"):
        claude_verifier.run(tmp_path, job, commit, "safe", diagnostic_path=link)


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


def test_review_context_preserves_exact_patch_while_sanitizing_instructions():
    prompt = "token=secret\n\nExact candidate patch from Git:\n+ token = hashlib.sha256(material).hexdigest()"
    result = claude_verifier._sanitize_review_context(prompt)
    assert "token=[REDACTED]" in result
    assert "+ token = hashlib.sha256(material).hexdigest()" in result
