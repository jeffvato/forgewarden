import json
import sys
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from swarm import claude_adapter
from swarm import cli


def test_claude_review_cli_requires_only_explicit_sanitized_context(tmp_path):
    context = tmp_path / "context.txt"
    context.write_text("sanitized review context\n", encoding="utf-8")
    job_id = "claude-" + "a" * 24
    expected = {
        "job_id": job_id,
        "model": "claude-sonnet-4-6",
        "findings": [],
        "recommendations": [],
        "limitations": [],
    }
    output = StringIO()
    with patch.object(sys, "argv", [
        "hermes-swarm", "claude-review", "--job-id", job_id,
        "--model", "sonnet", "--context-file", str(context),
    ]), patch.object(claude_adapter, "run_claude", return_value=expected) as run, redirect_stdout(output):
        assert cli.main() == 0
    run.assert_called_once_with(job_id, "sanitized review context\n", model="sonnet")
    assert json.loads(output.getvalue()) == expected


def test_claude_review_cli_rejects_symlinked_context(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("context", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    job_id = "claude-" + "b" * 24
    with patch.object(sys, "argv", [
        "hermes-swarm", "claude-review", "--job-id", job_id,
        "--context-file", str(link),
    ]), patch.object(claude_adapter, "run_claude") as run:
        assert cli.main() == 1
    run.assert_not_called()


def test_claude_review_cli_rejects_oversized_context(tmp_path):
    context = tmp_path / "large.txt"
    context.write_bytes(b"x" * (claude_adapter.MAX_CONTEXT_BYTES + 1))
    job_id = "claude-" + "c" * 24
    with patch.object(sys, "argv", [
        "hermes-swarm", "claude-review", "--job-id", job_id,
        "--context-file", str(context),
    ]), patch.object(claude_adapter, "run_claude") as run:
        assert cli.main() == 1
    run.assert_not_called()


def test_launcher_help_exposes_explicit_claude_review_route():
    import os
    import subprocess

    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["/bin/bash", str(root / "packaging" / "hermes-swarm"), "--help"],
        cwd=root,
        env={**os.environ, "HERMES_SWARM_PYTHON": sys.executable},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "claude-review" in result.stdout
