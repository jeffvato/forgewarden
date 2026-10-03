import json
import sys
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from swarm import cli
from swarm.verification_adapters import DaybreakReviewer


def test_daybreak_review_cli_requires_exact_commit_and_sanitized_context(tmp_path):
    context = tmp_path / "context.txt"
    context.write_text("sanitized review context\n", encoding="utf-8")
    job_id = "phase2a-" + "a" * 24
    commit = "b" * 40
    expected = {
        "job_id": job_id,
        "reviewed_commit": commit,
        "verdict": "APPROVE", "risk": "LOW", "blocking_findings": [],
        "non_blocking_notes": [], "tests_missing": [], "reasoning_summary": "ok", "proposed_rules": [],
    }
    output = StringIO()
    with patch.object(sys, "argv", [
        "hermes-swarm", "daybreak-review", "--job-id", job_id,
        "--revision", commit, "--context-file", str(context),
    ]), patch.object(DaybreakReviewer, "run", return_value=expected) as run, redirect_stdout(output):
        assert cli.main() == 0
    run.assert_called_once()
    assert json.loads(output.getvalue()) == expected


def test_daybreak_review_cli_rejects_symlinked_context(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("context", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    job_id = "phase2a-" + "b" * 24
    with patch.object(sys, "argv", [
        "hermes-swarm", "daybreak-review", "--job-id", job_id,
        "--revision", "c" * 40, "--context-file", str(link),
    ]), patch.object(DaybreakReviewer, "run") as run:
        assert cli.main() == 1
    run.assert_not_called()


def test_daybreak_review_cli_rejects_oversized_context(tmp_path):
    context = tmp_path / "large.txt"
    context.write_bytes(b"x" * 24001)
    job_id = "phase2a-" + "c" * 24
    with patch.object(sys, "argv", [
        "hermes-swarm", "daybreak-review", "--job-id", job_id,
        "--revision", "d" * 40, "--context-file", str(context),
    ]), patch.object(DaybreakReviewer, "run") as run:
        assert cli.main() == 1
    run.assert_not_called()


def test_launcher_help_exposes_explicit_daybreak_review_route():
    import os
    import subprocess

    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-m", "swarm.cli", "--help"],
        cwd=root,
        env={**os.environ, "HERMES_SWARM_PYTHON": sys.executable},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "daybreak-review" in result.stdout
