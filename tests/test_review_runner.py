from pathlib import Path

import pytest

from swarm.review_runner import ReviewRunnerError, run_review_cycle


def test_review_cycle_requires_full_candidate_sha(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    with pytest.raises(ReviewRunnerError, match="full Git commit SHA"):
        run_review_cycle(tmp_path, "abc123", "phase2a-" + "a" * 24, "review")


def test_review_cycle_records_provider_failure_without_approving(repo_fixture: Path):
    sha = repo_fixture.joinpath(".candidate-sha").read_text().strip()

    def approved(snapshot, job_id, commit, context):
        return {
            "job_id": job_id,
            "reviewed_commit": commit,
            "verdict": "APPROVE",
            "risk": "LOW",
            "blocking_findings": [],
            "non_blocking_notes": [],
            "tests_missing": [],
            "reasoning_summary": "approved",
            "proposed_rules": [],
        }

    def unavailable(snapshot, job_id, commit, context):
        raise RuntimeError("provider unavailable")

    result = run_review_cycle(
        repo_fixture,
        sha,
        "phase2a-" + "b" * 24,
        "review",
        claude_runner=approved,
        gemini_runner=unavailable,
    )
    assert result["state"] == "REVIEW_REQUIRED"
    assert result["mutation_allowed"] is False
    assert result["reviews"][1]["state"] == "UNAVAILABLE"


def test_review_cycle_rejects_provider_result_for_different_commit(repo_fixture: Path):
    sha = repo_fixture.joinpath(".candidate-sha").read_text().strip()

    def stale(snapshot, job_id, commit, context):
        return {
            "job_id": job_id,
            "reviewed_commit": "0" * 40,
            "verdict": "APPROVE",
            "risk": "LOW",
            "blocking_findings": [],
            "non_blocking_notes": [],
            "tests_missing": [],
            "reasoning_summary": "stale",
            "proposed_rules": [],
        }

    result = run_review_cycle(
        repo_fixture,
        sha,
        "phase2a-" + "c" * 24,
        "review",
        claude_runner=stale,
        gemini_runner=stale,
    )
    assert result["state"] == "REVIEW_REQUIRED"
    assert all(item["state"] == "UNAVAILABLE" for item in result["reviews"])


@pytest.fixture
def repo_fixture(tmp_path: Path) -> Path:
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-q", "-m", "fixture"],
        check=True,
    )
    sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    (repo / ".candidate-sha").write_text(sha, encoding="utf-8")
    return repo
