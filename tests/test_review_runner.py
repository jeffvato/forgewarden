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


def test_review_cycle_uses_independent_provider_snapshots(repo_fixture: Path):
    sha = repo_fixture.joinpath(".candidate-sha").read_text().strip()
    snapshots = []

    def approved(snapshot, job_id, commit, context):
        snapshots.append(snapshot)
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

    result = run_review_cycle(
        repo_fixture,
        sha,
        "phase2a-" + "d" * 24,
        "review",
        claude_runner=approved,
        gemini_runner=approved,
    )
    assert result["state"] == "APPROVED"
    assert len(snapshots) == 2
    assert snapshots[0] != snapshots[1]


def test_review_cycle_does_not_stall_when_optional_reviewers_are_unavailable(repo_fixture: Path):
    sha = repo_fixture.joinpath(".candidate-sha").read_text().strip()

    def approved(snapshot, job_id, commit, context):
        return {
            "job_id": job_id, "reviewed_commit": commit, "verdict": "APPROVE", "risk": "LOW",
            "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [],
            "reasoning_summary": "approved", "proposed_rules": [],
        }

    def unavailable(snapshot, job_id, commit, context):
        raise RuntimeError("provider unavailable")

    result = run_review_cycle(
        repo_fixture, sha, "phase2a-" + "9" * 24, "review", claude_runner=approved,
        gemini_runner=unavailable, reviewers=("CLAUDE", "GEMINI"),
        required_reviewers=("CLAUDE",), adjudicate_disagreements=True,
    )
    assert result["state"] == "APPROVED"
    assert result["reviews"][1]["state"] == "UNAVAILABLE"


def test_review_cycle_supports_explicit_claude_only_mode(repo_fixture: Path):
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

    result = run_review_cycle(
        repo_fixture,
        sha,
        "phase2a-" + "e" * 24,
        "review",
        claude_runner=approved,
        reviewers=("CLAUDE",),
    )
    assert result["state"] == "APPROVED"
    assert [item["provider"] for item in result["reviews"]] == ["CLAUDE"]


def test_review_cycle_uses_claude_to_adjudicate_provider_disagreement(repo_fixture: Path):
    sha = repo_fixture.joinpath(".candidate-sha").read_text().strip()
    calls = {"claude": 0}

    def report(snapshot, job_id, commit, context):
        return {"job_id": job_id, "reviewed_commit": commit, "verdict": "APPROVE", "risk": "LOW", "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [], "reasoning_summary": "approved", "proposed_rules": []}

    def claude(snapshot, job_id, commit, context):
        calls["claude"] += 1
        if calls["claude"] == 1:
            return report(snapshot, job_id, commit, context)
        return report(snapshot, job_id, commit, context)

    def rejected(snapshot, job_id, commit, context):
        result = report(snapshot, job_id, commit, context)
        result["verdict"] = "REJECT"
        result["risk"] = "HIGH"
        result["blocking_findings"] = ["provider disagreement"]
        return result

    result = run_review_cycle(repo_fixture, sha, "phase2a-" + "f" * 24, "review", claude_runner=claude, reviewers=("CLAUDE", "OPENROUTER", "NVIDIA"), openrouter_runner=rejected, nvidia_runner=report, adjudicate_disagreements=True)
    assert result["state"] == "APPROVED"
    assert result["adjudication"]["provider"] == "CLAUDE_ADJUDICATION"
    assert calls["claude"] == 2


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
