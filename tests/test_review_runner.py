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


def test_sequential_fallback_uses_gemini_only_after_claude_is_unavailable(repo_fixture: Path):
    sha = repo_fixture.joinpath(".candidate-sha").read_text().strip()
    calls = []

    def unavailable(snapshot, job_id, commit, context):
        calls.append("CLAUDE")
        raise RuntimeError("Claude usage limit reached")

    def approved(snapshot, job_id, commit, context):
        calls.append("GEMINI")
        return {
            "job_id": job_id, "reviewed_commit": commit, "verdict": "APPROVE", "risk": "LOW",
            "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [],
            "reasoning_summary": "fallback approval", "proposed_rules": [],
        }

    result = run_review_cycle(
        repo_fixture, sha, "phase2a-" + "e" * 24, "review",
        claude_runner=unavailable, gemini_runner=approved,
        reviewers=("CLAUDE", "GEMINI"), required_reviewers=("CLAUDE",),
        sequential_fallback=True,
    )
    assert calls == ["CLAUDE", "GEMINI"]
    assert result["reviews"][0]["state"] == "UNAVAILABLE"
    assert result["reviews"][1]["state"] == "APPROVED"


def test_sequential_fallback_uses_claude_after_anythingllm_is_unavailable(repo_fixture: Path):
    sha = repo_fixture.joinpath(".candidate-sha").read_text().strip()
    calls = []

    def unavailable(snapshot, job_id, commit, context):
        calls.append("ANYTHINGLLM")
        raise RuntimeError("AnythingLLM usage limit reached")

    def approved(snapshot, job_id, commit, context):
        calls.append("CLAUDE")
        return {"job_id": job_id, "reviewed_commit": commit, "verdict": "APPROVE", "risk": "LOW",
                "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [],
                "reasoning_summary": "fallback approval", "proposed_rules": []}

    result = run_review_cycle(
        repo_fixture, sha, "phase2a-" + "b" * 24, "review",
        anythingllm_runner=unavailable, claude_runner=approved,
        reviewers=("ANYTHINGLLM", "CLAUDE"), required_reviewers=("CLAUDE",),
        sequential_fallback=True,
    )
    assert calls == ["ANYTHINGLLM", "CLAUDE"]
    assert result["state"] == "APPROVED"


def test_sequential_fallback_accepts_primary_without_requiring_fallback(repo_fixture: Path):
    sha = repo_fixture.joinpath(".candidate-sha").read_text().strip()
    calls = []
    def approved(snapshot, job_id, commit, context):
        calls.append("ANYTHINGLLM")
        return {"job_id": job_id, "reviewed_commit": commit, "verdict": "APPROVE", "risk": "LOW",
                "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [],
                "reasoning_summary": "primary approval", "proposed_rules": []}
    def should_not_run(*args):
        calls.append("CLAUDE")
        raise AssertionError("fallback must not run after primary approval")
    result = run_review_cycle(
        repo_fixture, sha, "phase2a-" + "d" * 24, "review",
        anythingllm_runner=approved, claude_runner=should_not_run,
        reviewers=("ANYTHINGLLM", "CLAUDE"), required_reviewers=("CLAUDE",),
        sequential_fallback=True,
    )
    assert calls == ["ANYTHINGLLM"]
    assert result["state"] == "APPROVED"


def test_sequential_fallback_does_not_override_primary_rejection(repo_fixture: Path):
    sha = repo_fixture.joinpath(".candidate-sha").read_text().strip()
    calls = []

    def rejected(snapshot, job_id, commit, context):
        calls.append("ANYTHINGLLM")
        return {"job_id": job_id, "reviewed_commit": commit, "verdict": "REJECT", "risk": "MEDIUM",
                "blocking_findings": ["finding"], "non_blocking_notes": [], "tests_missing": [],
                "reasoning_summary": "rejected", "proposed_rules": []}

    def should_not_run(*args):
        calls.append("CLAUDE")
        raise AssertionError("fallback must not replace a substantive rejection")

    result = run_review_cycle(
        repo_fixture, sha, "phase2a-" + "c" * 24, "review",
        anythingllm_runner=rejected, claude_runner=should_not_run,
        reviewers=("ANYTHINGLLM", "CLAUDE"), required_reviewers=("CLAUDE",),
        sequential_fallback=True,
    )
    assert calls == ["ANYTHINGLLM"]
    assert result["state"] == "REVIEW_REQUIRED"


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


def test_review_cycle_externalizes_large_exact_patch_for_read_only_review(repo_fixture: Path):
    import subprocess

    large = repo_fixture / "large.txt"
    large.write_text("x" * 30_000, encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_fixture), "add", "large.txt"], check=True)
    subprocess.run(["git", "-C", str(repo_fixture), "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-q", "-m", "large"], check=True)
    sha = subprocess.check_output(["git", "-C", str(repo_fixture), "rev-parse", "HEAD"], text=True).strip()
    seen = {}

    def approved(snapshot, job_id, commit, context):
        seen["context"] = context
        seen["patch"] = (snapshot / "EXACT_CANDIDATE.patch").read_text(encoding="utf-8")
        return {"job_id": job_id, "reviewed_commit": commit, "verdict": "APPROVE", "risk": "LOW", "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [], "reasoning_summary": "approved", "proposed_rules": []}

    result = run_review_cycle(repo_fixture, sha, "phase2a-" + "a" * 24, "review", claude_runner=approved, reviewers=("CLAUDE",))
    assert result["state"] == "APPROVED"
    assert "EXACT_CANDIDATE.patch" in seen["context"]
    assert "large.txt" in seen["patch"]


def test_review_cycle_embeds_large_exact_patch_for_tool_free_anythingllm(repo_fixture: Path):
    import subprocess

    large = repo_fixture / "large.txt"
    large.write_text("x" * 30_000, encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_fixture), "add", "large.txt"], check=True)
    subprocess.run(["git", "-C", str(repo_fixture), "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-q", "-m", "large"], check=True)
    sha = subprocess.check_output(["git", "-C", str(repo_fixture), "rev-parse", "HEAD"], text=True).strip()
    seen = {}

    def approved(snapshot, job_id, commit, context):
        seen["context"] = context
        seen["snapshot_patch"] = (snapshot / "EXACT_CANDIDATE.patch").is_file()
        return {"job_id": job_id, "reviewed_commit": commit, "verdict": "APPROVE", "risk": "LOW", "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [], "reasoning_summary": "approved", "proposed_rules": []}

    result = run_review_cycle(
        repo_fixture, sha, "phase2a-" + "b" * 24, "review",
        anythingllm_runner=approved, reviewers=("ANYTHINGLLM",),
    )
    assert result["state"] == "APPROVED"
    assert seen["snapshot_patch"] is True
    assert "Exact candidate patch from Git (zero unchanged context):" in seen["context"]
    assert "large.txt" in seen["context"]
    assert "available at EXACT_CANDIDATE.patch" not in seen["context"]


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


@pytest.mark.parametrize("outcome", ["APPROVE", "UNAVAILABLE"])
def test_adjudication_retains_exact_snapshot_until_finished(repo_fixture, outcome):
    sha = (repo_fixture / ".candidate-sha").read_text().strip()
    snapshots = []
    inspected = []

    def payload(job_id, commit, verdict="APPROVE"):
        return {"job_id": job_id, "reviewed_commit": commit, "verdict": verdict,
                "risk": "LOW", "blocking_findings": [], "non_blocking_notes": [],
                "tests_missing": [], "reasoning_summary": "fixture review", "proposed_rules": []}

    def claude(snapshot, job_id, commit, context):
        snapshots.append(snapshot)
        assert (snapshot / "README.md").read_text() == "fixture\n"
        patch = (snapshot / "EXACT_CANDIDATE.patch").read_text()
        assert sha in patch and "+fixture" in patch
        inspected.append(patch)
        if len(snapshots) == 2 and outcome == "UNAVAILABLE":
            raise RuntimeError("fixture adjudicator unavailable after inspection")
        return payload(job_id, commit)

    def disagrees(snapshot, job_id, commit, context):
        return payload(job_id, commit, "REJECT")

    result = run_review_cycle(
        repo_fixture, sha, "phase2a-" + "8" * 24,
        "FULL_SNAPSHOT_READ_ONLY_REVIEW: inspect exact fixture patch",
        claude_runner=claude, openrouter_runner=disagrees,
        reviewers=("CLAUDE", "OPENROUTER"), required_reviewers=("CLAUDE",),
        adjudicate_disagreements=True,
    )
    assert len(inspected) == 2
    assert inspected[0] == inspected[1]
    assert snapshots[0] == snapshots[1]
    assert all(not snapshot.exists() for snapshot in snapshots)
    assert result["mutation_allowed"] is False
    if outcome == "APPROVE":
        assert result["state"] == "APPROVED"
        assert result["adjudication"]["state"] == "APPROVED"
        assert result["adjudication"]["result"]["reviewed_commit"] == sha
    else:
        assert result["state"] == "REVIEW_REQUIRED"
        assert result["adjudication"]["state"] == "UNAVAILABLE"
        assert "after inspection" in result["adjudication"]["error"]


def test_review_cycle_supports_exact_bound_azure_reviewer(repo_fixture):
    sha = (repo_fixture / ".candidate-sha").read_text().strip()
    seen = {}

    def azure(snapshot, job_id, commit, context):
        seen.update(snapshot=snapshot, commit=commit, context=context)
        return {"job_id": job_id, "reviewed_commit": commit, "verdict": "APPROVE", "risk": "LOW", "blocking_findings": [], "non_blocking_notes": [], "tests_missing": [], "reasoning_summary": "Azure reviewed exact commit", "proposed_rules": []}

    result = run_review_cycle(repo_fixture, sha, "phase2a-" + "7" * 24, "Azure review", reviewers=("AZURE",), required_reviewers=("AZURE",), azure_runner=azure)
    assert result["state"] == "APPROVED"
    assert result["reviews"][0]["provider"] == "AZURE"
    assert seen["commit"] == sha and "Exact candidate patch" in seen["context"]
    assert not seen["snapshot"].exists()
