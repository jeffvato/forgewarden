import pytest
from swarm.review_handoff import ReviewHandoffError, ReviewResult, create_review_cycle, record_review
SHA_A="a"*40; SHA_B="b"*40
def result(role="CLAUDE", sha=SHA_A, disposition="APPROVED", rationale="ok"):
    return ReviewResult(role, sha, (), "LOW", disposition, rationale)
def test_exact_candidate_is_immutable_and_reviews_are_structured():
    cycle=create_review_cycle(SHA_A); updated=record_review(cycle,result())
    assert cycle.reviews == {}; assert updated.reviews["CLAUDE"].reviewed_commit == SHA_A
    with pytest.raises(TypeError): updated.reviews["x"] = result()
def test_stale_and_duplicate_reviews_fail_closed():
    cycle=create_review_cycle(SHA_A)
    with pytest.raises(ReviewHandoffError,match="mismatched"): record_review(cycle,result(sha=SHA_B))
    cycle=record_review(cycle,result())
    with pytest.raises(ReviewHandoffError,match="already"): record_review(cycle,result())
def test_rejection_requires_rationale_and_invalid_sha_rejected():
    with pytest.raises(ReviewHandoffError,match="full"): create_review_cycle("short")
    with pytest.raises(ReviewHandoffError,match="rationale"): record_review(create_review_cycle(SHA_A),result(disposition="REJECTED",rationale=""))
