"""Immutable exact-commit review handoff evidence."""
from __future__ import annotations
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

_SHA1 = re.compile(r"[0-9a-fA-F]{40}")
_ROLES = frozenset({"CLAUDE", "GEMINI"})
_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
_DISPOSITIONS = frozenset({"APPROVED", "REJECTED", "FINDINGS"})
class ReviewHandoffError(ValueError): pass
@dataclass(frozen=True)
class ReviewResult:
    role: str; reviewed_commit: str; findings: tuple[str, ...]; severity: str; disposition: str; rationale: str
@dataclass(frozen=True)
class ReviewCycle:
    candidate_commit: str; reviews: Mapping[str, ReviewResult]
def create_review_cycle(candidate_commit: str) -> ReviewCycle:
    if not _SHA1.fullmatch(candidate_commit): raise ReviewHandoffError("candidate commit must be a full Git SHA-1")
    return ReviewCycle(candidate_commit.lower(), MappingProxyType({}))
def record_review(cycle: ReviewCycle, result: ReviewResult) -> ReviewCycle:
    if result.role not in _ROLES or result.severity not in _SEVERITIES or result.disposition not in _DISPOSITIONS: raise ReviewHandoffError("invalid review role, severity, or disposition")
    if not _SHA1.fullmatch(result.reviewed_commit) or result.reviewed_commit.lower() != cycle.candidate_commit: raise ReviewHandoffError("stale or mismatched review commit")
    if any(not isinstance(finding, str) or not finding.strip() for finding in result.findings): raise ReviewHandoffError("findings must contain non-empty strings")
    if result.role in cycle.reviews: raise ReviewHandoffError("review role already recorded")
    if result.disposition == "REJECTED" and not result.rationale.strip(): raise ReviewHandoffError("rejected review requires rationale")
    reviews = dict(cycle.reviews); reviews[result.role] = result
    return ReviewCycle(cycle.candidate_commit, MappingProxyType(reviews))
def complete_review_cycle(cycle: ReviewCycle, required_roles: frozenset[str] | set[str] = _ROLES) -> ReviewCycle:
    required = frozenset(required_roles)
    if not required or not required.issubset(_ROLES): raise ReviewHandoffError("review cycle contains an unsupported reviewer role")
    if set(cycle.reviews) != required: raise ReviewHandoffError("required reviewer evidence is incomplete")
    if any(review.disposition == "REJECTED" for review in cycle.reviews.values()): raise ReviewHandoffError("rejected review requires repair")
    if any(review.disposition == "FINDINGS" and review.severity in {"HIGH", "CRITICAL"} for review in cycle.reviews.values()): raise ReviewHandoffError("high or critical findings require repair")
    return cycle
