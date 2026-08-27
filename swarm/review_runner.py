"""Bounded, read-only exact-commit review orchestration."""

from __future__ import annotations

import json
import re
import subprocess
import tarfile
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

from . import claude_verifier
from .adapters import GeminiAdapter, ResourceLimits
from .core import SwarmError, read_restricted_bytes, redact, validate_contract, validate_snapshot_symlinks
from .verification_adapters import nvidia_adapter, openrouter_adapter

_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")
_JOB_ID = re.compile(r"^phase2a-[a-z0-9]{24}$")


class ReviewRunnerError(SwarmError):
    """The exact-commit review cycle could not be completed safely."""


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ReviewRunnerError(f"Git review preparation failed: {result.stderr.strip()[:1000]}")
    return result.stdout.strip()


def _validate_inputs(repository: Path, candidate_commit: str, job_id: str) -> str:
    if not repository.is_dir() or repository.is_symlink():
        raise ReviewRunnerError("review repository must be a regular directory")
    if not _FULL_SHA.fullmatch(candidate_commit):
        raise ReviewRunnerError("review requires a full Git commit SHA")
    if not _JOB_ID.fullmatch(job_id):
        raise ReviewRunnerError("review requires a Phase 2A job ID")
    resolved = _git(repository, "rev-parse", "--verify", f"{candidate_commit}^{{commit}}")
    if resolved.lower() != candidate_commit.lower():
        raise ReviewRunnerError("candidate commit does not resolve to the supplied full SHA")
    return resolved


def _extract_archive(repository: Path, commit: str, destination: Path) -> None:
    process = subprocess.Popen(
        ["git", "-C", str(repository), "archive", "--format=tar", commit],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            root = destination.resolve()
            for member in archive:
                target = (destination / member.name).resolve()
                try:
                    target.relative_to(root)
                except ValueError as exc:
                    raise ReviewRunnerError("Git archive contains an escaping path") from exc
                archive.extract(member, destination, filter="data")
    finally:
        process.stdout.close()
    stderr = process.stderr.read().decode("utf-8", errors="replace") if process.stderr else ""
    if process.wait() != 0:
        raise ReviewRunnerError(f"Git archive failed: {stderr[:1000]}")
    validate_snapshot_symlinks(destination)


def _review_record(provider: str, result: dict[str, Any] | None = None, error: str | None = None) -> dict[str, Any]:
    if result is not None:
        return {
            "provider": provider,
            "state": "APPROVED" if result.get("verdict") == "APPROVE" and result.get("risk") == "LOW" and not result.get("blocking_findings") and not result.get("tests_missing") else "REVIEW_RETURNED",
            "result": result,
        }
    return {"provider": provider, "state": "UNAVAILABLE", "error": str(error or "review failed")[:2000]}


def run_review_cycle(
    repository: Path,
    candidate_commit: str,
    job_id: str,
    context: str,
    *,
    allow_external_review: bool = False,
    claude_runner: Callable[..., dict[str, Any]] | None = None,
    gemini_runner: Callable[..., dict[str, Any]] | None = None,
    openrouter_runner: Callable[..., dict[str, Any]] | None = None,
    nvidia_runner: Callable[..., dict[str, Any]] | None = None,
    reviewers: tuple[str, ...] = ("CLAUDE", "GEMINI"),
    adjudicate_disagreements: bool = False,
    required_reviewers: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Run the configured independent reviewers without changing the repository.

    Provider failures are captured as ``UNAVAILABLE`` and never converted into
    approval. The overall cycle is approved only when every configured reviewer
    returns a valid low-risk approval for the exact candidate commit.
    """
    if not isinstance(context, str) or not context.strip():
        raise ReviewRunnerError("review context must be non-empty text")
    commit = _validate_inputs(repository, candidate_commit, job_id)
    patch = _git(repository, "show", "--format=fuller", "--stat", "--patch", commit)
    review_context = context + "\n\nExact candidate patch from Git:\n" + patch
    if len(review_context.encode("utf-8")) > 24_000:
        raise ReviewRunnerError("review context plus exact candidate patch exceeds the 24000-byte bound")
    requested = tuple(dict.fromkeys(reviewers))
    supported = {"CLAUDE", "GEMINI", "OPENROUTER", "NVIDIA"}
    if not requested or any(provider not in supported for provider in requested):
        raise ReviewRunnerError("reviewers must contain supported read-only providers")
    required = requested if required_reviewers is None else tuple(dict.fromkeys(required_reviewers))
    if not required or any(provider not in requested for provider in required):
        raise ReviewRunnerError("required reviewers must be selected from reviewers")
    with tempfile.TemporaryDirectory(prefix=f"forgewarden-review-{job_id}-") as temporary:
        snapshots = {provider: Path(temporary) / provider.lower() for provider in requested}
        for snapshot in snapshots.values():
            snapshot.mkdir()
            _extract_archive(repository, commit, snapshot)

        claude = claude_runner or claude_verifier.run
        gemini = gemini_runner
        if "GEMINI" in requested and gemini is None:
            adapter = GeminiAdapter(
                snapshots["GEMINI"] / "schemas/gemini-review.schema.json",
                ResourceLimits(),
                allow_external_review=allow_external_review,
            )
            gemini = adapter.run
        openrouter = openrouter_runner or (openrouter_adapter().run if "OPENROUTER" in requested else None)
        nvidia = nvidia_runner or (nvidia_adapter().run if "NVIDIA" in requested else None)

        provider_map = {"CLAUDE": claude, "GEMINI": gemini, "OPENROUTER": openrouter, "NVIDIA": nvidia}
        providers = tuple((provider, provider_map[provider]) for provider in requested)

        def invoke_provider(provider: str, invoke: Callable[..., dict[str, Any]]) -> dict[str, Any]:
            try:
                result = invoke(snapshots[provider], job_id, commit, review_context)
                contract_provider = provider.lower() if provider in {"CLAUDE", "GEMINI"} else "claude"
                validate_contract(result, contract_provider, expected_job_id=job_id, expected_commit=commit)
                return _review_record(provider, result=result)
            except Exception as exc:  # provider boundaries must not hide the other review
                return _review_record(provider, error=redact(str(exc)))

        # Providers are independent read-only reviewers. Run them concurrently so
        # a slow or unavailable provider cannot prevent the other review from
        # completing. Each adapter owns its bounded subprocess timeout.
        with ThreadPoolExecutor(max_workers=len(providers), thread_name_prefix="forgewarden-review") as executor:
            futures = [executor.submit(invoke_provider, provider, invoke) for provider, invoke in providers]
            records = [future.result() for future in futures]

    adjudication = None
    if adjudicate_disagreements and "CLAUDE" in requested and next(record for record in records if record["provider"] == "CLAUDE")["state"] != "UNAVAILABLE":
        non_claude = [record for record in records if record["provider"] != "CLAUDE" and record["state"] != "UNAVAILABLE"]
        if any(record["state"] != "APPROVED" for record in non_claude):
            try:
                adjudication_prompt = review_context + "\n\nThe following read-only provider reports disagree. Adjudicate them against the exact commit and return the final Claude decision:\n" + json.dumps(non_claude, sort_keys=True)
                final_result = claude(snapshots["CLAUDE"], job_id, commit, adjudication_prompt)
                validate_contract(final_result, "claude", expected_job_id=job_id, expected_commit=commit)
                adjudication = _review_record("CLAUDE_ADJUDICATION", result=final_result)
            except Exception as exc:
                adjudication = _review_record("CLAUDE_ADJUDICATION", error=redact(str(exc)))
    required_records = [record for record in records if record["provider"] in required]
    optional_records = [record for record in records if record["provider"] not in required]
    approved = bool(adjudication and adjudication["state"] == "APPROVED") or (
        all(record["state"] == "APPROVED" for record in required_records)
        and all(record["state"] in {"APPROVED", "UNAVAILABLE"} for record in optional_records)
    )
    return {
        "state": "APPROVED" if approved else "REVIEW_REQUIRED",
        "candidate_commit": commit,
        "job_id": job_id,
        "mutation_allowed": False,
        "deployment": "DISABLED",
        "kill_switch": "ENGAGED",
        "reviews": records,
        "adjudication": adjudication,
    }


def read_context(path: Path) -> str:
    """Read a bounded, non-symlinked review context file."""
    if path.is_symlink() or any(parent.is_symlink() for parent in (path.parent, *path.parent.parents)):
        raise ReviewRunnerError("review context path is symlinked")
    if not path.is_file():
        raise ReviewRunnerError("review context file is missing")
    content = read_restricted_bytes(path, "review context")
    if len(content) > 24_000:
        raise ReviewRunnerError("review context exceeds the 24000-byte bound")
    return content.decode("utf-8")


def render_result(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, sort_keys=True) + "\n"
