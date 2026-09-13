"""Build a disposable release candidate without mutating the source tree."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .phase5_release_audit import GENERATED_PARTS, ReleaseAudit


_ROOT = Path(__file__).resolve().parents[1]
_READINESS_PROFILE = _ROOT / "config/phase5-release-readiness.yaml"
_READINESS_SCHEMA = _ROOT / "schemas/phase5-release-readiness.schema.json"
_EXPORT_POLICY = _ROOT / "config/phase5-public-export.yaml"
_EXPORT_SCHEMA = _ROOT / "schemas/phase5-public-export.schema.json"
_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def _read_yaml(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("Phase 5 policy input must be a bounded regular file")
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Phase 5 policy input must be an object")
    return value


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("Phase 5 schema input must be a bounded regular file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Phase 5 schema input must be an object")
    return value


def _load_contract(track: str) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    profile = _read_yaml(_READINESS_PROFILE)
    policy = _read_yaml(_EXPORT_POLICY)
    Draft202012Validator(_read_json(_READINESS_SCHEMA)).validate(profile)
    Draft202012Validator(_read_json(_EXPORT_SCHEMA)).validate(policy)
    if (profile.get("publication") != "DISABLED"
            or profile.get("history_strategy") != "SANITIZED_SINGLE_COMMIT"
            or profile.get("current_repository", {}).get("visibility") != "PRIVATE"
            or policy.get("publication") != "DISABLED"):
        raise ValueError("Phase 5 publication boundary is not fail-closed")
    profile_tracks = {item["track"]: item for item in profile["tracks"]}
    if track not in policy["tracks"] or track not in profile_tracks:
        raise ValueError("unsupported public-export track")
    profile_track = profile_tracks[track]
    policy_track = policy["tracks"][track]
    if (track == "PRIVATE_CORE" or profile_track["includes_private_core"]
            or policy_track["includes_private_core"]
            or profile_track["source_scope"] != "EXPLICIT_ALLOWLIST_ONLY"
            or policy_track["source_scope"] != "EXPLICIT_ALLOWLIST_ONLY"
            or profile_track["publication"] != "DISABLED"):
        raise ValueError("public-export track is not bounded")
    paths = _normalize_allowlist(policy_track["allowlist"], policy["limits"])
    return profile, policy, paths


def _normalize_allowlist(values: object, limits: dict[str, int]) -> list[str]:
    if not isinstance(values, list) or not values or len(values) > limits["max_files"]:
        raise ValueError("public-export file-count budget violated")
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > limits["max_path_bytes"]:
            raise ValueError("public-export path is invalid")
        path = PurePosixPath(value)
        if (value.startswith("/") or "\\" in value or ":" in value or str(path) != value
                or any(part in {"", ".", ".."} for part in path.parts)):
            raise ValueError("public-export path is invalid")
        folded = value.casefold()
        if folded in seen:
            raise ValueError("public-export allowlist contains a duplicate path")
        seen.add(folded)
        normalized.append(value)
    return sorted(normalized)


def _source_root(source: Path) -> Path:
    supplied = Path(source)
    if supplied.is_symlink():
        raise ValueError("public-export source must be a real directory")
    try:
        resolved = supplied.resolve(strict=True)
    except OSError as exc:
        raise ValueError("public-export source must be a real directory") from exc
    if not resolved.is_dir():
        raise ValueError("public-export source must be a real directory")
    return resolved


def _destination_root(source: Path, destination: Path) -> Path:
    supplied = Path(destination)
    if not supplied.is_absolute():
        supplied = Path.cwd() / supplied
    if ".." in supplied.parts or supplied.exists() or supplied.is_symlink():
        raise FileExistsError("public-export destination must be new")
    for ancestor in supplied.parents:
        if ancestor.exists() and (ancestor.is_symlink() or not ancestor.is_dir()):
            raise ValueError("public-export destination ancestry is unsafe")
    resolved = supplied.resolve(strict=False)
    if source == resolved or source in resolved.parents:
        raise ValueError("public-export destination must be outside the source tree")
    if not resolved.parent.is_dir() or resolved.parent.is_symlink():
        raise ValueError("public-export destination parent must be a real directory")
    return resolved


def _git(source: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(source), *args], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, shell=False, check=False, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("public-export Git inspection failed") from exc
    if result.returncode or len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("public-export Git inspection failed")
    return result.stdout


def _head(source: Path) -> str:
    value = _git(source, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    if not _SHA.fullmatch(value):
        raise ValueError("public-export source commit is invalid")
    return value


def _tracked_blob(source: Path, commit: str, relative: str) -> bytes:
    entry = _git(source, "ls-tree", "-z", commit, "--", relative)
    if not entry.endswith(b"\0") or entry.count(b"\0") != 1:
        raise ValueError("allowlisted source must be exactly one tracked file")
    metadata, separator, path = entry[:-1].partition(b"\t")
    fields = metadata.split(b" ")
    if not separator or len(fields) != 3 or fields[0] not in {b"100644", b"100755"} or fields[1] != b"blob":
        raise ValueError("allowlisted source must be a regular tracked file")
    if path.decode("utf-8") != relative or not _SHA.fullmatch(fields[2].decode("ascii")):
        raise ValueError("allowlisted source Git metadata is invalid")
    return _git(source, "cat-file", "blob", fields[2].decode("ascii"))


def _read_source_file(source: Path, relative: str, commit: str, max_bytes: int) -> bytes:
    path = source.joinpath(*PurePosixPath(relative).parts)
    if path.is_symlink():
        raise ValueError("allowlisted source must be a regular file")
    try:
        info = path.stat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError("allowlisted source must be a regular file") from exc
    if not stat.S_ISREG(info.st_mode) or source not in resolved.parents:
        raise ValueError("allowlisted source must be a regular file")
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if not data:
        raise ValueError("allowlisted source cannot be empty")
    if len(data) > max_bytes:
        raise ValueError("public-export per-file budget exceeded")
    if data != _tracked_blob(source, commit, relative):
        raise ValueError("allowlisted source drifted from the exact commit")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("allowlisted source must be UTF-8 text") from exc
    return data


def _policy_sha256(profile: dict[str, Any], policy: dict[str, Any]) -> str:
    payload = json.dumps(
        {"profile": profile, "export_policy": policy},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _cleanup(destination: Path) -> None:
    if destination.is_symlink():
        destination.unlink()
    elif destination.exists():
        shutil.rmtree(destination)


TEMPLATES = {
    "README.md": """# Forge Warden

Forge Warden is a local-first coding-swarm safety and evidence platform for
bounded review, deterministic validation, audit evidence, and fail-closed
dry-run workflows. This candidate is sanitized; deployment, unattended
execution, production access, and public publication remain disabled.

Supported environment: Python 3.12 or newer on Linux, WSL, or another POSIX-like
development environment. Read `docs/install.md` and
`docs/reproducibility.md` before use.
""",
    "docs/install.md": """# Install and operating boundary

Create a fresh Python 3.12 virtual environment, install `requirements.lock`,
then run `python -m swarm.cli status` and confirm the safety state is engaged.

This candidate does not authorize VPS access, production deployment, public
publication, unattended jobs, or credential handling. Updates require a new
candidate and fresh validation. Rollback means discarding this disposable
candidate and retaining the prior reviewed candidate.
""",
    "docs/reproducibility.md": """# Reproducibility

The candidate targets Python 3.12 and uses `requirements.lock` with exact
versions from the tested environment. A clean-room release pass must add
artifact hashes before public publication. Recreate the environment in a clean
virtual environment, record the interpreter version, and run validation before
review.

Private evidence, tests, and local project records are intentionally excluded.
""",
    "requirements.lock": """anyio==4.14.2
mcp==1.26.0
PyYAML==6.0.3
jsonschema==4.26.0
attrs==26.1.0
jsonschema-specifications==2025.9.1
referencing==0.37.0
rpds-py==2026.6.3
typing-extensions==4.16.0
""",
}


def build_release_candidate(source: Path, destination: Path) -> dict[str, object]:
    source = source.resolve()
    destination = destination.resolve()
    if source == destination or source in destination.parents:
        raise ValueError("release candidate destination must be outside the source tree")
    if destination.exists():
        raise FileExistsError(destination)

    inventory = ReleaseAudit(source).inventory()
    excluded = {
        Path(item["path"])
        for item in inventory["findings"]
    }
    destination.mkdir(parents=True)
    copied_files = 0
    excluded_files = 0
    skipped_generated = 0
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if ".git" in relative.parts:
            continue
        if path.name.endswith(":Zone.Identifier"):
            continue
        if relative in excluded or any(parent in excluded for parent in relative.parents):
            if path.is_file() and not path.is_symlink():
                excluded_files += 1
            continue
        if GENERATED_PARTS.intersection(relative.parts):
            skipped_generated += 1
            continue
        if path.is_symlink():
            continue
        target = destination / relative
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            copied_files += 1
    for relative, content in TEMPLATES.items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return {
        "publication": "DISABLED",
        "mutation_performed": False,
        "source_tree_mutated": False,
        "excluded_files": excluded_files,
        "skipped_generated_entries": skipped_generated,
        "copied_files": copied_files,
        "generated_template_files": len(TEMPLATES),
        "excluded_review_required_files": len({
            Path(item["path"])
            for item in inventory["findings"]
            if item["intended_public_status"] == "REVIEW_REQUIRED"
        }),
        "review_required_findings": sum(
            item["intended_public_status"] == "REVIEW_REQUIRED"
            for item in inventory["findings"]
        ),
    }
