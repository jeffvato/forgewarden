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

_ROOT = Path(__file__).resolve().parents[1]
_READINESS_PROFILE = _ROOT / "config/phase5-release-readiness.yaml"
_READINESS_SCHEMA = _ROOT / "schemas/phase5-release-readiness.schema.json"
_EXPORT_POLICY = _ROOT / "config/phase5-public-export.yaml"
_EXPORT_SCHEMA = _ROOT / "schemas/phase5-public-export.schema.json"
_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_TEXT_SUFFIXES = frozenset({".css", ".html", ".js", ".json", ".md", ".py", ".txt", ".yaml", ".yml"})
_MEDIA_SUFFIXES = frozenset({
    ".avif", ".eot", ".gif", ".ico", ".jpeg", ".jpg", ".mp3", ".mp4",
    ".ogg", ".otf", ".pdf", ".png", ".svg", ".ttf", ".wav", ".webm", ".webp", ".woff", ".woff2",
})
_PROHIBITED_PARTS = frozenset({
    ".git", ".github", ".integration-runtime", ".pytest_cache", ".swarm",
    ".swarm-state", "__pycache__", "config", "evidence", "reviews", "tests",
})
_PROHIBITED_NAME_MARKERS = (
    "audit", "credential", "evidence", "history", "integrity", "private", "review", "secret",
)
_CONTENT_PATTERNS = (
    ("personal_identity", re.compile(
        rb"(?i)\b(author|owner|personal[-_ ]?name|user[-_ ]?name)\s*[:=]\s*['\"]?[a-z][a-z ._-]{4,}")),
    ("personal_email", re.compile(rb"(?i)\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b")),
    ("personal_home_path", re.compile(rb"(?i)(/home/[a-z0-9._-]+/|[a-z]:\\users\\[a-z0-9._-]+\\|/Users/[a-z0-9._-]+/)")),
    ("cloud_identifier", re.compile(
        rb"(?i)\b(?:azure[-_ ]?(?:tenant|subscription|client|registry|resource|deployment)(?:[-_ ]?(?:id|name))?|(?:tenant|subscription|client|registry|resource|deployment)[-_ ]?(?:id|name))\s*[:=]\s*['\"]?(?![A-Z-]*DEMO-)[a-z0-9][a-z0-9._:/-]{5,}")),
    ("internal_url_or_host", re.compile(
        rb"(?i)https?://(?:localhost|127\.0\.0\.1|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|[a-z0-9.-]+\.internal)(?=[:/\s]|$)")),
    ("machine_fingerprint", re.compile(
        rb"(?i)\b(machine[-_ ]?id|host[-_ ]?name|device[-_ ]?serial)\s*[:=]\s*['\"]?[a-z0-9][a-z0-9._-]{5,}")),
    ("historical_commit", re.compile(rb"(?i)(?<![0-9a-f])[0-9a-f]{40}(?:[0-9a-f]{24})?(?![0-9a-f])")),
    ("internal_record_identifier", re.compile(
        rb"(?i)\b(job|evidence|provider[-_ ]?session)[-_ ]?id\s*[:=]\s*['\"]?(?![A-Z-]*DEMO-)[a-z0-9][a-z0-9._:-]{5,}")),
    ("credential_shaped_content", re.compile(
        rb"(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(api[-_ ]?key|password|secret|token)\s*[:=]\s*(?:['\"][^'\"]{12,}['\"]|[a-z0-9][a-z0-9._/-]{11,}))")),
    ("customer_endpoint_identifier", re.compile(
        rb"(?i)\b(customer|tenant|endpoint)[-_ ]?id\s*[:=]\s*['\"]?(?![A-Z-]*DEMO-)[a-z0-9][a-z0-9._:-]{4,}")),
)


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
        _validate_public_path(path)
        normalized.append(value)
    return sorted(normalized)


def _validate_public_path(path: PurePosixPath) -> None:
    lowered_parts = {part.casefold() for part in path.parts}
    lowered_name = path.name.casefold()
    if (_PROHIBITED_PARTS.intersection(lowered_parts)
            or any(marker in lowered_name for marker in _PROHIBITED_NAME_MARKERS)
            or path.suffix.casefold() in _MEDIA_SUFFIXES
            or path.suffix.casefold() not in _TEXT_SUFFIXES):
        raise ValueError("allowlisted path belongs to a prohibited export class")


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
    _validate_public_content(data)
    return data


def _validate_public_content(data: bytes) -> None:
    if any(byte < 32 and byte not in {9, 10, 13} for byte in data):
        raise ValueError("allowlisted source contains control data")
    for category, pattern in _CONTENT_PATTERNS:
        if pattern.search(data):
            raise ValueError(f"allowlisted source contains prohibited {category}")


def _policy_sha256(profile: dict[str, Any], policy: dict[str, Any]) -> str:
    controls = {
        "profile": profile, "export_policy": policy,
        "prohibited_parts": sorted(_PROHIBITED_PARTS),
        "prohibited_name_markers": _PROHIBITED_NAME_MARKERS,
        "text_suffixes": sorted(_TEXT_SUFFIXES), "media_suffixes": sorted(_MEDIA_SUFFIXES),
        "content_patterns": [(name, pattern.pattern.decode("ascii"))
                             for name, pattern in _CONTENT_PATTERNS],
    }
    payload = json.dumps(controls, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _source_binding_sha256(source_commit: str, policy_sha256: str) -> str:
    """Bind private source state without publishing its historical commit ID."""
    if not _SHA.fullmatch(source_commit) or not re.fullmatch(r"[0-9a-f]{64}", policy_sha256):
        raise ValueError("public-export source binding input is invalid")
    payload = f"FORGEWARDEN_PUBLIC_SOURCE_BINDING_V1\0{source_commit}\0{policy_sha256}".encode()
    return hashlib.sha256(payload).hexdigest()


def _cleanup(destination: Path) -> None:
    if destination.is_symlink():
        destination.unlink()
    elif destination.exists():
        shutil.rmtree(destination)


def build_release_candidate(
    source: Path, destination: Path, *, track: str, expected_source_commit: str,
) -> dict[str, object]:
    """Copy one exact allowlisted track into a local, disposable candidate."""
    if not isinstance(expected_source_commit, str) or not _SHA.fullmatch(expected_source_commit):
        raise ValueError("expected public-export source commit is invalid")
    profile, policy, paths = _load_contract(track)
    source_root = _source_root(source)
    destination_root = _destination_root(source_root, destination)
    if _head(source_root) != expected_source_commit:
        raise ValueError("public-export source commit does not match the expected commit")

    destination_root.mkdir(mode=0o700)
    captured: dict[str, bytes] = {}
    try:
        total_bytes = 0
        files = []
        for relative in paths:
            data = _read_source_file(
                source_root, relative, expected_source_commit, policy["limits"]["max_file_bytes"])
            total_bytes += len(data)
            if total_bytes > policy["limits"]["max_total_bytes"]:
                raise ValueError("public-export aggregate byte budget exceeded")
            captured[relative] = data
            target = destination_root.joinpath(*PurePosixPath(relative).parts)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with target.open("xb") as handle:
                handle.write(data)
            files.append({
                "path": relative, "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })

        if _head(source_root) != expected_source_commit:
            raise ValueError("public-export source commit drifted during construction")
        for relative, before in captured.items():
            if _read_source_file(
                    source_root, relative, expected_source_commit,
                    policy["limits"]["max_file_bytes"]) != before:
                raise ValueError("allowlisted source drifted during construction")
        policy_sha256 = _policy_sha256(profile, policy)
        manifest: dict[str, object] = {
            "schema_version": "1", "track": track, "publication": "DISABLED",
            "source_binding_sha256": _source_binding_sha256(
                expected_source_commit, policy_sha256),
            "policy_sha256": policy_sha256,
            "matched_values_included": False, "file_count": len(files),
            "total_bytes": total_bytes, "files": files,
        }
        encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(encoded) > policy["limits"]["max_manifest_bytes"]:
            raise ValueError("public-export manifest budget exceeded")
        with (destination_root / policy["manifest_name"]).open("xb") as handle:
            handle.write(encoded)
        return manifest
    except Exception:
        _cleanup(destination_root)
        raise
