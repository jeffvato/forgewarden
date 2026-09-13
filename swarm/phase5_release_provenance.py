"""Offline dependency closure and sanitized SBOM-candidate generation."""
from __future__ import annotations

import ast
import hashlib
import json
import re
import stat
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .phase5_release_candidate import (
    _CONTENT_PATTERNS,
    _load_contract,
    _policy_sha256,
    _source_binding_sha256,
    _validate_public_content,
)

_ROOT = Path(__file__).resolve().parents[1]
_POLICY = _ROOT / "config/phase5-release-provenance.yaml"
_SCHEMA = _ROOT / "schemas/phase5-release-provenance.schema.json"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REMOTE = re.compile(r"(?i)(?:https?:)?//|\b(?:data|javascript):")
_JS_FETCH = re.compile(r"\bfetch\s*\(\s*(['\"])([^'\"]+)\1")
_JS_FORBIDDEN = re.compile(
    r"(?m)\b(?:eval|Function|require)\s*\(|\bimport\s*\(|^\s*import\s+|\bfrom\s*['\"]")
_FENCED_PYTHON = re.compile(r"```(?:python|py)\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_CSS_URL = re.compile(r"\burl\s*\(\s*(['\"]?)([^)'\"]+)\1\s*\)", re.IGNORECASE)


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-standard JSON constant is denied")


def _strict_json(text: str) -> Any:
    return json.loads(text, parse_constant=_reject_json_constant)


def _bounded_object(path: Path, *, yaml_input: bool, max_bytes: int = 1024 * 1024) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise ValueError("release provenance input must be a bounded regular file")
    text = path.read_text(encoding="utf-8")
    value = yaml.safe_load(text) if yaml_input else _strict_json(text)
    if not isinstance(value, dict):
        raise ValueError("release provenance input must be an object")
    return value


def _load_policy() -> dict[str, Any]:
    policy = _bounded_object(_POLICY, yaml_input=True)
    Draft202012Validator(_bounded_object(_SCHEMA, yaml_input=False)).validate(policy)
    if (policy["publication"] != "DISABLED" or policy["license_concluded"] != "NOASSERTION"
            or policy["license_declared"] != "NOASSERTION" or policy["legal_status"] != "PENDING"
            or policy["production_ready"] is not False):
        raise ValueError("release provenance policy is not fail-closed")
    return policy


def _policy_digest(policy: dict[str, Any]) -> str:
    encoded = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _candidate_root(path: Path) -> Path:
    supplied = Path(path)
    if supplied.is_symlink():
        raise ValueError("release candidate must be a real directory")
    try:
        root = supplied.resolve(strict=True)
    except OSError as exc:
        raise ValueError("release candidate must be a real directory") from exc
    if not root.is_dir():
        raise ValueError("release candidate must be a real directory")
    return root


def _relative_path(value: object, max_bytes: int) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > max_bytes:
        raise ValueError("release candidate path is invalid")
    path = PurePosixPath(value)
    if (value.startswith("/") or "\\" in value or ":" in value or str(path) != value
            or any(part in {"", ".", ".."} for part in path.parts)):
        raise ValueError("release candidate path is invalid")
    return value


def _regular_bytes(root: Path, relative: str, max_bytes: int) -> bytes:
    path = root.joinpath(*PurePosixPath(relative).parts)
    if path.is_symlink():
        raise ValueError("release candidate file must be regular")
    try:
        info = path.stat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError("release candidate file must be regular") from exc
    if not stat.S_ISREG(info.st_mode) or root not in resolved.parents:
        raise ValueError("release candidate file must be regular")
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if not data or len(data) > max_bytes:
        raise ValueError("release candidate file violates its byte budget")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("release candidate file must be UTF-8 text") from exc
    return data


def _manifest(
    root: Path, policy: dict[str, Any], *, expected_track: str,
    expected_source_commit: str, expected_manifest_sha256: str,
) -> tuple[dict[str, Any], list[tuple[str, bytes]], str]:
    if not _SHA256.fullmatch(expected_manifest_sha256):
        raise ValueError("expected release manifest digest is invalid")
    manifest_name = policy["source_manifest_name"]
    raw = _regular_bytes(root, manifest_name, policy["limits"]["max_manifest_bytes"])
    if hashlib.sha256(raw).hexdigest() != expected_manifest_sha256:
        raise ValueError("release manifest digest does not match")
    manifest = _strict_json(raw.decode("utf-8"))
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "track", "publication", "source_binding_sha256",
        "policy_sha256", "matched_values_included", "file_count", "total_bytes", "files",
    }:
        raise ValueError("release manifest shape is invalid")
    profile, export_policy, allowlist = _load_contract(expected_track)
    export_digest = _policy_sha256(profile, export_policy)
    if (manifest["schema_version"] != "1" or manifest["track"] != expected_track
            or manifest["publication"] != "DISABLED" or manifest["matched_values_included"] is not False
            or manifest["policy_sha256"] != export_digest
            or manifest["source_binding_sha256"] != _source_binding_sha256(
                expected_source_commit, export_digest)):
        raise ValueError("release manifest binding is invalid")
    entries = manifest["files"]
    if (not isinstance(entries, list) or len(entries) != len(allowlist)
            or not isinstance(manifest["file_count"], int)
            or isinstance(manifest["file_count"], bool)
            or manifest["file_count"] != len(entries)
            or not isinstance(manifest["total_bytes"], int)
            or isinstance(manifest["total_bytes"], bool)):
        raise ValueError("release manifest file count is invalid")
    files: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    total = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
            raise ValueError("release manifest file entry is invalid")
        relative = _relative_path(entry["path"], policy["limits"]["max_path_bytes"])
        folded = relative.casefold()
        if folded in seen or not isinstance(entry["size"], int) or isinstance(entry["size"], bool):
            raise ValueError("release manifest file entry is invalid")
        if not isinstance(entry["sha256"], str) or not _SHA256.fullmatch(entry["sha256"]):
            raise ValueError("release manifest file entry is invalid")
        seen.add(folded)
        data = _regular_bytes(root, relative, policy["limits"]["max_file_bytes"])
        if entry["size"] != len(data) or entry["sha256"] != hashlib.sha256(data).hexdigest():
            raise ValueError("release candidate file digest is invalid")
        _validate_public_content(data)
        total += len(data)
        files.append((relative, data))
    if sorted(path for path, _ in files) != allowlist or manifest["total_bytes"] != total:
        raise ValueError("release manifest allowlist or aggregate size is invalid")
    if total > policy["limits"]["max_total_bytes"] or expected_source_commit in raw.decode("utf-8"):
        raise ValueError("release manifest exposes prohibited source state")
    expected_paths = {manifest_name, *allowlist}
    actual_paths: set[str] = set()
    expected_directories = {str(parent) for value in expected_paths for parent in PurePosixPath(value).parents
                            if str(parent) != "."}
    actual_directories: set[str] = set()
    for item in root.rglob("*"):
        relative = item.relative_to(root).as_posix()
        if item.is_symlink():
            raise ValueError("release candidate contains a symlink")
        if item.is_file():
            actual_paths.add(relative)
        elif item.is_dir():
            actual_directories.add(relative)
        else:
            raise ValueError("release candidate contains a special file")
    if actual_paths != expected_paths or actual_directories != expected_directories or (root / ".git").exists():
        raise ValueError("release candidate contains extra or missing paths")
    return manifest, files, export_digest


def _dependency(source: str, target: str, classification: str) -> dict[str, str]:
    return {
        "source": source,
        "target": target,
        "classification": classification,
        "license_concluded": "NOASSERTION",
        "license_declared": "NOASSERTION",
    }


def _python_dependencies(source: str, text: str, allowed: set[str]) -> list[dict[str, str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise ValueError("release Python source is invalid") from exc
    dependencies: list[dict[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [item.name.split(".", 1)[0] for item in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                raise ValueError("relative or unresolved Python import is denied")
            names = [node.module.split(".", 1)[0]]
        else:
            names = []
        for name in names:
            if name not in allowed:
                raise ValueError("undeclared or private Python dependency is denied")
            dependencies.append(_dependency(source, name, "STANDARD_LIBRARY"))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {
            "eval", "exec", "compile", "__import__",
        }:
            raise ValueError("dynamic Python evaluation or import is denied")
    return dependencies


class _AssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[str] = []
        self.inline_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "script":
            if values.get("src"):
                self.references.append(str(values["src"]))
            else:
                self.inline_script = True
        if tag == "link" and values.get("href"):
            self.references.append(str(values["href"]))
        if tag in {"audio", "embed", "iframe", "img", "source", "video"} and values.get("src"):
            self.references.append(str(values["src"]))


def _local_reference(source: str, value: str, *, asset_root: str, included: set[str]) -> dict[str, str]:
    if _REMOTE.search(value) or "\\" in value or ":" in value:
        raise ValueError("remote or unsafe asset reference is denied")
    relative_value = value[1:] if value.startswith("/") else value
    path = PurePosixPath(relative_value)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("unsafe local asset reference is denied")
    target = (PurePosixPath(asset_root) / path).as_posix() if asset_root else path.as_posix()
    if target not in included:
        raise ValueError("unresolved or cross-track asset reference is denied")
    return _dependency(source, target, "LOCAL_INCLUDED")


def _scan_file(
    source: str, data: bytes, *, track_policy: dict[str, Any], included: set[str],
    allowed_schema_identifiers: set[str],
) -> list[dict[str, str]]:
    text = data.decode("utf-8")
    suffix = PurePosixPath(source).suffix.lower()
    if suffix == ".py":
        return _python_dependencies(source, text, set(track_policy["python_stdlib"]))
    if suffix == ".md":
        if _REMOTE.search(text):
            raise ValueError("remote documentation reference is denied")
        dependencies: list[dict[str, str]] = []
        for block in _FENCED_PYTHON.findall(text):
            dependencies.extend(_python_dependencies(source, block, set(track_policy["python_stdlib"])))
        return dependencies
    if suffix == ".js":
        if _REMOTE.search(text) or _JS_FORBIDDEN.search(text):
            raise ValueError("remote, dynamic, or imported JavaScript is denied")
        matches = list(_JS_FETCH.finditer(text))
        if len(matches) != len(re.findall(r"\bfetch\s*\(", text)):
            raise ValueError("dynamic JavaScript fetch target is denied")
        dependencies = []
        optional = set(track_policy["optional_api_interfaces"])
        for match in matches:
            value = match.group(2)
            if value in optional:
                dependencies.append(_dependency(source, value, "DECLARED_OPTIONAL_API_INTERFACE"))
            else:
                dependencies.append(_local_reference(
                    source, value, asset_root=track_policy["local_asset_root"], included=included))
        return dependencies
    if suffix == ".html":
        if _REMOTE.search(text):
            raise ValueError("remote HTML reference is denied")
        parser = _AssetParser()
        parser.feed(text)
        if parser.inline_script:
            raise ValueError("inline HTML script is denied")
        return [_local_reference(
            source, value, asset_root=track_policy["local_asset_root"], included=included)
                for value in parser.references]
    if suffix == ".css":
        if re.search(r"(?i)@import\b", text) or _REMOTE.search(text):
            raise ValueError("remote or imported stylesheet dependency is denied")
        matches = list(_CSS_URL.finditer(text))
        if len(matches) != len(re.findall(r"(?i)\burl\s*\(", text)):
            raise ValueError("dynamic stylesheet reference is denied")
        return [_local_reference(
            source, match.group(2), asset_root=track_policy["local_asset_root"], included=included)
                for match in matches]
    if suffix == ".json":
        value = _strict_json(text)
        dependencies = []
        stack = [value]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                if "$ref" in item:
                    raise ValueError("JSON Schema reference is denied")
                for key in ("$schema", "$id"):
                    if key in item:
                        identifier = item[key]
                        if identifier not in allowed_schema_identifiers:
                            raise ValueError("unknown schema identifier is denied")
                        dependencies.append(_dependency(
                            source, identifier, "NON_LOADING_SCHEMA_IDENTIFIER"))
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
        return dependencies
    raise ValueError("unsupported release candidate file type")


def _sanitize_output(encoded: bytes) -> None:
    without_hashes = re.sub(rb"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", b"HASH", encoded)
    for category, pattern in _CONTENT_PATTERNS:
        if category != "historical_commit" and pattern.search(without_hashes):
            raise ValueError("release provenance output contains prohibited metadata")


def build_release_provenance(
    candidate: Path, *, expected_track: str, expected_source_commit: str,
    expected_manifest_sha256: str,
) -> dict[str, Any]:
    """Validate one exact local export and return deterministic SBOM-candidate facts."""
    policy = _load_policy()
    if expected_track not in policy["tracks"]:
        raise ValueError("unsupported release provenance track")
    root = _candidate_root(candidate)
    manifest, files, export_policy_digest = _manifest(
        root, policy, expected_track=expected_track,
        expected_source_commit=expected_source_commit,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    track_policy = policy["tracks"][expected_track]
    roles = track_policy["file_roles"]
    included = {path for path, _ in files}
    if set(roles) != included:
        raise ValueError("release provenance file-role policy drifted")
    references: list[dict[str, str]] = []
    file_records = []
    for path, data in sorted(files):
        references.extend(_scan_file(
            path, data, track_policy=track_policy, included=included,
            allowed_schema_identifiers=set(policy["allowed_schema_identifiers"]),
        ))
        file_records.append({
            "path": path,
            "role": roles[path],
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "license_concluded": "NOASSERTION",
            "license_declared": "NOASSERTION",
        })
    unique_references = sorted(
        {tuple(sorted(item.items())) for item in references},
        key=lambda item: dict(item)["source"] + "\0" + dict(item)["target"],
    )
    if len(unique_references) != len(references):
        raise ValueError("duplicate dependency reference is denied")
    if len(references) > policy["limits"]["max_references"]:
        raise ValueError("release dependency-reference budget exceeded")
    result: dict[str, Any] = {
        "schema_version": "1",
        "format": policy["format"],
        "compatibility_target": policy["compatibility_target"],
        "track": expected_track,
        "standalone_class": track_policy["standalone_class"],
        "publication": "DISABLED",
        "production_ready": False,
        "legal_status": "PENDING",
        "license_concluded": "NOASSERTION",
        "license_declared": "NOASSERTION",
        "dependency_closure": "VERIFIED_OFFLINE",
        "source_binding_sha256": manifest["source_binding_sha256"],
        "source_manifest_sha256": expected_manifest_sha256,
        "export_policy_sha256": export_policy_digest,
        "provenance_policy_sha256": _policy_digest(policy),
        "matched_values_included": False,
        "files": file_records,
        "references": [dict(item) for item in unique_references],
        "unresolved_dependencies": [],
        "pending_gates": list(policy["required_pending_gates"]),
        "safety": {
            "network_accessed": False,
            "package_installation_performed": False,
            "provider_invoked": False,
            "credential_accessed": False,
            "git_remote_created": False,
            "publication_performed": False,
            "deployment_performed": False,
            "authority_granted": False,
        },
    }
    encoded = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > policy["limits"]["max_output_bytes"]:
        raise ValueError("release provenance output exceeds its byte budget")
    _sanitize_output(encoded)
    return result
