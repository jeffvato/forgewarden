"""Construct and verify a deterministic local release-candidate repository."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from swarm.phase5_release_provenance import build_release_provenance

_ROOT = Path(__file__).resolve().parents[1]
_POLICY = _ROOT / "config/phase5-release-repository.yaml"
_SCHEMA = _ROOT / "schemas/phase5-release-repository.schema.json"
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_GIT = frozenset({
    "add", "cat-file", "commit-tree", "config", "diff", "for-each-ref",
    "fsck", "init", "ls-tree", "rev-list", "rev-parse", "status",
    "symbolic-ref", "update-ref", "write-tree",
})
_ALLOWED_LOCAL_CONFIG = frozenset({
    "core.bare",
    "core.filemode",
    "core.ignorecase",
    "core.logallrefupdates",
    "core.precomposeunicode",
    "core.repositoryformatversion",
    "extensions.objectformat",
})


def _read_yaml(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("release repository policy must be a bounded regular file")
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("release repository policy must be an object")
    return value


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("release repository schema must be a bounded regular file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("release repository schema must be an object")
    return value


def _load_policy() -> dict[str, Any]:
    policy = _read_yaml(_POLICY)
    Draft202012Validator(_read_json(_SCHEMA)).validate(policy)
    if (policy["publication"] != "DISABLED" or policy["production_ready"]
            or policy["license_concluded"] != "NOASSERTION"
            or policy["license_declared"] != "NOASSERTION"
            or policy["legal_status"] != "PENDING"):
        raise ValueError("release repository policy is not fail-closed")
    return policy


def encode_release_provenance(provenance: dict[str, Any]) -> bytes:
    """Return the canonical repository form of validated provenance facts."""
    if not isinstance(provenance, dict):
        raise ValueError("release provenance must be an object")
    return (json.dumps(
        provenance, indent=2, sort_keys=True, allow_nan=False,
    ) + "\n").encode("utf-8")


def _strict_json(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {value}")),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("release manifest is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("release manifest is invalid")
    return value


def _regular_bytes(root: Path, relative: str, max_bytes: int) -> bytes:
    path = root.joinpath(*PurePosixPath(relative).parts)
    if path.is_symlink():
        raise ValueError("release input contains a link")
    try:
        info = path.stat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError("release input file is missing") from exc
    if not stat.S_ISREG(info.st_mode) or root not in resolved.parents:
        raise ValueError("release input must be a regular confined file")
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("release repository per-file budget exceeded")
    return data


def _candidate_root(candidate: Path) -> Path:
    supplied = Path(candidate)
    if supplied.is_symlink():
        raise ValueError("release candidate must be a real directory")
    try:
        root = supplied.resolve(strict=True)
    except OSError as exc:
        raise ValueError("release candidate must be a real directory") from exc
    if not root.is_dir() or (root / ".git").exists():
        raise ValueError("release candidate must be a non-repository directory")
    return root


def _destination_root(candidate: Path, destination: Path) -> Path:
    supplied = Path(destination)
    if not supplied.is_absolute():
        supplied = Path.cwd() / supplied
    if ".." in supplied.parts or supplied.exists() or supplied.is_symlink():
        raise FileExistsError("release repository destination must be new")
    for ancestor in supplied.parents:
        if ancestor.exists() and (ancestor.is_symlink() or not ancestor.is_dir()):
            raise ValueError("release repository destination ancestry is unsafe")
    resolved = supplied.resolve(strict=False)
    if candidate == resolved or candidate in resolved.parents or resolved in candidate.parents:
        raise ValueError("release repository destination overlaps its candidate")
    if not resolved.parent.is_dir() or resolved.parent.is_symlink():
        raise ValueError("release repository destination parent must be a real directory")
    return resolved


def _manifest_snapshot(
    root: Path, policy: dict[str, Any], *, expected_manifest_sha256: str,
) -> tuple[bytes, dict[str, bytes]]:
    manifest_name = policy["source_manifest_name"]
    manifest_bytes = _regular_bytes(root, manifest_name, policy["limits"]["max_file_bytes"])
    if hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_sha256:
        raise ValueError("release source manifest digest is invalid")
    manifest = _strict_json(manifest_bytes)
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise ValueError("release manifest file list is invalid")
    captured: dict[str, bytes] = {manifest_name: manifest_bytes}
    total = len(manifest_bytes)
    seen = {manifest_name.casefold()}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
            raise ValueError("release manifest file entry is invalid")
        relative = entry["path"]
        if not isinstance(relative, str) or not relative:
            raise ValueError("release manifest path is invalid")
        path = PurePosixPath(relative)
        if (str(path) != relative or relative.startswith("/") or "\\" in relative
                or ":" in relative or any(part in {"", ".", ".."} for part in path.parts)
                or len(relative.encode("utf-8")) > policy["limits"]["max_path_bytes"]):
            raise ValueError("release manifest path is invalid")
        folded = relative.casefold()
        if folded in seen:
            raise ValueError("release manifest path is duplicated")
        seen.add(folded)
        data = _regular_bytes(root, relative, policy["limits"]["max_file_bytes"])
        if (not isinstance(entry["size"], int) or isinstance(entry["size"], bool)
                or entry["size"] != len(data) or not isinstance(entry["sha256"], str)
                or not _SHA256.fullmatch(entry["sha256"])
                or entry["sha256"] != hashlib.sha256(data).hexdigest()):
            raise ValueError("release manifest file digest is invalid")
        captured[relative] = data
        total += len(data)
    if (len(captured) + 1 > policy["limits"]["max_files"]
            or total > policy["limits"]["max_total_bytes"]):
        raise ValueError("release repository output budget exceeded")
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    expected_directories = {
        str(parent)
        for relative in captured
        for parent in PurePosixPath(relative).parents
        if str(parent) != "."
    }
    for item in root.rglob("*"):
        relative = item.relative_to(root).as_posix()
        if item.is_symlink():
            raise ValueError("release candidate contains a link")
        if item.is_file():
            actual_files.add(relative)
        elif item.is_dir():
            actual_directories.add(relative)
        else:
            raise ValueError("release candidate contains a special file")
    if actual_files != set(captured) or actual_directories != expected_directories:
        raise ValueError("release candidate contains extra or missing paths")
    return manifest_bytes, captured


def _git_environment(policy: dict[str, Any]) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "TZ": "UTC",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": policy["author_name"],
        "GIT_AUTHOR_EMAIL": policy["author_email"],
        "GIT_AUTHOR_DATE": policy["author_date"],
        "GIT_COMMITTER_NAME": policy["committer_name"],
        "GIT_COMMITTER_EMAIL": policy["committer_email"],
        "GIT_COMMITTER_DATE": policy["committer_date"],
    }


class _GitRunner:
    def __init__(self, root: Path, policy: dict[str, Any]) -> None:
        self.root = root
        self.policy = policy
        self.calls = 0
        self.git = shutil.which("git", path="/usr/bin:/bin")
        if not self.git:
            raise ValueError("trusted Git executable is unavailable")

    def run(
        self, args: list[str], *, input_data: bytes | None = None,
        allowed_returncodes: tuple[int, ...] = (0,),
    ) -> subprocess.CompletedProcess[bytes]:
        if not args or args[0] not in _ALLOWED_GIT:
            raise ValueError("release repository Git operation is not allowlisted")
        self.calls += 1
        if self.calls > self.policy["limits"]["max_git_commands"]:
            raise ValueError("release repository Git-command budget exceeded")
        try:
            result = subprocess.run(
                [self.git, "-C", str(self.root), *args],
                input=input_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=False,
                timeout=15,
                env=_git_environment(self.policy),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("release repository Git operation failed") from exc
        if (result.returncode not in allowed_returncodes
                or len(result.stdout) + len(result.stderr)
                > self.policy["limits"]["max_git_output_bytes"]):
            raise ValueError("release repository Git operation failed")
        return result


def _write_files(root: Path, files: dict[str, bytes], policy: dict[str, Any]) -> None:
    total = 0
    for relative, data in sorted(files.items()):
        if len(data) > policy["limits"]["max_file_bytes"]:
            raise ValueError("release repository per-file budget exceeded")
        total += len(data)
        if total > policy["limits"]["max_total_bytes"]:
            raise ValueError("release repository total-byte budget exceeded")
        target = root.joinpath(*PurePosixPath(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if target.parent.is_symlink():
            raise ValueError("release repository output ancestry is unsafe")
        with target.open("xb") as handle:
            handle.write(data)
        target.chmod(0o600)


def _worktree_paths(root: Path) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    for item in root.rglob("*"):
        relative = item.relative_to(root).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        if item.is_symlink():
            raise ValueError("release repository contains a link")
        if item.is_file():
            files.add(relative)
        elif item.is_dir():
            directories.add(relative)
        else:
            raise ValueError("release repository contains a special file")
    return files, directories


def _parse_tree(raw: bytes) -> dict[str, tuple[str, str, str]]:
    entries: dict[str, tuple[str, str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, separator, encoded_path = record.partition(b"\t")
        fields = metadata.decode("ascii").split(" ")
        path = encoded_path.decode("utf-8")
        if (not separator or len(fields) != 3 or fields[1] != "blob"
                or fields[0] != "100644" or path in entries):
            raise ValueError("release repository tree is invalid")
        entries[path] = (fields[0], fields[1], fields[2])
    return entries


def _verify_repository(
    root: Path, runner: _GitRunner, files: dict[str, bytes],
    policy: dict[str, Any], commit: str, tree: str,
) -> None:
    if runner.run(["symbolic-ref", "--quiet", "--short", "HEAD"]).stdout.strip() != b"main":
        raise ValueError("release repository branch is invalid")
    if runner.run(["rev-parse", "--verify", "HEAD^{commit}"]).stdout.decode().strip() != commit:
        raise ValueError("release repository commit binding is invalid")
    if runner.run(["rev-parse", "--verify", "HEAD^{tree}"]).stdout.decode().strip() != tree:
        raise ValueError("release repository tree binding is invalid")
    if runner.run(["rev-list", "--all", "--count"]).stdout.strip() != b"1":
        raise ValueError("release repository must contain one commit")
    parents = runner.run(["rev-list", "--parents", "--max-count=1", "HEAD"]).stdout.decode().split()
    if parents != [commit]:
        raise ValueError("release repository commit must be a root")
    refs = runner.run(["for-each-ref", "--format=%(refname)"]).stdout.decode().splitlines()
    if refs != ["refs/heads/main"]:
        raise ValueError("release repository contains an extra ref")
    tree_entries = _parse_tree(
        runner.run(["ls-tree", "-rz", "--full-tree", "HEAD"]).stdout)
    if set(tree_entries) != set(files):
        raise ValueError("release repository tree path set is invalid")
    if runner.run(["status", "--porcelain=v1"]).stdout:
        raise ValueError("release repository worktree is dirty")
    runner.run(["diff", "--quiet", "HEAD", "--"])
    worktree_files, worktree_directories = _worktree_paths(root)
    expected_directories = {
        str(parent)
        for relative in files
        for parent in PurePosixPath(relative).parents
        if str(parent) != "."
    }
    if worktree_files != set(files) or worktree_directories != expected_directories:
        raise ValueError("release repository worktree path set is invalid")
    for relative, expected in files.items():
        if _regular_bytes(root, relative, policy["limits"]["max_file_bytes"]) != expected:
            raise ValueError("release repository worktree content is invalid")
    alternates = root / ".git" / "objects" / "info" / "alternates"
    hooks = root / ".git" / "hooks"
    if alternates.exists() or alternates.is_symlink() or hooks.exists() or hooks.is_symlink():
        raise ValueError("release repository contains hooks or alternates")
    config_lines = runner.run(["config", "--local", "--list"]).stdout.decode().splitlines()
    for line in config_lines:
        key = line.partition("=")[0].casefold()
        if key not in _ALLOWED_LOCAL_CONFIG:
            raise ValueError("release repository local configuration is unsafe")
    reachable = {
        line.split(" ", 1)[0]
        for line in runner.run(["rev-list", "--objects", "--all"]).stdout.decode().splitlines()
    }
    all_objects = set(
        runner.run([
            "cat-file", "--batch-all-objects", "--batch-check=%(objectname)",
        ]).stdout.decode().splitlines()
    )
    if not reachable or reachable != all_objects:
        raise ValueError("release repository contains unreachable or inherited objects")
    runner.run(["fsck", "--strict", "--no-reflogs", "--unreachable", "--no-progress"])


def _cleanup(destination: Path) -> None:
    if destination.is_symlink():
        destination.unlink()
    elif destination.exists():
        shutil.rmtree(destination)


def build_release_repository(
    candidate: Path,
    destination: Path,
    *,
    expected_track: str,
    expected_source_commit: str,
    expected_manifest_sha256: str,
    expected_provenance_sha256: str,
) -> dict[str, Any]:
    """Create one verified local root commit from exact sanitized inputs."""
    if not isinstance(expected_track, str) or not expected_track:
        raise ValueError("expected release track is invalid")
    if not isinstance(expected_source_commit, str) or not re.fullmatch(
            r"[0-9a-f]{40}(?:[0-9a-f]{24})?", expected_source_commit):
        raise ValueError("expected private source commit is invalid")
    if (not isinstance(expected_manifest_sha256, str)
            or not _SHA256.fullmatch(expected_manifest_sha256)
            or not isinstance(expected_provenance_sha256, str)
            or not _SHA256.fullmatch(expected_provenance_sha256)):
        raise ValueError("expected release digest is invalid")

    policy = _load_policy()
    candidate_root = _candidate_root(candidate)
    destination_root = _destination_root(candidate_root, destination)
    provenance = build_release_provenance(
        candidate_root,
        expected_track=expected_track,
        expected_source_commit=expected_source_commit,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    provenance_bytes = encode_release_provenance(provenance)
    if hashlib.sha256(provenance_bytes).hexdigest() != expected_provenance_sha256:
        raise ValueError("release provenance digest is invalid")
    _, files = _manifest_snapshot(
        candidate_root, policy, expected_manifest_sha256=expected_manifest_sha256)
    provenance_name = policy["provenance_name"]
    if provenance_name.casefold() in {path.casefold() for path in files}:
        raise ValueError("release provenance path collides with candidate content")
    files[provenance_name] = provenance_bytes
    if len(files) > policy["limits"]["max_files"]:
        raise ValueError("release repository file-count budget exceeded")

    destination_root.mkdir(mode=0o700)
    try:
        _write_files(destination_root, files, policy)
        after = build_release_provenance(
            candidate_root,
            expected_track=expected_track,
            expected_source_commit=expected_source_commit,
            expected_manifest_sha256=expected_manifest_sha256,
        )
        if after != provenance:
            raise ValueError("release candidate drifted during repository construction")

        runner = _GitRunner(destination_root, policy)
        runner.run([
            "init", "--quiet", "--initial-branch=" + policy["branch"],
            "--object-format=" + policy["object_format"],
        ])
        hooks = destination_root / ".git" / "hooks"
        if hooks.exists():
            shutil.rmtree(hooks)
        runner.run(["config", "--local", "core.logAllRefUpdates", "false"])
        runner.run(["add", "--all", "--", "."])
        tree = runner.run(["write-tree"]).stdout.decode().strip()
        if not _SHA1.fullmatch(tree):
            raise ValueError("release repository tree identifier is invalid")
        commit = runner.run(
            ["commit-tree", tree],
            input_data=(policy["commit_message"] + "\n").encode("utf-8"),
        ).stdout.decode().strip()
        if not _SHA1.fullmatch(commit):
            raise ValueError("release repository commit identifier is invalid")
        runner.run(["update-ref", "refs/heads/main", commit])
        runner.run(["symbolic-ref", "HEAD", "refs/heads/main"])
        _verify_repository(destination_root, runner, files, policy, commit, tree)

        result: dict[str, Any] = {
            "schema_version": "1",
            "format": policy["format"],
            "track": expected_track,
            "publication": "DISABLED",
            "production_ready": False,
            "legal_status": "PENDING",
            "license_concluded": "NOASSERTION",
            "license_declared": "NOASSERTION",
            "branch": policy["branch"],
            "root_commit_sha1": commit,
            "tree_sha1": tree,
            "file_count": len(files),
            "source_binding_sha256": provenance["source_binding_sha256"],
            "source_manifest_sha256": expected_manifest_sha256,
            "provenance_sha256": expected_provenance_sha256,
            "pending_gates": list(policy["required_pending_gates"]),
            "safety": {
                "source_history_inherited": False,
                "extra_git_object_present": False,
                "git_remote_present": False,
                "hook_present": False,
                "alternate_object_store_present": False,
                "environment_identity_used": False,
                "network_accessed": False,
                "credential_accessed": False,
                "publication_performed": False,
                "deployment_performed": False,
                "authority_granted": False,
            },
        }
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if expected_source_commit.encode("ascii") in encoded:
            raise ValueError("release repository result exposes private source state")
        return result
    except Exception:
        _cleanup(destination_root)
        raise
