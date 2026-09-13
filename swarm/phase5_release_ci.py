"""Run bounded offline checks against an exact sanitized release repository."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from swarm.phase5_release_repository import (
    _GitRunner,
    _load_policy as _load_repository_policy,
    _regular_bytes,
    _strict_json,
    _verify_repository,
    _worktree_paths,
)

_ROOT = Path(__file__).resolve().parents[1]
_POLICY = _ROOT / "config/phase5-release-ci.yaml"
_SCHEMA = _ROOT / "schemas/phase5-release-ci.schema.json"
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_SDK_SCRIPT = """import json
import pathlib
import sys

def deny(event, args):
    if event.startswith(("socket.", "subprocess.", "os.system", "os.exec", "ctypes.dlopen")):
        raise RuntimeError("forbidden validation capability")

sys.addaudithook(deny)
root = pathlib.Path.cwd()
schema = json.loads((root / "schemas/addon-manifest.schema.json").read_text(encoding="utf-8"))
document = (root / "docs/add-on-sdk.md").read_text(encoding="utf-8")
assert schema.get("title") == "Forgewarden Add-on Manifest"
assert schema.get("type") == "object"
assert schema.get("additionalProperties") is False
assert schema.get("required") == [
    "manifest_version", "id", "name", "version", "publisher", "description",
    "entrypoint", "capabilities", "permissions", "signature",
]
assert document.startswith("# ForgeWarden add-on manifest contract\\n")
print("SDK_CONTRACT_OK")
"""

_DEMO_SCRIPT = """import importlib.util
import json
import pathlib
import sys

def deny(event, args):
    if event.startswith(("socket.", "subprocess.", "os.system", "os.exec", "ctypes.dlopen")):
        raise RuntimeError("forbidden validation capability")

sys.addaudithook(deny)
root = pathlib.Path.cwd()
source = root / "swarm/mission_control_demo.py"
spec = importlib.util.spec_from_file_location("forgewarden_public_demo", source)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
actual = module.mission_control_demo_snapshot()
expected = json.loads((root / "console/demo-data.json").read_text(encoding="utf-8"))
assert actual == expected
assert actual["data_mode"] == "DEMO"
assert actual["safety"] == {
    "deployment": "DISABLED",
    "kill_switch": "ENGAGED",
    "mode": "DRY_RUN",
    "mutation_allowed": False,
}
assert actual["implementation"]["production_backend"] == "NOT_CONNECTED"
print("DEMO_PROVIDER_OK")
"""

_COMMANDS: dict[str, tuple[str, tuple[str, ...]]] = {
    "SDK_CONTRACT": ("PYTHON", ("-I", "-B", "-c", _SDK_SCRIPT)),
    "DEMO_PROVIDER": ("PYTHON", ("-I", "-B", "-c", _DEMO_SCRIPT)),
    "DEMO_JAVASCRIPT_SYNTAX": ("NODE", ("--check", "console/app.js")),
}
_RUNTIME_NAMES = {"PYTHON": "python3", "NODE": "node"}
_RESULT_KEYS = frozenset({
    "schema_version",
    "format",
    "track",
    "publication",
    "production_ready",
    "legal_status",
    "license_concluded",
    "license_declared",
    "branch",
    "root_commit_sha1",
    "tree_sha1",
    "file_count",
    "source_binding_sha256",
    "source_manifest_sha256",
    "provenance_sha256",
    "pending_gates",
    "safety",
})
_RESULT_SAFETY_KEYS = frozenset({
    "source_history_inherited",
    "extra_git_object_present",
    "git_remote_present",
    "hook_present",
    "alternate_object_store_present",
    "environment_identity_used",
    "network_accessed",
    "credential_accessed",
    "publication_performed",
    "deployment_performed",
    "authority_granted",
})


def _read_yaml(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("clean-export CI policy must be a bounded regular file")
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("clean-export CI policy must be an object")
    return value


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("clean-export CI schema must be a bounded regular file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("clean-export CI schema must be an object")
    return value


def _load_policy() -> dict[str, Any]:
    policy = _read_yaml(_POLICY)
    Draft202012Validator(_read_json(_SCHEMA)).validate(policy)
    if (policy["publication"] != "DISABLED" or policy["production_ready"]
            or policy["license_concluded"] != "NOASSERTION"
            or policy["license_declared"] != "NOASSERTION"
            or policy["legal_status"] != "PENDING"):
        raise ValueError("clean-export CI policy is not fail-closed")
    return policy


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def _repository_root(repository: Path) -> Path:
    supplied = Path(repository)
    if supplied.is_symlink():
        raise ValueError("clean-export repository must be a real directory")
    try:
        root = supplied.resolve(strict=True)
    except OSError as exc:
        raise ValueError("clean-export repository must be a real directory") from exc
    git_dir = root / ".git"
    if not root.is_dir() or git_dir.is_symlink() or not git_dir.is_dir():
        raise ValueError("clean-export repository must contain an owned Git directory")
    return root


def _validate_repository_result(
    result: dict[str, Any], expected_track: str, policy: dict[str, Any],
    repository_policy: dict[str, Any],
) -> None:
    if not isinstance(result, dict) or set(result) != _RESULT_KEYS:
        raise ValueError("release repository result shape is invalid")
    if (result["schema_version"] != "1"
            or result["format"] != policy["repository_format"]
            or result["track"] != expected_track
            or expected_track not in policy["tracks"]
            or result["publication"] != "DISABLED"
            or result["production_ready"] is not False
            or result["legal_status"] != "PENDING"
            or result["license_concluded"] != "NOASSERTION"
            or result["license_declared"] != "NOASSERTION"
            or result["branch"] != repository_policy["branch"]
            or result["pending_gates"] != policy["required_pending_gates"]):
        raise ValueError("release repository result violates the CI boundary")
    for key in ("root_commit_sha1", "tree_sha1"):
        if not isinstance(result[key], str) or not _SHA1.fullmatch(result[key]):
            raise ValueError("release repository Git binding is invalid")
    for key in (
        "source_binding_sha256", "source_manifest_sha256", "provenance_sha256",
    ):
        if not isinstance(result[key], str) or not _SHA256.fullmatch(result[key]):
            raise ValueError("release repository digest binding is invalid")
    if (not isinstance(result["file_count"], int)
            or isinstance(result["file_count"], bool)
            or result["file_count"] != len(policy["tracks"][expected_track]["required_files"])):
        raise ValueError("release repository file-count binding is invalid")
    safety = result["safety"]
    if (not isinstance(safety, dict) or set(safety) != _RESULT_SAFETY_KEYS
            or any(value is not False for value in safety.values())):
        raise ValueError("release repository safety result is invalid")


def _repository_snapshot(
    root: Path,
    result: dict[str, Any],
    policy: dict[str, Any],
    repository_policy: dict[str, Any],
) -> tuple[dict[str, bytes], dict[str, Any]]:
    expected_paths = set(policy["tracks"][result["track"]]["required_files"])
    actual_paths, actual_directories = _worktree_paths(root)
    expected_directories = {
        str(parent)
        for relative in expected_paths
        for parent in Path(relative).parents
        if str(parent) != "."
    }
    if actual_paths != expected_paths or actual_directories != expected_directories:
        raise ValueError("clean-export repository path set is invalid")
    files: dict[str, bytes] = {}
    total = 0
    for relative in sorted(expected_paths):
        data = _regular_bytes(root, relative, policy["limits"]["max_file_bytes"])
        files[relative] = data
        total += len(data)
    if total > policy["limits"]["max_total_bytes"]:
        raise ValueError("clean-export repository byte budget exceeded")

    manifest_bytes = files[policy["source_manifest_name"]]
    provenance_bytes = files[policy["provenance_name"]]
    if hashlib.sha256(manifest_bytes).hexdigest() != result["source_manifest_sha256"]:
        raise ValueError("clean-export source manifest binding is invalid")
    if hashlib.sha256(provenance_bytes).hexdigest() != result["provenance_sha256"]:
        raise ValueError("clean-export provenance binding is invalid")
    manifest = _strict_json(manifest_bytes)
    provenance = _strict_json(provenance_bytes)
    if (manifest.get("track") != result["track"]
            or manifest.get("publication") != "DISABLED"
            or manifest.get("source_binding_sha256") != result["source_binding_sha256"]):
        raise ValueError("clean-export manifest facts are invalid")
    if (provenance.get("track") != result["track"]
            or provenance.get("publication") != "DISABLED"
            or provenance.get("production_ready") is not False
            or provenance.get("legal_status") != "PENDING"
            or provenance.get("license_concluded") != "NOASSERTION"
            or provenance.get("license_declared") != "NOASSERTION"
            or provenance.get("dependency_closure") != "VERIFIED_OFFLINE"
            or provenance.get("source_binding_sha256") != result["source_binding_sha256"]
            or provenance.get("source_manifest_sha256") != result["source_manifest_sha256"]
            or provenance.get("unresolved_dependencies") != []
            or provenance.get("matched_values_included") is not False
            or not isinstance(provenance.get("pending_gates"), list)
            or not set(provenance["pending_gates"]).issubset(result["pending_gates"])
            or not isinstance(provenance.get("safety"), dict)
            or any(value is not False for value in provenance["safety"].values())):
        raise ValueError("clean-export provenance facts are invalid")

    runner = _GitRunner(root, repository_policy)
    _verify_repository(
        root,
        runner,
        files,
        repository_policy,
        result["root_commit_sha1"],
        result["tree_sha1"],
    )
    timestamp = int(datetime.fromisoformat(repository_policy["author_date"]).timestamp())
    expected_commit = (
        f"tree {result['tree_sha1']}\n"
        f"author {repository_policy['author_name']} "
        f"<{repository_policy['author_email']}> {timestamp} +0000\n"
        f"committer {repository_policy['committer_name']} "
        f"<{repository_policy['committer_email']}> {timestamp} +0000\n\n"
        f"{repository_policy['commit_message']}\n"
    ).encode("utf-8")
    actual_commit = runner.run(
        ["cat-file", "commit", result["root_commit_sha1"]],
    ).stdout
    if actual_commit != expected_commit:
        raise ValueError("clean-export root commit metadata is invalid")
    return files, provenance


def _command_plan(
    track: str, policy: dict[str, Any],
) -> list[tuple[str, str, tuple[str, ...], str]]:
    configured = policy["tracks"][track]["checks"]
    if not isinstance(configured, list) or not configured:
        raise ValueError("clean-export command plan is empty")
    if len(configured) > policy["limits"]["max_commands"]:
        raise ValueError("clean-export command budget exceeded")
    plan = []
    seen: set[str] = set()
    for item in configured:
        if not isinstance(item, dict) or set(item) != {"id", "runtime", "success_marker"}:
            raise ValueError("clean-export check definition is invalid")
        check_id = item["id"]
        if check_id in seen or check_id not in _COMMANDS:
            raise ValueError("clean-export check is duplicated or unknown")
        runtime, args = _COMMANDS[check_id]
        if runtime != item["runtime"]:
            raise ValueError("clean-export runtime binding is invalid")
        seen.add(check_id)
        plan.append((check_id, runtime, args, item["success_marker"]))
    return plan


def _runtime(runtime: str, policy: dict[str, Any]) -> str:
    name = _RUNTIME_NAMES.get(runtime)
    if name is None:
        raise ValueError("clean-export runtime is not allowlisted")
    search = ":".join(policy["runtime_search_path"])
    executable = shutil.which(name, path=search)
    if not executable:
        raise ValueError("clean-export runtime is unavailable")
    path = Path(executable)
    if (not path.is_absolute() or str(path.parent) not in policy["runtime_search_path"]
            or not path.is_file()):
        raise ValueError("clean-export runtime path is invalid")
    return str(path)


def _run_check(
    root: Path,
    *,
    check_id: str,
    runtime: str,
    args: tuple[str, ...],
    marker: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    executable = _runtime(runtime, policy)
    with tempfile.TemporaryDirectory(prefix="forgewarden-release-ci-") as temporary:
        environment = {
            "PATH": ":".join(policy["runtime_search_path"]),
            "HOME": temporary,
            "TMPDIR": temporary,
            "LC_ALL": "C",
            "TZ": "UTC",
            "PYTHONHASHSEED": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
            "NO_COLOR": "1",
        }
        try:
            result = subprocess.run(
                [executable, *args],
                cwd=root,
                env=environment,
                shell=False,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=policy["limits"]["max_command_seconds"],
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("clean-export check failed or timed out") from exc
    output_size = len(result.stdout) + len(result.stderr)
    if output_size > policy["limits"]["max_output_bytes"]:
        raise ValueError("clean-export check output exceeded its bound")
    if result.returncode != 0:
        raise ValueError("clean-export check failed")
    if marker == "NO_OUTPUT":
        if result.stdout or result.stderr:
            raise ValueError("clean-export check produced unexpected output")
    elif result.stdout != (marker + "\n").encode("utf-8") or result.stderr:
        raise ValueError("clean-export check success marker is invalid")
    return {
        "check_id": check_id,
        "runtime": runtime,
        "argv_sha256": hashlib.sha256(_canonical([runtime, *args])).hexdigest(),
        "returncode": 0,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "output_bytes": output_size,
        "passed": True,
    }


def run_release_ci(
    repository: Path,
    *,
    expected_track: str,
    expected_repository_result: dict[str, Any],
) -> dict[str, Any]:
    """Validate one exact local public candidate with no external authority."""
    if not isinstance(expected_track, str) or not expected_track:
        raise ValueError("expected clean-export track is invalid")
    policy = _load_policy()
    repository_policy = _load_repository_policy()
    _validate_repository_result(
        expected_repository_result, expected_track, policy, repository_policy)
    root = _repository_root(repository)
    files, provenance = _repository_snapshot(
        root, expected_repository_result, policy, repository_policy)
    before = {path: hashlib.sha256(data).hexdigest() for path, data in files.items()}
    plan = _command_plan(expected_track, policy)
    checks = [
        _run_check(
            root,
            check_id=check_id,
            runtime=runtime,
            args=args,
            marker=marker,
            policy=policy,
        )
        for check_id, runtime, args, marker in plan
    ]
    after_files, after_provenance = _repository_snapshot(
        root, expected_repository_result, policy, repository_policy)
    after = {
        path: hashlib.sha256(data).hexdigest()
        for path, data in after_files.items()
    }
    if before != after or provenance != after_provenance:
        raise ValueError("clean-export repository changed during validation")

    plan_facts = [
        {
            "check_id": check_id,
            "runtime": runtime,
            "argv_sha256": hashlib.sha256(_canonical([runtime, *args])).hexdigest(),
            "success_marker": marker,
        }
        for check_id, runtime, args, marker in plan
    ]
    output: dict[str, Any] = {
        "schema_version": "1",
        "format": policy["format"],
        "track": expected_track,
        "publication": "DISABLED",
        "production_ready": False,
        "legal_status": "PENDING",
        "license_concluded": "NOASSERTION",
        "license_declared": "NOASSERTION",
        "root_commit_sha1": expected_repository_result["root_commit_sha1"],
        "tree_sha1": expected_repository_result["tree_sha1"],
        "source_binding_sha256": expected_repository_result["source_binding_sha256"],
        "source_manifest_sha256": expected_repository_result["source_manifest_sha256"],
        "provenance_sha256": expected_repository_result["provenance_sha256"],
        "repository_result_sha256": hashlib.sha256(
            _canonical(expected_repository_result)).hexdigest(),
        "command_plan_sha256": hashlib.sha256(_canonical(plan_facts)).hexdigest(),
        "checks": checks,
        "pending_gates": list(policy["required_pending_gates"]),
        "safety": {
            "private_core_loaded": False,
            "ambient_identity_used": False,
            "ambient_credential_used": False,
            "generated_state_written": False,
            "network_accessed": False,
            "package_installed": False,
            "git_remote_accessed": False,
            "publication_performed": False,
            "deployment_performed": False,
            "authority_granted": False,
        },
    }
    encoded = _canonical(output)
    if len(encoded) > policy["limits"]["max_output_bytes"]:
        raise ValueError("clean-export CI evidence exceeded its bound")
    return output
