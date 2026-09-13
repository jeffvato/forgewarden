"""Aggregate Phase 5 technical proof without satisfying release authority gates."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

_ROOT = Path(__file__).resolve().parents[1]
_POLICY = _ROOT / "config/phase5-release-gate.yaml"
_SCHEMA = _ROOT / "schemas/phase5-release-gate.schema.json"
_TRACKS = ("PUBLIC_SDK", "SOURCE_AVAILABLE_DEMO")
_GATES = ("legal_review", "chain_of_title_review", "trademark_media_review", "dependency_sbom_review", "reproducible_build_review", "clean_export_ci_review", "customer_root_release_approval")
_SAFETY = ("publication_performed", "deployment_performed", "authority_granted", "network_accessed", "credential_accessed", "license_selected", "human_gate_satisfied")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(char in "0123456789abcdef" for char in value)


def _policy() -> dict[str, Any]:
    value = yaml.safe_load(_POLICY.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != "1" or value.get("format") != "FORGEWARDEN_RELEASE_ASSURANCE_GATE_V1" or value.get("technical_assurance") != "VERIFIED" or value.get("final_disposition") != "BLOCKED_PENDING_HUMAN_GATES" or value.get("publication") != "DISABLED" or value.get("production_ready") is not False or value.get("legal_status") != "PENDING" or value.get("license_concluded") != "NOASSERTION" or value.get("license_declared") != "NOASSERTION" or value.get("required_pending_gates") != list(_GATES) or value.get("tracks") != list(_TRACKS):
        raise ValueError("release gate policy is not fail-closed")
    return value


def _reject_sensitive(value: Any) -> None:
    encoded = _canonical(value).decode("utf-8", "strict").lower()
    if len(encoded.encode()) > 1_048_576:
        raise ValueError("release gate input exceeds its bound")
    for marker in ("api_key", "access_token", "password", "private key", "begin rsa", "secret"):
        if marker in encoded:
            raise ValueError("release gate input contains sensitive material")


def _safe_facts(value: dict[str, Any]) -> None:
    safety = value.get("safety")
    if not isinstance(safety, dict) or set(safety) != set(_SAFETY) or any(item is not False for item in safety.values()):
        raise ValueError("release gate safety facts are unsafe")


def _common(value: dict[str, Any], track: str, *, require_checks: bool = False) -> None:
    if value.get("track") != track or value.get("publication") != "DISABLED" or value.get("production_ready") is not False or value.get("legal_status") != "PENDING" or value.get("license_concluded") != "NOASSERTION" or value.get("license_declared") != "NOASSERTION":
        raise ValueError("release gate track facts conflict")
    _safe_facts(value)
    for key in ("source_binding_sha256", "source_manifest_sha256", "provenance_sha256"):
        if not _digest(value.get(key), 64):
            raise ValueError("release gate digest fact is invalid")
    if require_checks and (not isinstance(value.get("checks"), list) or not value["checks"] or any(not isinstance(item, dict) or item.get("passed") is not True for item in value["checks"])):
        raise ValueError("release gate validation facts are incomplete")


def _history(value: dict[str, Any]) -> None:
    if value.get("schema_version") != "1" or value.get("audit_kind") != "EXACT_GIT_HISTORY" or value.get("publication") != "DISABLED" or value.get("mutation_performed") is not False or value.get("strategy") != "SANITIZED_SINGLE_COMMIT" or value.get("candidate_proof_required") is not True or value.get("disposition") != "CANDIDATE_PROOF_REQUIRED" or value.get("blocking_finding_count") != 0 or value.get("matched_values_included") is not False:
        raise ValueError("release gate history proof is not accepted")


def _track_facts(track: str, provenance: dict[str, Any], repository: dict[str, Any], ci: dict[str, Any]) -> dict[str, Any]:
    _common(provenance, track)
    _common(repository, track)
    _common(ci, track, require_checks=True)
    if not isinstance(repository.get("file_count"), int) or isinstance(repository["file_count"], bool) or repository["file_count"] < 1 or not _digest(repository.get("root_commit_sha1"), 40) or not _digest(repository.get("tree_sha1"), 40) or not _digest(ci.get("repository_result_sha256"), 64) or not _digest(ci.get("command_plan_sha256"), 64):
        raise ValueError("release gate repository or CI facts are invalid")
    for key in ("source_binding_sha256", "source_manifest_sha256", "provenance_sha256"):
        if not (provenance[key] == repository[key] == ci[key]):
            raise ValueError("release gate cross-stage digest mismatch")
    return {"track": track, "source_binding_sha256": provenance["source_binding_sha256"], "source_manifest_sha256": provenance["source_manifest_sha256"], "provenance_sha256": provenance["provenance_sha256"], "root_commit_sha1": repository["root_commit_sha1"], "tree_sha1": repository["tree_sha1"], "repository_result_sha256": ci["repository_result_sha256"], "command_plan_sha256": ci["command_plan_sha256"], "file_count": repository["file_count"], "checks_passed": len(ci["checks"])}


def build_release_assurance_gate(*, history_audit: dict[str, Any], provenance: dict[str, dict[str, Any]], repositories: dict[str, dict[str, Any]], ci: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Return technical proof while remaining blocked on every human release gate."""
    policy = _policy()
    inputs = {"history_audit": history_audit, "provenance": provenance, "repositories": repositories, "ci": ci}
    _reject_sensitive(inputs)
    if not all(isinstance(item, dict) for item in (history_audit, provenance, repositories, ci)) or set(provenance) != set(_TRACKS) or set(repositories) != set(_TRACKS) or set(ci) != set(_TRACKS):
        raise ValueError("release gate input tracks are incomplete or duplicated")
    _history(history_audit)
    tracks = [_track_facts(track, provenance[track], repositories[track], ci[track]) for track in _TRACKS]
    output = {"schema_version": "1", "format": policy["format"], "technical_assurance": "VERIFIED", "final_disposition": "BLOCKED_PENDING_HUMAN_GATES", "publication": "DISABLED", "production_ready": False, "legal_status": "PENDING", "license_concluded": "NOASSERTION", "license_declared": "NOASSERTION", "pending_gates": list(_GATES), "tracks": tracks, "input_bundle_sha256": hashlib.sha256(_canonical(inputs)).hexdigest(), "safety": {key: False for key in _SAFETY}}
    Draft202012Validator(json.loads(_SCHEMA.read_text(encoding="utf-8"))).validate(output)
    return output
