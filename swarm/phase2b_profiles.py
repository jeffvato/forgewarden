"""Strict validation for admitted fixture-only Phase 2B profiles."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .core import SwarmError, read_restricted_bytes

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_A = ROOT / "config" / "phase2b-console-asset-profile.yaml"
CANDIDATE_A_SCHEMA = ROOT / "schemas" / "phase2b-candidate-profile.schema.json"
CANDIDATE_B = ROOT / "config" / "phase2b-audit-review-profile.yaml"
CANDIDATE_B_SCHEMA = ROOT / "schemas" / "phase2b-audit-review-profile.schema.json"
REGISTRY = ROOT / "config" / "phase2b-profile-registry.yaml"
REGISTRY_PROFILE_ID = "console_asset_safety_dry_run_v1"
REGISTRY_CANDIDATE_B_ID = "audit_review_dry_run_v1"


def load_design_profile(path: Path = CANDIDATE_A, schema_path: Path = CANDIDATE_A_SCHEMA) -> dict[str, Any]:
    """Load and validate the admitted fixture-only candidate contract."""
    try:
        import jsonschema
        import yaml
        value = yaml.safe_load(read_restricted_bytes(path, "Phase 2B candidate profile").decode("utf-8"))
        schema = json.loads(read_restricted_bytes(schema_path, "Phase 2B candidate schema").decode("utf-8"))
        jsonschema.Draft202012Validator(schema).validate(value)
    except (ImportError, OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise SwarmError("Phase 2B candidate profile is unreadable or invalid") from exc
    except Exception as exc:
        if exc.__class__.__module__ == "jsonschema.exceptions":
            raise SwarmError("Phase 2B candidate profile failed strict schema validation") from exc
        raise
    if not isinstance(value, dict) or value.get("status") != "REGISTERED_DRY_RUN":
        raise SwarmError("Phase 2B candidate profile is not admitted for fixture-only dry-run")
    return value


def load_registered_candidate() -> dict[str, Any]:
    """Validate the narrow Phase 2B admission registry and return Candidate A."""
    try:
        import yaml
        registry = yaml.safe_load(read_restricted_bytes(REGISTRY, "Phase 2B profile registry").decode("utf-8"))
    except (ImportError, OSError, UnicodeError, ValueError) as exc:
        raise SwarmError("Phase 2B profile registry is unreadable") from exc
    if not isinstance(registry, dict) or registry.get("registry_version") != 1:
        raise SwarmError("Phase 2B profile registry is invalid")
    entries = registry.get("profiles")
    expected = [
        {
            "profile_id": REGISTRY_PROFILE_ID,
            "contract": "config/phase2b-console-asset-profile.yaml",
            "evidence": "docs/phase2b-console-asset-safety-evidence.json",
            "execution": "DISPOSABLE_FIXTURE_ONLY",
            "deployment": "DISABLED",
        },
        {
            "profile_id": REGISTRY_CANDIDATE_B_ID,
            "contract": "config/phase2b-audit-review-profile.yaml",
            "evidence": "docs/phase2b-audit-review-evidence.json",
            "execution": "DISPOSABLE_FIXTURE_ONLY",
            "deployment": "DISABLED",
        },
    ]
    if entries != expected:
        raise SwarmError("Phase 2B profile registry failed strict admission checks")
    return load_design_profile()


def load_registered_candidate_b() -> dict[str, Any]:
    """Validate the Phase 2B registry and return the admitted Candidate B contract."""
    load_registered_candidate()
    return load_design_profile(CANDIDATE_B, CANDIDATE_B_SCHEMA)
