"""Local scaffold for reviewable Forgewarden add-on packages."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .addons import canonical_manifest_digest, validate_manifest

_IDENTITY = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def scaffold(destination: Path, addon_id: str, version: str, *, publisher: str = "Forgewarden Builder") -> Path:
    """Create a minimal, disabled-by-default, least-privilege add-on package."""
    if not _IDENTITY.fullmatch(addon_id):
        raise ValueError("add-on id must be 3-64 lowercase letters, digits, or hyphens")
    if not _VERSION.fullmatch(version):
        raise ValueError("add-on version must use MAJOR.MINOR.PATCH")
    target = Path(destination).expanduser()
    if target.exists() or target.is_symlink():
        raise ValueError("scaffold destination already exists")
    target.mkdir(parents=True, mode=0o700)
    entrypoint = target / "addon" / "main.js"
    entrypoint.parent.mkdir(mode=0o700)
    entrypoint.write_text("// Forgewarden add-on entrypoint. Keep capabilities and permissions minimal.\n", encoding="utf-8")
    manifest = {
        "manifest_version": 1,
        "id": addon_id,
        "name": addon_id.replace("-", " ").title(),
        "version": version,
        "publisher": publisher,
        "description": "Review this local add-on before installation.",
        "entrypoint": "addon/main.js",
        "capabilities": ["ui.panel"],
        "permissions": {"read": [], "network": False, "shell": False, "git": False, "production": False},
        "signature": {"algorithm": "sha256-signature-v1", "key_id": "forgewarden-local", "manifest_sha256": "0" * 64},
    }
    manifest["signature"]["manifest_sha256"] = canonical_manifest_digest(manifest)
    validate_manifest(manifest)
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target
