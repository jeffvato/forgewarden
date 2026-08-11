"""Local trusted-catalog admission for Forgewarden add-on packages."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .addons import AddonManifestError, load_manifest, verify_manifest_digest


def admit_package(package: Path, trusted_publishers: set[str]) -> dict[str, str]:
    """Admit one local package after manifest, digest, entrypoint, and trust checks."""
    package = Path(package).expanduser()
    if package.is_symlink() or not package.is_dir():
        raise AddonManifestError("catalog package must be a regular directory")
    manifest = load_manifest(package / "manifest.json")
    verify_manifest_digest(manifest)
    if manifest["publisher"] not in trusted_publishers:
        raise AddonManifestError("add-on publisher is not trusted by this local catalog")
    entrypoint = package / manifest["entrypoint"]
    if entrypoint.is_symlink() or not entrypoint.is_file():
        raise AddonManifestError("catalog package entrypoint is missing or unsafe")
    return {
        "id": manifest["id"],
        "name": manifest["name"],
        "version": manifest["version"],
        "publisher": manifest["publisher"],
        "manifest_sha256": manifest["signature"]["manifest_sha256"],
        "package": package.name,
    }


def write_catalog(path: Path, packages: Iterable[Path], trusted_publishers: set[str]) -> dict[str, object]:
    entries = [admit_package(package, trusted_publishers) for package in packages]
    ids = [entry["id"] for entry in entries]
    if len(ids) != len(set(ids)):
        raise AddonManifestError("catalog cannot contain duplicate add-on IDs")
    catalog: dict[str, object] = {"catalog_version": 1, "source": "LOCAL_ONLY", "addons": sorted(entries, key=lambda entry: entry["id"])}
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(destination)
    return catalog
