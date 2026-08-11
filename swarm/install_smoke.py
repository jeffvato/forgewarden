"""Disposable clean-environment installer smoke validation."""
from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from .installation import promote_install, stage_install, uninstall


def run_clean_install_smoke() -> dict[str, Any]:
    """Exercise the local lifecycle in a disposable temporary environment."""
    with TemporaryDirectory(prefix="forgewarden-clean-install-") as temp:
        root = Path(temp); source = root / "release"; target = root / "install"
        executable = source / "bin" / "forgewarden"
        executable.parent.mkdir(parents=True)
        executable.write_text("forgewarden smoke fixture\n", encoding="utf-8")
        staged, _ = stage_install(source, target, "1.0.0", ["bin/forgewarden"])
        promoted = promote_install(staged, target)
        manifest = json.loads((target / ".forgewarden-manifest.json").read_text(encoding="utf-8"))
        removed = uninstall(manifest, target, confirm=True)
        return {
            "environment": "DISPOSABLE_TEMPORARY_DIRECTORY",
            "steps": ["STAGE", "PROMOTE", "CONFIRMED_UNINSTALL"],
            "release": promoted["release"],
            "removed_files": len(removed),
            "cleaned": not (target / "bin" / "forgewarden").exists(),
            "deployment": "DISABLED",
        }
