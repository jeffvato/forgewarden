"""Build a disposable release candidate without mutating the source tree."""
from __future__ import annotations

import shutil
from pathlib import Path

from .phase5_release_audit import GENERATED_PARTS, ReleaseAudit


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
    return {
        "publication": "DISABLED",
        "mutation_performed": False,
        "source_tree_mutated": False,
        "excluded_files": excluded_files,
        "skipped_generated_entries": skipped_generated,
        "copied_files": copied_files,
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
