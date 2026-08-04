"""Build a disposable release candidate without mutating the source tree."""
from __future__ import annotations

import shutil
from pathlib import Path

from .phase5_release_audit import GENERATED_PARTS, ReleaseAudit


TEMPLATES = {
    "README.md": """# Forge Warden

Forge Warden is a local-first coding-swarm safety and evidence platform for
bounded review, deterministic validation, audit evidence, and fail-closed
dry-run workflows. This candidate is sanitized; deployment, unattended
execution, production access, and public publication remain disabled.

Supported environment: Python 3.12 or newer on Linux, WSL, or another POSIX-like
development environment. Read `docs/install.md` and
`docs/reproducibility.md` before use.
""",
    "docs/install.md": """# Install and operating boundary

Create a fresh Python 3.12 virtual environment, install `requirements.lock`,
then run `python -m swarm.cli status` and confirm the safety state is engaged.

This candidate does not authorize VPS access, production deployment, public
publication, unattended jobs, or credential handling. Updates require a new
candidate and fresh validation. Rollback means discarding this disposable
candidate and retaining the prior reviewed candidate.
""",
    "docs/reproducibility.md": """# Reproducibility

The candidate targets Python 3.12 and uses `requirements.lock` with exact
versions from the tested environment. A clean-room release pass must add
artifact hashes before public publication. Recreate the environment in a clean
virtual environment, record the interpreter version, and run validation before
review.

Private evidence, tests, and local project records are intentionally excluded.
""",
    "requirements.lock": """anyio==4.14.2
mcp==1.26.0
PyYAML==6.0.3
jsonschema==4.26.0
attrs==26.1.0
jsonschema-specifications==2025.9.1
referencing==0.37.0
rpds-py==2026.6.3
typing-extensions==4.16.0
""",
}


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
        if path.name.endswith(":Zone.Identifier"):
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
    for relative, content in TEMPLATES.items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return {
        "publication": "DISABLED",
        "mutation_performed": False,
        "source_tree_mutated": False,
        "excluded_files": excluded_files,
        "skipped_generated_entries": skipped_generated,
        "copied_files": copied_files,
        "generated_template_files": len(TEMPLATES),
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
