"""Ownership-manifest primitives for safe Forgewarden installation lifecycle."""
from __future__ import annotations

import hashlib
import json
import argparse
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any, Iterable

from .core import SwarmError, read_restricted_bytes

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "installation-manifest.schema.json"


class InstallationManifestError(SwarmError):
    """The installation manifest cannot safely authorize a lifecycle action."""


def _validate_path(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or "\\" in relative or any(part in {"", ".", ".."} for part in path.parts):
        raise InstallationManifestError(f"unsafe owned path: {relative}")
    resolved_root = root.resolve()
    resolved = (root / path).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise InstallationManifestError(f"owned path escaped install root: {relative}") from exc
    return resolved


def build_manifest(install_root: Path, release: str, files: Iterable[Path]) -> dict[str, Any]:
    root = Path(install_root).expanduser().resolve()
    if root == Path("/") or root == Path.home():
        raise InstallationManifestError("refusing a broad or home-directory install root")
    entries = []
    for raw in files:
        path = Path(raw)
        if path.is_symlink() or not path.is_file():
            raise InstallationManifestError(f"owned file must be a regular file: {path}")
        try:
            relative = path.resolve().relative_to(root).as_posix()
        except ValueError as exc:
            raise InstallationManifestError(f"file is outside install root: {path}") from exc
        _validate_path(root, relative)
        entries.append({"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    if not entries:
        raise InstallationManifestError("installation manifest cannot own zero files")
    return {"manifest_version": 1, "product": "forgewarden", "release": release, "install_root": str(root), "files": sorted(entries, key=lambda item: item["path"])}


def validate_manifest(manifest: Any, expected_root: Path | None = None) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise InstallationManifestError("installation manifest must be an object")
    try:
        import jsonschema
        schema = json.loads(read_restricted_bytes(SCHEMA, "installation manifest schema").decode("utf-8"))
        jsonschema.Draft202012Validator(schema).validate(manifest)
    except ImportError as exc:
        raise InstallationManifestError("jsonschema is required for installation validation") from exc
    except jsonschema.ValidationError as exc:
        raise InstallationManifestError(f"installation manifest failed schema validation: {exc.message}") from exc
    root = Path(manifest["install_root"]).resolve()
    if root == Path("/") or root == Path.home():
        raise InstallationManifestError("manifest install root is too broad")
    if expected_root is not None and root != Path(expected_root).expanduser().resolve():
        raise InstallationManifestError("manifest install root does not match requested root")
    for entry in manifest["files"]:
        _validate_path(root, entry["path"])
    return json.loads(json.dumps(manifest, sort_keys=True))


def uninstall_preview(manifest: dict[str, Any], expected_root: Path | None = None) -> list[Path]:
    value = validate_manifest(manifest, expected_root)
    root = Path(value["install_root"])
    return [root / entry["path"] for entry in value["files"]]


def uninstall(manifest: dict[str, Any], expected_root: Path, *, confirm: bool = False) -> list[str]:
    targets = uninstall_preview(manifest, expected_root)
    if not confirm:
        raise InstallationManifestError("uninstall is preview-only until --confirm-uninstall is supplied")
    removed: list[str] = []
    for target in targets:
        if target.is_symlink():
            raise InstallationManifestError(f"refusing to remove symlinked owned path: {target}")
        if target.exists():
            if not target.is_file():
                raise InstallationManifestError(f"refusing to remove non-file owned path: {target}")
            target.unlink()
            removed.append(str(target))
    return removed


def _safe_install_root(value: Path) -> Path:
    root = Path(value).expanduser().resolve()
    if root == Path("/") or root == Path.home():
        raise InstallationManifestError("refusing a broad or home-directory install root")
    return root


def _relative_release_file(source_root: Path, relative: str) -> Path:
    if not isinstance(relative, str):
        raise InstallationManifestError("release file path must be a string")
    raw = source_root / relative
    if raw.is_symlink():
        raise InstallationManifestError(f"release file must not be a symlink: {relative}")
    return _validate_path(source_root, relative)


def stage_install(source_root: Path, install_root: Path, release: str, files: Iterable[str]) -> tuple[Path, dict[str, Any]]:
    """Copy an explicit release file list into a disposable sibling stage."""
    source = _safe_install_root(source_root)
    target = _safe_install_root(install_root)
    if not source.is_dir():
        raise InstallationManifestError(f"release source is not a directory: {source}")
    stage = Path(tempfile.mkdtemp(prefix=".forgewarden-stage-", dir=target.parent))
    staged_files: list[Path] = []
    try:
        for relative in files:
            source_file = _relative_release_file(source, relative)
            if source_file.is_symlink() or not source_file.is_file():
                raise InstallationManifestError(f"release file must be a regular file: {relative}")
            destination = _validate_path(stage, relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_file, destination)
            staged_files.append(destination)
        manifest = build_manifest(stage, release, staged_files)
        manifest["install_root"] = str(target)
        validate_manifest(manifest, target)
        manifest_path = stage / ".forgewarden-manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return stage, manifest
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def _read_stage_manifest(stage: Path, expected_root: Path) -> dict[str, Any]:
    if stage.is_symlink() or not stage.is_dir():
        raise InstallationManifestError(f"staged release must be a regular directory: {stage}")
    manifest_path = stage / ".forgewarden-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InstallationManifestError(f"staged release manifest is unreadable: {manifest_path}") from exc
    return validate_manifest(manifest, expected_root)


def promote_install(staged: Path, install_root: Path) -> dict[str, Any]:
    """Atomically promote a sibling stage, retaining the prior install for rollback."""
    target = _safe_install_root(install_root)
    stage = Path(staged).expanduser().resolve()
    if stage.parent != target.parent:
        raise InstallationManifestError("staged release must be beside the install root for atomic promotion")
    manifest = _read_stage_manifest(stage, target)
    backup: Path | None = None
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_dir():
            raise InstallationManifestError(f"existing install root is not a regular directory: {target}")
        backup_root = target.parent / ".forgewarden-backups"
        backup_root.mkdir(mode=0o700, exist_ok=True)
        backup = backup_root / f"{manifest['release']}-{uuid.uuid4().hex}"
        os.replace(target, backup)
    try:
        os.replace(stage, target)
    except OSError:
        if backup is not None and not target.exists():
            os.replace(backup, target)
        raise
    return {"release": manifest["release"], "install_root": str(target), "backup": str(backup) if backup else None}


def rollback_install(backup: Path, install_root: Path) -> dict[str, Any]:
    """Restore a retained install backup without deleting the current release."""
    target = _safe_install_root(install_root)
    backup_path = Path(backup).expanduser().resolve()
    backup_root = (target.parent / ".forgewarden-backups").resolve()
    try:
        backup_path.relative_to(backup_root)
    except ValueError as exc:
        raise InstallationManifestError("rollback backup is outside the managed backup directory") from exc
    manifest = _read_stage_manifest(backup_path, target)
    displaced: Path | None = None
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_dir():
            raise InstallationManifestError(f"current install root is not a regular directory: {target}")
        displaced = target.parent / f".forgewarden-rollback-current-{uuid.uuid4().hex}"
        os.replace(target, displaced)
    try:
        os.replace(backup_path, target)
    except OSError:
        if displaced is not None and not target.exists():
            os.replace(displaced, target)
        raise
    return {"release": manifest["release"], "install_root": str(target), "displaced": str(displaced) if displaced else None}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Forgewarden ownership-manifest lifecycle tool")
    parser.add_argument("command", choices=("validate", "preview-uninstall", "uninstall", "stage-install", "promote", "rollback", "check-prerequisites"))
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--stage", type=Path)
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--release")
    parser.add_argument("--file", action="append", dest="files", default=[])
    parser.add_argument("--tool", action="append", dest="tools", default=[])
    parser.add_argument("--confirm-uninstall", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "check-prerequisites":
            from .prerequisites import inspect_prerequisites, require_prerequisites
            report = inspect_prerequisites(args.tools)
            print(json.dumps(report, sort_keys=True))
            require_prerequisites(report)
            return 0
        if args.command in {"validate", "preview-uninstall", "uninstall"}:
            if args.manifest is None or args.root is None:
                raise InstallationManifestError("--manifest and --root are required for this command")
            manifest = json.loads(read_restricted_bytes(args.manifest, "installation manifest").decode("utf-8"))
        elif args.command == "stage-install":
            if args.source is None or args.root is None or not args.release or not args.files:
                raise InstallationManifestError("stage-install requires --source, --root, --release, and at least one --file")
            stage, manifest = stage_install(args.source, args.root, args.release, args.files)
            print(json.dumps({"stage": str(stage), "manifest": manifest}, sort_keys=True))
            return 0
        elif args.command == "promote":
            if args.stage is None or args.root is None:
                raise InstallationManifestError("promote requires --stage and --root")
            print(json.dumps(promote_install(args.stage, args.root), sort_keys=True))
            return 0
        else:
            if args.backup is None or args.root is None:
                raise InstallationManifestError("rollback requires --backup and --root")
            print(json.dumps(rollback_install(args.backup, args.root), sort_keys=True))
            return 0
        if args.command == "validate":
            validate_manifest(manifest, args.root); print("VALID")
        elif args.command == "preview-uninstall":
            for path in uninstall_preview(manifest, args.root): print(path)
        else:
            for path in uninstall(manifest, args.root, confirm=args.confirm_uninstall): print(path)
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, InstallationManifestError) as exc:
        print(f"FAILED: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
