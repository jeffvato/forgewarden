"""Fail-closed validation for declarative Forgewarden add-on manifests."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .core import SwarmError, read_restricted_bytes

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "addon-manifest.schema.json"
SAFE_ENTRYPOINT = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,239}$")


class AddonManifestError(SwarmError):
    """The add-on manifest cannot be safely admitted."""


def _schema() -> dict[str, Any]:
    try:
        return json.loads(read_restricted_bytes(SCHEMA, "add-on manifest schema").decode("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AddonManifestError("add-on manifest schema is unavailable or invalid") from exc


def validate_manifest(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise AddonManifestError("add-on manifest must be an object")
    try:
        import jsonschema
        jsonschema.Draft202012Validator(_schema()).validate(manifest)
    except ImportError as exc:
        raise AddonManifestError("jsonschema is required for add-on validation") from exc
    except jsonschema.ValidationError as exc:
        raise AddonManifestError(f"add-on manifest failed schema validation: {exc.message}") from exc
    entrypoint = manifest["entrypoint"]
    if entrypoint.startswith("/") or "\\" in entrypoint or any(part in {"", ".", ".."} for part in Path(entrypoint).parts):
        raise AddonManifestError("add-on entrypoint must be a safe relative path")
    if not SAFE_ENTRYPOINT.fullmatch(entrypoint):
        raise AddonManifestError("add-on entrypoint contains unsafe characters")
    if any(capability.startswith("task.") for capability in manifest["capabilities"]) and "job_status" not in manifest["permissions"]["read"]:
        raise AddonManifestError("task add-ons must declare job_status read access")
    return json.loads(json.dumps(manifest, sort_keys=True))


def load_manifest(path: Path) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AddonManifestError("add-on manifest must be a regular file")
    try:
        value = json.loads(read_restricted_bytes(path, "add-on manifest").decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AddonManifestError("add-on manifest is unreadable or invalid JSON") from exc
    return validate_manifest(value)


def canonical_manifest_digest(manifest: dict[str, Any]) -> str:
    value = dict(manifest)
    signature = dict(value.get("signature", {}))
    signature.pop("manifest_sha256", None)
    value["signature"] = signature
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def verify_manifest_digest(manifest: dict[str, Any]) -> None:
    expected = manifest["signature"]["manifest_sha256"]
    if canonical_manifest_digest(manifest) != expected:
        raise AddonManifestError("add-on manifest digest does not match its signature record")


class AddonManager:
    """Local-only add-on lifecycle; installs files but never executes them."""

    def __init__(self, root: Path):
        self.root = Path(root).expanduser()
        if self.root.is_symlink() or self.root.resolve() in {Path("/"), Path.home()}:
            raise AddonManifestError("add-on root is unsafe")
        self.packages = self.root / "packages"
        self.registry = self.root / "registry.json"
        self.audit = self.root / "audit.jsonl"

    def _read_registry(self) -> dict[str, Any]:
        if not self.registry.exists():
            return {"registry_version": 1, "addons": {}}
        try:
            value = json.loads(read_restricted_bytes(self.registry, "add-on registry").decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AddonManifestError("add-on registry is unreadable or invalid") from exc
        if not isinstance(value, dict) or value.get("registry_version") != 1 or not isinstance(value.get("addons"), dict):
            raise AddonManifestError("add-on registry has an invalid shape")
        return value

    def _write_registry(self, value: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.registry.with_name(self.registry.name + ".tmp")
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(self.registry)

    def _audit(self, event: str, addon_id: str, version: str, status: str) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.audit.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"event": event, "addon_id": addon_id, "version": version, "status": status}, sort_keys=True) + "\n")
        self.audit.chmod(0o600)

    @staticmethod
    def _copy_package(source: Path, target: Path) -> None:
        if source.is_symlink() or not source.is_dir():
            raise AddonManifestError("add-on package must be a regular directory")
        target.mkdir(parents=True, exist_ok=False, mode=0o700)
        for item in source.rglob("*"):
            relative = item.relative_to(source)
            destination = target / relative
            if item.is_symlink():
                raise AddonManifestError(f"add-on package contains a symlink: {relative}")
            if item.is_dir():
                destination.mkdir(mode=0o700)
            elif item.is_file():
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                shutil.copy2(item, destination)
            else:
                raise AddonManifestError(f"add-on package contains unsupported entry: {relative}")

    def install(self, package: Path) -> dict[str, Any]:
        package = Path(package)
        manifest = load_manifest(package / "manifest.json")
        verify_manifest_digest(manifest)
        entrypoint = package / manifest["entrypoint"]
        if entrypoint.is_symlink() or not entrypoint.is_file():
            raise AddonManifestError("add-on entrypoint is missing or unsafe")
        state = self._read_registry()
        addon_id = manifest["id"]
        if addon_id in state["addons"]:
            raise AddonManifestError("add-on is already installed")
        target = self.packages / addon_id / manifest["version"]
        self.packages.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._copy_package(package, target)
        state["addons"][addon_id] = {"manifest": manifest, "status": "DISABLED", "path": str(target)}
        self._write_registry(state)
        self._audit("install", addon_id, manifest["version"], "DISABLED")
        return state["addons"][addon_id]

    @staticmethod
    def _version(value: str) -> tuple[int, int, int]:
        return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]

    def update(self, package: Path) -> dict[str, Any]:
        package = Path(package)
        manifest = load_manifest(package / "manifest.json")
        verify_manifest_digest(manifest)
        entrypoint = package / manifest["entrypoint"]
        if entrypoint.is_symlink() or not entrypoint.is_file():
            raise AddonManifestError("add-on entrypoint is missing or unsafe")
        state = self._read_registry(); addon_id = manifest["id"]; current = state["addons"].get(addon_id)
        if current is None:
            raise AddonManifestError("add-on is not installed")
        old_version = current["manifest"]["version"]
        if self._version(manifest["version"]) <= self._version(old_version):
            raise AddonManifestError("update version must be newer than the installed version")
        current_path = Path(current["path"]).resolve()
        packages = self.packages.resolve()
        try:
            current_path.relative_to(packages)
        except ValueError as exc:
            raise AddonManifestError("registered add-on path escaped package root") from exc
        backup = self.root / "backups" / addon_id / old_version
        backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if backup.exists():
            raise AddonManifestError("update backup already exists")
        current_path.rename(backup)
        target = self.packages / addon_id / manifest["version"]
        try:
            self._copy_package(package, target)
        except Exception:
            backup.rename(current_path)
            raise
        record = {"manifest": manifest, "status": "DISABLED", "path": str(target), "previous": {"version": old_version, "path": str(backup)}}
        state["addons"][addon_id] = record; self._write_registry(state)
        self._audit("update", addon_id, manifest["version"], "DISABLED")
        return record

    def rollback(self, addon_id: str, version: str) -> dict[str, Any]:
        state = self._read_registry(); current = state["addons"].get(addon_id)
        if current is None or current.get("previous", {}).get("version") != version:
            raise AddonManifestError("requested rollback version is not available")
        current_path = Path(current["path"]).resolve(); backup = Path(current["previous"]["path"]).resolve()
        packages = self.packages.resolve()
        for path in (current_path, backup):
            try:
                path.relative_to(packages if path == current_path else self.root.resolve())
            except ValueError as exc:
                raise AddonManifestError("rollback path escaped managed roots") from exc
        if backup.is_symlink() or not backup.is_dir():
            raise AddonManifestError("rollback backup is missing or unsafe")
        retired = self.root / "backups" / addon_id / current["manifest"]["version"]
        retired.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        current_path.rename(retired)
        backup.rename(current_path)
        restored_manifest = load_manifest(current_path / "manifest.json")
        record = {"manifest": restored_manifest, "status": "DISABLED", "path": str(current_path), "previous": {"version": current["manifest"]["version"], "path": str(retired)}}
        state["addons"][addon_id] = record; self._write_registry(state)
        self._audit("rollback", addon_id, restored_manifest["version"], "DISABLED")
        return record

    def set_status(self, addon_id: str, status: str) -> dict[str, Any]:
        if status not in {"ENABLED", "DISABLED"}:
            raise AddonManifestError("add-on status must be ENABLED or DISABLED")
        state = self._read_registry()
        record = state["addons"].get(addon_id)
        if record is None:
            raise AddonManifestError("add-on is not installed")
        record["status"] = status
        self._write_registry(state)
        self._audit("status", addon_id, record["manifest"]["version"], status)
        return record

    def list_installed(self) -> dict[str, Any]:
        """Return the registry for read-only console and audit consumers."""
        return json.loads(json.dumps(self._read_registry(), sort_keys=True))

    def remove(self, addon_id: str, *, confirm: bool = False) -> None:
        if not confirm:
            raise AddonManifestError("add-on removal requires explicit confirmation")
        state = self._read_registry()
        record = state["addons"].get(addon_id)
        if record is None:
            raise AddonManifestError("add-on is not installed")
        target = Path(record["path"]).resolve()
        packages = self.packages.resolve()
        try:
            target.relative_to(packages)
        except ValueError as exc:
            raise AddonManifestError("registered add-on path escaped package root") from exc
        if target.is_symlink() or not target.is_dir():
            raise AddonManifestError("registered add-on package is missing or unsafe")
        shutil.rmtree(target)
        if target.parent.exists() and not any(target.parent.iterdir()):
            target.parent.rmdir()
        state["addons"].pop(addon_id)
        self._write_registry(state)
        self._audit("remove", addon_id, record["manifest"]["version"], "REMOVED")
