import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from swarm.addons import AddonManager, AddonManifestError, canonical_manifest_digest, load_manifest, validate_manifest, verify_manifest_digest


def manifest():
    value = {
        "manifest_version": 1, "id": "inventory-inspector", "name": "Inventory Inspector", "version": "1.0.0",
        "publisher": "BT Gun Company", "description": "Read-only local inventory view.", "entrypoint": "addon/main.js",
        "capabilities": ["ui.panel", "evidence.read"],
        "permissions": {"read": ["redacted_evidence"], "network": False, "shell": False, "git": False, "production": False},
        "signature": {"algorithm": "sha256-signature-v1", "key_id": "btgunco-dev", "manifest_sha256": "0" * 64},
    }
    value["signature"]["manifest_sha256"] = canonical_manifest_digest(value)
    return value


def test_valid_manifest_and_digest():
    value = manifest()
    assert validate_manifest(value)["id"] == "inventory-inspector"
    verify_manifest_digest(value)


def test_manifest_rejects_privileged_permissions():
    value = manifest(); value["permissions"]["shell"] = True
    with pytest.raises(AddonManifestError):
        validate_manifest(value)


def test_manifest_rejects_path_escape_and_bad_digest():
    value = manifest(); value["entrypoint"] = "../escape.js"
    with pytest.raises(AddonManifestError):
        validate_manifest(value)
    value = manifest(); value["signature"]["manifest_sha256"] = "f" * 64
    with pytest.raises(AddonManifestError):
        verify_manifest_digest(value)


def test_load_manifest_rejects_symlink():
    with TemporaryDirectory() as temp:
        root = Path(temp); real = root / "manifest.json"; link = root / "link.json"
        real.write_text(json.dumps(manifest()), encoding="utf-8"); link.symlink_to(real)
        with pytest.raises(AddonManifestError):
            load_manifest(link)


def test_addon_lifecycle_is_disabled_by_default_and_requires_confirmation():
    with TemporaryDirectory() as temp:
        package = Path(temp) / "package"; package.mkdir(); (package / "addon").mkdir(); (package / "addon/main.js").write_text("export default {}\n")
        value = manifest(); (package / "manifest.json").write_text(json.dumps(value), encoding="utf-8")
        manager = AddonManager(Path(temp) / "state")
        record = manager.install(package)
        assert record["status"] == "DISABLED"
        assert manager.set_status("inventory-inspector", "ENABLED")["status"] == "ENABLED"
        assert manager.set_status("inventory-inspector", "DISABLED")["status"] == "DISABLED"
        with pytest.raises(AddonManifestError):
            manager.remove("inventory-inspector")
        manager.remove("inventory-inspector", confirm=True)
        assert not (Path(temp) / "state" / "packages" / "inventory-inspector").exists()


def test_addon_update_and_explicit_rollback_preserve_previous_version():
    with TemporaryDirectory() as temp:
        root = Path(temp); package = root / "package"; package.mkdir(); (package / "addon").mkdir(); (package / "addon/main.js").write_text("v1\n")
        first = manifest(); (package / "manifest.json").write_text(json.dumps(first), encoding="utf-8")
        manager = AddonManager(root / "state"); manager.install(package)
        second = manifest(); second["version"] = "1.1.0"; second["signature"]["manifest_sha256"] = canonical_manifest_digest(second)
        (package / "addon/main.js").write_text("v2\n"); (package / "manifest.json").write_text(json.dumps(second), encoding="utf-8")
        updated = manager.update(package); assert updated["manifest"]["version"] == "1.1.0"
        restored = manager.rollback("inventory-inspector", "1.0.0")
        assert restored["manifest"]["version"] == "1.0.0"
        assert (Path(restored["path"]) / "addon/main.js").read_text() == "v1\n"


def test_addon_lifecycle_writes_redacted_audit_events():
    with TemporaryDirectory() as temp:
        root = Path(temp); package = root / "package"; package.mkdir(); (package / "addon").mkdir(); (package / "addon/main.js").write_text("v1\n")
        value = manifest(); (package / "manifest.json").write_text(json.dumps(value), encoding="utf-8")
        manager = AddonManager(root / "state"); manager.install(package); manager.set_status("inventory-inspector", "ENABLED")
        manager.remove("inventory-inspector", confirm=True)
        events = [json.loads(line) for line in (root / "state" / "audit.jsonl").read_text().splitlines()]
        assert [event["event"] for event in events] == ["install", "status", "remove"]
        assert all(set(event) == {"event", "addon_id", "version", "status"} for event in events)
