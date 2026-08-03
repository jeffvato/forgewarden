#!/usr/bin/env python3
"""Hash-guarded Hermes 0.18.2 local-stdio startup compatibility patch."""
import argparse
import hashlib
import importlib.metadata
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_HERMES_VERSION = "0.18.2"
TARGET = Path("/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/lib/python3.12/site-packages/tools/mcp_tool.py")
BACKUP_DIR = Path("/home/jeff/hermes-swarm-desktop-backend-backups")
EXPECTED_PREPATCH_SHA256 = "a4aa9a701de75fa0970180e94c7ac326c39b862b31bc5e3bbacef4346f48d1f0"
EXPECTED_POSTPATCH_SHA256 = "b7b5c60e79409f009256c0705c8dbb974b374e468ae9373416550d31315f9d65"
BACKUP_NAME = re.compile(r"^mcp_tool\.py\.backup-[0-9]{8}T[0-9]{6}Z-local-osv$")

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def transform(source: bytes) -> bytes:
    old = '''        from tools.osv_check import check_package_for_malware
        try:
            malware_error = await asyncio.wait_for(
                asyncio.to_thread(check_package_for_malware, command, args),
                timeout=_OSV_MALWARE_CHECK_TIMEOUT_S,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "MCP server '%s': OSV malware preflight timed out after %.0fs "
                "(network slow/unreachable) — proceeding without the check.",
                self.name, _OSV_MALWARE_CHECK_TIMEOUT_S,
            )
            malware_error = None
'''.encode()
    new = '''        from tools.osv_check import check_package_for_malware
        # Fixed absolute local executables cannot be package lookups. Avoid
        # network-bound OSV startup work for them; retain the check for
        # package-resolving commands such as npx/uvx/pipx.
        if os.path.isabs(command) and os.path.isfile(command):
            malware_error = None
        else:
            try:
                malware_error = await asyncio.wait_for(
                    asyncio.to_thread(check_package_for_malware, command, args),
                    timeout=_OSV_MALWARE_CHECK_TIMEOUT_S,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "MCP server '%s': OSV malware preflight timed out after %.0fs "
                    "(network slow/unreachable) — proceeding without the check.",
                    self.name, _OSV_MALWARE_CHECK_TIMEOUT_S,
                )
                malware_error = None
'''.encode()
    if source.count(old) != 1:
        raise RuntimeError("expected local-startup source shape not found")
    return source.replace(old, new, 1)

def require_version() -> None:
    if importlib.metadata.version("hermes-agent") != EXPECTED_HERMES_VERSION:
        raise RuntimeError("unsupported hermes-agent version")

def read_target() -> bytes:
    if TARGET.is_symlink() or not TARGET.is_file():
        raise RuntimeError("target missing or symlinked")
    return TARGET.read_bytes()

def replace_target(source: bytes) -> None:
    mode = TARGET.stat().st_mode & 0o777
    fd, tmp = tempfile.mkstemp(prefix=".mcp-tool-local-osv-", dir=TARGET.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(source)
        os.replace(tmp, TARGET)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def backup(source: bytes) -> Path:
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = BACKUP_DIR / f"mcp_tool.py.backup-{stamp}-local-osv"
    if path.exists():
        raise RuntimeError("backup already exists")
    fd, tmp = tempfile.mkstemp(prefix=".mcp-tool-local-osv-", dir=BACKUP_DIR)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(source)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return path

def apply() -> int:
    require_version(); source = read_target(); current = sha256(source)
    if current == EXPECTED_POSTPATCH_SHA256:
        print("already applied"); return 0
    if current != EXPECTED_PREPATCH_SHA256:
        raise RuntimeError(f"refusing unknown source hash: {current}")
    replacement = transform(source)
    if sha256(replacement) != EXPECTED_POSTPATCH_SHA256:
        raise RuntimeError("patched source hash mismatch")
    path = backup(source); replace_target(replacement)
    print(f"applied backup={path} sha256={EXPECTED_POSTPATCH_SHA256}"); return 0

def rollback(path: Path) -> int:
    require_version(); resolved = path.resolve()
    if BACKUP_DIR.resolve() not in resolved.parents or not BACKUP_NAME.fullmatch(resolved.name):
        raise RuntimeError("backup outside fixed directory")
    if resolved.is_symlink() or not resolved.is_file():
        raise RuntimeError("backup missing or symlinked")
    if sha256(read_target()) != EXPECTED_POSTPATCH_SHA256:
        raise RuntimeError("refusing rollback from unknown target")
    original = resolved.read_bytes()
    if sha256(original) != EXPECTED_PREPATCH_SHA256:
        raise RuntimeError("backup hash mismatch")
    replace_target(original); print(f"rolled back backup={resolved} sha256={EXPECTED_PREPATCH_SHA256}"); return 0

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("apply"); rb = sub.add_parser("rollback"); rb.add_argument("--backup", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        return apply() if args.command == "apply" else rollback(args.backup)
    except (OSError, RuntimeError, importlib.metadata.PackageNotFoundError) as exc:
        print(f"local startup patch refused: {exc}", file=sys.stderr); return 2

if __name__ == "__main__":
    raise SystemExit(main())
