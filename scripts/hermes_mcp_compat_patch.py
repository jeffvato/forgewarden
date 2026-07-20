#!/usr/bin/env python3
"""Hash-guarded Hermes 0.18.2 MCP reconnect compatibility patch.

This intentionally targets only the installed Desktop Hermes virtualenv.
The CLI has no arbitrary path option so an unknown installation cannot be
silently modified.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_HERMES_VERSION = "0.18.2"
TARGET = Path("/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/lib/python3.12/site-packages/tools/mcp_tool.py")
BACKUP_DIR = Path("/home/jeff/hermes-swarm-desktop-backend-backups")
EXPECTED_PREPATCH_SHA256 = "5781bd02572b40b7e5132235bbc4755f6ca5685f8a1b8772e7b47ed02925b129"
EXPECTED_POSTPATCH_SHA256 = "1adb71a97786260fe8c258bf9c348ee3b5ea484de0150aad9469147ed2ec42de"
OLD = b"msg = str(exc).lower()"
NEW = b"msg = _exc_str(exc).lower()"
FUNCTION_MARKER = b"def _is_session_expired_error"
BACKUP_NAME = re.compile(r"^mcp_tool\.py\.backup-[0-9]{8}T[0-9]{6}Z$")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_version() -> None:
    actual = importlib.metadata.version("hermes-agent")
    if actual != EXPECTED_HERMES_VERSION:
        raise RuntimeError(f"unsupported hermes-agent version: {actual}")


def read_target() -> bytes:
    if not TARGET.is_file() or TARGET.is_symlink():
        raise RuntimeError("installed Hermes MCP client source is missing or symlinked")
    return TARGET.read_bytes()


def patched_source(source: bytes) -> bytes:
    start = source.find(FUNCTION_MARKER)
    if start < 0:
        raise RuntimeError("session-expiry function not found")
    end = source.find(b"\ndef ", start + len(FUNCTION_MARKER))
    if end < 0:
        end = len(source)
    body = source[start:end]
    if body.count(OLD) != 1:
        raise RuntimeError("expected session-expiry source shape not found")
    return source[:start] + body.replace(OLD, NEW, 1) + source[end:]


def create_backup(source: bytes) -> Path:
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = BACKUP_DIR / f"mcp_tool.py.backup-{stamp}"
    if path.exists():
        raise RuntimeError(f"backup already exists: {path}")
    fd, temp_name = tempfile.mkstemp(prefix=".mcp_tool.backup-", dir=BACKUP_DIR)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(source)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    return path


def replace_target(source: bytes) -> None:
    mode = TARGET.stat().st_mode & 0o777
    fd, temp_name = tempfile.mkstemp(prefix=".mcp_tool.py.", dir=TARGET.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(source)
        os.replace(temp_name, TARGET)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def apply_patch() -> int:
    require_version()
    source = read_target()
    current = sha256(source)
    if current == EXPECTED_POSTPATCH_SHA256:
        print("already applied")
        return 0
    if current != EXPECTED_PREPATCH_SHA256:
        raise RuntimeError(f"refusing unknown source hash: {current}")
    replacement = patched_source(source)
    if sha256(replacement) != EXPECTED_POSTPATCH_SHA256:
        raise RuntimeError("patched source hash does not match guard")
    backup = create_backup(source)
    replace_target(replacement)
    if sha256(read_target()) != EXPECTED_POSTPATCH_SHA256:
        raise RuntimeError("post-patch hash verification failed")
    print(f"applied backup={backup} sha256={EXPECTED_POSTPATCH_SHA256}")
    return 0


def rollback_patch(backup: Path) -> int:
    require_version()
    resolved = backup.resolve()
    if BACKUP_DIR.resolve() not in resolved.parents or not BACKUP_NAME.fullmatch(resolved.name):
        raise RuntimeError("backup path is outside the fixed Hermes backup directory")
    if not resolved.is_file() or resolved.is_symlink():
        raise RuntimeError("backup is missing or symlinked")
    source = read_target()
    current = sha256(source)
    if current == EXPECTED_PREPATCH_SHA256:
        print("already rolled back")
        return 0
    if current != EXPECTED_POSTPATCH_SHA256:
        raise RuntimeError(f"refusing rollback from unknown source hash: {current}")
    original = resolved.read_bytes()
    if sha256(original) != EXPECTED_PREPATCH_SHA256:
        raise RuntimeError("backup hash does not match expected pre-patch source")
    replace_target(original)
    if sha256(read_target()) != EXPECTED_PREPATCH_SHA256:
        raise RuntimeError("rollback hash verification failed")
    print(f"rolled back backup={resolved} sha256={EXPECTED_PREPATCH_SHA256}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("apply")
    rollback = subparsers.add_parser("rollback")
    rollback.add_argument("--backup", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "apply":
            return apply_patch()
        return rollback_patch(args.backup)
    except (OSError, RuntimeError, importlib.metadata.PackageNotFoundError) as exc:
        print(f"compatibility patch refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
