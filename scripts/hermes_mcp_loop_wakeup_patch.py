#!/usr/bin/env python3
import argparse, hashlib, importlib.metadata, os, re, sys, tempfile
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_HERMES_VERSION = "0.18.2"
TARGET = Path("/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/lib/python3.12/site-packages/tools/mcp_tool.py")
BACKUP_DIR = Path("/home/jeff/hermes-swarm-desktop-backend-backups")
EXPECTED_PREPATCH_SHA256 = "1764639bca5249d9cc01fd0c0525b5d732f7623626b28b3c33dded31fef7ec10"
EXPECTED_POSTPATCH_SHA256 = "bc13c3ab73ecfe3a2e2f4ca486ec0b773d4c76de089f219e4e0db5547cf17d51"
BACKUP_NAME = re.compile(r"^mcp_tool\.py\.backup-[0-9]{8}T[0-9]{6}Z-loop-wakeup$")

def sha256(data: bytes) -> str: return hashlib.sha256(data).hexdigest()

def transform(source: bytes) -> bytes:
    old = ("            try:\n" "                loop.run_forever()\n" "            finally:\n").encode()
    new = ("            try:\n" "                # Bound selector sleep for WSL wakeup-fd compatibility.\n" "                def _wakeup_tick() -> None:\n" "                    if not loop.is_closed():\n" "                        loop.call_later(0.05, _wakeup_tick)\n" "                loop.call_later(0.05, _wakeup_tick)\n" "                loop.run_forever()\n" "            finally:\n").encode()
    if source.count(old) != 1: raise RuntimeError("expected loop-wakeup source shape not found")
    return source.replace(old, new, 1)

def require_version() -> None:
    if importlib.metadata.version("hermes-agent") != EXPECTED_HERMES_VERSION: raise RuntimeError("unsupported hermes-agent version")

def read_target() -> bytes:
    if TARGET.is_symlink() or not TARGET.is_file(): raise RuntimeError("target missing or symlinked")
    return TARGET.read_bytes()

def replace_target(source: bytes) -> None:
    mode = TARGET.stat().st_mode & 0o777; fd, tmp = tempfile.mkstemp(prefix=".mcp-tool-loop-wakeup-", dir=TARGET.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle: handle.write(source)
        os.replace(tmp, TARGET)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def backup(source: bytes) -> Path:
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True); stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = BACKUP_DIR / f"mcp_tool.py.backup-{stamp}-loop-wakeup"
    if path.exists(): raise RuntimeError("backup already exists")
    fd, tmp = tempfile.mkstemp(prefix=".mcp-tool-loop-wakeup-", dir=BACKUP_DIR)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle: handle.write(source)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    return path

def apply() -> int:
    require_version(); source = read_target(); current = sha256(source)
    if current == EXPECTED_POSTPATCH_SHA256: print("already applied"); return 0
    if current != EXPECTED_PREPATCH_SHA256: raise RuntimeError(f"refusing unknown source hash: {current}")
    replacement = transform(source)
    if sha256(replacement) != EXPECTED_POSTPATCH_SHA256: raise RuntimeError("patched source hash mismatch")
    path = backup(source); replace_target(replacement); print(f"applied backup={path} sha256={EXPECTED_POSTPATCH_SHA256}"); return 0

def rollback(path: Path) -> int:
    require_version(); resolved = path.resolve()
    if BACKUP_DIR.resolve() not in resolved.parents or not BACKUP_NAME.fullmatch(resolved.name): raise RuntimeError("backup outside fixed directory")
    if resolved.is_symlink() or not resolved.is_file(): raise RuntimeError("backup missing or symlinked")
    if sha256(read_target()) != EXPECTED_POSTPATCH_SHA256: raise RuntimeError("refusing rollback from unknown target")
    original = resolved.read_bytes()
    if sha256(original) != EXPECTED_PREPATCH_SHA256: raise RuntimeError("backup hash mismatch")
    replace_target(original); print(f"rolled back backup={resolved} sha256={EXPECTED_PREPATCH_SHA256}"); return 0

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest="command", required=True); sub.add_parser("apply")
    rb = sub.add_parser("rollback"); rb.add_argument("--backup", required=True, type=Path); args = parser.parse_args(argv)
    try: return apply() if args.command == "apply" else rollback(args.backup)
    except (OSError, RuntimeError, importlib.metadata.PackageNotFoundError) as exc: print(f"loop wakeup patch refused: {exc}", file=sys.stderr); return 2

if __name__ == "__main__": raise SystemExit(main())
