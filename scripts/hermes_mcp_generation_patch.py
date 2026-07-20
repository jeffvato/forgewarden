#!/usr/bin/env python3
"""Hash-guarded Hermes 0.18.2 generation-aware MCP reconnect patch."""
from __future__ import annotations
import argparse, hashlib, importlib.metadata, os, re, sys, tempfile
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_HERMES_VERSION = "0.18.2"
TARGET = Path("/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/lib/python3.12/site-packages/tools/mcp_tool.py")
BACKUP_DIR = Path("/home/jeff/hermes-swarm-desktop-backend-backups")
EXPECTED_PREPATCH_SHA256 = "1adb71a97786260fe8c258bf9c348ee3b5ea484de0150aad9469147ed2ec42de"
EXPECTED_POSTPATCH_SHA256 = "a4aa9a701de75fa0970180e94c7ac326c39b862b31bc5e3bbacef4346f48d1f0"
BACKUP_NAME = re.compile(r"^mcp_tool\.py\.backup-[0-9]{8}T[0-9]{6}Z-generation$")

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def require_version() -> None:
    if importlib.metadata.version("hermes-agent") != EXPECTED_HERMES_VERSION:
        raise RuntimeError("unsupported hermes-agent version")

def replace_once(source: bytes, old: bytes, new: bytes) -> bytes:
    if source.count(old) != 1:
        raise RuntimeError("expected source shape not found")
    return source.replace(old, new, 1)

def patched_source(source: bytes) -> bytes:
    source = replace_once(source, b'        "_reconnect_retries",\n', b'        "_reconnect_retries", "_connection_generation", "_ready_generation",\n')
    source = replace_once(source, b'        self._reconnect_retries: int = 0\n', b'        self._reconnect_retries: int = 0\n        # Readiness is generation-bound; a stale event cannot satisfy a retry.\n        self._connection_generation: int = 0\n        self._ready_generation: int = 0\n')
    source = replace_once(source, b'        self._ping_unsupported: bool = False\n', b'        self._ping_unsupported: bool = False\n\n    def _begin_connection(self) -> None:\n        self._connection_generation += 1\n        self._ready.clear()\n        self.session = None\n\n    def _mark_connection_ready(self) -> None:\n        self._ready_generation = self._connection_generation\n        self._ready.set()\n')
    source = replace_once(source, b'    async def _run_stdio(self, config: dict):\n        """Run the server using stdio transport."""\n', b'    async def _run_stdio(self, config: dict):\n        """Run the server using stdio transport."""\n        self._begin_connection()\n')
    source = replace_once(source, b'    async def _run_http(self, config: dict):\n        """Run the server using HTTP/StreamableHTTP transport."""\n', b'    async def _run_http(self, config: dict):\n        """Run the server using HTTP/StreamableHTTP transport."""\n        self._begin_connection()\n')
    ready = b'                    await self._discover_tools()\n                    self._ready.set()\n'
    if source.count(ready) != 3:
        raise RuntimeError("expected three standard transport-ready sites")
    source = source.replace(ready, b'                    await self._discover_tools()\n                    self._mark_connection_ready()\n')
    ready_sse = b'                        await self._discover_tools()\n                        self._ready.set()\n'
    source = replace_once(source, ready_sse, b'                        await self._discover_tools()\n                        self._mark_connection_ready()\n')
    source = replace_once(source, b'    old_session: Any = None,\n    timeout: float = 15.0,\n', b'    old_session: Any = None,\n    old_generation: Optional[int] = None,\n    timeout: float = 15.0,\n')
    source = replace_once(source, b'        if session is not None and session is not old_session and is_ready:\n', b'        ready_generation = getattr(srv, "_ready_generation", None)\n        generation_ready = (old_generation is None or (isinstance(ready_generation, int) and ready_generation > old_generation))\n        if session is not None and session is not old_session and is_ready and generation_ready:\n')
    source = replace_once(source, b'    old_session = getattr(srv, "session", None)\n', b'    old_session = getattr(srv, "session", None)\n    old_generation = getattr(srv, "_connection_generation", 0)\n')
    source = replace_once(source, b'        old_session=old_session,\n        timeout=timeout,\n', b'        old_session=old_session,\n        old_generation=old_generation,\n        timeout=timeout,\n')
    return source

def read_target() -> bytes:
    if TARGET.is_symlink() or not TARGET.is_file():
        raise RuntimeError("target missing or symlinked")
    return TARGET.read_bytes()

def backup(source: bytes) -> Path:
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = BACKUP_DIR / f"mcp_tool.py.backup-{stamp}-generation"
    if path.exists():
        raise RuntimeError("backup already exists")
    fd, tmp = tempfile.mkstemp(prefix=".mcp_tool-generation-", dir=BACKUP_DIR)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle: handle.write(source)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    return path

def replace_target(source: bytes) -> None:
    mode = TARGET.stat().st_mode & 0o777
    fd, tmp = tempfile.mkstemp(prefix=".mcp_tool-generation-", dir=TARGET.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle: handle.write(source)
        os.replace(tmp, TARGET)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def apply() -> int:
    require_version(); source = read_target(); current = sha256(source)
    if current == EXPECTED_POSTPATCH_SHA256: print("already applied"); return 0
    if current != EXPECTED_PREPATCH_SHA256: raise RuntimeError(f"refusing unknown source hash: {current}")
    replacement = patched_source(source)
    if sha256(replacement) != EXPECTED_POSTPATCH_SHA256: raise RuntimeError("patched source hash mismatch")
    path = backup(source); replace_target(replacement)
    print(f"applied backup={path} sha256={EXPECTED_POSTPATCH_SHA256}"); return 0

def rollback(path: Path) -> int:
    require_version(); resolved = path.resolve()
    if BACKUP_DIR.resolve() not in resolved.parents or not BACKUP_NAME.fullmatch(resolved.name): raise RuntimeError("backup outside fixed directory")
    if resolved.is_symlink() or not resolved.is_file(): raise RuntimeError("backup missing or symlinked")
    if sha256(read_target()) != EXPECTED_POSTPATCH_SHA256: raise RuntimeError("refusing rollback from unknown target")
    original = resolved.read_bytes()
    if sha256(original) != EXPECTED_PREPATCH_SHA256: raise RuntimeError("backup hash mismatch")
    replace_target(original); print(f"rolled back backup={resolved} sha256={EXPECTED_PREPATCH_SHA256}"); return 0

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("apply"); rb = sub.add_parser("rollback"); rb.add_argument("--backup", required=True, type=Path)
    args = parser.parse_args(argv)
    try: return apply() if args.command == "apply" else rollback(args.backup)
    except (OSError, RuntimeError, importlib.metadata.PackageNotFoundError) as exc:
        print(f"generation patch refused: {exc}", file=sys.stderr); return 2

if __name__ == "__main__":
    raise SystemExit(main())
