"""Local, read-only codebase index contract.

The index is an evidence aid only.  It is never an authority for admission,
deployment, or execution.
"""

import fnmatch
import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


INDEXER_VERSION = "1"
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_RESULTS = 50
SENSITIVE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "credentials",
    "credentials.json",
    "secrets",
    "secret.json",
    "id_rsa",
    "id_ed25519",
}
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdb")
SECRET_MARKERS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]?[^\s'\"]{12,}"),
)


class IndexPolicyError(ValueError):
    """The checkout or policy is unsafe to index."""


class StaleIndexError(RuntimeError):
    """The persisted index does not match the requested revision or policy."""


class IndexAccessError(PermissionError):
    """A query did not provide an auditable actor."""


@dataclass(frozen=True)
class IndexPolicy:
    include: tuple[str, ...] = ("*",)
    exclude: tuple[str, ...] = (".git/**", "__pycache__/**")

    def __post_init__(self) -> None:
        for pattern in (*self.include, *self.exclude):
            path = Path(pattern)
            if not pattern or path.is_absolute() or ".." in path.parts:
                raise IndexPolicyError("include and exclude patterns may not escape the checkout")

    def fingerprint(self) -> str:
        value = json.dumps({"include": self.include, "exclude": self.exclude}, separators=(",", ":"))
        return hashlib.sha256(value.encode()).hexdigest()


class CodebaseIndex:
    """Build and query a bounded index rooted at one approved checkout."""

    def __init__(self, approved_root: Path | str, index_path: Path | str, policy: IndexPolicy | None = None):
        root = Path(approved_root)
        if root.is_symlink():
            raise IndexPolicyError("approved checkout may not be a symlink")
        self.root = root.resolve()
        if not self.root.is_dir():
            raise IndexPolicyError("approved checkout must be a directory")
        index_candidate = Path(index_path)
        if index_candidate.is_symlink():
            raise IndexPolicyError("index storage may not be a symlink")
        self.index_path = index_candidate.resolve()
        if self.index_path.is_relative_to(self.root):
            raise IndexPolicyError("index storage must be outside the approved checkout")
        self.policy = policy or IndexPolicy()

    def build(self, revision: str) -> dict[str, Any]:
        if not revision or revision.strip() != revision or "/" in revision:
            raise IndexPolicyError("revision must be a non-empty opaque identifier")
        entries = [self._entry(path, revision) for path in self._files()]
        document = {
            "format": 1,
            "indexer_version": INDEXER_VERSION,
            "root": str(self.root),
            "revision": revision,
            "policy": self.policy.fingerprint(),
            "entries": entries,
            "audit": [{"action": "build", "actor": "system", "revision": revision}],
        }
        self._write(document)
        return {"revision": revision, "entries": len(entries), "indexer_version": INDEXER_VERSION}

    def delete(self, actor: str) -> None:
        self._require_actor(actor)
        try:
            self.index_path.unlink()
        except FileNotFoundError:
            return

    def query(self, term: str, revision: str, actor: str, limit: int = 20, fresh_scan: bool = True) -> list[dict[str, Any]]:
        self._require_actor(actor)
        if not term or limit < 1 or limit > MAX_RESULTS:
            raise ValueError("term is required and limit must be between 1 and 50")
        try:
            if self.index_path.is_symlink():
                raise IndexPolicyError("index storage may not be a symlink")
            document = json.loads(self._read_no_follow(self.index_path).decode("utf-8"))
            self._check_fresh(document, revision)
            entries = document["entries"]
            self._validate_entries(entries, revision)
        except (FileNotFoundError, json.JSONDecodeError, StaleIndexError, IndexPolicyError, KeyError, TypeError):
            if not fresh_scan:
                raise StaleIndexError("index is absent, corrupt, or stale")
            entries = [self._entry(path, revision) for path in self._files()]
            return self._match(entries, term, limit)
        document.setdefault("audit", []).append({"action": "query", "actor": actor, "term": term, "limit": limit})
        self._write(document)
        return self._match(entries, term, limit)

    def _files(self) -> Iterable[Path]:
        for base, dirs, names in os.walk(self.root, topdown=True, followlinks=False):
            base_path = Path(base)
            dirs[:] = sorted(dirs)
            names = sorted(names)
            for name in list(dirs):
                if (base_path / name).is_symlink():
                    raise IndexPolicyError(f"symlink directory rejected: {base_path / name}")
            for name in names:
                path = base_path / name
                if path.is_symlink():
                    raise IndexPolicyError(f"symlink file rejected: {path}")
                relative = path.relative_to(self.root).as_posix()
                if self._allowed(relative):
                    yield path

    def _allowed(self, relative: str) -> bool:
        parts = set(relative.lower().split("/"))
        name = relative.rsplit("/", 1)[-1].lower()
        if parts & SENSITIVE_NAMES or name in SENSITIVE_NAMES or name.endswith(SENSITIVE_SUFFIXES):
            return False
        return any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(name, pattern) for pattern in self.policy.include) and not any(
            fnmatch.fnmatch(relative, pattern) for pattern in self.policy.exclude
        )

    def _entry(self, path: Path, revision: str) -> dict[str, Any]:
        relative = path.relative_to(self.root).as_posix()
        data = self._read_no_follow(path)
        if len(data) > MAX_FILE_BYTES or b"\x00" in data:
            text = ""
        else:
            text = data.decode("utf-8", errors="replace")
            if any(marker.search(text) for marker in SECRET_MARKERS):
                text = ""
        return {"path": relative, "file_hash": hashlib.sha256(data).hexdigest(), "size": len(data), "revision": revision, "text": text}

    @staticmethod
    def _match(entries: list[dict[str, Any]], term: str, limit: int) -> list[dict[str, Any]]:
        needle = term.casefold()
        return [{"path": item["path"], "file_hash": item["file_hash"], "revision": item["revision"]} for item in entries if needle in item["path"].casefold() or needle in item["text"].casefold()][:limit]

    def _check_fresh(self, document: dict[str, Any], revision: str) -> None:
        if document.get("root") != str(self.root) or document.get("revision") != revision or document.get("policy") != self.policy.fingerprint() or document.get("indexer_version") != INDEXER_VERSION:
            raise StaleIndexError("index revision, policy, or indexer version differs")

    @staticmethod
    def _validate_entries(entries: Any, revision: str) -> None:
        if not isinstance(entries, list):
            raise IndexPolicyError("index entries must be a list")
        paths: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise IndexPolicyError("index entry must be an object")
            relative = entry.get("path")
            file_hash = entry.get("file_hash")
            if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise IndexPolicyError("index entry path escapes the checkout")
            if relative in paths or not isinstance(file_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", file_hash) or entry.get("revision") != revision:
                raise IndexPolicyError("index entry is malformed or duplicated")
            paths.add(relative)

    def _write(self, document: dict[str, Any]) -> None:
        if self.index_path.is_symlink():
            raise IndexPolicyError("index storage may not be a symlink")
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".codebase-index-", dir=self.index_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(document, handle, sort_keys=True, separators=(",", ":"))
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.index_path)
            os.chmod(self.index_path, 0o600)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @staticmethod
    def _read_no_follow(path: Path) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            if path.is_symlink():
                raise IndexPolicyError("symlinked file read rejected") from exc
            raise
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise IndexPolicyError("only regular files may be indexed")
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                return handle.read()
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _require_actor(actor: str) -> None:
        if not actor or not actor.strip() or actor.strip() != actor:
            raise IndexAccessError("auditable actor is required")
