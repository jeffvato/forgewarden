"""Read-only, fail-closed bootstrap state for the ForgeWarden supervisor."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping


MAX_CONTROL_FILE_BYTES = 1_048_576
_SHA1 = re.compile(r"[0-9a-fA-F]{40}")
_TASK_ID = re.compile(r"FWQ-[0-9]{4}")

CONTROL_FILE_REQUIREMENTS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "AGENTS.md": (
            "# ForgeWarden repository instructions",
            "## Authority and agent roles",
            "## Persistent project state",
            "## Continuous work loop",
            "## Stop conditions",
            "## Safety invariants",
            "## Product principle",
        ),
        "ROADMAP.md": (
            "# ForgeWarden Roadmap",
            "## Current implementation priority",
            "## Core trust model",
            "## Active / foundational requirement families",
            "## Broader approved security roadmap",
            "## Additional approved platform capabilities",
            "## Phase discipline",
        ),
        "WORK_QUEUE.md": (
            "# ForgeWarden Work Queue",
            "## States",
            "## Queue rules",
            "## Active queue",
            "## Future queue population",
        ),
        "SWARM_STATUS.md": (
            "# ForgeWarden Swarm Status",
            "## Current state",
            "## Resume protocol",
            "## Work-unit checkpoint",
            "## Stop conditions",
        ),
        "DECISIONS.md": (
            "# ForgeWarden Architectural Decisions",
            "## D-001 — Human/root authority remains above AI",
            "## D-016 — ForgeWarden Core scope is frozen",
        ),
        "BLOCKERS.md": (
            "# ForgeWarden Blockers",
            "## Current blockers",
            "## What is not a blocker",
            "## Blocker record format",
        ),
    }
)

CHECKPOINT_FIELDS = (
    "Task ID",
    "Starting commit",
    "Candidate commit",
    "Accepted commit",
    "Files changed",
    "Deterministic validation",
    "Claude review",
    "Gemini review",
    "Unresolved findings",
    "Blocker",
    "Next action",
)


class ControlStateError(ValueError):
    """Raised when repository control-state evidence is missing or invalid."""


@dataclass(frozen=True)
class ControlFile:
    name: str
    path: Path
    content: str
    sha256: str


@dataclass(frozen=True)
class ResumeState:
    checkpoint: Mapping[str, str]
    interrupted: bool


@dataclass(frozen=True)
class SupervisorState:
    repository_root: Path
    files: Mapping[str, ControlFile]
    resume: ResumeState


def _open_flags(*, directory: bool = False) -> int:
    """Return flags that prevent following links and blocking special files."""
    required = ("O_NOFOLLOW", "O_NONBLOCK")
    missing = [name for name in required if not hasattr(os, name)]
    if missing:
        raise ControlStateError("safe control-state reads unavailable: " + ", ".join(missing))
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if directory:
        if not hasattr(os, "O_DIRECTORY"):
            raise ControlStateError("safe control-state directory reads unavailable: O_DIRECTORY")
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _validate_root_path_chain(root: Path) -> None:
    if not root.is_absolute():
        raise ControlStateError("repository root must be an absolute path")
    if ".." in root.parts:
        raise ControlStateError("repository root must not contain parent traversal")
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError as exc:
            raise ControlStateError(f"repository root does not exist: {root}") from exc
        except OSError as exc:
            raise ControlStateError(f"unable to inspect repository root path: {current}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ControlStateError(f"repository root path contains symlink: {current}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ControlStateError(f"repository root path component is not a directory: {current}")


def _open_repository_root(root: Path) -> int:
    _validate_root_path_chain(root)
    try:
        descriptor = os.open(root, _open_flags(directory=True))
    except OSError as exc:
        raise ControlStateError(f"unable to open repository root safely: {root}") from exc
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise ControlStateError(f"repository root is not a directory: {root}")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_control_file(root_descriptor: int, path: Path, name: str) -> str:
    """Read a bounded regular file relative to an already-open repository root."""
    try:
        descriptor = os.open(name, _open_flags(), dir_fd=root_descriptor)
    except FileNotFoundError as exc:
        raise ControlStateError(f"missing required control file: {name}") from exc
    except OSError as exc:
        raise ControlStateError(f"unable to read control file safely: {name}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ControlStateError(f"control file must be a regular file: {name}")
        if metadata.st_size > MAX_CONTROL_FILE_BYTES:
            raise ControlStateError(f"control file exceeds {MAX_CONTROL_FILE_BYTES} bytes: {name}")
        payload = bytearray()
        while len(payload) <= MAX_CONTROL_FILE_BYTES:
            try:
                chunk = os.read(descriptor, min(65_536, MAX_CONTROL_FILE_BYTES + 1 - len(payload)))
            except BlockingIOError as exc:
                raise ControlStateError(f"control file could not be read without blocking: {name}") from exc
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MAX_CONTROL_FILE_BYTES:
            raise ControlStateError(f"control file exceeds {MAX_CONTROL_FILE_BYTES} bytes: {name}")
    finally:
        os.close(descriptor)
    try:
        return bytes(payload).decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeDecodeError as exc:
        raise ControlStateError(f"control file is not valid UTF-8: {name}") from exc


def _validate_section_structure(name: str, content: str) -> None:
    lines = content.splitlines()
    first_content = next((line for line in lines if line.strip()), "")
    expected = CONTROL_FILE_REQUIREMENTS[name]
    if first_content != expected[0]:
        raise ControlStateError(f"malformed control file {name}: invalid document title")
    positions: list[int] = []
    for heading in expected[1:]:
        matches = [index for index, line in enumerate(lines) if line == heading]
        if len(matches) != 1:
            raise ControlStateError(f"malformed control file {name}: required heading must appear exactly once: {heading}")
        positions.append(matches[0])
    if positions != sorted(positions):
        raise ControlStateError(f"malformed control file {name}: required headings are out of order")


def _validate_work_queue(content: str) -> None:
    tasks = re.findall(r"^### (FWQ-[0-9]{4}) — .+$", content, flags=re.MULTILINE)
    if not tasks or len(tasks) != len(set(tasks)):
        raise ControlStateError("malformed WORK_QUEUE.md: task identifiers are missing or duplicated")
    for task_id in tasks:
        match = re.search(
            rf"^### {re.escape(task_id)} — .*?(?=^### |\Z)", content, flags=re.MULTILINE | re.DOTALL
        )
        assert match is not None
        missing = [field for field in ("Requirement", "State", "Priority", "Dependencies", "Description") if not re.search(rf"^- {field}: .+$", match.group(0), flags=re.MULTILINE)]
        if missing:
            raise ControlStateError(f"malformed WORK_QUEUE.md task {task_id}: missing field(s): {', '.join(missing)}")


def _validate_content(name: str, content: str) -> None:
    if not content.strip():
        raise ControlStateError(f"control file is empty: {name}")
    _validate_section_structure(name, content)
    if name == "AGENTS.md" and ("`DRY_RUN` remains enforced" not in content or "Deployment remains disabled" not in content):
        raise ControlStateError("malformed AGENTS.md: DRY_RUN and deployment-disabled safeguards are required")
    if name == "SWARM_STATUS.md" and ("- Repository safety mode: DRY_RUN" not in content or "- Deployment: disabled" not in content):
        raise ControlStateError("malformed SWARM_STATUS.md: DRY_RUN and deployment-disabled safeguards are required")
    if name == "WORK_QUEUE.md":
        _validate_work_queue(content)


def _parse_resume_state(status_content: str) -> ResumeState:
    checkpoint: dict[str, str] = {}
    in_checkpoint = False
    for line in status_content.splitlines():
        if line == "## Work-unit checkpoint":
            in_checkpoint = True
            continue
        if in_checkpoint and line.startswith("## "):
            break
        if not in_checkpoint or not line.startswith("- "):
            continue
        field, separator, value = line[2:].partition(":")
        if separator and field in CHECKPOINT_FIELDS:
            if field in checkpoint:
                raise ControlStateError(f"malformed SWARM_STATUS.md checkpoint: duplicate field: {field}")
            checkpoint[field] = value.strip().strip("`").strip()

    missing = [field for field in CHECKPOINT_FIELDS if not checkpoint.get(field)]
    if missing:
        raise ControlStateError("malformed SWARM_STATUS.md checkpoint: missing field(s): " + ", ".join(missing))

    task_id = checkpoint["Task ID"]
    commits = {field: checkpoint[field] for field in ("Starting commit", "Candidate commit", "Accepted commit")}
    for field, value in commits.items():
        if value != "none" and not _SHA1.fullmatch(value):
            raise ControlStateError(f"malformed SWARM_STATUS.md checkpoint: {field} must be none or a full Git SHA-1")
    if task_id == "none":
        if any(value != "none" for value in commits.values()):
            raise ControlStateError("malformed SWARM_STATUS.md checkpoint: taskless checkpoints cannot contain task-specific commits")
    elif not _TASK_ID.fullmatch(task_id):
        raise ControlStateError("malformed SWARM_STATUS.md checkpoint: Task ID must be none or an FWQ identifier")
    else:
        if commits["Starting commit"] == "none":
            raise ControlStateError("malformed SWARM_STATUS.md checkpoint: active tasks require a starting commit")
        if commits["Accepted commit"] != "none":
            if commits["Candidate commit"] == "none":
                raise ControlStateError("malformed SWARM_STATUS.md checkpoint: accepted commits require a candidate commit")
            if commits["Accepted commit"].lower() != commits["Candidate commit"].lower():
                raise ControlStateError("malformed SWARM_STATUS.md checkpoint: accepted commit must equal candidate commit")

    return ResumeState(
        checkpoint=MappingProxyType(dict(checkpoint)),
        interrupted=task_id != "none" and commits["Accepted commit"] == "none",
    )


def load_supervisor_state(repository_root: Path) -> SupervisorState:
    """Load fixed control-state evidence without mutating disk or granting authority."""
    root = Path(repository_root).expanduser()
    root_descriptor = _open_repository_root(root)
    try:
        files: dict[str, ControlFile] = {}
        for name in CONTROL_FILE_REQUIREMENTS:
            path = root / name
            content = _read_control_file(root_descriptor, path, name)
            _validate_content(name, content)
            files[name] = ControlFile(name, path, content, hashlib.sha256(content.encode("utf-8")).hexdigest())
    finally:
        os.close(root_descriptor)

    return SupervisorState(root, MappingProxyType(files), _parse_resume_state(files["SWARM_STATUS.md"].content))
