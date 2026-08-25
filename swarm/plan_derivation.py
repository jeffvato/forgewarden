"""Bounded derivation of the next authorized ForgeWarden Core queue item."""
from __future__ import annotations

import re
from pathlib import Path

from .autonomous_loop import TaskSpec


def derive_next_core_task(repository: Path, existing_ids: set[str]) -> TaskSpec | None:
    """Derive only the explicitly planned Core queue-population task.

    Broader roadmap families are deliberately excluded; the active roadmap
    authorizes finishing Core queue population before expansion work.
    """
    roadmap = Path(repository) / "ROADMAP.md"
    queue = Path(repository) / "WORK_QUEUE.md"
    if not roadmap.is_file() or not queue.is_file():
        return None
    roadmap_text = roadmap.read_text(encoding="utf-8")
    queue_text = queue.read_text(encoding="utf-8")
    if "# ForgeWarden Roadmap" not in roadmap_text or "## Current implementation priority" not in roadmap_text:
        return None
    if "## Future queue population" not in queue_text or "ForgeWarden Core" not in roadmap_text:
        return None
    queue_ids = set(re.findall(r"^###\s+(FWQ-\d{4})\s+—", queue_text, flags=re.MULTILINE))
    numbers = [
        int(match.group(1))
        for value in existing_ids | queue_ids
        if (match := re.fullmatch(r"FWQ-(\d{4})", value))
    ]
    next_number = max(numbers or [0]) + 1
    task_id = f"FWQ-{next_number:04d}"
    return TaskSpec(
        task_id=task_id,
        requirement="Core supervisor/roadmap",
        description="Populate the next bounded Core work item from the active ForgeWarden roadmap and preserve dependency, approval, and validation metadata.",
        priority=2,
        allowed_paths=("WORK_QUEUE.md",),
        acceptance=("next Core task is explicit and bounded", "future security families remain parked"),
        target_path="WORK_QUEUE.md",
        expected_behavior="add one explicitly authorized bounded Core work item to the future queue",
        failing_assertion="the active queue has no eligible READY task after current milestone completion",
        test_command=("python3", "-m", "pytest", "-q", "tests/test_task_selection.py"),
        authorized=True,
    )
