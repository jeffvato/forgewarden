import json
from pathlib import Path
from typing import Any

from swarm.codebase_index import CodebaseIndex, INDEXER_VERSION


def build_index_evidence(report_path: Path, repository: Path, index_path: Path, revision: str, actor: str) -> dict[str, Any]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    findings = report.get("findings", [])
    paths = sorted({item["file"] for item in findings if isinstance(item, dict) and isinstance(item.get("file"), str)})
    index = CodebaseIndex(repository, index_path)
    matched: list[str] = []
    missing: list[str] = []
    for path in paths:
        results = index.query(path, revision, actor, limit=50, fresh_scan=False)
        if any(item.get("path") == path for item in results):
            matched.append(path)
        else:
            missing.append(path)
    return {
        "schema_version": "1",
        "mode": "READ_ONLY",
        "repository": str(Path(repository).expanduser().resolve()),
        "revision": revision,
        "indexer_version": INDEXER_VERSION,
        "actor": actor,
        "finding_files": paths,
        "matched_files": matched,
        "missing_files": missing,
    }
