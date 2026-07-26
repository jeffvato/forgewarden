import json
from pathlib import Path

import pytest

from swarm.core import SwarmError
from swarm.gemini_recovery import _prior_invalid_payload


def test_prior_invalid_payload_rejects_symlinked_audit(tmp_path: Path):
    outside = tmp_path / "outside.jsonl"
    outside.write_text(json.dumps({"job_id": "job-1", "missing_tests": ["x"]}) + "\n", encoding="utf-8")
    audit = tmp_path / "audit.jsonl"
    audit.symlink_to(outside)

    with pytest.raises(SwarmError):
        _prior_invalid_payload(audit, "job-1", "a" * 40)
