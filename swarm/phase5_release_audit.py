"""Read-only Phase 5 release scrubber; it never edits or publishes files."""
from __future__ import annotations

import re
from pathlib import Path


PATTERNS = (
    ("user_home_path", re.compile(r"(?i)(/home/jeff|c:\\\\users\\\\jeff|/Users/jeff)")),
    ("credential_assignment", re.compile(r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s]+")),
    ("private_audit", re.compile(r"(?i)(audit\.jsonl|private[-_ ]audit|customer[_-]data)")),
    ("machine_fingerprint", re.compile(r"(?i)(Ubuntu-24\.04|hostname|machine[-_ ]id|serial[-_ ]number)")),
)

GENERATED_PARTS = frozenset({".integration-runtime", ".pytest_cache", ".swarm", "__pycache__"})
LOCAL_ONLY_NAMES = frozenset({"Hermes-Codex-Gemini-Swarm-Master-Project-Record.md"})
PRIVATE_RELEASE_PATHS = frozenset({
    "docs/csv-baseline-manifest.md",
    "docs/controlled-baseline-0rtmvv09-postmortem.md",
    "docs/deadline-writer-wiring-validation.md",
    "docs/first-controlled-repair.md",
    "docs/first-controlled-repair-v2.md",
    "docs/first-controlled-repair-v2-final.md",
    "docs/first-controlled-repair-v2-retry.md",
    "docs/n8n-onboarding-report.md",
    "docs/pre-activation-report.md",
    "docs/phase5-release-audit-result.json",
    "docs/phase5-release-readiness.md",
    "docs/phase5-release-remediation-plan.md",
    "docs/phase5-release-triage.json",
})


class ReleaseAudit:
    """Scan a disposable candidate tree without changing it."""

    def __init__(self, root: Path):
        self.root = root

    def scan(self) -> dict[str, object]:
        findings: list[dict[str, object]] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path.is_symlink() or ".git" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                findings.append({"category": "unreadable_file", "path": str(path.relative_to(self.root))})
                continue
            for category, pattern in PATTERNS:
                if pattern.search(text):
                    findings.append({"category": category, "path": str(path.relative_to(self.root))})
        return {"publication": "DISABLED", "mutation_performed": False, "findings": findings, "clean": not findings}

    def inventory(self) -> dict[str, object]:
        """Return findings with explicit review placeholders; never classify silently."""
        result = self.scan()
        findings = [
            {
                **finding,
                "ownership": (
                    "PROJECT_GENERATED"
                    if GENERATED_PARTS.intersection(Path(finding["path"]).parts)
                    else "LOCAL_PROJECT_RECORD"
                    if Path(finding["path"]).name in LOCAL_ONLY_NAMES
                    else "PRIVATE_PROJECT_ARTIFACT"
                    if finding["path"] in PRIVATE_RELEASE_PATHS or Path(finding["path"]).name.endswith(".save")
                    else "PROJECT_TEST_FIXTURE"
                    if "tests" in Path(finding["path"]).parts
                    else "PROJECT_OWNED"
                ),
                "intended_public_status": (
                    "EXCLUDE_FROM_RELEASE"
                    if GENERATED_PARTS.intersection(Path(finding["path"]).parts)
                    else "EXCLUDE_FROM_RELEASE"
                    if Path(finding["path"]).name in LOCAL_ONLY_NAMES
                    else "EXCLUDE_FROM_RELEASE"
                    if finding["path"] in PRIVATE_RELEASE_PATHS or Path(finding["path"]).name.endswith(".save")
                    else "REVIEW_REQUIRED"
                ),
            }
            for finding in result["findings"]
        ]
        return {
            "publication": result["publication"],
            "mutation_performed": result["mutation_performed"],
            "clean": result["clean"],
            "findings": findings,
        }
