"""Read-only Phase 5 release scrubber; it never edits or publishes files."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
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


_HISTORY_PATTERNS = (
    ("credential_material", "BLOCKING", re.compile(
        rb"(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|"
        rb"(api[_-]?key|token|password|secret)\s*[:=]\s*['\"][^'\"]{12,}['\"])")),
    ("personal_home_path", "BLOCKING", re.compile(
        rb"(?i)(/home/[a-z0-9._-]+/|[a-z]:\\users\\[a-z0-9._-]+\\|/Users/[a-z0-9._-]+/)")),
)
_SENSITIVE_PATH = re.compile(r"(?i)(^|/)(\.env($|\.)|\.swarm-state/|audit\.jsonl$|[^/]+\.(pem|key)$)")
_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_REF = re.compile(r"^refs/[A-Za-z0-9._/@+-]+$")
_LIMITS = {
    "refs": 256, "commits": 5000, "objects": 10000, "blob_bytes": 2 * 1024 * 1024,
    "batch_blob_bytes": 8 * 1024 * 1024, "total_blob_bytes": 256 * 1024 * 1024,
    "findings": 512, "git_output": 40 * 1024 * 1024,
}
_STRATEGIES = frozenset({"PRESERVE_HISTORY", "SANITIZED_SINGLE_COMMIT"})
_SANITIZED_IDENTIFIERS = {
    "REMOVE_OR_REPLACE": (
        "personal_names_usernames_emails_and_home_paths",
        "azure_cloud_tenant_subscription_resource_identifiers",
        "internal_urls_hosts_addresses_and_machine_fingerprints",
        "historical_commit_job_evidence_and_provider_session_identifiers",
        "credential_shaped_fixtures",
        "customer_tenant_endpoint_and_asset_examples",
        "media_without_provenance_and_metadata_clearance",
    ),
    "PRESERVE_STABLE_PUBLIC_CONTRACTS": (
        "forgewarden_requirement_identifiers",
        "versioned_schema_identifiers",
        "documented_api_identifiers",
        "deterministic_fictional_demo_identifiers",
    ),
}


def _history_policy_sha256() -> str:
    policy = {
        "version": 1,
        "limits": _LIMITS,
        "patterns": [(name, severity, pattern.pattern.decode("ascii"))
                     for name, severity, pattern in _HISTORY_PATTERNS],
        "sensitive_path": _SENSITIVE_PATH.pattern,
        "sanitized_identifiers": _SANITIZED_IDENTIFIERS,
    }
    encoded = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


class HistoryReleaseAudit:
    """Read reachable Git history without changing refs, objects, or the worktree."""

    def __init__(self, root: Path):
        if root.is_symlink():
            raise ValueError("history audit repository must be a real directory")
        self.root = root.resolve()
        if not self.root.is_dir():
            raise ValueError("history audit repository must be a real directory")

    def _git(self, *args: str, stdin: bytes | None = None) -> bytes:
        try:
            result = subprocess.run(
                ["git", "-C", str(self.root), *args], input=stdin,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
                check=False, timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("history audit Git operation failed") from exc
        if result.returncode or len(result.stdout) > _LIMITS["git_output"]:
            raise ValueError("history audit Git operation failed")
        return result.stdout

    @staticmethod
    def _sha(value: str) -> str:
        if not _SHA.fullmatch(value):
            raise ValueError("history audit received an invalid object identifier")
        return value

    @staticmethod
    def _path(value: str) -> str:
        parts = value.split("/")
        if (not value or len(value.encode()) > 240 or value.startswith("/") or "\\" in value
                or any(part in {"", ".", ".."} for part in parts)
                or any(ord(character) < 32 or ord(character) == 127 for character in value)):
            raise ValueError("history audit received an unsafe repository path")
        return value

    def _head(self) -> str:
        return self._sha(self._git("rev-parse", "--verify", "HEAD^{commit}").decode().strip())

    def _refs(self) -> tuple[list[tuple[str, str]], str]:
        refs = []
        for line in self._git("for-each-ref", "--format=%(refname)%00%(objectname)").decode().splitlines():
            fields = line.split("\0")
            if len(fields) != 2 or not _REF.fullmatch(fields[0]):
                raise ValueError("history audit received an unsafe ref")
            refs.append((fields[0], self._sha(fields[1])))
        refs.sort()
        if not refs or len(refs) > _LIMITS["refs"]:
            raise ValueError("history audit ref budget exceeded")
        digest = hashlib.sha256(json.dumps(refs, separators=(",", ":")).encode()).hexdigest()
        return refs, digest

    def _read_blob_batch(self, sizes: dict[str, int]) -> dict[str, bytes]:
        batch_bytes = sum(sizes.values())
        if any(size < 0 or size > _LIMITS["blob_bytes"] for size in sizes.values()):
            raise ValueError("history audit received invalid blob size")
        if batch_bytes > _LIMITS["batch_blob_bytes"]:
            raise ValueError("history audit blob batch budget exceeded")
        if not sizes:
            return {}
        selected = sorted(sizes)
        raw = self._git("cat-file", "--batch", stdin=("\n".join(selected) + "\n").encode())
        if len(raw) > _LIMITS["batch_blob_bytes"] + len(selected) * 96:
            raise ValueError("history audit blob batch output budget exceeded")
        contents, offset = {}, 0
        for oid in selected:
            newline = raw.find(b"\n", offset)
            header = raw[offset:newline].decode().split(" ") if newline >= 0 else []
            if len(header) != 3 or header[:2] != [oid, "blob"]:
                raise ValueError("history audit received malformed blob data")
            try:
                size = int(header[2])
            except ValueError as exc:
                raise ValueError("history audit received malformed blob data") from exc
            if size != sizes[oid]:
                raise ValueError("history audit received malformed blob data")
            start, end = newline + 1, newline + 1 + size
            if end >= len(raw) or raw[end:end + 1] != b"\n":
                raise ValueError("history audit received malformed blob data")
            contents[oid], offset = raw[start:end], end + 1
        if offset != len(raw):
            raise ValueError("history audit received malformed blob data")
        return contents

    def _content_batches(self, sizes: dict[str, int]):
        if any(size < 0 for size in sizes.values()):
            raise ValueError("history audit received invalid blob size")
        selected = [(oid, size) for oid, size in sorted(sizes.items())
                    if size <= _LIMITS["blob_bytes"]]
        if sum(size for _, size in selected) > _LIMITS["total_blob_bytes"]:
            raise ValueError("history audit aggregate blob budget exceeded")
        batch, batch_bytes = {}, 0
        for oid, size in selected:
            if batch and batch_bytes + size > _LIMITS["batch_blob_bytes"]:
                yield self._read_blob_batch(batch)
                batch, batch_bytes = {}, 0
            batch[oid] = size
            batch_bytes += size
        if batch:
            yield self._read_blob_batch(batch)

    def _first_commit(self, oid: str, path: str) -> str:
        commits = self._git(
            "log", "--all", "--reverse", "--format=%H", f"--find-object={oid}", "--", path
        ).decode().splitlines()
        if not commits:
            raise ValueError("history audit could not bind a finding to a commit")
        return self._sha(commits[0])

    def scan(self, *, expected_head: str, strategy: str) -> dict[str, object]:
        expected = self._sha(expected_head)
        if strategy not in _STRATEGIES:
            raise ValueError("unsupported history publication strategy")
        if self._head() != expected:
            raise ValueError("history audit HEAD does not match the exact candidate")
        refs, ref_hash = self._refs()

        commits = [self._sha(item) for item in self._git("rev-list", "--all").decode().splitlines()]
        if not commits or len(commits) > _LIMITS["commits"]:
            raise ValueError("history audit commit budget exceeded")
        commit_set = set(commits)

        paths, object_ids = [], set()
        lines = self._git("rev-list", "--objects", "--all").decode().splitlines()
        if len(lines) > _LIMITS["objects"]:
            raise ValueError("history audit object budget exceeded")
        for line in lines:
            oid, separator, path = line.partition(" ")
            object_ids.add(self._sha(oid))
            if separator and path:
                paths.append((oid, self._path(path)))

        request = ("\n".join(sorted(object_ids)) + "\n").encode()
        sizes = {}
        for line in self._git(
            "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)", stdin=request
        ).decode().splitlines():
            fields = line.split(" ")
            if len(fields) != 3:
                raise ValueError("history audit received malformed object metadata")
            oid = self._sha(fields[0])
            if fields[1] == "blob":
                sizes[oid] = int(fields[2])
        path_object_ids = {oid for oid, _ in paths}
        if set(sizes) - path_object_ids:
            raise ValueError("history audit found an unbound reachable blob")
        matched_content: dict[str, list[tuple[str, str]]] = {}
        for content_batch in self._content_batches(sizes):
            for oid, content in content_batch.items():
                matched_content[oid] = [
                    (name, severity) for name, severity, pattern in _HISTORY_PATTERNS
                    if pattern.search(content)
                ]

        current = set()
        for line in self._git("ls-tree", "-r", "--full-tree", "HEAD").decode().splitlines():
            metadata, separator, path = line.partition("\t")
            fields = metadata.split(" ")
            if not separator or len(fields) != 3:
                raise ValueError("history audit received malformed current tree data")
            current.add((self._sha(fields[2]), self._path(path)))

        findings = []
        for line in self._git("log", "--all", "--reverse", "--format=%H%x00%ae%x00%ce").decode().splitlines():
            fields = line.split("\0")
            if len(fields) != 3 or self._sha(fields[0]) not in commit_set:
                raise ValueError("history audit received malformed commit identity data")
            if any(email and not email.lower().endswith(
                    ("@example.invalid", "@example.com", "@users.noreply.github.com"))
                   for email in fields[1:]):
                findings.append({
                    "category": "identifying_git_identity", "severity": "REVIEW",
                    "path": "@commit-metadata", "first_commit": fields[0],
                    "blob_hash": None, "scope": "HISTORY_METADATA",
                })
                break

        for oid, path in sorted(set(paths)):
            if oid not in sizes:
                continue
            categories = ([("oversize_blob", "BLOCKING")]
                          if sizes[oid] > _LIMITS["blob_bytes"]
                          else list(matched_content[oid]))
            if _SENSITIVE_PATH.search(path):
                categories.append(("sensitive_operational_path", "BLOCKING"))
            for category, severity in categories:
                findings.append({
                    "category": category,
                    "severity": severity,
                    "path": "<redacted-path>" if _HISTORY_PATTERNS[0][2].search(path.encode()) else path,
                    "first_commit": self._first_commit(oid, path),
                    "blob_hash": oid,
                    "scope": "CURRENT_AND_HISTORY" if (oid, path) in current else "HISTORY_ONLY",
                })
                if len(findings) > _LIMITS["findings"]:
                    raise ValueError("history audit finding budget exceeded")

        final_refs, final_ref_hash = self._refs()
        if self._head() != expected or final_refs != refs or final_ref_hash != ref_hash:
            raise ValueError("history audit repository state drifted during inspection")
        findings.sort(key=lambda item: (
            str(item["category"]), str(item["path"]), str(item["first_commit"]), str(item["blob_hash"])))
        blocking = sum(item["severity"] == "BLOCKING" for item in findings)
        disposition = ("DENIED" if strategy == "PRESERVE_HISTORY" and blocking
                       else "CANDIDATE_PROOF_REQUIRED" if strategy == "SANITIZED_SINGLE_COMMIT"
                       else "HUMAN_REVIEW_REQUIRED")
        return {
            "schema_version": "1", "audit_kind": "EXACT_GIT_HISTORY",
            "publication": "DISABLED", "mutation_performed": False, "strategy": strategy,
            "expected_head": expected, "observed_head": expected,
            "ref_set_sha256": ref_hash, "policy_sha256": _history_policy_sha256(),
            "refs_scanned": len(refs), "commits_scanned": len(commits), "blobs_scanned": len(sizes),
            "matched_values_included": False, "blocking_finding_count": blocking,
            "findings": findings, "candidate_proof_required": strategy == "SANITIZED_SINGLE_COMMIT",
            "disposition": disposition,
        }
