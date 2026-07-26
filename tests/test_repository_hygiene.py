from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_gitignore_excludes_runtime_audit_and_credential_artifacts():
    rules = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    required = {
        "*.jsonl",
        "*.log",
        "*.sqlite",
        "*.sqlite3",
        "*.pem",
        "*.key",
        "*.p12",
        "*.credentials*",
        ".env",
        ".env.*",
        "hermes-swarm-runtime/",
        "hermes-swarm-audit/",
        "fable-evidence/",
    }
    assert required.issubset(set(rules))


def test_runtime_and_audit_roots_are_not_tracked():
    tracked = set(subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines())
    assert not any(path.startswith("hermes-swarm-runtime/") for path in tracked)
    assert not any(path.startswith("hermes-swarm-audit/") for path in tracked)


def test_no_private_key_block_is_tracked():
    import subprocess

    result = subprocess.run(
        ["git", "grep", "-n", "-I", "-E", "--", "-----BEGIN[[:space:]]+([^[:space:]]+[[:space:]]+)?PRIVATE[[:space:]]+KEY-----", "--", "."],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
