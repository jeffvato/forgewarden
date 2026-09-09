"""Bounded Microsoft Foundry exact-commit reviewer with transient credentials."""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .claude_verifier import schema
from .core import SwarmError, redact, validate_contract

try:
    import fcntl
except ImportError:  # pragma: no cover - WSL/Linux is required for live review
    fcntl = None


_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_AZURE_HOST = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:openai\.azure\.com|services\.ai\.azure\.com)$")
_TOKEN_SCOPE = "https://cognitiveservices.azure.com/.default"


class AzureFoundryError(SwarmError):
    """Foundry review configuration, authentication, or output is invalid."""


@dataclass(frozen=True)
class AzureFoundryConfig:
    endpoint: str
    deployment: str
    auth_method: str = "entra"
    timeout_seconds: int = 90
    max_response_bytes: int = 2_000_000
    max_completion_tokens: int = 4_000

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlsplit(self.endpoint)
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname or not _AZURE_HOST.fullmatch(parsed.hostname.lower()):
            raise AzureFoundryError("Foundry endpoint must be an approved Azure HTTPS host")
        if parsed.path.rstrip("/") not in {"", "/openai/v1"}:
            raise AzureFoundryError("Foundry endpoint must use the OpenAI v1 base route")
        if not _MODEL.fullmatch(self.deployment):
            raise AzureFoundryError("Foundry deployment identity is malformed")
        if self.auth_method not in {"entra", "api_key"}:
            raise AzureFoundryError("Foundry authentication method is unsupported")
        if not 1 <= self.timeout_seconds <= 300 or not 1 <= self.max_response_bytes <= 4_000_000 or not 1 <= self.max_completion_tokens <= 16_000:
            raise AzureFoundryError("Foundry resource bounds are invalid")


@dataclass(frozen=True)
class AzureCreditEvidence:
    remaining_microusd: int
    expires_at_epoch: float
    verified_at_epoch: float
    credit_only: bool
    spending_protection: bool

    def validate(self, *, now: float, max_age_seconds: float = 900.0) -> None:
        if not isinstance(self.remaining_microusd, int) or isinstance(self.remaining_microusd, bool) or self.remaining_microusd < 0:
            raise AzureFoundryError("Azure remaining-credit evidence is invalid")
        if any(not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) for value in (self.expires_at_epoch, self.verified_at_epoch)):
            raise AzureFoundryError("Azure credit timestamps are invalid")
        if not self.credit_only or not self.spending_protection:
            raise AzureFoundryError("Azure credit-only spending protection is not verified")
        if self.expires_at_epoch <= now:
            raise AzureFoundryError("Azure credits are expired")
        if self.verified_at_epoch > now or now - self.verified_at_epoch > max_age_seconds:
            raise AzureFoundryError("Azure credit evidence is stale")


class AzureCreditGuard:
    """Durably reserve worst-case review cost before any provider request."""

    def __init__(self, state_path: Path, evidence_resolver: Callable[[], AzureCreditEvidence], *, per_call_ceiling_microusd: int, reserve_microusd: int = 100_000_000, daily_call_limit: int = 20):
        if not state_path.is_absolute() or state_path.is_symlink() or per_call_ceiling_microusd <= 0 or reserve_microusd < 0 or not 1 <= daily_call_limit <= 1000:
            raise AzureFoundryError("Azure credit guard configuration is invalid")
        self.state_path = state_path
        self.evidence_resolver = evidence_resolver
        self.per_call_ceiling_microusd = per_call_ceiling_microusd
        self.reserve_microusd = reserve_microusd
        self.daily_call_limit = daily_call_limit

    def reserve(self, *, now: float | None = None) -> None:
        if fcntl is None:
            raise AzureFoundryError("Azure credit ledger locking is unavailable")
        lock_path = self.state_path.with_suffix(self.state_path.suffix + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        if lock_path.exists() and (lock_path.is_symlink() or not lock_path.is_file()):
            raise AzureFoundryError("Azure credit ledger lock path is unsafe")
        with lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                self._reserve_locked(now=now)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _reserve_locked(self, *, now: float | None = None) -> None:
        current = time.time() if now is None else now
        evidence = self.evidence_resolver()
        if not isinstance(evidence, AzureCreditEvidence):
            raise AzureFoundryError("Azure credit evidence is unavailable")
        evidence.validate(now=current)
        if evidence.remaining_microusd - self.reserve_microusd < self.per_call_ceiling_microusd:
            raise AzureFoundryError("Azure credit reserve would be breached")
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if self.state_path.exists() and (self.state_path.is_symlink() or not self.state_path.is_file()):
            raise AzureFoundryError("Azure credit ledger path is unsafe")
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8")) if self.state_path.exists() else {}
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AzureFoundryError("Azure credit ledger is unreadable") from exc
        day = time.strftime("%Y-%m-%d", time.gmtime(current))
        if state.get("day") != day:
            state = {"version": 1, "day": day, "calls": 0, "reserved_microusd": 0}
        if set(state) != {"version", "day", "calls", "reserved_microusd"} or state["version"] != 1:
            raise AzureFoundryError("Azure credit ledger schema is invalid")
        calls = int(state["calls"])
        reserved = int(state["reserved_microusd"])
        if calls >= self.daily_call_limit:
            raise AzureFoundryError("Azure daily review limit reached")
        if reserved + self.per_call_ceiling_microusd > evidence.remaining_microusd - self.reserve_microusd:
            raise AzureFoundryError("Azure local credit ceiling reached")
        state["calls"] = calls + 1
        state["reserved_microusd"] = reserved + self.per_call_ceiling_microusd
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{self.state_path.name}.", dir=self.state_path.parent)
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            with temporary.open("w", encoding="utf-8") as handle:
                json.dump(state, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.state_path)
        finally:
            temporary.unlink(missing_ok=True)


def azure_credit_evidence_from_environment() -> AzureCreditEvidence:
    """Load non-secret operator-verified credit evidence; absent values deny calls."""
    try:
        return AzureCreditEvidence(
            remaining_microusd=int(os.environ["FORGEWARDEN_AZURE_CREDIT_REMAINING_MICROUSD"]),
            expires_at_epoch=float(os.environ["FORGEWARDEN_AZURE_CREDIT_EXPIRES_EPOCH"]),
            verified_at_epoch=float(os.environ["FORGEWARDEN_AZURE_CREDIT_VERIFIED_EPOCH"]),
            credit_only=os.environ.get("FORGEWARDEN_AZURE_CREDIT_ONLY") == "1",
            spending_protection=os.environ.get("FORGEWARDEN_AZURE_SPENDING_PROTECTION") == "1",
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AzureFoundryError("Azure credit-only evidence is not configured") from exc


def default_azure_credit_guard() -> AzureCreditGuard:
    """Construct the deny-by-default local guard from explicit operator limits."""
    try:
        ceiling = int(os.environ["FORGEWARDEN_AZURE_MAX_CALL_MICROUSD"])
        reserve = int(os.environ.get("FORGEWARDEN_AZURE_CREDIT_RESERVE_MICROUSD", "100000000"))
        daily = int(os.environ.get("FORGEWARDEN_AZURE_DAILY_REVIEW_LIMIT", "20"))
    except (KeyError, TypeError, ValueError) as exc:
        raise AzureFoundryError("Azure per-call credit ceiling is not configured") from exc
    state_path = Path(os.environ.get("FORGEWARDEN_AZURE_CREDIT_LEDGER", "~/.cache/forgewarden/azure-credit-ledger.json")).expanduser().resolve()
    return AzureCreditGuard(state_path, azure_credit_evidence_from_environment, per_call_ceiling_microusd=ceiling, reserve_microusd=reserve, daily_call_limit=daily)


def azure_cli_token(*, runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run) -> str:
    """Resolve one Entra token through the authenticated Azure CLI without persisting it."""
    completed = runner(
        ["az", "account", "get-access-token", "--scope", _TOKEN_SCOPE, "--query", "accessToken", "-o", "tsv"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30, check=False,
    )
    token = completed.stdout.strip() if completed.returncode == 0 else ""
    if not token or any(char.isspace() for char in token) or len(token) > 16_384:
        detail = redact(completed.stderr.strip())[:500] if completed.stderr else "token unavailable"
        raise AzureFoundryError(f"Azure CLI credential unavailable: {detail}")
    return token


class AzureFoundryReviewer:
    """Submit bounded text only; the provider receives no repository or tool access."""

    def __init__(self, config: AzureFoundryConfig, credential_resolver: Callable[[], str], credit_guard: AzureCreditGuard, *, opener: Callable[..., Any] = urllib.request.urlopen):
        self.config = config
        self._credential_resolver = credential_resolver
        self._credit_guard = credit_guard
        self._opener = opener

    def run(self, snapshot: object, job_id: str, commit: str, prompt: str) -> dict[str, Any]:
        del snapshot
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt.encode("utf-8")) > 48_000:
            raise AzureFoundryError("Foundry review prompt is missing or exceeds its bound")
        self._credit_guard.reserve()
        credential = self._credential_resolver()
        if not isinstance(credential, str) or not credential or any(char.isspace() for char in credential) or len(credential) > 16_384:
            raise AzureFoundryError("Foundry credential resolver returned invalid material")
        payload = {
            "model": self.config.deployment,
            "messages": [
                {"role": "system", "content": "You are an independent read-only code reviewer. Model output is advisory. Return only the required JSON object."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
            "max_completion_tokens": self.config.max_completion_tokens,
            "response_format": {"type": "json_schema", "json_schema": {"name": "forgewarden_review", "strict": True, "schema": schema(job_id, commit)}},
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        headers["Authorization" if self.config.auth_method == "entra" else "api-key"] = ("Bearer " + credential) if self.config.auth_method == "entra" else credential
        endpoint = self.config.endpoint.rstrip("/")
        if not endpoint.endswith("/openai/v1"):
            endpoint += "/openai/v1"
        request = urllib.request.Request(endpoint + "/chat/completions", data=json.dumps(payload, separators=(",", ":")).encode("utf-8"), headers=headers, method="POST")
        try:
            with self._opener(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read(self.config.max_response_bytes + 1)
        except (OSError, urllib.error.URLError) as exc:
            raise AzureFoundryError(f"Foundry request failed: {redact(str(exc))[:500]}") from exc
        if len(raw) > self.config.max_response_bytes:
            raise AzureFoundryError("Foundry response exceeds its byte bound")
        try:
            envelope = json.loads(raw.decode("utf-8"))
            content = envelope["choices"][0]["message"]["content"]
            result = json.loads(content) if isinstance(content, str) else content
        except (UnicodeError, json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise AzureFoundryError("Foundry returned malformed review output") from exc
        if not isinstance(result, dict):
            raise AzureFoundryError("Foundry review output must be an object")
        validate_contract(result, "claude", expected_job_id=job_id, expected_commit=commit)
        return result
