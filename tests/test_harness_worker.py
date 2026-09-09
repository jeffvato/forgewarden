import pytest

from swarm.harness_context import BudgetAdmission, BudgetUsage, ContextItem, build_context_packet
from swarm.harness_task import HarnessTask, TaskStatus
from swarm.harness_worker import HarnessWorkerError, WorkerRegistration, WorkerRegistry, WorkerRequest, WorkerRole, WorkerTransport, default_cli_registrations, plan_invocation, validate_worker_output


NOW = "2026-09-09T12:00:00+00:00"


def task(model="approved-model"):
    return HarnessTask(task_id="FWQ-0068", requirement_id="FW-HARNESS-004", title="Workers", description="Govern workers", status=TaskStatus.READY, priority=0, assigned_role="CODE_WRITER", assigned_model=model, repository="/repo", created_at=NOW, relevant_files=("swarm/harness_worker.py", "tests"))


def request(worker="codex-cli", role=WorkerRole.CODE_WRITER, model="approved-model", credential=None):
    current = task(model)
    context = build_context_packet(current, (ContextItem("architecture_constraint", "D-023", "AI has no authority"), ContextItem("task_state", current.task_id, "ready"), ContextItem("forbidden_change", "deployment", "disabled")))
    return WorkerRequest(current, context, BudgetAdmission(current.task_id, worker, BudgetUsage(model_calls=1), BudgetUsage(model_calls=1)), worker, role, credential)


def registry():
    return WorkerRegistry((WorkerRegistration("codex-cli", "openai", "approved-model", WorkerTransport.CLI, (WorkerRole.CODE_WRITER,), True, executable="codex"),))


def test_initial_cli_registry_binds_agy_to_read_only_gemini():
    records = WorkerRegistry(default_cli_registrations(codex_model="codex-model", claude_model="claude-model", gemini_model="gemini-model")).snapshot()
    assert records["gemini-agy"].executable == "agy"
    assert WorkerRole.CODE_WRITER not in records["gemini-agy"].allowed_roles
    assert records["codex-cli"].allowed_roles == (WorkerRole.CODE_WRITER,)


def test_cli_plan_is_exact_sanitized_and_carries_no_credentials():
    plan = plan_invocation(registry(), request())
    assert plan.executable == "codex" and plan.credential_handle is None
    assert plan.environment_keys == ("HOME", "PATH", "LANG", "TMPDIR")
    assert plan.mutation_allowed and plan.deployment == "DISABLED"


def test_gemini_agy_cannot_claim_code_writer_role():
    reg = WorkerRegistry(default_cli_registrations(codex_model="c", claude_model="a", gemini_model="g"))
    with pytest.raises(HarnessWorkerError, match="role is not approved"):
        plan_invocation(reg, request("gemini-agy", WorkerRole.CODE_WRITER, "g"))


def test_cli_rejects_secret_handle_and_model_or_budget_substitution():
    with pytest.raises(HarnessWorkerError, match="cannot carry"):
        plan_invocation(registry(), request(credential="fwkeys://tenant/key"))
    with pytest.raises(HarnessWorkerError, match="assigned model"):
        plan_invocation(registry(), request(model="other-model"))
    wrong = request()
    wrong = WorkerRequest(wrong.task, wrong.context, BudgetAdmission(wrong.task.task_id, "other-worker", BudgetUsage(), BudgetUsage()), wrong.worker_id, wrong.role)
    with pytest.raises(HarnessWorkerError, match="another worker"):
        plan_invocation(registry(), wrong)


def api_registration(approved=True, network=True):
    return WorkerRegistration("openai-api", "openai", "approved-model", WorkerTransport.API, (WorkerRole.CODE_WRITER,), approved, route_id="provider.openai.responses", credential_class="openai-api-key", network_approved=network)


def test_api_plan_requires_approval_network_and_opaque_fwkeys_handle():
    plan = plan_invocation(WorkerRegistry((api_registration(),)), request("openai-api", credential="fwkeys://tenant/openai/key"))
    assert plan.route_id == "provider.openai.responses" and plan.executable is None
    for registration, handle, match in [(api_registration(False), "fwkeys://tenant/openai/key", "role is not approved"), (api_registration(network=False), "fwkeys://tenant/openai/key", "network route"), (api_registration(), "sk-secret", "opaque FW-KEYS")]:
        with pytest.raises(HarnessWorkerError, match=match):
            plan_invocation(WorkerRegistry((registration,)), request("openai-api", credential=handle))


def test_worker_output_is_exact_bound_and_scoped():
    current = request()
    payload = {"task_id": current.task.task_id, "worker_id": current.worker_id, "context_sha256": current.context.sha256, "candidate_commit": "a" * 40, "changed_files": ["swarm/harness_worker.py", "tests/test_harness_worker.py"], "attempted_actions": ["edit"], "denied_actions": ["deploy"], "summary": "bounded change"}
    output = validate_worker_output(current, payload)
    assert output.changed_files == ("swarm/harness_worker.py", "tests/test_harness_worker.py")
    payload["changed_files"] = ["../secret"]
    with pytest.raises(HarnessWorkerError, match="escape"):
        validate_worker_output(current, payload)


@pytest.mark.parametrize("field,value,match", [("worker_id", "other", "binding"), ("candidate_commit", "HEAD", "commit"), ("summary", "", "summary")])
def test_malformed_or_unbound_output_fails_closed(field, value, match):
    current = request()
    payload = {"task_id": current.task.task_id, "worker_id": current.worker_id, "context_sha256": current.context.sha256, "candidate_commit": None, "changed_files": [], "attempted_actions": [], "denied_actions": [], "summary": "ok"}
    payload[field] = value
    with pytest.raises(HarnessWorkerError, match=match):
        validate_worker_output(current, payload)


def test_registration_rejects_ambiguous_transport_configuration():
    with pytest.raises(HarnessWorkerError, match="CLI workers"):
        WorkerRegistration("bad-cli", "google", "model", WorkerTransport.CLI, (WorkerRole.ANALYST,), True, executable="agy --unsafe")
    with pytest.raises(HarnessWorkerError, match="API workers"):
        WorkerRegistration("bad-api", "google", "model", WorkerTransport.API, (WorkerRole.ANALYST,), True, executable="agy", route_id="route", credential_class="key")


def test_worker_output_rejects_credential_like_values():
    current = request()
    payload = {"task_id": current.task.task_id, "worker_id": current.worker_id, "context_sha256": current.context.sha256, "candidate_commit": None, "changed_files": [], "attempted_actions": [], "denied_actions": [], "summary": "token sk-abcdefghijk"}
    with pytest.raises(HarnessWorkerError, match="credential-like"):
        validate_worker_output(current, payload)
