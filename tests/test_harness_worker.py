import pytest
from dataclasses import replace

from swarm.harness_context import BudgetAdmission, BudgetUsage, ContextItem, build_context_packet
from swarm.harness_task import HarnessTask, TaskStatus
from swarm.harness_worker import HarnessWorkerError, WorkerRegistration, WorkerRegistry, WorkerRequest, WorkerRole, WorkerTransport, default_cli_registrations, plan_identity_bound_invocation, plan_invocation, validate_worker_output
from swarm.identity import IdentityRegistry, bind_delegated_provider_identity, validate_identity_record
from swarm.keys import SecretHandleRegistry, validate_secret_handle_record


NOW = "2026-09-09T12:00:00+00:00"


def task(model="approved-model"):
    return HarnessTask(task_id="FWQ-0068", requirement_id="FW-HARNESS-004", title="Workers", description="Govern workers", status=TaskStatus.READY, priority=0, assigned_role="CODE_WRITER", assigned_model=model, repository="/repo", created_at=NOW, relevant_files=("swarm/harness_worker.py", "tests"))


def request(worker="codex-cli", role=WorkerRole.CODE_WRITER, model="approved-model", credential=None):
    current = task(model)
    context = build_context_packet(current, (ContextItem("architecture_constraint", "D-023", "AI has no authority"), ContextItem("task_state", current.task_id, "ready"), ContextItem("forbidden_change", "deployment", "disabled")))
    return WorkerRequest(current, context, BudgetAdmission(current.task_id, worker, BudgetUsage(model_calls=1), BudgetUsage(model_calls=1)), worker, role, credential)


def registry():
    return WorkerRegistry((WorkerRegistration("codex-cli", "openai", "approved-model", WorkerTransport.CLI, (WorkerRole.CODE_WRITER,), True, executable="codex"),))


def identity_registry(identity_id="fw-id/codex-cli", tenant="tenant"):
    records = IdentityRegistry(lambda *_args: None)
    records.register(validate_identity_record({"schema_version": "1", "identity_id": identity_id, "tenant_id": tenant, "identity_kind": "AI_AGENT", "owner_identity_ref": "fw-id/owner", "purpose": "bounded worker", "lifecycle_state": "ACTIVE", "created_at_epoch": 1, "lifecycle_changed_at_epoch": 1, "expires_at_epoch": 1000, "provider_subject_ref": "provider/openai-worker", "credential_handle_ref": f"fwkeys://{tenant}/provider/openai-worker"}))
    return records


def key_registry(tenant="tenant", owner="fw-id/codex-cli", credential_class="API_KEY", expires=100):
    records = SecretHandleRegistry(lambda *_args: None)
    records.register(validate_secret_handle_record({
        "schema_version": "1", "handle_id": f"fwkeys://{tenant}/provider/openai-worker",
        "tenant_id": tenant, "credential_class": credential_class,
        "owner_identity_ref": owner, "purpose": "provider worker binding",
        "backend_reference_class": "TRUSTED_ADAPTER", "lifecycle_state": "ACTIVE",
        "created_at_epoch": 1, "lifecycle_changed_at_epoch": 1,
        "expires_at_epoch": expires, "generation": 1, "export_policy": "NON_EXPORTABLE",
    }))
    return records


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


def test_identity_bound_cli_plan_requires_exact_active_tenant_worker_identity():
    reg = WorkerRegistry((WorkerRegistration("codex-cli", "openai", "approved-model", WorkerTransport.CLI, (WorkerRole.CODE_WRITER,), True, executable="codex", identity_ref="fw-id/codex-cli"),))
    plan = plan_identity_bound_invocation(reg, request(), identity_registry=identity_registry(), tenant_id="tenant", now_epoch=10)
    assert plan.worker_id == "codex-cli" and plan.credential_handle is None
    with pytest.raises(HarnessWorkerError, match="FW-ID admission denied"):
        plan_identity_bound_invocation(reg, request(), identity_registry=identity_registry(), tenant_id="other", now_epoch=10)
    missing = WorkerRegistry((WorkerRegistration("codex-cli", "openai", "approved-model", WorkerTransport.CLI, (WorkerRole.CODE_WRITER,), True, executable="codex"),))
    with pytest.raises(HarnessWorkerError, match="lacks an FW-ID"):
        plan_identity_bound_invocation(missing, request(), identity_registry=identity_registry(), tenant_id="tenant", now_epoch=10)
    with pytest.raises(HarnessWorkerError, match="not an active"):
        plan_identity_bound_invocation(reg, request(), identity_registry=identity_registry(), tenant_id="tenant", now_epoch=1000)


def test_identity_bound_api_plan_requires_exact_current_provider_binding():
    ids = identity_registry()
    ids.register(validate_identity_record({"schema_version": "1", "identity_id": "fw-id/owner", "tenant_id": "tenant", "identity_kind": "HUMAN", "owner_identity_ref": "fw-id/owner", "purpose": "owner", "lifecycle_state": "ACTIVE", "created_at_epoch": 1, "lifecycle_changed_at_epoch": 1, "expires_at_epoch": None, "provider_subject_ref": None, "credential_handle_ref": None}))
    keys = key_registry()
    wire = {"binding_id": "fw-id-binding/openai-api", "tenant_id": "tenant", "subject_identity_id": "fw-id/codex-cli", "owner_identity_id": "fw-id/owner", "provider": "OPENAI", "provider_subject_ref": "provider/openai-worker", "consent_ref": "approval/provider-one", "credential_class": "API_KEY", "credential_handle_ref": "fwkeys://tenant/provider/openai-worker", "issued_at_epoch": 1, "expires_at_epoch": 100}
    binding = bind_delegated_provider_identity(wire, registry=ids, key_registry=keys, now_epoch=10, audit=lambda *_args: None)
    reg = WorkerRegistry((WorkerRegistration("openai-api", "openai", "approved-model", WorkerTransport.API, (WorkerRole.CODE_WRITER,), True, route_id="provider.openai.responses", credential_class="openai-api-key", network_approved=True, identity_ref="fw-id/codex-cli"),))
    api_request = request("openai-api", credential="fwkeys://tenant/provider/openai-worker")
    assert plan_identity_bound_invocation(reg, api_request, identity_registry=ids, tenant_id="tenant", now_epoch=10, provider_binding=binding, key_registry=keys).route_id
    with pytest.raises(HarnessWorkerError, match="stale"):
        plan_identity_bound_invocation(reg, api_request, identity_registry=ids, tenant_id="tenant", now_epoch=100, provider_binding=binding, key_registry=keys)
    with pytest.raises(HarnessWorkerError, match="requires a delegated"):
        plan_identity_bound_invocation(reg, api_request, identity_registry=ids, tenant_id="tenant", now_epoch=10)
    with pytest.raises(HarnessWorkerError, match="claims authority"):
        plan_identity_bound_invocation(reg, api_request, identity_registry=ids, tenant_id="tenant", now_epoch=10, provider_binding=replace(binding, authority_granted=True), key_registry=keys)
    wrong_class = WorkerRegistry((replace(api_registration(), identity_ref="fw-id/codex-cli", credential_class="openai-oauth-token-set"),))
    with pytest.raises(HarnessWorkerError, match="credential class"):
        plan_identity_bound_invocation(wrong_class, api_request, identity_registry=ids, tenant_id="tenant", now_epoch=10, provider_binding=binding, key_registry=keys)


def test_integrated_identity_lifecycle_binds_provider_worker_and_revocation_fail_closed():
    events = []
    ids = IdentityRegistry(lambda *args: events.append(args))
    owner = validate_identity_record({"schema_version": "1", "identity_id": "fw-id/owner", "tenant_id": "tenant", "identity_kind": "HUMAN", "owner_identity_ref": "fw-id/owner", "purpose": "owner", "lifecycle_state": "ACTIVE", "created_at_epoch": 1, "lifecycle_changed_at_epoch": 1, "expires_at_epoch": None, "provider_subject_ref": None, "credential_handle_ref": None})
    worker = validate_identity_record({"schema_version": "1", "identity_id": "fw-id/codex-cli", "tenant_id": "tenant", "identity_kind": "AI_AGENT", "owner_identity_ref": owner.identity_id, "purpose": "bounded worker", "lifecycle_state": "ACTIVE", "created_at_epoch": 1, "lifecycle_changed_at_epoch": 1, "expires_at_epoch": 100, "provider_subject_ref": "provider/openai-worker", "credential_handle_ref": "fwkeys://tenant/provider/openai-worker"})
    ids.register(owner)
    ids.register(worker)
    keys = key_registry()
    binding = bind_delegated_provider_identity({"binding_id": "fw-id-binding/openai-api", "tenant_id": "tenant", "subject_identity_id": worker.identity_id, "owner_identity_id": owner.identity_id, "provider": "OPENAI", "provider_subject_ref": "provider/openai-worker", "consent_ref": "approval/provider-one", "credential_class": "API_KEY", "credential_handle_ref": "fwkeys://tenant/provider/openai-worker", "issued_at_epoch": 1, "expires_at_epoch": 90}, registry=ids, key_registry=keys, now_epoch=10, audit=lambda *args: events.append(args))
    workers = WorkerRegistry((WorkerRegistration("openai-api", "openai", "approved-model", WorkerTransport.API, (WorkerRole.CODE_WRITER,), True, route_id="provider.openai.responses", credential_class="openai-api-key", network_approved=True, identity_ref=worker.identity_id),))
    worker_request = request("openai-api", credential="fwkeys://tenant/provider/openai-worker")
    plan = plan_identity_bound_invocation(workers, worker_request, identity_registry=ids, tenant_id="tenant", now_epoch=10, provider_binding=binding, key_registry=keys)
    assert plan.worker_id == "openai-api" and plan.task_id == worker_request.task.task_id
    assert [event for event, _ in events] == ["fw_id_registered", "fw_id_registered", "fw_id_provider_identity_bound"]
    ids.revoke(worker.identity_id, tenant_id="tenant", now_epoch=20)
    with pytest.raises(HarnessWorkerError, match="not an active"):
        plan_identity_bound_invocation(workers, worker_request, identity_registry=ids, tenant_id="tenant", now_epoch=21, provider_binding=binding, key_registry=keys)
    assert events[-1][0] == "fw_id_lifecycle_changed" and events[-1][1]["lifecycle_state"] == "REVOKED"


def test_integrated_identity_and_provider_expiration_boundaries_deny_admission():
    ids = IdentityRegistry(lambda *_args: None)
    owner = validate_identity_record({"schema_version": "1", "identity_id": "fw-id/owner", "tenant_id": "tenant", "identity_kind": "HUMAN", "owner_identity_ref": "fw-id/owner", "purpose": "owner", "lifecycle_state": "ACTIVE", "created_at_epoch": 1, "lifecycle_changed_at_epoch": 1, "expires_at_epoch": None, "provider_subject_ref": None, "credential_handle_ref": None})
    worker = validate_identity_record({"schema_version": "1", "identity_id": "fw-id/codex-cli", "tenant_id": "tenant", "identity_kind": "AI_AGENT", "owner_identity_ref": owner.identity_id, "purpose": "worker", "lifecycle_state": "ACTIVE", "created_at_epoch": 1, "lifecycle_changed_at_epoch": 1, "expires_at_epoch": 100, "provider_subject_ref": "provider/openai-worker", "credential_handle_ref": "fwkeys://tenant/provider/openai-worker"})
    ids.register(owner); ids.register(worker)
    keys = key_registry()
    wire = {"binding_id": "fw-id-binding/openai-api", "tenant_id": "tenant", "subject_identity_id": worker.identity_id, "owner_identity_id": owner.identity_id, "provider": "OPENAI", "provider_subject_ref": "provider/openai-worker", "consent_ref": "approval/provider-one", "credential_class": "API_KEY", "credential_handle_ref": "fwkeys://tenant/provider/openai-worker", "issued_at_epoch": 1, "expires_at_epoch": 90}
    binding = bind_delegated_provider_identity(wire, registry=ids, key_registry=keys, now_epoch=10, audit=lambda *_args: None)
    workers = WorkerRegistry((WorkerRegistration("openai-api", "openai", "approved-model", WorkerTransport.API, (WorkerRole.CODE_WRITER,), True, route_id="provider.openai.responses", credential_class="openai-api-key", network_approved=True, identity_ref=worker.identity_id),))
    worker_request = request("openai-api", credential="fwkeys://tenant/provider/openai-worker")
    with pytest.raises(HarnessWorkerError, match="delegated provider identity is stale"):
        plan_identity_bound_invocation(workers, worker_request, identity_registry=ids, tenant_id="tenant", now_epoch=90, provider_binding=binding, key_registry=keys)
    identity_lifetime_binding = bind_delegated_provider_identity({**wire, "expires_at_epoch": 100}, registry=ids, key_registry=keys, now_epoch=10, audit=lambda *_args: None)
    with pytest.raises(HarnessWorkerError, match="not an active"):
        plan_identity_bound_invocation(workers, worker_request, identity_registry=ids, tenant_id="tenant", now_epoch=100, provider_binding=identity_lifetime_binding, key_registry=keys)


def api_bound_fixture(*, key_expires=100):
    ids = identity_registry()
    ids.register(validate_identity_record({
        "schema_version": "1", "identity_id": "fw-id/owner",
        "tenant_id": "tenant", "identity_kind": "HUMAN",
        "owner_identity_ref": "fw-id/owner", "purpose": "owner",
        "lifecycle_state": "ACTIVE", "created_at_epoch": 1,
        "lifecycle_changed_at_epoch": 1, "expires_at_epoch": None,
        "provider_subject_ref": None, "credential_handle_ref": None,
    }))
    keys = key_registry(expires=key_expires)
    wire = {
        "binding_id": "fw-id-binding/openai-api", "tenant_id": "tenant",
        "subject_identity_id": "fw-id/codex-cli",
        "owner_identity_id": "fw-id/owner", "provider": "OPENAI",
        "provider_subject_ref": "provider/openai-worker",
        "consent_ref": "approval/provider-one", "credential_class": "API_KEY",
        "credential_handle_ref": "fwkeys://tenant/provider/openai-worker",
        "issued_at_epoch": 1, "expires_at_epoch": 90,
    }
    binding = bind_delegated_provider_identity(
        wire, registry=ids, key_registry=keys, now_epoch=10,
        audit=lambda *_args: None,
    )
    workers = WorkerRegistry((WorkerRegistration(
        "openai-api", "openai", "approved-model", WorkerTransport.API,
        (WorkerRole.CODE_WRITER,), True,
        route_id="provider.openai.responses",
        credential_class="openai-api-key", network_approved=True,
        identity_ref="fw-id/codex-cli",
    ),))
    return ids, keys, binding, workers, request(
        "openai-api", credential="fwkeys://tenant/provider/openai-worker",
    )


def test_api_plan_rechecks_key_revocation_and_expiration():
    ids, keys, binding, workers, api_request = api_bound_fixture()
    keys.revoke(binding.credential_handle_ref, tenant_id="tenant", now_epoch=20)
    with pytest.raises(HarnessWorkerError, match="stale, inactive, or mismatched"):
        plan_identity_bound_invocation(
            workers, api_request, identity_registry=ids, tenant_id="tenant",
            now_epoch=21, provider_binding=binding, key_registry=keys,
        )

    ids, keys, binding, workers, api_request = api_bound_fixture(key_expires=50)
    with pytest.raises(HarnessWorkerError, match="stale, inactive, or mismatched"):
        plan_identity_bound_invocation(
            workers, api_request, identity_registry=ids, tenant_id="tenant",
            now_epoch=50, provider_binding=binding, key_registry=keys,
        )


def test_api_plan_rejects_rotated_generation_replay():
    ids, keys, binding, workers, api_request = api_bound_fixture()
    replacement = validate_secret_handle_record({
        "schema_version": "1", "handle_id": binding.credential_handle_ref,
        "tenant_id": "tenant", "credential_class": "API_KEY",
        "owner_identity_ref": "fw-id/codex-cli",
        "purpose": "provider worker binding",
        "backend_reference_class": "TRUSTED_ADAPTER",
        "lifecycle_state": "PROVISIONED", "created_at_epoch": 20,
        "lifecycle_changed_at_epoch": 20, "expires_at_epoch": 100,
        "generation": 2, "export_policy": "NON_EXPORTABLE",
    })
    keys.replace_generation(
        binding.credential_handle_ref, replacement,
        tenant_id="tenant", now_epoch=20,
    )
    keys.activate(binding.credential_handle_ref, tenant_id="tenant", now_epoch=21)
    with pytest.raises(HarnessWorkerError, match="stale, inactive, or mismatched"):
        plan_identity_bound_invocation(
            workers, api_request, identity_registry=ids, tenant_id="tenant",
            now_epoch=22, provider_binding=binding, key_registry=keys,
        )


def test_api_plan_requires_key_registry_but_cli_remains_handle_free():
    ids, _keys, binding, workers, api_request = api_bound_fixture()
    with pytest.raises(HarnessWorkerError, match="canonical FW-KEYS registry"):
        plan_identity_bound_invocation(
            workers, api_request, identity_registry=ids, tenant_id="tenant",
            now_epoch=10, provider_binding=binding,
        )
    cli = WorkerRegistry((WorkerRegistration(
        "codex-cli", "openai", "approved-model", WorkerTransport.CLI,
        (WorkerRole.CODE_WRITER,), True, executable="codex",
        identity_ref="fw-id/codex-cli",
    ),))
    assert plan_identity_bound_invocation(
        cli, request(), identity_registry=identity_registry(),
        tenant_id="tenant", now_epoch=10,
    ).credential_handle is None
