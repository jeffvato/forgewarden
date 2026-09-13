from dataclasses import replace

import pytest

from swarm.mission_control import MissionControlError, project_operations_continuity
from swarm.operations import OperationalHealthRegistry, validate_operational_snapshot
from swarm.operations_capacity import CapacityAssessmentRegistry
from swarm.recovery import (
    RecoveryCheckpoint, ResumeDecision, admit_interruption,
    load_recovery_checkpoint, recovery_checkpoint_digest, write_recovery_checkpoint,
)


TENANT = "tenant-ops"
COMMIT = "a" * 40
TAIL = "b" * 64


def operational_snapshot():
    return validate_operational_snapshot({
        "schema_version": "1",
        "snapshot_id": "ops-snapshot-1",
        "tenant_id": TENANT,
        "observed_at_epoch": 100,
        "expires_at_epoch": 200,
        "components": [{
            "component_id": "endpoint-pipeline",
            "tenant_id": TENANT,
            "state": "DEGRADED",
            "queue_depth": 8,
            "queue_limit": 10,
            "budget_used": 4,
            "budget_limit": 10,
        }],
        "mode": "DRY_RUN",
        "deployment": "DISABLED",
        "kill_switch": "ENGAGED",
    })


def checkpoint():
    return RecoveryCheckpoint(
        "1", f"fw-rec/{TENANT}/ops-1", TENANT, "FWQ-0400", "FW-OPS-004",
        "running", "worker", "c" * 40, COMMIT, "d" * 64, "NOT_RUN",
        "NOT_RUN", (f"fw-lease/{TENANT}/ops-1",), True, 1, 10, 1, 3,
        TAIL, "2026-09-13T05:00:00Z", "HOST_RESTART",
        ResumeDecision.RESUME, "DRY_RUN", "DISABLED", False,
    )


def lifecycle(tmp_path):
    evidence = []
    def health_sink(event, payload):
        evidence.append((event, payload))
        return f"fw-evid/{TENANT}/ops/health-1"
    health = OperationalHealthRegistry(health_sink).project(
        operational_snapshot(), tenant_id=TENANT, now_epoch=150,
    )
    capacity = CapacityAssessmentRegistry(
        lambda event, payload: evidence.append((event, payload))
        or f"fw-evid/{TENANT}/ops/capacity-1"
    ).assess("capacity-1", TENANT, (health,), now_epoch=151, max_age_seconds=60)
    path = tmp_path / "ops-checkpoint.json"
    digest = write_recovery_checkpoint(path, checkpoint())
    recovered = load_recovery_checkpoint(
        path, tenant_id=TENANT, current_commit=COMMIT,
        evidence_tail_sha256=TAIL,
    )
    admission = admit_interruption(
        recovered, admission_id=f"fw-rec-admission/{TENANT}/ops-1",
        checkpoint_sha256=digest, tenant_id=TENANT, current_commit=COMMIT,
        evidence_tail_sha256=TAIL, kill_switch="ENGAGED",
        authority_current=True, occurred_at="2026-09-13T05:01:00Z",
        evidence_sink=lambda payload: evidence.append(("fw_rec_resume", payload)),
    )
    return health, capacity, admission, evidence, path


def test_operations_restart_continuity_projects_canonical_read_only_state(tmp_path):
    health, capacity, admission, evidence, path = lifecycle(tmp_path)
    assert path.stat().st_mode & 0o077 == 0
    view = project_operations_continuity(health, capacity, admission, tenant_id=TENANT)
    assert view.health == "DEGRADED" and view.pressure == "ELEVATED"
    assert view.resume_decision == "RESUME"
    assert view.mode == "DRY_RUN" and view.deployment == "DISABLED"
    assert view.mutation_allowed is view.recovery_executed is view.authority_granted is False
    assert [item[0] for item in evidence] == [
        "fw_ops_health_projected", "fw_ops_capacity_assessed", "fw_rec_resume",
    ]


@pytest.mark.parametrize(
    "part",
    ["health_tenant", "capacity_authority", "admission_tenant", "stale_capacity", "bad_evidence", "bad_pressure"],
)
def test_operations_continuity_rejects_substitution_and_unsafe_state(tmp_path, part):
    health, capacity, admission, _evidence, _path = lifecycle(tmp_path)
    if part == "health_tenant":
        health = replace(health, tenant_id="tenant-other")
    elif part == "capacity_authority":
        capacity = replace(capacity, authority_granted=True)
    elif part == "admission_tenant":
        admission = replace(admission, tenant_id="tenant-other")
    elif part == "stale_capacity":
        capacity = replace(capacity, assessed_at_epoch=149)
    elif part == "bad_evidence":
        health = replace(health, evidence_reference=f"fw-evid/{TENANT}/ops/api_key=secret")
    else:
        capacity = replace(capacity, pressure="MODEL_SAYS_HEALTHY")
    with pytest.raises(MissionControlError):
        project_operations_continuity(health, capacity, admission, tenant_id=TENANT)


def test_corrupt_checkpoint_prevents_operations_continuity_after_restart(tmp_path):
    _health, _capacity, _admission, _evidence, path = lifecycle(tmp_path)
    path.write_text(path.read_text().replace("FWQ-0400", "FWQ-9999"))
    path.chmod(0o600)
    with pytest.raises(Exception, match="integrity"):
        load_recovery_checkpoint(path, tenant_id=TENANT, current_commit=COMMIT, evidence_tail_sha256=TAIL)
