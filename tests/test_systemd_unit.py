from pathlib import Path


UNIT = Path(__file__).resolve().parents[1] / "systemd" / "hermes-swarm-phase2a-worker@.service"


def test_phase2a_worker_unit_has_explicit_sandbox_and_environment():
    text = UNIT.read_text(encoding="utf-8")
    required = (
        "WorkingDirectory=/home/jeff/hermes-swarm-phase1",
        "Environment=HOME=/home/jeff",
        "Environment=PATH=/home/jeff/anaconda3/bin:/home/jeff/.local/bin:/usr/bin:/bin",
        "UMask=0077",
        "NoNewPrivileges=yes",
        "PrivateTmp=yes",
        "ProtectSystem=full",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
        "RestrictSUIDSGID=yes",
        "RestrictRealtime=yes",
        "LockPersonality=yes",
        "RestrictAddressFamilies=AF_UNIX",
        "MemorySwapMax=0",
    )
    assert all(item in text for item in required)
    assert "deploy" not in text.lower()
    assert "production" not in text.lower()


def test_phase2a_worker_unit_runs_only_the_guarded_worker_command():
    text = UNIT.read_text(encoding="utf-8")
    exec_lines = [line for line in text.splitlines() if line.startswith("ExecStart=")]
    assert exec_lines == [
        "ExecStart=/home/jeff/anaconda3/bin/python3 -m swarm.cli phase2a-worker --job-id %i --runtime-root /home/jeff/hermes-swarm-runtime --audit-dir /home/jeff/hermes-swarm-audit"
    ]
