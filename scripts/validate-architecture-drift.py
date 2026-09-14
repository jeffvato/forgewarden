#!/usr/bin/env python3
from pathlib import Path
from swarm.architecture_drift import ArchitectureDriftError, validate_repository

try:
    validate_repository(Path(__file__).resolve().parents[1])
except ArchitectureDriftError as exc:
    print(f"architecture drift detected: {exc}")
    raise SystemExit(1)
print("validated provider access architecture boundary")
# Source and CI entry point are reviewed together.
