#!/usr/bin/env python3
"""CI entry point for ForgeWarden safety-invariant validation."""
from swarm.invariant_ci import run

if __name__ == "__main__":
    raise SystemExit(run())
