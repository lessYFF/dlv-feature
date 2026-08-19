#!/usr/bin/env python3
"""Conservatively upgrade v5 state to v6 without preserving unsupported completion claims."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from delivery_proof import extract_state, write_state


ORDER = ("prd", "prototype", "architecture", "code_spec", "code", "verification")


def timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--apply", action="store_true", help="Write the conservative upgrade")
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve()
    state_path = root / "delivery" / args.feature_id / "state.md"
    if not state_path.is_file():
        print(f"error: missing {state_path}", file=sys.stderr)
        return 2
    content, state = extract_state(state_path)
    if state.get("schema_version") != 5:
        print("error: only schema_version=5 can be upgraded by this script", file=sys.stderr)
        return 2
    stages = state.get("stages", {})
    prototype_completed = stages.get("prototype", {}).get("status") == "completed"
    start = "prototype" if prototype_completed else "code_spec"
    print(
        f"upgrade plan: schema 5 → 6; preserve earlier truth; mark {start} and downstream stale; "
        "require a new proof contract and fresh verification"
    )
    if not args.apply:
        print("dry-run: pass --apply after reviewing the invalidation boundary")
        return 0

    state["schema_version"] = 6
    state["proof_contract"] = {
        "status": "pending",
        "code_spec_fingerprint": None,
        "obligations": [],
        "verdict": "PENDING",
    }
    start_index = ORDER.index(start)
    for stage in ORDER[start_index:]:
        item = stages.get(stage)
        if isinstance(item, dict) and item.get("status") not in {"pending", "not_applicable"}:
            item["status"] = "stale"
    verification = stages.get("verification")
    if isinstance(verification, dict):
        inputs = verification.setdefault("inputs", {})
        inputs.setdefault("prototype", None)
        inputs.setdefault("proof_contract", None)
        verification["verdict"] = None
        verification["finalization"] = None
    state["current_stage"] = start
    state["last_updated"] = timestamp()
    write_state(state_path, content, state)
    print(f"upgraded: {state_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
