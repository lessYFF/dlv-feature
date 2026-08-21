#!/usr/bin/env python3
"""Conservatively upgrade v6 state to v7 and require a new sealed Proof Contract."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from delivery_proof import extract_state, validate_feature_id, write_state

ORDER = ("prd", "prototype", "architecture", "code_spec", "code", "verification")


def timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        validate_feature_id(args.feature_id)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    state_path = Path(args.root).expanduser().resolve() / "delivery" / args.feature_id / "state.md"
    if not state_path.is_file():
        print(f"error: missing {state_path}", file=sys.stderr)
        return 2
    content, state = extract_state(state_path)
    if state.get("schema_version") != 6:
        print("error: only schema_version=6 can be upgraded by this script", file=sys.stderr)
        return 2
    print(
        "upgrade plan: schema 6 → 7; preserve approved PRD/Prototype/Architecture; "
        "mark Code Spec, Code, and Verification stale; replace prose PO expectations with "
        "structured assertions, seal a new immutable contract, and collect a fresh Verification Run"
    )
    if not args.apply:
        print("dry-run: pass --apply after reviewing the conservative invalidation boundary")
        return 0

    state["schema_version"] = 7
    state["proof_contract"] = {
        "status": "pending",
        "code_spec_fingerprint": None,
        "environments": [],
        "obligations": [],
        "approval": None,
        "sealed_at": None,
        "seal": None,
    }
    stages = state.get("stages", {})
    for stage in ("code_spec", "code", "verification"):
        item = stages.get(stage)
        if isinstance(item, dict) and item.get("status") not in {"pending", "not_applicable"}:
            item["status"] = "stale"
    verification = stages.get("verification")
    if isinstance(verification, dict):
        verification.update({
            "active_run_id": None,
            "run_digest": None,
            "evidence_count": 0,
            "evidence_head": None,
            "verdict": None,
            "finalization": None,
        })
    old_blockers = state.pop("blockers", [])
    state["risks"] = [
        {
            "id": f"RISK-{index:02d}",
            "type": "blocker",
            "severity": "high",
            "status": "open",
            "statement": str(value),
            "owner": "migration-review",
        }
        for index, value in enumerate(old_blockers, 1)
    ]
    state["current_stage"] = "code_spec"
    state["last_updated"] = timestamp()
    write_state(state_path, content, state)
    print(f"upgraded: {state_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
