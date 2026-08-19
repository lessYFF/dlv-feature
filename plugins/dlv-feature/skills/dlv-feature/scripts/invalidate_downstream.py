#!/usr/bin/env python3
"""Mark changed schema-v6 delivery artifacts and all downstream stages stale."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from delivery_proof import extract_state, file_digest, repository_fingerprint, write_state


ORDER = ("prd", "prototype", "architecture", "code_spec", "code", "verification")
ARTIFACTS = {
    "prd": "prd.md",
    "prototype": "prototype.html",
    "architecture": "architecture-design.md",
    "code_spec": "code-spec.md",
    "verification": "verification.md",
}


def timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--from-stage", choices=ORDER, help="Explicitly invalidate this stage and downstream")
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve()
    state_path = root / "delivery" / args.feature_id / "state.md"
    if not state_path.is_file():
        print(f"error: missing {state_path}", file=sys.stderr)
        return 2
    content, state = extract_state(state_path)
    if state.get("schema_version") != 6:
        print("error: invalidate_downstream.py only accepts schema_version=6", file=sys.stderr)
        return 2
    stages = state.get("stages", {})
    changed: list[str] = []
    if args.from_stage:
        changed.append(args.from_stage)
    for stage, name in ARTIFACTS.items():
        item = stages.get(stage, {})
        path = state_path.parent / name
        if item.get("status") == "completed" and path.is_file() and item.get("fingerprint") != file_digest(path):
            changed.append(stage)
    code = stages.get("code", {})
    if code.get("status") == "completed":
        result = code.get("result")
        recorded = result.get("repository_fingerprint") if isinstance(result, dict) else None
        try:
            current = repository_fingerprint(root, args.feature_id)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if recorded != current:
            changed.append("code")
    if not changed:
        print("fresh: no downstream invalidation required")
        return 0
    start = min(ORDER.index(stage) for stage in changed)
    for stage in ORDER[start:]:
        item = stages.get(stage)
        if isinstance(item, dict) and item.get("status") not in {"pending", "not_applicable"}:
            item["status"] = "stale"
        if stage == "verification" and isinstance(item, dict):
            item["finalization"] = None
            item["verdict"] = None
    if start <= ORDER.index("code_spec"):
        contract = state.get("proof_contract")
        if isinstance(contract, dict):
            contract["status"] = "stale"
            contract["verdict"] = "PENDING"
    state["current_stage"] = ORDER[start]
    state["last_updated"] = timestamp()
    write_state(state_path, content, state)
    print(f"stale from {ORDER[start]}: {', '.join(ORDER[start:])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
