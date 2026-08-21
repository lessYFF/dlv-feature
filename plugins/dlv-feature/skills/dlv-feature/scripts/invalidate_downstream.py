#!/usr/bin/env python3
"""Mark changed schema-v8 truth/code and downstream runs stale."""

from __future__ import annotations

import argparse
import copy
import sys
from datetime import datetime, timezone
from pathlib import Path

from delivery_proof import exclusive_file_lock, extract_state, file_digest, repository_fingerprint, validate_feature_id, write_state


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


def invalidate(root: Path, feature_id: str, from_stage: str | None) -> str:
    state_path = root / "delivery" / feature_id / "state.md"
    if not state_path.is_file():
        raise ValueError(f"missing {state_path}")
    with exclusive_file_lock(root / ".dlv" / "runs" / feature_id / ".feature.lock"):
        content, state = extract_state(state_path)
        if state.get("schema_version") != 8:
            raise ValueError("invalidate_downstream.py only accepts schema_version=8")
        original_state = copy.deepcopy(state)
        stages = state.get("stages", {})
        changed: list[str] = [from_stage] if from_stage else []
        for stage, name in ARTIFACTS.items():
            item = stages.get(stage, {})
            path = state_path.parent / name
            if item.get("status") == "completed" and path.is_file() and item.get("fingerprint") != file_digest(path):
                changed.append(stage)
        code = stages.get("code", {})
        if code.get("status") == "completed":
            result = code.get("result")
            recorded = result.get("repository_fingerprint") if isinstance(result, dict) else None
            if recorded != repository_fingerprint(root, feature_id):
                changed.append("code")
        if not changed:
            return "fresh: no downstream invalidation required"
        start = min(ORDER.index(stage) for stage in changed)
        for stage in ORDER[start:]:
            item = stages.get(stage)
            if isinstance(item, dict) and item.get("status") not in {"pending", "not_applicable"}:
                item["status"] = "stale"
            if stage == "verification" and isinstance(item, dict):
                item.update({"finalization": None, "verdict": None, "run_digest": None})
        remove_contract_snapshot = start <= ORDER.index("code_spec")
        if remove_contract_snapshot:
            contract = state.get("proof_contract")
            if isinstance(contract, dict):
                contract.update({"status": "stale", "seal": None, "sealed_at": None, "approval": None})
        approvals = state.setdefault("approvals", {})
        quality_reviews = state.setdefault("quality_reviews", {"architecture": None, "code_spec": None})
        if start <= ORDER.index("prd"):
            for key in ("prd", "prototype", "architecture", "code_spec"):
                approvals.pop(key, None)
            quality_reviews.update({"architecture": None, "code_spec": None})
        elif start <= ORDER.index("prototype"):
            for key in ("prd", "prototype", "architecture", "code_spec"):
                approvals.pop(key, None)
            quality_reviews.update({"architecture": None, "code_spec": None})
        elif start <= ORDER.index("architecture"):
            for key in ("architecture", "code_spec"):
                approvals.pop(key, None)
            quality_reviews.update({"architecture": None, "code_spec": None})
        elif start <= ORDER.index("code_spec"):
            approvals.pop("code_spec", None)
            quality_reviews["code_spec"] = None
        state["current_stage"] = ORDER[start]
        state["last_updated"] = timestamp()
        write_state(state_path, content, state)
        if remove_contract_snapshot:
            try:
                (state_path.parent / "proof-contract.json").unlink(missing_ok=True)
            except OSError:
                write_state(state_path, content, original_state)
                raise
        return f"stale from {ORDER[start]}: {', '.join(ORDER[start:])}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--from-stage", choices=ORDER, help="Explicitly invalidate this stage and downstream")
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve()
    try:
        validate_feature_id(args.feature_id)
        print(invalidate(root, args.feature_id, args.from_stage))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
