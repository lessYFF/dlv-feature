#!/usr/bin/env python3
"""Upgrade schema v8 to v9 and replace approvals with automated quality gates."""

from __future__ import annotations

import argparse
import copy
import sys
from datetime import datetime, timezone
from pathlib import Path

from delivery_proof import exclusive_file_lock, extract_state, validate_feature_id, write_state


def timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def is_interrupted_v9_upgrade(state: dict[str, object]) -> bool:
    reviews = state.get("quality_reviews")
    contract = state.get("proof_contract")
    requirement = state.get("requirement_review")
    return (
        state.get("schema_version") == 9
        and state.get("current_stage") == "prd"
        and not any(key in state for key in ("approvals", "approval_challenges", "approval_trust"))
        and reviews == {"product": None, "architecture": None, "code_spec": None}
        and isinstance(contract, dict)
        and contract.get("status") == "stale"
        and contract.get("quality_review") is None
        and contract.get("sealed_at") is None
        and contract.get("seal") is None
        and isinstance(requirement, dict)
        and requirement.get("status") == "in_progress"
        and requirement.get("reviewed_at") is None
    )


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
    root = Path(args.root).expanduser().resolve()
    state_path = root / "delivery" / args.feature_id / "state.md"
    if not state_path.is_file():
        print(f"error: missing {state_path}", file=sys.stderr)
        return 2
    content, state = extract_state(state_path)
    snapshot_path = state_path.parent / "proof-contract.json"
    lock_path = root / ".dlv" / "runs" / args.feature_id / ".feature.lock"
    if is_interrupted_v9_upgrade(state):
        print("recovery plan: finish interrupted schema 8 → 9 Proof Contract snapshot cleanup")
        if not args.apply:
            print("dry-run: pass --apply to finish the interrupted upgrade")
            return 0
        with exclusive_file_lock(lock_path):
            _, locked_state = extract_state(state_path)
            if not is_interrupted_v9_upgrade(locked_state):
                print("error: state changed while waiting for the upgrade recovery lock", file=sys.stderr)
                return 2
            snapshot_path.unlink(missing_ok=True)
        print(f"recovered: {state_path}")
        return 0
    if state.get("schema_version") != 8:
        print("error: only schema_version=8 can be upgraded by this script", file=sys.stderr)
        return 2
    print(
        "upgrade plan: schema 8 → 9; preserve documents, code, and raw evidence as untrusted candidates; "
        "invalidate every caller-asserted approval, quality verdict, seal, PASS, and finalization; "
        "require fresh Product, Architecture, and Code Spec automated quality reviews"
    )
    if not args.apply:
        print("dry-run: pass --apply after reviewing the invalidation boundary")
        return 0

    with exclusive_file_lock(lock_path):
        content, state = extract_state(state_path)
        if state.get("schema_version") != 8:
            print("error: state changed while waiting for the upgrade lock", file=sys.stderr)
            return 2
        original_state = copy.deepcopy(state)
        state["schema_version"] = 9
        state.pop("approval_trust", None)
        state.pop("approval_challenges", None)
        state.pop("approvals", None)
        state["quality_reviews"] = {"product": None, "architecture": None, "code_spec": None}
        requirement = state.get("requirement_review")
        if isinstance(requirement, dict):
            requirement.pop("approved_at", None)
            requirement.update({"status": "in_progress", "reviewed_at": None})
        proof_contract = state.get("proof_contract")
        if not isinstance(proof_contract, dict):
            proof_contract = {"environments": [], "obligations": []}
        proof_contract.update({
            "status": "stale",
            "code_spec_fingerprint": None,
            "quality_review": None,
            "sealed_at": None,
            "seal": None,
        })
        proof_contract.pop("approval", None)
        state["proof_contract"] = proof_contract
        stages = state.get("stages", {})
        for stage in ("prd", "prototype", "architecture", "code_spec", "code", "verification"):
            item = stages.get(stage)
            if isinstance(item, dict):
                item["status"] = "pending" if stage == "prd" else "stale"
                item.pop("approved_at", None)
                if stage in {"prd", "prototype", "architecture", "code_spec"}:
                    item["reviewed_at"] = None
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
        risks = state.get("risks")
        state["risks"] = [
            item for item in risks if not (
                isinstance(item, dict)
                and isinstance(item.get("statement"), str)
                and item["statement"].startswith(("V8 requires fresh", "V9 rejects caller-asserted"))
            )
        ] if isinstance(risks, list) else []
        architecture_review = state.get("architecture_review")
        if isinstance(architecture_review, dict):
            architecture_review.pop("approved_at", None)
            candidate_status = "in_progress" if (state_path.parent / "architecture-design.md").is_file() else "pending"
            architecture_review.update({"status": candidate_status, "reviewed_at": None})
            material_decisions = architecture_review.get("material_decisions")
            if isinstance(material_decisions, list):
                for decision in material_decisions:
                    if isinstance(decision, dict):
                        decision.pop("approval", None)
                        decision["verdict"] = "PENDING"
        state["current_stage"] = "prd"
        state["last_updated"] = timestamp()
        write_state(state_path, content, state)
        try:
            snapshot_path.unlink(missing_ok=True)
        except OSError:
            write_state(state_path, content, original_state)
            raise
    print(f"upgraded: {state_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
