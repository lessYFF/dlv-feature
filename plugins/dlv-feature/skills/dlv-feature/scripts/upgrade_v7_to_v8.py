#!/usr/bin/env python3
"""Conservatively upgrade schema v7 state to v8 without promoting old approvals."""

from __future__ import annotations

import argparse
import copy
import sys
from datetime import datetime, timezone
from pathlib import Path

from delivery_proof import exclusive_file_lock, extract_state, validate_feature_id, write_state


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
    root = Path(args.root).expanduser().resolve()
    state_path = root / "delivery" / args.feature_id / "state.md"
    if not state_path.is_file():
        print(f"error: missing {state_path}", file=sys.stderr)
        return 2
    content, state = extract_state(state_path)
    if state.get("schema_version") != 7:
        print("error: only schema_version=7 can be upgraded by this script", file=sys.stderr)
        return 2
    print(
        "upgrade plan: schema 7 → 8; preserve delivery documents and raw evidence; "
        "invalidate product/architecture/Code Spec approvals, old PASS/finalization, and the sealed Proof Contract; "
        "resume at PRD product confirmation"
    )
    if not args.apply:
        print("dry-run: pass --apply after reviewing the conservative invalidation boundary")
        return 0

    snapshot_path = state_path.parent / "proof-contract.json"
    lock_path = root / ".dlv" / "runs" / args.feature_id / ".feature.lock"
    with exclusive_file_lock(lock_path):
        content, state = extract_state(state_path)
        if state.get("schema_version") != 7:
            print("error: state changed while waiting for the upgrade lock", file=sys.stderr)
            return 2
        original_state = copy.deepcopy(state)
        state["schema_version"] = 8
        state["approvals"] = {}
        state["quality_reviews"] = {"architecture": None, "code_spec": None}
        requirement = state.get("requirement_review")
        if isinstance(requirement, dict):
            requirement["status"] = "pending"
            requirement["approved_at"] = None
        proof_contract = state.get("proof_contract")
        if not isinstance(proof_contract, dict):
            proof_contract = {"environments": [], "obligations": []}
        proof_contract.update({
            "status": "stale",
            "code_spec_fingerprint": None,
            "approval": None,
            "sealed_at": None,
            "seal": None,
        })
        state["proof_contract"] = proof_contract
        stages = state.get("stages", {})
        for stage in ("prd", "prototype", "architecture", "code_spec", "code", "verification"):
            item = stages.get(stage)
            if isinstance(item, dict) and item.get("status") != "not_applicable":
                item["status"] = "pending" if stage == "prd" else (
                    "stale" if item.get("status") != "pending" else "pending"
                )
                if stage in {"prd", "prototype", "code_spec"}:
                    item["approved_at"] = None
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
        if not isinstance(risks, list):
            risks = []
            state["risks"] = risks
        used = {
            item.get("id") for item in risks if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        number = 1
        while f"RISK-{number:02d}" in used:
            number += 1
        risks.append({
            "id": f"RISK-{number:02d}",
            "type": "blocker",
            "severity": "high",
            "status": "open",
            "statement": "V8 requires fresh requirement/product confirmation, Architecture and Code Spec quality reviews, approvals, and Verification Run; V7 PASS is not transferable.",
            "owner": "delivery-owner",
        })
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
