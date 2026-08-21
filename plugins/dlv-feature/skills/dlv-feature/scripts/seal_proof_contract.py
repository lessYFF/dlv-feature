#!/usr/bin/env python3
"""Seal a schema-v7 Proof Contract exactly once after Code Spec approval."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from delivery_proof import atomic_write_text, exclusive_file_lock, extract_state, load_json, proof_contract_digest, validate_feature_id, validate_proof_contract, write_state


def timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def seal_contract(feature_id: str, root: Path, approved_by: str, approval_reference: str) -> str:
    state_path = root / "delivery" / feature_id / "state.md"
    with exclusive_file_lock(root / ".dlv" / "runs" / feature_id / ".feature.lock"):
        content, state = extract_state(state_path)
        if state.get("schema_version") != 7:
            raise ValueError("seal_proof_contract.py requires schema_version=7")
        code_spec = state.get("stages", {}).get("code_spec", {})
        if code_spec.get("status") != "completed" or not code_spec.get("fingerprint"):
            raise ValueError("Code Spec must be completed before sealing its Proof Contract")
        contract = state.get("proof_contract")
        if not isinstance(contract, dict):
            raise ValueError("proof_contract must be an object")
        prd_path = state_path.parent / "prd.md"
        prd_text = prd_path.read_text(encoding="utf-8") if prd_path.is_file() else ""
        acceptance_ids = set(re.findall(r"\b(?:AC|EX)-[0-9]+\b", prd_text))
        prototype_completed = state.get("stages", {}).get("prototype", {}).get("status") == "completed"
        artifact_path = state_path.parent / "proof-contract.json"
        if artifact_path.is_file() and not contract.get("seal") and contract.get("status") != "completed":
            recovered = load_json(artifact_path)
            if (
                recovered.get("code_spec_fingerprint") != code_spec["fingerprint"]
                or recovered.get("approval") != {"approved_by": approved_by, "reference": approval_reference}
                or recovered.get("seal") != proof_contract_digest(recovered)
            ):
                raise ValueError("orphaned Proof Contract snapshot disagrees with the requested approval")
            recovery_errors: list[str] = []
            validate_proof_contract(recovered, acceptance_ids, code_spec["fingerprint"], prototype_completed, recovery_errors)
            if recovery_errors:
                raise ValueError("orphaned Proof Contract snapshot is invalid: " + "; ".join(recovery_errors))
            state["proof_contract"] = recovered
            state["last_updated"] = timestamp()
            write_state(state_path, content, state)
            return str(recovered["seal"])
        if artifact_path.exists() or contract.get("seal") or contract.get("sealed_at") or contract.get("status") == "completed":
            raise ValueError("Proof Contract is already sealed; invalidate Code Spec to replace it")
        contract["code_spec_fingerprint"] = code_spec["fingerprint"]
        contract["status"] = "completed"
        contract["approval"] = {
            "approved_by": approved_by,
            "reference": approval_reference,
        }
        contract["sealed_at"] = timestamp()
        contract["seal"] = proof_contract_digest(contract)
        errors: list[str] = []
        validate_proof_contract(
            contract,
            acceptance_ids,
            code_spec["fingerprint"],
            prototype_completed,
            errors,
        )
        if errors:
            raise ValueError("cannot seal invalid Proof Contract: " + "; ".join(errors))
        state["last_updated"] = timestamp()
        atomic_write_text(artifact_path, json.dumps(contract, ensure_ascii=False, indent=2) + "\n")
        try:
            write_state(state_path, content, state)
        except BaseException:
            artifact_path.unlink(missing_ok=True)
            raise
        return str(contract["seal"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--approved-by", required=True)
    parser.add_argument("--approval-reference", required=True)
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve()
    try:
        validate_feature_id(args.feature_id)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        print(seal_contract(args.feature_id, root, args.approved_by, args.approval_reference))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
