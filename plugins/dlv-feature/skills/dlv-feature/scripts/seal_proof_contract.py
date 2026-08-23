#!/usr/bin/env python3
"""Seal a schema-v9 Proof Contract exactly once after Code Spec quality PASS."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from delivery_proof import atomic_write_text, exclusive_file_lock, extract_state, file_digest, load_json, proof_contract_digest, validate_feature_id, validate_proof_contract, write_state
from quality_gates import proof_contract_draft_digest, validate_quality_review


def timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def seal_contract(feature_id: str, root: Path) -> str:
    state_path = root / "delivery" / feature_id / "state.md"
    with exclusive_file_lock(root / ".dlv" / "runs" / feature_id / ".feature.lock"):
        content, state = extract_state(state_path)
        if state.get("schema_version") != 9:
            raise ValueError("seal_proof_contract.py requires schema_version=9")
        code_spec = state.get("stages", {}).get("code_spec", {})
        code_spec_path = state_path.parent / "code-spec.md"
        if not code_spec_path.is_file():
            raise ValueError("Code Spec artifact is required before sealing its Proof Contract")
        code_spec_fingerprint = file_digest(code_spec_path)
        contract = state.get("proof_contract")
        if not isinstance(contract, dict):
            raise ValueError("proof_contract must be an object")
        prd_path = state_path.parent / "prd.md"
        prd_text = prd_path.read_text(encoding="utf-8") if prd_path.is_file() else ""
        acceptance_ids = set(re.findall(r"\b(?:AC|EX)-[0-9]+\b", prd_text))
        prototype_completed = state.get("stages", {}).get("prototype", {}).get("status") == "completed"
        artifact_path = state_path.parent / "proof-contract.json"
        review_errors: list[str] = []
        review = validate_quality_review(root, feature_id, "code_spec", state, review_errors)
        if review_errors:
            raise ValueError("; ".join(review_errors))
        quality_review = dict(state["quality_reviews"]["code_spec"])
        if quality_review.get("artifact_sha256") != code_spec_fingerprint:
            raise ValueError("Code Spec quality review is stale for the current artifact")
        if quality_review.get("proof_contract_sha256") != proof_contract_draft_digest(contract):
            raise ValueError("Code Spec quality review is stale for the Proof Contract draft")
        if artifact_path.is_file() and not contract.get("seal") and contract.get("status") != "completed":
            recovered = load_json(artifact_path)
            if (
                recovered.get("code_spec_fingerprint") != code_spec_fingerprint
                or recovered.get("quality_review") != quality_review
                or recovered.get("seal") != proof_contract_digest(recovered)
            ):
                raise ValueError("orphaned Proof Contract snapshot disagrees with the current Code Spec review")
            recovery_errors: list[str] = []
            validate_proof_contract(recovered, acceptance_ids, code_spec_fingerprint, prototype_completed, recovery_errors)
            if recovery_errors:
                raise ValueError("orphaned Proof Contract snapshot is invalid: " + "; ".join(recovery_errors))
            state["proof_contract"] = recovered
            code_spec.update({
                "status": "completed",
                "fingerprint": code_spec_fingerprint,
                "reviewed_at": review["reviewed_at"],
            })
            state["current_stage"] = "code"
            state["last_updated"] = timestamp()
            write_state(state_path, content, state)
            return str(recovered["seal"])
        if artifact_path.exists() or contract.get("seal") or contract.get("sealed_at") or contract.get("status") == "completed":
            raise ValueError("Proof Contract is already sealed; invalidate Code Spec to replace it")
        contract["code_spec_fingerprint"] = code_spec_fingerprint
        contract["status"] = "completed"
        contract["quality_review"] = quality_review
        contract["sealed_at"] = timestamp()
        contract["seal"] = proof_contract_digest(contract)
        errors: list[str] = []
        validate_proof_contract(
            contract,
            acceptance_ids,
            code_spec_fingerprint,
            prototype_completed,
            errors,
        )
        if errors:
            raise ValueError("cannot seal invalid Proof Contract: " + "; ".join(errors))
        code_spec.update({
            "status": "completed",
            "fingerprint": code_spec_fingerprint,
            "reviewed_at": review["reviewed_at"],
        })
        state["current_stage"] = "code"
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
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve()
    try:
        validate_feature_id(args.feature_id)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        print(seal_contract(args.feature_id, root))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
