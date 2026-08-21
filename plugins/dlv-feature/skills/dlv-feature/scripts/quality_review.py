#!/usr/bin/env python3
"""Record a fingerprint-bound schema-v8 Architecture or Code Spec quality review."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from delivery_proof import (
    atomic_write_text,
    exclusive_file_lock,
    extract_state,
    file_digest,
    load_json,
    validate_feature_id,
    write_state,
)
from quality_gates import REVIEW_ID, review_artifacts, validate_review_payload


def timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def record_review(feature_id: str, root: Path, review_type: str, run_id: str, result_path: Path) -> Path:
    validate_feature_id(feature_id)
    root = root.expanduser().resolve()
    if review_type not in {"architecture", "code_spec"}:
        raise ValueError("review_type must be architecture or code_spec")
    if not REVIEW_ID.fullmatch(run_id):
        raise ValueError("review-run-id must use lowercase hyphen-case")
    state_path = root / "delivery" / feature_id / "state.md"
    with exclusive_file_lock(root / ".dlv" / "runs" / feature_id / ".feature.lock"):
        content, state = extract_state(state_path)
        if state.get("schema_version") != 8:
            raise ValueError("quality reviews require schema_version=8")
        payload = load_json(result_path)
        if payload.get("review_type") != review_type:
            raise ValueError("result review_type does not match the command")
        payload["review_run_id"] = run_id
        payload["reviewed_at"] = timestamp()
        payload.update(review_artifacts(root, feature_id, review_type, state))
        errors: list[str] = []
        validate_review_payload(payload, review_type, errors)
        if errors:
            raise ValueError("; ".join(errors))
        destination = root / ".dlv" / "reviews" / feature_id / f"{run_id}.json"
        if destination.exists():
            raise ValueError(f"quality review run already exists: {destination}")
        atomic_write_text(destination, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        reviews = state.get("quality_reviews")
        approvals = state.get("approvals")
        if not isinstance(reviews, dict) or not isinstance(approvals, dict):
            destination.unlink(missing_ok=True)
            raise ValueError("state quality_reviews and approvals must be objects")
        reviews[review_type] = {
            "status": "completed" if payload["verdict"] == "PASS" else "blocked",
            "review_run_id": run_id,
            "artifact_sha256": payload["artifact_sha256"],
            "proof_contract_sha256": payload.get("proof_contract_sha256"),
            "verdict": payload["verdict"],
            "record_sha256": file_digest(destination),
        }
        approvals.pop(review_type, None)
        state["last_updated"] = timestamp()
        try:
            write_state(state_path, content, state)
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("review_type", choices=("architecture", "code_spec"))
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    try:
        output = record_review(args.feature_id, Path(args.root), args.review_type, args.run_id, Path(args.result))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
