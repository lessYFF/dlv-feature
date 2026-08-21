#!/usr/bin/env python3
"""Write fingerprint-bound schema-v8 approval receipts and advance approved stages."""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from delivery_proof import exclusive_file_lock, extract_state, file_digest, validate_feature_id, write_state
from quality_gates import (
    SHA256,
    proof_contract_draft_digest,
    prototype_decision_digest,
    requirement_review_digest,
    validate_approval_receipt,
    validate_quality_review,
)
from validate_feature import validate_architecture_review


def timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def receipt(stage: str, artifact: str, args: argparse.Namespace, **extra: str) -> dict[str, str]:
    return {
        "stage": stage,
        "artifact_sha256": artifact,
        "approved_by": args.approved_by,
        "approval_reference": args.approval_reference,
        "approval_text_sha256": args.approval_text_sha256,
        "approved_at": timestamp(),
        **extra,
    }


def approve(args: argparse.Namespace) -> Path:
    root = Path(args.root).expanduser().resolve()
    validate_feature_id(args.feature_id)
    for field in ("approved_by", "approval_reference"):
        if not getattr(args, field).strip():
            raise ValueError(f"--{field.replace('_', '-')} must be concrete")
    if not SHA256.fullmatch(args.approval_text_sha256):
        raise ValueError("--approval-text-sha256 must be a lowercase SHA-256 fingerprint")
    state_path = root / "delivery" / args.feature_id / "state.md"
    with exclusive_file_lock(root / ".dlv" / "runs" / args.feature_id / ".feature.lock"):
        content, state = extract_state(state_path)
        if state.get("schema_version") != 8:
            raise ValueError("approvals require schema_version=8")
        approvals = state.get("approvals")
        stages = state.get("stages")
        if not isinstance(approvals, dict) or not isinstance(stages, dict):
            raise ValueError("state approvals and stages must be objects")
        if args.stage == "requirement_review":
            review = state.get("requirement_review")
            summary = review.get("summary") if isinstance(review, dict) else None
            required_summary = {"goal", "users_scenarios", "in_scope", "out_scope", "key_rules", "ui_impact", "open_questions"}
            confirmed_ids = review.get("confirmed_ids") if isinstance(review, dict) else None
            if (
                not isinstance(review, dict)
                or not isinstance(review.get("source_fingerprint"), str)
                or not SHA256.fullmatch(review["source_fingerprint"])
                or not isinstance(confirmed_ids, list)
                or not confirmed_ids
                or not all(isinstance(value, str) and re.fullmatch(r"SRC-[0-9]+", value) for value in confirmed_ids)
                or not isinstance(summary, dict)
                or required_summary - summary.keys()
                or summary.get("ui_impact") not in {"visible", "non_visible", "none"}
                or any(
                    summary.get(key) is None
                    or summary.get(key) == ""
                    or summary.get(key) == []
                    or summary.get(key) == {}
                    for key in required_summary - {"ui_impact"}
                )
            ):
                raise ValueError("requirement review must be complete enough to approve")
            artifact = requirement_review_digest(state.get("requirement_review"))
            old = approvals.get("requirement_review")
            if isinstance(old, dict) and old.get("artifact_sha256") != artifact and any(
                stages.get(name, {}).get("status") not in {"pending", "stale"}
                for name in ("prd", "prototype", "architecture", "code_spec", "code", "verification")
            ):
                raise ValueError("changed requirement review requires invalidate_downstream.py --from-stage prd")
            approvals["requirement_review"] = receipt("requirement_review", artifact, args)
            state["requirement_review"]["status"] = "completed"
            state["requirement_review"]["approved_at"] = approvals["requirement_review"]["approved_at"]
            stages["prd"]["status"] = "in_progress"
        elif args.stage == "product":
            if any(
                stages.get(name, {}).get("status") not in {"pending", "stale"}
                for name in ("architecture", "code_spec", "code", "verification")
            ):
                raise ValueError("product reapproval requires invalidate_downstream.py --from-stage prd")
            requirement_errors: list[str] = []
            requirement = state.get("requirement_review")
            if not isinstance(requirement, dict) or requirement.get("status") != "completed":
                raise ValueError("product approval requires completed requirement review")
            validate_approval_receipt(
                approvals.get("requirement_review"),
                "requirement_review",
                requirement_review_digest(requirement),
                requirement_errors,
            )
            if requirement_errors:
                raise ValueError("; ".join(requirement_errors))
            prd_path = state_path.parent / "prd.md"
            if not prd_path.is_file():
                raise ValueError("product approval requires prd.md")
            prd_text = prd_path.read_text(encoding="utf-8")
            visible = bool(re.search(r"(?i)(?:UI\s*影响|界面影响)\s*[:：|]\s*`?visible\b", prd_text))
            prototype_path = state_path.parent / "prototype.html"
            if visible and not prototype_path.is_file():
                raise ValueError("visible UI product approval requires prototype.html")
            if not visible and prototype_path.is_file():
                raise ValueError("non-visible product approval must not include prototype.html")
            prd_sha = file_digest(prd_path)
            approvals["prd"] = receipt("prd", prd_sha, args)
            stages["prd"].update({"status": "completed", "fingerprint": prd_sha, "approved_at": approvals["prd"]["approved_at"]})
            if prototype_path.is_file():
                prototype_sha = file_digest(prototype_path)
                approvals["prototype"] = receipt("prototype", prototype_sha, args)
                stages["prototype"].update({
                    "status": "completed", "fingerprint": prototype_sha,
                    "approved_at": approvals["prototype"]["approved_at"], "inputs": {"prd": prd_sha},
                })
                if isinstance(stages["prototype"].get("contract"), dict):
                    stages["prototype"]["contract"]["prd_fingerprint"] = prd_sha
                    stages["prototype"]["contract"]["html_fingerprint"] = prototype_sha
            else:
                approvals["prototype"] = receipt(
                    "prototype", prototype_decision_digest(prd_sha), args
                )
                stages["prototype"].update({
                    "status": "not_applicable",
                    "fingerprint": None,
                    "approved_at": approvals["prototype"]["approved_at"],
                    "inputs": {"prd": prd_sha},
                })
            state["current_stage"] = "architecture"
        elif args.stage == "architecture":
            if any(
                stages.get(name, {}).get("status") not in {"pending", "stale"}
                for name in ("code_spec", "code", "verification")
            ):
                raise ValueError("Architecture reapproval requires invalidate_downstream.py --from-stage architecture")
            if stages.get("prd", {}).get("status") != "completed" or stages.get("prototype", {}).get("status") not in {"completed", "not_applicable"}:
                raise ValueError("architecture approval requires product-approved PRD and prototype decision")
            errors: list[str] = []
            prototype_fingerprint = (
                stages["prototype"].get("fingerprint")
                if stages["prototype"].get("status") == "completed"
                else None
            )
            validate_architecture_review(
                state.get("architecture_review"),
                stages,
                stages["prd"].get("fingerprint"),
                prototype_fingerprint,
                errors,
            )
            review = validate_quality_review(root, args.feature_id, "architecture", state, errors)
            if errors or review is None:
                raise ValueError("; ".join(errors))
            artifact = review["artifact_sha256"]
            approvals["architecture"] = receipt(
                "architecture", artifact, args, quality_review_run_id=review["review_run_id"]
            )
            stages["architecture"].update({"status": "completed", "fingerprint": artifact})
            state["current_stage"] = "code_spec"
        else:
            contract = state.get("proof_contract")
            if any(
                stages.get(name, {}).get("status") not in {"pending", "stale"}
                for name in ("code", "verification")
            ) or (isinstance(contract, dict) and contract.get("status") == "completed"):
                raise ValueError("Code Spec reapproval requires invalidate_downstream.py --from-stage code_spec")
            if stages.get("architecture", {}).get("status") != "completed":
                raise ValueError("Code Spec approval requires approved Architecture")
            errors = []
            review = validate_quality_review(root, args.feature_id, "code_spec", state, errors)
            if errors or review is None:
                raise ValueError("; ".join(errors))
            proof_sha = proof_contract_draft_digest(state.get("proof_contract"))
            approvals["code_spec"] = receipt(
                "code_spec", review["artifact_sha256"], args,
                quality_review_run_id=review["review_run_id"], proof_contract_sha256=proof_sha,
            )
        state["last_updated"] = timestamp()
        write_state(state_path, content, state)
    return state_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("requirement_review", "product", "architecture", "code_spec"))
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--approved-by", required=True)
    parser.add_argument("--approval-reference", required=True)
    parser.add_argument("--approval-text-sha256", required=True)
    args = parser.parse_args()
    try:
        output = approve(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
