#!/usr/bin/env python3
"""Shared schema-v8 approval and quality-review contracts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from delivery_proof import file_digest, value_digest


SHA256 = re.compile(r"^[0-9a-f]{64}$")
REVIEW_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
FINDING_IDS = {
    "architecture": re.compile(r"^ARQ-[0-9]+$"),
    "code_spec": re.compile(r"^CSQ-[0-9]+$"),
}


def requirement_review_digest(review: Any) -> str:
    if not isinstance(review, dict):
        return value_digest(None)
    return value_digest({
        "source_fingerprint": review.get("source_fingerprint"),
        "confirmed_ids": review.get("confirmed_ids"),
        "summary": review.get("summary"),
    })


def prototype_decision_digest(prd_sha256: str) -> str:
    """Bind a no-prototype product decision to the PRD that justified it."""
    return value_digest({"status": "not_applicable", "prd_sha256": prd_sha256})


def proof_contract_draft_digest(contract: Any) -> str:
    if not isinstance(contract, dict):
        return value_digest(None)
    return value_digest({
        key: value for key, value in contract.items()
        if key not in {"status", "code_spec_fingerprint", "approval", "sealed_at", "seal"}
    })


def review_artifacts(root: Path, feature_id: str, review_type: str, state: dict[str, Any]) -> dict[str, str | None]:
    feature_dir = root / "delivery" / feature_id
    if review_type == "architecture":
        path = feature_dir / "architecture-design.md"
        return {"artifact_sha256": file_digest(path) if path.is_file() else None, "proof_contract_sha256": None}
    path = feature_dir / "code-spec.md"
    return {
        "artifact_sha256": file_digest(path) if path.is_file() else None,
        "proof_contract_sha256": proof_contract_draft_digest(state.get("proof_contract")),
    }


def validate_review_payload(payload: Any, review_type: str, errors: list[str]) -> None:
    prefix = f"quality_review.{review_type}"
    if not isinstance(payload, dict):
        errors.append(f"{prefix} must be an object")
        return
    if payload.get("review_type") != review_type:
        errors.append(f"{prefix}.review_type is invalid")
    if not isinstance(payload.get("review_run_id"), str) or not REVIEW_ID.fullmatch(payload["review_run_id"]):
        errors.append(f"{prefix}.review_run_id must use lowercase hyphen-case")
    for field in ("reviewer", "review_reference", "reviewed_at"):
        if not isinstance(payload.get(field), str) or not payload[field].strip():
            errors.append(f"{prefix}.{field} must be concrete")
    if payload.get("verdict") not in {"PASS", "REVISE", "BLOCKED"}:
        errors.append(f"{prefix}.verdict is invalid")
    for field in ("artifact_sha256",):
        if not isinstance(payload.get(field), str) or not SHA256.fullmatch(payload[field]):
            errors.append(f"{prefix}.{field} must be a SHA-256 fingerprint")
    if review_type == "code_spec" and (
        not isinstance(payload.get("proof_contract_sha256"), str)
        or not SHA256.fullmatch(payload["proof_contract_sha256"])
    ):
        errors.append(f"{prefix}.proof_contract_sha256 must be a SHA-256 fingerprint")
    findings = payload.get("findings")
    if not isinstance(findings, list):
        errors.append(f"{prefix}.findings must be an array")
        return
    seen: set[str] = set()
    blocking = False
    for index, finding in enumerate(findings):
        location = f"{prefix}.findings[{index}]"
        if not isinstance(finding, dict):
            errors.append(f"{location} must be an object")
            continue
        finding_id = finding.get("id")
        if not isinstance(finding_id, str) or not FINDING_IDS[review_type].fullmatch(finding_id):
            errors.append(f"{location}.id is invalid")
        elif finding_id in seen:
            errors.append(f"duplicate quality-review finding: {finding_id}")
        else:
            seen.add(finding_id)
        if finding.get("severity") not in {"critical", "major", "minor"}:
            errors.append(f"{location}.severity is invalid")
        if finding.get("status") not in {"open", "resolved"}:
            errors.append(f"{location}.status is invalid")
        for field in ("statement", "evidence"):
            if not isinstance(finding.get(field), str) or not finding[field].strip():
                errors.append(f"{location}.{field} must be concrete")
        if finding.get("severity") in {"critical", "major"} and finding.get("status") == "open":
            blocking = True
    if payload.get("verdict") == "PASS" and blocking:
        errors.append(f"{prefix} cannot PASS with open critical or major findings")


def validate_quality_review(
    root: Path,
    feature_id: str,
    review_type: str,
    state: dict[str, Any],
    errors: list[str],
    *,
    require_pass: bool = True,
) -> dict[str, Any] | None:
    reviews = state.get("quality_reviews")
    summary = reviews.get(review_type) if isinstance(reviews, dict) else None
    if not isinstance(summary, dict):
        errors.append(f"completed {review_type} requires a quality review")
        return None
    run_id = summary.get("review_run_id")
    if not isinstance(run_id, str) or not REVIEW_ID.fullmatch(run_id):
        errors.append(f"quality_reviews.{review_type}.review_run_id is invalid")
        return None
    path = root / ".dlv" / "reviews" / feature_id / f"{run_id}.json"
    if not path.is_file():
        errors.append(f"quality review record is missing: {path}")
        return None
    import json

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append(f"cannot read quality review {run_id}: {exc}")
        return None
    validate_review_payload(payload, review_type, errors)
    if summary != {
        "status": "completed" if payload.get("verdict") == "PASS" else "blocked",
        "review_run_id": run_id,
        "artifact_sha256": payload.get("artifact_sha256"),
        "proof_contract_sha256": payload.get("proof_contract_sha256"),
        "verdict": payload.get("verdict"),
        "record_sha256": file_digest(path),
    }:
        errors.append(f"quality_reviews.{review_type} disagrees with its review record")
    expected = review_artifacts(root, feature_id, review_type, state)
    if payload.get("artifact_sha256") != expected["artifact_sha256"]:
        errors.append(f"quality review {review_type} is stale for its artifact")
    if review_type == "code_spec" and payload.get("proof_contract_sha256") != expected["proof_contract_sha256"]:
        errors.append("Code Spec quality review is stale for the Proof Contract")
    if require_pass and payload.get("verdict") != "PASS":
        errors.append(f"quality review {review_type} must PASS before approval")
    return payload


def validate_approval_receipt(
    receipt: Any,
    stage: str,
    artifact_sha256: str,
    errors: list[str],
    *,
    review: dict[str, Any] | None = None,
    proof_contract_sha256: str | None = None,
) -> None:
    prefix = f"approvals.{stage}"
    if not isinstance(receipt, dict):
        errors.append(f"{prefix} must be an approval receipt")
        return
    required = ("stage", "artifact_sha256", "approved_by", "approval_reference", "approval_text_sha256", "approved_at")
    for field in required:
        if not isinstance(receipt.get(field), str) or not receipt[field].strip():
            errors.append(f"{prefix}.{field} must be concrete")
    if receipt.get("stage") != stage:
        errors.append(f"{prefix}.stage is invalid")
    if receipt.get("artifact_sha256") != artifact_sha256:
        errors.append(f"{prefix} is stale for the approved artifact")
    if not isinstance(receipt.get("approval_text_sha256"), str) or not SHA256.fullmatch(receipt["approval_text_sha256"]):
        errors.append(f"{prefix}.approval_text_sha256 must be a SHA-256 fingerprint")
    if review is not None and receipt.get("quality_review_run_id") != review.get("review_run_id"):
        errors.append(f"{prefix} is not bound to the current quality review")
    if proof_contract_sha256 is not None and receipt.get("proof_contract_sha256") != proof_contract_sha256:
        errors.append(f"{prefix} is stale for the Proof Contract")
