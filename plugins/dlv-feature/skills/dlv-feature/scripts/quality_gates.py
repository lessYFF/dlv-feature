#!/usr/bin/env python3
"""Shared delivery-schema-v9 automated quality-review contracts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from delivery_proof import file_digest, value_digest


SHA256 = re.compile(r"^[0-9a-f]{64}$")
REVIEW_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REVIEW_TYPES = ("product", "architecture", "code_spec")
FINDING_IDS = {
    "product": re.compile(r"^PRQ-[0-9]+$"),
    "architecture": re.compile(r"^ARQ-[0-9]+$"),
    "code_spec": re.compile(r"^CSQ-[0-9]+$"),
}
REQUIRED_CHECKS = {
    "product": {
        "source-coverage", "prd-acceptance-coverage", "prototype-state-coverage",
        "prd-prototype-consistency", "no-invented-scope",
    },
    "architecture": {
        "database-risk", "api-compatibility", "existing-business-impact",
        "authorization-and-isolation", "fact-ownership",
    },
    "code_spec": {
        "prd-coverage", "prototype-coverage", "risk-coverage", "proof-coverage",
        "unmapped-changes",
    },
}
COVERAGE_CHECKS = {
    "source-coverage", "prd-acceptance-coverage", "prototype-state-coverage",
    "prd-coverage", "prototype-coverage", "risk-coverage", "proof-coverage",
}
N_A_CHECKS = {
    "product": {"prototype-state-coverage"},
    "architecture": {"database-risk", "api-compatibility", "authorization-and-isolation"},
    "code_spec": {"prototype-coverage"},
}
REVIEW_EXECUTION_MODES = {"fresh_context", "isolated_process"}


def document_ids(text: str, prefixes: tuple[str, ...]) -> set[str]:
    pattern = r"\b(?:" + "|".join(prefixes) + r")-(?:[A-Z][0-9]+-)?[0-9]+\b"
    return set(re.findall(pattern, text))


def expected_review_coverage(
    feature_dir: Path, review_type: str, state: dict[str, Any]
) -> dict[str, set[str]]:
    prd_path = feature_dir / "prd.md"
    prd = prd_path.read_text(encoding="utf-8") if prd_path.is_file() else ""
    if review_type == "product":
        requirement = state.get("requirement_review")
        confirmed = requirement.get("confirmed_ids", []) if isinstance(requirement, dict) else []
        return {
            "source-coverage": {item for item in confirmed if isinstance(item, str)},
            "prd-acceptance-coverage": document_ids(prd, ("AC", "EX")),
            "prototype-state-coverage": document_ids(prd, ("US",)) if (feature_dir / "prototype.html").is_file() else set(),
        }
    if review_type == "code_spec":
        risks = state.get("risks") if isinstance(state.get("risks"), list) else []
        obligations = state.get("proof_contract", {}).get("obligations", []) if isinstance(state.get("proof_contract"), dict) else []
        return {
            "prd-coverage": document_ids(prd, ("FR", "BR", "AC", "EX", "US")),
            "prototype-coverage": document_ids(prd, ("US",)) if (feature_dir / "prototype.html").is_file() else set(),
            "risk-coverage": {str(item.get("id")) for item in risks if isinstance(item, dict) and item.get("id")},
            "proof-coverage": {str(item.get("id")) for item in obligations if isinstance(item, dict) and item.get("id")},
        }
    return {}


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
        if key not in {"status", "code_spec_fingerprint", "quality_review", "sealed_at", "seal"}
    })


def architecture_review_digest(review: Any) -> str:
    if not isinstance(review, dict):
        return value_digest(None)
    return value_digest({
        key: value for key, value in review.items()
        if key not in {"status", "reviewed_at"}
    })


def review_artifacts(root: Path, feature_id: str, review_type: str, state: dict[str, Any]) -> dict[str, Any]:
    if review_type not in REVIEW_TYPES:
        raise ValueError(f"unknown review type: {review_type}")
    feature_dir = root / "delivery" / feature_id
    stages = state.get("stages", {})
    prd_path = feature_dir / "prd.md"
    prd_sha = file_digest(prd_path) if prd_path.is_file() else None
    prototype_path = feature_dir / "prototype.html"
    prototype_sha = (
        file_digest(prototype_path)
        if prototype_path.is_file()
        else prototype_decision_digest(prd_sha) if isinstance(prd_sha, str) else None
    )
    if review_type == "product":
        bound = {
            "requirements": requirement_review_digest(state.get("requirement_review")),
            "prd": prd_sha,
            "prototype": prototype_sha,
        }
        return {
            "artifact_sha256": value_digest(bound) if all(isinstance(value, str) for value in bound.values()) else None,
            "proof_contract_sha256": None,
            "bound_artifacts": bound,
        }
    if review_type == "architecture":
        path = feature_dir / "architecture-design.md"
        artifact_sha = file_digest(path) if path.is_file() else None
        bound = {
            "architecture": artifact_sha,
            "architecture_review": architecture_review_digest(state.get("architecture_review")),
            "product_review": value_digest(state.get("quality_reviews", {}).get("product")),
            "prd": stages.get("prd", {}).get("fingerprint"),
            "prototype": prototype_sha,
        }
        return {
            "artifact_sha256": artifact_sha,
            "proof_contract_sha256": None,
            "bound_artifacts": bound,
        }
    path = feature_dir / "code-spec.md"
    artifact_sha = file_digest(path) if path.is_file() else None
    proof_sha = proof_contract_draft_digest(state.get("proof_contract"))
    bound = {
        "code_spec": artifact_sha,
        "proof_contract": proof_sha,
        "prd": stages.get("prd", {}).get("fingerprint"),
        "prototype": prototype_sha,
        "architecture": stages.get("architecture", {}).get("fingerprint"),
        "architecture_review": value_digest(state.get("quality_reviews", {}).get("architecture")),
        "risks": value_digest(state.get("risks", [])),
    }
    return {
        "artifact_sha256": artifact_sha,
        "proof_contract_sha256": proof_sha,
        "bound_artifacts": bound,
    }


def validate_review_payload(payload: Any, review_type: str, errors: list[str]) -> None:
    prefix = f"quality_review.{review_type}"
    if review_type not in REVIEW_TYPES:
        errors.append(f"{prefix}.review_type is invalid")
        return
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
    execution = payload.get("execution")
    if not isinstance(execution, dict):
        errors.append(f"{prefix}.execution must describe the independent review run")
    else:
        if execution.get("mode") not in REVIEW_EXECUTION_MODES:
            errors.append(f"{prefix}.execution.mode must be fresh_context or isolated_process")
        for field in ("provider", "invocation_id", "transcript_path"):
            if not isinstance(execution.get(field), str) or not execution[field].strip():
                errors.append(f"{prefix}.execution.{field} must be concrete")
        if not isinstance(execution.get("transcript_sha256"), str) or not SHA256.fullmatch(execution["transcript_sha256"]):
            errors.append(f"{prefix}.execution.transcript_sha256 must be a SHA-256 fingerprint")
    if payload.get("verdict") not in {"PASS", "REVISE", "BLOCKED"}:
        errors.append(f"{prefix}.verdict is invalid")
    if not isinstance(payload.get("artifact_sha256"), str) or not SHA256.fullmatch(payload["artifact_sha256"]):
        errors.append(f"{prefix}.artifact_sha256 must be a SHA-256 fingerprint")
    bound = payload.get("bound_artifacts")
    if not isinstance(bound, dict) or not bound:
        errors.append(f"{prefix}.bound_artifacts must be a non-empty object")
    elif any(not isinstance(value, str) or not SHA256.fullmatch(value) for value in bound.values()):
        errors.append(f"{prefix}.bound_artifacts must contain only SHA-256 fingerprints")
    if review_type == "code_spec" and (
        not isinstance(payload.get("proof_contract_sha256"), str)
        or not SHA256.fullmatch(payload["proof_contract_sha256"])
    ):
        errors.append(f"{prefix}.proof_contract_sha256 must be a SHA-256 fingerprint")

    findings = payload.get("findings")
    if not isinstance(findings, list):
        errors.append(f"{prefix}.findings must be an array")
        findings = []
    seen_findings: set[str] = set()
    blocking = False
    for index, finding in enumerate(findings):
        location = f"{prefix}.findings[{index}]"
        if not isinstance(finding, dict):
            errors.append(f"{location} must be an object")
            continue
        finding_id = finding.get("id")
        if not isinstance(finding_id, str) or not FINDING_IDS[review_type].fullmatch(finding_id):
            errors.append(f"{location}.id is invalid")
        elif finding_id in seen_findings:
            errors.append(f"duplicate quality-review finding: {finding_id}")
        else:
            seen_findings.add(finding_id)
        if finding.get("severity") not in {"critical", "major", "minor"}:
            errors.append(f"{location}.severity is invalid")
        if finding.get("status") not in {"open", "resolved"}:
            errors.append(f"{location}.status is invalid")
        for field in ("statement", "evidence"):
            if not isinstance(finding.get(field), str) or not finding[field].strip():
                errors.append(f"{location}.{field} must be concrete")
        if finding.get("severity") in {"critical", "major"} and finding.get("status") == "open":
            blocking = True

    checks = payload.get("checks")
    if not isinstance(checks, list):
        errors.append(f"{prefix}.checks must be an array")
        checks = []
    by_id: dict[str, dict[str, Any]] = {}
    for index, check in enumerate(checks):
        location = f"{prefix}.checks[{index}]"
        if not isinstance(check, dict):
            errors.append(f"{location} must be an object")
            continue
        check_id = check.get("id")
        if not isinstance(check_id, str) or check_id not in REQUIRED_CHECKS[review_type]:
            errors.append(f"{location}.id is invalid")
            continue
        if check_id in by_id:
            errors.append(f"duplicate quality-review check: {check_id}")
            continue
        by_id[check_id] = check
        status = check.get("status")
        if status not in {"PASS", "FAIL", "N/A"}:
            errors.append(f"{location}.status is invalid")
        if status == "N/A" and check_id not in N_A_CHECKS[review_type]:
            errors.append(f"{location} cannot be N/A")
        if status == "N/A" and (
            not isinstance(check.get("not_applicable_reason"), str)
            or not check["not_applicable_reason"].strip()
        ):
            errors.append(f"{location}.not_applicable_reason must be concrete for N/A")
        if not isinstance(check.get("evidence"), str) or not check["evidence"].strip():
            errors.append(f"{location}.evidence must be concrete")
        if check_id in COVERAGE_CHECKS and status == "PASS" and check.get("coverage_pct") != 100:
            errors.append(f"{location}.coverage_pct must be 100 for PASS")
        if check_id in COVERAGE_CHECKS and status == "PASS" and not isinstance(check.get("covered_ids"), list):
            errors.append(f"{location}.covered_ids must be an explicit array for PASS")
        if check_id == "unmapped-changes" and status == "PASS" and check.get("unmapped_count") != 0:
            errors.append(f"{location}.unmapped_count must be 0 for PASS")
    missing = REQUIRED_CHECKS[review_type] - set(by_id)
    if missing:
        errors.append(f"{prefix}.checks missing required checks: {', '.join(sorted(missing))}")
    if payload.get("verdict") == "PASS":
        if blocking:
            errors.append(f"{prefix} cannot PASS with open critical or major findings")
        failed_checks = sorted(check_id for check_id, check in by_id.items() if check.get("status") == "FAIL")
        if failed_checks:
            errors.append(f"{prefix} cannot PASS with failed checks: {', '.join(failed_checks)}")


def validate_review_context(
    payload: dict[str, Any], review_type: str, feature_dir: Path, errors: list[str],
    state: dict[str, Any] | None = None,
) -> None:
    """Reject context-sensitive N/A claims that would skip an existing Prototype."""
    checks = payload.get("checks")
    if not isinstance(checks, list):
        return
    by_id = {check.get("id"): check for check in checks if isinstance(check, dict)}
    expected_coverage = expected_review_coverage(feature_dir, review_type, state or {})
    for check_id, expected_ids in expected_coverage.items():
        check = by_id.get(check_id, {})
        status = check.get("status")
        covered = check.get("covered_ids")
        if status == "N/A" and expected_ids:
            errors.append(f"quality_review.{review_type}.{check_id} cannot be N/A with required IDs")
        if status == "PASS" and (
            not isinstance(covered, list)
            or any(not isinstance(item, str) for item in covered)
            or set(covered) != expected_ids
            or len(covered) != len(expected_ids)
        ):
            errors.append(
                f"quality_review.{review_type}.{check_id}.covered_ids must exactly match: {', '.join(sorted(expected_ids)) or 'none'}"
            )
    if review_type in {"product", "code_spec"} and (feature_dir / "prototype.html").is_file():
        check_id = "prototype-state-coverage" if review_type == "product" else "prototype-coverage"
        if by_id.get(check_id, {}).get("status") == "N/A":
            errors.append(f"quality_review.{review_type}.{check_id} cannot be N/A when prototype.html exists")
    if review_type != "architecture" or not isinstance(state, dict):
        return
    review = state.get("architecture_review")
    if not isinstance(review, dict):
        return
    additions = review.get("additions") if isinstance(review.get("additions"), list) else []
    addition_types = {item.get("type") for item in additions if isinstance(item, dict)}
    applicability = {
        "database-risk": bool(addition_types & {"table", "link_table", "field"}),
        "api-compatibility": bool(review.get("api_decisions")) or "api" in addition_types,
        "authorization-and-isolation": any(
            isinstance(review.get(name), dict) and review[name].get("applicable")
            for name in ("isolation", "boundary_proofs")
        ),
    }
    for check_id, applicable in applicability.items():
        if applicable and by_id.get(check_id, {}).get("status") == "N/A":
            errors.append(f"quality_review.architecture.{check_id} cannot be N/A for the reviewed architecture")


def validate_quality_review(
    root: Path,
    feature_id: str,
    review_type: str,
    state: dict[str, Any],
    errors: list[str],
    *,
    require_pass: bool = True,
) -> dict[str, Any] | None:
    root = root.expanduser().resolve()
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
    validate_review_context(payload, review_type, root / "delivery" / feature_id, errors, state)
    if payload.get("review_run_id") != run_id:
        errors.append(f"quality_review.{review_type}.review_run_id disagrees with its record filename")
    execution = payload.get("execution")
    if isinstance(execution, dict) and isinstance(execution.get("transcript_path"), str):
        transcript = (root / execution["transcript_path"]).resolve()
        expected_transcript = (
            root / ".dlv" / "reviews" / feature_id
            / f"{run_id}.{execution.get('invocation_id')}.transcript.jsonl"
        )
        try:
            transcript.relative_to(root)
        except ValueError:
            errors.append(f"quality_review.{review_type}.execution.transcript_path escapes the project root")
        else:
            if transcript != expected_transcript or transcript != expected_transcript.absolute():
                errors.append(f"quality_review.{review_type}.execution.transcript_path is not canonical")
            elif not transcript.is_file():
                errors.append(f"quality_review.{review_type} transcript is missing")
            elif execution.get("transcript_sha256") != file_digest(transcript):
                errors.append(f"quality_review.{review_type} transcript hash is stale")
    expected_summary = {
        "status": "completed" if payload.get("verdict") == "PASS" else "blocked",
        "review_run_id": run_id,
        "artifact_sha256": payload.get("artifact_sha256"),
        "proof_contract_sha256": payload.get("proof_contract_sha256"),
        "bound_artifacts": payload.get("bound_artifacts"),
        "verdict": payload.get("verdict"),
        "record_sha256": file_digest(path),
    }
    if summary != expected_summary:
        errors.append(f"quality_reviews.{review_type} disagrees with its review record")
    expected = review_artifacts(root, feature_id, review_type, state)
    if payload.get("artifact_sha256") != expected["artifact_sha256"]:
        errors.append(f"quality review {review_type} is stale for its artifact")
    if payload.get("bound_artifacts") != expected["bound_artifacts"]:
        errors.append(f"quality review {review_type} is stale for its bound inputs")
    if review_type == "code_spec" and payload.get("proof_contract_sha256") != expected["proof_contract_sha256"]:
        errors.append("Code Spec quality review is stale for the Proof Contract")
    if require_pass and payload.get("verdict") != "PASS":
        errors.append(f"quality review {review_type} must PASS before stage transition")
    return payload
