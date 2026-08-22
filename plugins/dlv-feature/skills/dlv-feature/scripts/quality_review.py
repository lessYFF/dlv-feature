#!/usr/bin/env python3
"""Record one automated schema-v9 Product, Architecture, or Code Spec review."""

from __future__ import annotations

import argparse
import copy
import json
import secrets
import shutil
import subprocess
import sys
import tempfile
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
from quality_gates import (
    REQUIRED_CHECKS,
    REVIEW_ID,
    REVIEW_TYPES,
    expected_review_coverage,
    prototype_decision_digest,
    review_artifacts,
    validate_review_context,
    validate_review_payload,
)


def timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def confined_path(root: Path, path: Path, label: str, *, canonical: bool = False) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} escapes the project root") from exc
    if canonical and resolved != path.absolute():
        raise ValueError(f"{label} must not be relocated through a symlink")
    return resolved


def _record_review(
    feature_id: str, root: Path, review_type: str, run_id: str, result_path: Path,
    *, execution: dict[str, str], reviewed_artifacts: dict[str, object],
) -> Path:
    validate_feature_id(feature_id)
    root = root.expanduser().resolve()
    if review_type not in REVIEW_TYPES:
        raise ValueError("review_type must be product, architecture, or code_spec")
    if not REVIEW_ID.fullmatch(run_id):
        raise ValueError("review-run-id must use lowercase hyphen-case")
    feature_dir = confined_path(root, root / "delivery" / feature_id, "feature directory")
    review_dir = confined_path(
        root, root / ".dlv" / "reviews" / feature_id,
        "quality review directory", canonical=True,
    )
    state_path = feature_dir / "state.md"
    with exclusive_file_lock(root / ".dlv" / "runs" / feature_id / ".feature.lock"):
        content, state = extract_state(state_path)
        original_state = copy.deepcopy(state)
        if state.get("schema_version") != 9:
            raise ValueError("quality reviews require schema_version=9")
        current_artifacts = review_artifacts(root, feature_id, review_type, state)
        if current_artifacts != reviewed_artifacts:
            raise ValueError("quality review inputs changed during the isolated review; run a fresh review")
        payload = load_json(result_path)
        payload["review_type"] = review_type
        payload["reviewer"] = execution.get("provider")
        payload["review_reference"] = execution.get("invocation_id")
        payload["execution"] = execution
        payload["review_run_id"] = run_id
        payload["reviewed_at"] = timestamp()
        payload.update(reviewed_artifacts)
        errors: list[str] = []
        validate_review_payload(payload, review_type, errors)
        validate_review_context(payload, review_type, state_path.parent, errors, state)
        if errors:
            raise ValueError("; ".join(errors))
        destination = review_dir / f"{run_id}.json"
        if destination.exists():
            raise ValueError(f"quality review run already exists: {destination}")
        invocation_id = execution.get("invocation_id")
        for existing in destination.parent.glob("*.json") if destination.parent.is_dir() else ():
            try:
                existing_payload = load_json(existing)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if existing_payload.get("execution", {}).get("invocation_id") == invocation_id:
                raise ValueError("independent review invocation_id cannot be reused")
        atomic_write_text(destination, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        reviews = state.get("quality_reviews")
        stages = state.get("stages")
        if not isinstance(reviews, dict) or not isinstance(stages, dict):
            destination.unlink(missing_ok=True)
            raise ValueError("state quality_reviews and stages must be objects")
        reviews[review_type] = {
            "status": "completed" if payload["verdict"] == "PASS" else "blocked",
            "review_run_id": run_id,
            "artifact_sha256": payload["artifact_sha256"],
            "proof_contract_sha256": payload.get("proof_contract_sha256"),
            "bound_artifacts": payload.get("bound_artifacts"),
            "verdict": payload["verdict"],
            "record_sha256": file_digest(destination),
        }
        passed = payload["verdict"] == "PASS"
        blocked_status = "blocked" if payload["verdict"] == "BLOCKED" else "in_progress"
        if review_type == "product":
            requirement = state.get("requirement_review")
            if not isinstance(requirement, dict):
                destination.unlink(missing_ok=True)
                raise ValueError("product review requires requirement_review")
            if passed:
                requirement.update({"status": "completed", "reviewed_at": payload["reviewed_at"]})
                prd_sha = payload["bound_artifacts"]["prd"]
                stages["prd"].update({
                    "status": "completed", "fingerprint": prd_sha, "reviewed_at": payload["reviewed_at"],
                })
                prototype_path = state_path.parent / "prototype.html"
                if prototype_path.is_file():
                    stages["prototype"].update({
                        "status": "completed",
                        "fingerprint": payload["bound_artifacts"]["prototype"],
                        "reviewed_at": payload["reviewed_at"],
                        "inputs": {"prd": prd_sha},
                    })
                    contract = stages["prototype"].get("contract")
                    if isinstance(contract, dict):
                        contract.update({
                            "prd_fingerprint": prd_sha,
                            "html_fingerprint": payload["bound_artifacts"]["prototype"],
                        })
                else:
                    stages["prototype"].update({
                        "status": "not_applicable", "fingerprint": None,
                        "reviewed_at": payload["reviewed_at"], "inputs": {"prd": prd_sha},
                    })
                state["current_stage"] = "architecture"
            else:
                requirement["status"] = blocked_status
                stages["prd"]["status"] = blocked_status
                state["current_stage"] = "prd"
        elif review_type == "architecture":
            if stages.get("prd", {}).get("status") != "completed":
                destination.unlink(missing_ok=True)
                raise ValueError("Architecture review requires a passed Product review")
            if passed:
                stages["architecture"].update({
                    "status": "completed", "fingerprint": payload["artifact_sha256"],
                    "reviewed_at": payload["reviewed_at"],
                })
                architecture_review = state.get("architecture_review")
                if isinstance(architecture_review, dict):
                    architecture_review.update({"status": "completed", "reviewed_at": payload["reviewed_at"]})
                state["current_stage"] = "code_spec"
            else:
                stages["architecture"]["status"] = blocked_status
                architecture_review = state.get("architecture_review")
                if isinstance(architecture_review, dict):
                    architecture_review.update({"status": blocked_status, "reviewed_at": payload["reviewed_at"]})
                state["current_stage"] = "architecture"
        else:
            if stages.get("architecture", {}).get("status") != "completed":
                destination.unlink(missing_ok=True)
                raise ValueError("Code Spec review requires a passed Architecture review")
            stages["code_spec"]["status"] = "in_progress" if passed else blocked_status
            state["current_stage"] = "code_spec"
        state["last_updated"] = timestamp()
        try:
            write_state(state_path, content, state)
            if passed:
                validation = subprocess.run(
                    [sys.executable, str(Path(__file__).with_name("validate_feature.py")), feature_id, "--root", str(root)],
                    capture_output=True,
                    text=True,
                )
                if validation.returncode != 0:
                    write_state(state_path, content, original_state)
                    destination.unlink(missing_ok=True)
                    detail = (validation.stdout + validation.stderr).strip()
                    raise ValueError(f"quality review PASS failed intermediate validation: {detail}")
                if review_artifacts(root, feature_id, review_type, state) != reviewed_artifacts:
                    write_state(state_path, content, original_state)
                    destination.unlink(missing_ok=True)
                    raise ValueError("quality review inputs changed during final validation; run a fresh review")
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
    return destination


def review_output_schema(review_type: str) -> dict[str, object]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["verdict", "findings", "checks"],
        "properties": {
            "verdict": {"type": "string", "enum": ["PASS", "REVISE", "BLOCKED"]},
            "findings": {
                "type": "array",
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["id", "severity", "status", "statement", "evidence"],
                    "properties": {
                        "id": {"type": "string"},
                        "severity": {"type": "string", "enum": ["critical", "major", "minor"]},
                        "status": {"type": "string", "enum": ["open", "resolved"]},
                        "statement": {"type": "string"}, "evidence": {"type": "string"},
                    },
                },
            },
            "checks": {
                "type": "array",
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["id", "status", "evidence", "coverage_pct", "covered_ids", "unmapped_count", "not_applicable_reason"],
                    "properties": {
                        "id": {"type": "string", "enum": sorted(REQUIRED_CHECKS[review_type])},
                        "status": {"type": "string", "enum": ["PASS", "FAIL", "N/A"]},
                        "evidence": {"type": "string"},
                        "coverage_pct": {"type": ["integer", "null"]},
                        "covered_ids": {"type": "array", "items": {"type": "string"}},
                        "unmapped_count": {"type": ["integer", "null"]},
                        "not_applicable_reason": {"type": ["string", "null"]},
                    },
                },
            },
        },
    }


def run_isolated_review(feature_id: str, root: Path, review_type: str, run_id: str) -> Path:
    validate_feature_id(feature_id)
    if review_type not in REVIEW_TYPES:
        raise ValueError("review_type must be product, architecture, or code_spec")
    if not REVIEW_ID.fullmatch(run_id):
        raise ValueError("review-run-id must use lowercase hyphen-case")
    root = root.expanduser().resolve()
    feature_dir = confined_path(root, root / "delivery" / feature_id, "feature directory")
    review_dir = confined_path(
        root, root / ".dlv" / "reviews" / feature_id,
        "quality review directory", canonical=True,
    )
    snapshot_parent = confined_path(
        root, root / ".dlv" / "review-inputs",
        "quality review input directory", canonical=True,
    )
    state_path = feature_dir / "state.md"
    _, state = extract_state(state_path)
    invocation_id = f"review-{secrets.token_hex(16)}"
    coverage = {
        check_id: sorted(values)
        for check_id, values in expected_review_coverage(state_path.parent, review_type, state).items()
    }
    artifacts = review_artifacts(root, feature_id, review_type, state)
    snapshot_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dlv-review-", dir=snapshot_parent) as temporary:
        temp_dir = Path(temporary)
        snapshot_dir = temp_dir / "input-snapshot"
        snapshot_dir.mkdir()
        bound_files = {
            "prd.md": "prd",
            "prototype.html": "prototype",
            "architecture-design.md": "architecture",
            "code-spec.md": "code_spec",
        }
        bound_artifacts = artifacts.get("bound_artifacts", {})
        snapshot_names = [
            name for name, bound_key in bound_files.items()
            if isinstance(bound_artifacts, dict) and bound_key in bound_artifacts
        ]
        for name in snapshot_names:
            source = feature_dir / name
            if source.is_file():
                shutil.copy2(source, snapshot_dir / name)
        for name in snapshot_names:
            bound_key = bound_files[name]
            snapshot_file = snapshot_dir / name
            bound_digest = bound_artifacts.get(bound_key) if isinstance(bound_artifacts, dict) else None
            expected_present = isinstance(bound_digest, str)
            if (
                name == "prototype.html" and isinstance(bound_artifacts, dict)
                and isinstance(bound_digest, str) and isinstance(bound_artifacts.get("prd"), str)
            ):
                expected_present = bound_digest != prototype_decision_digest(str(bound_artifacts.get("prd")))
            if snapshot_file.is_file() != expected_present:
                raise ValueError("quality review input presence changed while creating the immutable snapshot")
            if expected_present and bound_digest != file_digest(snapshot_file):
                raise ValueError("quality review inputs changed while creating the immutable snapshot")
        (snapshot_dir / "state.json").write_text(
            json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
        (snapshot_dir / "review-request.json").write_text(
            json.dumps({"review_type": review_type, "coverage": coverage, "artifacts": artifacts}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        for snapshot_file in snapshot_dir.iterdir():
            snapshot_file.chmod(0o444)
        prompt = (
            "You are an independent read-only feature quality reviewer. Use fresh context. "
            f"The immutable delivery-input snapshot is {snapshot_dir.relative_to(root).as_posix()}. "
            "Read all bound delivery artifacts and state-derived review inputs only from that snapshot; "
            "the live delivery directory is not review input. Repository source evidence may be inspected read-only, "
            "but it cannot redefine the snapshotted delivery inputs. Never trust a prior verdict. "
            f"Review type: {review_type}. Feature: {feature_id}. Required checks: {json.dumps(sorted(REQUIRED_CHECKS[review_type]))}. "
            f"Kernel-derived coverage IDs: {json.dumps(coverage, ensure_ascii=False)}. "
            f"Bound artifact hashes: {json.dumps(artifacts, ensure_ascii=False)}. "
            "For every required check return one entry with concrete snapshot file/ID evidence. "
            "For coverage checks, covered_ids must enumerate only IDs actually traced and coverage_pct must reflect the complete set. "
            "Use N/A only when genuinely inapplicable and explain why. PASS is forbidden for a failed required check, "
            "open critical/major finding, incomplete coverage, or unmapped change. Return only the schema JSON."
        )
        schema_path = temp_dir / "schema.json"
        result_path = temp_dir / "result.json"
        schema_path.write_text(json.dumps(review_output_schema(review_type)), encoding="utf-8")
        try:
            completed = subprocess.run(
                [
                    "codex", "exec", "--ephemeral", "--json", "--sandbox", "read-only",
                    "--cd", str(root), "--output-schema", str(schema_path),
                    "--output-last-message", str(result_path), "-",
                ],
                input=prompt,
                capture_output=True,
                text=True,
                timeout=900,
            )
        except subprocess.TimeoutExpired as exc:
            raise ValueError("isolated Codex review timed out after 900 seconds") from exc
        if completed.returncode != 0 or not result_path.is_file():
            detail = (completed.stdout + completed.stderr).strip()
            raise ValueError(f"isolated Codex review failed: {detail}")
        transcript_path = review_dir / f"{run_id}.{invocation_id}.transcript.jsonl"
        if transcript_path.exists():
            raise ValueError(f"quality review transcript already exists: {transcript_path}")
        atomic_write_text(transcript_path, completed.stdout + completed.stderr)
        execution = {
            "mode": "isolated_process",
            "provider": "codex-exec",
            "invocation_id": invocation_id,
            "transcript_path": transcript_path.relative_to(root).as_posix(),
            "transcript_sha256": file_digest(transcript_path),
        }
        try:
            return _record_review(
                feature_id, root, review_type, run_id, result_path,
                execution=execution, reviewed_artifacts=artifacts,
            )
        except BaseException:
            transcript_path.unlink(missing_ok=True)
            raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("review_type", choices=REVIEW_TYPES)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        output = run_isolated_review(args.feature_id, Path(args.root), args.review_type, args.run_id)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
