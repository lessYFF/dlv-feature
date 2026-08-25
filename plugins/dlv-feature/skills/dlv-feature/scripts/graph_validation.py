#!/usr/bin/env python3
"""Validate schema-v11 Delivery Graph state, attestations, contract, and evidence."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from delivery_graph import (
    GLOBAL_LENS,
    LENSES,
    SCHEMA_VERSION,
    STAGES,
    confined_project_path,
    feature_dir,
    generate_proof_contract,
    graph_digest,
    load_graph,
    load_state,
    node_hashes,
    prototype_errors,
    readiness,
    review_units,
    semantic_issues,
    render_stage_document,
    stage_hash,
    structural_errors,
)
from delivery_proof import file_digest, load_json, repository_fingerprint, value_digest
from delivery_governance import (
    BLOCKING_FINDING_STATUSES,
    finding_summary,
    ledger_path,
    load_ledger,
    source_revision_status,
)
from graph_contract import validate_contract


ALLOWED_FILES = {
    "delivery-graph.json", "state.json", "prd.md", "architecture-design.md",
    "code-spec.md", "proof-contract.json", "prototype.html", "verification.md",
}


def validate_attestations(root: Path, feature_id: str, graph: dict[str, Any], state: dict[str, Any], errors: list[str]) -> None:
    attestations = state.get("attestations")
    if not isinstance(attestations, dict):
        errors.append("state.attestations must be an object")
        return
    units = review_units(graph)
    unknown = set(attestations) - set(units)
    if unknown:
        errors.append("state references unknown review lenses: " + ", ".join(sorted(unknown)))
    for unit_id, summary in attestations.items():
        if unit_id not in units:
            continue
        unit = units[unit_id]
        lens = unit["lens"]
        if not isinstance(summary, dict):
            errors.append(f"attestation summary must be an object: {lens}")
            continue
        if set(summary) != {"review_run_id", "record_path", "record_sha256", "subgraph_sha256", "verdict"}:
            errors.append(f"attestation summary contains non-reference fields: {lens}")
        if summary.get("subgraph_sha256") != unit["subgraph_sha256"]:
            errors.append(f"attestation subgraph is stale: {unit_id}")
        relative = summary.get("record_path")
        if not isinstance(relative, str):
            errors.append(f"attestation record_path is invalid: {lens}")
            continue
        try:
            path = confined_project_path(root, relative, f"attestation record {lens}")
            expected_parent = confined_project_path(root, Path(".dlv") / "reviews" / feature_id, "review directory")
        except ValueError:
            errors.append(f"attestation record escapes feature review directory: {lens}")
            continue
        try:
            path.relative_to(expected_parent)
        except ValueError:
            errors.append(f"attestation record escapes feature review directory: {lens}")
            continue
        if path.resolve() != path.absolute():
            errors.append(f"attestation record is relocated through a symlink: {lens}")
            continue
        if not path.is_file() or file_digest(path) != summary.get("record_sha256"):
            errors.append(f"attestation record is missing or stale: {lens}")
            continue
        try:
            record = load_json(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"attestation record is invalid JSON object: {lens}: {exc}")
            continue
        expected_record_keys = {
            "schema_version", "feature_id", "review_run_id", "unit_id", "lens", "component_id", "stage", "execution",
            "graph_snapshot_sha256", "subgraph_sha256", "covered_node_ids", "issues",
            "semantic_checks", "semantic_findings", "semantic_verdict", "verdict", "reviewed_at",
        }
        if set(record) != expected_record_keys:
            errors.append(f"attestation record contains unknown or missing fields: {lens}")
        if record.get("schema_version") != SCHEMA_VERSION or record.get("feature_id") != feature_id or record.get("lens") != lens:
            errors.append(f"attestation record identity/schema is invalid: {lens}")
        if record.get("review_run_id") != summary.get("review_run_id") or path.name != f"{summary.get('review_run_id')}.{unit_id}.json":
            errors.append(f"attestation run identity disagrees with record path: {unit_id}")
        expected_stage = "global" if lens == GLOBAL_LENS else LENSES[lens]["stage"]
        if record.get("stage") != expected_stage:
            errors.append(f"attestation stage disagrees with lens: {unit_id}")
        if record.get("unit_id") != unit_id or record.get("component_id") != unit["component_id"]:
            errors.append(f"attestation component identity is invalid: {unit_id}")
        if record.get("covered_node_ids") != unit["node_ids"]:
            errors.append(f"attestation node coverage is incomplete: {unit_id}")
        if record.get("subgraph_sha256") != summary.get("subgraph_sha256") or record.get("verdict") != summary.get("verdict"):
            errors.append(f"attestation summary disagrees with record: {lens}")
        issues = record.get("issues")
        if not isinstance(issues, list):
            errors.append(f"attestation issues must be an array: {lens}")
        elif record.get("verdict") == "PASS" and any(item.get("severity") in {"critical", "major"} for item in issues if isinstance(item, dict)):
            errors.append(f"PASS attestation hides a critical/major issue: {lens}")
        if lens == GLOBAL_LENS:
            covered = set(unit["node_ids"])
            expected_issues = [issue for issue in semantic_issues(graph) if issue["node_id"] in covered]
        else:
            covered = set(unit["node_ids"])
            expected_issues = [issue for issue in semantic_issues(graph, lens) if issue["node_id"] == "GRAPH" or issue["node_id"] in covered]
        if issues != expected_issues:
            errors.append(f"attestation semantic verdict is not reproducible: {lens}")
        semantic_findings = record.get("semantic_findings")
        semantic_checks = record.get("semantic_checks")
        semantic_verdict = record.get("semantic_verdict")
        if not isinstance(semantic_findings, list) or not isinstance(semantic_checks, list):
            errors.append(f"attestation semantic review payload is invalid: {lens}")
            semantic_findings, semantic_checks = [], []
        if any(
            not isinstance(item, dict) or set(item) != {"id", "status", "evidence"}
            or item.get("status") not in {"PASS", "FAIL"}
            or not isinstance(item.get("id"), str) or not isinstance(item.get("evidence"), str)
            for item in semantic_checks
        ):
            errors.append(f"attestation semantic checks are invalid: {lens}")
        if any(
            not isinstance(item, dict)
            or set(item) != {
                "id", "unit_id", "severity", "status", "statement", "evidence", "risk_path",
                "root_cause", "first_seen_at", "last_seen_at", "first_seen_revision", "last_seen_revision",
                "previously_invisible_reason", "waiver", "supersedes",
            }
            or item.get("severity") not in {"critical", "major", "minor"}
            or item.get("status") not in {"OPEN", "FIXED_PENDING_REVIEW", "VERIFIED", "OUT_OF_SCOPE", "ACCEPTED_RISK", "SUPERSEDED"}
            for item in semantic_findings
        ):
            errors.append(f"attestation semantic findings are invalid: {lens}")
        open_major = any(
            item.get("severity") in {"critical", "major"} and item.get("status") in BLOCKING_FINDING_STATUSES
            for item in semantic_findings if isinstance(item, dict)
        )
        failed_check = any(item.get("status") != "PASS" for item in semantic_checks if isinstance(item, dict))
        execution = record.get("execution")
        if not isinstance(execution, dict):
            errors.append(f"attestation execution metadata is invalid: {lens}")
        elif execution.get("mode") == "isolated_process":
            expected_execution_keys = {
                "mode", "provider", "invocation_id", "transcript_path",
                "transcript_sha256", "result_sha256", "independent",
            }
            if (
                set(execution) != expected_execution_keys
                or execution.get("provider") != "codex-exec"
                or execution.get("independent") is not True
                or not isinstance(execution.get("invocation_id"), str)
                or re.fullmatch(r"lens-[0-9a-f]{32}", execution["invocation_id"]) is None
                or execution.get("result_sha256") != value_digest({
                    "verdict": semantic_verdict,
                    "checks": semantic_checks,
                    "findings": semantic_findings,
                })
            ):
                errors.append(f"isolated semantic attestation provenance is invalid: {lens}")
            if not semantic_checks:
                errors.append(f"isolated semantic attestation requires checks: {lens}")
            transcript_relative = execution.get("transcript_path")
            if not isinstance(transcript_relative, str):
                errors.append(f"semantic attestation transcript path is invalid: {lens}")
            else:
                try:
                    transcript = confined_project_path(root, transcript_relative, f"attestation transcript {lens}")
                except ValueError:
                    errors.append(f"semantic attestation transcript escapes review directory: {lens}")
                    continue
                try:
                    transcript.relative_to(expected_parent)
                except ValueError:
                    errors.append(f"semantic attestation transcript escapes review directory: {lens}")
                else:
                    if transcript.resolve() != transcript.absolute() or not transcript.is_file() or file_digest(transcript) != execution.get("transcript_sha256"):
                        errors.append(f"semantic attestation transcript is missing or stale: {lens}")
        elif (
            set(execution) != {"mode", "engine", "independent"}
            or execution.get("mode") != "isolated_deterministic_lens"
            or execution.get("engine") != "dlv-feature/graph-review-v11"
            or execution.get("independent") is not True
        ):
            errors.append(f"deterministic attestation execution metadata is invalid: {lens}")
        expected_verdict = "BLOCKED" if (
            any(item.get("severity") in {"critical", "major"} for item in expected_issues)
            or semantic_verdict != "PASS" or open_major or failed_check
        ) else "PASS"
        if record.get("verdict") != expected_verdict:
            errors.append(f"composite attestation verdict hides a failed lens: {lens}")


def finalization_payload(state: dict[str, Any], report_sha256: str | None) -> dict[str, Any]:
    verification = state.get("verification", {})
    finalization = verification.get("finalization") if isinstance(verification, dict) else None
    return {
        "schema_version": state.get("schema_version"),
        "feature_id": state.get("feature_id"),
        "graph_sha256": state.get("graph_sha256"),
        "stage_hashes": state.get("stage_hashes"),
        "attestations_sha256": value_digest(state.get("attestations", {})),
        "proof_contract": state.get("proof_contract"),
        "code": state.get("code"),
        "run_id": verification.get("active_run_id"),
        "run_digest": verification.get("run_digest"),
        "verdict": verification.get("verdict"),
        "report_sha256": report_sha256,
        "finalized_at": finalization.get("finalized_at") if isinstance(finalization, dict) else None,
        "tool": finalization.get("tool") if isinstance(finalization, dict) else None,
    }


def finalization_token(state: dict[str, Any], report_sha256: str | None) -> str:
    return value_digest(finalization_payload(state, report_sha256))


def validate(root: Path, feature_id: str, *, final: bool = False) -> list[str]:
    root = root.expanduser().resolve()
    errors: list[str] = []
    directory = feature_dir(root, feature_id)
    try:
        graph = load_graph(root, feature_id)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [str(exc)]
    errors.extend(structural_errors(graph, feature_id))
    if errors:
        return errors
    errors.extend(prototype_errors(root, feature_id, graph))
    state_path = directory / "state.json"
    if not state_path.is_file():
        return errors + ["missing generated state.json; compile the Delivery Graph"]
    try:
        state = load_state(state_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return errors + [f"state.json is not a valid object: {exc}"]
    expected_state_keys = {
        "schema_version", "feature_id", "graph_sha256", "node_hashes", "stage_hashes",
        "readiness", "attestations", "source_revision", "risk", "finding_ledger", "convergence",
        "execution", "proof_contract", "code", "verification", "last_compiled_at",
    }
    if set(state) != expected_state_keys:
        errors.append("state.json must contain only canonical hash/status/reference fields")
    if state.get("schema_version") != SCHEMA_VERSION or state.get("feature_id") != feature_id:
        errors.append("state identity/schema is invalid")
    if state.get("graph_sha256") != graph_digest(graph):
        errors.append("state graph hash is stale; compile the Delivery Graph")
    if state.get("stage_hashes") != {stage: stage_hash(graph, stage) for stage in STAGES}:
        errors.append("state stage hashes are stale")
    if state.get("node_hashes") != node_hashes(graph):
        errors.append("state node hashes are stale")
    generated_views = {
        "prd.md": render_stage_document(graph, "product"),
        "architecture-design.md": render_stage_document(graph, "architecture"),
        "code-spec.md": render_stage_document(graph, "implementation_proof"),
    }
    for name, expected_content in generated_views.items():
        path = directory / name
        if not path.is_file() or path.read_text(encoding="utf-8") != expected_content:
            errors.append(f"generated artifact is missing or stale: {name}")
    try:
        source_status = source_revision_status(directory, feature_id, graph["source_revision"])
        ledger = load_ledger(root, feature_id)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"governance records are invalid: {exc}")
        source_status, ledger = {"status": "drift"}, {"entries": {}, "campaigns": []}
    source_reference = state.get("source_revision")
    if source_reference != source_status:
        errors.append("state Source Revision reference is stale")
    risk = state.get("risk")
    if not isinstance(risk, dict) or set(risk) != {"source", "design", "observed", "effective", "profiles"}:
        errors.append("state risk assessment is invalid")
    ledger_reference = state.get("finding_ledger")
    if not isinstance(ledger_reference, dict) or set(ledger_reference) != {"record_path", "sha256", "summary"}:
        errors.append("state finding ledger reference is invalid")
    elif ledger_reference.get("record_path") != f".dlv/findings/{feature_id}/ledger.json" or (
        ledger_path(root, feature_id).is_file() and ledger_reference.get("sha256") != file_digest(ledger_path(root, feature_id))
    ) or ledger_reference.get("summary") != finding_summary(ledger):
        errors.append("state finding ledger reference is stale")
    convergence = state.get("convergence")
    if not isinstance(convergence, dict) or set(convergence) != {"status", "ready_distance", "reason"}:
        errors.append("state convergence is invalid")
    execution = state.get("execution")
    if not isinstance(execution, dict) or set(execution) != {"status", "checkpoint", "reason"}:
        errors.append("state execution checkpoint is invalid")
    validate_attestations(root, feature_id, graph, state, errors)
    if state.get("readiness") != readiness(graph, state.get("attestations", {}), source_status=source_status, ledger=ledger):
        errors.append("state readiness disagrees with current review units/governance")
    contract_path = directory / "proof-contract.json"
    if not contract_path.is_file():
        errors.append("missing generated proof-contract.json")
        contract = {}
    else:
        try:
            contract = load_json(contract_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"proof-contract.json is not a valid object: {exc}")
            contract = {}
        reference = state.get("proof_contract", {})
        if not isinstance(reference, dict) or set(reference) != {"status", "draft_sha256", "sha256", "seal"}:
            errors.append("state Proof Contract must contain references only")
            reference = reference if isinstance(reference, dict) else {}
        if (
            reference.get("sha256") != value_digest(contract)
            or reference.get("status") != contract.get("status")
            or reference.get("draft_sha256") != contract.get("draft_sha256")
            or reference.get("seal") != contract.get("seal")
        ):
            errors.append("state Proof Contract reference is stale")
        if contract.get("status") == "sealed":
            validate_contract(root, feature_id, contract, state, errors)
        elif contract.get("status") == "draft":
            expected_contract = generate_proof_contract(graph)
            expected_contract["attestations"] = dict(state.get("attestations", {}))
            if contract != expected_contract:
                errors.append("generated Proof Contract draft is stale")
        elif final or state.get("code", {}).get("status") == "completed":
            errors.append("Code/final validation requires a sealed Proof Contract")
        else:
            errors.append("Proof Contract status must be draft or sealed")
    code = state.get("code")
    if not isinstance(code, dict):
        errors.append("state.code must be an object")
    elif set(code) != {"status", "repository_fingerprint"} or code.get("status") not in {"pending", "stale", "needs_reconcile", "completed"}:
        errors.append("state.code shape/status is invalid")
    elif code.get("status") == "completed":
        try:
            current = repository_fingerprint(root, feature_id)
        except ValueError as exc:
            errors.append(str(exc))
        else:
            if code.get("repository_fingerprint") != current:
                errors.append("Code repository fingerprint is stale")
    verification = state.get("verification")
    verification_shape_valid = True
    if not isinstance(verification, dict):
        errors.append("state.verification must be an object")
        verification_shape_valid = False
    elif set(verification) - {
        "status", "active_run_id", "run_digest", "verdict", "evidence_count",
        "evidence_head", "finalization",
    } or verification.get("status") not in {"pending", "blocked", "in_progress", "completed"}:
        errors.append("state.verification shape/status is invalid")
        verification_shape_valid = False
    else:
        active_run_id = verification.get("active_run_id")
        run_digest = verification.get("run_digest")
        verdict = verification.get("verdict")
        evidence_count = verification.get("evidence_count")
        evidence_head = verification.get("evidence_head")
        status = verification.get("status")
        if active_run_id is not None and (
            not isinstance(active_run_id, str) or not re.fullmatch(r"[a-z0-9._-]+", active_run_id)
        ):
            errors.append("state.verification.active_run_id must be null or a safe string")
            verification_shape_valid = False
        if run_digest is not None and (not isinstance(run_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", run_digest)):
            errors.append("state.verification.run_digest must be null or a SHA-256 digest")
            verification_shape_valid = False
        if verdict not in {None, "PASS", "BLOCKED"}:
            errors.append("state.verification.verdict must be null, PASS, or BLOCKED")
            verification_shape_valid = False
        if "evidence_count" in verification and (type(evidence_count) is not int or evidence_count < 0):
            errors.append("state.verification.evidence_count must be a non-negative integer")
            verification_shape_valid = False
        if "evidence_head" in verification and (
            not isinstance(evidence_head, str) or not re.fullmatch(r"[0-9a-f]{64}", evidence_head)
        ):
            errors.append("state.verification.evidence_head must be a SHA-256 digest")
            verification_shape_valid = False
        if status == "pending":
            if active_run_id is not None or run_digest is not None or verdict is not None or verification.get("finalization") is not None:
                errors.append("pending Verification cannot reference a run, verdict, digest, or finalization")
                verification_shape_valid = False
            if evidence_count not in {None, 0} or evidence_head not in {None, "0" * 64}:
                errors.append("pending Verification cannot contain evidence")
                verification_shape_valid = False
        elif status in {"blocked", "in_progress"}:
            if active_run_id is None or run_digest is not None or verdict is not None or verification.get("finalization") is not None:
                errors.append(f"{status} Verification state has inconsistent run/finalization fields")
                verification_shape_valid = False
            if "evidence_count" not in verification or "evidence_head" not in verification:
                errors.append(f"{status} Verification state requires evidence count and head")
                verification_shape_valid = False
        elif status == "completed":
            if active_run_id is None or run_digest is None or verdict != "PASS" or not isinstance(verification.get("finalization"), dict):
                errors.append("completed Verification state requires an active run, PASS digest, and finalization")
                verification_shape_valid = False
            if "evidence_count" not in verification or "evidence_head" not in verification:
                errors.append("completed Verification state requires evidence count and head")
                verification_shape_valid = False
    if verification_shape_valid and verification.get("active_run_id") is not None:
        from graph_verification import render_content, validate_run

        run_errors: list[str] = []
        try:
            verdict, digest = validate_run(root, feature_id, verification["active_run_id"], run_errors)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            verdict, digest = "BLOCKED", None
            run_errors.append(str(exc))
        errors.extend(run_errors)
        if verification.get("run_digest") is not None and verification.get("run_digest") != digest:
            errors.append("Verification Run digest is stale")
        if verification.get("verdict") == "PASS" and verdict != "PASS":
            errors.append("Verification PASS disagrees with active evidence")
        report_path = directory / "verification.md"
        try:
            expected_report = render_content(feature_id, root, verification["active_run_id"])
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"cannot regenerate Verification view: {exc}")
        else:
            if not report_path.is_file() or report_path.read_text(encoding="utf-8") != expected_report:
                errors.append("generated Verification report is missing or stale")
    elif (directory / "verification.md").exists() or (directory / "verification.md").is_symlink():
        errors.append("verification.md exists without an active schema-v11 run")
    if final:
        if state.get("readiness", {}).get("status") != "ready":
            errors.append("final validation requires Delivery Readiness")
        if state.get("code", {}).get("status") != "completed":
            errors.append("final validation requires completed Code")
        if state.get("verification", {}).get("status") != "completed" or state.get("verification", {}).get("verdict") != "PASS":
            errors.append("final validation requires completed PASS Verification")
        report = directory / "verification.md"
        report_sha = file_digest(report) if report.is_file() else None
        if report_sha is None:
            errors.append("final validation requires generated verification.md")
        record = state.get("verification", {}).get("finalization")
        if not isinstance(record, dict) or record.get("tool") != "finalize_delivery.py" or not isinstance(record.get("finalized_at"), str):
            errors.append("finalization record is invalid")
        elif record.get("token") != finalization_token(state, report_sha):
            errors.append("finalization token is stale")
    if directory.is_dir():
        for entry in directory.iterdir():
            if entry.is_dir() and entry.name != "source-revisions":
                errors.append(f"unexpected directory in feature artifact set: {entry.name}/")
            elif entry.is_dir() and entry.name == "source-revisions":
                if any(not item.is_file() or item.suffix != ".json" for item in entry.iterdir()):
                    errors.append("source-revisions contains an invalid artifact")
            elif entry.name not in ALLOWED_FILES:
                errors.append(f"unexpected feature artifact: {entry.name}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--final", action="store_true")
    args = parser.parse_args(argv)
    try:
        errors = validate(Path(args.root), args.feature_id, final=args.final)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors = [str(exc)]
    for error in errors:
        print(f"ERROR: {error}")
    if errors:
        print(f"INVALID: {len(errors)} error(s)")
        return 1
    print("DELIVERY COMPLETE: 0 errors" if args.final else "VALID INTERMEDIATE: 0 errors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
