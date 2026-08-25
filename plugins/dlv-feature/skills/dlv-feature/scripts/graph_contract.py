#!/usr/bin/env python3
"""Seal and validate a schema-v10 generated Proof Contract."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any

from delivery_graph import (
    SCHEMA_VERSION,
    atomic_write_json,
    confined_project_path,
    feature_dir,
    generate_proof_contract,
    load_graph,
    load_state,
    review_units,
    semantic_issues,
    timestamp,
)
from delivery_proof import exclusive_file_lock, file_digest, load_json, value_digest


def seal_payload(contract: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in contract.items() if key != "seal"}


def validate_contract(root: Path, feature_id: str, contract: dict[str, Any], state: dict[str, Any], errors: list[str]) -> None:
    root = root.expanduser().resolve()
    graph = load_graph(root, feature_id)
    expected = generate_proof_contract(graph)
    expected_keys = {
        "schema_version", "feature_id", "graph_sha256", "subgraph_sha256",
        "environments", "obligations", "draft_sha256", "status", "attestations",
        "sealed_at", "seal",
    }
    if set(contract) != expected_keys:
        errors.append("Proof Contract contains unknown or missing fields")
    if contract.get("schema_version") != SCHEMA_VERSION or contract.get("feature_id") != feature_id:
        errors.append("Proof Contract identity/schema is invalid")
    if contract.get("draft_sha256") != expected["draft_sha256"]:
        errors.append("Proof Contract draft is stale for the current implementation/proof subgraph")
    if contract.get("environments") != expected["environments"] or contract.get("obligations") != expected["obligations"]:
        errors.append("Proof Contract disagrees with the deterministic graph compiler")
    if contract.get("status") != "sealed":
        errors.append("Proof Contract is not sealed")
    if not isinstance(contract.get("sealed_at"), str):
        errors.append("sealed Proof Contract requires sealed_at")
    if contract.get("seal") != value_digest(seal_payload(contract)):
        errors.append("Proof Contract seal is invalid")
    expected_attestations = set(review_units(graph))
    summaries = contract.get("attestations")
    state_attestations = state.get("attestations")
    if not isinstance(state_attestations, dict):
        errors.append("state attestations must be an object")
        state_attestations = {}
    if not isinstance(summaries, dict) or set(summaries) != expected_attestations:
        errors.append("Proof Contract must bind every applicable stage attestation")
    else:
        units = review_units(graph)
        for unit_id, summary in summaries.items():
            if not isinstance(summary, dict) or set(summary) != {
                "review_run_id", "record_path", "record_sha256", "subgraph_sha256", "verdict",
            }:
                errors.append(f"Proof Contract attestation summary is invalid: {unit_id}")
                continue
            if summary.get("verdict") != "PASS" or summary.get("subgraph_sha256") != units[unit_id]["subgraph_sha256"]:
                errors.append(f"Proof Contract attestation is stale or non-PASS: {unit_id}")
            if state_attestations.get(unit_id) != summary:
                errors.append(f"Proof Contract attestation disagrees with state reference: {unit_id}")
            record_relative = summary.get("record_path")
            if not isinstance(record_relative, str):
                errors.append(f"Proof Contract attestation record path is invalid: {unit_id}")
                continue
            try:
                record_path = confined_project_path(root, record_relative, f"attestation record {unit_id}")
                review_dir = confined_project_path(root, Path(".dlv") / "reviews" / feature_id, "review directory")
            except ValueError:
                errors.append(f"Proof Contract attestation record escapes review directory: {unit_id}")
                continue
            try:
                record_path.relative_to(review_dir)
            except ValueError:
                errors.append(f"Proof Contract attestation record escapes review directory: {unit_id}")
                continue
            if not record_path.is_file() or file_digest(record_path) != summary.get("record_sha256"):
                errors.append(f"Proof Contract attestation record is missing or stale: {unit_id}")
                continue
            record = load_json(record_path)
            execution = record.get("execution")
            if (
                record.get("feature_id") != feature_id
                or record.get("unit_id") != unit_id
                or record.get("lens") != units[unit_id]["lens"]
                or record.get("review_run_id") != summary.get("review_run_id")
                or record.get("subgraph_sha256") != summary.get("subgraph_sha256")
                or record.get("verdict") != summary.get("verdict")
            ):
                errors.append(f"Proof Contract attestation record identity is invalid: {unit_id}")
                continue
            if (
                not isinstance(execution, dict)
                or set(execution) != {
                    "mode", "provider", "invocation_id", "transcript_path",
                    "transcript_sha256", "result_sha256", "independent",
                }
                or execution.get("mode") != "isolated_process"
                or execution.get("provider") != "codex-exec"
                or execution.get("independent") is not True
                or not isinstance(execution.get("invocation_id"), str)
                or re.fullmatch(r"lens-[0-9a-f]{32}", execution["invocation_id"]) is None
                or execution.get("result_sha256") != value_digest({
                    "verdict": record.get("semantic_verdict"),
                    "checks": record.get("semantic_checks"),
                    "findings": record.get("semantic_findings"),
                })
            ):
                errors.append(f"Proof Contract requires an independent semantic attestation: {unit_id}")
                continue
            transcript_relative = execution.get("transcript_path")
            if not isinstance(transcript_relative, str):
                errors.append(f"Proof Contract semantic transcript path is invalid: {unit_id}")
                continue
            try:
                transcript = confined_project_path(root, transcript_relative, f"attestation transcript {unit_id}")
            except ValueError:
                errors.append(f"Proof Contract semantic transcript escapes review directory: {unit_id}")
                continue
            try:
                transcript.relative_to(review_dir)
            except ValueError:
                errors.append(f"Proof Contract semantic transcript escapes review directory: {unit_id}")
                continue
            if not transcript.is_file() or file_digest(transcript) != execution.get("transcript_sha256"):
                errors.append(f"Proof Contract semantic transcript is missing or stale: {unit_id}")


def seal_contract(root: Path, feature_id: str) -> str:
    root = root.expanduser().resolve()
    directory = feature_dir(root, feature_id)
    state_path = directory / "state.json"
    contract_path = directory / "proof-contract.json"
    lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    with exclusive_file_lock(lock):
        graph = load_graph(root, feature_id)
        state = load_state(state_path)
        if state.get("readiness", {}).get("status") != "ready":
            raise ValueError("Proof Contract requires Delivery Readiness")
        from graph_validation import validate_attestations

        attestation_errors: list[str] = []
        validate_attestations(root, feature_id, graph, state, attestation_errors)
        if attestation_errors:
            raise ValueError("Proof Contract attestation preconditions failed: " + "; ".join(attestation_errors))
        issues = semantic_issues(graph)
        if issues:
            raise ValueError("Proof Contract cannot seal with semantic issues: " + "; ".join(issue["statement"] for issue in issues))
        current = load_json(contract_path)
        expected = generate_proof_contract(graph)
        if current.get("status") == "sealed":
            errors: list[str] = []
            validate_contract(root, feature_id, current, state, errors)
            if errors:
                raise ValueError("sealed Proof Contract is stale; change the graph and recompile instead of resealing")
            expected_reference = {
                "status": "sealed",
                "draft_sha256": current["draft_sha256"],
                "sha256": value_digest(current),
                "seal": current["seal"],
            }
            if state.get("proof_contract") != expected_reference:
                state["proof_contract"] = expected_reference
                state["last_compiled_at"] = timestamp()
                atomic_write_json(state_path, state)
            return str(current["seal"])
        if current.get("draft_sha256") != expected["draft_sha256"]:
            raise ValueError("compile the current Delivery Graph before sealing")
        contract = copy.deepcopy(expected)
        contract["status"] = "sealed"
        contract["attestations"] = {
            unit_id: state["attestations"][unit_id]
            for unit_id in review_units(graph)
        }
        contract["sealed_at"] = timestamp()
        contract["seal"] = value_digest(seal_payload(contract))
        seal_errors: list[str] = []
        validate_contract(root, feature_id, contract, state, seal_errors)
        if seal_errors:
            raise ValueError("Proof Contract seal preconditions failed: " + "; ".join(seal_errors))
        atomic_write_json(contract_path, contract)
        state["proof_contract"] = {
            "status": "sealed",
            "draft_sha256": contract["draft_sha256"],
            "sha256": value_digest(contract),
            "seal": contract["seal"],
        }
        state["last_compiled_at"] = timestamp()
        atomic_write_json(state_path, state)
        return str(contract["seal"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    try:
        print(seal_contract(Path(args.root), args.feature_id))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
