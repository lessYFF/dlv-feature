#!/usr/bin/env python3
"""Validate a schema-v8 Verification Run and append-only Evidence Bundle."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from delivery_proof import (
    MISSING,
    extract_state,
    evaluate_oracle,
    file_digest,
    load_json,
    load_manifest,
    proof_contract_digest,
    repository_fingerprint,
    resolve_source,
    run_dir,
    value_digest,
)
from verification_run import (
    MAX_ANCHOR_BYTES,
    active_records,
    computed_visual_metrics,
    contract_maps,
    is_supported_image,
    load_runtime_trace,
    run_digest,
)

EVIDENCE_ID = re.compile(r"^EVID-[0-9]{4,}$")
STATUSES = {"passed", "failed", "blocked"}


def validate_risks(state: dict[str, Any], errors: list[str]) -> None:
    risks = state.get("risks")
    if not isinstance(risks, list):
        errors.append("risks must be an array")
        return
    seen: set[str] = set()
    for index, item in enumerate(risks):
        prefix = f"risks[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        risk_id = item.get("id")
        if not isinstance(risk_id, str) or not re.fullmatch(r"RISK-[0-9]+", risk_id):
            errors.append(f"{prefix}.id must use RISK-nn")
        elif risk_id in seen:
            errors.append(f"duplicate risk: {risk_id}")
        else:
            seen.add(risk_id)
        if item.get("type") not in {"blocker", "residual"}:
            errors.append(f"{prefix}.type must be blocker or residual")
        if item.get("severity") not in {"critical", "high", "medium", "low"}:
            errors.append(f"{prefix}.severity is invalid")
        if item.get("status") not in {"open", "mitigated", "accepted", "closed"}:
            errors.append(f"{prefix}.status is invalid")
        for field in ("statement", "owner"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                errors.append(f"{prefix}.{field} must be concrete")
        if item.get("type") == "blocker":
            if item.get("status") not in {"open", "mitigated", "closed"}:
                errors.append(f"blocker risk cannot be accepted: {risk_id}")
            if item.get("status") == "open":
                errors.append(f"open blocker prevents PASS: {risk_id}")
        if item.get("type") == "residual" and item.get("status") == "accepted" and not item.get("accepted_by"):
            errors.append(f"accepted residual risk requires accepted_by: {risk_id}")


def validate_verification_run(
    root: Path,
    feature_id: str,
    state: dict[str, Any],
    errors: list[str],
) -> tuple[str, str | None]:
    verification = state.get("stages", {}).get("verification", {})
    run_id = verification.get("active_run_id")
    if not isinstance(run_id, str) or not run_id:
        errors.append("verification requires active_run_id")
        return "BLOCKED", None
    destination = run_dir(root, feature_id, run_id)
    metadata_path = destination / "run.json"
    manifest_path = destination / "evidence.jsonl"
    if not metadata_path.is_file() or not manifest_path.is_file():
        errors.append(f"verification run is incomplete: {destination}")
        return "BLOCKED", None
    metadata = load_json(metadata_path)
    records = load_manifest(manifest_path)
    contract = state.get("proof_contract", {})
    contract_artifact = root / "delivery" / feature_id / "proof-contract.json"
    if not contract_artifact.is_file() or load_json(contract_artifact) != contract:
        errors.append("sealed proof-contract.json is missing or disagrees with state")
    obligations, environments = contract_maps(contract if isinstance(contract, dict) else {})
    contract_digest = proof_contract_digest(contract)
    if metadata.get("schema_version") != 8 or metadata.get("feature_id") != feature_id or metadata.get("run_id") != run_id:
        errors.append("run.json identity does not match state")
    if metadata.get("contract_digest") != contract_digest:
        errors.append("verification run has a stale Proof Contract")
    if metadata.get("preflight_verdict") != "PASS":
        errors.append("verification run environment preflight is BLOCKED")
    preflight = metadata.get("preflight")
    expected_preflight = {
        (environment_id, check.get("id")): check
        for environment_id, environment in environments.items()
        for check in environment.get("spec", {}).get("preflight", [])
        if isinstance(check, dict)
    }
    if not isinstance(preflight, list) or not preflight:
        errors.append("verification run has no machine-executed preflight evidence")
    else:
        seen_preflight: set[tuple[Any, Any]] = set()
        for item in preflight:
            if not isinstance(item, dict):
                errors.append("verification run has malformed preflight evidence")
                continue
            identity = (item.get("environment_id"), item.get("check_id"))
            check = expected_preflight.get(identity)
            if check is None or identity in seen_preflight:
                errors.append(f"preflight identity is unknown or duplicated: {identity}")
                continue
            seen_preflight.add(identity)
            if item.get("status") != "passed":
                errors.append(f"preflight check is not passed: {identity}")
            anchor = (destination / str(item.get("anchor"))).resolve()
            try:
                anchor.relative_to(destination.resolve())
            except ValueError:
                errors.append("preflight anchor escapes the run directory")
                continue
            if not anchor.is_file() or item.get("sha256") != file_digest(anchor):
                errors.append(f"preflight anchor is missing or stale: {item.get('anchor')}")
                continue
            anchor_value = load_json(anchor)
            if (
                anchor_value.get("environment_id") != identity[0]
                or anchor_value.get("check_id") != identity[1]
                or anchor_value.get("argv") != check.get("argv")
                or anchor_value.get("exit_code") != 0
                or anchor_value.get("status") != "passed"
            ):
                errors.append(f"preflight anchor disagrees with its contracted check: {identity}")
        if seen_preflight != set(expected_preflight):
            errors.append("preflight evidence does not exactly cover contracted checks")
    current_code = repository_fingerprint(root, feature_id)
    if metadata.get("code_fingerprint") != current_code:
        errors.append("verification run has stale code")
    snapshots = metadata.get("environments")
    if not isinstance(snapshots, dict) or set(snapshots) != set(environments):
        errors.append("run environment snapshots do not exactly cover contracted environments")
        snapshots = {}
    for environment_id, environment in environments.items():
        snapshot = snapshots.get(environment_id)
        if not isinstance(snapshot, dict):
            continue
        if snapshot.get("spec") != environment.get("spec"):
            errors.append(f"run environment {environment_id} is stale")
        if snapshot.get("digest") != value_digest(environment.get("spec")):
            errors.append(f"run environment {environment_id} digest is invalid")

    seen: set[str] = set()
    superseded: set[str] = set()
    previous_hash = "0" * 64
    for index, record in enumerate(records):
        prefix = f"evidence[{index}]"
        evidence_id = record.get("evidence_id")
        if not isinstance(evidence_id, str) or not EVIDENCE_ID.fullmatch(evidence_id):
            errors.append(f"{prefix}.evidence_id is invalid")
            continue
        if evidence_id in seen:
            errors.append(f"duplicate evidence: {evidence_id}")
        seen.add(evidence_id)
        if record.get("schema_version") != 8:
            errors.append(f"{evidence_id} schema_version must be 8")
        recorded_hash = record.get("record_hash")
        payload = {key: value for key, value in record.items() if key != "record_hash"}
        if record.get("previous_hash") != previous_hash or recorded_hash != value_digest(payload):
            errors.append(f"{evidence_id} breaks the append-only evidence hash chain")
        if isinstance(recorded_hash, str):
            previous_hash = recorded_hash
        po_id = record.get("po_id")
        obligation = obligations.get(po_id)
        if obligation is None:
            errors.append(f"{evidence_id} cites unknown proof obligation: {po_id}")
            continue
        if record.get("proof_type") != obligation.get("proof_type"):
            errors.append(f"{evidence_id} proof type does not match {po_id}")
        if record.get("status") not in STATUSES:
            errors.append(f"{evidence_id} status is invalid")
        if record.get("contract_digest") != contract_digest:
            errors.append(f"{evidence_id} has stale contract fingerprint")
        if record.get("code_fingerprint") != current_code:
            errors.append(f"{evidence_id} has stale code fingerprint")
        environment_id = obligation.get("environment_id")
        snapshot = snapshots.get(environment_id, {}) if isinstance(snapshots, dict) else {}
        if record.get("environment_id") != environment_id or record.get("environment_digest") != snapshot.get("digest"):
            errors.append(f"{evidence_id} has stale environment fingerprint")
        expected_assertions = {item.get("id") for item in obligation.get("assertions", []) if isinstance(item, dict)}
        assertion_results = record.get("assertion_results")
        if not isinstance(assertion_results, list):
            errors.append(f"{evidence_id}.assertion_results must be an array")
            assertion_results = []
        actual_assertions = {item.get("assertion_id") for item in assertion_results if isinstance(item, dict)}
        if actual_assertions != expected_assertions:
            errors.append(f"{evidence_id} does not exactly cover contracted assertions")
        assertion_contract = {
            item.get("id"): item for item in obligation.get("assertions", []) if isinstance(item, dict)
        }
        for result in assertion_results:
            if not isinstance(result, dict) or result.get("assertion_id") not in assertion_contract:
                continue
            oracle = assertion_contract[result["assertion_id"]].get("oracle", {})
            actual = resolve_source(record, oracle.get("source", ""))
            present = actual is not MISSING
            stored_actual = None if actual is MISSING else actual
            if (
                result.get("present") is not present
                or result.get("actual") != stored_actual
                or type(result.get("actual")) is not type(stored_actual)
            ):
                errors.append(f"{evidence_id} assertion {result.get('assertion_id')} actual disagrees with its contracted source")
            computed = evaluate_oracle(actual, oracle)
            expected_status = "passed" if computed else "failed"
            if record.get("status") in {"passed", "failed"} and result.get("status") != expected_status:
                errors.append(f"{evidence_id} assertion {result.get('assertion_id')} status disagrees with its oracle")
        if record.get("status") == "passed" and any(item.get("status") != "passed" for item in assertion_results):
            errors.append(f"{evidence_id} is passed while an assertion is not passed")
        command = record.get("command")
        if not isinstance(command, dict) or not isinstance(command.get("argv"), list) or not command["argv"]:
            errors.append(f"{evidence_id} has no exact argv")
        else:
            runner = obligation.get("runner", {})
            try:
                expected_cwd = (root / str(runner.get("cwd", "."))).resolve().relative_to(root.resolve()).as_posix() or "."
            except ValueError:
                expected_cwd = "<outside-root>"
            if command.get("argv") != runner.get("argv") or command.get("cwd") != expected_cwd:
                errors.append(f"{evidence_id} command disagrees with the sealed PO runner")
        if not isinstance(record.get("observation"), dict):
            errors.append(f"{evidence_id} observation must be a structured object")
        elif record.get("proof_type") == "runtime":
            contracted_environment = environments.get(environment_id, {})
            expected_runtime = contracted_environment.get("spec", {}).get("runtime")
            if record["observation"].get("runtime") != expected_runtime:
                errors.append(f"{evidence_id} runtime does not match its sealed target environment")
        anchors = record.get("anchors")
        if not isinstance(anchors, list) or not anchors:
            errors.append(f"{evidence_id} has no anchors")
        else:
            generated_payloads: dict[str, Any] = {}
            anchor_roles: set[str] = set()
            role_counts: dict[str, int] = {}
            role_paths: dict[str, Path] = {}
            for anchor in anchors:
                if not isinstance(anchor, dict) or not isinstance(anchor.get("path"), str):
                    errors.append(f"{evidence_id} has an invalid anchor")
                    continue
                if isinstance(anchor.get("role"), str):
                    anchor_roles.add(anchor["role"])
                    role_counts[anchor["role"]] = role_counts.get(anchor["role"], 0) + 1
                path = (destination / anchor["path"]).resolve()
                try:
                    path.relative_to(destination.resolve())
                except ValueError:
                    errors.append(f"{evidence_id} anchor escapes the run directory")
                    continue
                if not path.is_file():
                    errors.append(f"{evidence_id} anchor is missing: {anchor['path']}")
                elif path.stat().st_size > MAX_ANCHOR_BYTES:
                    errors.append(f"{evidence_id} anchor exceeds the size limit: {anchor['path']}")
                elif anchor.get("sha256") != file_digest(path):
                    errors.append(f"{evidence_id} anchor hash mismatch: {anchor['path']}")
                elif isinstance(anchor.get("role"), str):
                    role_paths[anchor["role"]] = path
                elif anchor["path"].endswith("-command.json"):
                    generated_payloads["command"] = load_json(path)
                elif anchor["path"].endswith("-observation.json"):
                    generated_payloads["observation"] = load_json(path)
            for generated_name in ("command", "observation"):
                if generated_payloads.get(generated_name) != record.get(generated_name):
                    errors.append(f"{evidence_id} generated {generated_name} anchor disagrees with the manifest")
            if record.get("proof_type") == "visual":
                visual_roles = {"prototype_screenshot", "implementation_screenshot", "visual_diff"}
                if not visual_roles <= anchor_roles or any(role_counts.get(role) != 1 for role in visual_roles):
                    errors.append(f"{evidence_id} visual evidence requires exactly one anchor per screenshot/diff role")
                visual_paths = [role_paths.get(role) for role in visual_roles]
                if None not in visual_paths and len(set(visual_paths)) != len(visual_roles):
                    errors.append(f"{evidence_id} visual screenshot/diff roles must use distinct files")
                for role in visual_roles:
                    path = role_paths.get(role)
                    if path is not None and not is_supported_image(path):
                        errors.append(f"{evidence_id} {role} is not a supported image")
                if all(role in role_paths for role in visual_roles):
                    try:
                        computed_pixel, computed_geometry = computed_visual_metrics([
                            (role, role_paths[role]) for role in visual_roles
                        ])
                    except (OSError, ValueError) as exc:
                        errors.append(f"{evidence_id} visual anchors are invalid: {exc}")
                    else:
                        observation = record.get("observation", {})
                        if observation.get("pixel_diff_ratio") != computed_pixel:
                            errors.append(f"{evidence_id} visual pixel metric disagrees with stored screenshots")
                        if observation.get("geometry_diff_max") != computed_geometry:
                            errors.append(f"{evidence_id} visual geometry metric disagrees with stored screenshots")
            if record.get("proof_type") == "runtime":
                if role_counts.get("runtime_trace") != 1:
                    errors.append(f"{evidence_id} runtime evidence requires exactly one runtime_trace role")
                trace_path = role_paths.get("runtime_trace")
                if trace_path is not None:
                    try:
                        trace = load_runtime_trace(trace_path)
                    except ValueError as exc:
                        errors.append(f"{evidence_id} {exc}")
                    else:
                        if trace != record.get("observation"):
                            errors.append(f"{evidence_id} runtime_trace does not match its observation")
        replaced = record.get("supersedes")
        if not isinstance(replaced, list) or not all(isinstance(item, str) for item in replaced):
            errors.append(f"{evidence_id}.supersedes must be an array")
            replaced = []
        if set(replaced) - seen:
            errors.append(f"{evidence_id} supersedes future or unknown evidence")
        if set(replaced) & superseded:
            errors.append(f"{evidence_id} supersedes evidence that was already superseded")
        for old_id in replaced:
            old = next((item for item in records[:index] if item.get("evidence_id") == old_id), None)
            if old and old.get("po_id") != po_id:
                errors.append(f"{evidence_id} supersedes evidence for another obligation")
        superseded |= set(replaced)

    active = active_records(records)
    verification_state = state.get("stages", {}).get("verification", {})
    expected_head = records[-1].get("record_hash") if records else "0" * 64
    if verification_state.get("evidence_count") != len(records) or verification_state.get("evidence_head") != expected_head:
        errors.append("evidence manifest disagrees with the state-anchored append-only head")
    for po_id, obligation in obligations.items():
        current = [record for record in active if record.get("po_id") == po_id]
        if len(current) != 1:
            errors.append(f"{po_id} requires exactly one active evidence record; found {len(current)}")
            continue
        status = current[0].get("status")
        if status == "passed":
            continue
        errors.append(f"{po_id} has no fresh passed evidence")
    validate_risks(state, errors)
    digest = run_digest(destination)
    return ("PASS" if not errors else "BLOCKED"), digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--run-id")
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve()
    errors: list[str] = []
    try:
        state_path = root / "delivery" / args.feature_id / "state.md"
        _, state = extract_state(state_path)
        if args.run_id:
            state.setdefault("stages", {}).setdefault("verification", {})["active_run_id"] = args.run_id
        verdict, digest = validate_verification_run(root, args.feature_id, state, errors)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(str(exc))
        verdict, digest = "BLOCKED", None
    for error in errors:
        print(f"ERROR: {error}")
    print(json.dumps({"verdict": verdict, "run_digest": digest, "errors": len(errors)}, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
