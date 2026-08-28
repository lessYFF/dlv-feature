#!/usr/bin/env python3
"""Target-runtime Verification Runs for schema-v12 Delivery Graph features."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from delivery_graph import (
    SCHEMA_VERSION,
    SAFE_RUN_ID,
    SHA256,
    MAX_COMMAND_TIMEOUT_SECONDS,
    atomic_write_json,
    confined_project_path,
    feature_dir,
    load_graph,
    load_state,
    timestamp,
)
from delivery_proof import (
    MISSING,
    append_jsonl,
    atomic_write_text,
    evaluate_oracle,
    exclusive_file_lock,
    file_digest,
    load_json,
    load_manifest,
    repository_fingerprint,
    resolve_source,
    value_digest,
)
from graph_contract import validate_contract
from runtime_evidence import (
    DEFAULT_TIMEOUT_SECONDS,
    computed_visual_metrics,
    copy_bounded_anchor,
    is_supported_image,
    load_runtime_trace,
    run_bounded,
)
from delivery_contracts import is_boolean_only_observation
from repository_adapter import load_adapter
from target_attestation import attestation_key_digest, validate_attestation_config, verify_target_attestation


ZERO_HASH = "0" * 64
SAFE_CHECK_ID = SAFE_RUN_ID
EVIDENCE_RECORD_KEYS = {
    "schema_version", "evidence_id", "recorded_at", "po_id", "proof_type",
    "claim_ids", "challenge_nonce", "target_identity", "adapter_sha256", "fixture_sha256", "attestation_key_sha256",
    "status", "contract_digest", "code_fingerprint", "commit_identity", "environment_id",
    "environment_digest", "command", "assertion_results", "observation",
    "anchors", "blocked_reason", "supersedes", "previous_hash", "record_hash",
}


HIGH_STRENGTH_PROOFS = {"runtime", "invariant", "visual"}


def formal_head_identity(root: Path, feature_id: str) -> str:
    pathspec = [".", ":(exclude)delivery/**", ":(exclude).dlv/**"]
    for staged in (False, True):
        command = ["git", "diff", "--quiet"]
        if staged:
            command.append("--cached")
        command.extend(["HEAD", "--", *pathspec])
        if subprocess.run(command, cwd=root, check=False).returncode != 0:
            raise ValueError("high-strength Proof requires committed Code with no source drift")
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=root, capture_output=True, check=False,
    )
    if untracked.returncode != 0:
        raise ValueError("high-strength Proof cannot establish the Git commit identity")
    paths = [
        value.decode("utf-8", errors="surrogateescape")
        for value in untracked.stdout.split(b"\0") if value
    ]
    if any(not path.startswith(("delivery/", ".dlv/")) for path in paths):
        raise ValueError("high-strength Proof requires committed Code with no untracked source")
    completed = subprocess.run(
        ["git", "show", "-s", "--format=%H%x00%B", "HEAD"],
        cwd=root, capture_output=True, check=False,
    )
    if completed.returncode != 0:
        raise ValueError("high-strength Proof cannot establish the Git commit identity")
    commit, separator, body = completed.stdout.partition(b"\0")
    try:
        identity = commit.decode("ascii").strip()
        message = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("high-strength Proof Git identity is invalid") from exc
    if not separator or not re.fullmatch(r"[0-9a-f]{40,64}", identity):
        raise ValueError("high-strength Proof Git identity is invalid")
    if not re.search(rf"(?mi)^DLV-Feature:\s*{re.escape(feature_id)}\s*$", message):
        raise ValueError("high-strength Proof requires the HEAD commit to carry the DLV-Feature trailer")
    return identity


def _authenticity_snapshot(root: Path, spec: dict[str, Any]) -> dict[str, Any]:
    required = {"target_identity", "build_identity", "deployment_identity", "adapter_sha256", "fixture", "attestation"}
    if not required <= set(spec) or not all(
        isinstance(spec.get(key), str) and spec[key].strip() for key in required - {"fixture", "attestation"}
    ):
        raise ValueError("high-strength Environment lacks target/build/deployment/adapter identity")
    _, current_adapter = load_adapter(root)
    if current_adapter != spec.get("adapter_sha256"):
        raise ValueError("repository adapter fingerprint is missing or stale")
    fixture = spec.get("fixture")
    if not isinstance(fixture, dict) or set(fixture) != {"path", "sha256"} or not isinstance(fixture.get("path"), str):
        raise ValueError("high-strength Environment fixture binding is invalid")
    fixture_path = confined_project_path(root, fixture["path"], "verification fixture")
    if not fixture_path.is_file() or file_digest(fixture_path) != fixture.get("sha256"):
        raise ValueError("verification fixture fingerprint is missing or stale")
    attestation = validate_attestation_config(spec.get("attestation"))
    return {
        "target_identity": spec["target_identity"],
        "build_identity": spec["build_identity"],
        "deployment_identity": spec["deployment_identity"],
        "adapter_sha256": current_adapter or "",
        "fixture_sha256": fixture["sha256"],
        "attestation": attestation,
        "attestation_key_sha256": attestation_key_digest(attestation),
    }


def validate_runtime_binding(observation: dict[str, Any], authenticity: dict[str, Any], challenge_nonce: str) -> None:
    for role in ("action", "result_readback"):
        value = observation.get(role)
        if (
            not isinstance(value, dict)
            or value.get("target_identity") != authenticity.get("target_identity")
            or value.get("challenge_nonce") != challenge_nonce
        ):
            raise ValueError("runtime action/readback target identity or challenge nonce mismatch")


def asserted_measurements_are_boolean_only(observation: dict[str, Any], assertions: Any) -> bool:
    if not isinstance(assertions, list):
        return True
    measured: list[Any] = []
    for assertion in assertions:
        source = assertion.get("oracle", {}).get("source") if isinstance(assertion, dict) else None
        if not isinstance(source, str) or not source.startswith("/observation/"):
            continue
        actual = resolve_source({"observation": observation}, source)
        if actual is not MISSING:
            measured.append(actual)
    return is_boolean_only_observation({"asserted_measurements": measured})


def bounded_timeout(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= MAX_COMMAND_TIMEOUT_SECONDS:
        raise ValueError(f"timeout_seconds must be between 1 and {MAX_COMMAND_TIMEOUT_SECONDS}")
    return value


def run_directory(root: Path, feature_id: str, run_id: str) -> Path:
    root = root.expanduser().resolve()
    if not SAFE_RUN_ID.fullmatch(run_id):
        raise ValueError("run-id must use lowercase letters, digits, dots, underscores, or hyphens")
    return confined_project_path(
        root, Path(".dlv") / "runs" / feature_id / run_id, "run directory",
    )


def parse_environment_args(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        environment_id, separator, raw = value.partition("=")
        if not separator or not environment_id or not raw:
            raise ValueError("--environment must use ENV-001=/path/to/environment.json")
        if environment_id in result:
            raise ValueError(f"duplicate environment input: {environment_id}")
        result[environment_id] = Path(raw).expanduser().resolve()
    return result


def contract_maps(contract: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    obligations = {item["id"]: item for item in contract.get("obligations", []) if isinstance(item, dict) and isinstance(item.get("id"), str)}
    environments = {item["id"]: item for item in contract.get("environments", []) if isinstance(item, dict) and isinstance(item.get("id"), str)}
    return obligations, environments


def contract_digest(contract: dict[str, Any]) -> str:
    return value_digest(contract)


def start_request_digest(
    feature_id: str, run_id: str, contract: dict[str, Any], state: dict[str, Any],
    supplied: dict[str, Path], snapshots: dict[str, Any], commit_identity: str | None,
) -> str:
    return value_digest({
        "feature_id": feature_id,
        "run_id": run_id,
        "contract_digest": contract_digest(contract),
        "code_fingerprint": state.get("code", {}).get("repository_fingerprint"),
        "commit_identity": commit_identity,
        "environments": {
            environment_id: {
                "path": supplied[environment_id].as_posix(),
                "source_sha256": snapshot.get("source_sha256"),
            }
            for environment_id, snapshot in sorted(snapshots.items())
        },
    })


def recover_pending_start(
    root: Path, feature_id: str, run_id: str, request_digest: str,
) -> Path | None:
    """Repair an interrupted run-metadata/state/report start transaction."""
    destination = run_directory(root, feature_id, run_id)
    journal_path = destination / "pending-start.json"
    if not journal_path.is_file():
        return None
    journal = load_json(journal_path)
    if (
        set(journal) != {
            "schema_version", "request_digest", "metadata_digest",
            "previous_verification", "target_verification",
        }
        or journal.get("schema_version") != SCHEMA_VERSION
        or journal.get("request_digest") != request_digest
        or not isinstance(journal.get("metadata_digest"), str)
        or not SHA256.fullmatch(journal["metadata_digest"])
        or not isinstance(journal.get("previous_verification"), dict)
        or not isinstance(journal.get("target_verification"), dict)
    ):
        raise ValueError("pending Verification start does not match the requested run")
    metadata = load_json(destination / "run.json")
    if value_digest(metadata) != journal["metadata_digest"]:
        raise ValueError("pending Verification start metadata is divergent")
    if load_manifest(destination / "evidence.jsonl"):
        raise ValueError("pending Verification start evidence is not empty")
    summaries = metadata.get("preflight")
    if not isinstance(summaries, list):
        raise ValueError("pending Verification start preflight summary is invalid")
    for item in summaries:
        if not isinstance(item, dict) or set(item) != {"environment_id", "check_id", "status", "anchor", "sha256"}:
            raise ValueError("pending Verification start preflight summary is invalid")
        anchor = destination / str(item.get("anchor", ""))
        try:
            anchor.resolve().relative_to(destination)
        except ValueError as exc:
            raise ValueError("pending Verification start preflight anchor escapes the run") from exc
        if not anchor.is_file() or file_digest(anchor) != item.get("sha256"):
            raise ValueError("pending Verification start preflight anchor is divergent")
    state_path = feature_dir(root, feature_id) / "state.json"
    state = load_state(state_path)
    verification = state.get("verification")
    previous = journal["previous_verification"]
    target = journal["target_verification"]
    if verification == previous:
        state["verification"] = target
        atomic_write_json(state_path, state)
    elif verification != target:
        raise ValueError("pending Verification start state is divergent")
    render(feature_id, root, run_id, locked=True)
    journal_path.unlink()
    if metadata.get("preflight_verdict") != "PASS":
        raise ValueError(f"environment preflight blocked run: {destination}")
    return destination


def recover_pending_transaction(
    root: Path, feature_id: str, run_id: str,
    expected_request_digest: str | None = None,
) -> str | None:
    """Replay an interrupted evidence append/state-head transaction."""
    destination = run_directory(root, feature_id, run_id)
    journal_path = destination / "pending-record.json"
    if not journal_path.is_file():
        return None
    journal = load_json(journal_path)
    record_value = journal.get("record")
    if (
        set(journal) != {"schema_version", "request_digest", "previous_count", "previous_head", "record"}
        or journal.get("schema_version") != SCHEMA_VERSION
        or not isinstance(journal.get("request_digest"), str)
        or not SHA256.fullmatch(journal["request_digest"])
        or not isinstance(record_value, dict)
    ):
        raise ValueError("pending evidence transaction is invalid")
    previous_count = journal.get("previous_count")
    previous_head = journal.get("previous_head")
    if type(previous_count) is not int or previous_count < 0 or not isinstance(previous_head, str) or not SHA256.fullmatch(previous_head):
        raise ValueError("pending evidence transaction predecessor is invalid")
    record_hash = record_value.get("record_hash")
    record_payload = {key: value for key, value in record_value.items() if key != "record_hash"}
    if (
        set(record_value) != EVIDENCE_RECORD_KEYS
        or record_value.get("schema_version") != SCHEMA_VERSION
        or record_value.get("evidence_id") != f"EVID-{previous_count + 1:04d}"
        or record_value.get("previous_hash") != previous_head
        or not isinstance(record_hash, str)
        or not SHA256.fullmatch(record_hash)
        or record_hash != value_digest(record_payload)
    ):
        raise ValueError("pending evidence record is invalid")
    records = load_manifest(destination / "evidence.jsonl")
    state_path = feature_dir(root, feature_id) / "state.json"
    state = load_state(state_path)
    verification = state.get("verification", {})
    if verification.get("active_run_id") != run_id:
        raise ValueError("cannot recover evidence transaction for a non-active run")
    current_count = verification.get("evidence_count")
    current_head = verification.get("evidence_head")
    new_count = previous_count + 1
    new_head = record_hash
    if len(records) == previous_count:
        actual_head = records[-1].get("record_hash") if records else ZERO_HASH
        if actual_head != previous_head or (current_count, current_head) != (previous_count, previous_head):
            raise ValueError("cannot recover evidence transaction from a divergent predecessor")
        append_jsonl(destination / "evidence.jsonl", record_value)
    elif len(records) == previous_count + 1 and records[-1] == record_value:
        if (current_count, current_head) not in {
            (previous_count, previous_head), (new_count, new_head),
        }:
            raise ValueError("cannot recover evidence transaction after divergent state edits")
    else:
        raise ValueError("cannot recover evidence transaction after divergent manifest edits")
    if (current_count, current_head) == (previous_count, previous_head):
        verification["evidence_count"] = new_count
        verification["evidence_head"] = new_head
        state["verification"] = verification
        atomic_write_json(state_path, state)
    elif (current_count, current_head) != (new_count, new_head):
        raise ValueError("cannot recover evidence transaction after divergent state edits")
    clear_durable_execution(
        destination, journal["request_digest"], str(record_value.get("po_id")),
    )
    render(feature_id, root, run_id, locked=True)
    journal_path.unlink()
    if expected_request_digest is not None and journal.get("request_digest") != expected_request_digest:
        raise ValueError("recovered a prior evidence transaction; retry the current record request")
    return str(record_value.get("evidence_id"))


def load_pending_execution(destination: Path) -> dict[str, Any] | None:
    journal_path = destination / "pending-execution.json"
    if not journal_path.is_file():
        return None
    journal = load_json(journal_path)
    if (
        set(journal) != {"schema_version", "request_digest", "po_id", "runner_digest", "challenge_nonce"}
        or journal.get("schema_version") != SCHEMA_VERSION
        or not isinstance(journal.get("request_digest"), str)
        or not SHA256.fullmatch(journal["request_digest"])
        or not isinstance(journal.get("po_id"), str)
        or not isinstance(journal.get("runner_digest"), str)
        or not SHA256.fullmatch(journal["runner_digest"])
        or not isinstance(journal.get("challenge_nonce"), str)
        or not SHA256.fullmatch(journal["challenge_nonce"])
    ):
        raise ValueError("pending Proof execution is invalid")
    return journal


def clear_durable_execution(
    destination: Path, request_digest: str, po_id: str,
) -> None:
    """Clear an execution marker only after its exact result is durable."""
    journal = load_pending_execution(destination)
    if journal is None:
        return
    if journal["request_digest"] != request_digest or journal["po_id"] != po_id:
        raise ValueError("durable Proof record disagrees with pending execution")
    (destination / "pending-execution.json").unlink()


def reject_ambiguous_execution(
    destination: Path, request_digest: str,
) -> None:
    """Fail closed when a runner may have executed without durable output."""
    journal = load_pending_execution(destination)
    if journal is None:
        return
    if journal["request_digest"] != request_digest:
        raise ValueError("pending Proof execution does not match the requested evidence")
    raise ValueError(
        "sealed runner outcome is ambiguous after an interrupted write; "
        "start a new Verification Run instead of executing it again"
    )


def _validated_inputs(root: Path, feature_id: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    directory = feature_dir(root, feature_id)
    graph = load_graph(root, feature_id)
    state = load_state(directory / "state.json")
    contract = load_json(directory / "proof-contract.json")
    errors: list[str] = []
    validate_contract(root, feature_id, contract, state, errors)
    if errors:
        raise ValueError("; ".join(errors))
    if state.get("code", {}).get("status") != "completed":
        raise ValueError("Code must be marked completed before Verification")
    current_code = repository_fingerprint(root, feature_id)
    if state.get("code", {}).get("repository_fingerprint") != current_code:
        raise ValueError("Code fingerprint is stale")
    return graph, state, contract


def start(feature_id: str, root: Path, run_id: str, environment_args: list[str]) -> Path:
    root = root.expanduser().resolve()
    destination = run_directory(root, feature_id, run_id)
    feature_lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    with exclusive_file_lock(feature_lock):
        _, state, contract = _validated_inputs(root, feature_id)
        obligations, environments = contract_maps(contract)
        if not obligations:
            raise ValueError("Verification requires at least one Proof obligation")
        supplied = parse_environment_args(environment_args)
        if set(supplied) != set(environments):
            raise ValueError(
                f"environment inputs must exactly match the contract; missing={sorted(set(environments)-set(supplied))}, "
                f"extra={sorted(set(supplied)-set(environments))}"
            )
        snapshots: dict[str, Any] = {}
        high_strength_environments = {
            obligation.get("environment_id") for obligation in obligations.values()
            if obligation.get("proof_type") in HIGH_STRENGTH_PROOFS
        }
        for environment_id, environment in environments.items():
            path = supplied[environment_id]
            actual = load_json(path)
            if actual != environment.get("spec"):
                raise ValueError(f"environment {environment_id} does not match its contracted structured spec")
            authenticity = _authenticity_snapshot(root, actual) if environment_id in high_strength_environments else None
            snapshots[environment_id] = {
                "target": environment.get("target"),
                "spec": actual,
                "digest": value_digest(actual),
                "source_sha256": file_digest(path),
                "authenticity": authenticity,
            }
        commit_identity = formal_head_identity(root, feature_id) if high_strength_environments else None
        request_digest = start_request_digest(
            feature_id, run_id, contract, state, supplied, snapshots, commit_identity,
        )
        if destination.exists():
            recovered = recover_pending_start(
                root, feature_id, run_id, request_digest,
            )
            if recovered is not None:
                return recovered
            raise ValueError(f"Verification Run already exists: {destination}")
        destination.mkdir(parents=True)
        try:
            preflight: list[dict[str, Any]] = []
            for environment_id, environment in environments.items():
                checks = environment.get("spec", {}).get("preflight", [])
                if not isinstance(checks, list):
                    raise ValueError(f"environment {environment_id} preflight must be an array")
                for check in checks:
                    if not isinstance(check, dict) or not isinstance(check.get("id"), str) or not isinstance(check.get("argv"), list):
                        raise ValueError(f"environment {environment_id} has an invalid preflight command")
                    if not SAFE_CHECK_ID.fullmatch(check["id"]):
                        raise ValueError(f"environment {environment_id} preflight id must be a safe filename segment")
                    try:
                        command = run_bounded(
                            check["argv"], root,
                            bounded_timeout(check.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
                        )
                    except OSError as exc:
                        command = {"exit_code": 127, "stdout": "", "stderr": str(exc), "timed_out": False}
                    result = {
                        "environment_id": environment_id,
                        "check_id": check["id"],
                        "argv": check["argv"],
                        "exit_code": command["exit_code"],
                        "stdout": command["stdout"],
                        "stderr": command["stderr"],
                        "timed_out": command["timed_out"],
                        "status": "passed" if command["exit_code"] == 0 and not command["timed_out"] else "blocked",
                    }
                    anchor = confined_project_path(
                        destination,
                        Path("preflight") / f"{environment_id.lower()}-{check['id']}.json",
                        "preflight anchor",
                    )
                    atomic_write_json(anchor, result)
                    preflight.append({
                        "environment_id": environment_id,
                        "check_id": check["id"],
                        "status": result["status"],
                        "anchor": anchor.relative_to(destination).as_posix(),
                        "sha256": file_digest(anchor),
                    })
            metadata = {
                "schema_version": SCHEMA_VERSION,
                "feature_id": feature_id,
                "run_id": run_id,
                "created_at": timestamp(),
                "contract_digest": contract_digest(contract),
                "code_fingerprint": state["code"]["repository_fingerprint"],
                "commit_identity": commit_identity,
                "environments": snapshots,
                "preflight": preflight,
                "preflight_verdict": "PASS" if all(item["status"] == "passed" for item in preflight) else "BLOCKED",
            }
            atomic_write_json(destination / "run.json", metadata)
            atomic_write_text(destination / "evidence.jsonl", "")
            previous_verification = state.get("verification")
            target_verification = {
                "status": "in_progress" if metadata["preflight_verdict"] == "PASS" else "blocked",
                "active_run_id": run_id,
                "run_digest": None,
                "verdict": None,
                "evidence_count": 0,
                "evidence_head": ZERO_HASH,
                "finalization": None,
            }
            atomic_write_json(destination / "pending-start.json", {
                "schema_version": SCHEMA_VERSION,
                "request_digest": request_digest,
                "metadata_digest": value_digest(metadata),
                "previous_verification": previous_verification,
                "target_verification": target_verification,
            })
        except BaseException:
            shutil.rmtree(destination)
            raise
        state["verification"] = target_verification
        atomic_write_json(feature_dir(root, feature_id) / "state.json", state)
        render(feature_id, root, run_id, locked=True)
        (destination / "pending-start.json").unlink()
        if metadata["preflight_verdict"] != "PASS":
            raise ValueError(f"environment preflight blocked run: {destination}")
        return destination


def _copy_extra_anchors(destination: Path, evidence_id: str, raw_anchors: Any) -> tuple[list[dict[str, Any]], list[tuple[str | None, Path]]]:
    if not isinstance(raw_anchors, list):
        raise ValueError("anchors must be an array")
    stored: list[dict[str, Any]] = []
    normalized: list[tuple[str | None, Path]] = []
    anchor_dir = destination / "anchors"
    anchor_dir.mkdir(exist_ok=True)
    for index, raw in enumerate(raw_anchors, 1):
        role: str | None
        if isinstance(raw, dict):
            role, source_value = raw.get("role"), raw.get("path")
            if not isinstance(role, str) or not role or not isinstance(source_value, str):
                raise ValueError("structured anchors require non-empty role and path")
        else:
            role, source_value = None, str(raw)
        source = Path(source_value).expanduser().resolve()
        target = anchor_dir / f"{evidence_id.lower()}-{index}-{source.name}"
        copy_bounded_anchor(source, target)
        normalized.append((role, target))
        record: dict[str, Any] = {
            "path": target.relative_to(destination).as_posix(),
            "sha256": file_digest(target),
            "size": target.stat().st_size,
        }
        if role is not None:
            record["role"] = role
        stored.append(record)
    return stored, normalized


def _copy_visual_anchors(
    destination: Path, evidence_id: str, command_cwd: Path,
    observation: dict[str, Any], obligation: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[tuple[str | None, Path]]]:
    required = {"prototype_screenshot", "implementation_screenshot", "visual_diff"}
    raw_paths = observation.get("anchor_paths")
    raw_hashes = observation.get("anchor_sha256")
    if not isinstance(raw_paths, dict) or set(raw_paths) != required or not all(
        isinstance(raw_paths.get(role), str) and raw_paths[role] for role in required
    ):
        raise ValueError("visual runner observation requires exact anchor_paths")
    if not isinstance(raw_hashes, dict) or set(raw_hashes) != required or not all(
        isinstance(raw_hashes.get(role), str) and SHA256.fullmatch(raw_hashes[role]) for role in required
    ):
        raise ValueError("visual runner observation requires exact anchor_sha256")
    if observation.get("prototype_sha256") != obligation.get("prototype_sha256"):
        raise ValueError("visual runner Prototype digest disagrees with the sealed obligation")
    if observation.get("capture_profile") != obligation.get("capture_profile"):
        raise ValueError("visual runner capture profile disagrees with the sealed obligation")
    structured = []
    resolved_sources: list[Path] = []
    for role in sorted(required):
        source = Path(raw_paths[role]).expanduser()
        if not source.is_absolute():
            source = command_cwd / source
        resolved = source.resolve()
        resolved_sources.append(resolved)
        structured.append({"role": role, "path": str(resolved)})
    if len(set(resolved_sources)) != len(required):
        raise ValueError("visual runner must produce three distinct anchor paths")
    stored, normalized = _copy_extra_anchors(destination, evidence_id, structured)
    stored_by_role = {anchor.get("role"): anchor.get("sha256") for anchor in stored}
    if stored_by_role != raw_hashes:
        raise ValueError("visual runner signed anchor hashes disagree with captured bytes")
    observation["anchor_paths"] = {
        anchor["role"]: anchor["path"] for anchor in stored if "role" in anchor
    }
    for role, path in normalized:
        if role in required and (path.suffix.lower() != ".png" or not is_supported_image(path)):
            raise ValueError("visual comparison anchors must be valid PNG files")
    return stored, normalized


def record(feature_id: str, root: Path, run_id: str, result_path: Path, supersedes: list[str]) -> str:
    root = root.expanduser().resolve()
    destination = run_directory(root, feature_id, run_id)
    result = load_json(result_path.expanduser().resolve())
    request_digest = value_digest({"result": result, "supersedes": supersedes})
    feature_lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    with exclusive_file_lock(feature_lock), exclusive_file_lock(destination / ".run.lock"):
        recovered = recover_pending_transaction(root, feature_id, run_id, request_digest)
        if recovered is not None:
            (destination / "pending-execution.json").unlink(missing_ok=True)
            return recovered
        reject_ambiguous_execution(destination, request_digest)
        metadata = load_json(destination / "run.json")
        if metadata.get("preflight_verdict") != "PASS":
            raise ValueError("cannot record evidence into a preflight-blocked run")
        _, state, contract = _validated_inputs(root, feature_id)
        verification = state.get("verification", {})
        if verification.get("active_run_id") != run_id or verification.get("status") != "in_progress":
            raise ValueError("evidence may only be recorded into the active in-progress run")
        if metadata.get("contract_digest") != contract_digest(contract):
            raise ValueError("Verification Run contract is stale")
        if metadata.get("code_fingerprint") != repository_fingerprint(root, feature_id):
            raise ValueError("Verification Run code fingerprint is stale")
        allowed = {"po_id", "proof_type", "outcome", "blocked_reason", "anchors"}
        forbidden = set(result) - allowed
        if forbidden:
            raise ValueError("result contains caller-controlled computed fields: " + ", ".join(sorted(forbidden)))
        obligations, _ = contract_maps(contract)
        po_id = result.get("po_id")
        obligation = obligations.get(po_id)
        if obligation is None:
            raise ValueError(f"unknown Proof obligation: {po_id}")
        if result.get("proof_type") != obligation.get("proof_type"):
            raise ValueError("result proof_type disagrees with sealed obligation")
        proof_type = obligation.get("proof_type")
        if proof_type in HIGH_STRENGTH_PROOFS and metadata.get("commit_identity") != formal_head_identity(root, feature_id):
            raise ValueError("Verification Run Git commit identity is stale")
        outcome = result.get("outcome", "evaluate")
        if outcome not in {"evaluate", "blocked"}:
            raise ValueError("outcome must be evaluate or blocked")
        if outcome == "blocked" and not isinstance(result.get("blocked_reason"), str):
            raise ValueError("blocked outcome requires blocked_reason")
        blocked_reason = result.get("blocked_reason")
        runner = obligation.get("runner")
        if not isinstance(runner, dict) or not isinstance(runner.get("argv"), list):
            raise ValueError("Proof obligation has no executable sealed runner")
        command_cwd = (root / str(runner.get("cwd", "."))).resolve()
        try:
            command_cwd.relative_to(root)
        except ValueError as exc:
            raise ValueError("runner cwd escapes project root") from exc
        if not command_cwd.is_dir():
            raise ValueError("runner cwd is not a directory")
        runner_was_invoked = outcome == "evaluate"
        challenge_nonce = secrets.token_hex(32)
        if runner_was_invoked:
            execution_path = destination / "pending-execution.json"
            atomic_write_json(execution_path, {
                "schema_version": SCHEMA_VERSION,
                "request_digest": request_digest,
                "po_id": po_id,
                "runner_digest": value_digest(runner),
                "challenge_nonce": challenge_nonce,
            })
            try:
                completed = run_bounded(
                    runner["argv"], command_cwd,
                    bounded_timeout(runner.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
                    environment={
                        **os.environ,
                        "DLV_CHALLENGE_NONCE": challenge_nonce,
                    },
                    deny_process_fork=proof_type in HIGH_STRENGTH_PROOFS,
                )
            except ValueError:
                execution_path.unlink(missing_ok=True)
                raise
            except OSError as exc:
                outcome = "blocked"
                blocked_reason = f"sealed runner unavailable: {exc}"
                completed = {"exit_code": 127, "stdout": "", "stderr": str(exc), "timed_out": False}
            command = {
                "argv": runner["argv"], "cwd": command_cwd.relative_to(root).as_posix() or ".",
                "exit_code": completed["exit_code"], "stdout": completed["stdout"],
                "stderr": completed["stderr"], "timed_out": completed["timed_out"],
            }
            if completed["timed_out"]:
                outcome = "blocked"
                blocked_reason = "sealed runner timed out"
            adapter = runner.get("observation_adapter")
            if outcome == "blocked":
                observation = {"blocked_reason": blocked_reason}
            elif adapter in {"json_stdout", "visual_bundle", "runtime_trace"}:
                try:
                    observation = json.loads(completed["stdout"])
                except json.JSONDecodeError as exc:
                    observation = {"adapter_error": f"stdout is not JSON: {exc.msg}"}
                if not isinstance(observation, dict):
                    observation = {"adapter_error": "stdout JSON must be an object"}
            elif adapter == "none":
                observation = {}
            else:
                raise ValueError("sealed runner observation_adapter is invalid")
        else:
            command = {"argv": runner["argv"], "cwd": command_cwd.relative_to(root).as_posix() or ".", "exit_code": None, "stdout": "", "stderr": "", "timed_out": False}
            observation = {"blocked_reason": blocked_reason}
        snapshot = metadata.get("environments", {}).get(obligation.get("environment_id"), {})
        authenticity = snapshot.get("authenticity") if isinstance(snapshot, dict) else None
        if repository_fingerprint(root, feature_id) != metadata.get("code_fingerprint"):
            raise ValueError("Code changed while the sealed runner was executing")
        if proof_type in HIGH_STRENGTH_PROOFS:
            current_authenticity = _authenticity_snapshot(root, snapshot.get("spec", {}))
            if current_authenticity != authenticity:
                raise ValueError("adapter, fixture, build, deployment, or runtime target drifted during Proof execution")
        existing = load_manifest(destination / "evidence.jsonl")
        current_head = existing[-1]["record_hash"] if existing else ZERO_HASH
        if verification.get("evidence_count") != len(existing) or verification.get("evidence_head") != current_head:
            raise ValueError("evidence manifest disagrees with state hash-chain head")
        evidence_id = f"EVID-{len(existing) + 1:04d}"
        known = {item.get("evidence_id") for item in existing}
        if set(supersedes) - known:
            raise ValueError("supersedes references unknown evidence")
        already = {item for item in existing for item in item.get("supersedes", [])}
        if set(supersedes) & already:
            raise ValueError("evidence can be superseded only once")
        if any(item.get("po_id") != po_id for item in existing if item.get("evidence_id") in supersedes):
            raise ValueError("evidence may supersede only the same Proof obligation")
        if outcome == "evaluate" and proof_type in HIGH_STRENGTH_PROOFS:
            if not isinstance(authenticity, dict):
                raise ValueError("high-strength Proof lacks sealed runtime authenticity")
            if observation.get("challenge_nonce") != challenge_nonce or observation.get("target_identity") != authenticity.get("target_identity"):
                raise ValueError("high-strength Proof target identity/challenge nonce mismatch")
            verify_target_attestation(observation, authenticity, challenge_nonce)
            if is_boolean_only_observation(observation):
                raise ValueError("boolean-only observation cannot satisfy a high-strength Proof")
            if asserted_measurements_are_boolean_only(observation, obligation.get("assertions", [])):
                raise ValueError("boolean-only asserted measurement cannot satisfy a high-strength Proof")
        if outcome == "evaluate" and proof_type == "visual":
            if result.get("anchors"):
                raise ValueError("visual anchors must come from the sealed runner observation")
            stored, normalized = _copy_visual_anchors(
                destination, evidence_id, command_cwd, observation, obligation,
            )
        else:
            stored, normalized = _copy_extra_anchors(destination, evidence_id, result.get("anchors", []))
        role_counts: dict[str, int] = {}
        for role, _ in normalized:
            if role:
                role_counts[role] = role_counts.get(role, 0) + 1
        if outcome == "evaluate" and proof_type == "visual":
            required = {"prototype_screenshot", "implementation_screenshot", "visual_diff"}
            if any(role_counts.get(role) != 1 for role in required):
                raise ValueError("visual evidence requires exactly one prototype, implementation, and diff screenshot")
            pixel, geometry = computed_visual_metrics(normalized)
            if observation.get("pixel_diff_ratio") != pixel or observation.get("geometry_diff_max") != geometry:
                raise ValueError("visual runner metrics disagree with recomputed screenshot metrics")
        if outcome == "evaluate" and proof_type == "runtime":
            required = {"runtime", "action", "result_readback"}
            if not required <= set(observation):
                raise ValueError("runtime_trace observation is incomplete")
            snapshot = metadata.get("environments", {}).get(obligation.get("environment_id"), {})
            if observation.get("runtime") != snapshot.get("spec", {}).get("runtime"):
                raise ValueError("runtime_trace runtime disagrees with sealed Environment")
            validate_runtime_binding(observation, authenticity, challenge_nonce)
            traces = [path for role, path in normalized if role == "runtime_trace"]
            if len(traces) != 1 or load_runtime_trace(traces[0]) != observation:
                raise ValueError("runtime evidence requires one matching runtime_trace anchor")
        source = {"command": command, "observation": observation}
        assertion_results: list[dict[str, Any]] = []
        assertions = obligation.get("assertions", [])
        for assertion in assertions:
            actual = resolve_source(source, assertion["oracle"]["source"])
            status = outcome if outcome == "blocked" else ("passed" if evaluate_oracle(actual, assertion["oracle"]) else "failed")
            assertion_results.append({
                "assertion_id": assertion["id"], "status": status,
                "present": actual is not MISSING, "actual": None if actual is MISSING else actual,
            })
        has_exit_contract = any(
            assertion.get("oracle", {}).get("source") == "/command/exit_code"
            for assertion in assertions if isinstance(assertion, dict)
        )
        uncontracted_command_failure = (
            type(command.get("exit_code")) is int
            and command["exit_code"] != 0
            and not has_exit_contract
        )
        status = "blocked" if outcome == "blocked" else (
            "passed" if assertion_results
            and all(item["status"] == "passed" for item in assertion_results)
            and not uncontracted_command_failure
            else "failed"
        )
        anchor_dir = destination / "anchors"
        anchor_dir.mkdir(exist_ok=True)
        for name, value in (("command", command), ("observation", observation)):
            path = anchor_dir / f"{evidence_id.lower()}-{name}.json"
            atomic_write_json(path, value)
            stored.append({"path": path.relative_to(destination).as_posix(), "sha256": file_digest(path), "size": path.stat().st_size})
        snapshot = metadata.get("environments", {}).get(obligation.get("environment_id"), {})
        record_value = {
            "schema_version": SCHEMA_VERSION,
            "evidence_id": evidence_id,
            "recorded_at": timestamp(),
            "po_id": po_id,
            "proof_type": proof_type,
            "claim_ids": obligation.get("claim_ids", []),
            "challenge_nonce": challenge_nonce,
            "target_identity": authenticity.get("target_identity") if isinstance(authenticity, dict) else None,
            "adapter_sha256": authenticity.get("adapter_sha256") if isinstance(authenticity, dict) else None,
            "fixture_sha256": authenticity.get("fixture_sha256") if isinstance(authenticity, dict) else None,
            "attestation_key_sha256": authenticity.get("attestation_key_sha256") if isinstance(authenticity, dict) else None,
            "status": status,
            "contract_digest": metadata["contract_digest"],
            "code_fingerprint": metadata["code_fingerprint"],
            "commit_identity": metadata.get("commit_identity") if proof_type in HIGH_STRENGTH_PROOFS else None,
            "environment_id": obligation.get("environment_id"),
            "environment_digest": snapshot.get("digest"),
            "command": command,
            "assertion_results": assertion_results,
            "observation": observation,
            "anchors": stored,
            "blocked_reason": blocked_reason,
            "supersedes": supersedes,
            "previous_hash": current_head,
        }
        if repository_fingerprint(root, feature_id) != metadata.get("code_fingerprint"):
            raise ValueError("Code changed while evidence anchors were being recorded")
        record_value["record_hash"] = value_digest(record_value)
        atomic_write_json(destination / "pending-record.json", {
            "schema_version": SCHEMA_VERSION,
            "request_digest": request_digest,
            "previous_count": len(existing),
            "previous_head": current_head,
            "record": record_value,
        })
        if runner_was_invoked:
            execution_path.unlink()
        append_jsonl(destination / "evidence.jsonl", record_value)
        verification["evidence_count"] = len(existing) + 1
        verification["evidence_head"] = record_value["record_hash"]
        state["verification"] = verification
        atomic_write_json(feature_dir(root, feature_id) / "state.json", state)
        render(feature_id, root, run_id, locked=True)
        (destination / "pending-record.json").unlink()
        return evidence_id


def validate_run(root: Path, feature_id: str, run_id: str, errors: list[str]) -> tuple[str, str | None]:
    root = root.expanduser().resolve()
    destination = run_directory(root, feature_id, run_id)
    if (destination / "pending-execution.json").is_file():
        errors.append(
            "Verification Run contains an ambiguous sealed runner execution; start a new run"
        )
    metadata = load_json(destination / "run.json")
    _, state, contract = _validated_inputs(root, feature_id)
    obligations, environments = contract_maps(contract)
    if set(metadata) != {
        "schema_version", "feature_id", "run_id", "created_at", "contract_digest",
        "code_fingerprint", "commit_identity", "environments", "preflight", "preflight_verdict",
    }:
        errors.append("Verification Run metadata contains unknown or missing fields")
    if metadata.get("schema_version") != SCHEMA_VERSION or metadata.get("feature_id") != feature_id or metadata.get("run_id") != run_id:
        errors.append("Verification Run identity/schema is invalid")
    if metadata.get("contract_digest") != contract_digest(contract):
        errors.append("Verification Run contract digest is stale")
    high_strength_required = any(
        obligation.get("proof_type") in HIGH_STRENGTH_PROOFS
        for obligation in obligations.values()
    )
    if high_strength_required:
        try:
            if metadata.get("commit_identity") != formal_head_identity(root, feature_id):
                errors.append("Verification Run Git commit identity is stale")
        except ValueError as exc:
            errors.append(str(exc))
    elif metadata.get("commit_identity") is not None:
        errors.append("low-strength Verification Run must not claim a Git commit identity")
    if metadata.get("code_fingerprint") != repository_fingerprint(root, feature_id):
        errors.append("Verification Run code fingerprint is stale")
    if state.get("verification", {}).get("active_run_id") != run_id:
        errors.append("Verification Run is not the active run")
    snapshots = metadata.get("environments")
    if not isinstance(snapshots, dict) or set(snapshots) != set(environments):
        errors.append("Verification Run Environment set disagrees with the contract")
        snapshots = {}
    for environment_id, environment in environments.items():
        snapshot = snapshots.get(environment_id)
        if not isinstance(snapshot, dict):
            continue
        if set(snapshot) != {"target", "spec", "digest", "source_sha256", "authenticity"}:
            errors.append(f"Verification Run Environment snapshot shape is invalid: {environment_id}")
        if snapshot.get("target") != environment.get("target") or snapshot.get("spec") != environment.get("spec"):
            errors.append(f"Verification Run Environment snapshot is stale: {environment_id}")
        if snapshot.get("digest") != value_digest(environment.get("spec")):
            errors.append(f"Verification Run Environment digest is stale: {environment_id}")
    expected_preflight = {
        (environment_id, check.get("id")): check
        for environment_id, environment in environments.items()
        for check in environment.get("spec", {}).get("preflight", [])
        if isinstance(check, dict)
    }
    summaries = metadata.get("preflight")
    if not isinstance(summaries, list):
        errors.append("Verification Run preflight summary must be an array")
        summaries = []
    if {(item.get("environment_id"), item.get("check_id")) for item in summaries if isinstance(item, dict)} != set(expected_preflight):
        errors.append("Verification Run preflight coverage disagrees with the contract")
    derived_preflight_statuses: list[str] = []
    for item in summaries:
        if not isinstance(item, dict):
            errors.append("Verification Run preflight summary item is invalid")
            continue
        if set(item) != {"environment_id", "check_id", "status", "anchor", "sha256"}:
            errors.append(f"preflight summary shape is invalid: {item.get('check_id')}")
        anchor = destination / str(item.get("anchor", ""))
        try:
            anchor.resolve().relative_to(destination)
        except ValueError:
            errors.append("preflight anchor escapes the run directory")
            continue
        if not anchor.is_file() or file_digest(anchor) != item.get("sha256"):
            errors.append(f"preflight anchor is missing or stale: {item.get('check_id')}")
            continue
        result = load_json(anchor)
        if set(result) != {
            "environment_id", "check_id", "argv", "exit_code", "stdout",
            "stderr", "timed_out", "status",
        }:
            errors.append(f"preflight result shape is invalid: {item.get('check_id')}")
        contracted = expected_preflight.get((item.get("environment_id"), item.get("check_id")))
        if not isinstance(contracted, dict) or result.get("argv") != contracted.get("argv"):
            errors.append(f"preflight command disagrees with contract: {item.get('check_id')}")
        if result.get("environment_id") != item.get("environment_id") or result.get("check_id") != item.get("check_id"):
            errors.append(f"preflight identity disagrees with summary: {item.get('check_id')}")
        derived = "passed" if result.get("exit_code") == 0 and not result.get("timed_out") else "blocked"
        derived_preflight_statuses.append(derived)
        if result.get("status") != derived or item.get("status") != derived:
            errors.append(f"preflight status is not reproducible: {item.get('check_id')}")
        if derived != "passed":
            errors.append(f"preflight is not passed: {item.get('check_id')}")
    derived_preflight_verdict = "PASS" if all(status == "passed" for status in derived_preflight_statuses) and len(derived_preflight_statuses) == len(expected_preflight) else "BLOCKED"
    if metadata.get("preflight_verdict") != derived_preflight_verdict:
        errors.append("Verification Run preflight verdict is not reproducible")
    records = load_manifest(destination / "evidence.jsonl")
    prior = ZERO_HASH
    known: set[str] = set()
    superseded: set[str] = set()
    records_by_id: dict[str, dict[str, Any]] = {}
    seen_challenge_nonces: set[str] = set()
    current_authenticity_cache: dict[str, tuple[dict[str, Any] | None, str | None]] = {}
    for index, record_value in enumerate(records, 1):
        evidence_id = record_value.get("evidence_id")
        if set(record_value) != EVIDENCE_RECORD_KEYS:
            errors.append(f"evidence record contains unknown or missing fields: {evidence_id}")
        if record_value.get("schema_version") != SCHEMA_VERSION:
            errors.append(f"evidence schema is invalid: {evidence_id}")
        challenge_nonce = record_value.get("challenge_nonce")
        if not isinstance(challenge_nonce, str) or not SHA256.fullmatch(challenge_nonce):
            errors.append(f"evidence challenge nonce is invalid: {evidence_id}")
        elif challenge_nonce in seen_challenge_nonces:
            errors.append(f"evidence challenge nonce is reused: {evidence_id}")
        else:
            seen_challenge_nonces.add(challenge_nonce)
        if record_value.get("evidence_id") != f"EVID-{index:04d}":
            errors.append("evidence IDs must be append-only and contiguous")
        if record_value.get("previous_hash") != prior:
            errors.append(f"evidence hash-chain predecessor mismatch: {record_value.get('evidence_id')}")
        payload = {key: value for key, value in record_value.items() if key != "record_hash"}
        if record_value.get("record_hash") != value_digest(payload):
            errors.append(f"evidence record hash is stale: {record_value.get('evidence_id')}")
        prior = record_value.get("record_hash")
        replaced = record_value.get("supersedes")
        if not isinstance(replaced, list) or any(item not in known or item in superseded for item in replaced):
            errors.append(f"invalid supersession history: {evidence_id}")
            replaced = []
        if any(records_by_id[item].get("po_id") != record_value.get("po_id") for item in replaced if item in records_by_id):
            errors.append(f"evidence supersedes a different Proof: {evidence_id}")
        superseded.update(replaced)
        known.add(evidence_id)
        records_by_id[str(evidence_id)] = record_value
        obligation = obligations.get(record_value.get("po_id"))
        if obligation is None:
            errors.append(f"evidence references unknown Proof: {evidence_id}")
            obligation = {}
        snapshot = snapshots.get(obligation.get("environment_id"), {}) if isinstance(snapshots, dict) else {}
        if record_value.get("proof_type") != obligation.get("proof_type"):
            errors.append(f"evidence Proof type disagrees with contract: {evidence_id}")
        if record_value.get("claim_ids") != obligation.get("claim_ids", []):
            errors.append(f"evidence Claim binding disagrees with contract: {evidence_id}")
        if record_value.get("contract_digest") != metadata.get("contract_digest"):
            errors.append(f"evidence contract digest is stale: {evidence_id}")
        if record_value.get("code_fingerprint") != metadata.get("code_fingerprint"):
            errors.append(f"evidence Code fingerprint is stale: {evidence_id}")
        if record_value.get("environment_id") != obligation.get("environment_id") or record_value.get("environment_digest") != snapshot.get("digest"):
            errors.append(f"evidence Environment binding is stale: {evidence_id}")
        authenticity = snapshot.get("authenticity") if isinstance(snapshot, dict) else None
        if obligation.get("proof_type") in HIGH_STRENGTH_PROOFS:
            if record_value.get("commit_identity") != metadata.get("commit_identity"):
                errors.append(f"evidence Git commit identity is stale: {evidence_id}")
            environment_id = str(record_value.get("environment_id"))
            if environment_id not in current_authenticity_cache:
                try:
                    current_authenticity_cache[environment_id] = (
                        _authenticity_snapshot(root, snapshot.get("spec", {})), None,
                    )
                except (OSError, ValueError) as exc:
                    current_authenticity_cache[environment_id] = (None, str(exc))
            current_authenticity, authenticity_error = current_authenticity_cache[environment_id]
            if authenticity_error is not None:
                errors.append(f"evidence authenticity cannot be validated: {evidence_id}: {authenticity_error}")
            if authenticity != current_authenticity:
                errors.append(f"evidence adapter/fixture/target binding is stale: {evidence_id}")
            if (
                record_value.get("target_identity") != (authenticity or {}).get("target_identity")
                or record_value.get("adapter_sha256") != (authenticity or {}).get("adapter_sha256")
                or record_value.get("fixture_sha256") != (authenticity or {}).get("fixture_sha256")
                or record_value.get("attestation_key_sha256") != (authenticity or {}).get("attestation_key_sha256")
            ):
                errors.append(f"evidence authenticity fields disagree with the run: {evidence_id}")
        elif record_value.get("commit_identity") is not None:
            errors.append(f"low-strength evidence must not claim a Git commit identity: {evidence_id}")
        runner = obligation.get("runner") if isinstance(obligation, dict) else None
        command = record_value.get("command")
        observation = record_value.get("observation")
        if not isinstance(runner, dict) or not isinstance(command, dict) or not isinstance(observation, dict):
            errors.append(f"evidence command/observation contract is invalid: {evidence_id}")
            runner, command, observation = {}, {}, {}
        elif set(command) != {"argv", "cwd", "exit_code", "stdout", "stderr", "timed_out"}:
            errors.append(f"evidence command contains unknown or missing fields: {evidence_id}")
        elif (
            not isinstance(command.get("argv"), list)
            or not all(isinstance(item, str) for item in command["argv"])
            or not isinstance(command.get("cwd"), str)
            or (command.get("exit_code") is not None and type(command.get("exit_code")) is not int)
            or not isinstance(command.get("stdout"), str)
            or not isinstance(command.get("stderr"), str)
            or type(command.get("timed_out")) is not bool
        ):
            errors.append(f"evidence command field types are invalid: {evidence_id}")
        expected_cwd_path = (root / str(runner.get("cwd", "."))).resolve()
        try:
            expected_cwd = expected_cwd_path.relative_to(root).as_posix() or "."
        except ValueError:
            expected_cwd = "<escapes-root>"
        if command.get("argv") != runner.get("argv") or command.get("cwd") != expected_cwd:
            errors.append(f"evidence command disagrees with sealed runner: {evidence_id}")
        normalized_anchors: list[tuple[str | None, Path]] = []
        generated_command = generated_observation = False
        raw_anchors = record_value.get("anchors")
        if not isinstance(raw_anchors, list):
            errors.append(f"evidence anchors must be an array: {evidence_id}")
            raw_anchors = []
        for anchor in raw_anchors:
            if not isinstance(anchor, dict):
                errors.append(f"evidence anchor metadata is invalid: {evidence_id}")
                continue
            if set(anchor) not in ({"path", "sha256", "size"}, {"path", "sha256", "size", "role"}):
                errors.append(f"evidence anchor metadata shape is invalid: {evidence_id}")
                continue
            path = destination / str(anchor.get("path", ""))
            try:
                path.resolve().relative_to(destination)
            except ValueError:
                errors.append(f"evidence anchor escapes run: {record_value.get('evidence_id')}")
                continue
            if not path.is_file() or file_digest(path) != anchor.get("sha256") or path.stat().st_size != anchor.get("size"):
                errors.append(f"evidence anchor is missing or stale: {evidence_id}")
                continue
            normalized_anchors.append((anchor.get("role"), path))
            if path.name == f"{str(evidence_id).lower()}-command.json":
                generated_command = load_json(path) == command
            if path.name == f"{str(evidence_id).lower()}-observation.json":
                generated_observation = load_json(path) == observation
        if not generated_command or not generated_observation:
            errors.append(f"evidence generated command/observation anchors disagree: {evidence_id}")
        proof_type = obligation.get("proof_type") if isinstance(obligation, dict) else None
        if proof_type == "visual" and record_value.get("status") != "blocked":
            roles = [role for role, _ in normalized_anchors]
            required = {"prototype_screenshot", "implementation_screenshot", "visual_diff"}
            if any(roles.count(role) != 1 for role in required):
                errors.append(f"visual evidence anchor roles are incomplete: {evidence_id}")
            else:
                expected_paths = {
                    role: path.relative_to(destination).as_posix()
                    for role, path in normalized_anchors if role in required
                }
                if observation.get("anchor_paths") != expected_paths:
                    errors.append(f"visual evidence anchor paths disagree with runner observation: {evidence_id}")
                expected_hashes = {
                    role: file_digest(path) for role, path in normalized_anchors if role in required
                }
                if observation.get("anchor_sha256") != expected_hashes:
                    errors.append(f"visual evidence signed anchor hashes disagree: {evidence_id}")
                if observation.get("prototype_sha256") != obligation.get("prototype_sha256"):
                    errors.append(f"visual evidence Prototype binding is stale: {evidence_id}")
                if observation.get("capture_profile") != obligation.get("capture_profile"):
                    errors.append(f"visual evidence capture profile is stale: {evidence_id}")
                try:
                    pixel, geometry = computed_visual_metrics(normalized_anchors)
                except (OSError, ValueError) as exc:
                    errors.append(f"visual evidence cannot be recomputed: {evidence_id}: {exc}")
                else:
                    if observation.get("pixel_diff_ratio") != pixel or observation.get("geometry_diff_max") != geometry:
                        errors.append(f"visual evidence metrics are not reproducible: {evidence_id}")
        if proof_type == "runtime" and record_value.get("status") != "blocked":
            traces = [path for role, path in normalized_anchors if role == "runtime_trace"]
            try:
                trace_matches = len(traces) == 1 and load_runtime_trace(traces[0]) == observation
            except (OSError, ValueError, json.JSONDecodeError):
                trace_matches = False
            if not trace_matches:
                errors.append(f"runtime evidence trace is missing or stale: {evidence_id}")
            if observation.get("runtime") != snapshot.get("spec", {}).get("runtime"):
                errors.append(f"runtime evidence target is stale: {evidence_id}")
            for role in ("action", "result_readback"):
                value = observation.get(role)
                if not isinstance(value, dict) or value.get("target_identity") != (authenticity or {}).get("target_identity") or value.get("challenge_nonce") != challenge_nonce:
                    errors.append(f"runtime evidence {role} target/nonce binding is stale: {evidence_id}")
        if proof_type in HIGH_STRENGTH_PROOFS and record_value.get("status") != "blocked":
            if observation.get("target_identity") != (authenticity or {}).get("target_identity") or observation.get("challenge_nonce") != challenge_nonce:
                errors.append(f"high-strength evidence target/nonce binding is stale: {evidence_id}")
            if is_boolean_only_observation(observation):
                errors.append(f"high-strength evidence is boolean-only: {evidence_id}")
            if asserted_measurements_are_boolean_only(observation, obligation.get("assertions", [])):
                errors.append(f"high-strength asserted measurement is boolean-only: {evidence_id}")
            try:
                verify_target_attestation(observation, authenticity or {}, challenge_nonce)
            except ValueError as exc:
                errors.append(f"high-strength target attestation is invalid: {evidence_id}: {exc}")
        assertions = obligation.get("assertions", []) if isinstance(obligation, dict) else []
        explicitly_blocked = (
            isinstance(record_value.get("blocked_reason"), str)
            and observation == {"blocked_reason": record_value.get("blocked_reason")}
        )
        blocked = command.get("timed_out") is True or explicitly_blocked
        expected_results: list[dict[str, Any]] = []
        for assertion in assertions:
            actual = resolve_source({"command": command, "observation": observation}, assertion["oracle"]["source"])
            assertion_status = "blocked" if blocked else ("passed" if evaluate_oracle(actual, assertion["oracle"]) else "failed")
            expected_results.append({
                "assertion_id": assertion["id"], "status": assertion_status,
                "present": actual is not MISSING, "actual": None if actual is MISSING else actual,
            })
        if record_value.get("assertion_results") != expected_results:
            errors.append(f"evidence assertion results are not reproducible: {evidence_id}")
        has_exit_contract = any(
            assertion.get("oracle", {}).get("source") == "/command/exit_code"
            for assertion in assertions if isinstance(assertion, dict)
        )
        uncontracted_command_failure = (
            type(command.get("exit_code")) is int
            and command["exit_code"] != 0
            and not has_exit_contract
        )
        expected_status = "blocked" if blocked else (
            "passed" if expected_results
            and all(item["status"] == "passed" for item in expected_results)
            and not uncontracted_command_failure
            else "failed"
        )
        if record_value.get("status") != expected_status:
            errors.append(f"evidence status is not reproducible: {evidence_id}")
        if blocked and not isinstance(record_value.get("blocked_reason"), str):
            errors.append(f"blocked evidence requires a reason: {evidence_id}")
    verification = state.get("verification", {})
    if verification.get("evidence_count") != len(records) or verification.get("evidence_head") != prior:
        errors.append("state evidence head/count disagrees with manifest")
    active = [record_value for record_value in records if record_value.get("evidence_id") not in superseded]
    by_po: dict[str, list[dict[str, Any]]] = {}
    for record_value in active:
        by_po.setdefault(str(record_value.get("po_id")), []).append(record_value)
    for po_id in obligations:
        candidates = by_po.get(po_id, [])
        if len(candidates) != 1:
            errors.append(f"Proof obligation requires exactly one active evidence: {po_id}")
        elif candidates[0].get("status") != "passed":
            errors.append(f"active evidence is not passed: {po_id}")
    extras = set(by_po) - set(obligations)
    if extras:
        errors.append("evidence covers unknown Proof obligations: " + ", ".join(sorted(extras)))
    digest = value_digest({"run": metadata, "records": records})
    return ("PASS" if not errors else "BLOCKED"), digest


def render_content(feature_id: str, root: Path, run_id: str) -> str:
    root = root.expanduser().resolve()
    destination = run_directory(root, feature_id, run_id)
    metadata = load_json(destination / "run.json")
    records = load_manifest(destination / "evidence.jsonl")
    superseded = {item for record_value in records for item in record_value.get("supersedes", [])}
    active = [record_value for record_value in records if record_value.get("evidence_id") not in superseded]
    errors: list[str] = []
    try:
        verdict, digest = validate_run(root, feature_id, run_id, errors)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        verdict, digest = "BLOCKED", None
        errors.append(str(exc))
    lines = [
        f"# {feature_id} — Verification Run", "",
        "> Generated from immutable run metadata and append-only evidence. Do not edit.", "",
        "## 1. Run", "",
        f"- Run: `{run_id}`", f"- Contract: `{metadata.get('contract_digest')}`",
        f"- Code: `{metadata.get('code_fingerprint')}`", f"- Run digest: `{digest}`", "",
        "## 2. Active evidence", "",
        "| Evidence | Proof | Type | Status |", "|---|---|---|---|",
    ]
    lines.extend(f"| {item.get('evidence_id')} | {item.get('po_id')} | {item.get('proof_type')} | {item.get('status')} |" for item in active)
    if not active:
        lines.append("| — | — | — | pending |")
    lines.extend(["", "## 3. Verdict", "", f"**{verdict}**", ""])
    if errors:
        lines.extend(["## 4. Blocking findings", ""] + [f"- {error}" for error in errors] + [""])
    return "\n".join(lines)


def render(feature_id: str, root: Path, run_id: str, *, locked: bool = False) -> Path:
    root = root.expanduser().resolve()
    destination = run_directory(root, feature_id, run_id)
    if not locked:
        feature_lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
        with exclusive_file_lock(feature_lock), exclusive_file_lock(destination / ".run.lock"):
            return render(feature_id, root, run_id, locked=True)
    output = feature_dir(root, feature_id) / "verification.md"
    atomic_write_text(output, render_content(feature_id, root, run_id))
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    start_parser = sub.add_parser("start")
    start_parser.add_argument("feature_id")
    start_parser.add_argument("--root", default=".")
    start_parser.add_argument("--run-id", required=True)
    start_parser.add_argument("--environment", action="append", default=[])
    record_parser = sub.add_parser("record")
    record_parser.add_argument("feature_id")
    record_parser.add_argument("--root", default=".")
    record_parser.add_argument("--run-id", required=True)
    record_parser.add_argument("--result", required=True)
    record_parser.add_argument("--supersedes", action="append", default=[])
    render_parser = sub.add_parser("render")
    render_parser.add_argument("feature_id")
    render_parser.add_argument("--root", default=".")
    render_parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    root = Path(args.root)
    try:
        if args.command == "start":
            print(start(args.feature_id, root, args.run_id, args.environment))
        elif args.command == "record":
            print(record(args.feature_id, root, args.run_id, Path(args.result), args.supersedes))
        else:
            print(render(args.feature_id, root, args.run_id))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
