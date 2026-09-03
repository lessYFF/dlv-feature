#!/usr/bin/env python3
"""Execute and record kernel-derived evidence for one critical risk experiment."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

from delivery_graph import atomic_write_json, compile_graph, confined_project_path, feature_dir, load_graph, load_state, timestamp
from delivery_governance import load_source_revision, sign_kernel_receipt
from delivery_proof import MISSING, evaluate_oracle, exclusive_file_lock, load_json, resolve_source, value_digest
from graph_verification import HIGH_STRENGTH_PROOFS, _authenticity_snapshot, asserted_measurements_are_boolean_only, bounded_timeout
from runtime_evidence import DEFAULT_TIMEOUT_SECONDS, run_bounded
from target_attestation import verify_target_attestation
from delivery_contracts import is_boolean_only_observation
from quality_core import experiment_binding


def _execute_proof(root: Path, proof: dict[str, object]) -> dict[str, object]:
    runner = proof.get("runner")
    if not isinstance(runner, dict) or not isinstance(runner.get("argv"), list):
        raise ValueError(f"critical experiment Proof {proof.get('id')} has no sealed runner")
    cwd = (root / str(runner.get("cwd", "."))).resolve()
    try:
        cwd.relative_to(root)
    except ValueError as exc:
        raise ValueError("critical experiment runner cwd escapes project root") from exc
    if not cwd.is_dir():
        raise ValueError("critical experiment runner cwd is not a directory")
    proof_type = proof.get("proof_type")
    challenge_nonce = secrets.token_hex(32)
    completed = run_bounded(
        runner["argv"], cwd,
        bounded_timeout(runner.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
        environment={**os.environ, "DLV_CHALLENGE_NONCE": challenge_nonce},
        deny_process_fork=proof_type in HIGH_STRENGTH_PROOFS,
    )
    command = {
        "argv": runner["argv"], "cwd": cwd.relative_to(root).as_posix() or ".",
        "exit_code": completed["exit_code"], "stdout": completed["stdout"],
        "stderr": completed["stderr"], "timed_out": completed["timed_out"],
    }
    adapter = runner.get("observation_adapter")
    if adapter in {"json_stdout", "visual_bundle", "runtime_trace"}:
        try:
            observation = json.loads(completed["stdout"])
        except json.JSONDecodeError as exc:
            raise ValueError(f"critical experiment runner stdout is not JSON: {exc.msg}") from exc
        if not isinstance(observation, dict):
            raise ValueError("critical experiment runner stdout JSON must be an object")
    elif adapter == "none":
        observation = {}
    else:
        raise ValueError("critical experiment runner observation_adapter is invalid")
    environment = proof.get("environment")
    environment_spec = environment.get("attributes", {}).get("spec") if isinstance(environment, dict) else None
    if proof_type in HIGH_STRENGTH_PROOFS:
        if not isinstance(environment_spec, dict):
            raise ValueError("high-strength critical experiment requires one sealed Environment")
        authenticity = _authenticity_snapshot(root, environment_spec)
        if observation.get("target_identity") != authenticity.get("target_identity") or observation.get("challenge_nonce") != challenge_nonce:
            raise ValueError("high-strength critical experiment target/nonce binding is invalid")
        if is_boolean_only_observation(observation) or asserted_measurements_are_boolean_only(observation, proof.get("assertions")):
            raise ValueError("high-strength critical experiment cannot rely on boolean-only measurements")
        verify_target_attestation(observation, authenticity, challenge_nonce)
    assertions: list[dict[str, object]] = []
    for assertion in proof.get("assertions", []):
        oracle = assertion.get("oracle")
        actual = resolve_source({"command": command, "observation": observation}, oracle.get("source")) if isinstance(oracle, dict) else MISSING
        passed = actual is not MISSING and evaluate_oracle(actual, oracle)
        assertions.append({
            "assertion_id": assertion.get("id"), "passed": passed,
            "present": actual is not MISSING, "actual": None if actual is MISSING else actual,
        })
    has_exit_contract = any(
        item.get("oracle", {}).get("source") == "/command/exit_code"
        for item in proof.get("assertions", []) if isinstance(item, dict)
    )
    verdict = "PASS" if (
        assertions and all(item["passed"] for item in assertions)
        and not completed["timed_out"] and (completed["exit_code"] == 0 or has_exit_contract)
    ) else "BLOCKED"
    return {
        "proof_id": proof.get("id"), "proof_type": proof_type,
        "runner_sha256": value_digest(runner), "environment_sha256": value_digest(environment),
        "challenge_nonce": challenge_nonce, "command": command, "observation": observation,
        "assertion_results": assertions, "verdict": verdict,
    }


def record(root: Path, feature_id: str, experiment_id: str) -> Path:
    root = root.expanduser().resolve()
    feature_dir(root, feature_id)
    lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    with exclusive_file_lock(lock):
        graph = load_graph(root, feature_id)
        state = load_state(feature_dir(root, feature_id) / "state.json")
        matches = [item for item in state.get("critical_experiments", {}).get("experiments", []) if item.get("id") == experiment_id]
        if len(matches) != 1:
            raise ValueError("experiment_id is not in the current deterministic critical experiment set")
        experiment = matches[0]
        frontier_matches = [item for item in state.get("risk_frontier", []) if item.get("id") == experiment["frontier_id"]]
        if len(frontier_matches) != 1:
            raise ValueError("critical experiment risk frontier is stale")
        binding = experiment_binding(graph, frontier_matches[0])
        binding_sha256 = value_digest(binding)
        if binding_sha256 != experiment.get("binding_sha256"):
            raise ValueError("critical experiment Proof/Assertion/Environment binding is stale")
        proof_results = [_execute_proof(root, proof) for proof in binding["proofs"]]
        verdict = "PASS" if proof_results and all(item["verdict"] == "PASS" for item in proof_results) else "BLOCKED"
        core = {
            "schema_version": graph["schema_version"], "feature_id": feature_id,
            "experiment_id": experiment_id, "frontier_id": experiment["frontier_id"],
            "frontier_sha256": value_digest(frontier_matches[0]), "graph_sha256": value_digest(graph),
            "binding_sha256": binding_sha256, "recorded_at": timestamp(),
            "verdict": verdict, "proof_results": proof_results,
        }
        source = load_source_revision(feature_dir(root, feature_id), feature_id, graph["source_revision"])
        core["kernel_receipt"] = sign_kernel_receipt(core, source)
        core["record_sha256"] = value_digest(core)
        directory = confined_project_path(root, Path(".dlv") / "experiments" / feature_id, "experiment directory")
        directory.mkdir(parents=True, exist_ok=True)
        destination = directory / f"{experiment_id}-{core['record_sha256'][:12]}.json"
        if destination.exists():
            if load_json(destination) != core:
                raise ValueError("critical experiment content-address collision")
        else:
            atomic_write_json(destination, core)
        compile_graph(root, feature_id, _lock_held=True)
        return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--experiment", required=True)
    args = parser.parse_args(argv)
    try:
        path = record(Path(args.root), args.feature_id, args.experiment)
        value = load_json(path)
        print(f"{value['verdict']}: {path}")
        return 0 if value["verdict"] == "PASS" else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
