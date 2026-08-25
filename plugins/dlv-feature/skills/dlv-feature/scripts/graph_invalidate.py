#!/usr/bin/env python3
"""Dependency-scoped invalidation for schema-v10 Delivery Graph features."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from delivery_graph import (
    atomic_write_json,
    compile_graph,
    confined_project_path,
    feature_dir,
    impact_closure,
    load_graph,
    load_state,
    node_hashes,
    review_units,
)
from delivery_proof import exclusive_file_lock, repository_fingerprint


def invalidate(
    root: Path, feature_id: str, changed_nodes: list[str] | None = None,
    reset_reviews: bool = False,
) -> str:
    root = root.expanduser().resolve()
    directory = feature_dir(root, feature_id)
    state_path = directory / "state.json"
    graph = load_graph(root, feature_id)
    before = load_state(state_path)
    current_hashes = node_hashes(graph)
    detected = {
        node_id for node_id in set(before.get("node_hashes", {})) | set(current_hashes)
        if before.get("node_hashes", {}).get(node_id) != current_hashes.get(node_id)
    }
    requested = set(changed_nodes or [])
    unknown = requested - (set(current_hashes) | set(before.get("node_hashes", {})))
    if unknown:
        raise ValueError("changed-node references unknown IDs: " + ", ".join(sorted(unknown)))
    changed = detected | requested
    impacted = impact_closure(graph, changed & set(current_hashes)) | (changed - set(current_hashes))
    old_attestations = set(before.get("attestations", {}))
    if requested and impacted:
        lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
        with exclusive_file_lock(lock):
            before = load_state(state_path)
            units = review_units(graph)
            before["attestations"] = {
                unit_id: summary for unit_id, summary in before.get("attestations", {}).items()
                if unit_id in units and not (set(units[unit_id]["node_ids"]) & impacted)
            }
            atomic_write_json(state_path, before)
    if reset_reviews:
        lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
        with exclusive_file_lock(lock):
            before = load_state(state_path)
            before["attestations"] = {}
            atomic_write_json(state_path, before)
    state = compile_graph(root, feature_id)
    invalidated = old_attestations - set(state.get("attestations", {}))
    # Source changes after Code completion invalidate only Code and runtime
    # claims. Graph reviews and the sealed plan remain reusable.
    if state.get("code", {}).get("status") == "completed":
        current_code = repository_fingerprint(root, feature_id)
        if state["code"].get("repository_fingerprint") != current_code:
            lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
            with exclusive_file_lock(lock):
                state = load_state(state_path)
                state["code"] = {"status": "stale", "repository_fingerprint": None}
                state["verification"] = {
                    "status": "pending", "active_run_id": None, "run_digest": None,
                    "verdict": None, "finalization": None,
                }
                atomic_write_json(state_path, state)
    return (
        f"changed=[{', '.join(sorted(changed))}] impacted=[{', '.join(sorted(impacted))}] "
        f"invalidated_attestations=[{', '.join(sorted(invalidated))}]"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--changed-node", action="append", default=[])
    parser.add_argument("--all-reviews", action="store_true", help="Explicitly discard every semantic review unit")
    args = parser.parse_args(argv)
    try:
        print(invalidate(Path(args.root), args.feature_id, args.changed_node, args.all_reviews))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
