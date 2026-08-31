#!/usr/bin/env python3
"""Capture, confirm, and resolve immutable schema-v13 Source Revisions.

Capture records new issue text/comments/attachments without editing the Delivery
Graph.  Confirmation is the explicit Owner decision that begins a new scope
epoch; it invalidates exactly declared affected nodes, or conservatively all
attestations when the impact is not yet known.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from delivery_governance import DECISION_REASONS, create_source_revision, load_source_revision, source_dir, source_path
from delivery_graph import atomic_write_json, confined_project_path, feature_dir, load_graph, node_map
from delivery_proof import atomic_write_text, exclusive_file_lock, load_json
from graph_invalidate import invalidate


def _next_revision_id(directory: Path) -> str:
    numbers = [
        int(path.stem.removeprefix("SRC-")) for path in source_dir(directory).glob("SRC-*.json")
        if path.stem.removeprefix("SRC-").isdigit()
    ]
    return f"SRC-{max(numbers, default=0) + 1:03d}"


def capture(root: Path, feature_id: str, source_file: Path, owner: str) -> Path:
    root = root.expanduser().resolve()
    directory = feature_dir(root, feature_id)
    source_file = source_file.expanduser()
    if source_file.is_symlink() or not source_file.is_file():
        raise ValueError("source input must be a regular, non-symlink JSON file")
    source_file = source_file.resolve()
    source = load_json(source_file)
    lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    with exclusive_file_lock(lock):
        revision_id = _next_revision_id(directory)
        return create_source_revision(directory, feature_id, revision_id, source, owner=owner, status="pending_confirmation")


def confirm(root: Path, feature_id: str, revision_id: str, owner: str, affected_nodes: list[str]) -> str:
    root = root.expanduser().resolve()
    directory = feature_dir(root, feature_id)
    graph_path = directory / "delivery-graph.json"
    lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    with exclusive_file_lock(lock):
        revision_path = source_path(directory, revision_id)
        revision = load_source_revision(directory, feature_id, revision_id)
        if revision["status"] != "pending_confirmation":
            raise ValueError("only a pending source revision can be confirmed")
        if not isinstance(owner, str) or not owner.strip():
            raise ValueError("confirmation owner must be non-empty")
        graph = load_graph(root, feature_id)
        unknown = set(affected_nodes) - set(node_map(graph))
        if unknown:
            raise ValueError("affected-node references unknown IDs: " + ", ".join(sorted(unknown)))
        original_revision = revision_path.read_text(encoding="utf-8")
        original_graph = graph_path.read_text(encoding="utf-8")
        revision["status"] = "confirmed"
        revision["owner"] = owner
        # Owner confirmation is metadata, not source content; source_digest remains immutable.
        expected_revision = json.dumps(revision, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        graph["source_revision"] = revision_id
        expected_graph = json.dumps(graph, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        try:
            atomic_write_json(revision_path, revision)
            atomic_write_json(graph_path, graph)
            # A listed impact retains unrelated evidence. No impact declaration
            # means scope has changed but is not yet mapped, so discard claims.
            return invalidate(
                root, feature_id, affected_nodes or None,
                reset_reviews=not affected_nodes, _lock_held=True,
            )
        except BaseException:
            if revision_path.read_text(encoding="utf-8") == expected_revision:
                atomic_write_text(revision_path, original_revision)
            if graph_path.read_text(encoding="utf-8") == expected_graph:
                atomic_write_text(graph_path, original_graph)
            raise


def resolve(
    root: Path, feature_id: str, decision_id: str, question: str, answer: str,
    reason: str, owner: str, affected_nodes: list[str],
) -> str:
    """Record one precise Owner answer as a new confirmed source epoch."""
    root = root.expanduser().resolve()
    directory = feature_dir(root, feature_id)
    lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    with exclusive_file_lock(lock):
        if reason not in DECISION_REASONS:
            raise ValueError("Owner decision reason must be ambiguity, degradation, conflict, new_scope, unmapped, or platform_limitation")
        graph_file = directory / "delivery-graph.json"
        graph = load_graph(root, feature_id)
        unknown = set(affected_nodes) - set(node_map(graph))
        if unknown:
            raise ValueError("affected-node references unknown IDs: " + ", ".join(sorted(unknown)))
        current = load_source_revision(directory, feature_id, graph["source_revision"])
        decision = {
            "id": decision_id, "question": question, "answer": answer,
            "reason": reason, "decided_by": owner,
        }
        source = {
            "title": current["title"], "description": current["description"],
            "comments": current["comments"],
            "attachments": [item for item in current["attachments"] if item.get("kind") != "convergence_authority"],
            "decisions": [*current.get("decisions", []), decision],
            "risk_vector": current["risk_vector"],
        }
        revision_id = _next_revision_id(directory)
        original_graph = graph_file.read_text(encoding="utf-8")
        revision_path = create_source_revision(directory, feature_id, revision_id, source, owner=owner, status="confirmed")
        revision_content = revision_path.read_text(encoding="utf-8")
        graph["source_revision"] = revision_id
        for node in graph.get("nodes", []):
            if not isinstance(node, dict):
                continue
            for origin in node.get("origins", []):
                if (
                    isinstance(origin, dict) and origin.get("kind") == "direct"
                    and origin.get("source_ref") == current["revision_id"]
                ):
                    origin["source_ref"] = revision_id
        expected_graph = json.dumps(graph, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        try:
            atomic_write_json(graph_file, graph)
            return invalidate(root, feature_id, affected_nodes or None, reset_reviews=True, _lock_held=True)
        except BaseException:
            if graph_file.read_text(encoding="utf-8") == expected_graph:
                atomic_write_text(graph_file, original_graph)
            if revision_path.is_file() and revision_path.read_text(encoding="utf-8") == revision_content:
                revision_path.unlink()
            raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    commands = parser.add_subparsers(dest="command", required=True)
    capture_parser = commands.add_parser("capture")
    capture_parser.add_argument("--source", required=True)
    capture_parser.add_argument("--owner", required=True)
    confirm_parser = commands.add_parser("confirm")
    confirm_parser.add_argument("--revision", required=True)
    confirm_parser.add_argument("--owner", required=True)
    confirm_parser.add_argument("--affected-node", action="append", default=[])
    resolve_parser = commands.add_parser("resolve")
    resolve_parser.add_argument("--decision-id", required=True)
    resolve_parser.add_argument("--question", required=True)
    resolve_parser.add_argument("--answer", required=True)
    resolve_parser.add_argument("--reason", required=True)
    resolve_parser.add_argument("--owner", required=True)
    resolve_parser.add_argument("--affected-node", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            print(capture(Path(args.root), args.feature_id, Path(args.source), args.owner))
        elif args.command == "confirm":
            print(confirm(Path(args.root), args.feature_id, args.revision, args.owner, args.affected_node))
        else:
            print(resolve(
                Path(args.root), args.feature_id, args.decision_id, args.question, args.answer,
                args.reason, args.owner, args.affected_node,
            ))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
