#!/usr/bin/env python3
"""Capture and confirm immutable schema-v12 Scope Revisions.

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

from delivery_governance import create_source_revision, load_source_revision, source_dir, source_path
from delivery_graph import atomic_write_json, feature_dir, load_graph, node_map
from delivery_proof import exclusive_file_lock, load_json
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
    lock = root / ".dlv" / "runs" / feature_id / ".feature.lock"
    with exclusive_file_lock(lock):
        revision_id = _next_revision_id(directory)
        return create_source_revision(directory, feature_id, revision_id, source, owner=owner, status="pending_confirmation")


def confirm(root: Path, feature_id: str, revision_id: str, owner: str, affected_nodes: list[str]) -> str:
    root = root.expanduser().resolve()
    directory = feature_dir(root, feature_id)
    graph_path = directory / "delivery-graph.json"
    lock = root / ".dlv" / "runs" / feature_id / ".feature.lock"
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
        revision["status"] = "confirmed"
        revision["owner"] = owner
        # Owner confirmation is metadata, not source content; source_digest remains immutable.
        atomic_write_json(revision_path, revision)
        graph["source_revision"] = revision_id
        atomic_write_json(graph_path, graph)
        # A listed impact retains unrelated evidence. No impact declaration
        # means scope has changed but is not yet mapped, so discard claims.
        # Keep the complete epoch switch and invalidation in one lock-held
        # transaction so another actor cannot observe a half-confirmed scope.
        return invalidate(
            root, feature_id, affected_nodes or None,
            reset_reviews=not affected_nodes, _lock_held=True,
        )


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
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            print(capture(Path(args.root), args.feature_id, Path(args.source), args.owner))
        else:
            print(confirm(Path(args.root), args.feature_id, args.revision, args.owner, args.affected_node))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
