#!/usr/bin/env python3
"""Conservatively migrate a schema-v10 Delivery Graph to schema v11.

The migration never rewrites prior reviews, Proofs, runs, or evidence.  It
archives the mutable v10 delivery artifacts byte-for-byte, starts a new Source
Revision epoch, and deliberately drops old completion claims because their
review contracts did not bind the v11 governance records.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from delivery_governance import create_source_revision
from delivery_graph import atomic_write_json, compile_graph, confined_project_path, feature_dir
from delivery_proof import exclusive_file_lock, file_digest, load_json


ARCHIVE_FILES = (
    "delivery-graph.json", "state.json", "prd.md", "architecture-design.md", "code-spec.md",
    "proof-contract.json", "verification.md", "prototype.html",
)


def _archive_copy(source: Path, target: Path) -> str:
    """Archive one regular artifact atomically and verify its exact bytes."""
    if not source.is_file() or source.is_symlink() or source.resolve() != source.absolute():
        raise ValueError(f"schema-v10 artifact must be a regular non-symlink file: {source.name}")
    digest = file_digest(source)
    if target.exists() or target.is_symlink():
        if not target.is_file() or target.is_symlink() or target.resolve() != target.absolute() or file_digest(target) != digest:
            raise ValueError(f"schema-v10 archive diverges: {source.name}")
        return digest
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(source.read_bytes())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    if not target.is_file() or target.is_symlink() or target.resolve() != target.absolute() or file_digest(target) != digest:
        target.unlink(missing_ok=True)
        raise ValueError(f"schema-v10 archive byte verification failed: {source.name}")
    return digest


def _v11_graph(v10: dict[str, object]) -> dict[str, object]:
    graph = dict(v10)
    graph["schema_version"] = 11
    graph["source_revision"] = "SRC-001"
    prototype = graph.get("prototype")
    if isinstance(prototype, dict) and prototype.get("status") == "completed":
        graph["prototype"] = {"status": "contractual", "path": "prototype.html", "sha256": prototype.get("sha256")}
    elif not isinstance(prototype, dict) or prototype.get("status") == "not_applicable":
        graph["prototype"] = {"status": "not_applicable", "reason": "Migrated v10 delivery had no contractual Prototype."}
    graph["metadata"] = {"risk_vector": {}}
    return graph


def upgrade(root: Path, feature_id: str, *, apply: bool) -> dict[str, object]:
    root = root.expanduser().resolve()
    directory = feature_dir(root, feature_id)
    graph_path = directory / "delivery-graph.json"
    if not graph_path.is_file() or graph_path.is_symlink() or graph_path.resolve() != graph_path.absolute():
        raise ValueError("schema-v10 delivery graph must be a regular, non-symlink file")
    graph = load_json(graph_path)
    if graph.get("schema_version") != 10 or graph.get("feature_id") != feature_id:
        raise ValueError("only schema_version=10 for this feature can be upgraded")
    candidate = _v11_graph(graph)
    if not apply:
        return candidate
    lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    with exclusive_file_lock(lock):
        current = load_json(graph_path)
        if current != graph:
            raise ValueError("schema-v10 Delivery Graph changed before migration; retry")
        archive = confined_project_path(root, Path(".dlv") / "upgrades" / feature_id / "schema-v10-archive", "v10 archive")
        archive.mkdir(parents=True, exist_ok=True)
        manifest: dict[str, str] = {}
        for name in ARCHIVE_FILES:
            source = directory / name
            if not source.exists() and not source.is_symlink():
                continue
            target = archive / name
            manifest[name] = _archive_copy(source, target)
        atomic_write_json(archive / "manifest.json", {"feature_id": feature_id, "schema_version": 10, "artifacts": manifest})
        create_source_revision(
            directory, feature_id, "SRC-001",
            {
                "title": str(graph.get("title", feature_id)),
                "description": "Migrated schema-v10 delivery source. Reconcile the graph before claiming readiness.",
                "comments": [], "attachments": [], "risk_vector": {},
            },
            owner="schema-v10-migration", status="confirmed",
        )
        atomic_write_json(graph_path, candidate)
        # v10 attestations/proof seals remain archived historical evidence and
        # cannot be promoted into a v11 Source/Finding/Risk contract.
        atomic_write_json(directory / "state.json", {})
        compile_graph(root, feature_id, _lock_held=True)
    return candidate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        value = upgrade(Path(args.root), args.feature_id, apply=args.apply)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
