#!/usr/bin/env python3
"""Compatibility importer: migrate a schema-v10 Delivery Graph to schema v12.

The migration never rewrites prior reviews, Proofs, runs, or evidence.  It
archives the mutable v10 delivery artifacts byte-for-byte, starts a new Source
Revision epoch, and deliberately drops old completion claims because their
review contracts did not bind the v12 governance records.
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
from upgrade_v11_to_v12 import migrated_graph


ARCHIVE_FILES = (
    "delivery-graph.json", "state.json", "prd.md", "architecture-design.md", "code-spec.md",
    "proof-contract.json", "verification.md", "prototype.html", "source-revisions/SRC-001.json",
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


def _atomic_restore(path: Path, content: bytes) -> None:
    """Restore one archived file without exposing a partial rollback."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.restore.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _validated_manifest(archive: Path, feature_id: str) -> dict[str, str]:
    manifest_path = archive / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("schema-v10 archive manifest is missing")
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict) or set(manifest) != {"feature_id", "schema_version", "artifacts"}:
        raise ValueError("schema-v10 archive manifest is invalid")
    artifacts = manifest.get("artifacts")
    if manifest.get("feature_id") != feature_id or manifest.get("schema_version") != 10 or not isinstance(artifacts, dict):
        raise ValueError("schema-v10 archive identity is invalid")
    if set(artifacts) - set(ARCHIVE_FILES) or any(
        not isinstance(digest, str) or len(digest) != 64 for digest in artifacts.values()
    ):
        raise ValueError("schema-v10 archive artifact map is invalid")
    for name, digest in artifacts.items():
        path = archive / name
        if not path.is_file() or path.is_symlink() or path.resolve() != path.absolute() or file_digest(path) != digest:
            raise ValueError(f"schema-v10 archive diverges: {name}")
    return artifacts


def _restore_archive(directory: Path, archive: Path, manifest: dict[str, str]) -> None:
    for name in ARCHIVE_FILES:
        target = directory / name
        archived = archive / name
        if name in manifest:
            _atomic_restore(target, archived.read_bytes())
        else:
            target.unlink(missing_ok=True)
    source_directory = directory / "source-revisions"
    try:
        source_directory.rmdir()
    except OSError:
        pass


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
        if not apply:
            raise ValueError("only schema_version=10 for this feature can be upgraded")
    candidate = migrated_graph(_v11_graph(graph)) if graph.get("schema_version") == 10 else {}
    if not apply:
        return candidate
    lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    with exclusive_file_lock(lock):
        current = load_json(graph_path)
        archive = confined_project_path(root, Path(".dlv") / "upgrades" / feature_id / "schema-v10-archive", "v10 archive")
        manifest_path = archive / "manifest.json"
        if manifest_path.is_file():
            manifest = _validated_manifest(archive, feature_id)
            archived_graph = load_json(archive / "delivery-graph.json")
            archived_candidate = migrated_graph(_v11_graph(archived_graph))
            state = load_json(directory / "state.json") if (directory / "state.json").is_file() else {}
            source = load_json(directory / "source-revisions/SRC-001.json") if (directory / "source-revisions/SRC-001.json").is_file() else {}
            if current == archived_candidate and state.get("schema_version") == 12 and source.get("schema_version") == 12:
                return archived_candidate
            if current.get("schema_version") == 10:
                current_artifacts = {
                    name: file_digest(directory / name)
                    for name in ARCHIVE_FILES
                    if (directory / name).is_file() and not (directory / name).is_symlink()
                }
                if current != archived_graph or current_artifacts != manifest:
                    raise ValueError("schema-v10 delivery truth diverged after archive creation; preserve Owner edits")
            elif current.get("schema_version") == 12:
                raise ValueError("partial schema-v12 recovery is not automatic; preserve Owner edits and use a future versioned recovery")
            else:
                raise ValueError("schema-v10 migration state is unsupported")
        if current.get("schema_version") != 10 or current.get("feature_id") != feature_id:
            raise ValueError("only schema_version=10 for this feature can be upgraded")
        graph = current
        candidate = migrated_graph(_v11_graph(graph))
        archive.mkdir(parents=True, exist_ok=True)
        manifest: dict[str, str] = {}
        for name in ARCHIVE_FILES:
            source = directory / name
            if not source.exists() and not source.is_symlink():
                continue
            target = archive / name
            manifest[name] = _archive_copy(source, target)
        atomic_write_json(archive / "manifest.json", {"feature_id": feature_id, "schema_version": 10, "artifacts": manifest})
        source_path = directory / "source-revisions" / "SRC-001.json"
        source_before = source_path.read_bytes() if source_path.is_file() and not source_path.is_symlink() else None
        if source_path.exists() and source_before is None:
            raise ValueError("schema-v10 Source Revision target must be absent or a regular file")
        try:
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
            # cannot be promoted into a v12 Source/Claim/Finding/Proof contract.
            atomic_write_json(directory / "state.json", {})
            compile_graph(root, feature_id, _lock_held=True)
        except BaseException:
            _restore_archive(directory, archive, manifest)
            raise
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
