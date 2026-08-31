#!/usr/bin/env python3
"""Conservatively migrate schema-v12 delivery bytes to schema v13.

The original tree is archived byte-for-byte. No v12 Prototype, Ready state,
Proof Contract, or Verification result becomes a Product Lock.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import shutil
import stat
import sys
from pathlib import Path
from typing import Any

from delivery_graph import atomic_write_json, compile_graph, confined_project_path, feature_dir, graph_path
from delivery_governance import canonical_source_payload
from delivery_proof import exclusive_file_lock, file_digest, load_json, value_digest
from upgrade_v11_to_v12 import (
    _make_writable_tree,
    _reject_symlinks,
    _remove_tree_at,
    _secure_copy_directory_fds,
    _write_json_at,
)


MUTABLE_FEATURE_FILES = ("state.json", "proof-contract.json", "verification.md", "delivery-manifest.json")


def _mutable_path(root: Path, kind: str, feature_id: str) -> Path:
    return confined_project_path(
        root, Path(".dlv") / kind / feature_id, f"schema-v12 migration {kind} directory",
    )


def _archive_manifest(archive: Path, feature_id: str) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for path in sorted(archive.rglob("*")):
        if path == archive / "manifest.json":
            continue
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("schema-v12 migration archive contains an unsafe entry")
        files.append({
            "path": path.relative_to(archive).as_posix(),
            "sha256": file_digest(path),
            "size": metadata.st_size,
        })
    return {
        "schema_version": 13,
        "kind": "schema-v12-migration-archive",
        "feature_id": feature_id,
        "files": files,
    }


def _validate_archive(archive: Path, feature_id: str) -> None:
    if not archive.is_dir() or archive.is_symlink() or archive.resolve() != archive.absolute():
        raise ValueError("schema-v12 migration archive must be a regular confined directory")
    _reject_symlinks(archive)
    manifest_path = archive / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("schema-v12 migration archive manifest is missing")
    if load_json(manifest_path) != _archive_manifest(archive, feature_id):
        raise ValueError("schema-v12 migration archive manifest is stale or untrusted")


def _tree_identity(directory: Path, *, excluded_roots: set[str] | None = None) -> dict[str, tuple[int, str]]:
    excluded = excluded_roots or set()
    result: dict[str, tuple[int, str]] = {}
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory)
        if relative.parts and relative.parts[0] in excluded:
            continue
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("schema-v12 migration recovery tree contains an unsafe entry")
        result[relative.as_posix()] = (metadata.st_size, file_digest(path))
    return result


def _partial_v13_matches_archive(directory: Path, archive: Path) -> bool:
    archived_graph = load_json(archive / "delivery-graph.json")
    candidate = migrated_graph(archived_graph)
    current_graph = load_json(directory / "delivery-graph.json")
    if current_graph != candidate:
        return False
    archived_sources = archive / "source-revisions"
    for path in sorted(archived_sources.glob("SRC-*.json")):
        current = directory / "source-revisions" / path.name
        if not current.is_file() or load_json(current) != _migrated_source(load_json(path)):
            return False
    ignored = set(MUTABLE_FEATURE_FILES) | {
        "delivery-graph.json", "source-revisions", "prd.md", "architecture-design.md", "code-spec.md",
    }
    current_identity = _tree_identity(directory, excluded_roots={"archive-v12", *ignored})
    archived_identity = _tree_identity(archive, excluded_roots={"manifest.json", "mutable-records", *ignored})
    return current_identity == archived_identity


def _source_only_partial_matches_archive(directory: Path, archive: Path) -> bool:
    if load_json(directory / "delivery-graph.json") != load_json(archive / "delivery-graph.json"):
        return False
    archived_sources = archive / "source-revisions"
    current_sources = directory / "source-revisions"
    if {path.name for path in current_sources.glob("SRC-*.json")} != {path.name for path in archived_sources.glob("SRC-*.json")}:
        return False
    for archived in sorted(archived_sources.glob("SRC-*.json")):
        original = load_json(archived)
        current = load_json(current_sources / archived.name)
        if current not in (original, _migrated_source(original)):
            return False
    ignored = {"archive-v12", "source-revisions"}
    return _tree_identity(directory, excluded_roots=ignored) == _tree_identity(
        archive, excluded_roots={"manifest.json", "mutable-records", "source-revisions"},
    )


def _open_or_create_directory(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)


def _mutable_root_fds(root: Path, kind: str, feature_id: str) -> tuple[int, int, int, int]:
    """Pin every mutable-path ancestor so validation and mutation share one identity."""
    _mutable_path(root, kind, feature_id)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        dlv_fd = _open_or_create_directory(root_fd, ".dlv")
        try:
            kind_fd = _open_or_create_directory(dlv_fd, kind)
            try:
                feature_fd = _open_or_create_directory(kind_fd, feature_id)
            except BaseException:
                os.close(kind_fd)
                raise
        except BaseException:
            os.close(dlv_fd)
            raise
    except BaseException:
        os.close(root_fd)
        raise
    return root_fd, dlv_fd, kind_fd, feature_fd


def _close_fds(*descriptors: int) -> None:
    for descriptor in reversed(descriptors):
        os.close(descriptor)


def _clear_mutable_records(root: Path, feature_id: str) -> None:
    for kind in ("reviews", "findings", "runs"):
        root_fd, dlv_fd, kind_fd, feature_fd = _mutable_root_fds(root, kind, feature_id)
        try:
            for name in os.listdir(feature_fd):
                if kind == "runs" and name == ".feature.lock":
                    continue
                metadata = os.stat(name, dir_fd=feature_fd, follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    _remove_tree_at(feature_fd, name)
                else:
                    os.unlink(name, dir_fd=feature_fd)
            os.fsync(feature_fd)
        finally:
            _close_fds(root_fd, dlv_fd, kind_fd, feature_fd)


def _restore_mutable_records(root: Path, feature_id: str, mutable: Path) -> None:
    for kind in ("reviews", "findings", "runs"):
        source = mutable / kind
        if not source.is_dir():
            continue
        root_fd, dlv_fd, kind_fd, feature_fd = _mutable_root_fds(root, kind, feature_id)
        source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            _secure_copy_directory_fds(source_fd, feature_fd)
            os.fsync(feature_fd)
        finally:
            os.close(source_fd)
            _close_fds(root_fd, dlv_fd, kind_fd, feature_fd)


def _restore_archive(root: Path, feature_id: str, directory: Path, archive: Path) -> None:
    _validate_archive(archive, feature_id)
    for entry in list(directory.iterdir()):
        if entry == archive:
            continue
        shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
    for entry in archive.iterdir():
        if entry.name in {"mutable-records", "manifest.json"}:
            continue
        target = directory / entry.name
        shutil.copytree(entry, target) if entry.is_dir() else shutil.copy2(entry, target)
        _make_writable_tree(target)
    _clear_mutable_records(root, feature_id)
    mutable = archive / "mutable-records"
    _restore_mutable_records(root, feature_id, mutable)


def _apply_migration(root: Path, feature_id: str, directory: Path, candidate: dict[str, Any]) -> None:
    for source_path in sorted((directory / "source-revisions").glob("SRC-*.json")):
        atomic_write_json(source_path, _migrated_source(load_json(source_path)))
    atomic_write_json(graph_path(root, feature_id), candidate)
    for name in MUTABLE_FEATURE_FILES:
        (directory / name).unlink(missing_ok=True)
    _clear_mutable_records(root, feature_id)
    compile_graph(root, feature_id, _lock_held=True)


def migrated_graph(v12: dict[str, Any]) -> dict[str, Any]:
    if v12.get("schema_version") != 12:
        raise ValueError("delivery-graph.json must be schema v12")
    graph = copy.deepcopy(v12)
    graph["schema_version"] = 13
    graph["product_lock"] = None
    prototype = graph.pop("prototype", {"status": "not_applicable", "reason": "No visible UI contract is in scope."})
    if isinstance(prototype, dict) and prototype.get("status") == "not_applicable":
        graph["delivery_prototype"] = {
            "status": "not_applicable",
            "reason": prototype.get("reason") or "Migrated v12 delivery had no UI contract.",
        }
    else:
        graph["delivery_prototype"] = {
            "status": "generated", "path": "prototype.html", "sha256": prototype.get("sha256"),
            "generated_from_revision": graph.get("source_revision"),
            "generator": "v12-migration-untrusted-prototype",
        }
    for node in graph.get("nodes", []):
        if isinstance(node, dict) and node.get("type") in {"Requirement", "Behavior", "Acceptance", "Exception"}:
            node.setdefault("origins", [{"kind": "direct", "source_ref": graph["source_revision"]}])
    metadata = graph.setdefault("metadata", {})
    metadata["upgrade"] = {"from_schema": 12, "completion_claims_promoted": False, "product_lock_promoted": False}
    return graph


def _migrated_source(value: dict[str, Any]) -> dict[str, Any]:
    source = copy.deepcopy(value)
    if source.get("schema_version") != 12:
        raise ValueError("source revision must be schema v12")
    source["schema_version"] = 13
    source["decisions"] = []
    source["source_digest"] = value_digest(canonical_source_payload(source))
    return source


def upgrade(root: Path, feature_id: str, *, apply: bool = False) -> dict[str, Any]:
    root = root.expanduser().resolve()
    directory = feature_dir(root, feature_id)
    graph = load_json(graph_path(root, feature_id))
    if not apply:
        return migrated_graph(graph)
    lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    with exclusive_file_lock(lock):
        graph = load_json(graph_path(root, feature_id))
        archive = directory / "archive-v12"
        if archive.exists():
            _validate_archive(archive, feature_id)
            if graph.get("schema_version") == 13:
                state_path = directory / "state.json"
                if state_path.is_file() and load_json(state_path).get("schema_version") == 13:
                    raise ValueError("feature is already upgraded to schema v13")
                if not _partial_v13_matches_archive(directory, archive):
                    raise ValueError("partial schema-v13 migration contains Owner edits; refusing automatic recovery")
                _restore_archive(root, feature_id, directory, archive)
                shutil.rmtree(archive)
                graph = load_json(graph_path(root, feature_id))
            elif graph.get("schema_version") != 12:
                raise ValueError("current migration state has an unsupported schema")
            else:
                current_identity = _tree_identity(directory, excluded_roots={"archive-v12"})
                archived_identity = _tree_identity(archive, excluded_roots={"manifest.json", "mutable-records"})
                if current_identity != archived_identity:
                    if not _source_only_partial_matches_archive(directory, archive):
                        raise ValueError("current v12 tree diverged from archive-v12; refusing automatic recovery")
                    _restore_archive(root, feature_id, directory, archive)
                    graph = load_json(graph_path(root, feature_id))
                shutil.rmtree(archive)
        candidate = migrated_graph(graph)
        _reject_symlinks(directory)
        for kind in ("reviews", "findings", "runs"):
            source = _mutable_path(root, kind, feature_id)
            if source.exists():
                _reject_symlinks(source)
        staging_parent = confined_project_path(
            root, Path(".dlv") / "upgrades" / feature_id, "schema-v12 migration staging directory",
        )
        staging_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        staging_parent = confined_project_path(
            root, staging_parent.relative_to(root), "schema-v12 migration staging directory",
        )
        staging_name = "archive-v12.staging"
        parent_fd = os.open(staging_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        staging_fd: int | None = None
        mutable_fd: int | None = None
        archive_promoted = False
        try:
            _remove_tree_at(parent_fd, staging_name)
            os.mkdir(staging_name, 0o700, dir_fd=parent_fd)
            staging_fd = os.open(staging_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            _secure_copy_directory_fds(directory_fd, staging_fd)
            os.mkdir("mutable-records", 0o700, dir_fd=staging_fd)
            mutable_fd = os.open("mutable-records", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=staging_fd)
            for kind in ("reviews", "findings", "runs"):
                source = _mutable_path(root, kind, feature_id)
                if not source.exists():
                    continue
                source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.mkdir(kind, 0o700, dir_fd=mutable_fd)
                    target_fd = os.open(kind, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=mutable_fd)
                    try:
                        _secure_copy_directory_fds(source_fd, target_fd)
                        if kind == "runs":
                            try:
                                os.unlink(".feature.lock", dir_fd=target_fd)
                            except FileNotFoundError:
                                pass
                    finally:
                        os.close(target_fd)
                finally:
                    os.close(source_fd)
            os.close(mutable_fd)
            mutable_fd = None
            staging_path = staging_parent / staging_name
            _write_json_at(staging_fd, "manifest.json", _archive_manifest(staging_path, feature_id))
            os.fsync(staging_fd)
            os.rename(staging_name, "archive-v12", src_dir_fd=parent_fd, dst_dir_fd=directory_fd)
            archive_promoted = True
            os.fsync(directory_fd)
        except BaseException:
            _remove_tree_at(parent_fd, staging_name)
            if archive_promoted:
                _remove_tree_at(directory_fd, "archive-v12")
            raise
        finally:
            if mutable_fd is not None:
                os.close(mutable_fd)
            if staging_fd is not None:
                os.close(staging_fd)
            os.close(directory_fd)
            os.close(parent_fd)
        try:
            _apply_migration(root, feature_id, directory, candidate)
        except BaseException:
            _restore_archive(root, feature_id, directory, archive)
            shutil.rmtree(archive)
            raise
    return candidate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(upgrade(Path(args.root), args.feature_id, apply=args.apply), ensure_ascii=False, indent=2, sort_keys=True))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
