#!/usr/bin/env python3
"""Conservatively migrate schema-v11 delivery truth to schema v12.

Source Revision and graph semantics are preserved. Mutable v11 reviews,
findings, Proof Contracts, and Verification runs are archived and never
promoted into v12 PASS/Ready claims.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import stat
import sys
import secrets
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from delivery_contracts import CLAIM_LENSES, claim_id_for, review_budget
from delivery_governance import _source_convergence_attachment, canonical_source_payload
from delivery_graph import atomic_write_json, compile_graph, confined_project_path, feature_dir, graph_path
from delivery_proof import exclusive_file_lock, file_digest, load_json, value_digest


MUTABLE_FEATURE_FILES = ("state.json", "proof-contract.json", "verification.md")


def _claim_for(graph: dict[str, Any], lens: str, types: set[str]) -> dict[str, Any] | None:
    subjects = sorted(
        node["id"] for node in graph.get("nodes", [])
        if isinstance(node, dict) and node.get("type") in types
    )
    if not subjects:
        return None
    value = {
        "lens": lens,
        "invariant": f"Migrated v11 {lens.lower()} semantics remain explicit and require fresh proof",
        "subjects": subjects,
        "failure_boundary": "v11 migration boundary",
        "critical": True,
        "proof_ids": [],
    }
    return {"id": claim_id_for(value), **value}


def migrated_graph(v11: dict[str, Any]) -> dict[str, Any]:
    if v11.get("schema_version") != 11:
        raise ValueError("delivery-graph.json must be schema v11")
    graph = copy.deepcopy(v11)
    graph["schema_version"] = 12
    graph["claim_successions"] = []
    lens_types = {
        "PROVENANCE_INTEGRITY": {"Requirement", "Behavior", "Acceptance", "Exception", "Persona"},
        "STATE_AND_ATOMICITY": {"Fact", "Owner", "StateTransition", "Decision", "Risk"},
        "BOUNDARY_AND_CONCURRENCY": {"Boundary", "StateTransition", "Exception", "Risk", "Change", "Symbol"},
        "RUNTIME_AUTHENTICITY": {"Test", "Environment", "Proof", "Assertion", "Acceptance", "Exception"},
    }
    graph["claims"] = [claim for lens in CLAIM_LENSES if (claim := _claim_for(graph, lens, lens_types[lens]))]
    prototype = graph.get("prototype")
    if isinstance(prototype, dict) and prototype.get("status") in {"reference", "contractual"}:
        graph["prototype"] = {
            "status": "generated_candidate",
            "path": "prototype.html",
            "sha256": prototype.get("sha256"),
            "generated_from_revision": graph.get("source_revision"),
            "generator": "v11-migration-unverified-provenance",
        }
    metadata = graph.setdefault("metadata", {})
    metadata["review_budget"] = review_budget({"metadata": {}})
    metadata["delivery_mode"] = "standard"
    metadata["upgrade"] = {"from_schema": 11, "completion_claims_promoted": False}
    return graph


def _reject_symlinks(path: Path) -> None:
    root_metadata = path.lstat()
    candidates = [path, *path.rglob("*")] if stat.S_ISDIR(root_metadata.st_mode) else [path]
    for candidate in candidates:
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"schema-v11 migration source must not contain symlinks: {candidate}")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"schema-v11 migration source must contain only regular files/directories: {candidate}")
        if metadata.st_nlink > 1:
            raise ValueError(f"schema-v11 migration source must not contain hard-linked files: {candidate}")


def _same_entry(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev, left.st_ino, stat.S_IFMT(left.st_mode), left.st_nlink, left.st_size,
        left.st_mtime_ns, left.st_ctime_ns,
    ) == (
        right.st_dev, right.st_ino, stat.S_IFMT(right.st_mode), right.st_nlink, right.st_size,
        right.st_mtime_ns, right.st_ctime_ns,
    )


def _secure_copy_directory_fd(source_fd: int, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    for name in sorted(os.listdir(source_fd)):
        before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        target = destination / name
        if stat.S_ISDIR(before.st_mode):
            child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source_fd)
            try:
                if not _same_entry(before, os.fstat(child_fd)):
                    raise ValueError("schema-v11 migration source changed during secure snapshot")
                _secure_copy_directory_fd(child_fd, target)
                if not _same_entry(before, os.fstat(child_fd)):
                    raise ValueError("schema-v11 migration directory changed during secure snapshot")
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("schema-v11 migration source must contain only single-linked regular files/directories")
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_fd)
        try:
            if not _same_entry(before, os.fstat(file_fd)):
                raise ValueError("schema-v11 migration source changed during secure snapshot")
            target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            try:
                while chunk := os.read(file_fd, 1024 * 1024):
                    view = memoryview(chunk)
                    while view:
                        written = os.write(target_fd, view)
                        if written <= 0:
                            raise OSError("secure archive snapshot write made no progress")
                        view = view[written:]
                os.fsync(target_fd)
            finally:
                os.close(target_fd)
            if not _same_entry(before, os.fstat(file_fd)):
                raise ValueError("schema-v11 migration file changed during secure snapshot")
        finally:
            os.close(file_fd)


def _secure_copy_directory_fds(source_fd: int, destination_fd: int) -> None:
    """Copy a tree using pinned directory descriptors for both sides."""
    for name in sorted(os.listdir(source_fd)):
        before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        if stat.S_ISDIR(before.st_mode):
            source_child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source_fd)
            try:
                os.mkdir(name, 0o700, dir_fd=destination_fd)
                destination_child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=destination_fd)
                try:
                    if not _same_entry(before, os.fstat(source_child)):
                        raise ValueError("schema-v11 migration source changed during secure snapshot")
                    _secure_copy_directory_fds(source_child, destination_child)
                    if not _same_entry(before, os.fstat(source_child)):
                        raise ValueError("schema-v11 migration directory changed during secure snapshot")
                    os.fsync(destination_child)
                finally:
                    os.close(destination_child)
            finally:
                os.close(source_child)
            continue
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("schema-v11 migration source must contain only single-linked regular files/directories")
        source_file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_fd)
        try:
            destination_file = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=destination_fd,
            )
            try:
                if not _same_entry(before, os.fstat(source_file)):
                    raise ValueError("schema-v11 migration source changed during secure snapshot")
                while chunk := os.read(source_file, 1024 * 1024):
                    view = memoryview(chunk)
                    while view:
                        written = os.write(destination_file, view)
                        if written <= 0:
                            raise OSError("secure archive snapshot write made no progress")
                        view = view[written:]
                os.fsync(destination_file)
                if not _same_entry(before, os.fstat(source_file)):
                    raise ValueError("schema-v11 migration file changed during secure snapshot")
            finally:
                os.close(destination_file)
        finally:
            os.close(source_file)


def _fd_manifest(directory_fd: int, feature_id: str, prefix: str = "") -> dict[str, Any]:
    files: list[dict[str, Any]] = []

    def walk(current_fd: int, current_prefix: str) -> None:
        for name in sorted(os.listdir(current_fd)):
            if not current_prefix and name == "manifest.json":
                continue
            metadata = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
            relative = f"{current_prefix}/{name}" if current_prefix else name
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current_fd)
                try:
                    walk(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current_fd)
                digest = hashlib.sha256()
                size = 0
                try:
                    while chunk := os.read(descriptor, 1024 * 1024):
                        digest.update(chunk)
                        size += len(chunk)
                finally:
                    os.close(descriptor)
                files.append({"path": relative, "sha256": digest.hexdigest(), "size": size})
            else:
                raise ValueError("schema-v11 migration archive contains an unsafe entry")

    walk(directory_fd, prefix)
    return {
        "schema_version": 12,
        "kind": "schema-v11-migration-archive",
        "feature_id": feature_id,
        "files": sorted(files, key=lambda item: item["path"]),
    }


def _write_json_at(directory_fd: int, name: str, value: Any) -> None:
    content = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=directory_fd)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("migration manifest write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_tree_at(parent_fd: int, name: str) -> None:
    try:
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    try:
        for entry in os.listdir(child):
            metadata = os.stat(entry, dir_fd=child, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                _remove_tree_at(child, entry)
            else:
                os.unlink(entry, dir_fd=child)
    finally:
        os.close(child)
    os.rmdir(name, dir_fd=parent_fd)


def _secure_copy_tree(source: Path, destination: Path) -> None:
    source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _secure_copy_directory_fd(source_fd, destination)
    finally:
        os.close(source_fd)


def _make_read_only_tree(path: Path) -> None:
    for entry in sorted(path.rglob("*"), reverse=True):
        entry.chmod(0o500 if entry.is_dir() else 0o400)
    path.chmod(0o500)


def _make_writable_tree(path: Path) -> None:
    if path.is_file():
        path.chmod(0o600)
        return
    for entry in path.rglob("*"):
        entry.chmod(0o700 if entry.is_dir() else 0o600)
    path.chmod(0o700)


@contextmanager
def _private_archive_snapshot(root: Path, archive: Path, feature_id: str):
    parent = confined_project_path(
        root, Path(".dlv") / "upgrades" / feature_id / ".archive-snapshots",
        "schema-v11 private archive snapshot directory",
    )
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = confined_project_path(
        root, parent.relative_to(root), "schema-v11 private archive snapshot directory",
    )
    parent.chmod(0o700)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    name = f"{feature_id}-{secrets.token_hex(16)}"
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    temporary = parent / name
    if temporary.resolve().parent != parent.resolve():
        raise ValueError("schema-v11 private archive snapshot escaped its confined parent")
    snapshot = temporary / "archive"
    try:
        _secure_copy_tree(archive, snapshot)
        _validate_archive(snapshot, feature_id)
        _make_read_only_tree(snapshot)
        yield snapshot
    finally:
        if temporary.exists():
            for entry in temporary.rglob("*"):
                if entry.is_dir():
                    entry.chmod(0o700)
            temporary.chmod(0o700)
            shutil.rmtree(temporary)


def _archive_manifest(archive: Path, feature_id: str) -> dict[str, Any]:
    files = [path for path in archive.rglob("*") if path.is_file() and path != archive / "manifest.json"]
    return {
        "schema_version": 12,
        "kind": "schema-v11-migration-archive",
        "feature_id": feature_id,
        "files": [
            {
                "path": path.relative_to(archive).as_posix(),
                "sha256": file_digest(path),
                "size": path.stat().st_size,
            }
            for path in sorted(files)
        ],
    }


def _tree_file_identity(path: Path, *, excluded_roots: set[str] | None = None) -> dict[str, tuple[int, str]]:
    if not path.is_dir():
        return {}
    excluded = excluded_roots or set()
    result: dict[str, tuple[int, str]] = {}
    for candidate in sorted(path.rglob("*")):
        relative = candidate.relative_to(path)
        if relative.as_posix() == ".feature.lock":
            continue
        if relative.parts and relative.parts[0] in excluded:
            continue
        if candidate.is_symlink():
            raise ValueError("migration recovery identity must not contain symlinks")
        if candidate.is_file():
            result[relative.as_posix()] = (candidate.stat().st_size, file_digest(candidate))
    return result


def _validate_archive(archive: Path, feature_id: str) -> None:
    if not archive.is_dir() or archive.is_symlink() or archive.resolve() != archive.absolute():
        raise ValueError("schema-v11 migration archive must be a regular confined directory")
    _reject_symlinks(archive)
    manifest_path = archive / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("schema-v11 migration archive manifest is missing")
    manifest = load_json(manifest_path)
    if manifest != _archive_manifest(archive, feature_id):
        raise ValueError("schema-v11 migration archive manifest is stale or untrusted")


def _restore_archive(root: Path, feature_id: str, directory: Path, archive: Path) -> None:
    """Rollback a failed apply from the complete byte archive."""
    _validate_archive(archive, feature_id)
    for entry in list(directory.iterdir()):
        if entry == archive or entry.name == "archive-v11":
            continue
        if entry.is_dir():
            shutil.rmtree(entry)
        else:
            entry.unlink()
    for entry in archive.iterdir():
        if entry.name in {"mutable-records", "manifest.json"}:
            continue
        target = directory / entry.name
        if entry.is_dir():
            shutil.copytree(entry, target)
        else:
            shutil.copy2(entry, target)
        _make_writable_tree(target)
    mutable = archive / "mutable-records"
    for kind in ("reviews", "findings", "runs"):
        target = root / ".dlv" / kind / feature_id
        if kind == "runs":
            target.mkdir(parents=True, exist_ok=True)
            for entry in list(target.iterdir()):
                if entry.name == ".feature.lock":
                    continue
                shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
        elif target.exists():
            shutil.rmtree(target)
        source = mutable / kind
        if source.is_dir():
            target.parent.mkdir(parents=True, exist_ok=True)
            if kind == "runs":
                for entry in source.iterdir():
                    if entry.name == ".feature.lock":
                        continue
                    shutil.copytree(entry, target / entry.name) if entry.is_dir() else shutil.copy2(entry, target / entry.name)
            else:
                shutil.copytree(source, target)
            _make_writable_tree(target)


def _apply_archived_migration(root: Path, feature_id: str, directory: Path, archive: Path, migrated: dict[str, Any]) -> None:
    _validate_archive(archive, feature_id)
    archived_sources = archive / "source-revisions"
    for path in archived_sources.glob("SRC-*.json") if archived_sources.is_dir() else ():
        source = load_json(path)
        if source.get("schema_version") != 11:
            raise ValueError(f"Source Revision is not schema v11: {path.name}")
        source["schema_version"] = 12
        if not any(item.get("kind") == "convergence_authority" for item in source.get("attachments", [])):
            source["attachments"] = [
                *source.get("attachments", []),
                _source_convergence_attachment(directory, feature_id),
            ]
            source["source_digest"] = value_digest(canonical_source_payload(source))
        atomic_write_json(directory / "source-revisions" / path.name, source)
    for name in MUTABLE_FEATURE_FILES:
        (directory / name).unlink(missing_ok=True)
    for kind in ("reviews", "findings", "runs"):
        target = root / ".dlv" / kind / feature_id
        if kind == "runs":
            target.mkdir(parents=True, exist_ok=True)
            for entry in list(target.iterdir()):
                if entry.name == ".feature.lock":
                    continue
                shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
        elif target.exists():
            shutil.rmtree(target)
    atomic_write_json(graph_path(root, feature_id), migrated)
    compile_graph(root, feature_id, _lock_held=True)


def upgrade(root: Path, feature_id: str, *, apply: bool) -> dict[str, Any]:
    root = root.expanduser().resolve()
    directory = feature_dir(root, feature_id)
    if not apply:
        return migrated_graph(load_json(graph_path(root, feature_id)))
    lock = root / ".dlv" / "runs" / feature_id / ".feature.lock"
    with exclusive_file_lock(lock):
        graph = load_json(graph_path(root, feature_id))
        archive = directory / "archive-v11"
        if archive.exists():
            _validate_archive(archive, feature_id)
            with _private_archive_snapshot(root, archive, feature_id) as snapshot:
                archived_graph = load_json(snapshot / "delivery-graph.json")
                migrated = migrated_graph(archived_graph)
                current_sources = directory / "source-revisions"
                source_versions = [load_json(path).get("schema_version") for path in current_sources.glob("SRC-*.json")]
                state = load_json(directory / "state.json") if (directory / "state.json").is_file() else {}
                if graph.get("schema_version") == 12 and source_versions and all(version == 12 for version in source_versions) and state.get("schema_version") == 12:
                    raise ValueError("feature is already upgraded to schema v12")
                if graph.get("schema_version") == 11:
                    current_feature = _tree_file_identity(directory, excluded_roots={"archive-v11"})
                    archived_feature = _tree_file_identity(snapshot, excluded_roots={"manifest.json", "mutable-records"})
                    mutable_snapshot = snapshot / "mutable-records"
                    mutable_matches = all(
                        _tree_file_identity(root / ".dlv" / kind / feature_id)
                        == _tree_file_identity(mutable_snapshot / kind)
                        for kind in ("reviews", "findings", "runs")
                    )
                    if graph != archived_graph or current_feature != archived_feature or not mutable_matches:
                        raise ValueError("current v11 source diverged from the promoted archive; refusing destructive recovery")
                elif graph.get("schema_version") == 12:
                    raise ValueError(
                        "partial schema-v12 recovery is not automatic; preserve current files and use a future versioned recovery"
                    )
                else:
                    raise ValueError("current migration state has an unsupported schema")
                _apply_archived_migration(root, feature_id, directory, snapshot, migrated)
                return migrated
        migrated = migrated_graph(graph)
        _reject_symlinks(directory)
        for kind in ("reviews", "findings", "runs"):
            source = root / ".dlv" / kind / feature_id
            if source.exists():
                _reject_symlinks(source)
        staging_parent = confined_project_path(
            root, Path(".dlv") / "upgrades" / feature_id,
            "schema-v11 migration staging directory",
        )
        staging_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        staging_parent = confined_project_path(
            root, staging_parent.relative_to(root),
            "schema-v11 migration staging directory",
        )
        staging_parent.chmod(0o700)
        staging_name = "archive-v11.staging"
        parent_fd = os.open(staging_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except BaseException:
            os.close(parent_fd)
            raise
        staging_fd: int | None = None
        mutable_fd: int | None = None
        try:
            _remove_tree_at(parent_fd, staging_name)
            os.mkdir(staging_name, 0o700, dir_fd=parent_fd)
            staging_fd = os.open(staging_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            source_fd = os.dup(directory_fd)
            try:
                _secure_copy_directory_fds(source_fd, staging_fd)
            finally:
                os.close(source_fd)
            os.mkdir("mutable-records", 0o700, dir_fd=staging_fd)
            mutable_fd = os.open("mutable-records", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=staging_fd)
            for kind in ("reviews", "findings", "runs"):
                source = root / ".dlv" / kind / feature_id
                if source.exists():
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
            _write_json_at(staging_fd, "manifest.json", _fd_manifest(staging_fd, feature_id))
            os.fsync(staging_fd)
            os.close(staging_fd)
            staging_fd = None
            os.rename(staging_name, "archive-v11", src_dir_fd=parent_fd, dst_dir_fd=directory_fd)
            os.fsync(parent_fd)
            os.fsync(directory_fd)
        except BaseException:
            _remove_tree_at(parent_fd, staging_name)
            raise
        finally:
            if mutable_fd is not None:
                os.close(mutable_fd)
            if staging_fd is not None:
                os.close(staging_fd)
            os.close(directory_fd)
            os.close(parent_fd)
        with _private_archive_snapshot(root, archive, feature_id) as snapshot:
            try:
                _apply_archived_migration(root, feature_id, directory, snapshot, migrated)
            except BaseException:
                _restore_archive(root, feature_id, directory, snapshot)
                if archive.exists():
                    shutil.rmtree(archive)
                raise
    return migrated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = upgrade(Path(args.root), args.feature_id, apply=args.apply)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
