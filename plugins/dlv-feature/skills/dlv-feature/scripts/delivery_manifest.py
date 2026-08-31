"""Deterministic artifact manifest used for Multica retention handoff."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any

from delivery_proof import value_digest


def _file_record(directory_fd: int, name: str, relative: str) -> dict[str, Any]:
    metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"delivery artifact must be a single-linked regular file: {relative}")
    descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    digest = hashlib.sha256()
    size = 0
    try:
        opened = os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)
        if identity != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
            raise ValueError(f"delivery artifact changed before manifest capture: {relative}")
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
        closed = os.fstat(descriptor)
        if identity != (closed.st_dev, closed.st_ino, closed.st_size, closed.st_mtime_ns, closed.st_ctime_ns):
            raise ValueError(f"delivery artifact changed during manifest capture: {relative}")
    finally:
        os.close(descriptor)
    return {"path": relative, "sha256": digest.hexdigest(), "size": size}


def _walk_directory(directory_fd: int, prefix: Path | None, *, skip_current_manifest: bool) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for name in sorted(os.listdir(directory_fd)):
        if (skip_current_manifest and name == "delivery-manifest.json") or name.endswith(".lock"):
            continue
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        relative = ((prefix / name) if prefix is not None else Path(name)).as_posix()
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            try:
                files.extend(_walk_directory(
                    child, (prefix / name) if prefix is not None else Path(name), skip_current_manifest=False,
                ))
            finally:
                os.close(child)
        else:
            files.append(_file_record(directory_fd, name, relative))
    return files


def build_manifest(directory: Path, feature_id: str) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    project_root = directory.parent.parent
    roots = [(directory, None)] + [
        (project_root / ".dlv" / kind / feature_id, Path(".dlv") / kind / feature_id)
        for kind in ("product-alignments", "reviews", "findings", "runs")
    ]
    for root, prefix in roots:
        if not root.exists():
            continue
        if root.is_symlink() or not root.is_dir() or root.resolve() != root.absolute():
            raise ValueError(f"delivery artifact root is missing, unsafe, or symlinked: {root}")
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            files.extend(_walk_directory(descriptor, prefix, skip_current_manifest=prefix is None))
        finally:
            os.close(descriptor)
    files.sort(key=lambda item: item["path"])
    core = {"schema_version": 13, "feature_id": feature_id, "files": files}
    return {**core, "tree_digest": value_digest(core)}
