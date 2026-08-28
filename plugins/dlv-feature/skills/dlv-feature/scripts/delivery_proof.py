#!/usr/bin/env python3
"""Shared integrity, locking, hashing, and evidence helpers for schema v12."""

from __future__ import annotations

from contextlib import contextmanager
import errno
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator

STATE_START = "<!-- DLV_STATE_START -->"
STATE_END = "<!-- DLV_STATE_END -->"
FEATURE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MISSING = object()


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def validate_feature_id(feature_id: str) -> None:
    if not FEATURE_ID.fullmatch(feature_id):
        raise ValueError("feature-id must use lowercase letters, digits, and single hyphens")


def value_digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def repository_fingerprint(root: Path, feature_id: str) -> str:
    """Hash source state while excluding delivery records and generated run evidence."""
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root, capture_output=True, check=False,
    )
    if completed.returncode != 0:
        raise ValueError("project root must be a readable Git worktree to fingerprint Code")
    excluded = ("delivery/", ".dlv/")
    paths = sorted(
        value.decode("utf-8", errors="surrogateescape")
        for value in completed.stdout.split(b"\0")
        if value and not value.decode("utf-8", errors="surrogateescape").startswith(excluded)
    )
    digest = hashlib.sha256()
    for relative in paths:
        path = root / relative
        digest.update(relative.encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"symlink\0")
            digest.update(path.readlink().as_posix().encode("utf-8"))
        elif path.is_file():
            digest.update(b"file\0")
            before = path.stat()
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
                after = os.fstat(handle.fileno())
            identity = lambda value: (
                value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
            )
            if identity(before) != identity(after):
                raise ValueError(f"repository file changed while fingerprinting: {relative}")
        else:
            digest.update(b"missing\0")
        digest.update(b"\0")
    return digest.hexdigest()


def extract_state(path: Path) -> tuple[str, dict[str, Any]]:
    content = path.read_text(encoding="utf-8")
    match = re.search(
        rf"{re.escape(STATE_START)}\s*```json\s*\n([\s\S]*?)\n```\s*{re.escape(STATE_END)}",
        content,
    )
    if not match:
        raise ValueError("state.md has no valid DLV JSON block")
    state = json.loads(match.group(1))
    if not isinstance(state, dict):
        raise ValueError("state.md JSON block must be an object")
    return content, state


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def acquire_windows_lock(locking: Any, file_descriptor: int, nonblocking_mode: int) -> None:
    """Wait like POSIX flock; msvcrt.LK_LOCK otherwise gives up after about ten seconds."""
    while True:
        try:
            locking(file_descriptor, nonblocking_mode, 1)
            return
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EDEADLK}:
                raise
            time.sleep(0.05)


@contextmanager
def exclusive_file_lock(path: Path) -> Iterator[None]:
    """Hold one cross-platform advisory lock for a verification-run transaction."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        if os.name == "nt":
            import msvcrt

            if path.stat().st_size == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            acquire_windows_lock(msvcrt.locking, handle.fileno(), msvcrt.LK_NBLCK)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value

def load_manifest(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{number} must contain a JSON object")
        records.append(value)
    return records


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    """Append one fsynced canonical record; callers never rewrite prior evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical(record) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def evaluate_oracle(actual: Any, oracle: dict[str, Any]) -> bool:
    """Evaluate one contracted oracle without trusting a caller-supplied status."""
    operator = oracle.get("operator")
    expected = oracle.get("expected")
    if actual is MISSING:
        return operator == "absent"
    if operator == "eq":
        return actual == expected and type(actual) is type(expected)
    if operator == "ne":
        return actual != expected or type(actual) is not type(expected)
    if operator == "exists":
        return True
    if operator == "absent":
        return False
    if operator == "contains":
        try:
            return expected in actual
        except (TypeError, ValueError):
            return False
    if operator == "not_contains":
        try:
            return expected not in actual
        except (TypeError, ValueError):
            return False
    if operator == "matches":
        try:
            return isinstance(actual, str) and re.search(str(expected), actual) is not None
        except re.error:
            return False
    if operator == "lte":
        try:
            return actual <= expected and type(actual) is type(expected)
        except TypeError:
            return False
    if operator == "gte":
        try:
            return actual >= expected and type(actual) is type(expected)
        except TypeError:
            return False
    return False


def resolve_source(document: dict[str, Any], source: str) -> Any:
    """Resolve an RFC-6901-style pointer from recorder-owned command/observation data."""
    if not source.startswith("/") or not source.startswith(("/command/", "/observation/")):
        raise ValueError("oracle.source must start with /command/ or /observation/")
    value: Any = document
    for raw in source.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and token in value:
            value = value[token]
        elif isinstance(value, list) and token.isdigit() and int(token) < len(value):
            value = value[int(token)]
        else:
            return MISSING
    return value
