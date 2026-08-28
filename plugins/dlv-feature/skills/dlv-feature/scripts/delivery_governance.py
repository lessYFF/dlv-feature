#!/usr/bin/env python3
"""Schema-v12 governance records for scope, risk, findings, and convergence.

The Delivery Graph remains the canonical design truth.  This module keeps the
machine-maintained records that make reviews convergent rather than merely
repeatable: immutable source revisions, a proof-preserving finding ledger, and
the risk vector used to choose review depth.
"""

from __future__ import annotations

import base64
import copy
import functools
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from delivery_proof import atomic_write_text, file_digest, load_json, validate_feature_id, value_digest


SCHEMA_VERSION = 12
RISK_AXES = (
    "API_CONTRACT", "PERSISTENCE", "AUTHORIZATION", "TENANCY", "MONEY",
    "CONCURRENCY", "IRREVERSIBLE_SIDE_EFFECT", "CROSS_CLIENT", "VISUAL_CONTRACT",
)
RISK_LEVELS = {"absent": 0, "present": 1, "critical": 2}
FINDING_STATUSES = {
    "OPEN", "FIXED_PENDING_REVIEW", "VERIFIED", "OUT_OF_SCOPE",
    "ACCEPTED_RISK", "SUPERSEDED", "MERGE_CANDIDATE",
}
FINDING_SEVERITIES = {"critical", "major", "moderate", "minor"}
BLOCKING_FINDING_STATUSES = {"OPEN", "FIXED_PENDING_REVIEW", "MERGE_CANDIDATE"}
NON_WAIVABLE_AXES = {
    "TENANCY", "AUTHORIZATION", "MONEY", "IRREVERSIBLE_SIDE_EFFECT",
}
SOURCE_ID = re.compile(r"^SRC-[0-9]{3,}$")
FINDING_ID = re.compile(r"^FND-[0-9a-f]{12}$")
CLAIM_ID = re.compile(r"^CLM-[0-9a-f]{12}$")
_SUBPROCESS_RUN = subprocess.run
MAX_LEDGER_BYTES = 8 * 1024 * 1024
MAX_CONVERGENCE_EVENTS = 256
REVIEW_TRANSACTION_VERSION = 2
MAX_REVIEW_STATE_BYTES = 8 * 1024 * 1024
MAX_REVIEW_JOURNAL_BYTES = 24 * 1024 * 1024


@functools.lru_cache(maxsize=1)
def _trusted_openssl() -> str:
    discovered: list[Path] = []
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if directory:
            discovered.append(Path(directory) / "openssl")
    discovered.extend(Path(value) for value in ("/usr/bin/openssl", "/bin/openssl"))
    seen: set[Path] = set()
    for candidate in discovered:
        try:
            path = candidate.resolve(strict=True)
            if path in seen:
                continue
            seen.add(path)
            metadata = path.stat()
            if not path.is_absolute() or not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
                continue
            chain = [path, *path.parents]
            if any(
                item.stat().st_mode & 0o022
                or (hasattr(os, "getuid") and item.stat().st_uid != 0)
                for item in chain
            ):
                continue
            return str(path)
        except (FileNotFoundError, NotADirectoryError, OSError):
            continue
    raise ValueError("a root-owned, non-writable system OpenSSL executable is required")


def _fsync_directory(path: Path) -> None:
    """Persist directory-entry changes where the platform supports it."""
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def review_transaction_path(root: Path, feature_id: str) -> Path:
    validate_feature_id(feature_id)
    root = root.expanduser().resolve()
    path = root / ".dlv" / "reviews" / feature_id / "pending-review.json"
    current = root
    for part in path.relative_to(root).parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise ValueError("pending Review transaction path must not traverse a symlink")
    return path


def read_bounded_regular(path: Path, maximum: int, label: str, *, missing_ok: bool = False) -> bytes | None:
    """Read one stable, single-linked regular file without following a final symlink."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return None
        raise
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > maximum:
        raise ValueError(f"{label} exceeds its bounded regular-file contract")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        value = os.read(descriptor, maximum + 1)
        current = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(value) > maximum or not _same_file_identity(metadata, current):
        raise ValueError(f"{label} changed while reading")
    return value


def begin_review_transaction(
    root: Path,
    feature_id: str,
    run_id: str,
    unit_ids: list[str],
    original_ledger: bytes | None,
    original_state: bytes,
    expected_ledger: bytes,
    expected_state: bytes,
    record_digests: dict[str, str],
    transcript_digests: dict[str, str],
) -> Path:
    """Durably record the rollback image before mutating Review state."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", run_id):
        raise ValueError("review transaction run ID is invalid")
    if not unit_ids or len(set(unit_ids)) != len(unit_ids):
        raise ValueError("review transaction unit IDs are invalid")
    if (
        len(original_state) > MAX_REVIEW_STATE_BYTES
        or len(expected_state) > MAX_REVIEW_STATE_BYTES
        or (original_ledger is not None and len(original_ledger) > MAX_LEDGER_BYTES)
        or len(expected_ledger) > MAX_LEDGER_BYTES
    ):
        raise ValueError("Review transaction snapshots exceed the bounded resource contract")
    journal_path = review_transaction_path(root, feature_id)
    if journal_path.exists():
        raise ValueError("a pending Review transaction must be recovered before another Review commit")
    journal = {
        "version": REVIEW_TRANSACTION_VERSION,
        "feature_id": feature_id,
        "run_id": run_id,
        "unit_ids": sorted(unit_ids),
        "original_ledger_b64": base64.b64encode(original_ledger).decode("ascii") if original_ledger is not None else None,
        "original_ledger_sha256": hashlib.sha256(original_ledger).hexdigest() if original_ledger is not None else None,
        "original_state_b64": base64.b64encode(original_state).decode("ascii"),
        "original_state_sha256": hashlib.sha256(original_state).hexdigest(),
        "expected_ledger_sha256": hashlib.sha256(expected_ledger).hexdigest(),
        "expected_state_sha256": hashlib.sha256(expected_state).hexdigest(),
        "record_digests": dict(sorted(record_digests.items())),
        "transcript_digests": dict(sorted(transcript_digests.items())),
    }
    atomic_write_text(journal_path, json.dumps(journal, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    _fsync_directory(journal_path.parent)
    return journal_path


def finish_review_transaction(journal_path: Path) -> None:
    journal_path.unlink()
    _fsync_directory(journal_path.parent)


def recover_review_transaction(root: Path, feature_id: str) -> bool:
    """Roll back an interrupted Review commit; malformed journals fail closed."""
    journal_path = review_transaction_path(root, feature_id)
    if not journal_path.exists():
        return False
    raw_journal = read_bounded_regular(
        journal_path, MAX_REVIEW_JOURNAL_BYTES, "pending Review transaction journal", missing_ok=True,
    )
    if raw_journal is None:
        return False
    try:
        journal = json.loads(raw_journal.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("pending Review transaction journal is invalid") from exc
    expected_keys = {
        "version", "feature_id", "run_id", "unit_ids", "original_ledger_b64",
        "original_ledger_sha256", "original_state_b64", "original_state_sha256",
        "expected_ledger_sha256", "expected_state_sha256", "record_digests", "transcript_digests",
    }
    if not isinstance(journal, dict) or set(journal) != expected_keys:
        raise ValueError("pending Review transaction journal is invalid")
    run_id = journal.get("run_id")
    unit_ids = journal.get("unit_ids")
    record_digests = journal.get("record_digests")
    transcript_digests = journal.get("transcript_digests")
    if (
        journal.get("version") != REVIEW_TRANSACTION_VERSION
        or journal.get("feature_id") != feature_id
        or not isinstance(run_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", run_id)
        or not isinstance(unit_ids, list) or not unit_ids or unit_ids != sorted(set(unit_ids))
        or not all(isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9._:-]+", item) for item in unit_ids)
        or not isinstance(record_digests, dict) or not isinstance(transcript_digests, dict)
        or set(record_digests) != set(unit_ids)
        or not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in record_digests.values())
        or not all(isinstance(key, str) and isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for key, value in transcript_digests.items())
        or not all(isinstance(journal.get(key), str) and re.fullmatch(r"[0-9a-f]{64}", journal[key]) for key in ("expected_ledger_sha256", "expected_state_sha256"))
    ):
        raise ValueError("pending Review transaction journal is invalid")

    def decode_snapshot(encoded: Any, digest: Any, label: str, *, optional: bool = False) -> bytes | None:
        if optional and encoded is None and digest is None:
            return None
        if not isinstance(encoded, str) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"pending Review {label} snapshot is invalid")
        try:
            value = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise ValueError(f"pending Review {label} snapshot is invalid") from exc
        if hashlib.sha256(value).hexdigest() != digest:
            raise ValueError(f"pending Review {label} snapshot is invalid")
        return value

    original_state = decode_snapshot(journal.get("original_state_b64"), journal.get("original_state_sha256"), "state")
    original_ledger = decode_snapshot(
        journal.get("original_ledger_b64"), journal.get("original_ledger_sha256"), "ledger", optional=True,
    )
    assert original_state is not None
    if len(original_state) > MAX_REVIEW_STATE_BYTES or (original_ledger is not None and len(original_ledger) > MAX_LEDGER_BYTES):
        raise ValueError("pending Review transaction snapshots exceed the bounded resource contract")
    try:
        json.loads(original_state.decode("utf-8"))
        if original_ledger is not None:
            json.loads(original_ledger.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("pending Review transaction snapshot is invalid") from exc
    review_directory = journal_path.parent
    transcript_targets: list[tuple[Path, str]] = []
    for relative, digest in transcript_digests.items():
        path = root / relative
        try:
            path.resolve().relative_to(review_directory.resolve())
        except ValueError as exc:
            raise ValueError("pending Review transcript path is invalid") from exc
        if path.resolve() != path.absolute():
            raise ValueError("pending Review transcript path is invalid")
        transcript_targets.append((path, digest))
    state_path = root / "delivery" / feature_id / "state.json"
    ledger_file = ledger_path(root, feature_id)
    current_state = read_bounded_regular(state_path, MAX_REVIEW_STATE_BYTES, "Review state")
    current_ledger = read_bounded_regular(ledger_file, MAX_LEDGER_BYTES, "finding ledger", missing_ok=True)

    def digest(value: bytes | None) -> str | None:
        return hashlib.sha256(value).hexdigest() if value is not None else None

    allowed_state = {journal["original_state_sha256"], journal["expected_state_sha256"]}
    allowed_ledger = {journal["original_ledger_sha256"], journal["expected_ledger_sha256"]}
    if digest(current_state) not in allowed_state or digest(current_ledger) not in allowed_ledger:
        raise ValueError("pending Review transaction diverged after interruption; preserve Owner edits and require a decision")
    review_directory = journal_path.parent
    record_targets: list[Path] = []
    for unit_id, expected_digest in record_digests.items():
        path = review_directory / f"{run_id}.{unit_id}.json"
        current = read_bounded_regular(path, MAX_REVIEW_STATE_BYTES, "Review record", missing_ok=True)
        if current is not None and digest(current) != expected_digest:
            raise ValueError("pending Review record diverged after interruption; preserve Owner edits and require a decision")
        record_targets.append(path)
    for path, expected_digest in transcript_targets:
        current = read_bounded_regular(path, MAX_REVIEW_STATE_BYTES, "Review transcript", missing_ok=True)
        if current is not None and digest(current) != expected_digest:
            raise ValueError("pending Review transcript diverged after interruption; preserve Owner edits and require a decision")

    atomic_write_text(state_path, original_state.decode("utf-8"))
    if original_ledger is None:
        ledger_file.unlink(missing_ok=True)
    else:
        atomic_write_text(ledger_file, original_ledger.decode("utf-8"))
    for path in record_targets:
        path.unlink(missing_ok=True)
    for path, _ in transcript_targets:
        path.unlink(missing_ok=True)
    finish_review_transaction(journal_path)
    return True


def _default_convergence_private_key_path() -> Path:
    codex_root = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).expanduser()
    key_directory = codex_root / "dlv-feature"
    key_path = key_directory / "convergence-rs256.pem"
    key_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if key_directory.is_symlink():
        raise ValueError("DLV convergence key directory must not be symlinked")
    return key_path


def _configured_convergence_private_key_path() -> Path:
    configured = os.environ.get("DLV_CONVERGENCE_PRIVATE_KEY")
    return Path(configured).expanduser() if configured else _default_convergence_private_key_path()


def _generate_convergence_private_key(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".convergence-key-", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        completed = _SUBPROCESS_RUN(
            [_trusted_openssl(), "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(temporary)],
            capture_output=True, check=False, timeout=30,
        )
        if completed.returncode != 0:
            raise ValueError("OpenSSL could not generate the DLV convergence signing key")
        temporary.chmod(0o600)
        try:
            os.link(temporary, path)
        except FileExistsError:
            pass
    finally:
        temporary.unlink(missing_ok=True)


def _read_private_key(path: Path, *, allow_create: bool) -> bytes:
    if not path.exists() and allow_create:
        _generate_convergence_private_key(path)
    if not path.is_file():
        raise ValueError(
            "DLV convergence signing authority is unavailable; import the matching private key "
            "with DLV_CONVERGENCE_PRIVATE_KEY instead of rebaselining history"
        )
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
        or metadata.st_size > 32_768 or metadata.st_mode & 0o077
    ):
        raise ValueError("DLV convergence private key is invalid")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        key = os.read(descriptor, 32_769)
        if not key or len(key) > 32_768 or not _same_file_identity(metadata, os.fstat(descriptor)):
            raise ValueError("DLV convergence private key changed while reading")
        return key
    finally:
        os.close(descriptor)


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino, left.st_size, left.st_mtime_ns, left.st_ctime_ns) == (
        right.st_dev, right.st_ino, right.st_size, right.st_mtime_ns, right.st_ctime_ns,
    )


def _public_key_for(private_key_path: Path) -> str:
    completed = _SUBPROCESS_RUN(
        [_trusted_openssl(), "pkey", "-in", str(private_key_path), "-pubout"],
        capture_output=True, check=False, timeout=10,
    )
    if completed.returncode != 0:
        raise ValueError("DLV convergence private key cannot derive a public identity")
    try:
        public_key = completed.stdout.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("DLV convergence public key is invalid") from exc
    if not public_key.startswith("-----BEGIN PUBLIC KEY-----\n") or not public_key.endswith("-----END PUBLIC KEY-----\n"):
        raise ValueError("DLV convergence public key is invalid")
    return public_key


def _authority_key_id(public_key: str) -> str:
    return "rsa-sha256:" + hashlib.sha256(public_key.encode("ascii")).hexdigest()


def _validate_public_key(public_key: Any) -> str:
    if (
        not isinstance(public_key, str) or len(public_key) > 16_384
        or not public_key.startswith("-----BEGIN PUBLIC KEY-----\n")
        or not public_key.endswith("-----END PUBLIC KEY-----\n")
    ):
        raise ValueError("DLV convergence public key is invalid")
    return _validate_public_key_cached(public_key)


@functools.lru_cache(maxsize=16)
def _validate_public_key_cached(public_key: str) -> str:
    try:
        encoded = public_key.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("DLV convergence public key is invalid") from exc
    with tempfile.NamedTemporaryFile() as public_file:
        public_file.write(encoded)
        public_file.flush()
        completed = _SUBPROCESS_RUN(
            [_trusted_openssl(), "pkey", "-pubin", "-in", public_file.name, "-text_pub", "-noout"],
            capture_output=True, check=False, timeout=10,
        )
    output = completed.stdout.decode("ascii", errors="replace")
    match = re.search(r"Public-Key:\s*\(([0-9]+) bit\)", output)
    if completed.returncode != 0 or match is None or not 2048 <= int(match.group(1)) <= 8192:
        raise ValueError("DLV convergence RSA public key is weak or invalid")
    return public_key


def _convergence_attachment(public_key: str) -> dict[str, str]:
    _validate_public_key(public_key)
    identity = {"key_id": _authority_key_id(public_key), "public_key_pem": public_key}
    return {"kind": "convergence_authority", **identity, "sha256": value_digest(identity)}


def _validate_convergence_attachment(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"kind", "key_id", "public_key_pem", "sha256"}:
        raise ValueError("Source Revision convergence authority attachment is invalid")
    if value.get("kind") != "convergence_authority":
        raise ValueError("Source Revision convergence authority attachment kind is invalid")
    expected = _convergence_attachment(_validate_public_key(value.get("public_key_pem")))
    if value != expected:
        raise ValueError("Source Revision convergence authority attachment identity is stale")
    return value


def _source_convergence_attachment(feature_directory: Path, feature_id: str) -> dict[str, str]:
    root = feature_directory.parents[1]
    existing_ledger = ledger_path(root, feature_id)
    if existing_ledger.is_file():
        raw = load_json(existing_ledger)
        if raw.get("schema_version") == SCHEMA_VERSION and raw.get("convergence_authority") is not None:
            authority = _validate_convergence_authority(raw.get("convergence_authority"))
            return _convergence_attachment(authority["public_key_pem"])
    key_path = _configured_convergence_private_key_path()
    _read_private_key(key_path, allow_create=not bool(os.environ.get("DLV_CONVERGENCE_PRIVATE_KEY")))
    return _convergence_attachment(_public_key_for(key_path))


def _new_convergence_authority(source_revision: dict[str, Any]) -> dict[str, Any]:
    key_path = _configured_convergence_private_key_path()
    _read_private_key(key_path, allow_create=not bool(os.environ.get("DLV_CONVERGENCE_PRIVATE_KEY")))
    public_key = _public_key_for(key_path)
    attachments = [
        item for item in source_revision["attachments"]
        if item.get("kind") == "convergence_authority"
    ]
    if len(attachments) != 1 or _validate_convergence_attachment(attachments[0]) != _convergence_attachment(public_key):
        raise ValueError("confirmed Source Revision does not bind the active DLV convergence authority")
    return {
        "algorithm": "RS256",
        "key_id": _authority_key_id(public_key),
        "public_key_pem": public_key,
        "source_revision": source_revision["revision_id"],
        "source_digest": source_revision["source_digest"],
        "owner": source_revision["owner"],
        "established_at": timestamp(),
    }


def _validate_convergence_authority(value: Any) -> dict[str, Any]:
    required = {
        "algorithm", "key_id", "public_key_pem", "source_revision",
        "source_digest", "owner", "established_at",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("algorithm") != "RS256":
        raise ValueError("finding ledger convergence authority is invalid")
    if not all(isinstance(value.get(key), str) and value[key].strip() for key in required - {"algorithm"}):
        raise ValueError("finding ledger convergence authority is incomplete")
    if not SOURCE_ID.fullmatch(value["source_revision"]) or not re.fullmatch(r"[0-9a-f]{64}", value["source_digest"]):
        raise ValueError("finding ledger convergence authority source binding is invalid")
    _validate_public_key(value["public_key_pem"])
    if value["key_id"] != _authority_key_id(value["public_key_pem"]):
        raise ValueError("finding ledger convergence authority key identity is stale")
    return value


def _convergence_sign(payload: dict[str, Any], authority: dict[str, Any]) -> str:
    key_path = _configured_convergence_private_key_path()
    _read_private_key(key_path, allow_create=False)
    if _authority_key_id(_public_key_for(key_path)) != authority["key_id"]:
        raise ValueError(
            "DLV convergence private key does not match the repository authority; "
            "schema v12 does not support authority rotation or history rebaseline"
        )
    completed = _SUBPROCESS_RUN(
        [_trusted_openssl(), "dgst", "-sha256", "-sign", str(key_path)],
        input=json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        capture_output=True, check=False, timeout=10,
    )
    if completed.returncode != 0:
        raise ValueError("DLV convergence event could not be signed")
    return base64.b64encode(completed.stdout).decode("ascii")


def _verify_convergence_events(authority: dict[str, Any], events: list[dict[str, Any]]) -> None:
    with tempfile.NamedTemporaryFile() as public_file:
        public_file.write(authority["public_key_pem"].encode("ascii"))
        public_file.flush()
        for event in events:
            payload = {
                key: event[key]
                for key in (
                    "sequence", "state_key", "vector", "previous_hash", "key_id",
                    "authority_sha256", "source_revision", "source_digest",
                )
            }
            try:
                signature = base64.b64decode(event["signature"], validate=True)
            except (ValueError, TypeError) as exc:
                raise ValueError("finding ledger convergence signature is invalid") from exc
            with tempfile.NamedTemporaryFile() as signature_file, tempfile.NamedTemporaryFile() as message_file:
                signature_file.write(signature)
                signature_file.flush()
                message_file.write(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
                message_file.flush()
                completed = _SUBPROCESS_RUN(
                    [_trusted_openssl(), "dgst", "-sha256", "-verify", public_file.name, "-signature", signature_file.name, message_file.name],
                    capture_output=True, check=False, timeout=10,
                )
            if completed.returncode != 0:
                raise ValueError("finding ledger convergence signature verification failed")


def timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def canonical_source_payload(value: dict[str, Any]) -> dict[str, Any]:
    """Return the fields whose digest identifies a captured source revision."""
    return {
        "title": value["title"],
        "description": value["description"],
        "comments": value["comments"],
        "attachments": value["attachments"],
        "risk_vector": value["risk_vector"],
    }


def normalize_risk_vector(value: Any, *, label: str = "risk vector") -> dict[str, str]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    unknown = set(value) - set(RISK_AXES)
    if unknown:
        raise ValueError(f"{label} contains unknown axes: " + ", ".join(sorted(unknown)))
    result = {axis: "absent" for axis in RISK_AXES}
    for axis, level in value.items():
        if level not in RISK_LEVELS:
            raise ValueError(f"{label}.{axis} must be absent, present, or critical")
        result[axis] = level
    return result


def union_risk_vectors(*vectors: dict[str, str]) -> dict[str, str]:
    result = {axis: "absent" for axis in RISK_AXES}
    for vector in vectors:
        normalized = normalize_risk_vector(vector)
        for axis, level in normalized.items():
            if RISK_LEVELS[level] > RISK_LEVELS[result[axis]]:
                result[axis] = level
    return result


def profiles_for(vector: dict[str, str]) -> list[str]:
    vector = normalize_risk_vector(vector)
    profiles = ["UI_LOCAL"]
    if any(vector[axis] != "absent" for axis in ("API_CONTRACT", "PERSISTENCE", "CROSS_CLIENT")):
        profiles.append("CONTRACT_DATA")
    if any(vector[axis] != "absent" for axis in NON_WAIVABLE_AXES | {"CONCURRENCY"}):
        profiles.append("CRITICAL_DOMAIN")
    return profiles


def source_dir(feature_directory: Path) -> Path:
    return feature_directory / "source-revisions"


def source_path(feature_directory: Path, revision_id: str) -> Path:
    if not SOURCE_ID.fullmatch(revision_id):
        raise ValueError("source revision id must use SRC- followed by at least three digits")
    return source_dir(feature_directory) / f"{revision_id}.json"


def _validate_source(value: Any, *, expected_feature_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("source revision must be an object")
    expected = {
        "schema_version", "feature_id", "revision_id", "status", "captured_at", "owner",
        "title", "description", "comments", "attachments", "risk_vector", "source_digest",
    }
    if set(value) != expected:
        raise ValueError("source revision has unknown or missing fields")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("source revision schema is invalid")
    if expected_feature_id is not None and value.get("feature_id") != expected_feature_id:
        raise ValueError("source revision feature_id disagrees with feature")
    if not isinstance(value.get("revision_id"), str) or not SOURCE_ID.fullmatch(value["revision_id"]):
        raise ValueError("source revision id is invalid")
    if value.get("status") not in {"confirmed", "pending_confirmation"}:
        raise ValueError("source revision status is invalid")
    for key in ("captured_at", "owner", "title", "description", "source_digest"):
        if not isinstance(value.get(key), str) or not value[key].strip():
            raise ValueError(f"source revision {key} must be a non-empty string")
    if not isinstance(value.get("comments"), list) or not all(isinstance(item, str) for item in value["comments"]):
        raise ValueError("source revision comments must be a string array")
    if not isinstance(value.get("attachments"), list) or not all(isinstance(item, dict) for item in value["attachments"]):
        raise ValueError("source revision attachments must be an object array")
    convergence_attachments = [
        item for item in value["attachments"] if item.get("kind") == "convergence_authority"
    ]
    if len(convergence_attachments) != 1:
        raise ValueError("source revision must bind exactly one convergence authority")
    _validate_convergence_attachment(convergence_attachments[0])
    risk_vector = normalize_risk_vector(value.get("risk_vector"), label="source revision risk_vector")
    if value.get("source_digest") != value_digest(canonical_source_payload({**value, "risk_vector": risk_vector})):
        raise ValueError("source revision digest is stale")
    normalized = copy.deepcopy(value)
    normalized["risk_vector"] = risk_vector
    return normalized


def create_source_revision(
    feature_directory: Path, feature_id: str, revision_id: str, source: dict[str, Any], *,
    owner: str, status: str,
) -> Path:
    if status not in {"confirmed", "pending_confirmation"}:
        raise ValueError("source revision status is invalid")
    if not isinstance(source, dict):
        raise ValueError("source input must be a JSON object")
    allowed = {"title", "description", "comments", "attachments", "risk_vector"}
    unknown = set(source) - allowed
    if unknown:
        raise ValueError("source input contains unknown fields: " + ", ".join(sorted(unknown)))
    title = source.get("title")
    description = source.get("description", "")
    comments = source.get("comments", [])
    attachments = source.get("attachments", [])
    if not isinstance(title, str) or not title.strip() or not isinstance(description, str):
        raise ValueError("source input title and description must be strings; title must be non-empty")
    if not isinstance(comments, list) or not all(isinstance(item, str) for item in comments):
        raise ValueError("source input comments must be a string array")
    if not isinstance(attachments, list) or not all(isinstance(item, dict) for item in attachments):
        raise ValueError("source input attachments must be an object array")
    if not any(item.get("kind") == "convergence_authority" for item in attachments):
        attachments = [*attachments, _source_convergence_attachment(feature_directory, feature_id)]
    if not isinstance(owner, str) or not owner.strip():
        raise ValueError("source revision owner must be non-empty")
    value = {
        "schema_version": SCHEMA_VERSION,
        "feature_id": feature_id,
        "revision_id": revision_id,
        "status": status,
        "captured_at": timestamp(),
        "owner": owner,
        "title": title,
        "description": description,
        "comments": comments,
        "attachments": attachments,
        "risk_vector": normalize_risk_vector(source.get("risk_vector"), label="source input risk_vector"),
    }
    value["source_digest"] = value_digest(canonical_source_payload(value))
    _validate_source(value, expected_feature_id=feature_id)
    path = source_path(feature_directory, revision_id)
    if path.exists():
        raise ValueError(f"source revision already exists: {revision_id}")
    atomic_write_text(path, __import__("json").dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return path


def load_source_revision(feature_directory: Path, feature_id: str, revision_id: str) -> dict[str, Any]:
    path = source_path(feature_directory, revision_id)
    if not path.is_file() or path.resolve() != path.absolute():
        raise ValueError(f"source revision is missing or symlinked: {revision_id}")
    return _validate_source(load_json(path), expected_feature_id=feature_id)


def source_revision_status(feature_directory: Path, feature_id: str, current_id: str) -> dict[str, Any]:
    current = load_source_revision(feature_directory, feature_id, current_id)
    if current["status"] != "confirmed":
        raise ValueError("Delivery Graph source_revision must reference a confirmed source revision")
    current_number = int(current_id.removeprefix("SRC-"))
    pending: list[dict[str, Any]] = []
    directory = source_dir(feature_directory)
    if directory.is_dir():
        for path in sorted(directory.glob("SRC-*.json")):
            revision = _validate_source(load_json(path), expected_feature_id=feature_id)
            # An Owner confirmation selects an epoch.  Older captures remain
            # immutable historical input, not perpetual source drift; only a
            # capture after the selected epoch requires a new decision.
            if (
                revision["status"] == "pending_confirmation"
                and int(revision["revision_id"].removeprefix("SRC-")) > current_number
            ):
                pending.append(revision)
    return {
        "current_id": current_id,
        "source_digest": current["source_digest"],
        "status": "drift" if pending else "confirmed",
        "pending_ids": [item["revision_id"] for item in pending],
    }


def ledger_path(root: Path, feature_id: str) -> Path:
    return root / ".dlv" / "findings" / feature_id / "ledger.json"


def empty_ledger(feature_id: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION, "feature_id": feature_id,
        "entries": {}, "campaigns": [], "convergence_authority": None, "convergence_events": [],
    }


def load_ledger(root: Path, feature_id: str) -> dict[str, Any]:
    path = ledger_path(root, feature_id)
    if not path.is_file():
        return empty_ledger(feature_id)
    if path.stat().st_size > MAX_LEDGER_BYTES:
        raise ValueError("finding ledger exceeds the bounded resource contract")
    value = load_json(path)
    if set(value) != {"schema_version", "feature_id", "entries", "campaigns", "convergence_authority", "convergence_events"}:
        raise ValueError("finding ledger has unknown or missing fields")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("feature_id") != feature_id:
        raise ValueError("finding ledger identity/schema is invalid")
    if (
        not isinstance(value.get("entries"), dict)
        or not isinstance(value.get("campaigns"), list)
        or not isinstance(value.get("convergence_events"), list)
    ):
        raise ValueError("finding ledger entries/campaigns are invalid")
    if len(value["convergence_events"]) > MAX_CONVERGENCE_EVENTS:
        raise ValueError("finding ledger convergence history exceeds the bounded resource contract")
    for finding_id, entry in value["entries"].items():
        if not FINDING_ID.fullmatch(finding_id) or not isinstance(entry, dict):
            raise ValueError("finding ledger contains an invalid entry")
        required = {
            "id", "claim_id", "severity", "status", "statement", "evidence", "risk_path",
            "root_cause", "failure_mode", "violated_invariant", "subjects", "risk_axes",
            "semantic_key", "observed_in_units", "merge_candidates", "first_seen_at", "last_seen_at",
            "first_seen_revision", "last_seen_revision", "previously_invisible_reason", "waiver", "supersedes",
        }
        if set(entry) != required or entry.get("id") != finding_id:
            raise ValueError("finding ledger entry shape is invalid")
        if entry.get("severity") not in FINDING_SEVERITIES or entry.get("status") not in FINDING_STATUSES:
            raise ValueError("finding ledger severity/status is invalid")
        if not all(isinstance(entry.get(key), str) and entry[key].strip() for key in (
            "claim_id", "statement", "evidence", "risk_path", "root_cause", "failure_mode",
            "violated_invariant", "semantic_key", "first_seen_at",
            "last_seen_at", "first_seen_revision", "last_seen_revision", "previously_invisible_reason",
        )):
            raise ValueError("finding ledger entry evidence is incomplete")
        if not all(
            isinstance(entry.get(key), list) and entry[key] == sorted(set(entry[key]))
            and all(isinstance(item, str) and item for item in entry[key])
            for key in ("subjects", "risk_axes", "observed_in_units", "merge_candidates")
        ):
            raise ValueError("finding ledger semantic arrays are invalid")
        if not CLAIM_ID.fullmatch(entry["claim_id"]) or any(axis not in RISK_AXES for axis in entry["risk_axes"]):
            raise ValueError("finding ledger Claim/risk identity is invalid")
        expected_semantic_key = finding_semantic_key(entry)
        if entry["semantic_key"] != expected_semantic_key or finding_id != f"FND-{expected_semantic_key[:12]}":
            raise ValueError("finding ledger semantic identity is stale")
        waiver = entry["waiver"]
        if entry["status"] == "ACCEPTED_RISK":
            if (
                not isinstance(waiver, dict)
                or set(waiver) != {"owner", "reason", "decided_at"}
                or not all(isinstance(waiver.get(key), str) and waiver[key].strip() for key in waiver)
            ):
                raise ValueError("accepted Finding risk requires a complete Owner decision")
        elif waiver is not None:
            raise ValueError("only ACCEPTED_RISK may carry an Owner waiver")
        if entry["status"] == "ACCEPTED_RISK" and entry["severity"] in {"critical", "major"}:
            raise ValueError("finding ledger cannot accept P0/P1 delivery risk")
        if entry["supersedes"] is not None and not FINDING_ID.fullmatch(entry["supersedes"]):
            raise ValueError("finding ledger supersedes is invalid")
    for finding_id, entry in value["entries"].items():
        candidates = entry["merge_candidates"]
        if any(candidate == finding_id or candidate not in value["entries"] for candidate in candidates):
            raise ValueError("finding ledger merge candidate reference is invalid")
        if entry["status"] == "MERGE_CANDIDATE" and not candidates:
            raise ValueError("MERGE_CANDIDATE requires at least one candidate")
        if entry["status"] == "SUPERSEDED":
            if entry["supersedes"] not in value["entries"]:
                raise ValueError("SUPERSEDED finding requires an existing canonical target")
            target = value["entries"][entry["supersedes"]]
            if target.get("status") == "SUPERSEDED" or target.get("supersedes") is not None:
                raise ValueError("SUPERSEDED finding must reference a direct canonical target")
        elif entry["supersedes"] is not None:
            raise ValueError("only a SUPERSEDED finding may reference a canonical target")
    for campaign in value["campaigns"]:
        if (
            not isinstance(campaign, dict)
            or set(campaign) != {"run_id", "recorded_at", "unit_count", "new_findings"}
            or not isinstance(campaign.get("run_id"), str) or not campaign["run_id"].strip()
            or not isinstance(campaign.get("recorded_at"), str) or not campaign["recorded_at"].strip()
            or type(campaign.get("unit_count")) is not int or campaign["unit_count"] < 1
            or type(campaign.get("new_findings")) is not int or campaign["new_findings"] < 0
        ):
            raise ValueError("finding ledger campaign is invalid")
    authority = value["convergence_authority"]
    if value["convergence_events"]:
        authority = _validate_convergence_authority(authority)
    elif authority is not None:
        _validate_convergence_authority(authority)
    previous_hash: str | None = None
    for sequence, event in enumerate(value["convergence_events"], start=1):
        if (
            not isinstance(event, dict)
            or set(event) != {
                "sequence", "state_key", "vector", "previous_hash", "key_id",
                "authority_sha256", "source_revision", "source_digest", "signature", "record_hash",
            }
            or event.get("sequence") != sequence
            or not isinstance(event.get("state_key"), str) or not re.fullmatch(r"[0-9a-f]{64}", event["state_key"])
            or not isinstance(event.get("vector"), list) or len(event["vector"]) != 7
            or any(type(item) is not int or item < 0 for item in event["vector"])
            or event.get("previous_hash") != previous_hash
            or event.get("key_id") != authority["key_id"]
            or event.get("authority_sha256") != value_digest(authority)
            or not isinstance(event.get("source_revision"), str)
            or not SOURCE_ID.fullmatch(event["source_revision"])
            or not isinstance(event.get("source_digest"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", event["source_digest"])
            or not isinstance(event.get("signature"), str) or len(event["signature"]) > 16_384
        ):
            raise ValueError("finding ledger convergence event is invalid")
        record_payload = {
            key: event[key]
            for key in (
                "sequence", "state_key", "vector", "previous_hash", "key_id",
                "authority_sha256", "source_revision", "source_digest", "signature",
            )
        }
        if event.get("record_hash") != value_digest(record_payload):
            raise ValueError("finding ledger convergence chain is invalid")
        previous_hash = event["record_hash"]
        source = load_source_revision(
            root / "delivery" / feature_id, feature_id, event["source_revision"],
        )
        source_authorities = [
            item for item in source["attachments"] if item.get("kind") == "convergence_authority"
        ]
        if (
            source["source_digest"] != event["source_digest"]
            or len(source_authorities) != 1
            or source_authorities[0] != _convergence_attachment(authority["public_key_pem"])
        ):
            raise ValueError("finding ledger convergence Source Revision binding is invalid")
    if value["convergence_events"]:
        _verify_convergence_events(authority, value["convergence_events"])
    return value


def append_convergence_event(
    ledger: dict[str, Any], state_key: str, vector: list[int], source_revision: dict[str, Any],
) -> bool:
    events = ledger["convergence_events"]
    if events and events[-1]["state_key"] == state_key:
        return False
    if len(events) >= MAX_CONVERGENCE_EVENTS:
        raise ValueError("convergence history reached the schema-v12 terminal; a future versioned migration is required")
    if ledger["convergence_authority"] is None:
        ledger["convergence_authority"] = _new_convergence_authority(source_revision)
    authority = _validate_convergence_authority(ledger["convergence_authority"])
    source_authorities = [
        item for item in source_revision["attachments"] if item.get("kind") == "convergence_authority"
    ]
    if len(source_authorities) != 1 or source_authorities[0] != _convergence_attachment(authority["public_key_pem"]):
        raise ValueError("current confirmed Source Revision does not bind the ledger convergence authority")
    payload = {
        "sequence": len(events) + 1,
        "state_key": state_key,
        "vector": list(vector),
        "previous_hash": events[-1]["record_hash"] if events else None,
        "key_id": authority["key_id"],
        "authority_sha256": value_digest(authority),
        "source_revision": source_revision["revision_id"],
        "source_digest": source_revision["source_digest"],
    }
    signature = _convergence_sign(payload, authority)
    record_payload = {**payload, "signature": signature}
    event = {**record_payload, "record_hash": value_digest(record_payload)}
    _verify_convergence_events(authority, [event])
    events.append(event)
    return True


def write_ledger(root: Path, feature_id: str, ledger: dict[str, Any]) -> str:
    path = ledger_path(root, feature_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, __import__("json").dumps(ledger, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return file_digest(path)


def finding_summary(ledger: dict[str, Any]) -> dict[str, int]:
    entries = ledger["entries"].values()
    return {
        "open_blockers": sum(
            entry["severity"] in {"critical", "major"} and entry["status"] in BLOCKING_FINDING_STATUSES
            for entry in entries
        ),
        "open_total": sum(entry["status"] in BLOCKING_FINDING_STATUSES for entry in entries),
        "owner_decisions": sum(
            entry["severity"] == "moderate" and entry["status"] in BLOCKING_FINDING_STATUSES
            for entry in entries
        ),
        "verified": sum(entry["status"] == "VERIFIED" for entry in entries),
    }


def has_nonwaivable_blocker(ledger: dict[str, Any]) -> bool:
    for entry in ledger["entries"].values():
        if entry["status"] not in BLOCKING_FINDING_STATUSES or entry["severity"] not in {"critical", "major"}:
            continue
        if any(axis in NON_WAIVABLE_AXES for axis in entry.get("risk_axes", [])):
            return True
    return False


def finding_semantic_payload(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "claim_id": raw.get("claim_id"),
        "failure_mode": raw.get("failure_mode"),
        "violated_invariant": raw.get("violated_invariant"),
        "subjects": sorted(raw.get("subjects", [])),
        "risk_axes": sorted(raw.get("risk_axes", [])),
    }


def finding_semantic_key(raw: dict[str, Any]) -> str:
    return value_digest(finding_semantic_payload(raw))


def _partial_overlap(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if left.get("claim_id") != right.get("claim_id"):
        return False
    left_subjects, right_subjects = set(left.get("subjects", [])), set(right.get("subjects", []))
    left_axes, right_axes = set(left.get("risk_axes", [])), set(right.get("risk_axes", []))
    return bool(left_subjects & right_subjects) and bool(left_axes & right_axes)


def apply_review_findings(
    ledger: dict[str, Any], *, unit_id: str, source_revision: str, findings: list[dict[str, Any]],
    claim_ids: set[str] | None = None,
    claim_subjects: dict[str, set[str]] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Merge one review response into the stable Finding Ledger.

    Reviewers can use ``NEW`` for a new root cause or a prior ``FND-*`` ID to
    verify/fix it.  Every previously blocking finding in the unit must be
    addressed; omission keeps it OPEN rather than silently closing it.
    """
    updated = copy.deepcopy(ledger)
    entries: dict[str, dict[str, Any]] = updated["entries"]
    now = timestamp()
    active = {
        finding_id: entry for finding_id, entry in entries.items()
        if unit_id in entry.get("observed_in_units", []) and entry["status"] in BLOCKING_FINDING_STATUSES
    }
    semantic_index = {entry["semantic_key"]: finding_id for finding_id, entry in entries.items()}
    canonical: list[dict[str, Any]] = []
    addressed: set[str] = set()
    for raw in findings:
        if not isinstance(raw, dict):
            raise ValueError("semantic finding must be an object")
        raw_id = raw.get("id", "NEW")
        root_cause = raw.get("root_cause", raw.get("statement", "")).strip() if isinstance(raw.get("root_cause", raw.get("statement", "")), str) else ""
        statement = raw.get("statement")
        evidence = raw.get("evidence")
        risk_path = raw.get("risk_path", "graph semantic evidence")
        invisible = raw.get("previously_invisible_reason", "new semantic review evidence")
        severity = raw.get("severity")
        requested_status = str(raw.get("status", "OPEN")).upper()
        claim_id = raw.get("claim_id")
        failure_mode = raw.get("failure_mode")
        violated_invariant = raw.get("violated_invariant")
        subjects = sorted(raw.get("subjects", [])) if isinstance(raw.get("subjects"), list) else []
        risk_axes = sorted(raw.get("risk_axes", [])) if isinstance(raw.get("risk_axes"), list) else []
        if not root_cause or not all(isinstance(item, str) and item.strip() for item in (statement, evidence, risk_path, invisible)):
            raise ValueError("new finding requires statement, evidence, risk_path, root_cause, and previously_invisible_reason")
        if not all(isinstance(item, str) and item.strip() for item in (claim_id, failure_mode, violated_invariant)):
            raise ValueError("review finding requires claim_id, failure_mode, and violated_invariant")
        if claim_ids is not None and claim_id not in claim_ids:
            raise ValueError("review finding claim_id is unknown")
        if any(axis not in RISK_AXES for axis in risk_axes):
            raise ValueError("review finding contains an unknown risk axis")
        if claim_subjects is not None and not set(subjects) <= claim_subjects.get(claim_id, set()):
            raise ValueError("review finding subjects must belong to its Claim")
        if not subjects or subjects != sorted(set(subjects)) or not risk_axes or risk_axes != sorted(set(risk_axes)):
            raise ValueError("review finding subjects/risk_axes must be sorted unique non-empty arrays")
        semantic_key = finding_semantic_key({
            "claim_id": claim_id, "failure_mode": failure_mode, "violated_invariant": violated_invariant,
            "subjects": subjects, "risk_axes": risk_axes,
        })
        if severity not in FINDING_SEVERITIES or requested_status not in {"OPEN", "VERIFIED"}:
            raise ValueError("review finding severity/status is invalid")
        if raw_id == "NEW":
            finding_id = semantic_index.get(semantic_key) or f"FND-{semantic_key[:12]}"
        elif isinstance(raw_id, str) and FINDING_ID.fullmatch(raw_id) and raw_id in entries:
            finding_id = raw_id
        else:
            raise ValueError("review finding id must be NEW or an existing FND-* id")
        existing = entries.get(finding_id)
        if existing is not None and existing.get("semantic_key") != semantic_key:
            raise ValueError("review finding ID cannot be rebound to different semantics; use NEW")
        if existing is not None and existing.get("status") == "SUPERSEDED":
            canonical_id = existing.get("supersedes")
            canonical_entry = entries.get(canonical_id)
            if not isinstance(canonical_entry, dict) or canonical_entry.get("status") == "SUPERSEDED":
                raise ValueError("superseded review finding has no direct canonical target")
            if requested_status == "VERIFIED":
                raise ValueError("a superseded finding cannot verify its canonical target; return the canonical ID and semantics")
            routed = copy.deepcopy(canonical_entry)
            routed.update({
                "severity": severity,
                "status": (
                    "MERGE_CANDIDATE"
                    if requested_status == "OPEN" and canonical_entry.get("status") == "MERGE_CANDIDATE"
                    else requested_status
                ),
                "statement": statement,
                "evidence": evidence,
                "risk_path": risk_path,
                "root_cause": root_cause,
                "observed_in_units": sorted(set(canonical_entry.get("observed_in_units", [])) | {unit_id}),
                "last_seen_at": now,
                "last_seen_revision": source_revision,
                "previously_invisible_reason": invisible,
            })
            entries[canonical_id] = routed
            addressed.add(canonical_id)
            canonical.append(routed)
            continue
        if requested_status == "VERIFIED" and existing is None:
            raise ValueError("only an existing finding can be VERIFIED")
        if requested_status == "VERIFIED" and existing is not None and existing.get("status") not in {"FIXED_PENDING_REVIEW", "VERIFIED"}:
            raise ValueError("only a FIXED_PENDING_REVIEW finding can be VERIFIED")
        merge_candidates = sorted(
            finding_id_value for finding_id_value, candidate in entries.items()
            if finding_id_value != finding_id and candidate.get("semantic_key") != semantic_key
            and _partial_overlap(candidate, {
                "claim_id": claim_id, "subjects": subjects, "risk_axes": risk_axes,
            })
        )
        effective_status = requested_status
        if existing is None and requested_status == "OPEN" and merge_candidates:
            effective_status = "MERGE_CANDIDATE"
        elif existing is not None and existing.get("status") == "MERGE_CANDIDATE" and requested_status == "OPEN":
            effective_status = "MERGE_CANDIDATE"
        entry = {
            "id": finding_id,
            "claim_id": claim_id,
            "severity": severity,
            "status": effective_status,
            "statement": statement,
            "evidence": evidence,
            "risk_path": risk_path,
            "root_cause": root_cause,
            "failure_mode": failure_mode,
            "violated_invariant": violated_invariant,
            "subjects": subjects,
            "risk_axes": risk_axes,
            "semantic_key": semantic_key,
            "observed_in_units": sorted(set((existing or {}).get("observed_in_units", [])) | {unit_id}),
            "merge_candidates": merge_candidates if existing is None else existing.get("merge_candidates", []),
            "first_seen_at": existing["first_seen_at"] if existing else now,
            "last_seen_at": now,
            "first_seen_revision": existing["first_seen_revision"] if existing else source_revision,
            "last_seen_revision": source_revision,
            "previously_invisible_reason": invisible,
            "waiver": existing["waiver"] if existing else None,
            "supersedes": existing["supersedes"] if existing else None,
        }
        entries[finding_id] = entry
        semantic_index[semantic_key] = finding_id
        addressed.add(finding_id)
        canonical.append(entry)
    for finding_id, entry in active.items():
        if finding_id not in addressed:
            entry = copy.deepcopy(entry)
            entry["last_seen_at"] = now
            entry["last_seen_revision"] = source_revision
            entries[finding_id] = entry
            canonical.append(entry)
    return updated, sorted(canonical, key=lambda entry: entry["id"])
