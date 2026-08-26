#!/usr/bin/env python3
"""Schema-v11 governance records for scope, risk, findings, and convergence.

The Delivery Graph remains the canonical design truth.  This module keeps the
machine-maintained records that make reviews convergent rather than merely
repeatable: immutable source revisions, a proof-preserving finding ledger, and
the risk vector used to choose review depth.
"""

from __future__ import annotations

import copy
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from delivery_proof import atomic_write_text, file_digest, load_json, value_digest


SCHEMA_VERSION = 11
RISK_AXES = (
    "API_CONTRACT", "PERSISTENCE", "AUTHORIZATION", "TENANCY", "MONEY",
    "CONCURRENCY", "IRREVERSIBLE_SIDE_EFFECT", "CROSS_CLIENT", "VISUAL_CONTRACT",
)
RISK_LEVELS = {"absent": 0, "present": 1, "critical": 2}
FINDING_STATUSES = {
    "OPEN", "FIXED_PENDING_REVIEW", "VERIFIED", "OUT_OF_SCOPE",
    "ACCEPTED_RISK", "SUPERSEDED",
}
BLOCKING_FINDING_STATUSES = {"OPEN", "FIXED_PENDING_REVIEW"}
NON_WAIVABLE_AXES = {
    "TENANCY", "AUTHORIZATION", "MONEY", "IRREVERSIBLE_SIDE_EFFECT",
}
SOURCE_ID = re.compile(r"^SRC-[0-9]{3,}$")
FINDING_ID = re.compile(r"^FND-[0-9a-f]{12}$")


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
    return {"schema_version": SCHEMA_VERSION, "feature_id": feature_id, "entries": {}, "campaigns": []}


def load_ledger(root: Path, feature_id: str) -> dict[str, Any]:
    path = ledger_path(root, feature_id)
    if not path.is_file():
        return empty_ledger(feature_id)
    value = load_json(path)
    if set(value) != {"schema_version", "feature_id", "entries", "campaigns"}:
        raise ValueError("finding ledger has unknown or missing fields")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("feature_id") != feature_id:
        raise ValueError("finding ledger identity/schema is invalid")
    if not isinstance(value.get("entries"), dict) or not isinstance(value.get("campaigns"), list):
        raise ValueError("finding ledger entries/campaigns are invalid")
    for finding_id, entry in value["entries"].items():
        if not FINDING_ID.fullmatch(finding_id) or not isinstance(entry, dict):
            raise ValueError("finding ledger contains an invalid entry")
        required = {
            "id", "unit_id", "severity", "status", "statement", "evidence", "risk_path",
            "root_cause", "first_seen_at", "last_seen_at", "first_seen_revision", "last_seen_revision",
            "previously_invisible_reason", "waiver", "supersedes",
        }
        if set(entry) != required or entry.get("id") != finding_id:
            raise ValueError("finding ledger entry shape is invalid")
        if entry.get("severity") not in {"critical", "major", "minor"} or entry.get("status") not in FINDING_STATUSES:
            raise ValueError("finding ledger severity/status is invalid")
        if not all(isinstance(entry.get(key), str) and entry[key].strip() for key in (
            "unit_id", "statement", "evidence", "risk_path", "root_cause", "first_seen_at",
            "last_seen_at", "first_seen_revision", "last_seen_revision", "previously_invisible_reason",
        )):
            raise ValueError("finding ledger entry evidence is incomplete")
        if entry["waiver"] is not None and not isinstance(entry["waiver"], dict):
            raise ValueError("finding ledger waiver is invalid")
        if entry["supersedes"] is not None and not FINDING_ID.fullmatch(entry["supersedes"]):
            raise ValueError("finding ledger supersedes is invalid")
    return value


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
        "verified": sum(entry["status"] == "VERIFIED" for entry in entries),
    }


def has_nonwaivable_blocker(ledger: dict[str, Any]) -> bool:
    for entry in ledger["entries"].values():
        if entry["status"] not in BLOCKING_FINDING_STATUSES or entry["severity"] not in {"critical", "major"}:
            continue
        if any(axis in entry["risk_path"] for axis in NON_WAIVABLE_AXES):
            return True
    return False


def apply_review_findings(
    ledger: dict[str, Any], *, unit_id: str, source_revision: str, findings: list[dict[str, Any]],
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
        if entry["unit_id"] == unit_id and entry["status"] in BLOCKING_FINDING_STATUSES
    }
    root_index = {entry["root_cause"].strip().lower(): finding_id for finding_id, entry in entries.items()}
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
        if not root_cause or not all(isinstance(item, str) and item.strip() for item in (statement, evidence, risk_path, invisible)):
            raise ValueError("new finding requires statement, evidence, risk_path, root_cause, and previously_invisible_reason")
        if severity not in {"critical", "major", "minor"} or requested_status not in {"OPEN", "VERIFIED"}:
            raise ValueError("review finding severity/status is invalid")
        if raw_id == "NEW":
            finding_id = root_index.get(root_cause.lower()) or f"FND-{value_digest({'unit': unit_id, 'root': root_cause.lower()})[:12]}"
        elif isinstance(raw_id, str) and FINDING_ID.fullmatch(raw_id) and raw_id in entries:
            finding_id = raw_id
        else:
            raise ValueError("review finding id must be NEW or an existing FND-* id")
        existing = entries.get(finding_id)
        if existing is not None and existing["unit_id"] != unit_id:
            raise ValueError("review finding cannot move between review units")
        if requested_status == "VERIFIED" and existing is None:
            raise ValueError("only an existing finding can be VERIFIED")
        entry = {
            "id": finding_id,
            "unit_id": unit_id,
            "severity": severity,
            "status": requested_status,
            "statement": statement,
            "evidence": evidence,
            "risk_path": risk_path,
            "root_cause": root_cause,
            "first_seen_at": existing["first_seen_at"] if existing else now,
            "last_seen_at": now,
            "first_seen_revision": existing["first_seen_revision"] if existing else source_revision,
            "last_seen_revision": source_revision,
            "previously_invisible_reason": invisible,
            "waiver": existing["waiver"] if existing else None,
            "supersedes": existing["supersedes"] if existing else None,
        }
        entries[finding_id] = entry
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
