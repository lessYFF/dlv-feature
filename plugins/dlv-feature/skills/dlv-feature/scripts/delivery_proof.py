#!/usr/bin/env python3
"""Shared deterministic proof-kernel helpers for dlv-feature schema v6."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any


STATE_START = "<!-- DLV_STATE_START -->"
STATE_END = "<!-- DLV_STATE_END -->"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PO_ID = re.compile(r"^PO-[0-9]+$")
PRODUCT_ID = re.compile(r"^(?:AC|EX)-[0-9]+$")
PROOF_TYPES = {"visual", "runtime", "boundary", "invariant", "artifact"}


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def value_digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def repository_fingerprint(root: Path, feature_id: str) -> str:
    """Hash the current tracked and untracked source tree, excluding this delivery record."""
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError("project root must be a readable Git worktree to fingerprint Code")
    excluded = "delivery/"
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
            digest.update(path.read_bytes())
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


def write_state(path: Path, content: str, state: dict[str, Any]) -> None:
    replacement = f"{STATE_START}\n```json\n{json.dumps(state, ensure_ascii=False, indent=2)}\n```\n{STATE_END}"
    updated = re.sub(
        rf"{re.escape(STATE_START)}[\s\S]*?{re.escape(STATE_END)}",
        replacement,
        content,
        count=1,
    )
    atomic_write_text(path, updated)


def atomic_write_text(path: Path, content: str) -> None:
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


def proof_contract_digest(contract: Any) -> str:
    return value_digest(contract)


def code_result_digest(state: dict[str, Any]) -> str:
    return value_digest(state.get("stages", {}).get("code", {}).get("result"))


def finalization_payload(state: dict[str, Any]) -> dict[str, Any]:
    stages = state.get("stages", {})
    verification = stages.get("verification", {})
    return {
        "schema_version": state.get("schema_version"),
        "feature_id": state.get("feature_id"),
        "truth": {
            name: stages.get(name, {}).get("fingerprint")
            for name in ("prd", "prototype", "architecture", "code_spec")
        },
        "code_result": code_result_digest(state),
        "proof_contract": proof_contract_digest(state.get("proof_contract")),
        "verification": verification.get("fingerprint"),
        "repositories": verification.get("inputs", {}).get("repositories"),
        "verdict": verification.get("verdict"),
    }


def finalization_token(state: dict[str, Any]) -> str:
    return value_digest(finalization_payload(state))


def validate_proof_contract(
    contract: Any,
    acceptance_ids: set[str],
    code_spec_fingerprint: Any,
    prototype_completed: bool,
    errors: list[str],
) -> dict[str, dict[str, Any]]:
    location = "proof_contract"
    if not isinstance(contract, dict):
        errors.append(f"{location} must be an object")
        return {}
    if contract.get("status") not in {"pending", "completed", "stale", "blocked"}:
        errors.append(f"{location}.status is invalid")
    if contract.get("status") != "completed":
        errors.append(f"{location} must be completed before Code or Verification can complete")
    if contract.get("code_spec_fingerprint") != code_spec_fingerprint:
        errors.append(f"{location}.code_spec_fingerprint is stale")
    if contract.get("verdict") != "PASS":
        errors.append(f"{location}.verdict must be PASS")

    obligations = contract.get("obligations")
    if not isinstance(obligations, list) or not obligations:
        errors.append(f"{location}.obligations must be a non-empty array")
        return {}
    result: dict[str, dict[str, Any]] = {}
    coverage: set[str] = set()
    has_visual = False
    for index, item in enumerate(obligations):
        prefix = f"{location}.obligations[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        obligation_id = item.get("id")
        if not isinstance(obligation_id, str) or not PO_ID.fullmatch(obligation_id):
            errors.append(f"{prefix}.id must use PO-nn")
            continue
        if obligation_id in result:
            errors.append(f"duplicate proof obligation: {obligation_id}")
            continue
        result[obligation_id] = item
        product_ids = item.get("product_ids")
        if not isinstance(product_ids, list) or not product_ids:
            errors.append(f"{prefix}.product_ids must be a non-empty array")
        else:
            invalid = [value for value in product_ids if not isinstance(value, str) or not PRODUCT_ID.fullmatch(value)]
            unknown = {value for value in product_ids if isinstance(value, str)} - acceptance_ids
            if invalid or unknown:
                errors.append(f"{prefix}.product_ids contains unknown or invalid AC/EX IDs")
            coverage.update(value for value in product_ids if isinstance(value, str))
        proof_type = item.get("proof_type")
        if proof_type not in PROOF_TYPES:
            errors.append(f"{prefix}.proof_type must be one of {', '.join(sorted(PROOF_TYPES))}")
        has_visual = has_visual or proof_type == "visual"
        if not isinstance(item.get("critical"), bool):
            errors.append(f"{prefix}.critical must be boolean")
        for field in ("surface", "expected"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                errors.append(f"{prefix}.{field} must be concrete")
        environment = item.get("environment")
        if not isinstance(environment, str) or not environment.strip():
            errors.append(f"{prefix}.environment must freeze the target runtime environment")
        states = item.get("states")
        if proof_type in {"visual", "runtime"} and (
            not isinstance(states, list) or not states or not all(isinstance(value, str) and value.strip() for value in states)
        ):
            errors.append(f"{prefix}.states must enumerate target states for {proof_type} proof")

    missing = acceptance_ids - coverage
    if missing:
        errors.append(f"proof obligations do not cover acceptance IDs: {', '.join(sorted(missing))}")
    if prototype_completed and not has_visual:
        errors.append("visible UI with an approved prototype requires at least one visual proof obligation")
    return result


def validate_finalization(state: dict[str, Any], errors: list[str]) -> None:
    verification = state.get("stages", {}).get("verification", {})
    if verification.get("status") != "completed":
        return
    record = verification.get("finalization")
    if not isinstance(record, dict):
        errors.append("completed verification requires finalize_delivery.py finalization record")
        return
    if record.get("tool") != "finalize_delivery.py" or not isinstance(record.get("finalized_at"), str):
        errors.append("verification finalization record is invalid")
    expected = finalization_token(state)
    if record.get("token") != expected:
        errors.append("verification finalization token is stale or was not generated by current inputs")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    fingerprint = subparsers.add_parser("repository-fingerprint")
    fingerprint.add_argument("feature_id")
    fingerprint.add_argument("--root", default=".")
    args = parser.parse_args()
    if args.command == "repository-fingerprint":
        print(repository_fingerprint(Path(args.root).expanduser().resolve(), args.feature_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
