#!/usr/bin/env python3
"""Validate executable access, lineage, projection, and runtime boundary proofs."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


BP_ID = re.compile(r"^BP-[0-9]+$")
PRODUCT_ID = re.compile(r"^(?:AC|EX)-[0-9]+$")
GENERIC = re.compile(r"(?:相关|全部|所有|etc\.?|TBD|TODO|同上|\ball\s+relevant\b|\bgeneric\b|\brelevant\s+(?:route|entry|service)\b)", re.I)


def _read_state(feature_dir: Path) -> dict[str, Any]:
    text = (feature_dir / "state.md").read_text(encoding="utf-8")
    match = re.search(r"<!-- DLV_STATE_START -->\s*```json\s*\n([\s\S]*?)\n```\s*<!-- DLV_STATE_END -->", text)
    if not match:
        raise ValueError("state.md has no valid DLV JSON block")
    return json.loads(match.group(1))


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and not GENERIC.search(value)


def _strings(value: Any, minimum: int = 1) -> bool:
    return isinstance(value, list) and len(value) >= minimum and all(_text(item) for item in value)


def _authorization(value: Any) -> bool:
    return _text(value) and bool(re.search(r"(?:\bAND\b|\bOR\b|:|=|\(|\)|且|或)", value, re.I))


def _guard(value: Any) -> bool:
    return _text(value) and bool(re.search(r"(?:\brequire\w*\b|\bguard\b|\bcheck\w*\b|校验|鉴权|授权|权限).*(?:\bbefore\b|写入|副作用|service|Service|Permission|权限)|(?:\brequire\w*\b|\bguard\b|\bcheck\w*\b)\w*", value, re.I))


def validate_boundary_proofs(
    packet: Any,
    acceptance_ids: set[str],
    architecture_text: str,
    code_spec_text: str,
    verification_text: str,
    architecture_completed: bool,
    errors: list[str],
) -> set[str]:
    location = "architecture_review.boundary_proofs"
    if not isinstance(packet, dict):
        errors.append(f"{location} must be an object")
        return set()
    applicable = packet.get("applicable")
    if applicable not in {True, False}:
        errors.append(f"{location}.applicable must be true or false")
        return set()
    if not applicable:
        if packet.get("verdict") != "N/A" or not _text(packet.get("reason")):
            errors.append(f"non-applicable {location} requires verdict=N/A and a concrete reason")
        return set()
    if packet.get("verdict") != "PASS":
        errors.append(f"applicable {location} must PASS")
    proofs = packet.get("proofs")
    if not isinstance(proofs, list) or not proofs:
        errors.append(f"applicable {location} requires at least one BP-* proof")
        return set()
    seen: set[str] = set()
    result: set[str] = set()
    for index, proof in enumerate(proofs):
        prefix = f"{location}.proofs[{index}]"
        if not isinstance(proof, dict):
            errors.append(f"{prefix} must be an object")
            continue
        proof_id = proof.get("id")
        if not isinstance(proof_id, str) or not BP_ID.fullmatch(proof_id):
            errors.append(f"{prefix}.id must use BP-nn")
            continue
        if proof_id in seen:
            errors.append(f"duplicate boundary proof: {proof_id}")
        seen.add(proof_id)
        result.add(proof_id)
        if architecture_completed and proof_id not in architecture_text:
            errors.append(f"architecture-design.md does not consume {proof_id}")
        if code_spec_text and proof_id not in code_spec_text:
            errors.append(f"code-spec.md does not consume {proof_id}")
        if verification_text and proof_id not in verification_text:
            errors.append(f"verification.md does not execute {proof_id}")
        for field in ("fact", "owner", "verdict"):
            if field == "verdict":
                if proof.get(field) != "PASS":
                    errors.append(f"{prefix}.verdict must PASS")
            elif not _text(proof.get(field)):
                errors.append(f"{prefix}.{field} must be concrete")
        if not _authorization(proof.get("authorization")):
            errors.append(f"{prefix}.authorization must be an explicit non-generic expression")
        product_ids = proof.get("product_ids")
        if not _strings(product_ids):
            errors.append(f"{prefix}.product_ids must be a non-empty explicit array")
        else:
            unknown = set(product_ids) - acceptance_ids
            invalid = {item for item in product_ids if not PRODUCT_ID.fullmatch(item)}
            if unknown or invalid:
                errors.append(f"{prefix}.product_ids contains unknown/invalid acceptance IDs")
        entrypoints = proof.get("entrypoints")
        if not isinstance(entrypoints, list) or not entrypoints:
            errors.append(f"{prefix}.entrypoints must be non-empty")
        else:
            for item in entrypoints:
                if not isinstance(item, dict) or not _text(item.get("route")) or not _text(item.get("symbol")) or not _guard(item.get("guard")):
                    errors.append(f"{prefix}.entrypoints requires exact route, symbol, and guard")
                    break
        lineage = proof.get("lineage")
        if not isinstance(lineage, dict) or not all(_text(lineage.get(key)) for key in ("selector", "source")) or not _strings(lineage.get("forbidden")):
            errors.append(f"{prefix}.lineage requires selector, source, and explicit forbidden sources")
        projection = proof.get("projection")
        if not isinstance(projection, dict) or not _strings(projection.get("safe_when_denied")) or not _strings(projection.get("sensitive")):
            errors.append(f"{prefix}.projection requires explicit safe_when_denied and sensitive fields")
        probes = proof.get("probes")
        if not _strings(probes, 2):
            errors.append(f"{prefix}.probes requires at least two explicit negative/runtime probes")
        elif not any("direct" in item.lower() or "直接" in item for item in probes):
            errors.append(f"{prefix}.probes must include a direct-entry probe")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_dir")
    args = parser.parse_args()
    errors: list[str] = []
    try:
        feature_dir = Path(args.feature_dir).expanduser().resolve()
        state = _read_state(feature_dir)
        read = lambda name: (feature_dir / name).read_text(encoding="utf-8") if (feature_dir / name).is_file() else ""
        prd, architecture, code_spec, verification = map(read, ("prd.md", "architecture-design.md", "code-spec.md", "verification.md"))
        acceptance = set(re.findall(r"\b(?:AC|EX)-[0-9]+\b", prd))
        validate_boundary_proofs(state.get("architecture_review", {}).get("boundary_proofs"), acceptance, architecture, code_spec, verification, state.get("stages", {}).get("architecture", {}).get("status") == "completed", errors)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(str(exc))
    for error in errors:
        print(f"ERROR: {error}")
    print("VALID" if not errors else f"INVALID: {len(errors)} error(s)")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
