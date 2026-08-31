#!/usr/bin/env python3
"""Schema-v13 quality contracts shared by graph, Review, and Verification.

This module deliberately contains policy-free deterministic checks.  It never
decides PASS, lowers risk, or waives a Claim.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from delivery_proof import file_digest, value_digest


SCHEMA_VERSION = 13
CLAIM_LENSES = (
    "PROVENANCE_INTEGRITY",
    "STATE_AND_ATOMICITY",
    "BOUNDARY_AND_CONCURRENCY",
    "RUNTIME_AUTHENTICITY",
)
CLAIM_ID = re.compile(r"^CLM-[0-9a-f]{12}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PRODUCT_NODE_TYPES = {"Requirement", "Behavior", "Acceptance", "Exception"}
ORIGIN_KINDS = {"direct", "derived"}
DEFAULT_REVIEW_BUDGET = {
    "max_campaigns": 3,
    "max_unit_reviews": 24,
    "max_new_findings": 24,
}
MAX_AUTOMATIC_REVIEW_CAMPAIGNS = 3


def claim_semantic_key(claim: dict[str, Any]) -> dict[str, Any]:
    return {
        "lens": claim.get("lens"),
        "invariant": claim.get("invariant"),
        "subjects": sorted(claim.get("subjects", [])),
        "failure_boundary": claim.get("failure_boundary"),
        "critical": claim.get("critical"),
    }


def claim_id_for(claim: dict[str, Any]) -> str:
    return f"CLM-{value_digest(claim_semantic_key(claim))[:12]}"


def claims_by_id(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        claim["id"]: claim
        for claim in graph.get("claims", [])
        if isinstance(claim, dict) and isinstance(claim.get("id"), str)
    }


def claim_succession_map(graph: dict[str, Any]) -> dict[str, str]:
    # Semantic Claim changes create a new obligation. Automatically routing an
    # old Finding to a natural-language "stronger" invariant is not a
    # deterministic operation and can silently weaken the contract.
    return {}


def claim_errors(graph: dict[str, Any]) -> list[str]:
    claims = graph.get("claims")
    if not isinstance(claims, list):
        return ["Delivery Graph claims must be an array"]
    errors: list[str] = []
    seen: set[str] = set()
    node_ids = {
        node.get("id") for node in graph.get("nodes", [])
        if isinstance(node, dict) and isinstance(node.get("id"), str)
    }
    proof_ids = {
        node.get("id") for node in graph.get("nodes", [])
        if isinstance(node, dict) and node.get("type") == "Proof"
    }
    required = {"id", "lens", "invariant", "subjects", "failure_boundary", "critical", "proof_ids"}
    for index, claim in enumerate(claims):
        label = f"claims[{index}]"
        if not isinstance(claim, dict) or set(claim) != required:
            errors.append(f"{label} must contain exactly id, lens, invariant, subjects, failure_boundary, critical, and proof_ids")
            continue
        claim_id = claim.get("id")
        if not isinstance(claim_id, str) or not CLAIM_ID.fullmatch(claim_id):
            errors.append(f"{label}.id is invalid")
        elif claim_id in seen:
            errors.append(f"duplicate Claim id: {claim_id}")
        else:
            seen.add(claim_id)
        lens_valid = claim.get("lens") in CLAIM_LENSES
        if not lens_valid:
            errors.append(f"{label}.lens is invalid")
        invariant_valid = isinstance(claim.get("invariant"), str) and bool(claim["invariant"].strip())
        if not invariant_valid:
            errors.append(f"{label}.invariant must be non-empty")
        boundary_valid = isinstance(claim.get("failure_boundary"), str) and bool(claim["failure_boundary"].strip())
        if not boundary_valid:
            errors.append(f"{label}.failure_boundary must be non-empty")
        subjects = claim.get("subjects")
        subjects_valid = (
            isinstance(subjects, list) and bool(subjects)
            and all(isinstance(item, str) and item in node_ids for item in subjects)
        )
        if subjects_valid:
            subjects_valid = subjects == sorted(set(subjects))
        if not subjects_valid:
            errors.append(f"{label}.subjects must be a sorted, unique, non-empty array of graph node IDs")
        critical_valid = type(claim.get("critical")) is bool
        if not critical_valid:
            errors.append(f"{label}.critical must be boolean")
        if lens_valid and invariant_valid and boundary_valid and subjects_valid and critical_valid and claim_id != claim_id_for(claim):
            errors.append(f"{label}.id is stale for its stable semantic identity")
        if claim.get("lens") in {"STATE_AND_ATOMICITY", "BOUNDARY_AND_CONCURRENCY"} and claim.get("critical") is not True:
            errors.append(f"{label}.critical cannot downgrade a state, boundary, or concurrency Claim")
        bound_proofs = claim.get("proof_ids")
        if not isinstance(bound_proofs, list) or bound_proofs != sorted(set(bound_proofs)) or not all(
            isinstance(item, str) and item in proof_ids for item in bound_proofs
        ):
            errors.append(f"{label}.proof_ids must be a sorted, unique array of Proof node IDs")
    successions = graph.get("claim_successions")
    if not isinstance(successions, list):
        errors.append("Delivery Graph claim_successions must be an array")
    elif successions:
        errors.append(
            "Delivery Graph claim_successions must remain empty; semantic Claim changes "
            "require an independently reviewed new Claim and explicit Finding resolution"
        )
    return errors


def review_budget(graph: dict[str, Any]) -> dict[str, int]:
    configured = graph.get("metadata", {}).get("review_budget", {})
    if configured is None:
        configured = {}
    if not isinstance(configured, dict) or set(configured) - set(DEFAULT_REVIEW_BUDGET):
        raise ValueError("metadata.review_budget contains unknown fields")
    result = dict(DEFAULT_REVIEW_BUDGET)
    for key, value in configured.items():
        if type(value) is not int or value < 1:
            raise ValueError(f"metadata.review_budget.{key} must be a positive integer")
        if key == "max_campaigns" and value > MAX_AUTOMATIC_REVIEW_CAMPAIGNS:
            raise ValueError("metadata.review_budget.max_campaigns must be at most 3 before Owner decision")
        result[key] = value
    return result


def origin_errors(graph: dict[str, Any]) -> list[str]:
    """Require every contractual product statement to explain where it came from."""
    errors: list[str] = []
    for index, node in enumerate(graph.get("nodes", [])):
        if not isinstance(node, dict) or node.get("type") not in PRODUCT_NODE_TYPES:
            continue
        origins = node.get("origins")
        label = f"nodes[{index}].origins"
        if not isinstance(origins, list) or not origins:
            errors.append(f"{label} must be a non-empty array")
            continue
        for origin_index, origin in enumerate(origins):
            origin_label = f"{label}[{origin_index}]"
            if not isinstance(origin, dict) or origin.get("kind") not in ORIGIN_KINDS:
                errors.append(f"{origin_label} must declare direct or derived origin kind")
                continue
            if origin["kind"] == "direct":
                if set(origin) != {"kind", "source_ref"} or not isinstance(origin.get("source_ref"), str) or not origin["source_ref"].strip():
                    errors.append(f"{origin_label} direct origin requires exactly a non-empty source_ref")
            elif (
                set(origin) != {"kind", "constraint_ref", "reason"}
                or not isinstance(origin.get("constraint_ref"), str) or not origin["constraint_ref"].strip()
                or not isinstance(origin.get("reason"), str) or not origin["reason"].strip()
            ):
                errors.append(f"{origin_label} derived origin requires constraint_ref and reason")
    return errors


def delivery_prototype_shape_errors(prototype: Any) -> list[str]:
    if not isinstance(prototype, dict):
        return ["delivery_prototype declaration must be an object"]
    status = prototype.get("status")
    if status == "not_applicable":
        if set(prototype) != {"status", "reason"} or not isinstance(prototype.get("reason"), str) or not prototype["reason"].strip():
            return ["not-applicable delivery_prototype requires exactly status and a non-empty reason"]
        return []
    expected = {"status", "path", "sha256", "generated_from_revision", "generator"}
    if status != "generated" or set(prototype) != expected or prototype.get("path") != "prototype.html":
        return ["delivery_prototype must be not_applicable or a generated prototype.html"]
    if not isinstance(prototype.get("generated_from_revision"), str):
        return ["generated delivery_prototype revision is invalid"]
    if not isinstance(prototype.get("generator"), str) or not prototype["generator"].strip():
        return ["generated delivery_prototype generator is invalid"]
    if not isinstance(prototype.get("sha256"), str) or not SHA256.fullmatch(prototype["sha256"]):
        return ["delivery_prototype sha256 must be SHA-256"]
    return []


def delivery_prototype_provenance_errors(
    root: Path, feature_directory: Path, graph: dict[str, Any], source_revision: dict[str, Any],
) -> list[str]:
    prototype = graph.get("delivery_prototype", {})
    status = prototype.get("status") if isinstance(prototype, dict) else None
    if status == "not_applicable":
        path = feature_directory / "prototype.html"
        return ["prototype.html exists while delivery_prototype is not_applicable"] if path.exists() or path.is_symlink() else []
    if status != "generated":
        return ["delivery_prototype declaration is invalid"]
    path = feature_directory / "prototype.html"
    if not path.is_file() or path.resolve() != path.absolute():
        return ["Prototype requires a regular, non-symlink prototype.html"]
    errors = [] if file_digest(path) == prototype.get("sha256") else ["Delivery Prototype fingerprint is missing or stale"]
    if prototype.get("generated_from_revision") != graph.get("source_revision"):
        errors.append("generated Delivery Prototype source revision is stale")
    return errors


def prototype_review_blockers(graph: dict[str, Any]) -> list[str]:
    """Return prototype provenance drift that must block Product Alignment/Review."""
    prototype = graph.get("delivery_prototype")
    if (
        isinstance(prototype, dict) and prototype.get("status") == "generated"
        and prototype.get("generated_from_revision") != graph.get("source_revision")
    ):
        return ["generated Delivery Prototype source revision is stale"]
    return []


def target_attestation_provenance_errors(graph: dict[str, Any], source_revision: dict[str, Any]) -> list[str]:
    high_strength = {"runtime", "invariant", "visual"}
    bound_proof_ids: set[str] = set()
    claims = graph.get("claims", [])
    for claim in claims if isinstance(claims, list) else []:
        proof_ids_value = claim.get("proof_ids") if isinstance(claim, dict) else None
        if isinstance(proof_ids_value, list):
            bound_proof_ids.update(item for item in proof_ids_value if isinstance(item, str))
    proof_ids: set[str] = set()
    nodes = graph.get("nodes", [])
    for node in nodes if isinstance(nodes, list) else []:
        attributes = node.get("attributes") if isinstance(node, dict) else None
        if (
            isinstance(attributes, dict) and node.get("type") == "Proof"
            and attributes.get("proof_type") in high_strength and node.get("id") in bound_proof_ids
        ):
            proof_ids.add(node["id"])
    environment_ids = {
        edge.get("target") for edge in graph.get("edges", []) if isinstance(edge, dict)
        and edge.get("type") == "runs_in" and edge.get("source") in proof_ids
    }
    attachments = source_revision.get("attachments", [])
    if not isinstance(attachments, list):
        attachments = []
    errors: list[str] = []
    for node in nodes if isinstance(nodes, list) else []:
        if not isinstance(node, dict) or node.get("id") not in environment_ids:
            continue
        attributes = node.get("attributes")
        spec = attributes.get("spec") if isinstance(attributes, dict) else None
        config = spec.get("attestation") if isinstance(spec, dict) else None
        if not isinstance(config, dict):
            errors.append(f"high-strength Environment {node.get('id')} lacks source-bound target attestation")
            continue
        matches = [
            item for item in attachments if isinstance(item, dict)
            and item.get("ref") == config.get("source_ref")
        ]
        expected_sha = value_digest(config.get("public_key_jwk"))
        if (
            len(matches) != 1
            or matches[0].get("kind") != "target_attestation_jwk"
            or matches[0].get("jwk") != config.get("public_key_jwk")
            or matches[0].get("sha256") != expected_sha
            or config.get("source_sha256") != expected_sha
        ):
            errors.append(f"high-strength Environment {node.get('id')} target-attestation key provenance is missing or stale")
    return errors


def convergence_vector(graph: dict[str, Any], readiness: dict[str, Any], ledger: dict[str, Any]) -> list[int]:
    entries = list(ledger.get("entries", {}).values())
    obligation_weight = {"OPEN": 2, "MERGE_CANDIDATE": 2, "FIXED_PENDING_REVIEW": 1}
    critical = sum(
        obligation_weight.get(item.get("status"), 0)
        for item in entries if item.get("severity") == "critical"
    )
    nonwaivable_major = sum(
        obligation_weight.get(item.get("status"), 0)
        for item in entries
        if item.get("severity") == "major"
        and any(axis in {"TENANCY", "AUTHORIZATION", "MONEY", "IRREVERSIBLE_SIDE_EFFECT"} for axis in item.get("risk_axes", []))
    )
    claims = graph.get("claims", []) if isinstance(graph.get("claims"), list) else []
    unproven_critical = sum(item.get("critical") is True and not item.get("proof_ids") for item in claims if isinstance(item, dict))
    major = sum(
        obligation_weight.get(item.get("status"), 0)
        for item in entries if item.get("severity") == "major"
    )
    missing_proofs = sum(not item.get("proof_ids") for item in claims if isinstance(item, dict))
    stale_reviews = len(readiness.get("missing_units", [])) + len(readiness.get("blocked_units", []))
    review_units = len(readiness.get("required_units", []))
    return [critical, nonwaivable_major, unproven_critical, major, missing_proofs, stale_reviews, review_units]


def is_boolean_only_observation(observation: Any) -> bool:
    """True when an observation carries no non-boolean measured/read-back value."""
    ignored = {
        "challenge_nonce", "target_identity", "runtime", "target_attestation", "anchor_paths",
        "capture_profile", "prototype_sha256",
    }
    values: list[Any] = []

    def walk(value: Any, key: str | None = None) -> None:
        if key in ignored:
            return
        if isinstance(value, dict):
            for child_key, child in value.items():
                walk(child, child_key)
        elif isinstance(value, list):
            for child in value:
                walk(child)
        elif value is not None:
            values.append(value)

    walk(observation)
    return not values or all(type(value) is bool for value in values)
