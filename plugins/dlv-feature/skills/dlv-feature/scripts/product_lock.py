#!/usr/bin/env python3
"""Deterministic schema-v13 Product Alignment and Product Lock contracts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from delivery_governance import DECISION_REASONS, verify_kernel_receipt
from delivery_proof import file_digest, value_digest


ALIGNMENT_RESULTS = {"PRESERVED", "CLARIFIED", "DECISION_REQUIRED"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_ALIGNMENT_BYTES = 8 * 1024 * 1024
NON_PRODUCT_ATTACHMENT_KINDS = {"convergence_authority", "target_attestation_jwk", "repository_adapter"}


def load_alignment(path: Path) -> dict[str, Any]:
    from delivery_governance import read_bounded_regular

    content = read_bounded_regular(path, MAX_ALIGNMENT_BYTES, "Product Alignment artifact")
    assert content is not None
    value = json.loads(content.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Product Alignment artifact must be an object")
    return value


def _load_product_lock(path: Path) -> dict[str, Any]:
    from delivery_governance import read_bounded_regular

    content = read_bounded_regular(path, MAX_ALIGNMENT_BYTES, "Product Lock artifact")
    assert content is not None
    value = json.loads(content.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Product Lock artifact must be an object")
    return value


def delivery_prototype_digest(graph: dict[str, Any]) -> str | None:
    prototype = graph.get("delivery_prototype")
    return prototype.get("sha256") if isinstance(prototype, dict) and prototype.get("status") == "generated" else None


def product_node_ids(graph: dict[str, Any]) -> list[str]:
    return sorted(
        node["id"] for node in graph.get("nodes", [])
        if isinstance(node, dict) and node.get("type") in {"Requirement", "Behavior", "Acceptance", "Exception"}
    )


def source_anchor_refs(source_revision: dict[str, Any]) -> list[str]:
    revision_id = source_revision["revision_id"]
    anchors = [f"{revision_id}:title"]
    if source_revision.get("description"):
        anchors.append(f"{revision_id}:description")
    anchors.extend(f"{revision_id}:comment:{index:03d}" for index, _ in enumerate(source_revision.get("comments", []), 1))
    anchors.extend(
        item["ref"] for item in source_revision.get("attachments", [])
        if isinstance(item, dict) and item.get("kind") not in NON_PRODUCT_ATTACHMENT_KINDS
        and isinstance(item.get("ref"), str)
    )
    anchors.extend(
        item["id"] for item in source_revision.get("decisions", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    )
    return sorted(set(anchors))


def _anchor_origin_contract(source_revision: dict[str, Any], anchor: str) -> tuple[str, set[str]]:
    revision_id = source_revision["revision_id"]
    if anchor.startswith(f"{revision_id}:"):
        return "direct_revision", set()
    for attachment in source_revision.get("attachments", []):
        if isinstance(attachment, dict) and attachment.get("kind") not in NON_PRODUCT_ATTACHMENT_KINDS and attachment.get("ref") == anchor:
            return "direct", {
                value for key in ("ref", "locator")
                if isinstance((value := attachment.get(key)), str) and value
            }
    if any(isinstance(item, dict) and item.get("id") == anchor for item in source_revision.get("decisions", [])):
        return "derived", {anchor}
    raise ValueError(f"unknown Source anchor contract: {anchor}")


def source_anchor_node_ids(graph: dict[str, Any], source_revision: dict[str, Any], anchor: str) -> list[str]:
    kind, references = _anchor_origin_contract(source_revision, anchor)
    matched: list[str] = []
    for node in graph.get("nodes", []):
        if not isinstance(node, dict) or node.get("id") not in product_node_ids(graph):
            continue
        origins = node.get("origins", [])
        if kind == "direct_revision" and any(
            isinstance(origin, dict) and origin.get("kind") == "direct"
            and origin.get("source_ref") == source_revision["revision_id"]
            for origin in origins
        ):
            matched.append(node["id"])
        elif kind == "direct" and any(
            isinstance(origin, dict) and origin.get("kind") == "direct" and origin.get("source_ref") in references
            for origin in origins
        ):
            matched.append(node["id"])
        elif kind == "derived" and any(
            isinstance(origin, dict) and origin.get("kind") == "derived" and origin.get("constraint_ref") in references
            for origin in origins
        ):
            matched.append(node["id"])
    return sorted(matched)


def alignment_core(
    graph: dict[str, Any], source_revision: dict[str, Any], product_subgraph_sha256: str,
    prd_sha256: str, entries: list[dict[str, Any]], source_entries: list[dict[str, Any]], *,
    direct_refs: set[str], constraint_refs: set[str],
) -> dict[str, Any]:
    expected = product_node_ids(graph)
    seen: list[str] = []
    normalized: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"alignment entries[{index}] must be an object")
        required = {"node_id", "result", "evidence", "reason", "owner_question"}
        if set(entry) != required:
            raise ValueError(f"alignment entries[{index}] must contain exactly node_id, result, evidence, reason, and owner_question")
        node_id, result = entry.get("node_id"), entry.get("result")
        if node_id not in expected or node_id in seen:
            raise ValueError(f"alignment entries[{index}].node_id is unknown or duplicated")
        if result not in ALIGNMENT_RESULTS:
            raise ValueError(f"alignment entries[{index}].result is invalid")
        if not isinstance(entry.get("evidence"), str) or not entry["evidence"].strip():
            raise ValueError(f"alignment entries[{index}].evidence must be non-empty")
        reason, question = entry.get("reason"), entry.get("owner_question")
        if result == "DECISION_REQUIRED":
            if reason not in DECISION_REASONS or not isinstance(question, str) or not question.strip():
                raise ValueError("DECISION_REQUIRED alignment entry requires a reason and precise Owner question")
        elif reason is not None or question is not None:
            raise ValueError("non-decision alignment entry cannot carry reason or Owner question")
        seen.append(node_id)
        normalized.append(dict(entry))
    if sorted(seen) != expected:
        raise ValueError("alignment must cover every Requirement, Behavior, Acceptance, and Exception exactly once")
    verdict = "NEEDS_DECISION" if any(item["result"] == "DECISION_REQUIRED" for item in normalized) else "SAFE"
    anchors = source_anchor_refs(source_revision)
    normalized_source: list[dict[str, Any]] = []
    seen_anchors: set[str] = set()
    for index, entry in enumerate(source_entries):
        required = {"source_ref", "result", "node_ids", "evidence", "reason", "owner_question"}
        if not isinstance(entry, dict) or set(entry) != required:
            raise ValueError(f"alignment source_entries[{index}] has invalid shape")
        source_ref, result = entry.get("source_ref"), entry.get("result")
        if source_ref not in anchors or source_ref in seen_anchors:
            raise ValueError(f"alignment source_entries[{index}].source_ref is unknown or duplicated")
        node_ids = entry.get("node_ids")
        if (
            not isinstance(node_ids, list) or node_ids != sorted(set(node_ids))
            or not all(node_id in expected for node_id in node_ids)
        ):
            raise ValueError(f"alignment source_entries[{index}].node_ids are invalid")
        origin_nodes = source_anchor_node_ids(graph, source_revision, source_ref)
        if any(node_id not in origin_nodes for node_id in node_ids):
            raise ValueError(f"alignment source_entries[{index}] maps Source to nodes without reciprocal origins")
        if result not in ALIGNMENT_RESULTS or not isinstance(entry.get("evidence"), str) or not entry["evidence"].strip():
            raise ValueError(f"alignment source_entries[{index}] result/evidence is invalid")
        reason, question = entry.get("reason"), entry.get("owner_question")
        if result == "DECISION_REQUIRED":
            if reason not in DECISION_REASONS or not isinstance(question, str) or not question.strip():
                raise ValueError("DECISION_REQUIRED source entry requires a reason and Owner question")
        elif reason is not None or question is not None or not node_ids:
            raise ValueError("preserved/clarified source entry requires mapped nodes and no decision fields")
        seen_anchors.add(source_ref)
        normalized_source.append(dict(entry))
    if sorted(seen_anchors) != anchors:
        raise ValueError("alignment must cover every Source anchor exactly once")
    source_mappings = {item["source_ref"]: set(item["node_ids"]) for item in normalized_source}
    for anchor in anchors:
        for node_id in source_anchor_node_ids(graph, source_revision, anchor):
            if node_id not in source_mappings[anchor]:
                raise ValueError("alignment omits a reciprocal Graph origin from Source coverage")
    if any(item["result"] == "DECISION_REQUIRED" for item in normalized_source):
        verdict = "NEEDS_DECISION"
    source_refs = sorted({
        origin["source_ref"]
        for node in graph.get("nodes", []) if isinstance(node, dict) and node.get("id") in expected
        for origin in node.get("origins", []) if isinstance(origin, dict) and origin.get("kind") == "direct"
    })
    unknown_direct = set(source_refs) - direct_refs
    if unknown_direct:
        raise ValueError("alignment contains unmapped direct source refs: " + ", ".join(sorted(unknown_direct)))
    derived_refs = sorted({
        origin["constraint_ref"]
        for node in graph.get("nodes", []) if isinstance(node, dict) and node.get("id") in expected
        for origin in node.get("origins", []) if isinstance(origin, dict) and origin.get("kind") == "derived"
    })
    unknown_constraints = set(derived_refs) - constraint_refs
    if unknown_constraints:
        raise ValueError("alignment contains unmapped derived constraint refs: " + ", ".join(sorted(unknown_constraints)))
    return {
        "schema_version": 13,
        "feature_id": graph["feature_id"],
        "source_revision": graph["source_revision"],
        "source_digest": source_revision["source_digest"],
        "product_subgraph_sha256": product_subgraph_sha256,
        "prd_sha256": prd_sha256,
        "delivery_prototype_sha256": delivery_prototype_digest(graph),
        "reviewer": "codex-exec",
        "independent": True,
        "entries": sorted(normalized, key=lambda item: item["node_id"]),
        "source_entries": sorted(normalized_source, key=lambda item: item["source_ref"]),
        "source_coverage": {
            "covered_node_ids": expected,
            "source_anchor_refs": anchors,
            "direct_refs": source_refs,
            "derived_constraint_refs": derived_refs,
        },
        "verdict": verdict,
    }


def known_origin_refs(directory: Path, graph: dict[str, Any], source_revision: dict[str, Any]) -> tuple[set[str], set[str]]:
    """Resolve product origins to immutable Source records or declared constraints."""
    from delivery_governance import load_source_revision

    direct = {graph["source_revision"]}
    attachment_refs: set[str] = set()
    for item in source_revision.get("attachments", []):
        if not isinstance(item, dict) or item.get("kind") in NON_PRODUCT_ATTACHMENT_KINDS:
            continue
        for key in ("ref", "locator"):
            if isinstance(item.get(key), str) and item[key].strip():
                attachment_refs.add(item[key])
    decision_refs = {
        item["id"] for item in source_revision.get("decisions", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    return direct | attachment_refs, attachment_refs | decision_refs


def validate_alignment_record(
    alignment: dict[str, Any], graph: dict[str, Any], source_revision: dict[str, Any],
    product_subgraph_sha256: str, prd_sha256: str, *, directory: Path,
) -> list[str]:
    integrity_errors = alignment_integrity_errors(
        alignment, source_revision, directory=directory, feature_id=graph["feature_id"],
    )
    if integrity_errors:
        return integrity_errors
    return alignment_binding_errors(
        alignment, graph, source_revision, product_subgraph_sha256, prd_sha256,
        directory=directory,
    )


def alignment_binding_errors(
    alignment: dict[str, Any], graph: dict[str, Any], source_revision: dict[str, Any],
    product_subgraph_sha256: str, prd_sha256: str, *, directory: Path,
) -> list[str]:
    """Compare an already-authenticated Alignment with current product truth."""
    try:
        direct_refs, constraint_refs = known_origin_refs(directory, graph, source_revision)
        expected = alignment_core(
            graph, source_revision, product_subgraph_sha256, prd_sha256,
            alignment.get("entries"), alignment.get("source_entries"),
            direct_refs=direct_refs, constraint_refs=constraint_refs,
        )
        expected["execution"] = alignment["execution"]
        expected["alignment_digest"] = alignment_digest(expected)
    except (KeyError, TypeError, ValueError) as exc:
        return [str(exc)]
    return [] if alignment == expected else ["Product Alignment is stale or not reproducible"]


def alignment_integrity_errors(
    alignment: dict[str, Any], source_revision: dict[str, Any], *, directory: Path,
    feature_id: str,
) -> list[str]:
    """Validate immutable Alignment identity/provenance without current Graph bindings."""
    expected_keys = {
        "schema_version", "feature_id", "source_revision", "source_digest",
        "product_subgraph_sha256", "prd_sha256", "delivery_prototype_sha256",
        "reviewer", "independent", "entries", "source_entries", "source_coverage", "verdict",
        "execution", "alignment_digest",
    }
    if not isinstance(alignment, dict) or set(alignment) != expected_keys:
        return ["Product Alignment contains unknown or missing fields"]
    if (
        alignment.get("schema_version") != 13
        or alignment.get("feature_id") != feature_id
        or alignment.get("reviewer") != "codex-exec"
        or alignment.get("independent") is not True
        or alignment.get("verdict") != "SAFE"
    ):
        return ["Product Alignment immutable identity or SAFE verdict is invalid"]
    if alignment.get("alignment_digest") != alignment_digest(alignment):
        return ["Product Alignment content digest is invalid"]
    execution = alignment.get("execution")
    expected_execution_keys = {
        "mode", "provider", "invocation_id", "transcript_path", "transcript_sha256",
        "result_sha256", "independent", "kernel_receipt",
    }
    if (
        not isinstance(execution, dict) or set(execution) != expected_execution_keys
        or execution.get("mode") != "isolated_process" or execution.get("provider") != "codex-exec"
        or execution.get("independent") is not True
        or not isinstance(execution.get("invocation_id"), str)
        or re.fullmatch(r"alignment-[0-9a-f]{32}", execution["invocation_id"]) is None
        or execution.get("result_sha256") != value_digest({
            "entries": alignment.get("entries"), "source_entries": alignment.get("source_entries"),
        })
    ):
        return ["Product Alignment requires independent isolated-process execution"]
    root = directory.parent.parent
    transcript = root / str(execution.get("transcript_path", ""))
    review_dir = root / ".dlv" / "product-alignments" / feature_id
    if (
        not transcript.is_file() or transcript.resolve() != transcript.absolute()
        or transcript.parent != review_dir or file_digest(transcript) != execution.get("transcript_sha256")
    ):
        return ["Product Alignment transcript is missing, escaped, or stale"]
    receipt_payload = {
        "invocation_id": execution["invocation_id"],
        "transcript_sha256": execution["transcript_sha256"],
        "result_sha256": execution["result_sha256"],
        "source_digest": alignment.get("source_digest"),
        "product_subgraph_sha256": alignment.get("product_subgraph_sha256"),
        "prd_sha256": alignment.get("prd_sha256"),
        "delivery_prototype_sha256": alignment.get("delivery_prototype_sha256"),
    }
    try:
        verify_kernel_receipt(
            receipt_payload, execution.get("kernel_receipt"), source_revision,
            label="Product Alignment execution",
        )
    except (KeyError, TypeError, ValueError) as exc:
        return [str(exc)]
    return []


def alignment_digest(record: dict[str, Any]) -> str:
    return value_digest({key: value for key, value in record.items() if key != "alignment_digest"})


def lock_digest(record: dict[str, Any]) -> str:
    return value_digest({key: value for key, value in record.items() if key != "lock_digest"})


def load_current_product_lock(directory: Path, graph: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    reference = graph.get("product_lock")
    if reference is None:
        return None, ["current Product Lock is missing"]
    if not isinstance(reference, dict) or set(reference) != {"id", "sha256"}:
        return None, ["product_lock reference must contain exactly id and sha256"]
    lock_id, expected_sha = reference.get("id"), reference.get("sha256")
    if not isinstance(lock_id, str) or not re.fullmatch(r"PCL-[0-9a-f]{12}", lock_id):
        return None, ["product_lock id is invalid"]
    if not isinstance(expected_sha, str) or not SHA256.fullmatch(expected_sha):
        return None, ["product_lock sha256 is invalid"]
    path = directory / "product-locks" / f"{lock_id}.json"
    if not path.is_file() or path.resolve() != path.absolute():
        return None, ["current Product Lock artifact is missing"]
    try:
        record = _load_product_lock(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return None, [f"current Product Lock is invalid: {exc}"]
    if file_digest(path) != expected_sha or record.get("lock_digest") != lock_digest(record):
        return None, ["current Product Lock digest is stale"]
    expected_keys = {
        "schema_version", "feature_id", "source_revision", "source_digest",
        "product_subgraph_sha256", "prd_sha256", "delivery_prototype_sha256",
        "alignment_digest", "alignment_verdict", "source_coverage",
        "owner_decision_refs", "lock_digest",
    }
    if set(record) != expected_keys:
        return None, ["current Product Lock contains unknown or missing fields"]
    coverage = record.get("source_coverage")
    if not isinstance(coverage, dict) or set(coverage) != {"covered_node_ids", "source_anchor_refs", "direct_refs", "derived_constraint_refs"}:
        return None, ["current Product Lock source coverage is invalid"]
    if any(
        not isinstance(coverage.get(key), list)
        or not all(isinstance(item, str) for item in coverage[key])
        or coverage[key] != sorted(set(coverage[key]))
        for key in ("covered_node_ids", "source_anchor_refs", "direct_refs", "derived_constraint_refs")
    ):
        return None, ["current Product Lock source coverage values are invalid"]
    if (
        not isinstance(record.get("owner_decision_refs"), list)
        or not all(isinstance(item, str) for item in record["owner_decision_refs"])
        or record["owner_decision_refs"] != sorted(set(record["owner_decision_refs"]))
    ):
        return None, ["current Product Lock Owner decision references are invalid"]
    if lock_id != f"PCL-{record['lock_digest'][:12]}":
        return None, ["current Product Lock id disagrees with its content digest"]
    return record, []


def current_product_lock_status(
    directory: Path, graph: dict[str, Any], source_revision: dict[str, Any],
    product_subgraph_sha256: str, prd_sha256: str,
) -> dict[str, Any]:
    """Classify the current lock without inferring policy from error text.

    ``missing`` and ``content_stale`` are safe inputs to a fresh Product
    Alignment.  ``invalid`` means the content-addressed lock or its supporting
    Alignment cannot be trusted and must be recovered fail-closed.
    """
    if graph.get("product_lock") is None:
        return {"state": "missing", "errors": ["Delivery Graph has no current Product Lock"]}
    record, errors = load_current_product_lock(directory, graph)
    if record is None:
        return {"state": "invalid", "errors": errors}
    stale_errors: list[str] = []
    invalid_errors: list[str] = []
    expected = {
        "schema_version": 13,
        "feature_id": graph["feature_id"],
        "source_revision": graph["source_revision"],
        "source_digest": source_revision["source_digest"],
        "product_subgraph_sha256": product_subgraph_sha256,
        "prd_sha256": prd_sha256,
        "delivery_prototype_sha256": delivery_prototype_digest(graph),
    }
    for key, value in expected.items():
        if record.get(key) != value:
            stale_errors.append(f"current Product Lock {key} is stale")
    if record.get("source_coverage", {}).get("covered_node_ids") != product_node_ids(graph):
        stale_errors.append("current Product Lock source coverage is stale")
    if record.get("alignment_verdict") != "SAFE":
        invalid_errors.append("current Product Lock is not backed by SAFE Product Alignment")
    expected_decisions = sorted(
        item["id"] for item in source_revision.get("decisions", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    )
    if record.get("owner_decision_refs") != expected_decisions:
        stale_errors.append("current Product Lock Owner decision references are stale")
    alignment_value = record.get("alignment_digest")
    root = directory.parent.parent
    alignment_path = root / ".dlv" / "product-alignments" / graph["feature_id"] / f"ALN-{str(alignment_value)[:12]}.json"
    if (
        not isinstance(alignment_value, str) or not SHA256.fullmatch(alignment_value)
        or not alignment_path.is_file() or alignment_path.resolve() != alignment_path.absolute()
    ):
        invalid_errors.append("current Product Lock Product Alignment artifact is missing or symlinked")
    else:
        try:
            alignment = load_alignment(alignment_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            invalid_errors.append(f"current Product Lock Product Alignment artifact is invalid: {exc}")
        else:
            if alignment.get("alignment_digest") != alignment_value:
                invalid_errors.append("current Product Lock Product Alignment digest is stale")
            if record.get("alignment_verdict") != alignment.get("verdict") or alignment.get("verdict") != "SAFE":
                invalid_errors.append("current Product Lock disagrees with the authentic SAFE Product Alignment verdict")
            if record.get("source_coverage") != alignment.get("source_coverage"):
                invalid_errors.append("current Product Lock source coverage disagrees with Product Alignment")
            integrity_errors = alignment_integrity_errors(
                alignment, source_revision, directory=directory, feature_id=graph["feature_id"],
            )
            invalid_errors.extend(integrity_errors)
            if not integrity_errors:
                alignment_errors = alignment_binding_errors(
                    alignment, graph, source_revision, product_subgraph_sha256, prd_sha256,
                    directory=directory,
                )
                if stale_errors:
                    stale_errors.extend(alignment_errors)
                else:
                    invalid_errors.extend(alignment_errors)
    errors = [*stale_errors, *invalid_errors]
    if invalid_errors:
        state = "invalid"
    elif stale_errors:
        state = "content_stale"
    else:
        state = "safe"
    return {"state": state, "errors": errors}


def current_product_lock_errors(
    directory: Path, graph: dict[str, Any], source_revision: dict[str, Any],
    product_subgraph_sha256: str, prd_sha256: str,
) -> list[str]:
    return current_product_lock_status(
        directory, graph, source_revision, product_subgraph_sha256, prd_sha256,
    )["errors"]


def live_product_lock_status(root: Path, feature_id: str, graph: dict[str, Any] | None = None) -> dict[str, Any]:
    """Revalidate Product Lock, Product Alignment, PRD, and prototype at a live gate."""
    from delivery_graph import feature_dir, load_graph, prototype_errors, render_stage_document, stage_hash
    from delivery_governance import load_source_revision

    root = root.expanduser().resolve()
    graph = graph or load_graph(root, feature_id)
    directory = feature_dir(root, feature_id)
    errors = prototype_errors(root, feature_id, graph)
    try:
        source = load_source_revision(directory, feature_id, graph["source_revision"])
    except (KeyError, OSError, ValueError) as exc:
        return {"state": "invalid", "errors": [*errors, str(exc)]}
    prd_path = directory / "prd.md"
    expected_prd = render_stage_document(graph, "product")
    if not prd_path.is_file() or prd_path.resolve() != prd_path.absolute():
        return {"state": "invalid", "errors": [*errors, "current PRD artifact is missing or symlinked"]}
    if prd_path.read_text(encoding="utf-8") != expected_prd:
        errors.append("current PRD artifact is stale")
    status = current_product_lock_status(
        directory, graph, source, stage_hash(graph, "product"), file_digest(prd_path),
    )
    combined = [*errors, *status["errors"]]
    if errors and status["state"] == "safe":
        return {"state": "content_stale", "errors": combined}
    return {"state": status["state"], "errors": combined}


def live_product_lock_errors(root: Path, feature_id: str, graph: dict[str, Any] | None = None) -> list[str]:
    return live_product_lock_status(root, feature_id, graph)["errors"]
