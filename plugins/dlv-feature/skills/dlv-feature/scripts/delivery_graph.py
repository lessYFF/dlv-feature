#!/usr/bin/env python3
"""Schema-v10 Delivery Graph kernel and deterministic artifact compiler.

`delivery-graph.json` is the only editable delivery truth in schema v10.  This
module validates it, computes dependency-scoped hashes, renders disposable
human views, derives the Proof Contract, and keeps only references in
`state.json`.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from delivery_proof import (
    atomic_write_text,
    exclusive_file_lock,
    file_digest,
    load_json,
    repository_fingerprint,
    value_digest,
    validate_feature_id,
)


SCHEMA_VERSION = 10
STAGES = ("product", "architecture", "implementation_proof")
GLOBAL_LENS = "global-system-coherence"
GLOBAL_SKELETON_TYPES = {"Fact", "Owner", "Boundary", "StateTransition", "Risk", "Environment"}
GLOBAL_CLAIM_TYPES = {
    "Requirement", "Behavior", "Acceptance", "Exception", "Fact", "Owner",
    "Boundary", "StateTransition", "Decision", "Risk",
}
NODE_TYPES = {
    "Requirement", "Behavior", "Acceptance", "Exception", "Persona",
    "Fact", "Owner", "Boundary", "StateTransition", "Decision",
    "Change", "Symbol", "Test", "Environment", "Proof", "Assertion", "Risk",
}
EDGE_TYPES = {
    "derives_from", "owns", "guards", "transitions", "changes",
    "depends_on", "tests", "proves", "runs_in", "mitigates",
}
TYPE_STAGE = {
    **{name: "product" for name in ("Requirement", "Behavior", "Acceptance", "Exception", "Persona")},
    **{name: "architecture" for name in ("Fact", "Owner", "Boundary", "StateTransition", "Decision", "Risk")},
    **{name: "implementation_proof" for name in ("Change", "Symbol", "Test", "Environment", "Proof", "Assertion")},
}
TYPE_PREFIX = {
    "Requirement": "REQ", "Behavior": "BHV", "Acceptance": "AC", "Exception": "EX",
    "Persona": "PER", "Fact": "FACT", "Owner": "OWN", "Boundary": "BND",
    "StateTransition": "ST", "Decision": "DEC", "Change": "CHG", "Symbol": "SYM",
    "Test": "TST", "Environment": "ENV", "Proof": "PO", "Assertion": "ASRT",
    "Risk": "RISK",
}
NODE_ID = re.compile(r"^[A-Z][A-Z0-9_]*-[0-9]{3,}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
PROOF_TYPES = {"visual", "runtime", "boundary", "invariant", "artifact"}
ORACLE_OPERATORS = {"eq", "ne", "contains", "not_contains", "matches", "exists", "absent", "lte", "gte"}
ORACLE_KINDS = {"exit_code", "http_status", "json_path", "text", "file_hash", "screenshot_diff", "side_effect", "state"}
VISUAL_RUNTIMES = {"browser", "chromium", "firefox", "webkit", "wechat-devtools", "wechat-device", "ios", "android"}
MAX_COMMAND_TIMEOUT_SECONDS = 3600

# Every edge is directional: source depends on target.  The type constraints
# reject semantically meaningless graphs before a review can attest them.
EDGE_SHAPES: dict[str, tuple[set[str], set[str]]] = {
    "derives_from": (
        {"Behavior", "Acceptance", "Exception", "Fact", "Decision", "Change", "Test", "Proof", "Risk"},
        {"Requirement", "Behavior", "Acceptance", "Exception", "Persona", "Fact", "Boundary", "StateTransition", "Decision", "Change", "Risk"},
    ),
    "owns": ({"Owner"}, {"Fact", "Boundary", "StateTransition", "Decision", "Risk"}),
    "guards": ({"Boundary"}, {"Behavior", "Acceptance", "Exception", "StateTransition", "Change"}),
    "transitions": ({"StateTransition"}, {"Fact", "Boundary", "Decision"}),
    "changes": ({"Change"}, {"Behavior", "Fact", "Boundary", "StateTransition", "Decision"}),
    "depends_on": ({"Symbol", "Change", "Test", "Proof", "Assertion", "Decision"}, NODE_TYPES),
    "tests": ({"Test"}, {"Acceptance", "Exception", "Boundary", "StateTransition", "Change", "Symbol"}),
    "proves": ({"Proof", "Assertion"}, {"Acceptance", "Exception", "Boundary", "StateTransition", "Change", "Test", "Proof", "Risk"}),
    "runs_in": ({"Test", "Proof"}, {"Environment"}),
    "mitigates": ({"Decision", "Change", "Test", "Proof"}, {"Risk"}),
}

LENSES: dict[str, dict[str, Any]] = {
    "product-contract": {
        "stage": "product",
        "types": {"Requirement", "Behavior", "Acceptance", "Exception", "Persona"},
        "edges": {"derives_from"},
    },
    "fact-ownership": {
        "stage": "architecture",
        "types": {"Fact", "Owner", "Decision"},
        "edges": {"owns", "derives_from", "depends_on"},
    },
    "boundary-state-safety": {
        "stage": "architecture",
        "types": {"Boundary", "StateTransition", "Exception", "Risk", "Owner"},
        "edges": {"owns", "guards", "transitions", "derives_from", "mitigates"},
    },
    "change-traceability": {
        "stage": "implementation_proof",
        "types": {"Change", "Symbol", "Decision", "Behavior", "Boundary", "StateTransition"},
        "edges": {"changes", "depends_on", "derives_from"},
    },
    "proof-coverage": {
        "stage": "implementation_proof",
        "types": {"Acceptance", "Exception", "Test", "Environment", "Proof", "Assertion", "Risk"},
        "edges": {"tests", "proves", "runs_in", "mitigates", "depends_on"},
    },
}

# Shared providers remain visible in each dependency closure but must not join
# otherwise independent review components merely because every proof uses the
# same runtime or mitigates the same cross-cutting risk.
NON_PARTITIONING_ROOT_TYPES = {
    "proof-coverage": {"Environment", "Risk"},
}


def timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def confined_project_path(root: Path, relative: Path | str, label: str) -> Path:
    root = root.expanduser().resolve()
    path = root / relative
    try:
        path.absolute().relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} escapes the project root") from exc
    # resolve(strict=False) exposes a symlink in any existing ancestor even
    # when the final path does not exist yet.
    if path.resolve() != path.absolute():
        raise ValueError(f"{label} must not be relocated through a symlink")
    return path


def feature_dir(root: Path, feature_id: str) -> Path:
    validate_feature_id(feature_id)
    root = root.expanduser().resolve()
    return confined_project_path(root, Path("delivery") / feature_id, "feature directory")


def graph_path(root: Path, feature_id: str) -> Path:
    return feature_dir(root, feature_id) / "delivery-graph.json"


def is_v10(root: Path, feature_id: str) -> bool:
    try:
        path = graph_path(root, feature_id)
    except ValueError:
        return False
    return path.is_file()


def default_graph(feature_id: str, title: str | None = None) -> dict[str, Any]:
    validate_feature_id(feature_id)
    return {
        "schema_version": SCHEMA_VERSION,
        "feature_id": feature_id,
        "title": title or feature_id.replace("-", " ").title(),
        "nodes": [],
        "edges": [],
        "prototype": {"status": "not_applicable"},
    }


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def load_graph(root: Path, feature_id: str) -> dict[str, Any]:
    path = graph_path(root, feature_id)
    if not path.is_file():
        raise ValueError(f"missing Delivery Graph: {path}")
    if path.resolve() != path.absolute():
        raise ValueError("delivery-graph.json must not be relocated through a symlink")
    graph = load_json(path)
    if graph.get("feature_id") != feature_id:
        raise ValueError("Delivery Graph feature_id disagrees with directory/argument")
    return graph


def node_map(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(node.get("id")): node
        for node in graph.get("nodes", [])
        if isinstance(node, dict) and isinstance(node.get("id"), str)
    }


def edge_key(edge: dict[str, Any]) -> tuple[str, str, str]:
    return str(edge.get("source")), str(edge.get("type")), str(edge.get("target"))


def normalized_graph(graph: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(graph)
    if isinstance(value.get("nodes"), list):
        value["nodes"] = sorted(value["nodes"], key=lambda node: str(node.get("id")))
    if isinstance(value.get("edges"), list):
        value["edges"] = sorted(value["edges"], key=edge_key)
    return value


def graph_digest(graph: dict[str, Any]) -> str:
    return value_digest(normalized_graph(graph))


def structural_errors(graph: dict[str, Any], feature_id: str | None = None) -> list[str]:
    errors: list[str] = []
    allowed_top = {"schema_version", "feature_id", "title", "nodes", "edges", "prototype", "metadata"}
    unknown = set(graph) - allowed_top
    if unknown:
        errors.append("Delivery Graph contains unknown top-level keys: " + ", ".join(sorted(unknown)))
    if graph.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"Delivery Graph schema_version must be {SCHEMA_VERSION}")
    graph_feature_id = graph.get("feature_id")
    try:
        validate_feature_id(graph_feature_id)
    except (TypeError, ValueError):
        errors.append("Delivery Graph feature_id is invalid")
    if feature_id is not None and graph_feature_id != feature_id:
        errors.append("Delivery Graph feature_id disagrees with directory/argument")
    if not isinstance(graph.get("title"), str) or not graph["title"].strip():
        errors.append("Delivery Graph title must be a non-empty string")
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, list):
        errors.append("Delivery Graph nodes must be an array")
        nodes = []
    if not isinstance(edges, list):
        errors.append("Delivery Graph edges must be an array")
        edges = []
    seen: set[str] = set()
    typed: dict[str, str] = {}
    for index, node in enumerate(nodes):
        location = f"nodes[{index}]"
        if not isinstance(node, dict):
            errors.append(f"{location} must be an object")
            continue
        unknown_node = set(node) - {"id", "type", "title", "statement", "attributes"}
        if unknown_node:
            errors.append(f"{location} contains unknown keys: {', '.join(sorted(unknown_node))}")
        node_id, node_type = node.get("id"), node.get("type")
        if not isinstance(node_id, str) or not NODE_ID.fullmatch(node_id):
            errors.append(f"{location}.id must be an uppercase typed ID with at least three digits")
        elif node_id in seen:
            errors.append(f"duplicate node id: {node_id}")
        else:
            seen.add(node_id)
            if isinstance(node_type, str):
                typed[node_id] = node_type
        if node_type not in NODE_TYPES:
            errors.append(f"{location}.type is invalid: {node_type!r}")
        elif isinstance(node_id, str) and not node_id.startswith(TYPE_PREFIX[node_type] + "-"):
            errors.append(f"{location}.id must use {TYPE_PREFIX[node_type]}- prefix for {node_type}")
        for field in ("title", "statement"):
            if not isinstance(node.get(field), str) or not node[field].strip():
                errors.append(f"{location}.{field} must be a non-empty string")
        if "attributes" in node and not isinstance(node["attributes"], dict):
            errors.append(f"{location}.attributes must be an object")
    seen_edges: set[tuple[str, str, str]] = set()
    for index, edge in enumerate(edges):
        location = f"edges[{index}]"
        if not isinstance(edge, dict):
            errors.append(f"{location} must be an object")
            continue
        if set(edge) != {"source", "target", "type"}:
            errors.append(f"{location} must contain exactly source, target, and type")
        source, target, relation = edge.get("source"), edge.get("target"), edge.get("type")
        if source not in seen:
            errors.append(f"{location}.source references unknown node: {source!r}")
        if target not in seen:
            errors.append(f"{location}.target references unknown node: {target!r}")
        if source == target:
            errors.append(f"{location} cannot be a self-edge")
        if relation not in EDGE_TYPES:
            errors.append(f"{location}.type is invalid: {relation!r}")
        key = edge_key(edge)
        if key in seen_edges:
            errors.append(f"duplicate edge: {key[0]} {key[1]} {key[2]}")
        seen_edges.add(key)
        if relation in EDGE_SHAPES and source in typed and target in typed:
            sources, targets = EDGE_SHAPES[relation]
            if typed[source] not in sources or typed[target] not in targets:
                errors.append(
                    f"{location} has invalid shape for {relation}: {typed[source]} -> {typed[target]}"
                )
    dependency_graph: dict[str, list[str]] = {node_id: [] for node_id in seen}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if edge.get("type") in {"owns", "guards"}:
            dependent, dependency = edge.get("target"), edge.get("source")
        else:
            dependent, dependency = edge.get("source"), edge.get("target")
        if dependent in dependency_graph and dependency in dependency_graph:
            dependency_graph[dependent].append(dependency)
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node_id: str) -> bool:
        if node_id in visiting:
            return True
        if node_id in visited:
            return False
        visiting.add(node_id)
        if any(visit(target) for target in dependency_graph[node_id]):
            return True
        visiting.remove(node_id)
        visited.add(node_id)
        return False

    if any(visit(node_id) for node_id in sorted(dependency_graph) if node_id not in visited):
        errors.append("Delivery Graph dependency relationships must be acyclic")
    prototype = graph.get("prototype", {"status": "not_applicable"})
    if not isinstance(prototype, dict) or prototype.get("status") not in {"not_applicable", "completed"}:
        errors.append("prototype must be an object with status not_applicable or completed")
    elif prototype.get("status") == "not_applicable" and set(prototype) != {"status"}:
        errors.append("not-applicable prototype must contain exactly status")
    elif prototype.get("status") == "completed" and (
        set(prototype) != {"status", "path", "sha256"}
        or prototype.get("path") != "prototype.html"
        or not isinstance(prototype.get("sha256"), str)
        or not SHA256.fullmatch(prototype["sha256"])
    ):
        errors.append("completed prototype requires exactly path=prototype.html and a SHA-256")
    return errors


def prototype_errors(root: Path, feature_id: str, graph: dict[str, Any]) -> list[str]:
    """Validate the editable Prototype bytes bound by the Product contract."""
    path = feature_dir(root, feature_id) / "prototype.html"
    prototype = graph.get("prototype", {"status": "not_applicable"})
    if not isinstance(prototype, dict):
        return ["prototype declaration is invalid"]
    if prototype.get("status") == "not_applicable":
        return ["prototype.html exists while prototype is not_applicable"] if path.exists() or path.is_symlink() else []
    if prototype.get("status") != "completed":
        return ["prototype declaration is invalid"]
    if not path.is_file() or path.resolve() != path.absolute():
        return ["completed Prototype requires a regular, non-symlink prototype.html"]
    return [] if prototype.get("sha256") == file_digest(path) else ["Prototype fingerprint is missing or stale"]


def dependency_closure(
    graph: dict[str, Any], roots: Iterable[str], *, barriers: Iterable[str] = (),
) -> set[str]:
    """Return roots plus everything they transitively depend on."""
    by_source: dict[str, list[str]] = {}
    for edge in graph.get("edges", []):
        # owns/guards point from provider to consumer; all other relations
        # point from the dependent claim to its dependency.
        if edge.get("type") in {"owns", "guards"}:
            dependent, dependency = edge.get("target"), edge.get("source")
        else:
            dependent, dependency = edge.get("source"), edge.get("target")
        if isinstance(dependent, str) and isinstance(dependency, str):
            by_source.setdefault(dependent, []).append(dependency)
    seen = set(roots)
    blocked = set(barriers) - seen
    pending = list(seen)
    while pending:
        current = pending.pop()
        for target in by_source.get(current, []):
            if target not in seen and target not in blocked:
                seen.add(target)
                pending.append(target)
    return seen


def impact_closure(graph: dict[str, Any], changed: Iterable[str]) -> set[str]:
    """Return changed nodes plus every transitive dependent."""
    by_target: dict[str, list[str]] = {}
    for edge in graph.get("edges", []):
        if edge.get("type") in {"owns", "guards"}:
            dependent, dependency = edge.get("target"), edge.get("source")
        else:
            dependent, dependency = edge.get("source"), edge.get("target")
        if isinstance(dependent, str) and isinstance(dependency, str):
            by_target.setdefault(dependency, []).append(dependent)
    seen = set(changed)
    pending = list(seen)
    while pending:
        current = pending.pop()
        for source in by_target.get(current, []):
            if source not in seen:
                seen.add(source)
                pending.append(source)
    return seen


def subgraph(graph: dict[str, Any], selected: set[str]) -> dict[str, Any]:
    nodes = sorted(
        (copy.deepcopy(node) for node in graph.get("nodes", []) if node.get("id") in selected),
        key=lambda node: node["id"],
    )
    edges = sorted(
        (copy.deepcopy(edge) for edge in graph.get("edges", []) if edge.get("source") in selected and edge.get("target") in selected),
        key=edge_key,
    )
    return {"nodes": nodes, "edges": edges}


def stage_node_ids(graph: dict[str, Any], stage: str) -> set[str]:
    if stage not in STAGES:
        raise ValueError(f"unknown Delivery Graph stage: {stage}")
    roots = {
        node["id"] for node in graph.get("nodes", [])
        if isinstance(node, dict) and TYPE_STAGE.get(node.get("type")) == stage
    }
    return dependency_closure(graph, roots)


def stage_hash(graph: dict[str, Any], stage: str) -> str:
    payload: dict[str, Any] = {"stage": stage, **subgraph(graph, stage_node_ids(graph, stage))}
    if stage == "product":
        payload["prototype"] = graph.get("prototype", {"status": "not_applicable"})
    return value_digest(payload)


def lens_node_ids(graph: dict[str, Any], lens: str) -> set[str]:
    spec = LENSES[lens]
    non_partitioning = NON_PARTITIONING_ROOT_TYPES.get(lens, set())
    roots = {
        node["id"] for node in graph.get("nodes", [])
        if (
            isinstance(node, dict)
            and node.get("type") in spec["types"]
            and node.get("type") not in non_partitioning
        )
    }
    selected = set(roots)
    # Include the exact connected context used by the lens, then its upstream
    # dependencies. Unrelated graph branches do not invalidate the attestation.
    provider_edges = {"owns", "guards", "mitigates"}
    for edge in graph.get("edges", []):
        touches_in_scope_dependency = (
            edge.get("source") in roots
            or (edge.get("type") in provider_edges and edge.get("target") in roots)
        )
        if edge.get("type") in spec["edges"] and touches_in_scope_dependency:
            selected.update({edge["source"], edge["target"]})
    return dependency_closure(graph, selected)


def lens_hash(graph: dict[str, Any], lens: str) -> str:
    payload: dict[str, Any] = {"lens": lens, **subgraph(graph, lens_node_ids(graph, lens))}
    if lens == "product-contract":
        payload["prototype"] = graph.get("prototype", {"status": "not_applicable"})
    return value_digest(payload)


def lens_components(graph: dict[str, Any], lens: str) -> list[dict[str, Any]]:
    """Deterministically partition one lens without trusting caller boundaries."""
    if lens not in LENSES:
        raise ValueError(f"unknown review lens: {lens}")
    spec = LENSES[lens]
    non_partitioning = NON_PARTITIONING_ROOT_TYPES.get(lens, set())
    roots = {
        node["id"] for node in graph.get("nodes", [])
        if (
            isinstance(node, dict)
            and node.get("type") in spec["types"]
            and node.get("type") not in non_partitioning
        )
    }
    adjacency = {node_id: set() for node_id in roots}
    for edge in graph.get("edges", []):
        source, target = edge.get("source"), edge.get("target")
        if edge.get("type") in spec["edges"] and source in roots and target in roots:
            adjacency[source].add(target)
            adjacency[target].add(source)
    pending = set(roots)
    result: list[dict[str, Any]] = []
    while pending:
        start = min(pending)
        members, frontier = set(), [start]
        while frontier:
            current = frontier.pop()
            if current in members:
                continue
            members.add(current)
            pending.discard(current)
            frontier.extend(sorted(adjacency[current] - members, reverse=True))
        seeds = set(members)
        for edge in graph.get("edges", []):
            if edge.get("type") in {"owns", "guards", "mitigates"} and edge.get("target") in members:
                seeds.add(edge["source"])
        selected = dependency_closure(graph, seeds, barriers=roots - members)
        component_id = value_digest({"lens": lens, "roots": sorted(members)})[:16]
        component_payload: dict[str, Any] = {
            "lens": lens,
            "component_id": component_id,
            "lens_graph_issues": [
                issue for issue in semantic_issues(graph, lens)
                if issue["node_id"] == "GRAPH"
            ],
            **subgraph(graph, selected),
        }
        if lens == "product-contract":
            component_payload["prototype"] = graph.get("prototype", {"status": "not_applicable"})
        result.append({
            "unit_id": f"{lens}--{component_id}",
            "lens": lens,
            "component_id": component_id,
            "root_node_ids": sorted(members),
            "node_ids": sorted(selected),
            "lens_graph_issues": component_payload["lens_graph_issues"],
            "subgraph_sha256": value_digest(component_payload),
        })
    return sorted(result, key=lambda item: item["unit_id"])


def global_skeleton_node_ids(graph: dict[str, Any]) -> set[str]:
    nodes = node_map(graph)
    selected = {
        node_id for node_id, node in nodes.items()
        if node.get("type") in {"Owner", "Boundary", "StateTransition"}
        or (
            node.get("type") == "Risk"
            and node.get("attributes", {}).get("severity") in {"critical", "major"}
        )
    }
    occurrences: dict[str, set[str]] = {}
    for lens in LENSES:
        for component in lens_components(graph, lens):
            for node_id in component["node_ids"]:
                occurrences.setdefault(node_id, set()).add(component["unit_id"])
    selected.update(
        node_id for node_id, units in occurrences.items()
        if len(units) > 1 and nodes[node_id].get("type") in GLOBAL_SKELETON_TYPES
    )
    return selected


def review_units(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    units: dict[str, dict[str, Any]] = {}
    for lens in sorted(LENSES):
        for component in lens_components(graph, lens):
            units[component["unit_id"]] = component
    selected = global_skeleton_node_ids(graph)
    topology = [
        {"unit_id": unit_id, "lens": unit["lens"], "root_node_ids": unit["root_node_ids"]}
        for unit_id, unit in sorted(units.items())
    ]
    nodes = node_map(graph)
    memberships: dict[str, list[str]] = {}
    for unit_id, unit in units.items():
        for node_id in unit["node_ids"]:
            if nodes[node_id]["type"] in GLOBAL_CLAIM_TYPES:
                memberships.setdefault(node_id, []).append(unit_id)
    claim_synopsis = [
        {
            "id": node_id,
            "type": nodes[node_id]["type"],
            "title": nodes[node_id]["title"],
            "statement": nodes[node_id]["statement"],
            "component_unit_ids": sorted(unit_ids),
        }
        for node_id, unit_ids in sorted(memberships.items())
    ]
    skeleton_hash = value_digest({
        "lens": GLOBAL_LENS,
        "component_topology": topology,
        "claim_synopsis": claim_synopsis,
        **subgraph(graph, selected),
    })
    units[GLOBAL_LENS] = {
        "unit_id": GLOBAL_LENS,
        "lens": GLOBAL_LENS,
        "component_id": "global",
        "root_node_ids": sorted(selected),
        "node_ids": sorted(selected),
        "component_topology": topology,
        "claim_synopsis": claim_synopsis,
        "subgraph_sha256": skeleton_hash,
    }
    return dict(sorted(units.items()))


def readiness(graph: dict[str, Any], attestations: dict[str, Any]) -> dict[str, Any]:
    units = review_units(graph)
    missing = sorted(unit_id for unit_id in units if unit_id not in attestations)
    blocked = sorted(
        unit_id for unit_id in units
        if isinstance(attestations.get(unit_id), dict)
        and attestations[unit_id].get("verdict") != "PASS"
    )
    return {
        "status": "ready" if not missing and not blocked else "blocked" if blocked else "pending",
        "required_units": sorted(units),
        "missing_units": missing,
        "blocked_units": blocked,
        "global_skeleton_sha256": units[GLOBAL_LENS]["subgraph_sha256"],
    }


def applicable_lenses(graph: dict[str, Any], stage: str) -> list[str]:
    nodes = node_map(graph)
    result: list[str] = []
    for name, spec in LENSES.items():
        if spec["stage"] != stage:
            continue
        # The primary lens for every stage is always applicable; optional
        # architecture lenses activate only when their domain appears.
        lens_types = {nodes[node_id]["type"] for node_id in lens_node_ids(graph, name) if node_id in nodes}
        if stage in {"product", "implementation_proof"} or name == "fact-ownership" or lens_types & spec["types"]:
            result.append(name)
    return sorted(result)


def _has_edge(graph: dict[str, Any], *, source: str | None = None, target: str | None = None, relation: str | None = None) -> bool:
    return any(
        (source is None or edge.get("source") == source)
        and (target is None or edge.get("target") == target)
        and (relation is None or edge.get("type") == relation)
        for edge in graph.get("edges", [])
    )


def _mask_sql_comments(sql: str) -> str:
    chars = list(sql)
    index = 0
    quote: str | None = None
    while index < len(chars):
        if quote:
            if chars[index] == quote:
                if index + 1 < len(chars) and chars[index + 1] == quote:
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if chars[index] in {"'", '"'}:
            quote = chars[index]
            index += 1
            continue
        if chars[index:index + 2] == ["-", "-"]:
            while index < len(chars) and chars[index] != "\n":
                chars[index] = " "
                index += 1
            continue
        if chars[index:index + 2] == ["/", "*"]:
            chars[index:index + 2] = [" ", " "]
            index += 2
            while index < len(chars):
                if chars[index:index + 2] == ["*", "/"]:
                    chars[index:index + 2] = [" ", " "]
                    index += 2
                    break
                if chars[index] != "\n":
                    chars[index] = " "
                index += 1
            continue
        index += 1
    return "".join(chars)


def _sql_table_blocks(sql: str) -> list[tuple[str, str]]:
    pattern = re.compile(r'\bCREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+([\w."]+)\s*\(', re.I)
    masked = _mask_sql_comments(sql)
    blocks: list[tuple[str, str]] = []
    for match in pattern.finditer(masked):
        depth, index, quote = 1, match.end(), None
        while index < len(masked) and depth:
            char = masked[index]
            if quote:
                if char == quote:
                    quote = None
            elif char in {"'", '"'}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            index += 1
        if depth == 0:
            blocks.append((match.group(1).strip('"'), sql[match.end():index - 1]))
    return blocks


def _split_sql_definitions(body: str) -> list[str]:
    definitions: list[str] = []
    start = depth = 0
    quote: str | None = None
    masked = _mask_sql_comments(body)
    for index, char in enumerate(masked):
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            definitions.append(body[start:index])
            start = index + 1
    definitions.append(body[start:])
    return definitions


def database_schema_errors(sql: Any) -> list[str]:
    """Validate a schema contract, not repository-specific migration machinery."""
    if not isinstance(sql, str) or not sql.strip():
        return ["database persistence requires non-empty schema_sql"]
    executable = _mask_sql_comments(sql)
    executable_without_literals = re.sub(r"'(?:''|[^'])*'", "''", executable)
    errors: list[str] = []
    if re.search(r"\bV[0-9]+__[A-Za-z0-9_-]+\b", sql, re.I):
        errors.append("schema_sql must not contain repository migration numbering")
    if not re.search(r"\b(?:CREATE|ALTER)\s+TABLE\b", executable_without_literals, re.I):
        errors.append("schema_sql requires executable CREATE TABLE or ALTER TABLE DDL")
    if re.search(
        r"\b(?:DO|EXECUTE|LOOP|CREATE\s+SCHEMA|DROP|INSERT|UPDATE|DELETE)\b|\bFOR\s+\w+\s+IN\b",
        executable_without_literals, re.I,
    ):
        errors.append("schema_sql must not contain migration execution logic")
    comment_targets = {
        (table.strip('"').lower(), column.strip('"').lower())
        for table, column in re.findall(
            r"COMMENT\s+ON\s+COLUMN\s+([\w.\"]+)\.([\w\"]+)", executable, re.I,
        )
    }
    uncommented: list[str] = []
    for table, body in _sql_table_blocks(sql):
        inline_commented = {
            match.group(1).strip('"').lower()
            for line in body.splitlines()
            if (match := re.match(r'\s*("?[A-Za-z_][\w]*"?)\s+[A-Za-z]', line))
            and re.search(r"--\s*\S", line)
        }
        for definition in _split_sql_definitions(body):
            stripped = re.sub(r"^(?:\s*--[^\n]*\n)+", "", definition).strip()
            if not stripped or re.match(r"(?i)^(?:CONSTRAINT|PRIMARY|FOREIGN|UNIQUE|CHECK)\b", stripped):
                continue
            match = re.match(r'("?[A-Za-z_][\w]*"?)\s+[A-Za-z]', stripped)
            if match:
                column = match.group(1).strip('"')
                if column.lower() not in inline_commented and (table.lower(), column.lower()) not in comment_targets:
                    uncommented.append(f"{table}.{column}")
    for match in re.finditer(
        r'ALTER\s+TABLE\s+([\w.\"]+)\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?("?[A-Za-z_][\w]*"?)([^;\n]*)',
        executable, re.I,
    ):
        table, column = match.group(1).strip('"'), match.group(2).strip('"')
        line_end = sql.find("\n", match.end())
        raw_tail = sql[match.start(3):len(sql) if line_end < 0 else line_end]
        if not re.search(r"--\s*\S", raw_tail) and (table.lower(), column.lower()) not in comment_targets:
            uncommented.append(f"{table}.{column}")
    if uncommented:
        errors.append("schema_sql columns require comments: " + ", ".join(sorted(set(uncommented))))
    return errors


def semantic_issues(graph: dict[str, Any], lens: str | None = None) -> list[dict[str, str]]:
    """Return deterministic, typed issues; every major issue blocks PASS."""
    nodes = node_map(graph)
    issues: list[dict[str, str]] = []

    def add(code: str, node_id: str, statement: str, severity: str = "major") -> None:
        issues.append({"code": code, "node_id": node_id, "severity": severity, "statement": statement})

    def typed_edges(*, source: str | None = None, target: str | None = None, relation: str, source_type: str | None = None) -> list[dict[str, Any]]:
        return [
            edge for edge in graph.get("edges", [])
            if (source is None or edge.get("source") == source)
            and (target is None or edge.get("target") == target)
            and edge.get("type") == relation
            and (source_type is None or nodes.get(edge.get("source"), {}).get("type") == source_type)
        ]

    enabled = set(LENSES) if lens is None else {lens}
    if "product-contract" in enabled:
        requirements = [n for n in nodes.values() if n["type"] == "Requirement"]
        acceptances = [n for n in nodes.values() if n["type"] == "Acceptance"]
        if not requirements:
            add("PRODUCT_NO_REQUIREMENT", "GRAPH", "Product subgraph requires at least one Requirement")
        if not acceptances:
            add("PRODUCT_NO_ACCEPTANCE", "GRAPH", "Product subgraph requires at least one Acceptance")
        for node in nodes.values():
            if node["type"] == "Requirement" and not any(
                nodes.get(edge.get("source"), {}).get("type") == "Behavior"
                for edge in typed_edges(target=node["id"], relation="derives_from")
            ):
                add("PRODUCT_UNUSED_REQUIREMENT", node["id"], "Requirement requires at least one derived Behavior")
            if node["type"] in {"Behavior", "Acceptance", "Exception"} and not _has_edge(
                graph, source=node["id"], relation="derives_from"
            ):
                add("PRODUCT_ORPHAN", node["id"], f"{node['type']} must derive_from an upstream product node")
    if "fact-ownership" in enabled:
        architecture_claims = [
            node for node in nodes.values()
            if node["type"] in {"Fact", "Boundary", "StateTransition", "Decision", "Risk"}
        ]
        if not architecture_claims:
            add("ARCH_NO_CLAIM", "GRAPH", "Architecture subgraph requires at least one explicit claim")
        for node in nodes.values():
            if node["type"] in {"Fact", "Decision"} and not _has_edge(graph, target=node["id"], relation="owns"):
                add("ARCH_MISSING_OWNER", node["id"], f"{node['type']} requires exactly one explicit Owner")
            if node["type"] in {"Fact", "Decision"}:
                owners = [e for e in graph.get("edges", []) if e.get("target") == node["id"] and e.get("type") == "owns"]
                if len(owners) > 1:
                    add("ARCH_MULTIPLE_OWNERS", node["id"], f"{node['type']} has multiple owners")
            if node["type"] == "Fact":
                persistence = node.get("attributes", {}).get("persistence")
                if not isinstance(persistence, dict) or persistence.get("kind") not in {
                    "database", "external", "ephemeral", "none", "unknown",
                }:
                    add(
                        "FACT_PERSISTENCE_UNDECLARED", node["id"],
                        "Fact requires attributes.persistence.kind: database, external, ephemeral, none, or unknown",
                    )
                elif persistence.get("kind") == "unknown":
                    add(
                        "FACT_PERSISTENCE_UNRESOLVED", node["id"],
                        "Fact persistence is unknown and must be reconciled before readiness",
                    )
                elif persistence.get("kind") == "database":
                    schema_errors = database_schema_errors(persistence.get("schema_sql"))
                    if schema_errors:
                        add("DATABASE_SCHEMA_INVALID", node["id"], "; ".join(schema_errors), "critical")
                elif not isinstance(persistence.get("rationale"), str) or not persistence["rationale"].strip():
                    add(
                        "FACT_PERSISTENCE_RATIONALE_MISSING", node["id"],
                        "Non-database Fact persistence requires a concrete rationale",
                    )
            if node["type"] == "Decision":
                upstream = dependency_closure(graph, {node["id"]}) - {node["id"]}
                if not any(nodes.get(node_id, {}).get("type") in {"Requirement", "Behavior", "Acceptance", "Exception"} for node_id in upstream):
                    add("ARCH_PRODUCT_TRACE_MISSING", node["id"], "Decision must transitively derive from exact product truth")
    if "boundary-state-safety" in enabled:
        for node in nodes.values():
            if node["type"] == "Boundary" and not _has_edge(graph, target=node["id"], relation="owns"):
                add("BOUNDARY_MISSING_OWNER", node["id"], "Boundary requires exactly one explicit Owner")
            if node["type"] == "Boundary" and len(typed_edges(target=node["id"], relation="owns", source_type="Owner")) > 1:
                add("BOUNDARY_MULTIPLE_OWNERS", node["id"], "Boundary has multiple owners")
            if node["type"] == "StateTransition":
                guards = typed_edges(target=node["id"], relation="guards", source_type="Boundary")
                transitions = typed_edges(source=node["id"], relation="transitions")
                if len(guards) != 1:
                    add("STATE_UNGUARDED", node["id"], "StateTransition requires exactly one guarding Boundary", "critical")
                if len(transitions) != 1:
                    add("STATE_TARGET_MISSING", node["id"], "StateTransition requires exactly one transitions edge")
            if node["type"] == "Risk" and node.get("attributes", {}).get("severity") in {"critical", "major"}:
                if not _has_edge(graph, target=node["id"], relation="mitigates"):
                    add("RISK_UNMITIGATED", node["id"], "Critical/major Risk requires an explicit mitigation")
    if "change-traceability" in enabled:
        changes = [node for node in nodes.values() if node["type"] == "Change"]
        if not changes:
            add("IMPLEMENTATION_NO_CHANGE", "GRAPH", "Implementation subgraph requires at least one Change")
        if not any(node["type"] == "Symbol" for node in nodes.values()):
            add("IMPLEMENTATION_NO_SYMBOL", "GRAPH", "Implementation subgraph requires at least one concrete Symbol")
        for node in changes:
            if not _has_edge(graph, source=node["id"], relation="changes"):
                add("CHANGE_UNMAPPED", node["id"], "Change must map to the behavior or architecture decision it changes")
            symbols = [e for e in graph.get("edges", []) if e.get("target") == node["id"] and e.get("type") == "depends_on" and nodes.get(e.get("source"), {}).get("type") == "Symbol"]
            if not symbols:
                add("CHANGE_NO_SYMBOL", node["id"], "Change requires at least one implementation Symbol")
        for node in nodes.values():
            if node["type"] == "Symbol" and not _has_edge(graph, source=node["id"], relation="depends_on"):
                add("SYMBOL_ORPHAN", node["id"], "Symbol must depend_on a Change")
            if node["type"] in {"Decision", "StateTransition"} and not typed_edges(target=node["id"], relation="changes", source_type="Change"):
                add("ARCH_CHANGE_UNMAPPED", node["id"], f"{node['type']} requires an implementation Change")
    if "proof-coverage" in enabled:
        if graph.get("prototype", {}).get("status") == "completed":
            product_nodes = [node for node in nodes.values() if node["type"] in {"Acceptance", "Exception"}]
            applicable = {
                node["id"] for node in product_nodes
                if node.get("attributes", {}).get("prototype_applicable") is True
            }
            if not product_nodes or not applicable or any(
                type(node.get("attributes", {}).get("prototype_applicable")) is not bool
                for node in product_nodes
            ):
                add(
                    "PROTOTYPE_APPLICABILITY_INVALID", "GRAPH",
                    "Completed Prototype requires every Acceptance/Exception to declare prototype_applicable and at least one true value",
                    "critical",
                )
            visual_targets = {
                edge.get("target") for edge in graph.get("edges", [])
                if edge.get("type") == "proves"
                and nodes.get(edge.get("source"), {}).get("type") == "Proof"
                and nodes.get(edge.get("source"), {}).get("attributes", {}).get("proof_type") == "visual"
            }
            if not applicable or not applicable <= visual_targets:
                add(
                    "PROTOTYPE_VISUAL_PROOF_MISSING", "GRAPH",
                    "Completed Prototype requires zero-difference visual Proof coverage for every prototype-applicable Acceptance/Exception",
                    "critical",
                )
        for required_type in ("Test", "Environment", "Proof", "Assertion"):
            if not any(node["type"] == required_type for node in nodes.values()):
                add(
                    f"PROOF_NO_{required_type.upper()}", "GRAPH",
                    f"Implementation/proof subgraph requires at least one {required_type}",
                )
        for node in nodes.values():
            if node["type"] in {"Acceptance", "Exception"}:
                tested = bool(typed_edges(target=node["id"], relation="tests", source_type="Test"))
                proved = bool(typed_edges(target=node["id"], relation="proves", source_type="Proof"))
                if not tested or not proved:
                    add("PROOF_COVERAGE_GAP", node["id"], "Acceptance/Exception requires both Test and Proof coverage")
            elif node["type"] in {"Boundary", "StateTransition"}:
                tested = bool(typed_edges(target=node["id"], relation="tests", source_type="Test"))
                proved = bool(typed_edges(target=node["id"], relation="proves", source_type="Proof"))
                if not tested or not proved:
                    add("BOUNDARY_PROOF_GAP", node["id"], "Boundary/StateTransition requires direct Test and Proof coverage", "critical")
            elif node["type"] == "Test" and len(typed_edges(source=node["id"], relation="runs_in")) != 1:
                add("TEST_NO_ENVIRONMENT", node["id"], "Test requires exactly one runs_in Environment edge")
            elif node["type"] == "Proof":
                environment_edges = typed_edges(source=node["id"], relation="runs_in")
                if len(environment_edges) != 1:
                    add("PROOF_NO_ENVIRONMENT", node["id"], "Proof requires exactly one runs_in Environment edge")
                assertions = [e for e in graph.get("edges", []) if e.get("target") == node["id"] and e.get("type") == "proves" and nodes.get(e.get("source"), {}).get("type") == "Assertion"]
                if not assertions:
                    add("PROOF_NO_ASSERTION", node["id"], "Proof requires at least one Assertion")
                attrs = node.get("attributes", {})
                if attrs.get("proof_type") not in PROOF_TYPES:
                    add("PROOF_TYPE_INVALID", node["id"], "Proof attributes.proof_type is invalid")
                if not isinstance(attrs.get("runner"), dict):
                    add("PROOF_RUNNER_MISSING", node["id"], "Proof requires a structured runner")
                elif not isinstance(attrs["runner"].get("argv"), list) or not attrs["runner"]["argv"] or not all(isinstance(value, str) and value for value in attrs["runner"]["argv"]):
                    add("PROOF_RUNNER_INVALID", node["id"], "Proof runner.argv requires a non-empty string array")
                elif attrs["runner"].get("observation_adapter") not in {"json_stdout", "none", "visual_bundle", "runtime_trace"}:
                    add("PROOF_ADAPTER_INVALID", node["id"], "Proof runner observation_adapter is invalid")
                elif (
                    not isinstance(attrs["runner"].get("cwd", "."), str)
                    or type(attrs["runner"].get("timeout_seconds", 300)) is not int
                    or not 1 <= attrs["runner"].get("timeout_seconds", 300) <= MAX_COMMAND_TIMEOUT_SECONDS
                ):
                    add("PROOF_RUNNER_LIMIT_INVALID", node["id"], "Proof runner cwd/timeout is invalid")
                targets = typed_edges(source=node["id"], relation="proves")
                if not any(nodes.get(edge.get("target"), {}).get("type") in {"Acceptance", "Exception", "Test", "Boundary", "StateTransition", "Risk"} for edge in targets):
                    add("PROOF_TARGET_MISSING", node["id"], "Proof must prove a contracted behavior, test, boundary, transition, or risk")
                proof_type = attrs.get("proof_type")
                adapter = attrs.get("runner", {}).get("observation_adapter") if isinstance(attrs.get("runner"), dict) else None
                environment = nodes.get(environment_edges[0]["target"], {}) if len(environment_edges) == 1 else {}
                runtime = environment.get("attributes", {}).get("spec", {}).get("runtime") if isinstance(environment.get("attributes"), dict) else None
                assertion_nodes = [nodes[edge["source"]] for edge in assertions if edge.get("source") in nodes]
                sources = {item.get("attributes", {}).get("oracle", {}).get("source") for item in assertion_nodes}
                if proof_type == "visual":
                    if adapter != "visual_bundle" or runtime not in VISUAL_RUNTIMES:
                        add("VISUAL_PROFILE_INVALID", node["id"], "Visual Proof requires visual_bundle in a visual target runtime", "critical")
                    required_oracles = {
                        "/observation/pixel_diff_ratio": 0.0,
                        "/observation/geometry_diff_max": 0,
                        "/observation/forbidden_elements_count": 0,
                    }
                    for source, expected in required_oracles.items():
                        matches = [
                            item.get("attributes", {}).get("oracle", {}) for item in assertion_nodes
                            if item.get("attributes", {}).get("oracle", {}).get("source") == source
                        ]
                        if len(matches) != 1 or any(
                            oracle.get("kind") != "json_path"
                            or oracle.get("operator") != "eq"
                            or type(oracle.get("expected")) is not type(expected)
                            or oracle.get("expected") != expected
                            for oracle in matches
                        ):
                            add(
                                "VISUAL_ASSERTIONS_INCOMPLETE", node["id"],
                                "Visual Proof requires exactly one canonical zero-equality assertion for pixel, geometry, and forbidden elements",
                                "critical",
                            )
                            break
                    capture_profile = attrs.get("capture_profile")
                    if (
                        not isinstance(capture_profile, dict)
                        or set(capture_profile) != {"viewport", "state", "data", "dpr", "fonts"}
                        or not all(isinstance(capture_profile.get(key), str) and capture_profile[key] for key in ("viewport", "state", "data"))
                        or isinstance(capture_profile.get("dpr"), bool)
                        or not isinstance(capture_profile.get("dpr"), (int, float))
                        or capture_profile["dpr"] <= 0
                        or not isinstance(capture_profile.get("fonts"), list)
                        or not capture_profile["fonts"]
                        or not all(isinstance(font, str) and font for font in capture_profile["fonts"])
                    ):
                        add("VISUAL_CAPTURE_PROFILE_INVALID", node["id"], "Visual Proof requires an exact viewport/state/data/DPR/fonts capture profile", "critical")
                if proof_type == "runtime":
                    if adapter != "runtime_trace" or "/observation/result_readback" not in sources:
                        add("RUNTIME_PROFILE_INVALID", node["id"], "Runtime Proof requires runtime_trace and result_readback assertion", "critical")
            elif node["type"] == "Environment":
                attrs = node.get("attributes", {})
                if not isinstance(attrs.get("spec"), dict) or not isinstance(attrs.get("target"), str):
                    add("ENVIRONMENT_INCOMPLETE", node["id"], "Environment requires attributes.target and attributes.spec")
                else:
                    spec = attrs["spec"]
                    if not isinstance(spec.get("runtime"), str) or not spec["runtime"]:
                        add("ENVIRONMENT_RUNTIME_INVALID", node["id"], "Environment spec.runtime must be concrete")
                    preflight = spec.get("preflight")
                    preflight_ids = [check.get("id") for check in preflight if isinstance(check, dict)] if isinstance(preflight, list) else []
                    if not isinstance(preflight, list) or any(
                        not isinstance(check, dict)
                        or not isinstance(check.get("id"), str) or not check["id"]
                        or not SAFE_RUN_ID.fullmatch(check["id"])
                        or not isinstance(check.get("argv"), list) or not check["argv"]
                        or not all(isinstance(value, str) and value for value in check["argv"])
                        or type(check.get("timeout_seconds", 300)) is not int
                        or not 1 <= check.get("timeout_seconds", 300) <= MAX_COMMAND_TIMEOUT_SECONDS
                        for check in preflight
                    ) or len(preflight_ids) != len(set(preflight_ids)):
                        add("ENVIRONMENT_PREFLIGHT_INVALID", node["id"], "Environment preflight commands are invalid")
            elif node["type"] == "Risk" and node.get("attributes", {}).get("severity") not in {"critical", "major", "minor"}:
                add("RISK_SEVERITY_INVALID", node["id"], "Risk requires critical, major, or minor severity")
            elif node["type"] == "Assertion":
                oracle = node.get("attributes", {}).get("oracle")
                if not isinstance(oracle, dict) or not all(k in oracle for k in ("kind", "source", "operator")):
                    add("ASSERTION_ORACLE_INVALID", node["id"], "Assertion requires a structured oracle")
                elif (
                    oracle.get("kind") not in ORACLE_KINDS
                    or oracle.get("operator") not in ORACLE_OPERATORS
                    or not isinstance(oracle.get("source"), str)
                    or not oracle["source"].startswith(("/command/", "/observation/"))
                    or (oracle.get("operator") not in {"exists", "absent"} and "expected" not in oracle)
                ):
                    add("ASSERTION_ORACLE_INVALID", node["id"], "Assertion oracle kind/source/operator/expected is invalid", "critical")
                if len(typed_edges(source=node["id"], relation="proves")) != 1:
                    add("ASSERTION_TARGET_INVALID", node["id"], "Assertion must prove exactly one Proof")
    return sorted(issues, key=lambda item: (item["severity"], item["code"], item["node_id"]))


def node_hashes(graph: dict[str, Any]) -> dict[str, str]:
    by_node: dict[str, list[dict[str, Any]]] = {}
    for edge in graph.get("edges", []):
        for endpoint in (edge.get("source"), edge.get("target")):
            if isinstance(endpoint, str):
                by_node.setdefault(endpoint, []).append(edge)
    return {
        node["id"]: value_digest({
            "node": node,
            "edges": sorted(by_node.get(node["id"], []), key=edge_key),
        })
        for node in sorted(graph.get("nodes", []), key=lambda item: item["id"])
    }


def render_table(nodes: list[dict[str, Any]]) -> str:
    if not nodes:
        return "_No nodes declared._\n"
    lines = ["| ID | Type | Title | Statement |", "|---|---|---|---|"]
    for node in sorted(nodes, key=lambda item: item["id"]):
        values = [node["id"], node["type"], node["title"], node["statement"]]
        lines.append("| " + " | ".join(str(value).replace("|", "\\|").replace("\n", " ") for value in values) + " |")
    return "\n".join(lines) + "\n"


def render_edges(graph: dict[str, Any], selected: set[str]) -> str:
    edges = sorted(
        (edge for edge in graph.get("edges", []) if edge["source"] in selected and edge["target"] in selected),
        key=edge_key,
    )
    if not edges:
        return "_No relationships declared._\n"
    lines = ["| Source | Relation | Target |", "|---|---|---|"]
    lines.extend(f"| {e['source']} | {e['type']} | {e['target']} |" for e in edges)
    return "\n".join(lines) + "\n"


def render_stage_document(graph: dict[str, Any], stage: str) -> str:
    names = {
        "product": ("产品需求文档（PRD）", "Product contract"),
        "architecture": ("技术方案", "Architecture contract"),
        "implementation_proof": ("代码实现规格（Code Spec）", "Implementation and proof contract"),
    }
    title, scope = names[stage]
    selected = stage_node_ids(graph, stage)
    nodes = [node for node in graph.get("nodes", []) if node["id"] in selected]
    native = [node for node in nodes if TYPE_STAGE[node["type"]] == stage]
    context = [node for node in nodes if TYPE_STAGE[node["type"]] != stage]
    return (
        f"# {graph['title']} — {title}\n\n"
        "> Generated from `delivery-graph.json`. Do not edit this file.\n\n"
        "## 1. Scope\n\n"
        f"{scope}; subgraph SHA-256: `{stage_hash(graph, stage)}`.\n\n"
        "## 2. Stage nodes\n\n"
        f"{render_table(native)}\n"
        "## 3. Bound upstream context\n\n"
        f"{render_table(context)}\n"
        "## 4. Traceability\n\n"
        f"{render_edges(graph, selected)}"
    )


def generate_proof_contract(graph: dict[str, Any]) -> dict[str, Any]:
    nodes = node_map(graph)
    edges = graph.get("edges", [])
    environments: list[dict[str, Any]] = []
    for node in sorted((n for n in nodes.values() if n["type"] == "Environment"), key=lambda item: item["id"]):
        attrs = node.get("attributes", {})
        environments.append({"id": node["id"], "target": attrs.get("target"), "spec": attrs.get("spec")})
    obligations: list[dict[str, Any]] = []
    for node in sorted((n for n in nodes.values() if n["type"] == "Proof"), key=lambda item: item["id"]):
        attrs = node.get("attributes", {})
        outgoing_edges = [edge for edge in edges if edge.get("source") == node["id"]]
        targets = [edge["target"] for edge in outgoing_edges if edge.get("type") == "proves"]
        environment_ids = [edge["target"] for edge in outgoing_edges if edge.get("type") == "runs_in"]
        assertion_ids = [
            edge["source"] for edge in edges
            if edge.get("target") == node["id"] and edge.get("type") == "proves"
            and nodes.get(edge.get("source"), {}).get("type") == "Assertion"
        ]
        assertions = []
        for assertion_id in sorted(assertion_ids):
            assertion = nodes[assertion_id]
            assertion_attrs = assertion.get("attributes", {})
            assertions.append({
                "id": assertion_id,
                "description": assertion["statement"],
                "oracle": assertion_attrs.get("oracle"),
            })
        product_ids = sorted(target for target in targets if nodes.get(target, {}).get("type") in {"Acceptance", "Exception"})
        trace_ids = sorted(target for target in targets if target not in product_ids)
        obligations.append({
            "id": node["id"],
            "product_ids": product_ids,
            "trace_ids": trace_ids,
            "proof_type": attrs.get("proof_type"),
            "surface": attrs.get("surface", node["title"]),
            "environment_id": environment_ids[0] if len(environment_ids) == 1 else None,
            "critical": attrs.get("critical", True),
            "runner": attrs.get("runner"),
            "prototype_sha256": graph.get("prototype", {}).get("sha256") if attrs.get("proof_type") == "visual" else None,
            "capture_profile": attrs.get("capture_profile") if attrs.get("proof_type") == "visual" else None,
            "assertions": assertions,
        })
    core = {
        "schema_version": SCHEMA_VERSION,
        "feature_id": graph["feature_id"],
        "graph_sha256": graph_digest(graph),
        "subgraph_sha256": stage_hash(graph, "implementation_proof"),
        "environments": environments,
        "obligations": obligations,
    }
    return {**core, "draft_sha256": value_digest(core), "status": "draft", "attestations": {}, "sealed_at": None, "seal": None}


def load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    return load_json(path)


def _valid_attestation_reference(root: Path, feature_id: str, unit_id: str, summary: Any, graph: dict[str, Any]) -> bool:
    if not isinstance(summary, dict) or summary.get("verdict") not in {"PASS", "BLOCKED"}:
        return False
    unit = review_units(graph).get(unit_id)
    if unit is None or summary.get("subgraph_sha256") != unit["subgraph_sha256"]:
        return False
    relative = summary.get("record_path")
    if not isinstance(relative, str):
        return False
    path = root / relative
    try:
        path.resolve().relative_to(root)
    except ValueError:
        return False
    return path.is_file() and path.resolve() == path.absolute() and file_digest(path) == summary.get("record_sha256")


def compile_graph(
    root: Path, feature_id: str, *, check: bool = False,
    _lock_held: bool = False, expected_existing: dict[str, str] | None = None,
) -> dict[str, Any]:
    root = root.expanduser().resolve()
    directory = feature_dir(root, feature_id)
    graph = load_graph(root, feature_id)
    source_path = graph_path(root, feature_id)
    source_sha256 = file_digest(source_path)
    errors = structural_errors(graph, feature_id)
    errors.extend(prototype_errors(root, feature_id, graph))
    if errors:
        raise ValueError("; ".join(errors))
    state_path = directory / "state.json"
    contract_path = directory / "proof-contract.json"
    lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    lock_context = nullcontext() if _lock_held else exclusive_file_lock(lock)
    with lock_context:
        if file_digest(source_path) != source_sha256:
            raise ValueError("Delivery Graph changed before compilation acquired the feature lock; rerun")
        previous = load_state(state_path)
        units = review_units(graph)
        attestations = {
            unit_id: summary for unit_id, summary in previous.get("attestations", {}).items()
            if unit_id in units and _valid_attestation_reference(root, feature_id, unit_id, summary, graph)
        }
        stage_hashes = {stage: stage_hash(graph, stage) for stage in STAGES}
        delivery_readiness = readiness(graph, attestations)
        contract = generate_proof_contract(graph)
        previous_contract = load_json(contract_path) if contract_path.is_file() else None
        sealed_contract_preserved = False
        if (
            isinstance(previous_contract, dict)
            and previous_contract.get("status") == "sealed"
            and previous_contract.get("draft_sha256") == contract["draft_sha256"]
            and previous_contract.get("attestations") == attestations
        ):
            contract = previous_contract
            sealed_contract_preserved = True
        else:
            contract["attestations"] = dict(attestations)
        implementation_changed = previous.get("stage_hashes", {}).get("implementation_proof") != stage_hashes["implementation_proof"]
        code = copy.deepcopy(previous.get("code", {"status": "pending", "repository_fingerprint": None}))
        verification = copy.deepcopy(previous.get("verification", {
            "status": "pending", "active_run_id": None, "run_digest": None,
            "verdict": None, "finalization": None,
        }))
        sealed_contract_invalidated = (
            isinstance(previous_contract, dict)
            and previous_contract.get("status") == "sealed"
            and not sealed_contract_preserved
        )
        if implementation_changed or sealed_contract_invalidated:
            code = {"status": "stale" if code.get("status") == "completed" else "pending", "repository_fingerprint": None}
            verification = {"status": "pending", "active_run_id": None, "run_digest": None, "verdict": None, "finalization": None}
        state = {
            "schema_version": SCHEMA_VERSION,
            "feature_id": feature_id,
            "graph_sha256": graph_digest(graph),
            "node_hashes": node_hashes(graph),
            "stage_hashes": stage_hashes,
            "readiness": delivery_readiness,
            "attestations": attestations,
            "proof_contract": {
                "status": contract["status"],
                "draft_sha256": contract["draft_sha256"],
                "sha256": value_digest(contract),
                "seal": contract.get("seal"),
            },
            "code": code,
            "verification": verification,
            "last_compiled_at": previous.get("last_compiled_at") if check else timestamp(),
        }
        outputs = {
            directory / "prd.md": render_stage_document(graph, "product"),
            directory / "architecture-design.md": render_stage_document(graph, "architecture"),
            directory / "code-spec.md": render_stage_document(graph, "implementation_proof"),
            contract_path: json.dumps(contract, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            state_path: json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        }
        if check:
            stale = [path.name for path, content in outputs.items() if not path.is_file() or path.read_text(encoding="utf-8") != content]
            if stale:
                raise ValueError("generated artifacts are stale: " + ", ".join(sorted(stale)))
        else:
            guarded = expected_existing or {}
            for path in outputs:
                expected = guarded.get(path.name)
                if expected is not None and (not path.is_file() or file_digest(path) != expected):
                    raise ValueError(f"existing generated-output source changed before compilation: {path.name}")
            originals = {
                path: path.read_text(encoding="utf-8") if path.is_file() else None
                for path in outputs
            }
            written: list[Path] = []
            try:
                for path, content in outputs.items():
                    if file_digest(source_path) != source_sha256:
                        raise ValueError("Delivery Graph changed during compilation")
                    expected = guarded.get(path.name)
                    if expected is not None and file_digest(path) != expected:
                        raise ValueError(f"existing generated-output source changed during compilation: {path.name}")
                    atomic_write_text(path, content)
                    guarded.pop(path.name, None)
                    written.append(path)
                if file_digest(source_path) != source_sha256:
                    raise ValueError("Delivery Graph changed during compilation")
                if any(not path.is_file() or path.read_text(encoding="utf-8") != content for path, content in outputs.items()):
                    raise ValueError("generated artifacts changed during compilation")
            except BaseException:
                reconciliation_required = False
                for path in reversed(written):
                    current = path.read_text(encoding="utf-8") if path.is_file() else None
                    if current != outputs[path]:
                        reconciliation_required = True
                        continue
                    original = originals[path]
                    if original is None:
                        path.unlink(missing_ok=True)
                    else:
                        atomic_write_text(path, original)
                if reconciliation_required:
                    raise ValueError("compilation failed; concurrent generated-artifact edits were preserved")
                raise
        return state


def mark_code_complete(root: Path, feature_id: str) -> str:
    root = root.expanduser().resolve()
    directory = feature_dir(root, feature_id)
    graph = load_graph(root, feature_id)
    state_path = directory / "state.json"
    lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    with exclusive_file_lock(lock):
        state = load_state(state_path)
        required = review_units(graph)
        if not required or not all(
            _valid_attestation_reference(root, feature_id, unit_id, state.get("attestations", {}).get(unit_id), graph)
            and state.get("attestations", {}).get(unit_id, {}).get("verdict") == "PASS"
            for unit_id in required
        ):
            raise ValueError("Code requires Delivery Readiness with every fresh PASS review unit")
        contract = load_json(directory / "proof-contract.json")
        if contract.get("status") != "sealed":
            raise ValueError("Code requires a sealed Proof Contract")
        from graph_contract import validate_contract

        contract_errors: list[str] = []
        validate_contract(root, feature_id, contract, state, contract_errors)
        if contract_errors:
            raise ValueError("Code requires a valid sealed Proof Contract: " + "; ".join(contract_errors))
        fingerprint = repository_fingerprint(root, feature_id)
        state["code"] = {"status": "completed", "repository_fingerprint": fingerprint}
        state["verification"] = {"status": "pending", "active_run_id": None, "run_digest": None, "verdict": None, "finalization": None}
        state["last_compiled_at"] = timestamp()
        atomic_write_json(state_path, state)
        return fingerprint


def initialize(root: Path, feature_id: str, title: str | None = None) -> Path:
    root = root.expanduser().resolve()
    directory = feature_dir(root, feature_id)
    path = directory / "delivery-graph.json"
    if path.exists():
        compile_graph(root, feature_id)
        return path
    if directory.exists() and any(directory.iterdir()):
        raise ValueError(f"non-empty feature directory has no delivery-graph.json: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    atomic_write_json(path, default_graph(feature_id, title))
    compile_graph(root, feature_id)
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("feature_id")
    init.add_argument("--root", default=".")
    init.add_argument("--title")
    compile_parser = sub.add_parser("compile")
    compile_parser.add_argument("feature_id")
    compile_parser.add_argument("--root", default=".")
    compile_parser.add_argument("--check", action="store_true")
    validate = sub.add_parser("validate")
    validate.add_argument("feature_id")
    validate.add_argument("--root", default=".")
    code = sub.add_parser("mark-code-complete")
    code.add_argument("feature_id")
    code.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    root = Path(args.root)
    try:
        if args.command == "init":
            print(initialize(root, args.feature_id, args.title))
        elif args.command == "compile":
            state = compile_graph(root, args.feature_id, check=args.check)
            print(state["graph_sha256"])
        elif args.command == "validate":
            graph = load_graph(root, args.feature_id)
            errors = structural_errors(graph, args.feature_id)
            if not errors:
                errors.extend(issue["statement"] for issue in semantic_issues(graph))
            if errors:
                raise ValueError("; ".join(errors))
            compile_graph(root, args.feature_id, check=True)
            print("VALID DELIVERY GRAPH")
        else:
            print(mark_code_complete(root, args.feature_id))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
