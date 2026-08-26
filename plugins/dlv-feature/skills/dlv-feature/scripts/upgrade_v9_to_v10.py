#!/usr/bin/env python3
"""Conservatively upgrade a schema-v9 delivery into a schema-v10 Delivery Graph."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from delivery_graph import atomic_write_json, compile_graph, confined_project_path, feature_dir
from delivery_governance import create_source_revision
from delivery_proof import exclusive_file_lock, extract_state, file_digest, load_json, validate_feature_id


LEGACY_ID = re.compile(
    r"\b(?:SRC|FR|BR|AC|EX|US|ARCH|FLOW|API|DATA|UI|IMPACT|BP)-[A-Za-z0-9-]+\b|"
    r"\b(?:R-D[0-9]+-[0-9]+|T-B[0-9]+-[0-9]+|D[0-9]+|B[0-9]+)\b"
)
TYPE_BY_PREFIX = {
    "SRC": "Requirement", "FR": "Behavior", "BR": "Behavior", "AC": "Acceptance",
    "EX": "Exception", "US": "Persona", "ARCH": "Decision", "FLOW": "StateTransition",
    "API": "Boundary", "DATA": "Fact", "UI": "Decision", "IMPACT": "Risk", "BP": "Boundary",
    "R": "Change", "T": "Test", "D": "Change", "B": "Change",
}
LEGACY_ARTIFACTS = (
    "state.md", "prd.md", "architecture-design.md", "code-spec.md",
    "proof-contract.json", "verification.md",
)


def atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        Path(temporary).unlink(missing_ok=True)
        raise


def _title(text: str, fallback: str) -> str:
    match = re.search(r"(?m)^#\s+(.+?)(?:\s+[—-]\s+|$)", text)
    return match.group(1).strip() if match else fallback.replace("-", " ").title()


def _legacy_prefix(legacy_id: str) -> str:
    if legacy_id.startswith("R-D"):
        return "R"
    if legacy_id.startswith("T-B"):
        return "T"
    if re.fullmatch(r"D[0-9]+", legacy_id):
        return "D"
    if re.fullmatch(r"B[0-9]+", legacy_id):
        return "B"
    return legacy_id.split("-", 1)[0]


def _statement_for(text: str, legacy_id: str) -> str:
    for line in text.splitlines():
        if re.search(rf"(?<![A-Za-z0-9-]){re.escape(legacy_id)}(?![A-Za-z0-9-])", line):
            cleaned = re.sub(r"^[\s|>*#`\-0-9.]+", "", line).strip().replace("|", " ")
            return cleaned[:500] or f"Migrated candidate {legacy_id}"
    return f"Migrated candidate {legacy_id}"


def convert(root: Path, feature_id: str) -> dict[str, Any]:
    directory = feature_dir(root, feature_id)
    state_path = directory / "state.md"
    if not state_path.is_file():
        raise ValueError("schema-v9 state.md is required")
    _, state = extract_state(state_path)
    if state.get("schema_version") != 9:
        raise ValueError("only schema_version=9 can be upgraded by this script")
    texts: dict[str, str] = {}
    for name in ("prd.md", "architecture-design.md", "code-spec.md"):
        path = directory / name
        texts[name] = path.read_text(encoding="utf-8") if path.is_file() else ""
    counters: dict[str, int] = {}
    legacy_to_new: dict[str, str] = {}
    nodes: list[dict[str, Any]] = []

    def add(node_type: str, legacy_id: str, title: str, statement: str, attributes: dict[str, Any] | None = None) -> str:
        if legacy_id in legacy_to_new:
            return legacy_to_new[legacy_id]
        counters[node_type] = counters.get(node_type, 0) + 1
        prefix = {
            "Requirement": "REQ", "Behavior": "BHV", "Acceptance": "AC", "Exception": "EX",
            "Persona": "PER", "Fact": "FACT", "Owner": "OWN", "Boundary": "BND",
            "StateTransition": "ST", "Decision": "DEC", "Change": "CHG", "Symbol": "SYM",
            "Test": "TST", "Environment": "ENV", "Proof": "PO", "Assertion": "ASRT", "Risk": "RISK",
        }[node_type]
        node_id = f"{prefix}-{counters[node_type]:03d}"
        attrs = {"legacy_id": legacy_id}
        if node_type == "Fact":
            attrs["persistence"] = {"kind": "unknown"}
        if attributes:
            attrs.update(attributes)
        nodes.append({"id": node_id, "type": node_type, "title": title, "statement": statement, "attributes": attrs})
        legacy_to_new[legacy_id] = node_id
        return node_id

    for name, text in texts.items():
        for legacy_id in dict.fromkeys(LEGACY_ID.findall(text)):
            node_type = TYPE_BY_PREFIX[_legacy_prefix(legacy_id)]
            add(node_type, legacy_id, legacy_id, _statement_for(text, legacy_id), {"source_artifact": name})
    contract = state.get("proof_contract") if isinstance(state.get("proof_contract"), dict) else {}
    for environment in contract.get("environments", []):
        if isinstance(environment, dict) and isinstance(environment.get("id"), str):
            add(
                "Environment", environment["id"], str(environment.get("target") or environment["id"]),
                f"Migrated untrusted Environment candidate {environment['id']}",
                {"target": environment.get("target"), "spec": environment.get("spec")},
            )
    for obligation in contract.get("obligations", []):
        if not isinstance(obligation, dict) or not isinstance(obligation.get("id"), str):
            continue
        proof_id = add(
            "Proof", obligation["id"], str(obligation.get("surface") or obligation["id"]),
            f"Migrated untrusted Proof candidate {obligation['id']}",
            {
                "proof_type": obligation.get("proof_type"), "surface": obligation.get("surface"),
                "critical": obligation.get("critical", True), "runner": obligation.get("runner"),
                "legacy_product_ids": obligation.get("product_ids", []),
                "legacy_trace_ids": obligation.get("trace_ids", []),
            },
        )
        for assertion in obligation.get("assertions", []):
            if isinstance(assertion, dict) and isinstance(assertion.get("id"), str):
                add(
                    "Assertion", assertion["id"], assertion["id"],
                    str(assertion.get("description") or f"Migrated assertion {assertion['id']}"),
                    {"oracle": assertion.get("oracle"), "proof_legacy_id": obligation["id"]},
                )
    for risk in state.get("risks", []):
        if isinstance(risk, dict) and isinstance(risk.get("id"), str):
            add(
                "Risk", risk["id"], risk["id"], str(risk.get("statement") or risk["id"]),
                {key: value for key, value in risk.items() if key not in {"id", "statement"}},
            )
    edges: list[dict[str, str]] = []

    def connect(source: str | None, relation: str, target: str | None) -> None:
        if source and target and source != target:
            value = {"source": source, "type": relation, "target": target}
            if value not in edges:
                edges.append(value)

    first = lambda kind: next((node["id"] for node in nodes if node["type"] == kind), None)
    requirement, behavior = first("Requirement"), first("Behavior")
    for item in nodes:
        if item["type"] == "Behavior":
            connect(item["id"], "derives_from", requirement)
        elif item["type"] in {"Acceptance", "Exception"}:
            connect(item["id"], "derives_from", behavior or requirement)
        elif item["type"] == "Decision":
            connect(item["id"], "derives_from", first("Fact") or requirement)
        elif item["type"] == "StateTransition":
            connect(item["id"], "transitions", first("Fact"))
        elif item["type"] == "Change":
            connect(item["id"], "changes", first("Decision") or behavior)
        elif item["type"] == "Test":
            for target_type in ("Acceptance", "Exception"):
                connect(item["id"], "tests", first(target_type))
            connect(item["id"], "runs_in", first("Environment"))
        elif item["type"] == "Assertion":
            legacy_proof = item.get("attributes", {}).get("proof_legacy_id")
            connect(item["id"], "proves", legacy_to_new.get(legacy_proof))
    for obligation in contract.get("obligations", []):
        if not isinstance(obligation, dict):
            continue
        proof_id = legacy_to_new.get(str(obligation.get("id")))
        for legacy_id in obligation.get("product_ids", []):
            connect(proof_id, "proves", legacy_to_new.get(str(legacy_id)))
        for legacy_id in obligation.get("trace_ids", []):
            target = legacy_to_new.get(str(legacy_id))
            target_type = next((node["type"] for node in nodes if node["id"] == target), None)
            if target and target_type in {
                "Acceptance", "Exception", "Test", "Boundary", "StateTransition", "Risk",
            }:
                connect(proof_id, "proves", target)
        connect(proof_id, "runs_in", legacy_to_new.get(str(obligation.get("environment_id"))))
    prototype_path = directory / "prototype.html"
    prototype = (
        {"status": "contractual", "path": "prototype.html", "sha256": file_digest(prototype_path)}
        if prototype_path.is_file() else {"status": "not_applicable", "reason": "No legacy prototype artifact was captured."}
    )
    source_artifacts_sha256 = {
        name: file_digest(directory / name)
        for name in LEGACY_ARTIFACTS if (directory / name).is_file()
    }
    return {
        "schema_version": 11,
        "feature_id": feature_id,
        "title": _title(texts["prd.md"], feature_id),
        "source_revision": "SRC-001",
        "nodes": nodes,
        "edges": edges,
        "prototype": prototype,
        "metadata": {
            "risk_vector": {},
            "upgrade": "schema-v9-to-v10",
            "candidate_only": True,
            "source_state_sha256": file_digest(state_path),
            "source_artifacts_sha256": source_artifacts_sha256,
        },
    }


def apply_upgrade(root: Path, feature_id: str) -> Path:
    root = root.expanduser().resolve()
    directory = feature_dir(root, feature_id)
    graph_path = directory / "delivery-graph.json"
    state_path = directory / "state.md"
    lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    with exclusive_file_lock(lock):
        if graph_path.is_file():
            graph = load_json(graph_path)
            if graph.get("schema_version") != 11 or graph.get("feature_id") != feature_id:
                raise ValueError("existing delivery-graph.json is not this feature's schema-v11 graph")
            upgrade = graph.get("metadata")
            if (
                not isinstance(upgrade, dict)
                or upgrade.get("upgrade") != "schema-v9-to-v10"
                or upgrade.get("candidate_only") is not True
                or not isinstance(upgrade.get("source_state_sha256"), str)
                or not isinstance(upgrade.get("source_artifacts_sha256"), dict)
            ):
                raise ValueError("existing Delivery Graph is not a recoverable schema-v9 upgrade candidate")
        else:
            graph = convert(root, feature_id)
            atomic_write_json(graph_path, graph)
        source_path = directory / "source-revisions" / "SRC-001.json"
        if not source_path.exists():
            create_source_revision(
                directory, feature_id, "SRC-001",
                {
                    "title": graph["title"],
                    "description": "Legacy schema-v9 source archived as an untrusted migration candidate.",
                    "comments": [], "attachments": [], "risk_vector": {},
                },
                owner="schema-v9-import", status="confirmed",
            )
        archive = confined_project_path(root, Path(".dlv") / "upgrades" / feature_id / "schema-v9-candidates", "upgrade archive")
        expected_digests = graph["metadata"]["source_artifacts_sha256"]
        if state_path.is_file() and file_digest(state_path) != graph["metadata"]["source_state_sha256"]:
            raise ValueError("schema-v9 state changed after upgrade conversion; restart from a reconciled source")
        for name, expected_digest in expected_digests.items():
            if name not in LEGACY_ARTIFACTS or not isinstance(expected_digest, str):
                raise ValueError("upgrade source artifact digest map is invalid")
            source = directory / name
            target = archive / name
            target_present = target.exists() or target.is_symlink()
            if target_present and (
                not target.is_file()
                or target.resolve() != target.absolute()
                or file_digest(target) != expected_digest
            ):
                raise ValueError(f"upgrade archive diverges from converted source: {name}")
            if not target_present and (not source.is_file() or file_digest(source) != expected_digest):
                raise ValueError(f"schema-v9 source changed or disappeared during upgrade: {name}")
            if source.is_file() and not target_present:
                if source.resolve() != source.absolute():
                    raise ValueError(f"upgrade source must not be a symlink: {source}")
                atomic_write_bytes(target, source.read_bytes())
                if file_digest(target) != expected_digest:
                    target.unlink(missing_ok=True)
                    raise ValueError(f"upgrade archive byte verification failed: {name}")
        for name, expected_digest in expected_digests.items():
            target = archive / name
            if not target.is_file() or target.resolve() != target.absolute() or file_digest(target) != expected_digest:
                raise ValueError(f"upgrade archive is incomplete before legacy cleanup: {name}")
        compilation_complete = False
        try:
            compile_graph(root, feature_id, check=True, _lock_held=True)
            compilation_complete = True
        except ValueError as exc:
            if not str(exc).startswith("generated artifacts are stale:"):
                raise
        if not compilation_complete:
            compile_graph(
                root, feature_id, _lock_held=True,
                expected_existing={
                    name: digest for name, digest in expected_digests.items()
                    if name in {"prd.md", "architecture-design.md", "code-spec.md", "proof-contract.json"}
                },
            )
        for name, expected_digest in expected_digests.items():
            target = archive / name
            if not target.is_file() or target.resolve() != target.absolute() or file_digest(target) != expected_digest:
                raise ValueError(f"upgrade archive changed before legacy cleanup: {name}")
        if state_path.is_file() and file_digest(state_path) != graph["metadata"]["source_state_sha256"]:
            raise ValueError("schema-v9 state changed during upgrade compilation; preserve and reconcile it")
        verification_path = directory / "verification.md"
        expected_verification = graph["metadata"]["source_artifacts_sha256"].get("verification.md")
        if verification_path.exists() and (
            not isinstance(expected_verification, str)
            or verification_path.resolve() != verification_path.absolute()
            or not verification_path.is_file()
            or file_digest(verification_path) != expected_verification
        ):
            raise ValueError("legacy verification.md changed during upgrade compilation; preserve and reconcile it")
        verification_path.unlink(missing_ok=True)
        state_path.unlink(missing_ok=True)
    return graph_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    root = Path(args.root).expanduser().resolve()
    try:
        validate_feature_id(args.feature_id)
        if args.apply:
            print(apply_upgrade(root, args.feature_id))
        else:
            graph = convert(root, args.feature_id)
            print(
                "upgrade plan: schema 9 → 10; archive v9 documents as untrusted candidates; "
                f"derive {len(graph['nodes'])} candidate nodes and {len(graph['edges'])} trace edges; "
                "invalidate every review, seal, Code claim, Verification Run, PASS, and finalization"
            )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
