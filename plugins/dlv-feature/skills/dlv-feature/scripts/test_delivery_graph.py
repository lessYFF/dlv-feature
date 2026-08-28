#!/usr/bin/env python3
"""Schema-v12 Delivery Graph regression, mutation, and security tests."""

from __future__ import annotations

import copy
import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import delivery_graph
import delivery_contracts
import delivery_governance
import delivery_proof
import graph_contract
import graph_finalize
import graph_invalidate
import graph_review
import graph_validation
import graph_verification
import runtime_evidence
import upgrade_v9_to_v10
import upgrade_v10_to_v11
import upgrade_v11_to_v12
import scope_revision
import finding_ledger
import frontend_fast_path
import repository_adapter
import target_attestation
from delivery_governance import apply_review_findings, canonical_source_payload, create_source_revision, empty_ledger, finding_summary, load_ledger, write_ledger
from delivery_contracts import claim_id_for, is_boolean_only_observation


TEST_RSA_N = int(
    "ca684ab3740486690fbd894e46d957f7981f3a63de2ef295a53760703065e3bc676c9b3c55d1362fd7132aeed1bb0d28fb2778c3aae4fb27b3f60a17c24042ca8055b5d974dd1b58133abf3ce15a758e0a278a2e961ece6c20eae76f1afb1c91a2cd286a414d1d015e3c9a12fb8b33249380f58edbd0bb44142f6e7fac36a36737d76b0eabdf9ff8dc206abc94aca80dac3b5d6b6eb058f54deae37fd6d38ba88d4e105ad7062c156c110dc8620ce6af9621c0dc998443149656a72766d2511fdcbc0b363e3757e97a2943fae51a456c7ee2b9dc443e3356a597fcd82e0754588fd4434a32095fa1724472fdca0593a6cf7c699ae36a791dea1d9c7f72e620fd",
    16,
)
TEST_RSA_D = int(
    "1c6ab1fa29d2acd0393e81f5746af537b4aac5b6d9adbbaf18c802891db2605bc6257051f33671261c4afb9f15e0ee030fe7c5c3aacd851958e1b51f0acd9cd2f35b9531577fe763e127414c19d36a67abb34b6a28f76041bc095ebeb18a09c3c4988b1107e3fcab81807e9d25a5b063753608c3aac6ce53cb85b13cc97fce46e29b50d03dbf8fbd95dd94f79ef01886c85251b124820f0d928e3286ec24978c9ae1376f2a47838d86d405e4926f348c241c2efa9b33cfe146e6e77a9618681669af716ac7f72460a7a37a8ef5b87eb0aba695f59e0da90c1c3430eae30578b2957f49a87529b072dfe7726b3baf92ea8ea63aa4b68c0cb651ecc8334951c001",
    16,
)


def b64url_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_int(value: int) -> str:
    return b64url_bytes(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def test_attestation_config() -> dict[str, object]:
    jwk = {"kty": "RSA", "kid": "test-rsa-1", "n": b64url_int(TEST_RSA_N), "e": b64url_int(65537)}
    return {
        "algorithm": "RS256", "issuer": "test-target", "audience": "dlv-feature",
        "public_key_jwk": jwk, "source_ref": "test-target-attestation-key",
        "source_sha256": delivery_proof.value_digest(jwk),
    }


def test_attestation_attachment() -> dict[str, object]:
    config = test_attestation_config()
    return {
        "ref": config["source_ref"], "kind": "target_attestation_jwk",
        "sha256": config["source_sha256"], "jwk": config["public_key_jwk"],
    }


def bind_test_attestation_source(root: Path, feature_id: str = "cross-domain-feature") -> None:
    directory = root / "delivery" / feature_id
    graph_path = directory / "delivery-graph.json"
    graph = json.loads(graph_path.read_text())
    path = directory / "source-revisions" / f"{graph['source_revision']}.json"
    source = json.loads(path.read_text())
    if test_attestation_attachment() in source["attachments"]:
        return
    existing = sorted(directory.glob("source-revisions/SRC-*.json"))
    revision_id = f"SRC-{max(int(item.stem.removeprefix('SRC-')) for item in existing) + 1:03d}"
    create_source_revision(
        directory,
        feature_id,
        revision_id,
        {
            "title": source["title"],
            "description": source["description"],
            "comments": source["comments"],
            "attachments": [
                item for item in source["attachments"] if item.get("kind") != "convergence_authority"
            ] + [test_attestation_attachment()],
            "risk_vector": source["risk_vector"],
        },
        owner="test",
        status="confirmed",
    )
    graph["source_revision"] = revision_id
    write_json(graph_path, graph)


def sign_target_observation(observation: dict[str, object], spec: dict[str, object], nonce: str) -> None:
    config = spec["attestation"]
    assert isinstance(config, dict)
    header = {"alg": "RS256", "kid": config["public_key_jwk"]["kid"], "typ": "DLV-TARGET-ATTESTATION"}
    payload = {
        "issuer": config["issuer"], "audience": config["audience"], "challenge_nonce": nonce,
        "target_identity": spec["target_identity"], "build_identity": spec["build_identity"],
        "deployment_identity": spec["deployment_identity"],
        "measurement_sha256": delivery_proof.value_digest(target_attestation.signed_measurement(observation)),
    }
    encoded_header = b64url_bytes(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    encoded_payload = b64url_bytes(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    digest_info = target_attestation.SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(signing_input).digest()
    width = (TEST_RSA_N.bit_length() + 7) // 8
    encoded = b"\x00\x01" + b"\xff" * (width - len(digest_info) - 3) + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), TEST_RSA_D, TEST_RSA_N).to_bytes(width, "big")
    observation["target_attestation"] = f"{encoded_header}.{encoded_payload}.{b64url_bytes(signature)}"


def node(node_id: str, node_type: str, title: str, statement: str, **attributes: object) -> dict:
    value = {"id": node_id, "type": node_type, "title": title, "statement": statement}
    if attributes:
        value["attributes"] = attributes
    return value


def edge(source: str, relation: str, target: str) -> dict:
    return {"source": source, "type": relation, "target": target}


def claim(lens: str, invariant: str, subjects: list[str], failure_boundary: str, proof_ids: list[str], *, critical: bool = True) -> dict:
    value = {
        "lens": lens, "invariant": invariant, "subjects": sorted(subjects),
        "failure_boundary": failure_boundary, "critical": critical, "proof_ids": sorted(proof_ids),
    }
    return {"id": claim_id_for(value), **value}


def valid_graph(feature_id: str = "cross-domain-feature", *, runtime: str = "python") -> dict:
    runner = {
        "argv": [sys.executable, "-c", "import json; print(json.dumps({'count': 1, 'fact_version': 1, 'transition_version': 1, 'writer_count': 1, 'rejected_count': 1, 'guarded_transition_count': 1, 'duplicate_count': 0}))"],
        "cwd": ".",
        "observation_adapter": "json_stdout",
        "timeout_seconds": 30,
    }
    nodes = [
        node("REQ-001", "Requirement", "Need", "A user needs a deterministic result"),
        node("PER-001", "Persona", "Operator", "An authenticated operator"),
        node("BHV-001", "Behavior", "Execute", "The system executes the requested operation"),
        node("AC-001", "Acceptance", "Success", "The observable result is successful"),
        node("EX-001", "Exception", "Denied", "An invalid transition is denied"),
        node("OWN-001", "Owner", "Domain service", "The domain service owns authoritative facts"),
        node(
            "FACT-001", "Fact", "Result fact", "The stored result is authoritative",
            persistence={"kind": "external", "rationale": "The domain service owns this fixture fact"},
        ),
        node("BND-001", "Boundary", "Authorization boundary", "Authorization guards state mutation"),
        node("ST-001", "StateTransition", "Pending to complete", "The entity moves to completed"),
        node("DEC-001", "Decision", "Single writer", "One service owns the write transaction"),
        node("RISK-001", "Risk", "Duplicate execution", "Concurrent execution could duplicate side effects", severity="major", risk_axes=["CONCURRENCY"]),
        node("CHG-001", "Change", "Implement transaction", "Implement the guarded atomic transition"),
        node("SYM-001", "Symbol", "DomainService.execute", "Change the domain service execution symbol", path="src/domain_service.py"),
        node("ENV-001", "Environment", "Python runtime", "Execute in the target Python runtime", target="python runtime", spec={
            "runtime": runtime, "preflight": [], "target_identity": f"{runtime}:test-target",
            "build_identity": "build:test", "deployment_identity": "deployment:local",
            "adapter_sha256": "0" * 64,
            "fixture": {"path": ".dlv/fixtures/runtime.json", "sha256": "0" * 64},
            "attestation": test_attestation_config(),
        }),
        node("TST-001", "Test", "Behavior test", "Test concurrent success, rejection, and implementation paths"),
        node("PO-001", "Proof", "Runtime proof", "Prove the observable result in the target runtime", proof_type="boundary", surface="domain operation", critical=True, runner=runner),
        node("PO-002", "Proof", "State invariant proof", "Prove the authoritative state transition", proof_type="invariant", surface="domain state", critical=True, runner=runner),
        node(
            "ASRT-001", "Assertion", "Result assertion", "The measured result count is one",
            oracle={"kind": "state", "source": "/observation/count", "operator": "eq", "expected": 1},
            subject_ids=["AC-001", "BHV-001", "EX-001", "REQ-001", "TST-001"],
        ),
        node("ASRT-010", "Assertion", "Fact readback", "The authoritative fact is read back", oracle={"kind": "state", "source": "/observation/fact_version", "operator": "eq", "expected": 1}, subject_ids=["FACT-001"]),
        node("ASRT-011", "Assertion", "Transition readback", "The state transition is read back", oracle={"kind": "state", "source": "/observation/transition_version", "operator": "eq", "expected": 1}, subject_ids=["ST-001"]),
        node("ASRT-012", "Assertion", "Decision readback", "The writer decision is read back", oracle={"kind": "state", "source": "/observation/writer_count", "operator": "eq", "expected": 1}, subject_ids=["DEC-001"]),
        node("ASRT-013", "Assertion", "Boundary readback", "The boundary decision is read back", oracle={"kind": "side_effect", "source": "/observation/rejected_count", "operator": "eq", "expected": 1}, subject_ids=["BND-001"]),
        node("ASRT-015", "Assertion", "Concurrency readback", "Duplicate side effects are absent", oracle={"kind": "side_effect", "source": "/observation/duplicate_count", "operator": "eq", "expected": 0}, subject_ids=["RISK-001"]),
    ]
    edges = [
        edge("BHV-001", "derives_from", "REQ-001"),
        edge("BHV-001", "derives_from", "PER-001"),
        edge("AC-001", "derives_from", "BHV-001"),
        edge("EX-001", "derives_from", "BHV-001"),
        edge("OWN-001", "owns", "FACT-001"),
        edge("OWN-001", "owns", "BND-001"),
        edge("OWN-001", "owns", "ST-001"),
        edge("OWN-001", "owns", "DEC-001"),
        edge("BND-001", "guards", "ST-001"),
        edge("ST-001", "transitions", "FACT-001"),
        edge("DEC-001", "derives_from", "FACT-001"),
        edge("DEC-001", "derives_from", "BHV-001"),
        edge("CHG-001", "changes", "DEC-001"),
        edge("CHG-001", "changes", "ST-001"),
        edge("CHG-001", "mitigates", "RISK-001"),
        edge("SYM-001", "depends_on", "CHG-001"),
        edge("TST-001", "tests", "AC-001"),
        edge("TST-001", "tests", "EX-001"),
        edge("TST-001", "tests", "BND-001"),
        edge("TST-001", "tests", "ST-001"),
        edge("TST-001", "tests", "CHG-001"),
        edge("TST-001", "runs_in", "ENV-001"),
        edge("PO-001", "proves", "AC-001"),
        edge("PO-001", "proves", "EX-001"),
        edge("PO-001", "proves", "TST-001"),
        edge("PO-001", "proves", "BND-001"),
        edge("PO-001", "proves", "ST-001"),
        edge("PO-001", "runs_in", "ENV-001"),
        edge("PO-001", "mitigates", "RISK-001"),
        edge("ASRT-001", "proves", "PO-001"),
        edge("PO-002", "proves", "FACT-001"), edge("PO-002", "proves", "ST-001"),
        edge("PO-002", "proves", "DEC-001"), edge("PO-002", "proves", "BND-001"),
        edge("PO-002", "runs_in", "ENV-001"), edge("PO-002", "mitigates", "RISK-001"),
        edge("ASRT-010", "proves", "PO-002"), edge("ASRT-011", "proves", "PO-002"),
        edge("ASRT-012", "proves", "PO-002"), edge("ASRT-013", "proves", "PO-002"),
        edge("ASRT-015", "proves", "PO-002"),
    ]
    graph = delivery_graph.default_graph(feature_id, "Cross-domain feature")
    graph["nodes"] = nodes
    graph["edges"] = edges
    graph["claims"] = [
        claim("PROVENANCE_INTEGRITY", "Requirement behavior remains source-bound", ["REQ-001", "BHV-001", "AC-001", "EX-001"], "product contract", ["PO-001"]),
        claim("STATE_AND_ATOMICITY", "Authoritative state changes atomically", ["FACT-001", "ST-001", "DEC-001"], "domain transaction", ["PO-002"], critical=True),
        claim("BOUNDARY_AND_CONCURRENCY", "The owned boundary rejects unsafe transitions", ["BND-001", "ST-001", "RISK-001"], "authorization boundary", ["PO-002"], critical=True),
        claim("RUNTIME_AUTHENTICITY", "Runtime readback proves the target result", ["AC-001", "TST-001", "ENV-001", "PO-001", "ASRT-001"], "target runtime", ["PO-001"], critical=False),
    ]
    return graph


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def bind_test_runtime_files(root: Path, graph: dict[str, object]) -> None:
    adapter = root / ".dlv/repository-adapter.json"
    fixture = root / ".dlv/fixtures/runtime.json"
    write_json(adapter, {
        "schema_version": 12, "name": "test-adapter", "source_ref": "test-repository-adapter",
        "frontend_roots": ["src"], "capabilities": {},
    })
    write_json(fixture, {"case": "runtime-v1"})
    environment = next(item for item in graph["nodes"] if item["id"] == "ENV-001")
    spec = environment["attributes"]["spec"]
    spec["adapter_sha256"] = delivery_graph.file_digest(adapter)
    spec["fixture"] = {
        "path": fixture.relative_to(root).as_posix(),
        "sha256": delivery_graph.file_digest(fixture),
    }


def contracted_environment_spec(
    root: Path, *, feature_id: str = "cross-domain-feature", preflight: list[dict] | None = None,
) -> dict:
    graph = delivery_graph.load_graph(root, feature_id)
    spec = copy.deepcopy(next(item for item in graph["nodes"] if item["id"] == "ENV-001")["attributes"]["spec"])
    if preflight is not None:
        spec["preflight"] = preflight
    return spec


def fast_path_eligibility_snapshot(root: Path, adapter: dict, adapter_sha256: str) -> dict:
    root = root.resolve()
    graph = delivery_graph.load_graph(root, "cross-domain-feature")
    source = delivery_governance.load_source_revision(
        root / "delivery/cross-domain-feature", "cross-domain-feature", graph["source_revision"],
    )
    return {
        "graph": graph, "graph_sha256": delivery_graph.graph_digest(graph),
        "source": source, "source_sha256": delivery_proof.value_digest(source),
        "ledger_sha256": delivery_proof.value_digest(load_ledger(root, "cross-domain-feature")),
        "repository_fingerprint": delivery_proof.repository_fingerprint(root, "cross-domain-feature"),
        "adapter": adapter, "adapter_sha256": adapter_sha256,
    }


def remove_invariant_obligation(graph: dict[str, object]) -> None:
    removed = {"PO-002", "ASRT-010", "ASRT-011", "ASRT-012", "ASRT-013", "ASRT-015"}
    graph["claims"] = [
        item for item in graph["claims"]
        if item["lens"] not in {"STATE_AND_ATOMICITY", "BOUNDARY_AND_CONCURRENCY"}
    ]
    graph["nodes"] = [item for item in graph["nodes"] if item["id"] not in removed]
    graph["edges"] = [
        item for item in graph["edges"]
        if item["source"] not in removed and item["target"] not in removed
    ]


def remove_invariant_obligation_for_boundary_only_test(root: Path) -> None:
    graph = delivery_graph.load_graph(root, "cross-domain-feature")
    remove_invariant_obligation(graph)
    write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)


def write_png(path: Path, rgba: bytes = b"\x00\x00\x00\xff") -> None:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    path.parent.mkdir(parents=True, exist_ok=True)
    raw = b"\x00" + rgba
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


class GraphTestCase(unittest.TestCase):
    @staticmethod
    def fake_semantic_run(argv: list[str], *args: object, **kwargs: object) -> dict[str, object]:
        result_path = Path(argv[argv.index("--output-last-message") + 1])
        write_json(result_path, {
            "verdict": "PASS",
            "checks": [{
                "id": "fixture-consistency", "status": "PASS",
                "evidence": "fixture graph is semantically coherent",
            }],
            "findings": [],
        })
        return {"exit_code": 0, "timed_out": False, "stdout": '{"type":"fixture.semantic.review"}\n', "stderr": ""}

    def make_root(self, feature_id: str = "cross-domain-feature") -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name).resolve()
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        directory = root / "delivery" / feature_id
        directory.mkdir(parents=True)
        create_source_revision(
            directory,
            feature_id,
            "SRC-001",
            {
                "title": "Cross-domain feature",
                "description": "Initial feature source captured by the test fixture.",
                "comments": [],
                "attachments": [test_attestation_attachment()],
                "risk_vector": {},
            },
            owner="test",
            status="confirmed",
        )
        write_json(directory / "delivery-graph.json", delivery_graph.default_graph(feature_id, "Cross-domain feature"))
        delivery_graph.compile_graph(root, feature_id)
        graph = valid_graph(feature_id)
        bind_test_runtime_files(root, graph)
        write_json(directory / "delivery-graph.json", graph)
        return temporary, root

    def review_all(
        self, root: Path, feature_id: str = "cross-domain-feature", run_id: str = "readiness-01",
    ) -> None:
        if graph_validation.validate(root, feature_id):
            delivery_graph.compile_graph(root, feature_id)
        with patch.object(graph_review, "run_bounded", side_effect=self.fake_semantic_run):
            graph_review.run_isolated_readiness_review(root, feature_id, run_id)
        subprocess.run(["git", "add", "-A"], cwd=root, check=True)
        subprocess.run(
            [
                "git", "-c", "user.name=DLV Test", "-c", "user.email=dlv@example.invalid",
                "commit", "--allow-empty", "-qm", f"test: bind {feature_id}\n\nDLV-Feature: {feature_id}",
            ],
            cwd=root, check=True,
        )

    @staticmethod
    def unit_id(graph: dict[str, object], lens: str) -> str:
        matches = [unit_id for unit_id, unit in delivery_graph.review_units(graph).items() if unit["lens"] == lens]
        if len(matches) != 1:
            raise AssertionError(f"expected one {lens} review unit, got {matches}")
        return matches[0]

    def configure_visual_graph(self, root: Path, feature_id: str = "cross-domain-feature") -> tuple[dict[str, object], dict[str, Path]]:
        directory = root / "delivery" / feature_id
        prototype = directory / "prototype.html"
        prototype.write_text("<!doctype html><title>Prototype</title>\n", encoding="utf-8")
        paths = {
            "prototype_screenshot": root / ".dlv/visual/prototype.png",
            "implementation_screenshot": root / ".dlv/visual/implementation.png",
            "visual_diff": root / ".dlv/visual/diff.png",
        }
        for path in paths.values():
            write_png(path)
        profile: dict[str, object] = {
            "viewport": "1440x900", "state": "trip-accounting-open",
            "data": "fixture-v1", "dpr": 1, "fonts": ["Noto Sans SC"],
        }
        graph = valid_graph(feature_id, runtime="browser")
        remove_invariant_obligation(graph)
        adapter = root / ".dlv/repository-adapter.json"
        fixture = root / ".dlv/fixtures/visual.json"
        write_json(adapter, {"schema_version": 12, "name": "test-adapter", "source_ref": "test-repository-adapter", "frontend_roots": ["src"], "capabilities": {}})
        write_json(fixture, {"fixture": "visual-v1"})
        environment_spec = {
            "runtime": "browser", "preflight": [], "target_identity": "browser:test-target",
            "build_identity": "build:test", "deployment_identity": "deployment:local",
            "adapter_sha256": hashlib.sha256(adapter.read_bytes()).hexdigest(),
            "fixture": {"path": fixture.relative_to(root).as_posix(), "sha256": hashlib.sha256(fixture.read_bytes()).hexdigest()},
            "attestation": test_attestation_config(),
        }
        next(item for item in graph["nodes"] if item["id"] == "ENV-001")["attributes"]["spec"] = environment_spec
        source_path = directory / "source-revisions/SRC-001.json"
        if not source_path.is_file():
            create_source_revision(
                directory, feature_id, "SRC-001",
                {"title": "Visual fixture", "description": "fixture", "comments": [], "attachments": [test_attestation_attachment()], "risk_vector": {}},
                owner="test", status="confirmed",
            )
        else:
            bind_test_attestation_source(root, feature_id)
        source = json.loads(source_path.read_text())
        graph["prototype"] = {
            "status": "contractual", "path": "prototype.html",
            "sha256": hashlib.sha256(prototype.read_bytes()).hexdigest(),
            "source_revision": "SRC-001", "source_kind": "source_revision",
            "source_ref": "SRC-001", "source_sha256": source["source_digest"],
        }
        for item in graph["nodes"]:
            if item["type"] in {"Acceptance", "Exception"}:
                item.setdefault("attributes", {})["prototype_applicable"] = True
        proof = next(item for item in graph["nodes"] if item["id"] == "PO-001")
        proof["attributes"].update({
            "proof_type": "visual", "capture_profile": profile,
            "runner": {
                "argv": [sys.executable, "-c", "raise SystemExit('patched by test')"],
                "cwd": ".", "observation_adapter": "visual_bundle", "timeout_seconds": 30,
            },
        })
        assertion = next(item for item in graph["nodes"] if item["id"] == "ASRT-001")
        assertion["attributes"]["oracle"] = {
            "kind": "json_path", "source": "/observation/pixel_diff_ratio",
            "operator": "eq", "expected": 0.0,
        }
        graph["nodes"].extend([
            node("ASRT-002", "Assertion", "Geometry", "Geometry must match", oracle={"kind": "json_path", "source": "/observation/geometry_diff_max", "operator": "eq", "expected": 0}, subject_ids=["AC-001"]),
            node("ASRT-003", "Assertion", "Forbidden", "Forbidden elements must be absent", oracle={"kind": "json_path", "source": "/observation/forbidden_elements_count", "operator": "eq", "expected": 0}, subject_ids=["EX-001"]),
        ])
        graph["edges"].extend([
            edge("ASRT-002", "proves", "PO-001"), edge("ASRT-003", "proves", "PO-001"),
        ])
        write_json(directory / "delivery-graph.json", graph)
        return profile, paths

    def prepare_invariant_run(self, root: Path, run_id: str) -> tuple[Path, Path, dict[str, object]]:
        adapter = root / ".dlv/repository-adapter.json"
        fixture = root / ".dlv/fixtures/invariant.json"
        write_json(adapter, {"schema_version": 12, "name": "test-adapter", "source_ref": "test-repository-adapter", "frontend_roots": ["src"], "capabilities": {}})
        write_json(fixture, {"case": "invariant-v1"})
        graph = delivery_graph.load_graph(root, "cross-domain-feature")
        spec = {
            "runtime": "python", "preflight": [], "target_identity": "python:test-target",
            "build_identity": "build:test", "deployment_identity": "deployment:local",
            "adapter_sha256": delivery_graph.file_digest(adapter),
            "fixture": {"path": fixture.relative_to(root).as_posix(), "sha256": delivery_graph.file_digest(fixture)},
            "attestation": test_attestation_config(),
        }
        next(item for item in graph["nodes"] if item["id"] == "ENV-001")["attributes"]["spec"] = spec
        next(item for item in graph["nodes"] if item["id"] == "PO-001")["attributes"]["proof_type"] = "invariant"
        write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
        bind_test_attestation_source(root)
        self.review_all(root)
        graph_contract.seal_contract(root, "cross-domain-feature")
        delivery_graph.mark_code_complete(root, "cross-domain-feature")
        environment = root / ".dlv/invariant-environment.json"
        result = root / ".dlv/invariant-result.json"
        write_json(environment, spec)
        graph_verification.start("cross-domain-feature", root, run_id, [f"ENV-001={environment}"])
        write_json(result, {"po_id": "PO-001", "proof_type": "invariant", "outcome": "evaluate", "anchors": []})
        metadata = json.loads((root / f".dlv/runs/cross-domain-feature/{run_id}/run.json").read_text())
        return result, fixture, metadata

    @staticmethod
    def visual_command_result(graph: dict, profile: dict[str, object], paths: dict[str, Path], **overrides: object):
        environment = next(item for item in graph["nodes"] if item["id"] == "ENV-001")["attributes"]["spec"]
        def completed(*_args: object, **kwargs: object) -> dict[str, object]:
            nonce = kwargs["environment"]["DLV_CHALLENGE_NONCE"]
            observation = {
                "anchor_paths": {role: str(path) for role, path in paths.items()},
                "anchor_sha256": {role: delivery_graph.file_digest(path) for role, path in paths.items()},
                "prototype_sha256": graph["prototype"]["sha256"],
                "capture_profile": profile,
                "pixel_diff_ratio": 0.0,
                "geometry_diff_max": 0,
                "forbidden_elements_count": 0,
                "challenge_nonce": nonce,
                "target_identity": environment["target_identity"],
            }
            observation.update(overrides)
            sign_target_observation(observation, environment, nonce)
            return {
                "exit_code": 0, "stdout": json.dumps(observation), "stderr": "", "timed_out": False,
            }
        return completed

    @staticmethod
    def signed_command_result(spec: dict[str, object], values: dict[str, object], **overrides: object):
        def completed(*_args: object, **kwargs: object) -> dict[str, object]:
            nonce = kwargs["environment"]["DLV_CHALLENGE_NONCE"]
            observation = {**values, "challenge_nonce": nonce, "target_identity": spec["target_identity"]}
            observation.update(overrides)
            sign_target_observation(observation, spec, nonce)
            return {"exit_code": 0, "stdout": json.dumps(observation), "stderr": "", "timed_out": False}
        return completed

    def test_valid_cross_type_graph_has_no_structural_or_semantic_issues(self) -> None:
        graph = valid_graph()
        self.assertEqual([], delivery_graph.structural_errors(graph, graph["feature_id"]))
        self.assertEqual([], delivery_graph.semantic_issues(graph))

    def test_claim_cannot_bind_an_unrelated_or_weak_proof(self) -> None:
        graph = valid_graph()
        claim_value = next(item for item in graph["claims"] if item["lens"] == "BOUNDARY_AND_CONCURRENCY")
        claim_value["subjects"] = ["SYM-001"]
        claim_value["id"] = claim_id_for(claim_value)
        issues = delivery_graph.semantic_issues(graph)
        self.assertTrue(any(issue["code"] == "CLAIM_PROOF_TRACE_MISMATCH" for issue in issues), issues)
        graph = valid_graph()
        next(item for item in graph["nodes"] if item["id"] == "PO-001")["attributes"]["proof_type"] = "artifact"
        runtime_claim = next(item for item in graph["claims"] if item["lens"] == "RUNTIME_AUTHENTICITY")
        runtime_claim["critical"] = True
        runtime_claim["id"] = claim_id_for(runtime_claim)
        issues = delivery_graph.semantic_issues(graph)
        self.assertTrue(any(issue["code"] == "CLAIM_PROOF_STRENGTH_MISMATCH" for issue in issues), issues)
        graph = valid_graph()
        next(item for item in graph["nodes"] if item["id"] == "PO-002")["attributes"]["proof_type"] = "artifact"
        issues = delivery_graph.semantic_issues(graph)
        self.assertTrue(any(issue["code"] == "CLAIM_PROOF_STRENGTH_MISMATCH" for issue in issues), issues)
        graph = valid_graph()
        assertion = next(item for item in graph["nodes"] if item["id"] == "ASRT-001")
        assertion["attributes"]["subject_ids"] = ["AC-001"]
        issues = delivery_graph.semantic_issues(graph)
        self.assertTrue(any(issue["code"] == "CLAIM_ASSERTION_SUBJECT_MISMATCH" for issue in issues), issues)

    def test_claim_criticality_is_identity_bound_and_cannot_be_downgraded(self) -> None:
        graph = valid_graph()
        boundary = next(item for item in graph["claims"] if item["lens"] == "BOUNDARY_AND_CONCURRENCY")
        original_id = boundary["id"]
        boundary["critical"] = False
        self.assertNotEqual(original_id, claim_id_for(boundary))
        errors = delivery_graph.structural_errors(graph, graph["feature_id"])
        self.assertTrue(any("cannot downgrade" in error for error in errors), errors)

    def test_one_scalar_cannot_claim_multiple_state_subjects(self) -> None:
        graph = valid_graph()
        assertion = next(item for item in graph["nodes"] if item["id"] == "ASRT-010")
        assertion["attributes"]["subject_ids"] = ["DEC-001", "FACT-001", "ST-001"]
        graph["nodes"] = [item for item in graph["nodes"] if item["id"] not in {"ASRT-011", "ASRT-012"}]
        graph["edges"] = [item for item in graph["edges"] if item["source"] not in {"ASRT-011", "ASRT-012"}]
        issues = delivery_graph.semantic_issues(graph)
        self.assertTrue(any(
            issue["code"] == "CLAIM_SUBJECT_MEASUREMENT_BINDING_INVALID" for issue in issues
        ), issues)

    def test_database_fact_requires_executable_commented_schema_contract(self) -> None:
        valid_sql = """CREATE TABLE trip_accounting (
  id bigint PRIMARY KEY, -- accounting row identity
  amount numeric(18, 2) NOT NULL, -- settled amount
  metadata jsonb DEFAULT '{}'::jsonb -- structured accounting metadata
);
ALTER TABLE trip_accounting ALTER COLUMN amount TYPE numeric(20, 2);
"""
        graph = valid_graph()
        fact = next(item for item in graph["nodes"] if item["id"] == "FACT-001")
        fact["attributes"]["persistence"] = {"kind": "database", "schema_sql": valid_sql}
        self.assertFalse(
            any(item["code"] == "DATABASE_SCHEMA_INVALID" for item in delivery_graph.semantic_issues(graph)),
            delivery_graph.semantic_issues(graph),
        )
        invalid_contracts = {
            "missing DDL": "SELECT 1;",
            "comment-only DDL": "-- CREATE TABLE fake (id bigint);\nSELECT 1;",
            "uncommented column": "CREATE TABLE trip_accounting (id bigint);",
            "migration execution": "CREATE TABLE trip_accounting (id bigint -- identity\n); DO $$ BEGIN DELETE FROM trip_accounting; END $$;",
            "migration numbering": "CREATE TABLE trip_accounting (id bigint -- identity\n); -- V920260825120000__trip_accounting",
        }
        for label, sql in invalid_contracts.items():
            with self.subTest(label=label):
                fact["attributes"]["persistence"] = {"kind": "database", "schema_sql": sql}
                self.assertTrue(
                    any(item["code"] == "DATABASE_SCHEMA_INVALID" for item in delivery_graph.semantic_issues(graph)),
                    delivery_graph.semantic_issues(graph),
                )

    def test_fact_persistence_must_be_explicit_and_non_database_kind_needs_rationale(self) -> None:
        graph = valid_graph()
        fact = next(item for item in graph["nodes"] if item["id"] == "FACT-001")
        fact["attributes"].pop("persistence")
        self.assertTrue(any(item["code"] == "FACT_PERSISTENCE_UNDECLARED" for item in delivery_graph.semantic_issues(graph)))
        fact["attributes"]["persistence"] = {"kind": "external"}
        self.assertTrue(any(item["code"] == "FACT_PERSISTENCE_RATIONALE_MISSING" for item in delivery_graph.semantic_issues(graph)))

    def test_initialization_creates_v12_canonical_artifacts_and_initial_source_revision(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            path = delivery_graph.initialize(root, "new-feature", "New feature")
            self.assertTrue(path.is_file())
            self.assertFalse((path.parent / "state.md").exists())
            self.assertEqual(
                {"delivery-graph.json", "state.json", "prd.md", "architecture-design.md", "code-spec.md", "proof-contract.json", "source-revisions"},
                {item.name for item in path.parent.iterdir()},
            )
            self.assertTrue((path.parent / "source-revisions/SRC-001.json").is_file())

    def test_stable_entrypoints_dispatch_schema_v12_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            init = subprocess.run(
                [sys.executable, str(SCRIPTS / "init_feature.py"), "dispatch-feature", "--root", str(root)],
                capture_output=True, text=True,
            )
            self.assertEqual(0, init.returncode, init.stdout + init.stderr)
            graph_path = root / "delivery/dispatch-feature/delivery-graph.json"
            dispatch_graph = valid_graph("dispatch-feature")
            remove_invariant_obligation(dispatch_graph)
            bind_test_runtime_files(root, dispatch_graph)
            write_json(graph_path, dispatch_graph)
            bind_test_attestation_source(root, "dispatch-feature")
            for command in (
                [sys.executable, str(SCRIPTS / "delivery_graph.py"), "compile", "dispatch-feature", "--root", str(root)],
                [sys.executable, str(SCRIPTS / "delivery_graph.py"), "compile", "dispatch-feature", "--root", str(root), "--check"],
            ):
                completed = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
            self.review_all(root, "dispatch-feature", "readiness-02")
            completed = subprocess.run(
                [sys.executable, str(SCRIPTS / "invalidate_downstream.py"), "dispatch-feature", "--root", str(root), "--changed-node", "SYM-001"],
                capture_output=True, text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
            self.review_all(root, "dispatch-feature")
            completed = subprocess.run(
                [sys.executable, str(SCRIPTS / "quality_review.py"), "dispatch-feature", "--root", str(root), "--run-id", "dispatch-debug", "--deterministic-only"],
                capture_output=True, text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
            for command in (
                [sys.executable, str(SCRIPTS / "seal_proof_contract.py"), "dispatch-feature", "--root", str(root)],
                [sys.executable, str(SCRIPTS / "delivery_graph.py"), "mark-code-complete", "dispatch-feature", "--root", str(root)],
            ):
                completed = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, contracted_environment_spec(root, feature_id="dispatch-feature"))
            write_json(result, {"po_id": "PO-001", "proof_type": "boundary", "outcome": "evaluate", "anchors": []})
            commands = [
                [sys.executable, str(SCRIPTS / "verification_run.py"), "start", "dispatch-feature", "--root", str(root), "--run-id", "dispatch-run", "--environment", f"ENV-001={environment}"],
                [sys.executable, str(SCRIPTS / "verification_run.py"), "record", "dispatch-feature", "--root", str(root), "--run-id", "dispatch-run", "--result", str(result)],
                [sys.executable, str(SCRIPTS / "finalize_delivery.py"), "dispatch-feature", "--root", str(root)],
                [sys.executable, str(SCRIPTS / "validate_feature.py"), "dispatch-feature", "--root", str(root), "--final"],
            ]
            for command in commands:
                completed = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
            metadata = json.loads((root / ".dlv/runs/dispatch-feature/dispatch-run/run.json").read_text())
            self.assertIsNone(metadata["commit_identity"])

    def test_compiler_rendering_is_deterministic_and_checkable(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            delivery_graph.compile_graph(root, "cross-domain-feature")
            directory = root / "delivery/cross-domain-feature"
            before = {name: (directory / name).read_bytes() for name in ("prd.md", "architecture-design.md", "code-spec.md", "proof-contract.json")}
            delivery_graph.compile_graph(root, "cross-domain-feature", check=True)
            delivery_graph.compile_graph(root, "cross-domain-feature")
            after = {name: (directory / name).read_bytes() for name in before}
            self.assertEqual(before, after)

    def test_compiler_rolls_back_generated_outputs_when_graph_changes_mid_write(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            delivery_graph.compile_graph(root, "cross-domain-feature")
            directory = root / "delivery/cross-domain-feature"
            names = ("prd.md", "architecture-design.md", "code-spec.md", "proof-contract.json", "state.json")
            before = {name: (directory / name).read_bytes() for name in names}
            ledger_path = root / ".dlv/findings/cross-domain-feature/ledger.json"
            ledger_before = ledger_path.read_bytes()
            ledger_before_value = json.loads(ledger_before)
            graph_path = directory / "delivery-graph.json"
            original_write = delivery_graph.atomic_write_text
            changed = False

            def change_graph_after_first_write(path: Path, content: str) -> None:
                nonlocal changed
                original_write(path, content)
                if not changed:
                    changed = True
                    graph = json.loads(graph_path.read_text())
                    graph["title"] = "Concurrent edit"
                    write_json(graph_path, graph)

            with patch.object(delivery_graph, "atomic_write_text", side_effect=change_graph_after_first_write):
                with self.assertRaisesRegex(ValueError, "changed during compilation"):
                    delivery_graph.compile_graph(root, "cross-domain-feature")
            self.assertEqual(before, {name: (directory / name).read_bytes() for name in names})
            self.assertEqual(ledger_before, ledger_path.read_bytes())
            ledger_after = json.loads(ledger_path.read_bytes())
            self.assertEqual(
                (len(ledger_before_value["convergence_events"]), ledger_before_value["convergence_events"][-1]["record_hash"]),
                (len(ledger_after["convergence_events"]), ledger_after["convergence_events"][-1]["record_hash"]),
            )

    def test_node_and_edge_order_do_not_change_hashes(self) -> None:
        graph = valid_graph()
        reordered = copy.deepcopy(graph)
        reordered["nodes"].reverse()
        reordered["edges"].reverse()
        reordered["claims"].reverse()
        for stage in delivery_graph.STAGES:
            self.assertEqual(delivery_graph.stage_hash(graph, stage), delivery_graph.stage_hash(reordered, stage))
        for lens in delivery_graph.LENSES:
            self.assertEqual(delivery_graph.lens_hash(graph, lens), delivery_graph.lens_hash(reordered, lens))
        self.assertEqual(delivery_graph.graph_digest(graph), delivery_graph.graph_digest(reordered))
        self.assertEqual(
            delivery_graph.generate_proof_contract(graph)["draft_sha256"],
            delivery_graph.generate_proof_contract(reordered)["draft_sha256"],
        )

    def test_scope_revision_creates_drift_then_owner_confirmation_starts_a_new_epoch(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            source = root / "new-source.json"
            write_json(source, {
                "title": "Changed scope", "description": "Use the existing panel locally.",
                "comments": ["No server-side recalculation."], "attachments": [test_attestation_attachment()],
                "risk_vector": {"VISUAL_CONTRACT": "present"},
            })
            scope_revision.capture(root, "cross-domain-feature", source, "product-owner")
            delivery_graph.compile_graph(root, "cross-domain-feature")
            drifted = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            self.assertEqual(("needs_decision", True), (drifted["readiness"]["status"], drifted["readiness"]["source_drift"]))
            scope_revision.confirm(root, "cross-domain-feature", "SRC-002", "product-owner", ["BHV-001"])
            state = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            self.assertEqual("SRC-002", delivery_graph.load_graph(root, "cross-domain-feature")["source_revision"])
            self.assertFalse(state["readiness"]["source_drift"])
            self.assertEqual("present", state["risk"]["source"]["VISUAL_CONTRACT"])

    def test_confirming_latest_scope_revision_supersedes_older_pending_capture_for_drift(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            for title in ("Earlier scope", "Latest scope"):
                source = root / f"{title.replace(' ', '-').lower()}.json"
                write_json(source, {
                    "title": title, "description": "Local display behavior.", "comments": [],
                    "attachments": [test_attestation_attachment()],
                    "risk_vector": {},
                })
                scope_revision.capture(root, "cross-domain-feature", source, "product-owner")
            scope_revision.confirm(root, "cross-domain-feature", "SRC-003", "product-owner", ["BHV-001"])
            state = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            self.assertEqual("SRC-003", delivery_graph.load_graph(root, "cross-domain-feature")["source_revision"])
            self.assertFalse(state["readiness"]["source_drift"])

    def test_scope_confirmation_rejects_unknown_impact_without_mutating_epoch(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            source = root / "new-source.json"
            write_json(source, {
                "title": "Changed scope", "description": "Local display behavior.", "comments": [], "attachments": [],
                "risk_vector": {},
            })
            scope_revision.capture(root, "cross-domain-feature", source, "product-owner")
            with self.assertRaisesRegex(ValueError, "affected-node references unknown IDs"):
                scope_revision.confirm(root, "cross-domain-feature", "SRC-002", "product-owner", ["REQ-999"])
            revision = json.loads((root / "delivery/cross-domain-feature/source-revisions/SRC-002.json").read_text())
            self.assertEqual("pending_confirmation", revision["status"])
            self.assertEqual("SRC-001", delivery_graph.load_graph(root, "cross-domain-feature")["source_revision"])

    def test_ui_local_profile_does_not_activate_unrelated_architecture_lenses(self) -> None:
        graph = delivery_graph.default_graph("ui-local")
        graph["nodes"] = [
            node("REQ-001", "Requirement", "Need", "User needs a local guide"),
            node("BHV-001", "Behavior", "Show", "The page shows the guide"),
            node("AC-001", "Acceptance", "Visible", "The guide is visible"),
            node("CHG-001", "Change", "UI", "Change the local guide component"),
            node("SYM-001", "Symbol", "Guide", "Guide component", path="web/guide.tsx"),
            node("ENV-001", "Environment", "Browser", "Browser runtime", target="browser", spec={"runtime": "browser", "preflight": []}),
            node("TST-001", "Test", "Guide test", "Test guide visibility"),
            node("PO-001", "Proof", "Guide proof", "Prove the guide is visible", proof_type="artifact", surface="guide", critical=False, runner={"argv": [sys.executable, "-c", "print('{}')"], "cwd": ".", "observation_adapter": "json_stdout", "timeout_seconds": 30}),
            node("ASRT-001", "Assertion", "Exists", "Output exists", oracle={"kind": "json_path", "source": "/observation", "operator": "exists"}, subject_ids=["AC-001"]),
        ]
        graph["edges"] = [
            edge("BHV-001", "derives_from", "REQ-001"), edge("AC-001", "derives_from", "BHV-001"),
            edge("CHG-001", "changes", "BHV-001"), edge("SYM-001", "depends_on", "CHG-001"),
            edge("TST-001", "tests", "AC-001"), edge("TST-001", "runs_in", "ENV-001"),
            edge("PO-001", "proves", "AC-001"), edge("PO-001", "runs_in", "ENV-001"), edge("ASRT-001", "proves", "PO-001"),
        ]
        self.assertEqual(
            ["BOUNDARY_AND_CONCURRENCY", "PROVENANCE_INTEGRITY", "RUNTIME_AUTHENTICITY", "STATE_AND_ATOMICITY"],
            delivery_graph.active_review_lenses(graph),
        )
        self.assertIn("ARCH_NO_CLAIM", {issue["code"] for issue in delivery_graph.semantic_issues(graph)})

    def test_finding_ledger_deduplicates_root_cause_and_omission_keeps_blocker_open(self) -> None:
        ledger = empty_ledger("feature")
        findings = [{
            "id": "NEW", "severity": "major", "status": "OPEN", "statement": "Money state is ambiguous",
            "evidence": "ST-001", "risk_path": "MONEY → SETTLED", "root_cause": "zero-net transition ambiguity",
            "claim_id": "CLM-000000000001", "failure_mode": "ambiguous transition", "violated_invariant": "money settles once",
            "subjects": ["ST-001"], "risk_axes": ["MONEY"],
            "previously_invisible_reason": "first semantic review",
        }]
        ledger, first = apply_review_findings(ledger, unit_id="global-system-coherence", source_revision="SRC-001", findings=findings)
        ledger, second = apply_review_findings(ledger, unit_id="global-system-coherence", source_revision="SRC-001", findings=[{**findings[0], "id": "NEW"}])
        self.assertEqual(first[0]["id"], second[0]["id"])
        ledger, omitted = apply_review_findings(ledger, unit_id="global-system-coherence", source_revision="SRC-002", findings=[])
        self.assertEqual("OPEN", omitted[0]["status"])
        self.assertEqual(1, finding_summary(ledger)["open_blockers"])

    def test_finding_repair_requires_fresh_review_and_updates_convergence(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            ledger = empty_ledger("cross-domain-feature")
            ledger, entries = apply_review_findings(
                ledger, unit_id="global-system-coherence", source_revision="SRC-001", findings=[{
                    "id": "NEW", "severity": "major", "status": "OPEN", "statement": "Boundary proof is incomplete",
                    "evidence": "RISK-001", "risk_path": "CONCURRENCY → duplicate execution",
                    "root_cause": "missing duplicate execution observation",
                    "claim_id": valid_graph()["claims"][2]["id"], "failure_mode": "duplicate execution", "violated_invariant": "boundary rejects duplicates",
                    "subjects": ["RISK-001"], "risk_axes": ["CONCURRENCY"],
                    "previously_invisible_reason": "review found the missing observation",
                }],
            )
            finding_id = entries[0]["id"]
            write_ledger(root, "cross-domain-feature", ledger)
            delivery_graph.compile_graph(root, "cross-domain-feature")
            self.assertEqual("blocked", delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")["readiness"]["status"])
            finding_ledger.transition(root, "cross-domain-feature", finding_id, "FIXED_PENDING_REVIEW", "implementer", "Added result readback")
            state = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            self.assertEqual("FIXED_PENDING_REVIEW", load_ledger(root, "cross-domain-feature")["entries"][finding_id]["status"])
            self.assertEqual("CONVERGING", state["convergence"]["status"])

    def test_p2_requires_owner_decision_while_p3_remains_advisory(self) -> None:
        def finding(severity: str, suffix: str) -> dict[str, object]:
            bound_claim = valid_graph()["claims"][0]
            return {
                "id": "NEW", "severity": severity, "status": "OPEN",
                "statement": f"Bounded delivery concern {suffix}",
                "evidence": f"Observed bounded evidence {suffix}",
                "risk_path": f"VISUAL_CONTRACT → {suffix}",
                "root_cause": f"bounded root cause {suffix}",
                "claim_id": bound_claim["id"], "failure_mode": f"bounded failure {suffix}",
                "violated_invariant": bound_claim["invariant"],
                "subjects": [bound_claim["subjects"][0]], "risk_axes": ["VISUAL_CONTRACT"],
                "previously_invisible_reason": f"review exposed {suffix}",
            }

        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            ledger, p2_entries = apply_review_findings(
                load_ledger(root, "cross-domain-feature"), unit_id="global-system-coherence",
                source_revision="SRC-001", findings=[finding("moderate", "p2")],
            )
            write_ledger(root, "cross-domain-feature", ledger)
            state = delivery_graph.compile_graph(root, "cross-domain-feature")
            self.assertEqual("needs_decision", state["readiness"]["status"])
            self.assertEqual(1, state["readiness"]["open_owner_decision_findings"])
            finding_ledger.transition(
                root, "cross-domain-feature", p2_entries[0]["id"], "ACCEPTED_RISK",
                "owner", "Bounded impact is documented for follow-up",
            )
            accepted = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            self.assertEqual("ready", accepted["readiness"]["status"])
            self.assertEqual([], graph_validation.validate(root, "cross-domain-feature"))

        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            ledger, _ = apply_review_findings(
                load_ledger(root, "cross-domain-feature"), unit_id="global-system-coherence",
                source_revision="SRC-001", findings=[finding("minor", "p3")],
            )
            write_ledger(root, "cross-domain-feature", ledger)
            advisory = delivery_graph.compile_graph(root, "cross-domain-feature")
            self.assertEqual("ready", advisory["readiness"]["status"])
            self.assertEqual(1, advisory["finding_ledger"]["summary"]["open_total"])

    def test_p0_p1_cannot_be_accepted_as_delivery_risk(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            ledger = empty_ledger("cross-domain-feature")
            bound_claim = valid_graph()["claims"][0]
            ledger, entries = apply_review_findings(
                ledger, unit_id="global-system-coherence", source_revision="SRC-001", findings=[{
                    "id": "NEW", "severity": "major", "status": "OPEN",
                    "statement": "Important contract failure", "evidence": "Observed contract break",
                    "risk_path": "API_CONTRACT → client break", "root_cause": "incompatible contract",
                    "claim_id": bound_claim["id"], "failure_mode": "client request fails",
                    "violated_invariant": bound_claim["invariant"],
                    "subjects": [bound_claim["subjects"][0]], "risk_axes": ["API_CONTRACT"],
                    "previously_invisible_reason": "independent review exposed the break",
                }],
            )
            ledger["campaigns"] = [
                {"run_id": f"review-0{index}", "recorded_at": "2026-08-28T00:00:00+08:00", "unit_count": 1, "new_findings": 0}
                for index in range(1, 4)
            ]
            write_ledger(root, "cross-domain-feature", ledger)
            stopped = delivery_graph.compile_graph(root, "cross-domain-feature")
            self.assertEqual("NEEDS_DECISION", stopped["convergence"]["status"])
            with self.assertRaisesRegex(ValueError, "requires a decision"):
                graph_review.run_isolated_readiness_review(root, "cross-domain-feature", "review-04")
            with self.assertRaisesRegex(ValueError, "P0/P1"):
                finding_ledger.transition(
                    root, "cross-domain-feature", entries[0]["id"], "ACCEPTED_RISK",
                    "owner", "must not bypass important risk",
                )

    def test_observed_symbol_risk_requires_graph_reconciliation_before_code_completion(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            (root / "src").mkdir()
            (root / "src/domain_service.py").write_text("def reimburse(amount): return amount\n", encoding="utf-8")
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            with self.assertRaisesRegex(ValueError, "undeclared risk axes"):
                delivery_graph.mark_code_complete(root, "cross-domain-feature")
            state = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            self.assertEqual("needs_reconcile", state["code"]["status"])
            self.assertEqual("present", state["risk"]["observed"]["MONEY"])

    def test_v10_compatibility_import_archives_mutable_records_and_resets_claims(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            directory = root / "delivery/legacy-v10"
            directory.mkdir(parents=True)
            graph = valid_graph("legacy-v10")
            graph["schema_version"] = 10
            graph.pop("source_revision")
            graph["metadata"] = {}
            graph["prototype"] = {"status": "not_applicable"}
            write_json(directory / "delivery-graph.json", graph)
            write_json(directory / "state.json", {"schema_version": 10})
            upgrade_v10_to_v11.upgrade(root, "legacy-v10", apply=True)
            migrated = json.loads((directory / "delivery-graph.json").read_text())
            self.assertEqual((12, "SRC-001"), (migrated["schema_version"], migrated["source_revision"]))
            self.assertTrue((root / ".dlv/upgrades/legacy-v10/schema-v10-archive/delivery-graph.json").is_file())
            self.assertEqual({}, delivery_graph.load_state(directory / "state.json")["attestations"])

    def test_v10_compatibility_import_rolls_back_compile_failure_and_retries(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            directory = root / "delivery/legacy-v10"
            directory.mkdir(parents=True)
            graph = valid_graph("legacy-v10")
            graph["schema_version"] = 10
            graph.pop("source_revision")
            graph["metadata"] = {}
            graph["prototype"] = {"status": "not_applicable"}
            write_json(directory / "delivery-graph.json", graph)
            write_json(directory / "state.json", {"schema_version": 10, "sentinel": "original"})
            original_graph = (directory / "delivery-graph.json").read_bytes()
            original_state = (directory / "state.json").read_bytes()
            with patch.object(upgrade_v10_to_v11, "compile_graph", side_effect=OSError("injected compile failure")):
                with self.assertRaisesRegex(OSError, "injected compile failure"):
                    upgrade_v10_to_v11.upgrade(root, "legacy-v10", apply=True)
            self.assertEqual(original_graph, (directory / "delivery-graph.json").read_bytes())
            self.assertEqual(original_state, (directory / "state.json").read_bytes())
            self.assertFalse((directory / "source-revisions/SRC-001.json").exists())
            upgrade_v10_to_v11.upgrade(root, "legacy-v10", apply=True)
            self.assertEqual(12, delivery_graph.load_graph(root, "legacy-v10")["schema_version"])

    def test_v10_compatibility_import_rejects_partial_states_and_preserves_owner_edits(self) -> None:
        for stage in ("source-written", "graph-written"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                subprocess.run(["git", "init", "-q"], cwd=root, check=True)
                directory = root / "delivery/legacy-v10"
                directory.mkdir(parents=True)
                graph = valid_graph("legacy-v10")
                graph["schema_version"] = 10
                graph.pop("source_revision")
                graph.pop("claim_successions")
                graph["metadata"] = {}
                graph["prototype"] = {"status": "not_applicable"}
                write_json(directory / "delivery-graph.json", graph)
                write_json(directory / "state.json", {"schema_version": 10})
                candidate = upgrade_v10_to_v11.upgrade(root, "legacy-v10", apply=False)
                archive = root / ".dlv/upgrades/legacy-v10/schema-v10-archive"
                manifest: dict[str, str] = {}
                for name in upgrade_v10_to_v11.ARCHIVE_FILES:
                    source = directory / name
                    if source.is_file():
                        manifest[name] = upgrade_v10_to_v11._archive_copy(source, archive / name)
                write_json(archive / "manifest.json", {
                    "feature_id": "legacy-v10", "schema_version": 10, "artifacts": manifest,
                })
                create_source_revision(
                    directory, "legacy-v10", "SRC-001",
                    {
                        "title": "legacy-v10", "description": "OWNER EDIT AFTER CRASH",
                        "comments": [], "attachments": [], "risk_vector": {},
                    },
                    owner="schema-v10-migration", status="confirmed",
                )
                if stage == "graph-written":
                    write_json(directory / "delivery-graph.json", candidate)
                source_path = directory / "source-revisions/SRC-001.json"
                before_source = source_path.read_bytes()
                with self.assertRaisesRegex(ValueError, "preserve Owner edits|partial schema-v12"):
                    upgrade_v10_to_v11.upgrade(root, "legacy-v10", apply=True)
                self.assertEqual(before_source, source_path.read_bytes())

    def test_dependency_and_impact_closures_are_exact(self) -> None:
        graph = valid_graph()
        impacted = delivery_graph.impact_closure(graph, {"DEC-001"})
        self.assertEqual({
            "DEC-001", "CHG-001", "SYM-001", "TST-001", "PO-001", "ASRT-001",
            "PO-002", "ASRT-010", "ASRT-011", "ASRT-012", "ASRT-013", "ASRT-015",
        }, impacted)
        dependencies = delivery_graph.dependency_closure(graph, {"SYM-001"})
        self.assertEqual(
            {
                "SYM-001", "CHG-001", "DEC-001", "FACT-001", "OWN-001", "RISK-001",
                "BHV-001", "REQ-001", "PER-001", "ST-001", "BND-001",
            },
            dependencies,
        )

    def test_component_snapshot_includes_incoming_risk_mitigation_providers(self) -> None:
        graph = valid_graph()
        units = [unit for unit in delivery_graph.review_units(graph).values() if unit["lens"] == "BOUNDARY_AND_CONCURRENCY"]
        risk_unit = next(unit for unit in units if "RISK-001" in unit["root_node_ids"])
        self.assertTrue({"DEC-001", "CHG-001", "PO-001"} <= set(risk_unit["node_ids"]))

    def test_shared_mitigation_provider_does_not_cross_invalidate_risk_components(self) -> None:
        graph = valid_graph()
        graph["nodes"].append(
            node("RISK-002", "Risk", "Independent audit risk", "Audit publication could fail", severity="major"),
        )
        graph["edges"].extend([
            edge("CHG-001", "mitigates", "RISK-002"),
            edge("PO-001", "mitigates", "RISK-002"),
        ])
        before = {
            unit["root_node_ids"][0]: unit
            for unit in delivery_graph.lens_components(graph, "BOUNDARY_AND_CONCURRENCY")
            if unit["root_node_ids"] in (["RISK-001"], ["RISK-002"])
        }
        self.assertEqual({"RISK-001", "RISK-002"}, set(before))
        self.assertNotIn("RISK-002", before["RISK-001"]["node_ids"])
        self.assertNotIn("RISK-001", before["RISK-002"]["node_ids"])
        next(item for item in graph["nodes"] if item["id"] == "RISK-002")["statement"] += " visibly"
        after = {
            unit["root_node_ids"][0]: unit
            for unit in delivery_graph.lens_components(graph, "BOUNDARY_AND_CONCURRENCY")
            if unit["root_node_ids"] in (["RISK-001"], ["RISK-002"])
        }
        self.assertEqual(before["RISK-001"]["subgraph_sha256"], after["RISK-001"]["subgraph_sha256"])
        self.assertNotEqual(before["RISK-002"]["subgraph_sha256"], after["RISK-002"]["subgraph_sha256"])

    def test_shared_environment_is_context_without_bridging_proof_components(self) -> None:
        graph = valid_graph()
        graph["nodes"].extend([
            node("AC-002", "Acceptance", "Independent export", "The report export succeeds"),
            node("TST-002", "Test", "Export test", "Test the independent export"),
            node(
                "PO-002", "Proof", "Export proof", "Prove export in the target runtime",
                proof_type="runtime", surface="report export", critical=True,
                runner={
                    "argv": [sys.executable, "-c", "import json; print(json.dumps({'ok': True}))"],
                    "cwd": ".", "observation_adapter": "json_stdout", "timeout_seconds": 30,
                },
            ),
            node(
                "ASRT-002", "Assertion", "Export assertion", "The export result is true",
                oracle={"kind": "json_path", "source": "/observation/ok", "operator": "eq", "expected": True},
            ),
        ])
        graph["edges"].extend([
            edge("AC-002", "derives_from", "BHV-001"),
            edge("TST-002", "tests", "AC-002"),
            edge("TST-002", "runs_in", "ENV-001"),
            edge("PO-002", "proves", "AC-002"),
            edge("PO-002", "proves", "TST-002"),
            edge("PO-002", "runs_in", "ENV-001"),
            edge("ASRT-002", "proves", "PO-002"),
        ])
        units = delivery_graph.lens_components(graph, "RUNTIME_AUTHENTICITY")
        first = next(unit for unit in units if "PO-001" in unit["root_node_ids"])
        second = next(unit for unit in units if "PO-002" in unit["root_node_ids"])
        self.assertNotEqual(first["component_id"], second["component_id"])
        self.assertIn("ENV-001", first["node_ids"])
        self.assertIn("ENV-001", second["node_ids"])

    def test_structural_mutation_corpus_detects_every_fault(self) -> None:
        mutations = []
        graph = valid_graph()
        value = copy.deepcopy(graph); value["schema_version"] = 9; mutations.append(value)
        value = copy.deepcopy(graph); value["nodes"].append(copy.deepcopy(value["nodes"][0])); mutations.append(value)
        value = copy.deepcopy(graph); value["nodes"][0]["id"] = "bad"; mutations.append(value)
        value = copy.deepcopy(graph); value["nodes"][0]["type"] = "Unknown"; mutations.append(value)
        value = copy.deepcopy(graph); value["edges"][0]["target"] = "REQ-999"; mutations.append(value)
        value = copy.deepcopy(graph); value["edges"][0]["type"] = "unknown"; mutations.append(value)
        value = copy.deepcopy(graph); value["edges"][0] = edge("REQ-001", "owns", "BHV-001"); mutations.append(value)
        value = copy.deepcopy(graph); value["edges"].append(copy.deepcopy(value["edges"][0])); mutations.append(value)
        value = copy.deepcopy(graph); value["prototype"] = {"status": "maybe"}; mutations.append(value)
        value = copy.deepcopy(graph); value["unknown"] = True; mutations.append(value)
        self.assertTrue(all(delivery_graph.structural_errors(value) for value in mutations))

    def test_semantic_mutations_detect_owner_guard_transition_change_and_proof_faults(self) -> None:
        cases = {
            "missing owner": lambda edges: [e for e in edges if not (e["type"] == "owns" and e["target"] == "FACT-001")],
            "missing guard": lambda edges: [e for e in edges if e["type"] != "guards"],
            "missing transition": lambda edges: [e for e in edges if e["type"] != "transitions"],
            "unmapped change": lambda edges: [e for e in edges if not (e["source"] == "CHG-001" and e["type"] == "changes")],
            "untested acceptance": lambda edges: [e for e in edges if not (e["target"] == "AC-001" and e["type"] == "tests")],
            "unproved exception": lambda edges: [e for e in edges if not (e["target"] == "EX-001" and e["type"] == "proves")],
            "proof without environment": lambda edges: [e for e in edges if not (e["source"] == "PO-001" and e["type"] == "runs_in")],
            "proof without assertion": lambda edges: [e for e in edges if e["source"] != "ASRT-001"],
            "unmitigated risk": lambda edges: [e for e in edges if e["target"] != "RISK-001"],
        }
        for name, mutation in cases.items():
            with self.subTest(name=name):
                graph = valid_graph()
                graph["edges"] = mutation(graph["edges"])
                self.assertTrue(delivery_graph.semantic_issues(graph), name)

    def test_ui_local_graph_skips_unrelated_architecture_but_not_implementation_proof(self) -> None:
        graph = delivery_graph.default_graph("empty-stages")
        graph["nodes"] = [
            node("REQ-001", "Requirement", "Need", "A user needs a result"),
            node("BHV-001", "Behavior", "Act", "The system produces the result"),
            node("AC-001", "Acceptance", "Done", "The result is observable"),
        ]
        graph["edges"] = [
            edge("BHV-001", "derives_from", "REQ-001"),
            edge("AC-001", "derives_from", "BHV-001"),
        ]
        codes = {item["code"] for item in delivery_graph.semantic_issues(graph)}
        self.assertIn("ARCH_NO_CLAIM", codes)
        self.assertTrue({"IMPLEMENTATION_NO_CHANGE", "IMPLEMENTATION_NO_SYMBOL"} <= codes)

    def test_completed_prototype_requires_canonical_zero_difference_visual_proof(self) -> None:
        graph = valid_graph()
        graph["prototype"] = {"status": "contractual", "path": "prototype.html", "sha256": "0" * 64}
        codes = {item["code"] for item in delivery_graph.semantic_issues(graph, "RUNTIME_AUTHENTICITY")}
        self.assertIn("PROTOTYPE_VISUAL_PROOF_MISSING", codes)

        proof = next(item for item in graph["nodes"] if item["id"] == "PO-001")
        proof["attributes"]["proof_type"] = "visual"
        proof["attributes"]["runner"]["observation_adapter"] = "visual_bundle"
        proof["attributes"]["capture_profile"] = {
            "viewport": "1440x900", "state": "fixture", "data": "fixture-v1",
            "dpr": 1, "fonts": ["Noto Sans SC"],
        }
        for item in graph["nodes"]:
            if item["type"] in {"Acceptance", "Exception"}:
                item.setdefault("attributes", {})["prototype_applicable"] = True
        environment = next(item for item in graph["nodes"] if item["id"] == "ENV-001")
        environment["attributes"]["spec"]["runtime"] = "browser"
        assertion = next(item for item in graph["nodes"] if item["id"] == "ASRT-001")
        assertion["attributes"]["oracle"] = {
            "kind": "json_path", "source": "/observation/pixel_diff_ratio",
            "operator": "lte", "expected": 1.0,
        }
        graph["nodes"].extend([
            node("ASRT-002", "Assertion", "Geometry", "Geometry must match", oracle={"kind": "json_path", "source": "/observation/geometry_diff_max", "operator": "eq", "expected": 0}, subject_ids=["AC-001"]),
            node("ASRT-003", "Assertion", "Forbidden", "Forbidden elements must be absent", oracle={"kind": "json_path", "source": "/observation/forbidden_elements_count", "operator": "eq", "expected": 0}, subject_ids=["EX-001"]),
        ])
        graph["edges"].extend([
            edge("ASRT-002", "proves", "PO-001"), edge("ASRT-003", "proves", "PO-001"),
        ])
        codes = {item["code"] for item in delivery_graph.semantic_issues(graph, "RUNTIME_AUTHENTICITY")}
        self.assertIn("VISUAL_ASSERTIONS_INCOMPLETE", codes)
        assertion["attributes"]["oracle"] = {
            "kind": "json_path", "source": "/observation/pixel_diff_ratio",
            "operator": "eq", "expected": 0.0,
        }
        codes = {item["code"] for item in delivery_graph.semantic_issues(graph, "RUNTIME_AUTHENTICITY")}
        self.assertNotIn("PROTOTYPE_VISUAL_PROOF_MISSING", codes)
        self.assertNotIn("VISUAL_ASSERTIONS_INCOMPLETE", codes)

    def test_stage_review_composes_lenses_and_seal(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            state = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            self.assertEqual("ready", state["readiness"]["status"])
            self.assertEqual(set(delivery_graph.review_units(delivery_graph.load_graph(root, "cross-domain-feature"))), set(state["attestations"]))
            seal = graph_contract.seal_contract(root, "cross-domain-feature")
            contract = json.loads((root / "delivery/cross-domain-feature/proof-contract.json").read_text())
            self.assertEqual(seal, contract["seal"])
            self.assertEqual("sealed", contract["status"])

    def test_deterministic_only_debug_reviews_cannot_seal_without_semantic_attestation(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            delivery_graph.compile_graph(root, "cross-domain-feature")
            graph_review.record_readiness(root, "cross-domain-feature", "readiness-debug")
            with self.assertRaisesRegex(ValueError, "independent semantic attestation"):
                graph_contract.seal_contract(root, "cross-domain-feature")
            with patch.object(graph_review, "run_bounded", side_effect=self.fake_semantic_run) as reviewer:
                graph_review.run_isolated_readiness_review(root, "cross-domain-feature", "readiness-semantic")
            self.assertEqual(
                len(delivery_graph.review_units(delivery_graph.load_graph(root, "cross-domain-feature"))),
                reviewer.call_count,
            )
            graph_contract.seal_contract(root, "cross-domain-feature")

    def test_failed_lens_cannot_be_hidden_by_composite_pass(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            graph = valid_graph()
            graph["edges"] = [e for e in graph["edges"] if e["type"] != "guards"]
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            delivery_graph.compile_graph(root, "cross-domain-feature")
            graph_review.record_readiness(root, "cross-domain-feature", "readiness-bad")
            state = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            self.assertEqual("blocked", state["readiness"]["status"])
            boundary_units = [unit_id for unit_id, unit in delivery_graph.review_units(graph).items() if unit["lens"] == "BOUNDARY_AND_CONCURRENCY"]
            self.assertTrue(any(state["attestations"][unit_id]["verdict"] == "BLOCKED" for unit_id in boundary_units))
            with self.assertRaisesRegex(ValueError, "Delivery Readiness"):
                graph_contract.seal_contract(root, "cross-domain-feature")

    def test_unaffected_attestation_is_reused_and_affected_one_is_invalidated(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            path = root / "delivery/cross-domain-feature/delivery-graph.json"
            graph = json.loads(path.read_text())
            next(node for node in graph["nodes"] if node["id"] == "FACT-001")["statement"] += " with versioning"
            write_json(path, graph)
            message = graph_invalidate.invalidate(root, "cross-domain-feature")
            state = delivery_graph.load_state(path.parent / "state.json")
            units = delivery_graph.review_units(graph)
            self.assertIn(self.unit_id(graph, "PROVENANCE_INTEGRITY"), state["attestations"])
            self.assertNotIn(self.unit_id(graph, "STATE_AND_ATOMICITY"), state["attestations"])
            self.assertNotIn(delivery_graph.GLOBAL_LENS, state["attestations"])
            self.assertIn("FACT-001", message)

    def test_local_symbol_change_reviews_only_its_component_and_reuses_global_skeleton(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            path = root / "delivery/cross-domain-feature/delivery-graph.json"
            graph = json.loads(path.read_text())
            graph["nodes"].extend([
                node("BHV-002", "Behavior", "Independent export", "Export an independent accounting report"),
                node("CHG-002", "Change", "Export change", "Add the isolated export implementation"),
                node("SYM-002", "Symbol", "Export symbol", "report/export.py:export_report"),
            ])
            graph["edges"].extend([
                edge("BHV-002", "derives_from", "REQ-001"),
                edge("CHG-002", "changes", "BHV-002"),
                edge("SYM-002", "depends_on", "CHG-002"),
            ])
            write_json(path, graph)
            self.review_all(root)
            before = delivery_graph.load_state(path.parent / "state.json")
            units = delivery_graph.review_units(graph)
            changed_unit = next(unit_id for unit_id, unit in units.items() if "SYM-002" in unit["root_node_ids"])
            peer_units = {
                unit_id for unit_id, unit in units.items()
                if unit["lens"] == "BOUNDARY_AND_CONCURRENCY" and unit_id != changed_unit
            }
            self.assertTrue(peer_units)
            next(item for item in graph["nodes"] if item["id"] == "SYM-002")["statement"] += " with CSV output"
            write_json(path, graph)
            delivery_graph.compile_graph(root, "cross-domain-feature")
            stale = delivery_graph.load_state(path.parent / "state.json")
            self.assertNotIn(changed_unit, stale["attestations"])
            self.assertTrue(peer_units <= set(stale["attestations"]))
            self.assertEqual(before["attestations"][delivery_graph.GLOBAL_LENS], stale["attestations"][delivery_graph.GLOBAL_LENS])
            changed = next(unit for unit in delivery_graph.review_units(graph).values() if "SYM-002" in unit["root_node_ids"])
            theoretical = delivery_graph.dependency_closure(graph, {"SYM-002"})
            self.assertLessEqual(len(changed["node_ids"]) / len(theoretical), 1.25)
            with patch.object(graph_review, "run_bounded", side_effect=self.fake_semantic_run) as reviewer:
                graph_review.run_isolated_readiness_review(root, "cross-domain-feature", "local-symbol-rerun")
            self.assertEqual(1, reviewer.call_count)

    def test_cross_component_topology_change_invalidates_global_skeleton(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            path = root / "delivery/cross-domain-feature/delivery-graph.json"
            graph = json.loads(path.read_text())
            graph["nodes"].extend([
                node("BHV-002", "Behavior", "Independent export", "Export an independent accounting report"),
                node("CHG-002", "Change", "Export change", "Add the isolated export implementation"),
                node("SYM-002", "Symbol", "Export symbol", "report/export.py:export_report"),
            ])
            graph["edges"].extend([
                edge("BHV-002", "derives_from", "REQ-001"),
                edge("CHG-002", "changes", "BHV-002"),
                edge("SYM-002", "depends_on", "CHG-002"),
            ])
            write_json(path, graph)
            self.review_all(root)
            self.assertIn(delivery_graph.GLOBAL_LENS, delivery_graph.load_state(path.parent / "state.json")["attestations"])
            graph["edges"].append(edge("SYM-002", "depends_on", "CHG-001"))
            write_json(path, graph)
            delivery_graph.compile_graph(root, "cross-domain-feature")
            state = delivery_graph.load_state(path.parent / "state.json")
            self.assertNotIn(delivery_graph.GLOBAL_LENS, state["attestations"])

    def test_global_skeleton_binds_compact_cross_component_claims(self) -> None:
        graph = valid_graph()
        graph["nodes"].extend([
            node("REQ-002", "Requirement", "Refund prohibition", "The system must never allow cancellation refunds"),
            node("BHV-002", "Behavior", "Reject refunds", "The system rejects every cancellation refund"),
            node("AC-002", "Acceptance", "Refund rejected", "A cancellation refund is always rejected"),
        ])
        graph["edges"].extend([
            edge("BHV-002", "derives_from", "REQ-002"),
            edge("AC-002", "derives_from", "BHV-002"),
        ])
        next(item for item in graph["nodes"] if item["id"] == "REQ-001")["statement"] = (
            "The system must always allow cancellation refunds"
        )
        unit = delivery_graph.review_units(graph)[delivery_graph.GLOBAL_LENS]
        claims = {item["id"]: item for item in unit["claim_synopsis"]}
        self.assertEqual(
            {"REQ-001", "REQ-002"},
            {node_id for node_id in claims if node_id.startswith("REQ-")},
        )
        self.assertIn("must always allow", claims["REQ-001"]["statement"])
        self.assertIn("must never allow", claims["REQ-002"]["statement"])
        before = unit["subgraph_sha256"]
        next(item for item in graph["nodes"] if item["id"] == "REQ-002")["statement"] += " for any role"
        self.assertNotEqual(
            before,
            delivery_graph.review_units(graph)[delivery_graph.GLOBAL_LENS]["subgraph_sha256"],
        )

    def test_explicit_node_invalidation_removes_impacted_attestations_without_graph_edit(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph_invalidate.invalidate(root, "cross-domain-feature", ["FACT-001"])
            state = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            self.assertIn(self.unit_id(graph, "PROVENANCE_INTEGRITY"), state["attestations"])
            self.assertNotIn(self.unit_id(graph, "STATE_AND_ATOMICITY"), state["attestations"])
            affected_change_units = [
                unit_id for unit_id, unit in delivery_graph.review_units(graph).items()
                if unit["lens"] == "BOUNDARY_AND_CONCURRENCY" and "FACT-001" in unit["node_ids"]
            ]
            self.assertTrue(affected_change_units)
            self.assertTrue(all(unit_id not in state["attestations"] for unit_id in affected_change_units))

    def test_explicit_stage_invalidation_drops_seal_and_stales_code(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            graph_invalidate.invalidate(root, "cross-domain-feature", reset_reviews=True)
            state = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            self.assertEqual("draft", state["proof_contract"]["status"])
            self.assertEqual("stale", state["code"]["status"])
            self.assertEqual("pending", state["verification"]["status"])

    def test_prototype_bytes_are_bound_to_product_review_hash(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            directory = root / "delivery/cross-domain-feature"
            prototype = directory / "prototype.html"
            prototype.write_text("<main>version one</main>", encoding="utf-8")
            graph_path = directory / "delivery-graph.json"
            graph = json.loads(graph_path.read_text())
            graph["prototype"] = {
                "status": "contractual", "path": "prototype.html",
                "sha256": delivery_graph.file_digest(prototype),
                "source_revision": "SRC-001", "source_kind": "source_revision",
                "source_ref": "SRC-001", "source_sha256": json.loads((directory / "source-revisions/SRC-001.json").read_text())["source_digest"],
            }
            write_json(graph_path, graph)
            self.review_all(root)
            prior_unit = self.unit_id(graph, "PROVENANCE_INTEGRITY")
            prior = delivery_graph.load_state(directory / "state.json")["attestations"][prior_unit]
            prototype.write_text("<main>version two</main>", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Prototype fingerprint"):
                delivery_graph.compile_graph(root, "cross-domain-feature")
            graph["prototype"]["sha256"] = delivery_graph.file_digest(prototype)
            write_json(graph_path, graph)
            delivery_graph.compile_graph(root, "cross-domain-feature")
            state = delivery_graph.load_state(directory / "state.json")
            current_unit = self.unit_id(graph, "PROVENANCE_INTEGRITY")
            self.assertNotIn(current_unit, state["attestations"])
            self.assertNotEqual(prior["subgraph_sha256"], delivery_graph.review_units(graph)[current_unit]["subgraph_sha256"])

    def test_contract_mutation_breaks_seal(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            path = root / "delivery/cross-domain-feature/proof-contract.json"
            contract = json.loads(path.read_text())
            contract["obligations"][0]["surface"] = "tampered"
            write_json(path, contract)
            errors: list[str] = []
            state = delivery_graph.load_state(path.parent / "state.json")
            graph_contract.validate_contract(root, "cross-domain-feature", contract, state, errors)
            self.assertTrue(any("compiler" in error or "seal" in error for error in errors), errors)

    def test_seal_retry_repairs_state_after_interrupted_state_write(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            original_write = graph_contract.atomic_write_json
            failed = False

            def fail_state_once(path: Path, value: object) -> None:
                nonlocal failed
                if path.name == "state.json" and not failed:
                    failed = True
                    raise OSError("disk full")
                original_write(path, value)

            with patch.object(graph_contract, "atomic_write_json", side_effect=fail_state_once):
                with self.assertRaisesRegex(OSError, "disk full"):
                    graph_contract.seal_contract(root, "cross-domain-feature")
            graph_contract.seal_contract(root, "cross-domain-feature")
            self.assertEqual([], graph_validation.validate(root, "cross-domain-feature"))

    def test_non_object_state_attestations_are_reported_without_crashing(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            delivery_graph.compile_graph(root, "cross-domain-feature")
            state_path = root / "delivery/cross-domain-feature/state.json"
            state = delivery_graph.load_state(state_path)
            state["attestations"] = []
            write_json(state_path, state)
            errors = graph_validation.validate(root, "cross-domain-feature")
            self.assertTrue(any("attestations" in error for error in errors), errors)

    def test_state_contract_reference_tampering_is_rejected(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            state_path = root / "delivery/cross-domain-feature/state.json"
            state = delivery_graph.load_state(state_path)
            state["proof_contract"]["draft_sha256"] = "0" * 64
            state["proof_contract"]["seal"] = "1" * 64
            write_json(state_path, state)
            errors = graph_validation.validate(root, "cross-domain-feature")
            self.assertIn("state Proof Contract reference is stale", errors)

    def test_contract_rejects_relocated_attestation_and_transcript_paths(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            directory = root / "delivery/cross-domain-feature"
            contract = delivery_graph.load_json(directory / "proof-contract.json")
            state = delivery_graph.load_state(directory / "state.json")
            lens = next(iter(contract["attestations"]))

            relocated = copy.deepcopy(contract)
            relocated["attestations"][lens]["record_path"] = "../outside-review.json"
            errors: list[str] = []
            graph_contract.validate_contract(root, "cross-domain-feature", relocated, state, errors)
            self.assertTrue(any("record escapes review directory" in error for error in errors), errors)

            transcript_contract = copy.deepcopy(contract)
            summary = transcript_contract["attestations"][lens]
            record_path = root / summary["record_path"]
            record = delivery_graph.load_json(record_path)
            record["execution"]["transcript_path"] = "../outside-transcript.jsonl"
            write_json(record_path, record)
            summary["record_sha256"] = graph_contract.file_digest(record_path)
            transcript_state = copy.deepcopy(state)
            transcript_state["attestations"][lens] = copy.deepcopy(summary)
            errors = []
            graph_contract.validate_contract(
                root, "cross-domain-feature", transcript_contract, transcript_state, errors,
            )
            self.assertTrue(any("transcript escapes review directory" in error for error in errors), errors)

    def test_malformed_attributes_return_errors_instead_of_crashing(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            graph_path = root / "delivery/cross-domain-feature/delivery-graph.json"
            graph = json.loads(graph_path.read_text())
            next(item for item in graph["nodes"] if item["id"] == "RISK-001")["attributes"] = None
            write_json(graph_path, graph)
            errors = graph_validation.validate(root, "cross-domain-feature")
            self.assertTrue(any("attributes must be an object" in error for error in errors), errors)
        for malformed in (None, {"spec": None}):
            with self.subTest(environment_attributes=malformed):
                temporary, root = self.make_root()
                with temporary:
                    graph_path = root / "delivery/cross-domain-feature/delivery-graph.json"
                    graph = json.loads(graph_path.read_text())
                    next(item for item in graph["nodes"] if item["id"] == "ENV-001")["attributes"] = malformed
                    write_json(graph_path, graph)
                    errors = graph_validation.validate(root, "cross-domain-feature")
                    self.assertTrue(errors)

    def test_hand_edited_generated_view_is_rejected(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            delivery_graph.compile_graph(root, "cross-domain-feature")
            prd = root / "delivery/cross-domain-feature/prd.md"
            prd.write_text(prd.read_text(encoding="utf-8") + "\nmanual override\n", encoding="utf-8")
            errors = graph_validation.validate(root, "cross-domain-feature")
            self.assertIn("generated artifact is missing or stale: prd.md", errors)

    def test_review_record_tampering_invalidates_feature(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            record = next((root / ".dlv/reviews/cross-domain-feature").glob("readiness-01.PROVENANCE_INTEGRITY--*.json"))
            value = json.loads(record.read_text())
            value["verdict"] = "BLOCKED"
            write_json(record, value)
            errors = graph_validation.validate(root, "cross-domain-feature")
            self.assertTrue(any("record is missing or stale" in error for error in errors), errors)

    def test_isolated_semantic_lens_binds_immutable_transcript(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            delivery_graph.compile_graph(root, "cross-domain-feature")

            def fake_run(argv: list[str], *args: object, **kwargs: object) -> dict[str, object]:
                self.assertIn("--skip-git-repo-check", argv)
                self.assertNotEqual(str(root), argv[argv.index("--cd") + 1])
                result_path = Path(argv[argv.index("--output-last-message") + 1])
                write_json(result_path, {
                    "verdict": "PASS",
                    "checks": [{"id": "semantic-consistency", "status": "PASS", "evidence": "REQ-001 → BHV-001 → AC-001 is concrete and consistent"}],
                    "findings": [],
                })
                return {"exit_code": 0, "timed_out": False, "stdout": '{"type":"turn.completed"}\n', "stderr": ""}

            with patch.object(graph_review, "run_bounded", side_effect=fake_run):
                graph_review.run_isolated_readiness_review(root, "cross-domain-feature", "semantic-01")
            state = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            unit_id = self.unit_id(delivery_graph.load_graph(root, "cross-domain-feature"), "PROVENANCE_INTEGRITY")
            record = root / state["attestations"][unit_id]["record_path"]
            payload = json.loads(record.read_text())
            transcript = root / payload["execution"]["transcript_path"]
            self.assertTrue(transcript.is_file())
            transcript.write_text("tampered", encoding="utf-8")
            errors = graph_validation.validate(root, "cross-domain-feature")
            self.assertTrue(any("transcript is missing or stale" in error for error in errors), errors)

    def test_semantic_reviewer_timeout_and_process_failure_are_blocking(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            unit = delivery_graph.review_units(graph)[self.unit_id(graph, "PROVENANCE_INTEGRITY")]
            with patch.object(
                graph_review, "run_bounded",
                return_value={"exit_code": 124, "timed_out": True, "stdout": "", "stderr": "timeout"},
            ):
                with self.assertRaisesRegex(ValueError, "timed out after 900 seconds"):
                    graph_review._run_semantic_unit(
                        root, "cross-domain-feature", graph, unit, "timeout-review",
                    )
            failed = {"exit_code": 7, "timed_out": False, "stdout": "partial output", "stderr": "review failed"}
            with patch.object(graph_review, "run_bounded", return_value=failed):
                with self.assertRaisesRegex(ValueError, "semantic lens PROVENANCE_INTEGRITY failed"):
                    graph_review._run_semantic_unit(
                        root, "cross-domain-feature", graph, unit, "failed-review",
                    )

    def test_open_major_semantic_finding_forces_composite_blocked(self) -> None:
        graph = valid_graph()
        semantic = {
            "verdict": "PASS",
            "checks": [{"id": "meaning", "status": "PASS", "evidence": "IDs exist"}],
            "findings": [{
                "id": "LENS-1", "severity": "major", "status": "open",
                "statement": "Acceptance is semantically ambiguous", "evidence": "AC-001",
            }],
            "execution": {"mode": "isolated_process", "independent": True},
        }
        unit = delivery_graph.review_units(graph)[self.unit_id(graph, "PROVENANCE_INTEGRITY")]
        record = graph_review.evaluate_unit(graph, unit, "semantic-bad", semantic)
        self.assertEqual("BLOCKED", record["verdict"])

    def test_review_transaction_restores_ledger_state_and_records_on_failure(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            delivery_graph.compile_graph(root, "cross-domain-feature")
            ledger_path = root / ".dlv/findings/cross-domain-feature/ledger.json"
            state_path = root / "delivery/cross-domain-feature/state.json"
            before_ledger = ledger_path.read_bytes()
            before_state = state_path.read_bytes()
            original_write = graph_review.atomic_write_json

            def fail_after_state_write(path: Path, value: object) -> None:
                original_write(path, value)
                if path == state_path:
                    raise OSError("injected review state failure")

            with patch.object(graph_review, "atomic_write_json", side_effect=fail_after_state_write):
                with self.assertRaisesRegex(OSError, "injected review state failure"):
                    graph_review.record_readiness(root, "cross-domain-feature", "rollback-review")
            self.assertEqual(before_ledger, ledger_path.read_bytes())
            self.assertEqual(before_state, state_path.read_bytes())
            self.assertEqual([], list((root / ".dlv/reviews/cross-domain-feature").glob("rollback-review.*.json")))

    def test_compile_recovers_interrupted_review_transaction_and_run_id_is_retriable(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            delivery_graph.compile_graph(root, "cross-domain-feature")
            feature_id = "cross-domain-feature"
            run_id = "crash-recovery-review"
            ledger_path = root / f".dlv/findings/{feature_id}/ledger.json"
            state_path = root / f"delivery/{feature_id}/state.json"
            before_ledger = ledger_path.read_bytes()
            before_campaigns = json.loads(before_ledger)["campaigns"]
            before_state = state_path.read_bytes()
            unit_id = next(iter(delivery_graph.review_units(delivery_graph.load_graph(root, feature_id))))
            damaged_ledger = json.loads(before_ledger)
            damaged_ledger["campaigns"].append({
                "run_id": run_id, "recorded_at": "2026-01-01T00:00:00Z", "unit_count": 1, "new_findings": 0,
            })
            record_path = root / f".dlv/reviews/{feature_id}/{run_id}.{unit_id}.json"
            expected_ledger = (json.dumps(damaged_ledger, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
            expected_state = b"{}\n"
            record_content = (json.dumps({"partial": True}, indent=2, sort_keys=True) + "\n").encode()
            journal = delivery_governance.begin_review_transaction(
                root, feature_id, run_id, [unit_id], before_ledger, before_state,
                expected_ledger, expected_state, {unit_id: hashlib.sha256(record_content).hexdigest()}, {},
            )
            ledger_path.write_bytes(expected_ledger)
            state_path.write_bytes(expected_state)
            record_path.write_bytes(record_content)

            delivery_graph.compile_graph(root, feature_id)

            self.assertFalse(journal.exists())
            self.assertFalse(record_path.exists())
            self.assertEqual(before_campaigns, json.loads(ledger_path.read_bytes())["campaigns"])
            paths = graph_review.record_readiness(root, feature_id, run_id)
            self.assertTrue(paths)

    def test_interrupted_review_recovery_preserves_owner_edits_and_fails_closed(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            delivery_graph.compile_graph(root, "cross-domain-feature")
            feature_id = "cross-domain-feature"
            run_id = "owner-edit-review"
            ledger_path = root / f".dlv/findings/{feature_id}/ledger.json"
            state_path = root / f"delivery/{feature_id}/state.json"
            original_ledger = ledger_path.read_bytes()
            original_state = state_path.read_bytes()
            unit_id = next(iter(delivery_graph.review_units(delivery_graph.load_graph(root, feature_id))))
            expected_ledger = original_ledger
            expected_state = original_state
            delivery_governance.begin_review_transaction(
                root, feature_id, run_id, [unit_id], original_ledger, original_state,
                expected_ledger, expected_state, {unit_id: hashlib.sha256(b"expected").hexdigest()}, {},
            )
            owner_state = json.loads(original_state)
            owner_state["execution"] = {"status": "needs_decision", "checkpoint": "owner", "reason": "manual repair"}
            write_json(state_path, owner_state)
            before_owner_state = state_path.read_bytes()
            with self.assertRaisesRegex(ValueError, "preserve Owner edits"):
                delivery_graph.compile_graph(root, feature_id)
            self.assertEqual(before_owner_state, state_path.read_bytes())
            self.assertTrue(delivery_governance.review_transaction_path(root, feature_id).is_file())

    def test_oversized_review_journal_is_rejected_before_reading_payload(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            journal = delivery_governance.review_transaction_path(root, "cross-domain-feature")
            journal.parent.mkdir(parents=True, exist_ok=True)
            with journal.open("wb") as handle:
                handle.truncate(delivery_governance.MAX_REVIEW_JOURNAL_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "bounded regular-file contract"):
                delivery_graph.compile_graph(root, "cross-domain-feature")

    def test_semantic_reviewer_rejects_oversized_result_file(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            unit = delivery_graph.review_units(graph)[self.unit_id(graph, "PROVENANCE_INTEGRITY")]

            def oversized(argv: list[str], *args: object, **kwargs: object) -> dict[str, object]:
                result_path = Path(argv[argv.index("--output-last-message") + 1])
                with result_path.open("wb") as handle:
                    handle.truncate(runtime_evidence.MAX_CAPTURE_BYTES + 1)
                return {"exit_code": 0, "timed_out": False, "stdout": "", "stderr": ""}

            with patch.object(graph_review, "run_bounded", side_effect=oversized):
                with self.assertRaisesRegex(ValueError, "bounded regular-file contract"):
                    graph_review._run_semantic_unit(root, "cross-domain-feature", graph, unit, "oversized-result")

    def test_damaged_review_transaction_fails_closed_before_restoring_state(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            delivery_graph.compile_graph(root, "cross-domain-feature")
            state_path = root / "delivery/cross-domain-feature/state.json"
            before_state = state_path.read_bytes()
            journal = delivery_governance.review_transaction_path(root, "cross-domain-feature")
            journal.parent.mkdir(parents=True, exist_ok=True)
            write_json(journal, {"version": 2, "feature_id": "cross-domain-feature"})
            with self.assertRaisesRegex(ValueError, "pending Review transaction journal is invalid"):
                delivery_graph.compile_graph(root, "cross-domain-feature")
            self.assertEqual(before_state, state_path.read_bytes())

    def test_feature_and_review_path_traversal_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with self.assertRaises(ValueError):
                delivery_graph.feature_dir(root, "../escape")
        graph = valid_graph()
        with self.assertRaisesRegex(ValueError, "review-run-id"):
            graph_review.record_readiness(Path("."), graph["feature_id"], "../escape")
        temporary, root = self.make_root()
        with temporary, patch.object(graph_review, "run_bounded") as run:
            with self.assertRaisesRegex(ValueError, "review-run-id"):
                graph_review.run_isolated_readiness_review(root, "cross-domain-feature", "../escape")
            run.assert_not_called()

    @unittest.skipIf(os.name == "nt", "symlink semantics differ on Windows")
    def test_symlinked_feature_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "delivery").mkdir()
            outside = root / "outside"
            outside.mkdir()
            (root / "delivery/linked-feature").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                delivery_graph.feature_dir(root, "linked-feature")

    @unittest.skipIf(os.name == "nt", "symlink semantics differ on Windows")
    def test_symlinked_machine_directory_is_rejected_before_creation(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            outside = root / "outside-machine-data"
            outside.mkdir()
            (root / ".dlv").rename(root / "prior-machine-data")
            (root / ".dlv").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                delivery_graph.compile_graph(root, "cross-domain-feature")
            self.assertEqual([], list(outside.iterdir()))

    def test_end_to_end_runtime_evidence_and_finalization(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            remove_invariant_obligation_for_boundary_only_test(root)
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, contracted_environment_spec(root))
            destination = graph_verification.start(
                "cross-domain-feature", root, "run-01", [f"ENV-001={environment}"]
            )
            write_json(result, {"po_id": "PO-001", "proof_type": "boundary", "outcome": "evaluate", "anchors": []})
            self.assertEqual("EVID-0001", graph_verification.record("cross-domain-feature", root, "run-01", result, []))
            errors: list[str] = []
            verdict, _ = graph_verification.validate_run(root, "cross-domain-feature", "run-01", errors)
            self.assertEqual(("PASS", []), (verdict, errors))
            graph_finalize.finalize(root, "cross-domain-feature")
            self.assertEqual([], graph_validation.validate(root, "cross-domain-feature", final=True))
            self.assertTrue((destination / "evidence.jsonl").is_file())

    def test_nonzero_runner_cannot_pass_on_valid_stdout_without_exit_contract(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            proof = next(item for item in graph["nodes"] if item["id"] == "PO-001")
            proof["attributes"]["runner"]["argv"] = [
                sys.executable, "-c", "import json,sys; print(json.dumps({'ok': True})); sys.exit(1)",
            ]
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, contracted_environment_spec(root))
            graph_verification.start("cross-domain-feature", root, "run-exit-one", [f"ENV-001={environment}"])
            write_json(result, {"po_id": "PO-001", "proof_type": "boundary", "outcome": "evaluate", "anchors": []})
            graph_verification.record("cross-domain-feature", root, "run-exit-one", result, [])
            record = json.loads((root / ".dlv/runs/cross-domain-feature/run-exit-one/evidence.jsonl").read_text())
            self.assertEqual((1, "failed"), (record["command"]["exit_code"], record["status"]))
            errors: list[str] = []
            verdict, _ = graph_verification.validate_run(root, "cross-domain-feature", "run-exit-one", errors)
            self.assertEqual("BLOCKED", verdict)

    def test_timed_out_runner_cannot_pass_on_stdout_emitted_before_hang(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            proof = next(item for item in graph["nodes"] if item["id"] == "PO-001")
            proof["attributes"]["runner"].update({
                "argv": [
                    sys.executable, "-c",
                    "import json,time; print(json.dumps({'ok': True}), flush=True); time.sleep(2)",
                ],
                "timeout_seconds": 1,
            })
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, contracted_environment_spec(root))
            graph_verification.start("cross-domain-feature", root, "run-timeout", [f"ENV-001={environment}"])
            write_json(result, {"po_id": "PO-001", "proof_type": "boundary", "outcome": "evaluate", "anchors": []})
            graph_verification.record("cross-domain-feature", root, "run-timeout", result, [])
            record = json.loads((root / ".dlv/runs/cross-domain-feature/run-timeout/evidence.jsonl").read_text())
            self.assertEqual((True, "blocked"), (record["command"]["timed_out"], record["status"]))
            errors: list[str] = []
            verdict, _ = graph_verification.validate_run(root, "cross-domain-feature", "run-timeout", errors)
            self.assertEqual("BLOCKED", verdict)

    def test_explicit_nonzero_exit_contract_can_prove_a_negative_path(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            remove_invariant_obligation_for_boundary_only_test(root)
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            proof = next(item for item in graph["nodes"] if item["id"] == "PO-001")
            proof["attributes"]["runner"]["argv"] = [sys.executable, "-c", "raise SystemExit(7)"]
            assertion = next(item for item in graph["nodes"] if item["id"] == "ASRT-001")
            assertion["attributes"]["oracle"] = {
                "kind": "exit_code", "source": "/command/exit_code", "operator": "eq", "expected": 7,
            }
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, contracted_environment_spec(root))
            graph_verification.start("cross-domain-feature", root, "run-exit-contract", [f"ENV-001={environment}"])
            write_json(result, {"po_id": "PO-001", "proof_type": "boundary", "outcome": "evaluate", "anchors": []})
            graph_verification.record("cross-domain-feature", root, "run-exit-contract", result, [])
            errors: list[str] = []
            verdict, _ = graph_verification.validate_run(root, "cross-domain-feature", "run-exit-contract", errors)
            self.assertEqual(("PASS", []), (verdict, errors))

    def test_visual_evidence_is_runner_bound_to_prototype_and_capture_profile(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            profile, paths = self.configure_visual_graph(root)
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, next(item for item in graph["nodes"] if item["id"] == "ENV-001")["attributes"]["spec"])
            graph_verification.start("cross-domain-feature", root, "run-visual", [f"ENV-001={environment}"])
            write_json(result, {"po_id": "PO-001", "proof_type": "visual", "outcome": "evaluate", "anchors": []})
            completed = self.visual_command_result(graph, profile, paths)
            with patch.object(graph_verification, "run_bounded", side_effect=completed):
                self.assertEqual(
                    "EVID-0001",
                    graph_verification.record("cross-domain-feature", root, "run-visual", result, []),
                )
            errors: list[str] = []
            verdict, _ = graph_verification.validate_run(root, "cross-domain-feature", "run-visual", errors)
            self.assertEqual(("PASS", []), (verdict, errors))

    def test_visual_evidence_rejects_caller_labeled_screenshots(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            profile, paths = self.configure_visual_graph(root)
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, next(item for item in graph["nodes"] if item["id"] == "ENV-001")["attributes"]["spec"])
            graph_verification.start("cross-domain-feature", root, "run-visual-caller", [f"ENV-001={environment}"])
            write_json(result, {
                "po_id": "PO-001", "proof_type": "visual", "outcome": "evaluate",
                "anchors": [
                    {"role": "prototype_screenshot", "path": str(paths["implementation_screenshot"])},
                    {"role": "implementation_screenshot", "path": str(paths["implementation_screenshot"])},
                    {"role": "visual_diff", "path": str(paths["visual_diff"])},
                ],
            })
            with patch.object(
                graph_verification, "run_bounded",
                side_effect=self.visual_command_result(graph, profile, paths),
            ), self.assertRaisesRegex(ValueError, "sealed runner observation"):
                graph_verification.record("cross-domain-feature", root, "run-visual-caller", result, [])

    def test_visual_evidence_rejects_wrong_prototype_digest_or_capture_profile(self) -> None:
        for field, value, message in (
            ("prototype_sha256", "f" * 64, "Prototype digest"),
            ("capture_profile", {"viewport": "mobile"}, "capture profile"),
        ):
            with self.subTest(field=field):
                temporary, root = self.make_root()
                with temporary:
                    profile, paths = self.configure_visual_graph(root)
                    graph = delivery_graph.load_graph(root, "cross-domain-feature")
                    self.review_all(root)
                    graph_contract.seal_contract(root, "cross-domain-feature")
                    delivery_graph.mark_code_complete(root, "cross-domain-feature")
                    environment = root / ".dlv/environment.json"
                    result = root / ".dlv/result.json"
                    write_json(environment, next(item for item in graph["nodes"] if item["id"] == "ENV-001")["attributes"]["spec"])
                    graph_verification.start("cross-domain-feature", root, f"run-visual-{field}", [f"ENV-001={environment}"])
                    write_json(result, {"po_id": "PO-001", "proof_type": "visual", "outcome": "evaluate", "anchors": []})
                    with patch.object(
                        graph_verification, "run_bounded",
                        side_effect=self.visual_command_result(graph, profile, paths, **{field: value}),
                    ), self.assertRaisesRegex(ValueError, message):
                        graph_verification.record("cross-domain-feature", root, f"run-visual-{field}", result, [])

    def test_visual_runner_cannot_reuse_one_screenshot_path_for_two_roles(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            profile, paths = self.configure_visual_graph(root)
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, next(item for item in graph["nodes"] if item["id"] == "ENV-001")["attributes"]["spec"])
            graph_verification.start("cross-domain-feature", root, "run-visual-alias", [f"ENV-001={environment}"])
            write_json(result, {"po_id": "PO-001", "proof_type": "visual", "outcome": "evaluate", "anchors": []})
            aliased = dict(paths)
            aliased["prototype_screenshot"] = paths["implementation_screenshot"]
            with patch.object(
                graph_verification, "run_bounded",
                side_effect=self.visual_command_result(graph, profile, aliased),
            ), self.assertRaisesRegex(ValueError, "three distinct anchor paths"):
                graph_verification.record("cross-domain-feature", root, "run-visual-alias", result, [])

    def test_visual_proof_of_unrelated_nodes_does_not_cover_prototype(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            directory = root / "delivery/cross-domain-feature"
            directory.mkdir(parents=True)
            profile, _ = self.configure_visual_graph(root)
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["edges"] = [
                item for item in graph["edges"]
                if not (
                    item["source"] == "PO-001" and item["type"] == "proves"
                    and item["target"] in {"AC-001", "EX-001"}
                )
            ]
            graph["edges"].append(edge("PO-001", "proves", "RISK-001"))
            self.assertTrue(profile)
            codes = {item["code"] for item in delivery_graph.semantic_issues(graph, "RUNTIME_AUTHENTICITY")}
            self.assertIn("PROTOTYPE_VISUAL_PROOF_MISSING", codes)

    def test_interrupted_verification_start_recovers_without_rerunning_preflight(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            environment_node = next(item for item in graph["nodes"] if item["id"] == "ENV-001")
            environment_node["attributes"]["spec"]["preflight"] = [{
                "id": "python-ready", "argv": [sys.executable, "-c", "pass"],
            }]
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            write_json(environment, contracted_environment_spec(root, preflight=[{
                "id": "python-ready", "argv": [sys.executable, "-c", "pass"],
            }]))
            original_write = graph_verification.atomic_write_json
            original_run = graph_verification.run_bounded
            preflight_calls = 0

            def fail_state(path: Path, value: object) -> None:
                if path.name == "state.json":
                    raise OSError("disk full")
                original_write(path, value)

            def count_preflight(*args: object, **kwargs: object) -> dict:
                nonlocal preflight_calls
                preflight_calls += 1
                return original_run(*args, **kwargs)

            with patch.object(graph_verification, "atomic_write_json", side_effect=fail_state), patch.object(graph_verification, "run_bounded", side_effect=count_preflight):
                with self.assertRaisesRegex(OSError, "disk full"):
                    graph_verification.start("cross-domain-feature", root, "run-start-recover", [f"ENV-001={environment}"])
            destination = root / ".dlv/runs/cross-domain-feature/run-start-recover"
            self.assertTrue((destination / "pending-start.json").is_file())
            with patch.object(graph_verification, "run_bounded", side_effect=count_preflight):
                self.assertEqual(
                    destination.resolve(),
                    graph_verification.start("cross-domain-feature", root, "run-start-recover", [f"ENV-001={environment}"]),
                )
            self.assertEqual(1, preflight_calls)
            self.assertFalse((destination / "pending-start.json").exists())

    def test_pending_high_strength_start_rechecks_commit_before_recovery(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            environment_node = next(item for item in graph["nodes"] if item["id"] == "ENV-001")
            preflight = [{"id": "python-ready", "argv": [sys.executable, "-c", "pass"]}]
            environment_node["attributes"]["spec"]["preflight"] = preflight
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            write_json(environment, contracted_environment_spec(root, preflight=preflight))
            original_write = graph_verification.atomic_write_json

            def fail_state(path: Path, value: object) -> None:
                if path.name == "state.json":
                    raise OSError("disk full")
                original_write(path, value)

            passed = {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False}
            with patch.object(
                graph_verification, "formal_head_identity", return_value="a" * 40,
            ), patch.object(
                graph_verification, "atomic_write_json", side_effect=fail_state,
            ), patch.object(graph_verification, "run_bounded", return_value=passed):
                with self.assertRaisesRegex(OSError, "disk full"):
                    graph_verification.start(
                        "cross-domain-feature", root, "run-stale-commit", [f"ENV-001={environment}"],
                    )
            with patch.object(
                graph_verification, "formal_head_identity", return_value="b" * 40,
            ), patch.object(graph_verification, "run_bounded") as preflight_runner:
                with self.assertRaisesRegex(ValueError, "pending Verification start does not match"):
                    graph_verification.start(
                        "cross-domain-feature", root, "run-stale-commit", [f"ENV-001={environment}"],
                    )
                preflight_runner.assert_not_called()

    def test_ineligible_high_strength_commit_blocks_before_preflight_side_effects(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            environment_node = next(item for item in graph["nodes"] if item["id"] == "ENV-001")
            preflight = [{"id": "must-not-run", "argv": [sys.executable, "-c", "pass"]}]
            environment_node["attributes"]["spec"]["preflight"] = preflight
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            subprocess.run(
                ["git", "-c", "user.name=DLV Test", "-c", "user.email=dlv@example.invalid", "commit", "--allow-empty", "-qm", "no trailer"],
                cwd=root, check=True,
            )
            environment = root / ".dlv/environment.json"
            write_json(environment, contracted_environment_spec(root, preflight=preflight))
            with patch.object(graph_verification, "run_bounded") as preflight_runner:
                with self.assertRaisesRegex(ValueError, "HEAD commit.*DLV-Feature trailer"):
                    graph_verification.start(
                        "cross-domain-feature", root, "run-ineligible-preflight", [f"ENV-001={environment}"],
                    )
            preflight_runner.assert_not_called()

    def test_interrupted_start_rejects_a_different_environment_request_without_rerun(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            environment_node = next(item for item in graph["nodes"] if item["id"] == "ENV-001")
            preflight = [{"id": "python-ready", "argv": [sys.executable, "-c", "pass"]}]
            environment_node["attributes"]["spec"]["preflight"] = preflight
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            first = root / ".dlv/environment-first.json"
            second = root / ".dlv/environment-second.json"
            write_json(first, contracted_environment_spec(root, preflight=preflight))
            write_json(second, contracted_environment_spec(root, preflight=preflight))
            original_write = graph_verification.atomic_write_json
            original_run = graph_verification.run_bounded
            preflight_calls = 0

            def fail_state(path: Path, value: object) -> None:
                if path.name == "state.json":
                    raise OSError("disk full")
                original_write(path, value)

            def count_preflight(*args: object, **kwargs: object) -> dict:
                nonlocal preflight_calls
                preflight_calls += 1
                return original_run(*args, **kwargs)

            with patch.object(graph_verification, "atomic_write_json", side_effect=fail_state), patch.object(graph_verification, "run_bounded", side_effect=count_preflight):
                with self.assertRaisesRegex(OSError, "disk full"):
                    graph_verification.start(
                        "cross-domain-feature", root, "run-request-drift", [f"ENV-001={first}"],
                    )
            with patch.object(graph_verification, "run_bounded", side_effect=count_preflight):
                with self.assertRaisesRegex(ValueError, "does not match the requested run"):
                    graph_verification.start(
                        "cross-domain-feature", root, "run-request-drift", [f"ENV-001={second}"],
                    )
            self.assertEqual(1, preflight_calls)
            self.assertTrue((root / ".dlv/runs/cross-domain-feature/run-request-drift/pending-start.json").is_file())

    def test_pending_start_recovery_rejects_divergent_metadata_evidence_and_anchor(self) -> None:
        for corruption in ("metadata", "evidence", "anchor"):
            with self.subTest(corruption=corruption):
                temporary, root = self.make_root()
                with temporary:
                    graph = delivery_graph.load_graph(root, "cross-domain-feature")
                    environment_node = next(item for item in graph["nodes"] if item["id"] == "ENV-001")
                    preflight = [{"id": "python-ready", "argv": [sys.executable, "-c", "pass"]}]
                    environment_node["attributes"]["spec"]["preflight"] = preflight
                    write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
                    self.review_all(root)
                    graph_contract.seal_contract(root, "cross-domain-feature")
                    delivery_graph.mark_code_complete(root, "cross-domain-feature")
                    environment = root / ".dlv/environment.json"
                    write_json(environment, contracted_environment_spec(root, preflight=preflight))
                    original_write = graph_verification.atomic_write_json

                    def fail_state(path: Path, value: object) -> None:
                        if path.name == "state.json":
                            raise OSError("disk full")
                        original_write(path, value)

                    run_id = f"run-corrupt-{corruption}"
                    with patch.object(graph_verification, "atomic_write_json", side_effect=fail_state):
                        with self.assertRaisesRegex(OSError, "disk full"):
                            graph_verification.start(
                                "cross-domain-feature", root, run_id, [f"ENV-001={environment}"],
                            )
                    destination = root / f".dlv/runs/cross-domain-feature/{run_id}"
                    if corruption == "metadata":
                        metadata = delivery_graph.load_json(destination / "run.json")
                        metadata["started_at"] = "changed"
                        write_json(destination / "run.json", metadata)
                        expected = "metadata is divergent"
                    elif corruption == "evidence":
                        (destination / "evidence.jsonl").write_text("{}\n", encoding="utf-8")
                        expected = "evidence is not empty"
                    else:
                        anchor = next((destination / "preflight").iterdir())
                        anchor.write_text("changed\n", encoding="utf-8")
                        expected = "preflight anchor is divergent"
                    with self.assertRaisesRegex(ValueError, expected):
                        graph_verification.start(
                            "cross-domain-feature", root, run_id, [f"ENV-001={environment}"],
                        )

    def test_environment_arguments_and_snapshot_drift_fail_before_run_creation(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate environment input"):
            graph_verification.parse_environment_args([
                "ENV-001=/tmp/one.json", "ENV-001=/tmp/two.json",
            ])
        with self.assertRaisesRegex(ValueError, "must use ENV-001"):
            graph_verification.parse_environment_args(["malformed"])

        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/wrong-environment.json"
            write_json(environment, {"runtime": "browser", "preflight": []})
            with self.assertRaisesRegex(ValueError, "does not match its contracted structured spec"):
                graph_verification.start(
                    "cross-domain-feature", root, "run-environment-drift", [f"ENV-001={environment}"],
                )
            self.assertFalse((root / ".dlv/runs/cross-domain-feature/run-environment-drift").exists())

    def test_early_verification_start_write_failure_cleans_run_for_retry(self) -> None:
        for failure_point in ("preflight", "run.json"):
            with self.subTest(failure_point=failure_point):
                temporary, root = self.make_root()
                with temporary:
                    graph = delivery_graph.load_graph(root, "cross-domain-feature")
                    environment_node = next(item for item in graph["nodes"] if item["id"] == "ENV-001")
                    environment_node["attributes"]["spec"]["preflight"] = [{
                        "id": "python-ready", "argv": [sys.executable, "-c", "pass"],
                    }]
                    write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
                    self.review_all(root)
                    graph_contract.seal_contract(root, "cross-domain-feature")
                    delivery_graph.mark_code_complete(root, "cross-domain-feature")
                    environment = root / ".dlv/environment.json"
                    write_json(environment, contracted_environment_spec(root, preflight=[{
                        "id": "python-ready", "argv": [sys.executable, "-c", "pass"],
                    }]))
                    original_write = graph_verification.atomic_write_json
                    failed = False

                    def fail_once(path: Path, value: object) -> None:
                        nonlocal failed
                        matches = path.parent.name == "preflight" if failure_point == "preflight" else path.name == "run.json"
                        if matches and not failed:
                            failed = True
                            raise OSError("disk full")
                        original_write(path, value)

                    with patch.object(graph_verification, "atomic_write_json", side_effect=fail_once):
                        with self.assertRaisesRegex(OSError, "disk full"):
                            graph_verification.start("cross-domain-feature", root, "run-early-failure", [f"ENV-001={environment}"])
                    destination = root / ".dlv/runs/cross-domain-feature/run-early-failure"
                    self.assertFalse(destination.exists())
                    self.assertEqual(
                        destination.resolve(),
                        graph_verification.start("cross-domain-feature", root, "run-early-failure", [f"ENV-001={environment}"]),
                    )

    def test_validator_reports_non_string_active_run_without_traceback(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            delivery_graph.compile_graph(root, "cross-domain-feature")
            state_path = root / "delivery/cross-domain-feature/state.json"
            state = delivery_graph.load_state(state_path)
            state["verification"] = {
                "status": "in_progress", "active_run_id": 1, "run_digest": None,
                "verdict": None, "evidence_count": 0, "evidence_head": "0" * 64,
                "finalization": None,
            }
            write_json(state_path, state)
            errors = graph_validation.validate(root, "cross-domain-feature")
            self.assertTrue(any("active_run_id" in error for error in errors), errors)

    def test_validator_rejects_malformed_verification_fields_and_state_combinations(self) -> None:
        cases = (
            ({"status": "pending", "active_run_id": None, "run_digest": 1, "verdict": None,
              "evidence_count": 0, "evidence_head": "0" * 64, "finalization": None}, "run_digest"),
            ({"status": "pending", "active_run_id": None, "run_digest": None, "verdict": "MAYBE",
              "evidence_count": 0, "evidence_head": "0" * 64, "finalization": None}, "verdict"),
            ({"status": "pending", "active_run_id": None, "run_digest": None, "verdict": None,
              "evidence_count": True, "evidence_head": "0" * 64, "finalization": None}, "evidence_count"),
            ({"status": "in_progress", "active_run_id": "run-1", "run_digest": None, "verdict": None,
              "evidence_count": 0, "evidence_head": "bad", "finalization": None}, "evidence_head"),
            ({"status": "completed", "active_run_id": "run-1", "run_digest": None, "verdict": None,
              "evidence_count": 0, "evidence_head": "0" * 64, "finalization": None}, "completed Verification"),
        )
        for verification, expected in cases:
            with self.subTest(expected=expected):
                temporary, root = self.make_root()
                with temporary:
                    delivery_graph.compile_graph(root, "cross-domain-feature")
                    state_path = root / "delivery/cross-domain-feature/state.json"
                    state = delivery_graph.load_state(state_path)
                    state["verification"] = verification
                    write_json(state_path, state)
                    errors = graph_validation.validate(root, "cross-domain-feature")
                    self.assertTrue(any(expected in error for error in errors), errors)

    def test_evidence_transaction_recovers_without_duplicate_append(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, contracted_environment_spec(root))
            destination = graph_verification.start("cross-domain-feature", root, "run-recover", [f"ENV-001={environment}"])
            write_json(result, {"po_id": "PO-001", "proof_type": "boundary", "outcome": "evaluate", "anchors": []})
            original_write = graph_verification.atomic_write_json

            def fail_state(path: Path, value: object) -> None:
                if path.name == "state.json":
                    raise OSError("disk full")
                original_write(path, value)

            with patch.object(graph_verification, "atomic_write_json", side_effect=fail_state):
                with self.assertRaisesRegex(OSError, "disk full"):
                    graph_verification.record("cross-domain-feature", root, "run-recover", result, [])
            self.assertTrue((destination / "pending-record.json").is_file())
            self.assertEqual("EVID-0001", graph_verification.record("cross-domain-feature", root, "run-recover", result, []))
            self.assertFalse((destination / "pending-record.json").exists())
            self.assertFalse((destination / "pending-execution.json").exists())
            self.assertEqual(1, len((destination / "evidence.jsonl").read_text().splitlines()))

    def test_render_failure_keeps_wal_and_retry_does_not_rerun_runner(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, contracted_environment_spec(root))
            destination = graph_verification.start("cross-domain-feature", root, "run-render-recover", [f"ENV-001={environment}"])
            write_json(result, {"po_id": "PO-001", "proof_type": "boundary", "outcome": "evaluate", "anchors": []})
            original_render = graph_verification.render
            render_calls = 0
            runner_calls = 0
            original_runner = graph_verification.run_bounded

            def fail_render_once(*args: object, **kwargs: object) -> Path:
                nonlocal render_calls
                render_calls += 1
                if render_calls == 1:
                    raise OSError("report disk full")
                return original_render(*args, **kwargs)

            def count_runner(*args: object, **kwargs: object) -> dict:
                nonlocal runner_calls
                runner_calls += 1
                return original_runner(*args, **kwargs)

            with patch.object(graph_verification, "render", side_effect=fail_render_once), patch.object(graph_verification, "run_bounded", side_effect=count_runner):
                with self.assertRaisesRegex(OSError, "report disk full"):
                    graph_verification.record("cross-domain-feature", root, "run-render-recover", result, [])
                self.assertTrue((destination / "pending-record.json").is_file())
                self.assertEqual("EVID-0001", graph_verification.record("cross-domain-feature", root, "run-render-recover", result, []))
            self.assertEqual(1, runner_calls)
            self.assertEqual(1, len((destination / "evidence.jsonl").read_text().splitlines()))
            self.assertFalse((destination / "pending-record.json").exists())
            self.assertFalse((destination / "pending-execution.json").exists())

    def test_failed_record_journal_never_executes_runner_twice(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, contracted_environment_spec(root))
            destination = graph_verification.start(
                "cross-domain-feature", root, "run-ambiguous", [f"ENV-001={environment}"],
            )
            write_json(result, {
                "po_id": "PO-001", "proof_type": "boundary",
                "outcome": "evaluate", "anchors": [],
            })
            original_write = graph_verification.atomic_write_json
            original_runner = graph_verification.run_bounded
            runner_calls = 0

            def fail_record_journal(path: Path, value: object) -> None:
                if path.name == "pending-record.json":
                    raise OSError("disk full")
                original_write(path, value)

            def count_runner(*args: object, **kwargs: object) -> dict:
                nonlocal runner_calls
                runner_calls += 1
                return original_runner(*args, **kwargs)

            with patch.object(
                graph_verification, "atomic_write_json", side_effect=fail_record_journal,
            ), patch.object(graph_verification, "run_bounded", side_effect=count_runner):
                with self.assertRaisesRegex(OSError, "disk full"):
                    graph_verification.record(
                        "cross-domain-feature", root, "run-ambiguous", result, [],
                    )
            self.assertTrue((destination / "pending-execution.json").is_file())
            with patch.object(graph_verification, "run_bounded", side_effect=count_runner):
                with self.assertRaisesRegex(ValueError, "outcome is ambiguous"):
                    graph_verification.record(
                        "cross-domain-feature", root, "run-ambiguous", result, [],
                    )
            self.assertEqual(1, runner_calls)
            errors: list[str] = []
            verdict, _ = graph_verification.validate_run(
                root, "cross-domain-feature", "run-ambiguous", errors,
            )
            self.assertEqual("BLOCKED", verdict)
            self.assertTrue(any("ambiguous sealed runner execution" in error for error in errors), errors)

    def test_prelaunch_sandbox_failure_clears_execution_marker_for_retry(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, contracted_environment_spec(root))
            destination = graph_verification.start(
                "cross-domain-feature", root, "run-prelaunch-failure", [f"ENV-001={environment}"],
            )
            write_json(result, {
                "po_id": "PO-001", "proof_type": "boundary", "outcome": "evaluate", "anchors": [],
            })
            with patch.object(
                graph_verification, "run_bounded", side_effect=ValueError("OS sandbox unavailable"),
            ), self.assertRaisesRegex(ValueError, "OS sandbox unavailable"):
                graph_verification.record(
                    "cross-domain-feature", root, "run-prelaunch-failure", result, [],
                )
            self.assertFalse((destination / "pending-execution.json").exists())

    def test_finalizer_clears_execution_marker_covered_by_durable_record(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            remove_invariant_obligation_for_boundary_only_test(root)
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, contracted_environment_spec(root))
            destination = graph_verification.start(
                "cross-domain-feature", root, "run-dual-journal", [f"ENV-001={environment}"],
            )
            write_json(result, {
                "po_id": "PO-001", "proof_type": "boundary",
                "outcome": "evaluate", "anchors": [],
            })
            original_unlink = Path.unlink

            def interrupt_execution_unlink(path: Path, *args: object, **kwargs: object) -> None:
                if path.name == "pending-execution.json":
                    raise OSError("interrupted before execution marker cleanup")
                original_unlink(path, *args, **kwargs)

            with patch.object(Path, "unlink", interrupt_execution_unlink):
                with self.assertRaisesRegex(OSError, "interrupted"):
                    graph_verification.record(
                        "cross-domain-feature", root, "run-dual-journal", result, [],
                    )
            self.assertTrue((destination / "pending-record.json").is_file())
            self.assertTrue((destination / "pending-execution.json").is_file())
            graph_finalize.finalize(root, "cross-domain-feature")
            state = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            self.assertEqual(("completed", "PASS"), (
                state["verification"]["status"], state["verification"]["verdict"],
            ))
            self.assertFalse((destination / "pending-record.json").exists())
            self.assertFalse((destination / "pending-execution.json").exists())

    def test_damaged_pending_record_is_rejected_before_recovery_mutation(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, contracted_environment_spec(root))
            destination = graph_verification.start("cross-domain-feature", root, "run-damaged-wal", [f"ENV-001={environment}"])
            write_json(result, {"po_id": "PO-001", "proof_type": "boundary", "outcome": "evaluate", "anchors": []})
            original_write = graph_verification.atomic_write_json

            def fail_state(path: Path, value: object) -> None:
                if path.name == "state.json":
                    raise OSError("disk full")
                original_write(path, value)

            with patch.object(graph_verification, "atomic_write_json", side_effect=fail_state):
                with self.assertRaisesRegex(OSError, "disk full"):
                    graph_verification.record("cross-domain-feature", root, "run-damaged-wal", result, [])
            journal_path = destination / "pending-record.json"
            journal = json.loads(journal_path.read_text())
            journal["record"].pop("record_hash")
            write_json(journal_path, journal)
            before_manifest = (destination / "evidence.jsonl").read_bytes()
            before_state = (root / "delivery/cross-domain-feature/state.json").read_bytes()
            with self.assertRaisesRegex(ValueError, "pending evidence record is invalid"):
                graph_verification.recover_pending_transaction(root, "cross-domain-feature", "run-damaged-wal")
            self.assertEqual(before_manifest, (destination / "evidence.jsonl").read_bytes())
            self.assertEqual(before_state, (root / "delivery/cross-domain-feature/state.json").read_bytes())
            self.assertTrue(journal_path.exists())

    def test_failed_finalization_preserves_recovered_evidence_transaction(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, contracted_environment_spec(root))
            destination = graph_verification.start("cross-domain-feature", root, "run-finalize-recover", [f"ENV-001={environment}"])
            write_json(result, {"po_id": "PO-001", "proof_type": "boundary", "outcome": "evaluate", "anchors": []})
            original_write = graph_verification.atomic_write_json

            def fail_state(path: Path, value: object) -> None:
                if path.name == "state.json":
                    raise OSError("disk full")
                original_write(path, value)

            with patch.object(graph_verification, "atomic_write_json", side_effect=fail_state):
                with self.assertRaisesRegex(OSError, "disk full"):
                    graph_verification.record("cross-domain-feature", root, "run-finalize-recover", result, [])
            with patch.object(graph_finalize, "validate_run", side_effect=ValueError("forced finalization failure")):
                with self.assertRaisesRegex(ValueError, "forced finalization failure"):
                    graph_finalize.finalize(root, "cross-domain-feature")
            state = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            self.assertEqual(1, state["verification"]["evidence_count"])
            self.assertEqual(1, len((destination / "evidence.jsonl").read_text().splitlines()))
            self.assertFalse((destination / "pending-record.json").exists())

    def test_preflight_id_cannot_escape_run_directory(self) -> None:
        graph = valid_graph()
        environment_node = next(item for item in graph["nodes"] if item["id"] == "ENV-001")
        environment_node["attributes"]["spec"]["preflight"] = [{"id": "../../escape", "argv": ["true"]}]
        issues = delivery_graph.semantic_issues(graph, "RUNTIME_AUTHENTICITY")
        self.assertTrue(any(item["code"] == "ENVIRONMENT_PREFLIGHT_INVALID" for item in issues), issues)

    def test_timeout_policy_rejects_bool_and_unbounded_values(self) -> None:
        for timeout in (True, delivery_graph.MAX_COMMAND_TIMEOUT_SECONDS + 1, 10**100):
            with self.subTest(timeout=timeout):
                graph = valid_graph()
                proof = next(item for item in graph["nodes"] if item["id"] == "PO-001")
                proof["attributes"]["runner"]["timeout_seconds"] = timeout
                issues = delivery_graph.semantic_issues(graph, "RUNTIME_AUTHENTICITY")
                self.assertTrue(any(item["code"] == "PROOF_RUNNER_LIMIT_INVALID" for item in issues), issues)

    def test_all_oracle_operators_and_missing_are_distinct_from_null(self) -> None:
        cases = [
            (3, {"operator": "ne", "expected": 4}),
            (["a", "b"], {"operator": "contains", "expected": "b"}),
            (["a"], {"operator": "not_contains", "expected": "b"}),
            ("abc-123", {"operator": "matches", "expected": r"^abc-\d+$"}),
            (4, {"operator": "lte", "expected": 4}),
            (4, {"operator": "gte", "expected": 4}),
            (None, {"operator": "exists", "expected": None}),
            (delivery_proof.MISSING, {"operator": "absent", "expected": None}),
        ]
        for actual, oracle in cases:
            with self.subTest(actual=actual, oracle=oracle):
                self.assertTrue(delivery_proof.evaluate_oracle(actual, oracle))
        document = {"observation": {"explicit_null": None}}
        self.assertIsNone(delivery_proof.resolve_source(document, "/observation/explicit_null"))
        self.assertIs(delivery_proof.MISSING, delivery_proof.resolve_source(document, "/observation/missing"))
        self.assertFalse(delivery_proof.evaluate_oracle(None, {"operator": "absent", "expected": None}))

    def test_bounded_runner_redacts_secrets_and_caps_output(self) -> None:
        command = [
            sys.executable, "-c",
            "print('token=super-secret'); print('x' * 1100000)",
        ]
        result = runtime_evidence.run_bounded(command, Path.cwd(), 10)
        self.assertEqual(0, result["exit_code"])
        self.assertNotIn("super-secret", result["stdout"])
        self.assertIn("token=[REDACTED]", result["stdout"])
        self.assertIn(f"[TRUNCATED at {runtime_evidence.MAX_CAPTURE_BYTES} bytes]", result["stdout"])

    def test_bounded_runner_timeout_includes_blocked_stdin_write(self) -> None:
        started = time.monotonic()
        result = runtime_evidence.run_bounded(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            Path.cwd(), 1, input_text="x" * runtime_evidence.MAX_CAPTURE_BYTES,
        )
        self.assertTrue(result["timed_out"], result)
        self.assertLess(time.monotonic() - started, 5)

    def test_non_macos_runtime_does_not_require_unix_resource_module(self) -> None:
        if sys.platform != "darwin":
            self.assertIsNone(runtime_evidence.resource)

    def test_linux_sandbox_binds_non_home_cwd_after_private_tmp(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            cwd = Path(raw).resolve()
            with patch.object(runtime_evidence.sys, "platform", "linux"), patch.object(
                runtime_evidence, "trusted_sandbox_executable", return_value=Path("/usr/bin/bwrap"),
            ):
                argv = runtime_evidence.sandboxed_argv(["tool", "arg"], cwd)
            tmpfs_index = argv.index("/tmp")
            cwd_indices = [index for index, value in enumerate(argv) if value == str(cwd)]
            self.assertEqual(2, len(cwd_indices))
            self.assertGreater(cwd_indices[0], tmpfs_index)
            self.assertEqual(["--bind", str(cwd), str(cwd)], argv[cwd_indices[0] - 1:cwd_indices[1] + 1])
            self.assertIn("--unshare-net", argv)
            run_index = argv.index("/run")
            self.assertEqual("--tmpfs", argv[run_index - 1])

    def test_linux_sandbox_hides_read_protected_root_after_home_mount(self) -> None:
        protected = (Path.home() / "workspace/protected-review-root").resolve()
        with patch.object(runtime_evidence.sys, "platform", "linux"), patch.object(
            runtime_evidence, "trusted_sandbox_executable", return_value=Path("/usr/bin/bwrap"),
        ):
            argv = runtime_evidence.sandboxed_argv(
                ["tool"], Path.cwd(), read_protected=[protected],
            )
        home_indices = [index for index, value in enumerate(argv) if value == str(Path.home().resolve())]
        protected_index = argv.index(str(protected))
        self.assertEqual(2, len(home_indices))
        self.assertGreater(protected_index, home_indices[-1])
        self.assertEqual("--tmpfs", argv[protected_index - 1])

    def test_linux_semantic_review_mode_keeps_runtime_sockets_hidden_but_allows_outbound_network(self) -> None:
        with patch.object(runtime_evidence.sys, "platform", "linux"), patch.object(
            runtime_evidence, "trusted_sandbox_executable", return_value=Path("/usr/bin/bwrap"),
        ):
            argv = runtime_evidence.sandboxed_argv(
                ["codex", "exec"], Path.cwd(), allow_outbound_process_tree=True,
            )
        self.assertNotIn("--unshare-net", argv)
        run_index = argv.index("/run")
        self.assertEqual("--tmpfs", argv[run_index - 1])

    def test_repository_path_cannot_shadow_the_os_sandbox_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fake = Path(raw) / "bwrap"
            fake.write_text("#!/bin/sh\nexec \"$@\"\n", encoding="utf-8")
            fake.chmod(0o755)
            with patch.object(runtime_evidence.shutil, "which", return_value=str(fake)):
                with self.assertRaisesRegex(ValueError, "untrusted OS sandbox executable"):
                    runtime_evidence.trusted_sandbox_executable("bwrap")

    @unittest.skipUnless(sys.platform.startswith("linux") and runtime_evidence.shutil.which("bwrap"), "Linux bwrap required")
    def test_linux_sandbox_can_write_non_home_workspace(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as raw:
            cwd = Path(raw).resolve()
            result = runtime_evidence.run_bounded(
                [sys.executable, "-c", "from pathlib import Path; Path('written').write_text('ok')"], cwd, 10,
            )
            self.assertEqual(0, result["exit_code"], result)
            self.assertEqual("ok", (cwd / "written").read_text())

    @unittest.skipIf(os.name == "nt" or sys.platform == "darwin", "Linux process-tree cleanup semantics required")
    def test_bounded_runner_timeout_terminates_descendant_process(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            pid_file = root / "child.pid"
            command = [
                sys.executable, "-c",
                (
                    "import subprocess,sys,time; "
                    "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
                    "open(sys.argv[1],'w').write(str(p.pid)); time.sleep(60)"
                ),
                str(pid_file),
            ]
            result = runtime_evidence.run_bounded(command, root, 1)
            self.assertTrue(result["timed_out"])
            child_pid = int(pid_file.read_text(encoding="utf-8"))
            state = ""
            for _ in range(20):
                completed = subprocess.run(
                    ["ps", "-p", str(child_pid), "-o", "stat="],
                    capture_output=True, text=True,
                )
                state = completed.stdout.strip()
                if not state or state.startswith("Z"):
                    break
                time.sleep(0.05)
            self.assertTrue(not state or state.startswith("Z"), f"descendant still running with state {state}")

    @unittest.skipUnless(sys.platform == "darwin" and runtime_evidence.shutil.which("sandbox-exec"), "macOS sandbox-exec required")
    def test_macos_low_strength_runner_allows_normal_subprocess_tree(self) -> None:
        command = [
            sys.executable, "-c",
            "import subprocess,sys; subprocess.run([sys.executable,'-c','print(42)'],check=True)",
        ]
        result = runtime_evidence.run_bounded(command, Path.cwd(), 10)
        self.assertEqual(0, result["exit_code"], result)
        self.assertIn("42", result["stdout"])

    def test_macos_low_strength_policy_allows_fork_but_high_strength_can_deny_it(self) -> None:
        with patch.object(runtime_evidence.sys, "platform", "darwin"), patch.object(
            runtime_evidence, "trusted_sandbox_executable", return_value=Path("/usr/bin/sandbox-exec"),
        ):
            ordinary = runtime_evidence.sandboxed_argv(["tool"], Path.cwd())
            high_strength = runtime_evidence.sandboxed_argv(
                ["tool"], Path.cwd(), deny_process_fork=True,
            )
        self.assertNotIn("deny process-fork", ordinary[2])
        self.assertIn("deny process-fork", high_strength[2])

    def test_macos_process_tree_profile_allows_only_the_declared_unix_socket(self) -> None:
        docker_socket = Path("/tmp/dlv-test-docker.sock")
        with patch.object(runtime_evidence.sys, "platform", "darwin"), patch.object(
            runtime_evidence, "trusted_sandbox_executable", return_value=Path("/usr/bin/sandbox-exec"),
        ):
            argv = runtime_evidence.sandboxed_argv(
                ["docker", "run"], Path.cwd(), allow_process_tree=True,
                writable_roots=[Path.cwd()], allowed_unix_sockets=[docker_socket],
            )
        self.assertIn("allow network-outbound", argv[2])
        self.assertIn(str(docker_socket), argv[2])
        self.assertNotIn("network*", argv[2])

    def test_macos_semantic_review_profile_allows_outbound_only(self) -> None:
        with patch.object(runtime_evidence.sys, "platform", "darwin"), patch.object(
            runtime_evidence, "trusted_sandbox_executable", return_value=Path("/usr/bin/sandbox-exec"),
        ):
            argv = runtime_evidence.sandboxed_argv(
                ["codex", "exec"], Path.cwd(), allow_outbound_process_tree=True,
                writable_roots=[Path.cwd()],
            )
        self.assertIn('(allow default)', argv[2])
        self.assertIn('(deny network-inbound)', argv[2])
        self.assertNotIn('(deny process-fork)', argv[2])

    def test_semantic_review_copies_only_private_codex_bootstrap_files(self) -> None:
        with tempfile.TemporaryDirectory() as source_raw, tempfile.TemporaryDirectory() as target_raw:
            source = Path(source_raw)
            auth = source / "auth.json"
            auth.write_text("{}\n", encoding="utf-8")
            auth.chmod(0o600)
            config = source / "config.toml"
            config.write_text(
                'model = "test"\n[model_providers.test]\nname = "test"\n'
                '[mcp_servers.untrusted]\nurl = "https://example.invalid"\n[plugins."x"]\nenabled = true\n',
                encoding="utf-8",
            )
            config.chmod(0o600)
            (source / "state_5.sqlite").write_text("must-not-copy", encoding="utf-8")
            with patch.dict(os.environ, {"CODEX_HOME": str(source)}):
                isolated, original = graph_review.prepare_isolated_codex_home(Path(target_raw))
            self.assertEqual(source.resolve(), original)
            self.assertEqual({"auth.json", "config.toml"}, {path.name for path in isolated.iterdir()})
            self.assertTrue(all(path.stat().st_mode & 0o077 == 0 for path in isolated.iterdir()))
            sanitized = (isolated / "config.toml").read_text(encoding="utf-8")
            self.assertIn("model_providers.test", sanitized)
            self.assertNotIn("mcp_servers", sanitized)
            self.assertNotIn("plugins", sanitized)

    @unittest.skipUnless(sys.platform == "darwin" and runtime_evidence.shutil.which("sandbox-exec"), "macOS sandbox-exec required")
    def test_macos_isolated_process_tree_cannot_mutate_protected_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as protected_raw, tempfile.TemporaryDirectory() as isolated_raw:
            protected = Path(protected_raw)
            isolated = Path(isolated_raw)
            marker = protected / "detached"
            child = f"import time; from pathlib import Path; time.sleep(0.5); Path({str(marker)!r}).write_text('escaped')"
            command = [
                sys.executable, "-c",
                (
                    "import os,subprocess,sys; environment=dict(os.environ); "
                    "environment.pop('DLV_PROCESS_SUPERVISION',None); "
                    "subprocess.Popen([sys.executable,'-c',sys.argv[1]], start_new_session=True,env=environment)"
                ),
                child,
            ]
            result = runtime_evidence.run_bounded(
                command, isolated, 10, allow_process_tree=True,
                writable_roots=[isolated], read_protected=[protected],
            )
            self.assertEqual(0, result["exit_code"], result)
            time.sleep(0.6)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(sys.platform == "darwin" and runtime_evidence.shutil.which("sandbox-exec"), "macOS sandbox-exec required")
    def test_macos_semantic_snapshot_cannot_read_protected_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as protected_raw, tempfile.TemporaryDirectory() as isolated_raw:
            protected = Path(protected_raw).resolve()
            isolated = Path(isolated_raw).resolve()
            secret = protected / "ledger-secret"
            secret.write_text("REAL_REPO_SECRET", encoding="utf-8")
            result = runtime_evidence.run_bounded(
                [sys.executable, "-c", "import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())", str(secret)],
                isolated, 10, allow_process_tree=True,
                writable_roots=[isolated], read_protected=[protected],
            )
            self.assertNotEqual(0, result["exit_code"], result)
            self.assertNotIn("REAL_REPO_SECRET", result["stdout"] + result["stderr"])

    def test_validator_recomputes_assertions_even_if_hash_chain_and_state_are_rewritten(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, contracted_environment_spec(root))
            destination = graph_verification.start("cross-domain-feature", root, "run-tamper", [f"ENV-001={environment}"])
            write_json(result, {"po_id": "PO-001", "proof_type": "boundary", "outcome": "evaluate", "anchors": []})
            graph_verification.record("cross-domain-feature", root, "run-tamper", result, [])
            manifest = destination / "evidence.jsonl"
            record = json.loads(manifest.read_text())
            record["assertion_results"][0]["actual"] = False
            payload = {key: value for key, value in record.items() if key != "record_hash"}
            record["record_hash"] = delivery_graph.value_digest(payload)
            manifest.write_text(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            state_path = root / "delivery/cross-domain-feature/state.json"
            state = delivery_graph.load_state(state_path)
            state["verification"]["evidence_head"] = record["record_hash"]
            write_json(state_path, state)
            errors: list[str] = []
            verdict, _ = graph_verification.validate_run(root, "cross-domain-feature", "run-tamper", errors)
            self.assertEqual("BLOCKED", verdict)
            self.assertTrue(any("assertion results are not reproducible" in error for error in errors), errors)

    def test_validator_rejects_unknown_evidence_fields_even_with_rehashed_chain(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, contracted_environment_spec(root))
            destination = graph_verification.start("cross-domain-feature", root, "run-unknown-field", [f"ENV-001={environment}"])
            write_json(result, {"po_id": "PO-001", "proof_type": "boundary", "outcome": "evaluate", "anchors": []})
            graph_verification.record("cross-domain-feature", root, "run-unknown-field", result, [])
            manifest = destination / "evidence.jsonl"
            record = json.loads(manifest.read_text())
            record["caller_verdict"] = "PASS"
            record["record_hash"] = delivery_graph.value_digest({key: value for key, value in record.items() if key != "record_hash"})
            manifest.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            state_path = root / "delivery/cross-domain-feature/state.json"
            state = delivery_graph.load_state(state_path)
            state["verification"]["evidence_head"] = record["record_hash"]
            write_json(state_path, state)
            errors: list[str] = []
            verdict, _ = graph_verification.validate_run(root, "cross-domain-feature", "run-unknown-field", errors)
            self.assertEqual("BLOCKED", verdict)
            self.assertTrue(any("unknown or missing fields" in error for error in errors), errors)

    def make_v9_root(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        directory = root / "delivery/legacy-feature"
        directory.mkdir(parents=True)
        state = {
            "schema_version": 9,
            "feature_id": "legacy-feature",
            "current_stage": "verification",
            "quality_reviews": {"product": {"verdict": "PASS"}, "architecture": {"verdict": "PASS"}, "code_spec": {"verdict": "PASS"}},
            "proof_contract": {
                "status": "completed",
                "environments": [{"id": "ENV-01", "target": "python", "spec": {"runtime": "python", "preflight": []}}],
                "obligations": [{
                    "id": "PO-01", "product_ids": ["AC-01"], "trace_ids": ["BP-01"],
                    "proof_type": "boundary", "surface": "legacy", "environment_id": "ENV-01",
                    "critical": True,
                    "runner": {"argv": ["true"], "cwd": ".", "observation_adapter": "none"},
                    "assertions": [{"id": "ASRT-01", "description": "legacy assertion", "oracle": {"kind": "exit_code", "source": "/command/exit_code", "operator": "eq", "expected": 0}}],
                }],
                "seal": "f" * 64,
            },
            "risks": [],
            "last_updated": "2026-01-01T00:00:00+00:00",
        }
        state_text = (
            "# Legacy delivery state\n\n<!-- DLV_STATE_START -->\n```json\n"
            + json.dumps(state, ensure_ascii=False, indent=2)
            + "\n```\n<!-- DLV_STATE_END -->\n"
        )
        (directory / "state.md").write_text(state_text, encoding="utf-8")
        (directory / "prd.md").write_text("# Legacy — 产品需求文档（PRD）\n\nSRC-01 source\nFR-01 behavior\nAC-01 accepted\nEX-01 rejected\n", encoding="utf-8")
        (directory / "architecture-design.md").write_text("# Legacy — 技术方案\n\nDATA-01 fact\nBP-01 boundary\nARCH-01 decision\n", encoding="utf-8")
        (directory / "code-spec.md").write_text("# Legacy — 代码实现规格（Code Spec）\n\nD01 change\nT-B01-01 test\n", encoding="utf-8")
        write_json(directory / "proof-contract.json", state["proof_contract"])
        return temporary, root, directory

    def test_v9_to_v10_dry_run_is_read_only_and_apply_is_conservative(self) -> None:
        temporary, root, directory = self.make_v9_root()
        with temporary:
            before = {item.name: item.read_bytes() for item in directory.iterdir()}
            graph = upgrade_v9_to_v10.convert(root, "legacy-feature")
            self.assertEqual(before, {item.name: item.read_bytes() for item in directory.iterdir()})
            self.assertEqual(12, graph["schema_version"])
            upgrade_v9_to_v10.apply_upgrade(root, "legacy-feature")
            self.assertFalse((directory / "state.md").exists())
            state = delivery_graph.load_state(directory / "state.json")
            self.assertEqual({}, state["attestations"])
            self.assertEqual("pending", state["readiness"]["status"])
            self.assertEqual("draft", state["proof_contract"]["status"])
            self.assertEqual("pending", state["code"]["status"])
            archive = root / ".dlv/upgrades/legacy-feature/schema-v9-candidates"
            self.assertTrue((archive / "state.md").is_file())
            self.assertTrue((archive / "proof-contract.json").is_file())

    def test_v9_to_v10_cli_preview_and_apply(self) -> None:
        temporary, root, directory = self.make_v9_root()
        with temporary:
            preview = subprocess.run(
                [sys.executable, str(SCRIPTS / "upgrade_v9_to_v10.py"), "legacy-feature", "--root", str(root)],
                capture_output=True, text=True,
            )
            self.assertEqual(0, preview.returncode, preview.stdout + preview.stderr)
            self.assertIn("schema 9", preview.stdout)
            self.assertTrue((directory / "state.md").is_file())
            applied = subprocess.run(
                [sys.executable, str(SCRIPTS / "upgrade_v9_to_v10.py"), "legacy-feature", "--root", str(root), "--apply"],
                capture_output=True, text=True,
            )
            self.assertEqual(0, applied.returncode, applied.stdout + applied.stderr)
            self.assertFalse((directory / "state.md").exists())

    def test_prototype_provenance_is_required_and_stale_binding_blocks_compile(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            directory = root / "delivery/cross-domain-feature"
            prototype = directory / "prototype.html"
            prototype.write_text("<main>candidate</main>", encoding="utf-8")
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["prototype"] = {"status": "contractual", "path": "prototype.html", "sha256": delivery_graph.file_digest(prototype)}
            self.assertTrue(any("source provenance" in error for error in delivery_graph.structural_errors(graph)))
            source = json.loads((directory / "source-revisions/SRC-001.json").read_text())
            graph["prototype"].update({
                "source_revision": "SRC-001", "source_kind": "source_revision",
                "source_ref": "SRC-001", "source_sha256": "0" * 64,
            })
            write_json(directory / "delivery-graph.json", graph)
            with self.assertRaisesRegex(ValueError, "provenance"):
                delivery_graph.compile_graph(root, "cross-domain-feature")
            graph["prototype"]["source_sha256"] = source["source_digest"]
            write_json(directory / "delivery-graph.json", graph)
            delivery_graph.compile_graph(root, "cross-domain-feature")

    def test_generated_prototype_candidate_blocks_review_without_becoming_reference(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            directory = root / "delivery/cross-domain-feature"
            prototype = directory / "prototype.html"
            prototype.write_text("<main>generated</main>", encoding="utf-8")
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["prototype"] = {
                "status": "generated_candidate", "path": "prototype.html", "sha256": delivery_graph.file_digest(prototype),
                "generated_from_revision": "SRC-001", "generator": "test-generator",
            }
            write_json(directory / "delivery-graph.json", graph)
            state = delivery_graph.compile_graph(root, "cross-domain-feature")
            self.assertEqual("needs_decision", state["readiness"]["status"])
            with self.assertRaisesRegex(ValueError, "generated Prototype"):
                graph_review.run_isolated_readiness_review(root, "cross-domain-feature", "generated-review")

    def test_finding_identity_survives_review_unit_repartition(self) -> None:
        ledger = empty_ledger("feature")
        finding = {
            "id": "NEW", "severity": "major", "status": "OPEN", "statement": "Duplicate write",
            "evidence": "ST-001", "risk_path": "CONCURRENCY", "root_cause": "duplicate write",
            "claim_id": "CLM-000000000001", "failure_mode": "duplicate write", "violated_invariant": "write once",
            "subjects": ["ST-001"], "risk_axes": ["CONCURRENCY"], "previously_invisible_reason": "new evidence",
        }
        ledger, first = apply_review_findings(ledger, unit_id="unit-a", source_revision="SRC-001", findings=[finding])
        ledger, second = apply_review_findings(ledger, unit_id="unit-b", source_revision="SRC-001", findings=[finding])
        self.assertEqual(first[0]["id"], second[0]["id"])
        self.assertEqual(["unit-a", "unit-b"], second[0]["observed_in_units"])

    def test_finding_semantics_exact_merge_partial_overlap_and_text_do_not_false_merge(self) -> None:
        ledger = empty_ledger("feature")
        base = {
            "id": "NEW", "severity": "major", "status": "OPEN", "statement": "Same wording", "evidence": "node",
            "risk_path": "CONCURRENCY", "root_cause": "wording", "claim_id": "CLM-000000000001",
            "failure_mode": "duplicate", "violated_invariant": "once", "subjects": ["ST-001"],
            "risk_axes": ["CONCURRENCY"], "previously_invisible_reason": "new evidence",
        }
        ledger, exact = apply_review_findings(ledger, unit_id="u1", source_revision="SRC-001", findings=[base])
        ledger, merged = apply_review_findings(ledger, unit_id="u2", source_revision="SRC-001", findings=[base])
        self.assertEqual(exact[0]["id"], merged[0]["id"])
        partial = {**base, "failure_mode": "lost update", "subjects": ["ST-001", "ST-002"]}
        ledger, candidates = apply_review_findings(ledger, unit_id="u3", source_revision="SRC-001", findings=[partial])
        self.assertEqual("MERGE_CANDIDATE", candidates[0]["status"])
        ledger, repeated_candidate = apply_review_findings(
            ledger, unit_id="u5", source_revision="SRC-001", findings=[partial],
        )
        self.assertEqual("MERGE_CANDIDATE", repeated_candidate[0]["status"])
        distinct = {**base, "claim_id": "CLM-000000000002", "failure_mode": "duplicate"}
        ledger, separate = apply_review_findings(ledger, unit_id="u4", source_revision="SRC-001", findings=[distinct])
        self.assertNotEqual(exact[0]["id"], separate[0]["id"])

    def test_finding_id_cannot_be_rebound_and_claim_boundaries_are_enforced(self) -> None:
        ledger = empty_ledger("feature")
        base = {
            "id": "NEW", "severity": "major", "status": "OPEN", "statement": "Duplicate write",
            "evidence": "ST-001", "risk_path": "CONCURRENCY", "root_cause": "duplicate write",
            "claim_id": "CLM-000000000001", "failure_mode": "duplicate", "violated_invariant": "once",
            "subjects": ["ST-001"], "risk_axes": ["CONCURRENCY"], "previously_invisible_reason": "new evidence",
        }
        ledger, canonical = apply_review_findings(
            ledger, unit_id="u1", source_revision="SRC-001", findings=[base],
            claim_ids={"CLM-000000000001"}, claim_subjects={"CLM-000000000001": {"ST-001"}},
        )
        rebound = {**base, "id": canonical[0]["id"], "failure_mode": "lost update"}
        with self.assertRaisesRegex(ValueError, "cannot be rebound"):
            apply_review_findings(ledger, unit_id="u2", source_revision="SRC-001", findings=[rebound])
        for invalid, message in (
            ({**base, "risk_axes": ["AUTHORIZATON"]}, "unknown risk axis"),
            ({**base, "subjects": ["ST-999"]}, "belong to its Claim"),
        ):
            with self.assertRaisesRegex(ValueError, message):
                apply_review_findings(
                    empty_ledger("feature"), unit_id="u", source_revision="SRC-001", findings=[invalid],
                    claim_ids={"CLM-000000000001"}, claim_subjects={"CLM-000000000001": {"ST-001"}},
                )

    def test_merge_candidate_requires_explicit_related_supersession_target(self) -> None:
        ledger = empty_ledger("feature")
        base = {
            "id": "NEW", "severity": "major", "status": "OPEN", "statement": "Duplicate",
            "evidence": "ST-001", "risk_path": "CONCURRENCY", "root_cause": "duplicate",
            "claim_id": "CLM-000000000001", "failure_mode": "duplicate", "violated_invariant": "once",
            "subjects": ["ST-001"], "risk_axes": ["CONCURRENCY"], "previously_invisible_reason": "new",
        }
        ledger, first = apply_review_findings(ledger, unit_id="u1", source_revision="SRC-001", findings=[base])
        ledger, second = apply_review_findings(
            ledger, unit_id="u2", source_revision="SRC-001",
            findings=[{**base, "failure_mode": "lost update", "subjects": ["ST-001", "ST-002"]}],
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_ledger(root, "feature", ledger)
            with patch.object(finding_ledger, "compile_graph"):
                with self.assertRaisesRegex(ValueError, "superseded-by"):
                    finding_ledger.transition(root, "feature", second[0]["id"], "SUPERSEDED", "owner", "same issue")
                finding_ledger.transition(
                    root, "feature", second[0]["id"], "SUPERSEDED", "owner", "same issue", first[0]["id"],
                )
            updated = load_ledger(root, "feature")
            self.assertEqual("SUPERSEDED", updated["entries"][second[0]["id"]]["status"])
            self.assertEqual(first[0]["id"], updated["entries"][second[0]["id"]]["supersedes"])
            chained = copy.deepcopy(updated)
            chained["entries"][first[0]["id"]]["status"] = "MERGE_CANDIDATE"
            chained["entries"][first[0]["id"]]["merge_candidates"] = [second[0]["id"]]
            write_ledger(root, "feature", chained)
            with patch.object(finding_ledger, "compile_graph"), self.assertRaisesRegex(ValueError, "canonical"):
                finding_ledger.transition(
                    root, "feature", first[0]["id"], "SUPERSEDED", "owner", "must stay direct", second[0]["id"],
                )
            write_ledger(root, "feature", updated)
            rediscovered, routed = apply_review_findings(
                updated, unit_id="u3", source_revision="SRC-002",
                findings=[{**base, "failure_mode": "lost update", "subjects": ["ST-001", "ST-002"]}],
            )
            self.assertEqual(first[0]["id"], routed[0]["id"])
            self.assertEqual("OPEN", routed[0]["status"])
            self.assertEqual("SUPERSEDED", rediscovered["entries"][second[0]["id"]]["status"])
            rediscovered["entries"][first[0]["id"]]["status"] = "FIXED_PENDING_REVIEW"
            alias_verification = {
                **base, "id": second[0]["id"], "status": "VERIFIED",
                "failure_mode": "lost update", "subjects": ["ST-001", "ST-002"],
            }
            with self.assertRaisesRegex(ValueError, "superseded finding cannot verify"):
                apply_review_findings(
                    rediscovered, unit_id="u3", source_revision="SRC-002", findings=[alias_verification],
                )
            canonical_verification = {
                **base, "id": first[0]["id"], "status": "VERIFIED", "evidence": "canonical fix verified",
            }
            verified, routed = apply_review_findings(
                rediscovered, unit_id="u3", source_revision="SRC-002", findings=[canonical_verification],
            )
            self.assertEqual("VERIFIED", routed[0]["status"])
            self.assertEqual("VERIFIED", verified["entries"][first[0]["id"]]["status"])
            write_ledger(root, "feature", rediscovered)
            load_ledger(root, "feature")

    def test_repeated_verification_from_multiple_review_units_is_idempotent(self) -> None:
        base = {
            "id": "NEW", "severity": "major", "status": "OPEN", "statement": "Duplicate",
            "evidence": "ST-001", "risk_path": "CONCURRENCY", "root_cause": "duplicate",
            "claim_id": "CLM-000000000001", "failure_mode": "duplicate", "violated_invariant": "once",
            "subjects": ["ST-001"], "risk_axes": ["CONCURRENCY"], "previously_invisible_reason": "new",
        }
        ledger, found = apply_review_findings(
            empty_ledger("feature"), unit_id="u1", source_revision="SRC-001", findings=[base],
        )
        ledger, _ = apply_review_findings(
            ledger, unit_id="u2", source_revision="SRC-001", findings=[base],
        )
        finding_id = found[0]["id"]
        ledger["entries"][finding_id]["status"] = "FIXED_PENDING_REVIEW"
        verified = {**base, "id": finding_id, "status": "VERIFIED", "evidence": "fixed implementation"}
        ledger, first = apply_review_findings(
            ledger, unit_id="u1", source_revision="SRC-002", findings=[verified],
        )
        ledger, second = apply_review_findings(
            ledger, unit_id="u2", source_revision="SRC-002", findings=[verified],
        )
        self.assertEqual("VERIFIED", first[0]["status"])
        self.assertEqual("VERIFIED", second[0]["status"])
        self.assertEqual(["u1", "u2"], ledger["entries"][finding_id]["observed_in_units"])

    def test_claim_succession_cannot_auto_route_historic_finding(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            old_claim = next(item for item in graph["claims"] if item["lens"] == "STATE_AND_ATOMICITY")
            raw = {
                "id": "NEW", "severity": "major", "status": "OPEN",
                "statement": "Atomic readback is incomplete", "evidence": "ST-001",
                "risk_path": "CONCURRENCY → stale state", "root_cause": "missing atomic readback",
                "claim_id": old_claim["id"], "failure_mode": "stale state",
                "violated_invariant": old_claim["invariant"], "subjects": ["ST-001"],
                "risk_axes": ["CONCURRENCY"], "previously_invisible_reason": "first review",
            }
            ledger, entries = apply_review_findings(
                empty_ledger("cross-domain-feature"), unit_id="old-unit",
                source_revision="SRC-001", findings=[raw],
            )
            write_ledger(root, "cross-domain-feature", ledger)
            predecessor_claim = copy.deepcopy(old_claim)
            old_id = old_claim["id"]
            old_claim["invariant"] += " with authoritative readback"
            old_claim["id"] = claim_id_for(old_claim)
            graph["claim_successions"] = [{
                "predecessor": old_id, "successor": old_claim["id"],
                "reason": "The state invariant was strengthened without discarding its open Finding.",
                "predecessor_claim": predecessor_claim,
                "predecessor_subjects": {
                    subject: {
                        "type": next(item["type"] for item in graph["nodes"] if item["id"] == subject),
                        "sha256": delivery_proof.value_digest(next(item for item in graph["nodes"] if item["id"] == subject)),
                    }
                    for subject in predecessor_claim["subjects"]
                },
                "subject_map": {subject: subject for subject in predecessor_claim["subjects"]},
            }]
            self.assertTrue(
                any("claim_successions must remain empty" in error for error in delivery_contracts.claim_errors(graph))
            )

    def test_claim_validation_reports_mixed_subject_types_without_crashing(self) -> None:
        graph = valid_graph()
        graph["claims"][0]["subjects"] = ["ST-001", 7]
        errors = delivery_contracts.claim_errors(graph)
        self.assertTrue(any("subjects must be" in error for error in errors), errors)

    def test_claim_succession_rejects_unrelated_successor(self) -> None:
        graph = valid_graph()
        predecessor = copy.deepcopy(next(item for item in graph["claims"] if item["lens"] == "STATE_AND_ATOMICITY"))
        graph["claims"] = [item for item in graph["claims"] if item["id"] != predecessor["id"]]
        unrelated = next(item for item in graph["claims"] if item["lens"] == "PROVENANCE_INTEGRITY")
        graph["claim_successions"] = [{
            "predecessor": predecessor["id"], "successor": unrelated["id"],
            "reason": "malicious unrelated routing", "predecessor_claim": predecessor,
            "predecessor_subjects": {
                subject: {
                    "type": next(item["type"] for item in graph["nodes"] if item["id"] == subject),
                    "sha256": delivery_proof.value_digest(next(item for item in graph["nodes"] if item["id"] == subject)),
                }
                for subject in predecessor["subjects"]
            },
            "subject_map": {subject: unrelated["subjects"][0] for subject in predecessor["subjects"]},
        }]
        errors = delivery_graph.structural_errors(graph, graph["feature_id"])
        self.assertTrue(any("claim_successions must remain empty" in error for error in errors), errors)

    def test_claim_succession_rejects_many_to_one_subject_collapse(self) -> None:
        graph = valid_graph()
        predecessor = copy.deepcopy(next(item for item in graph["claims"] if item["lens"] == "STATE_AND_ATOMICITY"))
        successor = copy.deepcopy(predecessor)
        successor["invariant"] += " and only a fact remains"
        successor["subjects"] = ["FACT-001"]
        successor["id"] = claim_id_for(successor)
        graph["claims"] = [item for item in graph["claims"] if item["id"] != predecessor["id"]] + [successor]
        graph["claim_successions"] = [{
            "predecessor": predecessor["id"], "successor": successor["id"],
            "reason": "unsafe collapse", "predecessor_claim": predecessor,
            "predecessor_subjects": {
                subject: {
                    "type": next(item["type"] for item in graph["nodes"] if item["id"] == subject),
                    "sha256": delivery_proof.value_digest(next(item for item in graph["nodes"] if item["id"] == subject)),
                }
                for subject in predecessor["subjects"]
            },
            "subject_map": {subject: "FACT-001" for subject in predecessor["subjects"]},
        }]
        errors = delivery_graph.structural_errors(graph, graph["feature_id"])
        self.assertTrue(any("claim_successions must remain empty" in error for error in errors), errors)

    def test_convergence_detects_unit_growth_and_stops_automatic_review(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["nodes"].append(node("RISK-002", "Risk", "New isolated risk", "A new branch can fail", severity="major", risk_axes=["CONCURRENCY"]))
            graph["claims"].append(claim("BOUNDARY_AND_CONCURRENCY", "New branch is safe", ["RISK-002"], "new boundary", ["PO-001"]))
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            state = delivery_graph.compile_graph(root, "cross-domain-feature")
            self.assertEqual("CONVERGING", state["convergence"]["status"])
            graph["nodes"].append(node("RISK-003", "Risk", "Second isolated risk", "Another branch can fail", severity="major", risk_axes=["CONCURRENCY"]))
            graph["claims"].append(claim("BOUNDARY_AND_CONCURRENCY", "Another branch is safe", ["RISK-003"], "second boundary", ["PO-001"]))
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            state = delivery_graph.compile_graph(root, "cross-domain-feature")
            self.assertEqual("DIVERGING", state["convergence"]["status"])
            self.assertEqual(3, len(state["convergence"]["history"]))
            with self.assertRaisesRegex(ValueError, "requires a decision"):
                graph_review.run_isolated_readiness_review(root, "cross-domain-feature", "diverging-review")

    def test_unchanged_compile_becomes_stable_blocked_and_stops_automatic_review(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            first = delivery_graph.compile_graph(root, "cross-domain-feature")
            self.assertEqual("CONVERGING", first["convergence"]["status"])
            second = delivery_graph.compile_graph(root, "cross-domain-feature")
            self.assertEqual("STABLE_BLOCKED", second["convergence"]["status"])
            self.assertEqual(second["convergence"]["vector"], second["convergence"]["previous_vector"])
            self.assertEqual([], graph_validation.validate(root, "cross-domain-feature"))
            with patch.object(graph_review, "run_bounded") as reviewer:
                with self.assertRaisesRegex(ValueError, "requires a decision"):
                    graph_review.run_isolated_readiness_review(root, "cross-domain-feature", "stable-review")
                reviewer.assert_not_called()

    def test_convergence_detects_two_consecutive_ready_distance_increases(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["nodes"].append(node("RISK-002", "Risk", "First additional risk", "A first additional branch can fail", severity="major", risk_axes=["CONCURRENCY"]))
            graph["claims"].append(claim("BOUNDARY_AND_CONCURRENCY", "The first additional branch is safe", ["RISK-002"], "first additional boundary", ["PO-002"]))
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            first = delivery_graph.compile_graph(root, "cross-domain-feature")
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["nodes"].append(node("RISK-003", "Risk", "Second additional risk", "A second additional branch can fail", severity="major", risk_axes=["CONCURRENCY"]))
            graph["claims"].append(claim("BOUNDARY_AND_CONCURRENCY", "The second additional branch is safe", ["RISK-003"], "second additional boundary", ["PO-002"]))
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            result = delivery_graph.compile_graph(root, "cross-domain-feature")
            self.assertEqual("DIVERGING", result["convergence"]["status"])
            distances = [sum(item[:-1]) for item in result["convergence"]["history"]]
            self.assertTrue(distances[0] < distances[1] < distances[2], distances)
            self.assertLess(first["convergence"]["ready_distance"], result["convergence"]["ready_distance"])

    def test_validation_recomputes_every_convergence_field(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            state_path = root / "delivery/cross-domain-feature/state.json"
            original = delivery_graph.load_state(state_path)
            mutations = {
                "status": "CONVERGING",
                "vector": [9, 0, 0, 0, 0, 0, 7],
                "ready_distance": 9,
                "budget": {"max_campaigns": 99, "max_unit_reviews": 24, "max_new_findings": 24},
                "used": {"campaigns": 0, "unit_reviews": 0, "new_findings": 0},
            }
            for field, value in mutations.items():
                with self.subTest(field=field):
                    tampered = copy.deepcopy(original)
                    tampered["convergence"][field] = value
                    if field == "vector":
                        tampered["convergence"]["history"][-1] = value
                    write_json(state_path, tampered)
                    errors = graph_validation.validate(root, "cross-domain-feature")
                    self.assertTrue(any("convergence" in error for error in errors), errors)
            write_json(state_path, original)

    def test_validation_rejects_correlated_convergence_history_status_tampering(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            for node_id in ("REQ-001", "DEC-001"):
                next(item for item in graph["nodes"] if item["id"] == node_id)["statement"] += " changed"
                write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
                delivery_graph.compile_graph(root, "cross-domain-feature")
            state_path = root / "delivery/cross-domain-feature/state.json"
            tampered = delivery_graph.load_state(state_path)
            current = tampered["convergence"]["vector"]
            tampered["convergence"].update({
                "history": [current], "previous_vector": None, "status": "CONVERGING",
                "reason": "the lexicographic obligation vector decreased or established a baseline",
            })
            write_json(state_path, tampered)
            errors = graph_validation.validate(root, "cross-domain-feature")
            self.assertTrue(any("convergence" in error for error in errors), errors)

    def test_convergence_chain_cannot_be_rewritten_without_external_kernel_key(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            for suffix in ("one", "two"):
                next(item for item in graph["nodes"] if item["id"] == "REQ-001")["statement"] += suffix
                write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
                delivery_graph.compile_graph(root, "cross-domain-feature")
            ledger_path = root / ".dlv/findings/cross-domain-feature/ledger.json"
            ledger = json.loads(ledger_path.read_text())
            event = copy.deepcopy(ledger["convergence_events"][-1])
            event["sequence"] = 1
            event["previous_hash"] = None
            payload = {key: event[key] for key in ("sequence", "state_key", "vector", "previous_hash")}
            event["record_hash"] = delivery_proof.value_digest(payload)
            ledger["convergence_events"] = [event]
            write_json(ledger_path, ledger)
            with self.assertRaisesRegex(ValueError, "convergence chain"):
                delivery_governance.load_ledger(root, "cross-domain-feature")

    def test_convergence_history_verifies_cross_machine_without_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as codex_a, tempfile.TemporaryDirectory() as codex_b:
            with patch.dict(os.environ, {"CODEX_HOME": codex_a}, clear=False):
                temporary, root = self.make_root()
                with temporary:
                    delivery_graph.compile_graph(root, "cross-domain-feature")
                    with patch.dict(os.environ, {"CODEX_HOME": codex_b}, clear=False):
                        ledger = delivery_governance.load_ledger(root, "cross-domain-feature")
                        self.assertGreaterEqual(len(ledger["convergence_events"]), 1)
                        graph = delivery_graph.load_graph(root, "cross-domain-feature")
                        graph["title"] += " changed"
                        write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
                        with self.assertRaisesRegex(ValueError, "signing authority is unavailable"):
                            delivery_graph.compile_graph(root, "cross-domain-feature")

    def test_convergence_history_can_continue_after_importing_matching_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as codex_a, tempfile.TemporaryDirectory() as codex_b:
            with patch.dict(os.environ, {"CODEX_HOME": codex_a}, clear=False):
                temporary, root = self.make_root()
                with temporary:
                    delivery_graph.compile_graph(root, "cross-domain-feature")
                    ledger_path = root / ".dlv/findings/cross-domain-feature/ledger.json"
                    event_count = len(json.loads(ledger_path.read_text())["convergence_events"])
                    source_key = Path(codex_a) / "dlv-feature/convergence-rs256.pem"
                    imported_key = Path(codex_b) / "imported-convergence-rs256.pem"
                    imported_key.write_bytes(source_key.read_bytes())
                    imported_key.chmod(0o600)
                    with patch.dict(
                        os.environ,
                        {"CODEX_HOME": codex_b, "DLV_CONVERGENCE_PRIVATE_KEY": str(imported_key)},
                        clear=False,
                    ):
                        graph = delivery_graph.load_graph(root, "cross-domain-feature")
                        graph["title"] += " changed on another machine"
                        write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
                        delivery_graph.compile_graph(root, "cross-domain-feature")
                        ledger = delivery_governance.load_ledger(root, "cross-domain-feature")
                        self.assertEqual(event_count + 1, len(ledger["convergence_events"]))
                        self.assertEqual(
                            ledger["convergence_authority"]["key_id"],
                            ledger["convergence_events"][-1]["key_id"],
                        )

    def test_convergence_authority_cannot_silently_rotate_or_rebind_source(self) -> None:
        with tempfile.TemporaryDirectory() as codex_a, tempfile.TemporaryDirectory() as codex_b:
            with patch.dict(os.environ, {"CODEX_HOME": codex_a}, clear=False):
                temporary, root = self.make_root()
                with temporary:
                    delivery_graph.compile_graph(root, "cross-domain-feature")
                    with patch.dict(os.environ, {"CODEX_HOME": codex_b}, clear=False):
                        other_temporary, other_root = self.make_root()
                        with other_temporary:
                            delivery_graph.compile_graph(other_root, "cross-domain-feature")
                            other_source = delivery_governance.load_source_revision(
                                other_root / "delivery/cross-domain-feature", "cross-domain-feature", "SRC-001",
                            )
                            other_authority = next(
                                item for item in other_source["attachments"]
                                if item.get("kind") == "convergence_authority"
                            )
                        graph = delivery_graph.load_graph(root, "cross-domain-feature")
                        graph["title"] += " requires another event"
                        write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
                        with self.assertRaisesRegex(ValueError, "does not match the repository authority"):
                            delivery_graph.compile_graph(root, "cross-domain-feature")
                    source_directory = root / "delivery/cross-domain-feature/source-revisions"
                    changed_source = delivery_governance.load_source_revision(
                        root / "delivery/cross-domain-feature", "cross-domain-feature", "SRC-001",
                    )
                    changed_source.update({"revision_id": "SRC-002", "title": "Different authority source"})
                    changed_source["attachments"] = [
                        item for item in changed_source["attachments"]
                        if item.get("kind") != "convergence_authority"
                    ] + [other_authority]
                    changed_source["source_digest"] = delivery_proof.value_digest(canonical_source_payload(changed_source))
                    write_json(source_directory / "SRC-002.json", changed_source)
                    graph = delivery_graph.load_graph(root, "cross-domain-feature")
                    graph["source_revision"] = "SRC-002"
                    write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
                    with self.assertRaisesRegex(ValueError, "does not bind the ledger convergence authority"):
                        delivery_graph.compile_graph(root, "cross-domain-feature")
                    ledger_path = root / ".dlv/findings/cross-domain-feature/ledger.json"
                    ledger = json.loads(ledger_path.read_text())
                    ledger["convergence_authority"]["source_digest"] = "0" * 64
                    write_json(ledger_path, ledger)
                    with self.assertRaisesRegex(ValueError, "convergence event is invalid"):
                        delivery_governance.load_ledger(root, "cross-domain-feature")

    def test_review_budget_exhaustion_never_passes_or_waives(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["metadata"]["review_budget"] = {"max_campaigns": 1, "max_unit_reviews": 99, "max_new_findings": 99}
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            self.review_all(root)
            next(item for item in graph["nodes"] if item["id"] == "REQ-001")["statement"] += " with changed scope"
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            state = delivery_graph.compile_graph(root, "cross-domain-feature")
            self.assertEqual("NEEDS_DECISION", state["convergence"]["status"])
            self.assertNotEqual("ready", state["readiness"]["status"])

    def test_review_campaign_budget_cannot_be_configured_above_three(self) -> None:
        graph = valid_graph()
        graph["metadata"]["review_budget"] = {
            "max_campaigns": 4, "max_unit_reviews": 24, "max_new_findings": 24,
        }
        with self.assertRaisesRegex(ValueError, "at most 3"):
            delivery_contracts.review_budget(graph)
        self.assertTrue(
            any("at most 3" in error for error in delivery_graph.structural_errors(graph, graph["feature_id"]))
        )

    def test_review_budget_rejects_a_prospective_campaign_that_would_exceed_units(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["metadata"]["review_budget"] = {"max_campaigns": 3, "max_unit_reviews": 1, "max_new_findings": 99}
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            delivery_graph.compile_graph(root, "cross-domain-feature")
            unit_ids = list(delivery_graph.review_units(graph))[:2]
            with self.assertRaisesRegex(graph_review.ReviewBudgetExceeded, "unit-review budget"):
                graph_review._record_units(root, "cross-domain-feature", unit_ids, "over-budget")
            ledger = delivery_governance.load_ledger(root, "cross-domain-feature")
            self.assertEqual(2, ledger["campaigns"][-1]["unit_count"])
            state = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            self.assertEqual("NEEDS_DECISION", state["convergence"]["status"])
            self.assertEqual([], graph_validation.validate(root, "cross-domain-feature"))

    def test_review_budget_is_enforced_under_lock_and_debug_runs_do_not_consume_it(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["metadata"]["review_budget"] = {
                "max_campaigns": 1, "max_unit_reviews": 99, "max_new_findings": 1,
            }
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            delivery_graph.compile_graph(root, "cross-domain-feature")
            graph_review.record_readiness(root, "cross-domain-feature", "debug-budget-free")
            self.assertEqual([], delivery_governance.load_ledger(root, "cross-domain-feature")["campaigns"])

            units = delivery_graph.review_units(graph)
            unit_id, unit = next(iter(units.items()))
            claim = next(item for item in graph["claims"] if item["id"] in unit["claim_ids"])
            findings = [
                {
                    "id": "NEW", "severity": "major", "status": "OPEN",
                    "statement": f"Budget finding {index}", "evidence": claim["subjects"][0],
                    "risk_path": "transactional budget", "root_cause": f"root {index}",
                    "claim_id": claim["id"], "failure_mode": f"failure {index}",
                    "violated_invariant": claim["invariant"], "subjects": [claim["subjects"][0]],
                    "risk_axes": ["CONCURRENCY"],
                    "previously_invisible_reason": "combined response",
                }
                for index in range(2)
            ]
            semantic = {
                "verdict": "BLOCKED",
                "checks": [{"id": "budget", "status": "PASS", "evidence": "evaluated"}],
                "findings": findings,
                "execution": {"mode": "isolated_process", "provider": "codex-exec", "independent": True},
            }
            with self.assertRaisesRegex(graph_review.ReviewBudgetExceeded, "new-finding budget"):
                graph_review._record_units(
                    root, "cross-domain-feature", [unit_id], "transaction-budget", {unit_id: semantic},
                )
            ledger = delivery_governance.load_ledger(root, "cross-domain-feature")
            self.assertEqual(2, ledger["campaigns"][-1]["new_findings"])
            self.assertEqual(2, len(ledger["entries"]))
            self.assertFalse(list((root / ".dlv/reviews/cross-domain-feature").glob("transaction-budget.*")))
            state = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            self.assertEqual("NEEDS_DECISION", state["convergence"]["status"])
            self.assertEqual([], graph_validation.validate(root, "cross-domain-feature"))

    def test_high_strength_proof_rejects_boolean_only_observation(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            result, _, metadata = self.prepare_invariant_run(root, "boolean-only")
            spec = metadata["environments"]["ENV-001"]["spec"]
            completed = self.signed_command_result(spec, {"ok": True})
            with patch.object(graph_verification, "run_bounded", side_effect=completed), self.assertRaisesRegex(ValueError, "boolean-only"):
                graph_verification.record("cross-domain-feature", root, "boolean-only", result, [])

    def test_high_strength_run_binds_real_head_commit_and_rejects_source_drift(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            _, _, metadata = self.prepare_invariant_run(root, "commit-bound")
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True,
            ).stdout.strip()
            self.assertEqual(head, metadata["commit_identity"])
            self.assertNotEqual(metadata["code_fingerprint"], metadata["commit_identity"])
            untracked = root / "uncommitted-source.py"
            untracked.write_text("value = 1\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "no untracked source"):
                graph_verification.formal_head_identity(root, "cross-domain-feature")

    def test_high_strength_evidence_hash_binds_the_verified_commit_identity(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            result, _, metadata = self.prepare_invariant_run(root, "evidence-commit")
            spec = metadata["environments"]["ENV-001"]["spec"]
            completed = self.signed_command_result(spec, {"count": 1})
            with patch.object(graph_verification, "run_bounded", side_effect=completed):
                graph_verification.record("cross-domain-feature", root, "evidence-commit", result, [])
            run_path = root / ".dlv/runs/cross-domain-feature/evidence-commit/run.json"
            rewritten = json.loads(run_path.read_text())
            rewritten["commit_identity"] = "b" * 40
            write_json(run_path, rewritten)
            errors: list[str] = []
            with patch.object(graph_verification, "formal_head_identity", return_value="b" * 40):
                graph_verification.validate_run(root, "cross-domain-feature", "evidence-commit", errors)
            self.assertTrue(any("evidence Git commit identity is stale" in error for error in errors), errors)

    def test_each_evidence_record_gets_a_fresh_runner_nonce_and_high_strength_fork_policy(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            result, _, metadata = self.prepare_invariant_run(root, "fresh-evidence-nonce")
            spec = metadata["environments"]["ENV-001"]["spec"]
            issued: list[str] = []

            def signed(*_args: object, **kwargs: object) -> dict[str, object]:
                self.assertTrue(kwargs["deny_process_fork"])
                nonce = kwargs["environment"]["DLV_CHALLENGE_NONCE"]
                issued.append(nonce)
                observation = {"count": 1, "challenge_nonce": nonce, "target_identity": spec["target_identity"]}
                sign_target_observation(observation, spec, nonce)
                return {"exit_code": 0, "stdout": json.dumps(observation), "stderr": "", "timed_out": False}

            with patch.object(graph_verification, "run_bounded", side_effect=signed):
                graph_verification.record("cross-domain-feature", root, "fresh-evidence-nonce", result, [])
                graph_verification.record(
                    "cross-domain-feature", root, "fresh-evidence-nonce", result, ["EVID-0001"],
                )
            records = graph_verification.load_manifest(
                root / ".dlv/runs/cross-domain-feature/fresh-evidence-nonce/evidence.jsonl",
            )
            self.assertEqual(2, len(set(issued)))
            self.assertEqual(issued, [record["challenge_nonce"] for record in records])
            self.assertNotIn("challenge_nonce", metadata)
            errors: list[str] = []
            graph_verification.validate_run(root, "cross-domain-feature", "fresh-evidence-nonce", errors)
            self.assertFalse(any("challenge nonce" in error for error in errors), errors)

    def test_run_validation_rejects_reused_evidence_nonce(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            result, _, metadata = self.prepare_invariant_run(root, "reused-evidence-nonce")
            spec = metadata["environments"]["ENV-001"]["spec"]
            completed = self.signed_command_result(spec, {"count": 1})
            with patch.object(graph_verification.secrets, "token_hex", return_value="a" * 64), patch.object(
                graph_verification, "run_bounded", side_effect=completed,
            ):
                graph_verification.record("cross-domain-feature", root, "reused-evidence-nonce", result, [])
                graph_verification.record(
                    "cross-domain-feature", root, "reused-evidence-nonce", result, ["EVID-0001"],
                )
            errors: list[str] = []
            graph_verification.validate_run(root, "cross-domain-feature", "reused-evidence-nonce", errors)
            self.assertTrue(any("challenge nonce is reused" in error for error in errors), errors)

    def test_high_strength_proof_rejects_boolean_assertion_with_string_padding(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            assertion = next(item for item in graph["nodes"] if item["id"] == "ASRT-001")
            assertion["attributes"]["oracle"] = {
                "kind": "state", "source": "/observation/ok", "operator": "eq", "expected": True,
            }
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            result, _, metadata = self.prepare_invariant_run(root, "boolean-padding")
            spec = metadata["environments"]["ENV-001"]["spec"]
            completed = self.signed_command_result(spec, {"ok": True, "note": "unrelated padding"})
            with patch.object(graph_verification, "run_bounded", side_effect=completed), self.assertRaisesRegex(ValueError, "boolean-only asserted"):
                graph_verification.record("cross-domain-feature", root, "boolean-padding", result, [])

    def test_high_strength_proof_rejects_metadata_only_observation(self) -> None:
        observation = {"challenge_nonce": "nonce", "target_identity": "target", "target_attestation": "signed-token"}
        self.assertTrue(is_boolean_only_observation(observation))

    def test_high_strength_proof_rejects_target_or_nonce_mismatch(self) -> None:
        for field, value in (("target_identity", "wrong-target"), ("challenge_nonce", "wrong-nonce")):
            with self.subTest(field=field):
                temporary, root = self.make_root()
                with temporary:
                    result, _, metadata = self.prepare_invariant_run(root, f"mismatch-{field}")
                    spec = metadata["environments"]["ENV-001"]["spec"]
                    completed = self.signed_command_result(spec, {"count": 1}, **{field: value})
                    with patch.object(graph_verification, "run_bounded", side_effect=completed), self.assertRaisesRegex(ValueError, "mismatch"):
                        graph_verification.record("cross-domain-feature", root, f"mismatch-{field}", result, [])

    def test_high_strength_proof_rejects_unsigned_self_reported_target_measurement(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            result, _, metadata = self.prepare_invariant_run(root, "unsigned-target")
            def unsigned(*_args: object, **kwargs: object) -> dict[str, object]:
                nonce = kwargs["environment"]["DLV_CHALLENGE_NONCE"]
                observation = {"count": 1, "challenge_nonce": nonce, "target_identity": "python:test-target"}
                return {"exit_code": 0, "stdout": json.dumps(observation), "stderr": "", "timed_out": False}
            with patch.object(graph_verification, "run_bounded", side_effect=unsigned), self.assertRaisesRegex(ValueError, "target-signed"):
                graph_verification.record("cross-domain-feature", root, "unsigned-target", result, [])

    def test_target_attestation_rs256_rejects_tampering_and_identity_mismatch(self) -> None:
        nonce = "challenge-1"
        authenticity = {
            "target_identity": "runtime:test", "build_identity": "build:test",
            "deployment_identity": "deploy:test", "attestation": test_attestation_config(),
        }
        observation = {"count": 1, "challenge_nonce": nonce, "target_identity": "runtime:test"}
        sign_target_observation(observation, authenticity, nonce)
        target_attestation.verify_target_attestation(observation, authenticity, nonce)

        tampered = copy.deepcopy(observation)
        tampered["count"] = 2
        with self.assertRaisesRegex(ValueError, "binding is stale"):
            target_attestation.verify_target_attestation(tampered, authenticity, nonce)

        for field, value in (
            ("target_identity", "runtime:other"),
            ("build_identity", "build:other"),
            ("deployment_identity", "deploy:other"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(authenticity)
                changed[field] = value
                with self.assertRaisesRegex(ValueError, "binding is stale"):
                    target_attestation.verify_target_attestation(observation, changed, nonce)
        with self.assertRaisesRegex(ValueError, "binding is stale"):
            target_attestation.verify_target_attestation(observation, authenticity, "challenge-2")

    def test_target_attestation_rejects_bad_signature_wrong_key_duplicate_json_and_noncanonical_base64(self) -> None:
        nonce = "challenge-1"
        authenticity = {
            "target_identity": "runtime:test", "build_identity": "build:test",
            "deployment_identity": "deploy:test", "attestation": test_attestation_config(),
        }
        observation = {"count": 1, "challenge_nonce": nonce, "target_identity": "runtime:test"}
        sign_target_observation(observation, authenticity, nonce)
        header, payload, signature = observation["target_attestation"].split(".")

        bad_signature = bytearray(target_attestation._decode_base64url(signature, "signature"))
        bad_signature[-1] ^= 1
        modified = copy.deepcopy(observation)
        modified["target_attestation"] = f"{header}.{payload}.{b64url_bytes(bytes(bad_signature))}"
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            target_attestation.verify_target_attestation(modified, authenticity, nonce)

        wrong_key = copy.deepcopy(authenticity)
        wrong_key["attestation"]["public_key_jwk"]["n"] = b64url_int(TEST_RSA_N ^ (1 << 100))
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            target_attestation.verify_target_attestation(observation, wrong_key, nonce)

        decoded_payload = target_attestation._decode_base64url(payload, "payload").decode("utf-8")
        duplicate_payload = decoded_payload[:-1] + ',"issuer":"duplicate"}'
        duplicate = copy.deepcopy(observation)
        duplicate["target_attestation"] = f"{header}.{b64url_bytes(duplicate_payload.encode())}.{signature}"
        with self.assertRaisesRegex(ValueError, "duplicate keys"):
            target_attestation.verify_target_attestation(duplicate, authenticity, nonce)

        noncanonical = copy.deepcopy(observation)
        noncanonical["target_attestation"] = f"{header}=.{payload}.{signature}"
        with self.assertRaisesRegex(ValueError, "not canonical base64url"):
            target_attestation.verify_target_attestation(noncanonical, authenticity, nonce)

    def test_target_attestation_bounds_rsa_and_compact_token_inputs(self) -> None:
        weak_exponent = test_attestation_config()
        weak_exponent["public_key_jwk"]["e"] = b64url_int(3)
        with self.assertRaisesRegex(ValueError, "too weak or invalid"):
            target_attestation.validate_attestation_config(weak_exponent)
        oversized_modulus = test_attestation_config()
        oversized_modulus["public_key_jwk"]["n"] = "A" * (target_attestation.MAX_RSA_MODULUS_CHARS + 1)
        with self.assertRaisesRegex(ValueError, "modulus is invalid"):
            target_attestation.validate_attestation_config(oversized_modulus)
        authenticity = {
            "target_identity": "runtime:test", "build_identity": "build:test",
            "deployment_identity": "deploy:test", "attestation": test_attestation_config(),
        }
        observation = {
            "count": 1, "challenge_nonce": "challenge", "target_identity": "runtime:test",
            "target_attestation": f"{'A' * (target_attestation.MAX_COMPACT_SEGMENT_CHARS + 1)}.e30.AQ",
        }
        with self.assertRaisesRegex(ValueError, "header is invalid"):
            target_attestation.verify_target_attestation(observation, authenticity, "challenge")

    def test_runtime_action_and_readback_must_share_target_identity_and_nonce(self) -> None:
        authenticity = {"target_identity": "runtime:one"}
        valid = {
            "action": {"target_identity": "runtime:one", "challenge_nonce": "nonce-one"},
            "result_readback": {"target_identity": "runtime:one", "challenge_nonce": "nonce-one"},
        }
        graph_verification.validate_runtime_binding(valid, authenticity, "nonce-one")
        for role, field, value in (
            ("action", "target_identity", "runtime:two"),
            ("result_readback", "challenge_nonce", "nonce-two"),
        ):
            with self.subTest(role=role, field=field):
                invalid = copy.deepcopy(valid)
                invalid[role][field] = value
                with self.assertRaisesRegex(ValueError, "target identity or challenge nonce mismatch"):
                    graph_verification.validate_runtime_binding(invalid, authenticity, "nonce-one")

    def test_adapter_and_fixture_drift_invalidate_high_strength_proof(self) -> None:
        for drift in ("adapter", "fixture"):
            with self.subTest(drift=drift):
                temporary, root = self.make_root()
                with temporary:
                    result, fixture, metadata = self.prepare_invariant_run(root, f"drift-{drift}")
                    target = root / ".dlv/repository-adapter.json" if drift == "adapter" else fixture
                    write_json(target, {"changed": True})
                    completed = {"exit_code": 0, "stdout": "{}", "stderr": "", "timed_out": False}
                    with patch.object(graph_verification, "run_bounded", return_value=completed), self.assertRaisesRegex(ValueError, "fingerprint|repository adapter"):
                        graph_verification.record("cross-domain-feature", root, f"drift-{drift}", result, [])

    def test_frontend_fast_path_escalates_risk_and_requires_adapter_capabilities(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["metadata"]["delivery_mode"] = "frontend_fast_path"
            graph["metadata"]["risk_vector"]["API_CONTRACT"] = "present"
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            reasons = frontend_fast_path.eligibility(root, "cross-domain-feature")
            self.assertTrue(any("API_CONTRACT" in reason for reason in reasons))
            graph["metadata"]["risk_vector"]["API_CONTRACT"] = "absent"
            write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            write_json(root / ".dlv/repository-adapter.json", {"schema_version": 12, "name": "empty", "source_ref": "test-repository-adapter", "frontend_roots": ["src"], "capabilities": {}})
            reasons = frontend_fast_path.eligibility(root, "cross-domain-feature")
            self.assertTrue(any("lacks fast-path capabilities" in reason for reason in reasons))
            capabilities = {
                name: {"argv": ["true"], "cwd": ".", "timeout_seconds": 30, "max_output_bytes": 4096}
                for name in frontend_fast_path.REQUIRED_CAPABILITIES if name != "lint"
            }
            write_json(root / ".dlv/repository-adapter.json", {
                "schema_version": 12, "name": "missing-lint", "source_ref": "test-repository-adapter",
                "frontend_roots": ["src"], "capabilities": capabilities,
            })
            reasons = frontend_fast_path.eligibility(root, "cross-domain-feature")
            self.assertTrue(any("lint" in reason for reason in reasons), reasons)

    def test_frontend_fast_path_validates_run_id_and_routes_structured_cross_boundary_changes(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            with self.assertRaisesRegex(ValueError, "run-id"):
                frontend_fast_path.run(root, "cross-domain-feature", "../../escape")
            adapter = {
                "schema_version": 12, "name": "test", "source_ref": "test-repository-adapter", "frontend_roots": ["src"], "capabilities": {
                    name: {"argv": ["true"], "cwd": ".", "timeout_seconds": 30, "max_output_bytes": 4096}
                    for name in frontend_fast_path.REQUIRED_CAPABILITIES
                },
            }
            changes = {
                "schema_version": 12, "paths": ["api/controller.py"],
                "surfaces": ["api"], "risk_axes": ["API_CONTRACT"],
            }
            snapshot_bases: list[Path | None] = []

            def execute(_root: Path, _adapter: dict, capability: str, snapshot_base: Path | None = None) -> dict:
                snapshot_bases.append(snapshot_base)
                stdout = json.dumps(changes) if capability == "changes" else ""
                return {"capability": capability, "command": {}, "result": {"exit_code": 0, "timed_out": False, "stdout": stdout, "stderr": ""}}
            with (
                patch.object(frontend_fast_path, "_eligibility_snapshot", return_value=([], fast_path_eligibility_snapshot(root, adapter, "a" * 64))),
                patch.object(frontend_fast_path, "load_adapter", return_value=(adapter, "a" * 64)),
                patch.object(frontend_fast_path, "execute_capability", side_effect=execute),
                patch.object(frontend_fast_path, "kernel_git_snapshot", return_value=({"base_ref": "origin/main", "base_oid": "1", "merge_base_oid": "1", "paths": ["api/controller.py"]}, None)),
            ):
                result = frontend_fast_path.run(root, "cross-domain-feature", "fast-route")
            self.assertEqual("ROUTE_STANDARD", result["status"])
            self.assertEqual(1, len(snapshot_bases))
            self.assertIsNotNone(snapshot_bases[0])
            self.assertTrue((root / ".dlv/fast-path/cross-domain-feature/fast-route.json").is_file())

    def test_frontend_fast_path_happy_path_runs_quality_steps_once_before_review(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            delivery_graph.compile_graph(root, "cross-domain-feature")
            (root / "src").mkdir()
            (root / "src/view.tsx").write_text("export const View = () => null;\n", encoding="utf-8")
            adapter = {
                "schema_version": 12, "name": "test", "source_ref": "test-repository-adapter", "frontend_roots": ["src"], "capabilities": {
                    name: {"argv": ["true"], "cwd": ".", "timeout_seconds": 30, "max_output_bytes": 4096}
                    for name in (*frontend_fast_path.REQUIRED_CAPABILITIES, "lint")
                },
            }
            changes = {
                "schema_version": 12, "paths": ["src/view.tsx"],
                "surfaces": ["frontend"], "risk_axes": [],
            }
            calls: list[str] = []

            snapshot_bases: list[Path | None] = []

            def execute(_root: Path, _adapter: dict, capability: str, snapshot_base: Path | None = None) -> dict:
                calls.append(capability)
                snapshot_bases.append(snapshot_base)
                stdout = json.dumps(changes) if capability == "changes" else ""
                return {"capability": capability, "command": {}, "result": {"exit_code": 0, "timed_out": False, "stdout": stdout, "stderr": ""}}

            review_record = root.resolve() / "delivery/cross-domain-feature/composite-review.json"

            def review(_root: Path, _feature_id: str, _run_id: str) -> list[Path]:
                state = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
                self.assertEqual("CONVERGING", state["convergence"]["status"])
                return [review_record]

            with (
                patch.object(frontend_fast_path, "_eligibility_snapshot", return_value=([], fast_path_eligibility_snapshot(root, adapter, "a" * 64))),
                patch.object(frontend_fast_path, "load_adapter", return_value=(adapter, "a" * 64)),
                patch.object(frontend_fast_path, "execute_capability", side_effect=execute),
                patch.object(frontend_fast_path, "kernel_git_snapshot", return_value=({"base_ref": "origin/main", "base_oid": "1", "merge_base_oid": "1", "paths": ["src/view.tsx"]}, None)),
                patch.object(frontend_fast_path, "run_isolated_readiness_review", side_effect=review),
            ):
                result = frontend_fast_path.run(root, "cross-domain-feature", "fast-happy")
            self.assertEqual("PROOF_REQUIRED", result["status"])
            self.assertEqual(["changes", "lint", "targeted_tests", "typecheck", "build"], calls)
            self.assertEqual(1, len(set(snapshot_bases)))
            self.assertIsNotNone(snapshot_bases[0])
            self.assertEqual("composite_review", result["steps"][-1]["name"])
            with patch.object(frontend_fast_path, "execute_capability") as duplicate_execute:
                with self.assertRaisesRegex(ValueError, "journal already exists"):
                    frontend_fast_path.run(root, "cross-domain-feature", "fast-happy")
                duplicate_execute.assert_not_called()

    def test_frontend_fast_path_atomically_reserves_one_concurrent_run(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            (root / "src").mkdir()
            (root / "src/view.tsx").write_text("export const View = () => null;\n", encoding="utf-8")
            adapter = {
                "schema_version": 12, "name": "test", "source_ref": "test-repository-adapter",
                "frontend_roots": ["src"], "capabilities": {
                    name: {"argv": ["true"], "cwd": ".", "timeout_seconds": 30, "max_output_bytes": 4096}
                    for name in frontend_fast_path.REQUIRED_CAPABILITIES
                },
            }
            changes = {"schema_version": 12, "paths": ["src/view.tsx"], "surfaces": ["frontend"], "risk_axes": []}
            first_started = threading.Event()
            release_first = threading.Event()
            calls: list[str] = []

            def execute(_root: Path, _adapter: dict, capability: str, snapshot_base: Path | None = None) -> dict:
                calls.append(capability)
                if capability == "changes":
                    first_started.set()
                    self.assertTrue(release_first.wait(5), "concurrent run did not inspect the reservation")
                stdout = json.dumps(changes) if capability == "changes" else ""
                return {
                    "capability": capability, "command": {},
                    "result": {"exit_code": 0, "timed_out": False, "stdout": stdout, "stderr": ""},
                }

            snapshot = {"base_ref": "origin/main", "base_oid": "1", "merge_base_oid": "1", "paths": ["src/view.tsx"]}
            with (
                patch.object(frontend_fast_path, "_eligibility_snapshot", return_value=([], fast_path_eligibility_snapshot(root, adapter, "a" * 64))),
                patch.object(frontend_fast_path, "load_adapter", return_value=(adapter, "a" * 64)),
                patch.object(frontend_fast_path, "execute_capability", side_effect=execute),
                patch.object(frontend_fast_path, "kernel_git_snapshot", return_value=(snapshot, None)),
                patch.object(frontend_fast_path, "run_isolated_readiness_review", return_value=[]),
                ThreadPoolExecutor(max_workers=2) as executor,
            ):
                first = executor.submit(frontend_fast_path.run, root, "cross-domain-feature", "fast-first")
                self.assertTrue(first_started.wait(5), "first fast-path run did not start")
                second = executor.submit(frontend_fast_path.run, root, "cross-domain-feature", "fast-second")
                second_result = second.result(timeout=5)
                release_first.set()
                first_result = first.result(timeout=5)
            self.assertEqual("PROOF_REQUIRED", first_result["status"])
            self.assertEqual("ROUTE_STANDARD", second_result["status"])
            self.assertIn("already reserved", second_result["reasons"][0])
            self.assertEqual(list(frontend_fast_path.REQUIRED_CAPABILITIES), calls)
            self.assertFalse((root / ".dlv/fast-path/cross-domain-feature/active-reservation.json").exists())

    def test_frontend_fast_path_blocks_adapter_repository_mutation(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            (root / "src").mkdir()
            (root / "src/view.tsx").write_text("export const View = () => null;\n", encoding="utf-8")
            adapter = {
                "schema_version": 12, "name": "test", "source_ref": "test-repository-adapter", "frontend_roots": ["src"], "capabilities": {
                    name: {"argv": ["true"], "cwd": ".", "timeout_seconds": 30, "max_output_bytes": 4096}
                    for name in frontend_fast_path.REQUIRED_CAPABILITIES
                },
            }
            changes = {"schema_version": 12, "paths": ["src/view.tsx"], "surfaces": ["frontend"], "risk_axes": []}
            completed = {"capability": "changes", "command": {}, "result": {"exit_code": 0, "timed_out": False, "stdout": json.dumps(changes), "stderr": ""}}
            snapshot = {"base_ref": "origin/main", "base_oid": "1", "merge_base_oid": "1", "paths": ["src/view.tsx"]}
            with (
                patch.object(frontend_fast_path, "_eligibility_snapshot", return_value=([], fast_path_eligibility_snapshot(root, adapter, "a" * 64))),
                patch.object(frontend_fast_path, "load_adapter", return_value=(adapter, "a" * 64)),
                patch.object(frontend_fast_path, "execute_capability", return_value=completed),
                patch.object(frontend_fast_path, "kernel_git_snapshot", return_value=(snapshot, None)),
                patch.object(frontend_fast_path, "repository_fingerprint", side_effect=["before", "after"]),
            ):
                snapshot_state = fast_path_eligibility_snapshot(root, adapter, "a" * 64)
                snapshot_state["repository_fingerprint"] = "before"
                frontend_fast_path._eligibility_snapshot.return_value = ([], snapshot_state)
                result = frontend_fast_path.run(root, "cross-domain-feature", "fast-mutated")
            self.assertEqual("BLOCKED", result["status"])
            self.assertIn("mutated", result["reasons"][0])

    def test_frontend_fast_path_records_routine_failure_and_releases_reservation(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            adapter = {
                "schema_version": 12, "name": "test", "source_ref": "test-repository-adapter",
                "frontend_roots": ["src"], "capabilities": {
                    name: {"argv": ["true"], "cwd": ".", "timeout_seconds": 30, "max_output_bytes": 4096}
                    for name in frontend_fast_path.REQUIRED_CAPABILITIES
                },
            }
            with (
                patch.object(frontend_fast_path, "_eligibility_snapshot", return_value=([], fast_path_eligibility_snapshot(root, adapter, "a" * 64))),
                patch.object(frontend_fast_path, "kernel_git_snapshot", return_value=({"base_ref": "origin/main", "base_oid": "1", "merge_base_oid": "1", "paths": ["src/view.tsx"]}, None)),
                patch.object(frontend_fast_path, "execute_capability", side_effect=RuntimeError("secret adapter detail")),
            ):
                result = frontend_fast_path.run(root, "cross-domain-feature", "fast-routine-failure")
            self.assertEqual("BLOCKED", result["status"])
            self.assertEqual(["frontend fast-path execution failed: RuntimeError"], result["reasons"])
            journal = root / ".dlv/fast-path/cross-domain-feature/fast-routine-failure.json"
            self.assertTrue(journal.is_file())
            self.assertNotIn("secret adapter detail", journal.read_text(encoding="utf-8"))
            self.assertFalse((root / ".dlv/fast-path/cross-domain-feature/active-reservation.json").exists())

    def test_frontend_fast_path_routes_symlink_and_oversized_source_to_standard(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            outside = root.parent / f"{root.name}-outside.tsx"
            outside.write_text("authorization tenant payment", encoding="utf-8")
            try:
                (root / "linked.tsx").symlink_to(outside)
                output = json.dumps({
                    "schema_version": 12, "paths": ["linked.tsx"],
                    "surfaces": ["frontend"], "risk_axes": [],
                })
                reasons = frontend_fast_path._change_routing_reasons(root, output, ["linked.tsx"], ["src"])
                self.assertTrue(any("non-frontend/unreadable" in reason for reason in reasons), reasons)

                oversized = root / "large.tsx"
                with oversized.open("wb") as handle:
                    handle.truncate(frontend_fast_path.MAX_FAST_PATH_SOURCE_BYTES + 1)
                large_output = json.dumps({
                    "schema_version": 12, "paths": ["large.tsx"],
                    "surfaces": ["frontend"], "risk_axes": [],
                })
                large_reasons = frontend_fast_path._change_routing_reasons(root, large_output, ["large.tsx"], ["src"])
                self.assertTrue(any("non-frontend/unreadable" in reason for reason in large_reasons), large_reasons)
                invalid_utf8 = root / "src/invalid.tsx"
                invalid_utf8.parent.mkdir(exist_ok=True)
                invalid_utf8.write_bytes(b"export const value = '\xff';\n")
                invalid_output = json.dumps({
                    "schema_version": 12, "paths": ["src/invalid.tsx"],
                    "surfaces": ["frontend"], "risk_axes": [],
                })
                invalid_reasons = frontend_fast_path._change_routing_reasons(
                    root, invalid_output, ["src/invalid.tsx"], ["src"],
                )
                self.assertTrue(any("non-frontend/unreadable" in reason for reason in invalid_reasons), invalid_reasons)
                backend = root / "src/jobs/reconcile.ts"
                backend.parent.mkdir(parents=True)
                backend.write_text("export function reconcile() {}\n", encoding="utf-8")
                backend_output = json.dumps({
                    "schema_version": 12, "paths": ["src/jobs/reconcile.ts"],
                    "surfaces": ["frontend"], "risk_axes": [],
                })
                backend_reasons = frontend_fast_path._change_routing_reasons(
                    root, backend_output, ["src/jobs/reconcile.ts"], ["web/src"],
                )
                self.assertTrue(any("frontend_roots" in reason for reason in backend_reasons), backend_reasons)
                for relative, expected_axis in (
                    ("src/auth.ts", "AUTHORIZATION"),
                    ("src/api.ts", "API_CONTRACT"),
                    ("src/PaymentForm.tsx", "MONEY"),
                ):
                    risky = root / relative
                    risky.write_text("export const view = 1;\n", encoding="utf-8")
                    risky_output = json.dumps({
                        "schema_version": 12, "paths": [relative],
                        "surfaces": ["frontend"], "risk_axes": [],
                    })
                    risky_reasons = frontend_fast_path._change_routing_reasons(
                        root, risky_output, [relative], ["src"],
                    )
                    self.assertTrue(
                        any(expected_axis in reason for reason in risky_reasons),
                        (relative, risky_reasons),
                    )
            finally:
                outside.unlink(missing_ok=True)

    def test_repository_adapter_rejects_root_alias_as_frontend_root(self) -> None:
        adapter = {
            "schema_version": 12, "name": "unsafe", "source_ref": "adapter-source",
            "frontend_roots": ["./"], "capabilities": {},
        }
        with self.assertRaisesRegex(ValueError, "frontend_roots"):
            repository_adapter.validate_adapter(adapter)

    @unittest.skipUnless(sys.platform == "darwin" and runtime_evidence.shutil.which("sandbox-exec"), "macOS sandbox-exec required")
    def test_macos_repository_adapter_uses_bounded_disposable_oci_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "src").mkdir()
            adapter = {
                "schema_version": 12, "name": "isolated", "source_ref": "test",
                "frontend_roots": ["src"],
                "capabilities": {"build": {
                    "argv": [
                        sys.executable, "-c",
                        (
                            "import subprocess,sys; "
                            "subprocess.run([sys.executable,'-c',"
                            "\"from pathlib import Path; Path('built').write_text('ok')\"],check=True)"
                        ),
                    ],
                    "cwd": "src", "timeout_seconds": 10, "max_output_bytes": 4096,
                    "sandbox_image": "test/frontend@sha256:declared",
                }},
            }
            completed = {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False}
            docker_socket = root / "docker.sock"
            with patch.object(
                repository_adapter, "resolve_oci_image",
                return_value=(Path("/trusted/docker"), "sha256:" + "a" * 64, docker_socket),
            ), patch.object(repository_adapter, "run_bounded", return_value=completed) as runner, patch.object(
                repository_adapter, "cleanup_oci_container",
            ) as cleanup:
                result = repository_adapter.execute_capability(root, adapter, "build")
            self.assertEqual(0, result["result"]["exit_code"], result)
            self.assertEqual("sha256:" + "a" * 64, result["sandbox_image_id"])
            self.assertFalse((root / "src/built").exists())
            argv = runner.call_args.args[0]
            self.assertIn("--network=none", argv)
            self.assertIn("--pids-limit=256", argv)
            self.assertIn("--read-only", argv)
            mount = argv[argv.index("--mount") + 1]
            self.assertNotIn(str(root), mount)
            self.assertEqual([docker_socket], runner.call_args.kwargs["allowed_unix_sockets"])
            cidfile = Path(argv[argv.index("--cidfile") + 1])
            self.assertEqual(cidfile.parent, runner.call_args.kwargs["writable_roots"][0])
            cleanup.assert_called_once()

    def test_macos_docker_context_must_resolve_to_a_local_unix_socket(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            socket_path = Path(raw) / "docker.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(socket_path))
            try:
                responses = [
                    {"exit_code": 0, "stdout": f"unix://{socket_path}\n", "stderr": "", "timed_out": False},
                    {"exit_code": 0, "stdout": "sha256:" + "a" * 64, "stderr": "", "timed_out": False},
                ]
                with patch.object(repository_adapter, "trusted_executable", return_value=Path("/usr/local/bin/docker")), patch.object(
                    repository_adapter, "verify_macos_signature", return_value=Path("/usr/local/bin/docker"),
                ), patch.object(repository_adapter, "run_bounded", side_effect=responses):
                    _, image_id, resolved_socket = repository_adapter.resolve_oci_image("test/image@sha256:declared")
                self.assertEqual("sha256:" + "a" * 64, image_id)
                self.assertEqual(socket_path.resolve(), resolved_socket)
            finally:
                listener.close()

    def test_repository_snapshot_preserves_disk_reserve_and_container_cleanup_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            (root / "source").write_bytes(b"1234")
            insufficient = type("Disk", (), {"free": 4 + repository_adapter.MIN_SNAPSHOT_FREE_BYTES - 1})()
            with patch.object(repository_adapter.shutil, "disk_usage", return_value=insufficient):
                with self.assertRaisesRegex(ValueError, "temporary disk capacity"):
                    repository_adapter.validate_snapshot_budget(root, root)
            with self.assertRaisesRegex(ValueError, "identity was not created"):
                repository_adapter.cleanup_oci_container(Path("/trusted/docker"), root / "missing.cid")
            cidfile = root / "container.cid"
            cidfile.write_text("a" * 64, encoding="ascii")
            completed = {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False}
            survives = {"exit_code": 0, "stdout": "container", "stderr": "", "timed_out": False}
            with patch.object(repository_adapter, "run_bounded", side_effect=[completed, survives]):
                with self.assertRaisesRegex(ValueError, "survived bounded cleanup"):
                    repository_adapter.cleanup_oci_container(Path("/trusted/docker"), cidfile)
            generic_error = {
                "exit_code": 1, "stdout": "", "stderr": "Cannot connect to the Docker daemon", "timed_out": False,
            }
            with patch.object(repository_adapter, "run_bounded", return_value=generic_error):
                with self.assertRaisesRegex(ValueError, "cleanup failed"):
                    repository_adapter.cleanup_oci_container(Path("/trusted/docker"), cidfile)
            removed = {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False}
            with patch.object(
                repository_adapter, "run_bounded", side_effect=[removed, generic_error],
            ):
                with self.assertRaisesRegex(ValueError, "absence could not be verified"):
                    repository_adapter.cleanup_oci_container(Path("/trusted/docker"), cidfile)
            absent = {
                "exit_code": 1, "stdout": "", "stderr": f"Error: No such object: {'a' * 64}\n", "timed_out": False,
            }
            with patch.object(repository_adapter, "run_bounded", return_value=absent) as runner:
                repository_adapter.cleanup_oci_container(Path("/trusted/docker"), cidfile)
            self.assertEqual(2, runner.call_count)
            truncated = {
                "exit_code": 1, "stdout": "", "stderr": "noise\n[TRUNCATED at 4096 bytes]", "timed_out": False,
            }
            with patch.object(repository_adapter, "run_bounded", return_value=truncated):
                with self.assertRaisesRegex(ValueError, "output exceeded"):
                    repository_adapter.cleanup_oci_container(Path("/trusted/docker"), cidfile)

    @unittest.skipUnless(
        sys.platform == "darwin" or (sys.platform.startswith("linux") and runtime_evidence.shutil.which("bwrap")),
        "supported OS command sandbox is unavailable",
    )
    def test_repository_controlled_command_cannot_read_convergence_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            codex_home = Path(raw) / "codex"
            key = codex_home / "dlv-feature/convergence-rs256.pem"
            key.parent.mkdir(parents=True)
            key.write_text("secret authority", encoding="utf-8")
            key.chmod(0o600)
            with patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}, clear=False):
                result = runtime_evidence.run_bounded(
                    [sys.executable, "-c", f"from pathlib import Path; print(Path({str(key)!r}).read_text())"],
                    Path(raw), 10,
                )
            self.assertNotEqual(0, result["exit_code"])
            self.assertNotIn("secret authority", result["stdout"] + result["stderr"])

    @unittest.skipIf(os.name == "nt", "POSIX executable ownership and mode contract")
    def test_openssl_resolution_skips_path_controlled_executable_for_system_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fake = Path(raw) / "openssl"
            marker = Path(raw) / "invoked"
            fake.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
            fake.chmod(0o755)
            delivery_governance._trusted_openssl.cache_clear()
            try:
                with patch.dict(os.environ, {"PATH": f"{raw}{os.pathsep}{os.environ.get('PATH', '')}"}, clear=False):
                    resolved = Path(delivery_governance._trusted_openssl())
                    self.assertNotEqual(fake.resolve(), resolved)
                    self.assertEqual(0, resolved.stat().st_uid)
                self.assertFalse(marker.exists())
            finally:
                delivery_governance._trusted_openssl.cache_clear()

    def test_fast_path_kernel_git_snapshot_excludes_dlv_owned_artifacts(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            frontend = root / "web/src/panel.tsx"
            frontend.parent.mkdir(parents=True)
            frontend.write_text("export const panel = 1;\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(
                ["git", "-c", "user.name=DLV Test", "-c", "user.email=dlv@example.invalid", "commit", "-qm", "baseline"],
                cwd=root, check=True,
            )
            frontend.write_text("export const panel = 2;\n", encoding="utf-8")
            state_path = root / "delivery/cross-domain-feature/state.json"
            state_path.write_text(state_path.read_text() + "\n", encoding="utf-8")
            write_json(root / ".dlv/generated-noise.json", {"kernel": True})
            snapshot, error = frontend_fast_path.kernel_git_snapshot(root)
            self.assertIsNone(error)
            self.assertEqual(["web/src/panel.tsx"], snapshot["paths"])

    def test_fast_path_kernel_git_snapshot_includes_both_rename_paths(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            source = root / "backend/service.py"
            source.parent.mkdir(parents=True)
            source.write_text("value = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(
                ["git", "-c", "user.name=DLV Test", "-c", "user.email=dlv@example.invalid", "commit", "-qm", "rename baseline"],
                cwd=root, check=True,
            )
            destination = root / "frontend/view.ts"
            destination.parent.mkdir(parents=True)
            subprocess.run(["git", "mv", str(source), str(destination)], cwd=root, check=True)
            snapshot, error = frontend_fast_path.kernel_git_snapshot(root)
            self.assertIsNone(error)
            self.assertEqual(["backend/service.py", "frontend/view.ts"], snapshot["paths"])
            output = json.dumps({
                "schema_version": 12, "paths": snapshot["paths"],
                "surfaces": ["frontend"], "risk_axes": [],
            })
            reasons = frontend_fast_path._change_routing_reasons(
                root, output, snapshot["paths"], ["frontend"],
            )
            self.assertTrue(any("escapes declared frontend_roots" in reason for reason in reasons), reasons)

    def test_v11_to_v12_migration_archives_mutable_truth_without_promoting_ready(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            directory = root / "delivery/cross-domain-feature"
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["schema_version"] = 11
            graph.pop("claims")
            graph["metadata"].pop("review_budget")
            graph["metadata"].pop("delivery_mode")
            write_json(directory / "delivery-graph.json", graph)
            source_path = directory / "source-revisions/SRC-001.json"
            source = json.loads(source_path.read_text())
            source["schema_version"] = 11
            write_json(source_path, source)
            write_json(directory / "state.json", {"schema_version": 11, "readiness": {"status": "ready"}})
            lock_path = root / ".dlv/runs/cross-domain-feature/.feature.lock"
            before_lock_inode = lock_path.stat().st_ino
            upgrade_v11_to_v12.upgrade(root, "cross-domain-feature", apply=True)
            migrated = delivery_graph.load_graph(root, "cross-domain-feature")
            state = delivery_graph.load_state(directory / "state.json")
            self.assertEqual(12, migrated["schema_version"])
            self.assertTrue(migrated["claims"])
            self.assertEqual({}, state["attestations"])
            self.assertNotEqual("ready", state["readiness"]["status"])
            self.assertTrue((directory / "archive-v11/state.json").is_file())
            self.assertTrue(lock_path.is_file())
            self.assertEqual(before_lock_inode, lock_path.stat().st_ino)

    def test_v11_to_v12_migration_reloads_owner_edits_after_acquiring_lock(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            directory = root / "delivery/cross-domain-feature"
            graph_path = directory / "delivery-graph.json"
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["schema_version"] = 11
            graph.pop("claims")
            graph["metadata"].pop("review_budget")
            graph["metadata"].pop("delivery_mode")
            write_json(graph_path, graph)
            source_path = directory / "source-revisions/SRC-001.json"
            source = json.loads(source_path.read_text())
            source["schema_version"] = 11
            write_json(source_path, source)

            class EditingLock:
                def __enter__(self) -> None:
                    current = json.loads(graph_path.read_text())
                    current["title"] = "Owner edit while migration waited"
                    write_json(graph_path, current)

                def __exit__(self, *_args: object) -> None:
                    return None

            with patch.object(upgrade_v11_to_v12, "exclusive_file_lock", return_value=EditingLock()):
                migrated = upgrade_v11_to_v12.upgrade(root, "cross-domain-feature", apply=True)
            self.assertEqual("Owner edit while migration waited", migrated["title"])
            self.assertEqual("Owner edit while migration waited", delivery_graph.load_graph(root, "cross-domain-feature")["title"])

    def test_v11_to_v12_migration_rolls_back_and_remains_retryable_after_compile_failure(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            directory = root / "delivery/cross-domain-feature"
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["schema_version"] = 11
            graph.pop("claims")
            graph["metadata"].pop("review_budget")
            graph["metadata"].pop("delivery_mode")
            write_json(directory / "delivery-graph.json", graph)
            source_path = directory / "source-revisions/SRC-001.json"
            source = json.loads(source_path.read_text())
            source["schema_version"] = 11
            write_json(source_path, source)
            original_graph = (directory / "delivery-graph.json").read_bytes()
            original_source = source_path.read_bytes()
            with patch.object(upgrade_v11_to_v12, "compile_graph", side_effect=OSError("injected compile failure")):
                with self.assertRaisesRegex(OSError, "injected compile failure"):
                    upgrade_v11_to_v12.upgrade(root, "cross-domain-feature", apply=True)
            self.assertEqual(original_graph, (directory / "delivery-graph.json").read_bytes())
            self.assertEqual(original_source, source_path.read_bytes())
            self.assertFalse((directory / "archive-v11").exists())
            upgrade_v11_to_v12.upgrade(root, "cross-domain-feature", apply=True)
            self.assertEqual(12, delivery_graph.load_graph(root, "cross-domain-feature")["schema_version"])

    @unittest.skipUnless(Path("/dev/fd").is_dir(), "open descriptor inventory is unavailable")
    def test_v11_to_v12_migration_closes_source_fd_when_archive_target_open_fails(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            directory = root / "delivery/cross-domain-feature"
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["schema_version"] = 11
            graph.pop("claims")
            graph["metadata"].pop("review_budget")
            graph["metadata"].pop("delivery_mode")
            write_json(directory / "delivery-graph.json", graph)
            source_path = directory / "source-revisions/SRC-001.json"
            source = json.loads(source_path.read_text())
            source["schema_version"] = 11
            write_json(source_path, source)
            review_directory = root / ".dlv/reviews/cross-domain-feature"
            write_json(review_directory / "existing.json", {"schema_version": 11})
            original_open = upgrade_v11_to_v12.os.open
            review_opens = 0

            def fail_archive_target_open(path: object, *args: object, **kwargs: object) -> int:
                nonlocal review_opens
                if Path(os.fspath(path)).name == "reviews":
                    review_opens += 1
                    if review_opens == 2:
                        raise OSError("injected archive target open failure")
                return original_open(path, *args, **kwargs)

            before = len(list(Path("/dev/fd").iterdir()))
            with patch.object(upgrade_v11_to_v12.os, "open", side_effect=fail_archive_target_open):
                with self.assertRaisesRegex(OSError, "injected archive target open failure"):
                    upgrade_v11_to_v12.upgrade(root, "cross-domain-feature", apply=True)
            self.assertEqual(before, len(list(Path("/dev/fd").iterdir())))

    @unittest.skipIf(os.name == "nt", "symlink semantics differ on Windows")
    def test_v11_to_v12_migration_rejects_symlinked_staging_parent(self) -> None:
        temporary, root = self.make_root()
        with temporary, tempfile.TemporaryDirectory() as external_raw:
            directory = root / "delivery/cross-domain-feature"
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["schema_version"] = 11
            graph.pop("claims")
            graph["metadata"].pop("review_budget")
            graph["metadata"].pop("delivery_mode")
            write_json(directory / "delivery-graph.json", graph)
            source_path = directory / "source-revisions/SRC-001.json"
            source = json.loads(source_path.read_text())
            source["schema_version"] = 11
            write_json(source_path, source)
            external = Path(external_raw)
            staging_parent = root / ".dlv/upgrades/cross-domain-feature"
            staging_parent.parent.mkdir(parents=True, exist_ok=True)
            staging_parent.symlink_to(external, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "staging directory.*symlink"):
                upgrade_v11_to_v12.upgrade(root, "cross-domain-feature", apply=True)
            self.assertEqual([], list(external.iterdir()))

    @unittest.skipIf(os.name == "nt", "directory-fd migration contract is POSIX-only")
    def test_v11_to_v12_staging_parent_swap_cannot_redirect_archive_writes(self) -> None:
        temporary, root = self.make_root()
        with temporary, tempfile.TemporaryDirectory() as external_raw:
            directory = root / "delivery/cross-domain-feature"
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["schema_version"] = 11
            graph.pop("claims")
            graph["metadata"].pop("review_budget")
            graph["metadata"].pop("delivery_mode")
            write_json(directory / "delivery-graph.json", graph)
            source_path = directory / "source-revisions/SRC-001.json"
            source = json.loads(source_path.read_text())
            source["schema_version"] = 11
            write_json(source_path, source)
            staging_parent = root / ".dlv/upgrades/cross-domain-feature"
            displaced = root / ".dlv/upgrades/cross-domain-feature.pinned"
            external = Path(external_raw)
            original_copy = upgrade_v11_to_v12._secure_copy_directory_fds
            swapped = False

            def swap_then_copy(source_fd: int, destination_fd: int) -> None:
                nonlocal swapped
                if not swapped:
                    swapped = True
                    staging_parent.rename(displaced)
                    staging_parent.symlink_to(external, target_is_directory=True)
                original_copy(source_fd, destination_fd)

            with patch.object(upgrade_v11_to_v12, "_secure_copy_directory_fds", side_effect=swap_then_copy):
                with self.assertRaisesRegex(ValueError, "must not be relocated through a symlink"):
                    upgrade_v11_to_v12.upgrade(root, "cross-domain-feature", apply=True)
            self.assertEqual([], list(external.iterdir()))
            self.assertTrue((directory / "archive-v11/manifest.json").is_file())

    def test_v11_to_v12_migration_rejects_partial_v12_after_hard_interrupt(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            root = root.resolve()
            directory = root / "delivery/cross-domain-feature"
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["schema_version"] = 11
            graph.pop("claims")
            graph.pop("claim_successions")
            graph["metadata"].pop("review_budget")
            graph["metadata"].pop("delivery_mode")
            write_json(directory / "delivery-graph.json", graph)
            source_path = directory / "source-revisions/SRC-001.json"
            source = json.loads(source_path.read_text())
            source["schema_version"] = 11
            write_json(source_path, source)
            write_json(directory / "state.json", {"schema_version": 11, "readiness": {"status": "ready"}})
            staging = root / ".dlv/upgrades/cross-domain-feature/archive-v11.staging"
            staging.parent.mkdir(parents=True, exist_ok=True)
            upgrade_v11_to_v12.shutil.copytree(directory, staging)
            write_json(staging / "manifest.json", upgrade_v11_to_v12._archive_manifest(staging, "cross-domain-feature"))
            archive = directory / "archive-v11"
            upgrade_v11_to_v12.os.replace(staging, archive)
            candidate = upgrade_v11_to_v12.migrated_graph(graph)
            source["schema_version"] = 12
            write_json(source_path, source)
            write_json(directory / "delivery-graph.json", candidate)
            (directory / "state.json").unlink()
            before_graph = (directory / "delivery-graph.json").read_bytes()
            before_source = source_path.read_bytes()
            with self.assertRaisesRegex(ValueError, "partial schema-v12 recovery is not automatic"):
                upgrade_v11_to_v12.upgrade(root, "cross-domain-feature", apply=True)
            self.assertEqual(12, delivery_graph.load_graph(root, "cross-domain-feature")["schema_version"])
            self.assertFalse((directory / "state.json").exists())
            self.assertEqual(before_graph, (directory / "delivery-graph.json").read_bytes())
            self.assertEqual(before_source, source_path.read_bytes())

    def test_v11_to_v12_recovery_preserves_owner_edit_after_archive_promotion(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            directory = root / "delivery/cross-domain-feature"
            graph = delivery_graph.load_graph(root, "cross-domain-feature")
            graph["schema_version"] = 11
            graph.pop("claims")
            graph.pop("claim_successions")
            graph["metadata"].pop("review_budget")
            graph["metadata"].pop("delivery_mode")
            write_json(directory / "delivery-graph.json", graph)
            source_path = directory / "source-revisions/SRC-001.json"
            source = json.loads(source_path.read_text())
            source["schema_version"] = 11
            write_json(source_path, source)
            staging = root / ".dlv/upgrades/cross-domain-feature/archive-v11.staging"
            staging.parent.mkdir(parents=True, exist_ok=True)
            upgrade_v11_to_v12.shutil.copytree(directory, staging)
            write_json(staging / "manifest.json", upgrade_v11_to_v12._archive_manifest(staging, "cross-domain-feature"))
            upgrade_v11_to_v12.os.replace(staging, directory / "archive-v11")
            graph["title"] = "Owner edit after archive promotion"
            write_json(directory / "delivery-graph.json", graph)
            with self.assertRaisesRegex(ValueError, "diverged from the promoted archive"):
                upgrade_v11_to_v12.upgrade(root, "cross-domain-feature", apply=True)
            self.assertEqual(
                "Owner edit after archive promotion",
                delivery_graph.load_graph(root, "cross-domain-feature")["title"],
            )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO is unavailable on this platform")
    def test_v11_to_v12_migration_rejects_special_files_before_copy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "source"
            source.mkdir()
            os.mkfifo(source / "blocked.fifo")
            with self.assertRaisesRegex(ValueError, "regular files/directories"):
                upgrade_v11_to_v12._reject_symlinks(source)

    def test_v9_import_preserves_broad_code_trace_as_untrusted_metadata_not_proof_edge(self) -> None:
        temporary, root, directory = self.make_v9_root()
        with temporary:
            _, state = delivery_proof.extract_state(directory / "state.md")
            state["proof_contract"]["obligations"][0]["trace_ids"] = ["D01"]
            (directory / "state.md").write_text(
                "# Legacy delivery state\n\n<!-- DLV_STATE_START -->\n```json\n"
                + json.dumps(state, ensure_ascii=False, indent=2)
                + "\n```\n<!-- DLV_STATE_END -->\n",
                encoding="utf-8",
            )
            graph = upgrade_v9_to_v10.convert(root, "legacy-feature")
            proof = next(item for item in graph["nodes"] if item["type"] == "Proof")
            change = next(item for item in graph["nodes"] if item.get("attributes", {}).get("legacy_id") == "D01")
            self.assertEqual(["D01"], proof["attributes"]["legacy_trace_ids"])
            self.assertNotIn(
                {"source": proof["id"], "type": "proves", "target": change["id"]},
                graph["edges"],
            )

    def test_v9_upgrade_retries_after_partial_archive_write(self) -> None:
        temporary, root, directory = self.make_v9_root()
        with temporary:
            original_write = upgrade_v9_to_v10.atomic_write_bytes
            calls = 0

            def fail_second_archive(path: Path, content: bytes) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected archive failure")
                original_write(path, content)

            with patch.object(upgrade_v9_to_v10, "atomic_write_bytes", side_effect=fail_second_archive):
                with self.assertRaisesRegex(OSError, "injected archive failure"):
                    upgrade_v9_to_v10.apply_upgrade(root, "legacy-feature")
            self.assertTrue((directory / "state.md").is_file())
            upgrade_v9_to_v10.apply_upgrade(root, "legacy-feature")
            self.assertFalse((directory / "state.md").exists())

    @unittest.skipIf(os.name == "nt", "symlink semantics differ on Windows")
    def test_v9_upgrade_rejects_symlinked_legacy_source(self) -> None:
        temporary, root, directory = self.make_v9_root()
        with temporary:
            source = directory / "prd.md"
            outside = root / "outside-prd.md"
            outside.write_bytes(source.read_bytes())
            source.unlink()
            source.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                upgrade_v9_to_v10.apply_upgrade(root, "legacy-feature")

    def test_v9_to_v10_recovery_finishes_interrupted_state_cleanup(self) -> None:
        temporary, root, directory = self.make_v9_root()
        with temporary:
            original_state = (directory / "state.md").read_text(encoding="utf-8")
            upgrade_v9_to_v10.apply_upgrade(root, "legacy-feature")
            (directory / "state.md").write_text(original_state, encoding="utf-8")
            upgrade_v9_to_v10.apply_upgrade(root, "legacy-feature")
            self.assertFalse((directory / "state.md").exists())
            self.assertEqual(12, json.loads((directory / "delivery-graph.json").read_text())["schema_version"])

    def test_v9_to_v10_recovery_rejects_changed_source_or_archive(self) -> None:
        temporary, root, directory = self.make_v9_root()
        with temporary:
            graph = upgrade_v9_to_v10.convert(root, "legacy-feature")
            write_json(directory / "delivery-graph.json", graph)
            state_path = directory / "state.md"
            state_path.write_text(state_path.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "state changed"):
                upgrade_v9_to_v10.apply_upgrade(root, "legacy-feature")

        temporary, root, directory = self.make_v9_root()
        with temporary:
            graph = upgrade_v9_to_v10.convert(root, "legacy-feature")
            write_json(directory / "delivery-graph.json", graph)
            archive_file = root / ".dlv/upgrades/legacy-feature/schema-v9-candidates/state.md"
            archive_file.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "archive diverges"):
                upgrade_v9_to_v10.apply_upgrade(root, "legacy-feature")

    def test_v9_upgrade_preserves_crlf_source_bytes_before_cleanup(self) -> None:
        temporary, root, directory = self.make_v9_root()
        with temporary:
            source = directory / "prd.md"
            original = source.read_text(encoding="utf-8").replace("\n", "\r\n").encode("utf-8")
            source.write_bytes(original)
            upgrade_v9_to_v10.apply_upgrade(root, "legacy-feature")
            archived = root / ".dlv/upgrades/legacy-feature/schema-v9-candidates/prd.md"
            self.assertEqual(original, archived.read_bytes())

    def test_v9_upgrade_removes_legacy_verification_and_preserves_concurrent_state_edit(self) -> None:
        temporary, root, directory = self.make_v9_root()
        with temporary:
            (directory / "verification.md").write_text("DELIVERY COMPLETE: legacy PASS\n", encoding="utf-8")
            upgrade_v9_to_v10.apply_upgrade(root, "legacy-feature")
            self.assertFalse((directory / "verification.md").exists())
            self.assertFalse(any("verification.md" in error for error in graph_validation.validate(root, "legacy-feature")))

        temporary, root, directory = self.make_v9_root()
        with temporary:
            original_compile = upgrade_v9_to_v10.compile_graph

            def compile_then_edit(*args: object, **kwargs: object) -> dict:
                value = original_compile(*args, **kwargs)
                state_path = directory / "state.md"
                state_path.write_text(state_path.read_text(encoding="utf-8") + "\nconcurrent edit\n", encoding="utf-8")
                return value

            with patch.object(upgrade_v9_to_v10, "compile_graph", side_effect=compile_then_edit):
                with self.assertRaisesRegex(ValueError, "state changed during"):
                    upgrade_v9_to_v10.apply_upgrade(root, "legacy-feature")
            self.assertTrue((directory / "state.md").read_text(encoding="utf-8").endswith("concurrent edit\n"))

    def test_v9_upgrade_preserves_concurrent_legacy_and_archive_edits(self) -> None:
        temporary, root, directory = self.make_v9_root()
        with temporary:
            original_write = delivery_graph.atomic_write_text
            changed = False

            def edit_guarded_source(path: Path, content: str) -> None:
                nonlocal changed
                original_write(path, content)
                if not changed and path.name == "prd.md":
                    changed = True
                    target = directory / "code-spec.md"
                    target.write_text(target.read_text(encoding="utf-8") + "\nconcurrent edit\n", encoding="utf-8")

            with patch.object(delivery_graph, "atomic_write_text", side_effect=edit_guarded_source):
                with self.assertRaisesRegex(ValueError, "changed during compilation: code-spec.md"):
                    upgrade_v9_to_v10.apply_upgrade(root, "legacy-feature")
            self.assertTrue((directory / "state.md").is_file())
            self.assertTrue((directory / "code-spec.md").read_text(encoding="utf-8").endswith("concurrent edit\n"))

        temporary, root, directory = self.make_v9_root()
        with temporary:
            original_compile = upgrade_v9_to_v10.compile_graph

            def compile_then_edit_archive(*args: object, **kwargs: object) -> dict:
                value = original_compile(*args, **kwargs)
                archived = root / ".dlv/upgrades/legacy-feature/schema-v9-candidates/prd.md"
                archived.write_text(archived.read_text(encoding="utf-8") + "\nconcurrent edit\n", encoding="utf-8")
                return value

            with patch.object(upgrade_v9_to_v10, "compile_graph", side_effect=compile_then_edit_archive):
                with self.assertRaisesRegex(ValueError, "archive changed"):
                    upgrade_v9_to_v10.apply_upgrade(root, "legacy-feature")
            self.assertTrue((directory / "state.md").is_file())


if __name__ == "__main__":
    unittest.main()
