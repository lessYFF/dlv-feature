#!/usr/bin/env python3
"""Schema-v10 Delivery Graph regression, mutation, and security tests."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import delivery_graph
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
import scope_revision
import finding_ledger
from delivery_governance import apply_review_findings, empty_ledger, finding_summary, load_ledger, write_ledger


def node(node_id: str, node_type: str, title: str, statement: str, **attributes: object) -> dict:
    value = {"id": node_id, "type": node_type, "title": title, "statement": statement}
    if attributes:
        value["attributes"] = attributes
    return value


def edge(source: str, relation: str, target: str) -> dict:
    return {"source": source, "type": relation, "target": target}


def valid_graph(feature_id: str = "cross-domain-feature", *, runtime: str = "python") -> dict:
    runner = {
        "argv": [sys.executable, "-c", "import json; print(json.dumps({'ok': True}))"],
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
        node("ENV-001", "Environment", "Python runtime", "Execute in the target Python runtime", target="python runtime", spec={"runtime": runtime, "preflight": []}),
        node("TST-001", "Test", "Behavior test", "Test success and rejection paths"),
        node("PO-001", "Proof", "Runtime proof", "Prove the observable result in the target runtime", proof_type="boundary", surface="domain operation", critical=True, runner=runner),
        node("ASRT-001", "Assertion", "Result assertion", "The result readback is true", oracle={"kind": "json_path", "source": "/observation/ok", "operator": "eq", "expected": True}),
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
        edge("TST-001", "runs_in", "ENV-001"),
        edge("PO-001", "proves", "AC-001"),
        edge("PO-001", "proves", "EX-001"),
        edge("PO-001", "proves", "TST-001"),
        edge("PO-001", "proves", "BND-001"),
        edge("PO-001", "proves", "ST-001"),
        edge("PO-001", "runs_in", "ENV-001"),
        edge("PO-001", "mitigates", "RISK-001"),
        edge("ASRT-001", "proves", "PO-001"),
    ]
    graph = delivery_graph.default_graph(feature_id, "Cross-domain feature")
    graph["nodes"] = nodes
    graph["edges"] = edges
    return graph


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


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
    def fake_semantic_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        result_path = Path(argv[argv.index("--output-last-message") + 1])
        write_json(result_path, {
            "verdict": "PASS",
            "checks": [{
                "id": "fixture-consistency", "status": "PASS",
                "evidence": "fixture graph is semantically coherent",
            }],
            "findings": [],
        })
        return subprocess.CompletedProcess(argv, 0, stdout='{"type":"fixture.semantic.review"}\n', stderr="")

    def make_root(self, feature_id: str = "cross-domain-feature") -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        delivery_graph.initialize(root, feature_id, "Cross-domain feature")
        directory = root / "delivery" / feature_id
        write_json(directory / "delivery-graph.json", valid_graph(feature_id))
        return temporary, root

    def review_all(self, root: Path, feature_id: str = "cross-domain-feature") -> None:
        delivery_graph.compile_graph(root, feature_id)
        with patch.object(graph_review.subprocess, "run", side_effect=self.fake_semantic_run):
            graph_review.run_isolated_readiness_review(root, feature_id, "readiness-01")

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
        graph["prototype"] = {
            "status": "contractual", "path": "prototype.html",
            "sha256": hashlib.sha256(prototype.read_bytes()).hexdigest(),
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
            node("ASRT-002", "Assertion", "Geometry", "Geometry must match", oracle={"kind": "json_path", "source": "/observation/geometry_diff_max", "operator": "eq", "expected": 0}),
            node("ASRT-003", "Assertion", "Forbidden", "Forbidden elements must be absent", oracle={"kind": "json_path", "source": "/observation/forbidden_elements_count", "operator": "eq", "expected": 0}),
        ])
        graph["edges"].extend([
            edge("ASRT-002", "proves", "PO-001"), edge("ASRT-003", "proves", "PO-001"),
        ])
        write_json(directory / "delivery-graph.json", graph)
        return profile, paths

    @staticmethod
    def visual_command_result(graph: dict, profile: dict[str, object], paths: dict[str, Path], **overrides: object) -> dict:
        observation = {
            "anchor_paths": {role: str(path) for role, path in paths.items()},
            "prototype_sha256": graph["prototype"]["sha256"],
            "capture_profile": profile,
            "pixel_diff_ratio": 0.0,
            "geometry_diff_max": 0,
            "forbidden_elements_count": 0,
        }
        observation.update(overrides)
        return {
            "exit_code": 0, "stdout": json.dumps(observation), "stderr": "", "timed_out": False,
        }

    def test_valid_cross_type_graph_has_no_structural_or_semantic_issues(self) -> None:
        graph = valid_graph()
        self.assertEqual([], delivery_graph.structural_errors(graph, graph["feature_id"]))
        self.assertEqual([], delivery_graph.semantic_issues(graph))

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

    def test_initialization_creates_v11_canonical_artifacts_and_initial_source_revision(self) -> None:
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

    def test_stable_entrypoints_dispatch_schema_v10_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            init = subprocess.run(
                [sys.executable, str(SCRIPTS / "init_feature.py"), "dispatch-feature", "--root", str(root)],
                capture_output=True, text=True,
            )
            self.assertEqual(0, init.returncode, init.stdout + init.stderr)
            graph_path = root / "delivery/dispatch-feature/delivery-graph.json"
            write_json(graph_path, valid_graph("dispatch-feature"))
            for command in (
                [sys.executable, str(SCRIPTS / "delivery_graph.py"), "compile", "dispatch-feature", "--root", str(root)],
                [sys.executable, str(SCRIPTS / "delivery_graph.py"), "compile", "dispatch-feature", "--root", str(root), "--check"],
                [sys.executable, str(SCRIPTS / "invalidate_downstream.py"), "dispatch-feature", "--root", str(root), "--changed-node", "SYM-001"],
            ):
                completed = subprocess.run(command, capture_output=True, text=True)
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
            write_json(environment, {"runtime": "python", "preflight": []})
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

    def test_node_and_edge_order_do_not_change_hashes(self) -> None:
        graph = valid_graph()
        reordered = copy.deepcopy(graph)
        reordered["nodes"].reverse()
        reordered["edges"].reverse()
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
                "comments": ["No server-side recalculation."], "attachments": [],
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
                    "title": title, "description": "Local display behavior.", "comments": [], "attachments": [],
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
            node("ASRT-001", "Assertion", "Exists", "Output exists", oracle={"kind": "json_path", "source": "/observation", "operator": "exists"}),
        ]
        graph["edges"] = [
            edge("BHV-001", "derives_from", "REQ-001"), edge("AC-001", "derives_from", "BHV-001"),
            edge("CHG-001", "changes", "BHV-001"), edge("SYM-001", "depends_on", "CHG-001"),
            edge("TST-001", "tests", "AC-001"), edge("TST-001", "runs_in", "ENV-001"),
            edge("PO-001", "proves", "AC-001"), edge("PO-001", "runs_in", "ENV-001"), edge("ASRT-001", "proves", "PO-001"),
        ]
        self.assertEqual(
            ["change-traceability", "product-contract", "proof-coverage"],
            delivery_graph.active_review_lenses(graph),
        )
        self.assertNotIn("ARCH_NO_CLAIM", {issue["code"] for issue in delivery_graph.semantic_issues(graph)})

    def test_finding_ledger_deduplicates_root_cause_and_omission_keeps_blocker_open(self) -> None:
        ledger = empty_ledger("feature")
        findings = [{
            "id": "NEW", "severity": "major", "status": "OPEN", "statement": "Money state is ambiguous",
            "evidence": "ST-001", "risk_path": "MONEY → SETTLED", "root_cause": "zero-net transition ambiguity",
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

    def test_v10_to_v11_migration_archives_mutable_records_and_resets_claims(self) -> None:
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
            self.assertEqual((11, "SRC-001"), (migrated["schema_version"], migrated["source_revision"]))
            self.assertTrue((root / ".dlv/upgrades/legacy-v10/schema-v10-archive/delivery-graph.json").is_file())
            self.assertEqual({}, delivery_graph.load_state(directory / "state.json")["attestations"])

    def test_dependency_and_impact_closures_are_exact(self) -> None:
        graph = valid_graph()
        impacted = delivery_graph.impact_closure(graph, {"DEC-001"})
        self.assertEqual({"DEC-001", "CHG-001", "SYM-001"}, impacted)
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
        units = [unit for unit in delivery_graph.review_units(graph).values() if unit["lens"] == "boundary-state-safety"]
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
            for unit in delivery_graph.lens_components(graph, "boundary-state-safety")
            if unit["root_node_ids"] in (["RISK-001"], ["RISK-002"])
        }
        self.assertEqual({"RISK-001", "RISK-002"}, set(before))
        self.assertNotIn("RISK-002", before["RISK-001"]["node_ids"])
        self.assertNotIn("RISK-001", before["RISK-002"]["node_ids"])
        next(item for item in graph["nodes"] if item["id"] == "RISK-002")["statement"] += " visibly"
        after = {
            unit["root_node_ids"][0]: unit
            for unit in delivery_graph.lens_components(graph, "boundary-state-safety")
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
        units = delivery_graph.lens_components(graph, "proof-coverage")
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
        self.assertNotIn("ARCH_NO_CLAIM", codes)
        self.assertTrue({"IMPLEMENTATION_NO_CHANGE", "IMPLEMENTATION_NO_SYMBOL"} <= codes)

    def test_completed_prototype_requires_canonical_zero_difference_visual_proof(self) -> None:
        graph = valid_graph()
        graph["prototype"] = {"status": "contractual", "path": "prototype.html", "sha256": "0" * 64}
        codes = {item["code"] for item in delivery_graph.semantic_issues(graph, "proof-coverage")}
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
            node("ASRT-002", "Assertion", "Geometry", "Geometry must match", oracle={"kind": "json_path", "source": "/observation/geometry_diff_max", "operator": "eq", "expected": 0}),
            node("ASRT-003", "Assertion", "Forbidden", "Forbidden elements must be absent", oracle={"kind": "json_path", "source": "/observation/forbidden_elements_count", "operator": "eq", "expected": 0}),
        ])
        graph["edges"].extend([
            edge("ASRT-002", "proves", "PO-001"), edge("ASRT-003", "proves", "PO-001"),
        ])
        codes = {item["code"] for item in delivery_graph.semantic_issues(graph, "proof-coverage")}
        self.assertIn("VISUAL_ASSERTIONS_INCOMPLETE", codes)
        assertion["attributes"]["oracle"] = {
            "kind": "json_path", "source": "/observation/pixel_diff_ratio",
            "operator": "eq", "expected": 0.0,
        }
        codes = {item["code"] for item in delivery_graph.semantic_issues(graph, "proof-coverage")}
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
            with patch.object(graph_review.subprocess, "run", side_effect=self.fake_semantic_run) as reviewer:
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
            boundary_units = [unit_id for unit_id, unit in delivery_graph.review_units(graph).items() if unit["lens"] == "boundary-state-safety"]
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
            self.assertIn(self.unit_id(graph, "product-contract"), state["attestations"])
            self.assertNotIn(self.unit_id(graph, "fact-ownership"), state["attestations"])
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
                if unit["lens"] == "change-traceability" and unit_id != changed_unit
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
            with patch.object(graph_review.subprocess, "run", side_effect=self.fake_semantic_run) as reviewer:
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
            self.assertIn(self.unit_id(graph, "product-contract"), state["attestations"])
            self.assertNotIn(self.unit_id(graph, "fact-ownership"), state["attestations"])
            affected_change_units = [
                unit_id for unit_id, unit in delivery_graph.review_units(graph).items()
                if unit["lens"] == "change-traceability" and "FACT-001" in unit["node_ids"]
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
            }
            write_json(graph_path, graph)
            self.review_all(root)
            prior_unit = self.unit_id(graph, "product-contract")
            prior = delivery_graph.load_state(directory / "state.json")["attestations"][prior_unit]
            prototype.write_text("<main>version two</main>", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Prototype fingerprint"):
                delivery_graph.compile_graph(root, "cross-domain-feature")
            graph["prototype"]["sha256"] = delivery_graph.file_digest(prototype)
            write_json(graph_path, graph)
            delivery_graph.compile_graph(root, "cross-domain-feature")
            state = delivery_graph.load_state(directory / "state.json")
            current_unit = self.unit_id(graph, "product-contract")
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
            record = next((root / ".dlv/reviews/cross-domain-feature").glob("readiness-01.product-contract--*.json"))
            value = json.loads(record.read_text())
            value["verdict"] = "BLOCKED"
            write_json(record, value)
            errors = graph_validation.validate(root, "cross-domain-feature")
            self.assertTrue(any("record is missing or stale" in error for error in errors), errors)

    def test_isolated_semantic_lens_binds_immutable_transcript(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            delivery_graph.compile_graph(root, "cross-domain-feature")

            def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                self.assertIn("--skip-git-repo-check", argv)
                self.assertNotEqual(str(root), argv[argv.index("--cd") + 1])
                result_path = Path(argv[argv.index("--output-last-message") + 1])
                write_json(result_path, {
                    "verdict": "PASS",
                    "checks": [{"id": "semantic-consistency", "status": "PASS", "evidence": "REQ-001 → BHV-001 → AC-001 is concrete and consistent"}],
                    "findings": [],
                })
                return subprocess.CompletedProcess(argv, 0, stdout='{"type":"turn.completed"}\n', stderr="")

            with patch.object(graph_review.subprocess, "run", side_effect=fake_run):
                graph_review.run_isolated_readiness_review(root, "cross-domain-feature", "semantic-01")
            state = delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            unit_id = self.unit_id(delivery_graph.load_graph(root, "cross-domain-feature"), "product-contract")
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
            unit = delivery_graph.review_units(graph)[self.unit_id(graph, "product-contract")]
            with patch.object(
                graph_review.subprocess, "run",
                side_effect=subprocess.TimeoutExpired(["codex", "exec"], 900),
            ):
                with self.assertRaisesRegex(ValueError, "timed out after 900 seconds"):
                    graph_review._run_semantic_unit(
                        root, "cross-domain-feature", graph, unit, "timeout-review",
                    )
            failed = subprocess.CompletedProcess(
                ["codex", "exec"], 7, stdout="partial output", stderr="review failed",
            )
            with patch.object(graph_review.subprocess, "run", return_value=failed):
                with self.assertRaisesRegex(ValueError, "semantic lens product-contract failed"):
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
        unit = delivery_graph.review_units(graph)[self.unit_id(graph, "product-contract")]
        record = graph_review.evaluate_unit(graph, unit, "semantic-bad", semantic)
        self.assertEqual("BLOCKED", record["verdict"])

    def test_feature_and_review_path_traversal_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with self.assertRaises(ValueError):
                delivery_graph.feature_dir(root, "../escape")
        graph = valid_graph()
        with self.assertRaisesRegex(ValueError, "review-run-id"):
            graph_review.record_readiness(Path("."), graph["feature_id"], "../escape")
        temporary, root = self.make_root()
        with temporary, patch.object(graph_review.subprocess, "run") as run:
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
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, {"runtime": "python", "preflight": []})
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
            write_json(environment, {"runtime": "python", "preflight": []})
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
            write_json(environment, {"runtime": "python", "preflight": []})
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
            write_json(environment, {"runtime": "python", "preflight": []})
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
            write_json(environment, {"runtime": "browser", "preflight": []})
            graph_verification.start("cross-domain-feature", root, "run-visual", [f"ENV-001={environment}"])
            write_json(result, {"po_id": "PO-001", "proof_type": "visual", "outcome": "evaluate", "anchors": []})
            completed = self.visual_command_result(graph, profile, paths)
            with patch.object(graph_verification, "run_bounded", return_value=completed):
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
            write_json(environment, {"runtime": "browser", "preflight": []})
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
                return_value=self.visual_command_result(graph, profile, paths),
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
                    write_json(environment, {"runtime": "browser", "preflight": []})
                    graph_verification.start("cross-domain-feature", root, f"run-visual-{field}", [f"ENV-001={environment}"])
                    write_json(result, {"po_id": "PO-001", "proof_type": "visual", "outcome": "evaluate", "anchors": []})
                    with patch.object(
                        graph_verification, "run_bounded",
                        return_value=self.visual_command_result(graph, profile, paths, **{field: value}),
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
            write_json(environment, {"runtime": "browser", "preflight": []})
            graph_verification.start("cross-domain-feature", root, "run-visual-alias", [f"ENV-001={environment}"])
            write_json(result, {"po_id": "PO-001", "proof_type": "visual", "outcome": "evaluate", "anchors": []})
            aliased = dict(paths)
            aliased["prototype_screenshot"] = paths["implementation_screenshot"]
            with patch.object(
                graph_verification, "run_bounded",
                return_value=self.visual_command_result(graph, profile, aliased),
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
            codes = {item["code"] for item in delivery_graph.semantic_issues(graph, "proof-coverage")}
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
            write_json(environment, {"runtime": "python", "preflight": [{
                "id": "python-ready", "argv": [sys.executable, "-c", "pass"],
            }]})
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
            write_json(first, {"runtime": "python", "preflight": preflight})
            write_json(second, {"runtime": "python", "preflight": preflight})
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
                    write_json(environment, {"runtime": "python", "preflight": preflight})
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
                    write_json(environment, {"runtime": "python", "preflight": [{
                        "id": "python-ready", "argv": [sys.executable, "-c", "pass"],
                    }]})
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
            write_json(environment, {"runtime": "python", "preflight": []})
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
            write_json(environment, {"runtime": "python", "preflight": []})
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
            write_json(environment, {"runtime": "python", "preflight": []})
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

    def test_finalizer_clears_execution_marker_covered_by_durable_record(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, {"runtime": "python", "preflight": []})
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
            write_json(environment, {"runtime": "python", "preflight": []})
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
            write_json(environment, {"runtime": "python", "preflight": []})
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
        issues = delivery_graph.semantic_issues(graph, "proof-coverage")
        self.assertTrue(any(item["code"] == "ENVIRONMENT_PREFLIGHT_INVALID" for item in issues), issues)

    def test_timeout_policy_rejects_bool_and_unbounded_values(self) -> None:
        for timeout in (True, delivery_graph.MAX_COMMAND_TIMEOUT_SECONDS + 1, 10**100):
            with self.subTest(timeout=timeout):
                graph = valid_graph()
                proof = next(item for item in graph["nodes"] if item["id"] == "PO-001")
                proof["attributes"]["runner"]["timeout_seconds"] = timeout
                issues = delivery_graph.semantic_issues(graph, "proof-coverage")
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

    @unittest.skipIf(os.name == "nt", "POSIX process-group semantics required")
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

    def test_validator_recomputes_assertions_even_if_hash_chain_and_state_are_rewritten(self) -> None:
        temporary, root = self.make_root()
        with temporary:
            self.review_all(root)
            graph_contract.seal_contract(root, "cross-domain-feature")
            delivery_graph.mark_code_complete(root, "cross-domain-feature")
            environment = root / ".dlv/environment.json"
            result = root / ".dlv/result.json"
            write_json(environment, {"runtime": "python", "preflight": []})
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
            write_json(environment, {"runtime": "python", "preflight": []})
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
            self.assertEqual(11, graph["schema_version"])
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
            self.assertEqual(11, json.loads((directory / "delivery-graph.json").read_text())["schema_version"])

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
