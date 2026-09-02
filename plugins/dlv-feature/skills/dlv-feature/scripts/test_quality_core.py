#!/usr/bin/env python3
"""Regression and multi-domain benchmark tests for first-pass quality contracts."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
import base64
from pathlib import Path
import sys

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

from quality_core import (
    attachment_interpretation_errors,
    attachment_materialization_errors,
    critical_anchor_coverage,
    derive_delivery_status,
    derive_risk_frontier,
    experiment_plan,
    materialize_attachments,
    reconcile_subjects,
    source_anchors,
)


class QualityCoreTest(unittest.TestCase):
    def test_materializes_inline_and_local_attachments_and_rejects_locator_only_records(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            feature = root / "delivery/example"
            feature.mkdir(parents=True)
            local = root / "prototype.html"
            local.write_text("<main>exact source</main>", encoding="utf-8")
            attachments = materialize_attachments(feature, [
                {"ref": "inline", "kind": "brief", "inline_content": {"required": True}},
                {"ref": "prototype", "kind": "prototype", "locator": "prototype.html"},
            ])
            self.assertEqual([], attachment_materialization_errors({"attachments": attachments}))
            self.assertEqual("utf-8", attachments[1]["content_encoding"])
            self.assertEqual(hashlib.sha256(local.read_bytes()).hexdigest(), attachments[1]["sha256"])
            self.assertTrue(attachment_materialization_errors({"attachments": [
                {"ref": "legacy", "kind": "brief", "locator": "somewhere", "sha256": "0" * 64},
            ]}))

    def test_attachment_confinement_and_materialized_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as raw, tempfile.TemporaryDirectory() as outside_raw:
            root = Path(raw)
            feature = root / "delivery/example"
            feature.mkdir(parents=True)
            outside = Path(outside_raw) / "secret.txt"
            outside.write_text("secret", encoding="utf-8")
            for locator in (str(outside), "../outside.txt"):
                with self.assertRaisesRegex(ValueError, "inside the project root"):
                    materialize_attachments(feature, [{"ref": "escape", "kind": "brief", "locator": locator}])
            local = root / "local.txt"
            local.write_text("local", encoding="utf-8")
            link = root / "linked.txt"
            link.symlink_to(local)
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                materialize_attachments(feature, [{"ref": "link", "kind": "brief", "locator": "linked.txt"}])
            at_limit = b"x" * (8 * 1024 * 1024)
            accepted = materialize_attachments(feature, [{
                "ref": "limit", "kind": "brief", "content_encoding": "utf-8",
                "content": at_limit.decode(), "size_bytes": len(at_limit),
                "sha256": hashlib.sha256(at_limit).hexdigest(),
            }])
            self.assertEqual(len(at_limit), accepted[0]["size_bytes"])
            oversized = b"x" * (8 * 1024 * 1024 + 1)
            for attachment in (
                {"ref": "utf8", "kind": "brief", "content_encoding": "utf-8", "content": oversized.decode(),
                 "size_bytes": len(oversized), "sha256": hashlib.sha256(oversized).hexdigest()},
                {"ref": "b64", "kind": "image", "content_encoding": "base64", "content": base64.b64encode(oversized).decode(),
                 "size_bytes": len(oversized), "sha256": hashlib.sha256(oversized).hexdigest()},
            ):
                with self.assertRaisesRegex(ValueError, "exceeds"):
                    materialize_attachments(feature, [attachment])

    def test_binary_attachment_has_one_critical_whole_attachment_anchor(self) -> None:
        payload = b"\x89PNG\r\n\x1a\nbytes"
        source = {
            "revision_id": "SRC-001", "title": "Feature", "description": "",
            "comments": [], "decisions": [], "attachments": [{
                "ref": "design.png", "kind": "image", "content_encoding": "base64",
                "content": base64.b64encode(payload).decode(), "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }],
        }
        anchors = [item for item in source_anchors(source) if item["source_ref"] == "design.png"]
        self.assertEqual(1, len(anchors))
        self.assertTrue(anchors[0]["critical"])
        self.assertIn(hashlib.sha256(payload).hexdigest(), anchors[0]["text"])
        self.assertTrue(attachment_interpretation_errors(source))
        source["attachments"][0].update({"extracted_text": "按钮必须可见。", "extraction_adapter": "ocr-v1"})
        self.assertEqual([], attachment_interpretation_errors(source))
        self.assertTrue(any(item["kind"] == "requirement" for item in source_anchors(source)))

    def test_adjacent_chinese_clauses_keep_distinct_critical_kinds(self) -> None:
        source = {
            "revision_id": "SRC-001", "title": "功能",
            "description": "结果必须持久化。不得丢失错误状态。失败时应该展示恢复动作。",
            "comments": [], "attachments": [], "decisions": [],
        }
        anchors = source_anchors(source)
        self.assertTrue({"requirement", "prohibition", "error"} <= {item["kind"] for item in anchors})

    def test_multidomain_anchor_benchmark_preserves_at_least_ninety_percent(self) -> None:
        fixture = Path(__file__).parents[1] / "references/first-pass-benchmark.json"
        cases = json.loads(fixture.read_text(encoding="utf-8"))["cases"]
        scores = []
        for case in cases:
            source = {
                "revision_id": "SRC-001", "title": case["id"], "description": case["text"],
                "comments": [], "attachments": [], "decisions": [],
            }
            observed = {item["kind"] for item in source_anchors(source) if item["critical"]}
            expected = set(case["expected_kinds"])
            scores.append(100 * len(observed & expected) / len(expected))
        self.assertGreaterEqual(sum(scores) / len(scores), 90)

    def test_critical_anchor_coverage_requires_exact_origins(self) -> None:
        source = {
            "revision_id": "SRC-001", "title": "Feature",
            "description": "The result must be persisted. Never lose an error state.",
            "comments": [], "attachments": [], "decisions": [],
        }
        anchors = [item for item in source_anchors(source) if item["critical"]]
        graph = {"nodes": [{
            "id": "REQ-001", "type": "Requirement", "origins": [
                {"kind": "direct", "source_ref": item["id"]} for item in anchors
            ],
        }]}
        self.assertEqual(100, critical_anchor_coverage(graph, source)["coverage_pct"])
        graph["nodes"][0]["origins"].pop()
        self.assertLess(critical_anchor_coverage(graph, source)["coverage_pct"], 100)

    def test_subject_reconciliation_reads_only_formal_feature_commits(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
            (root / "src").mkdir()
            (root / "src/service.py").write_text("before\n")
            subprocess.run(["git", "add", "src/service.py"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
            graph = {"nodes": [{"id": "SYM-001", "type": "Symbol", "attributes": {"path": "src/service.py"}}]}
            initial = reconcile_subjects(root, "feature", graph)
            baseline = initial["baseline_oid"]
            self.assertEqual("pending_observation", initial["status"])
            (root / "src/service.py").write_text("after\n")
            subprocess.run(["git", "commit", "-qam", "feat: change\n\nDLV-Feature: feature"], cwd=root, check=True)
            self.assertEqual("reconciled", reconcile_subjects(root, "feature", graph, baseline)["status"])
            (root / "other.py").write_text("x\n")
            subprocess.run(["git", "add", "other.py"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "feat: other\n\nDLV-Feature: feature"], cwd=root, check=True)
            self.assertEqual(["other.py"], reconcile_subjects(root, "feature", graph, baseline)["unmapped_paths"])
            (root / "deleted.py").write_text("gone\n")
            subprocess.run(["git", "add", "deleted.py"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "ordinary commit"], cwd=root, check=True)
            (root / "deleted.py").unlink()
            (root / "dirty.py").write_text("dirty\n")
            observed = reconcile_subjects(root, "feature", graph, baseline)["observed_paths"]
            self.assertTrue({"deleted.py", "dirty.py", "other.py", "src/service.py"} <= set(observed))

    def test_subject_reconciliation_requires_every_planned_symbol(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            initial = reconcile_subjects(root, "feature", {"nodes": []})
            (root / "src").mkdir()
            (root / "src/one.py").write_text("one\n")
            graph = {"nodes": [
                {"id": "SYM-001", "type": "Symbol", "attributes": {"path": "src/one.py"}},
                {"id": "SYM-002", "type": "Symbol", "attributes": {"path": "src/two.py"}},
            ]}
            result = reconcile_subjects(root, "feature", graph, initial["baseline_oid"])
            self.assertEqual("blocked", result["status"])
            self.assertEqual(["SYM-002"], result["unobserved_subject_ids"])

    def test_frontier_experiments_are_minimal_and_evidence_is_reused(self) -> None:
        graph = {"claims": [
            {"id": "CLM-1", "lens": "BOUNDARY_AND_CONCURRENCY", "critical": True,
             "failure_boundary": "duplicate write", "subjects": ["BND-001"], "proof_ids": ["PO-001"]},
            {"id": "CLM-2", "lens": "BOUNDARY_AND_CONCURRENCY", "critical": True,
             "failure_boundary": "duplicate write", "subjects": ["ST-001"], "proof_ids": ["PO-001"]},
        ]}
        risk = {axis: "absent" for axis in (
            "API_CONTRACT", "PERSISTENCE", "AUTHORIZATION", "TENANCY", "MONEY",
            "CONCURRENCY", "IRREVERSIBLE_SIDE_EFFECT", "CROSS_CLIENT", "VISUAL_CONTRACT",
        )}
        risk["CONCURRENCY"] = "critical"
        frontier = derive_risk_frontier(graph, risk)
        self.assertEqual(1, len(frontier))
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            plan = experiment_plan(root, "feature", frontier)
            self.assertEqual("blocked", plan["status"])
            experiment = plan["experiments"][0]
            directory = root / ".dlv/experiments/feature"
            directory.mkdir(parents=True)
            forged = {
                "schema_version": 13, "feature_id": "feature", "experiment_id": experiment["id"],
                "frontier_id": frontier[0]["id"], "frontier_sha256": _digest(frontier[0]),
                "graph_sha256": "0" * 64, "recorded_at": "now", "verdict": "PASS",
                "observation": {"duplicate_count": 0},
            }
            forged["record_sha256"] = _digest(forged)
            path = directory / f"{experiment['id']}-{forged['record_sha256'][:12]}.json"
            path.write_text(json.dumps(forged), encoding="utf-8")
            self.assertEqual("blocked", experiment_plan(root, "feature", frontier)["status"])

    def test_delivery_ready_has_no_false_positive(self) -> None:
        state = {
            "readiness": {"status": "ready"}, "subject_reconciliation": {"status": "reconciled"},
            "critical_experiments": {"status": "ready"}, "code": {"status": "completed"},
            "proof_contract": {"status": "sealed"},
            "verification": {"status": "completed", "verdict": "PASS", "finalization": None},
        }
        self.assertEqual("REVIEWABLE", derive_delivery_status(state))
        for status in (None, "pending_observation", "blocked"):
            state["subject_reconciliation"] = {} if status is None else {"status": status}
            state["verification"]["finalization"] = {
                "tool": "finalize_delivery.py", "finalized_at": "now", "token": "0" * 64,
            }
            self.assertEqual("REVIEWABLE" if status == "pending_observation" else "AUTHORING", derive_delivery_status(state))
        state["subject_reconciliation"] = {"status": "reconciled"}
        state["verification"]["finalization"] = {
            "tool": "finalize_delivery.py", "finalized_at": "now", "token": "0" * 64,
        }
        self.assertEqual("DELIVERY_READY", derive_delivery_status(state))


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


if __name__ == "__main__":
    unittest.main()
