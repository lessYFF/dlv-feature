#!/usr/bin/env python3
"""Tests for non-blocking DLV execution assessment telemetry."""

from __future__ import annotations

import json
import math
import os
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

from execution_assessment import append_feedback, build_assessment, main, record


def passing_input() -> dict:
    return {
        "result": "DELIVERY_READY",
        "context": {
            "acceptance_items": 300, "surfaces": ["web", "api"],
            "contract_sensitive": True, "visual_applicable": True,
        },
        "quality": {
            "first_pass": {"passed": 285, "total": 300, "critical_passed": 4, "critical_total": 4},
            "final": {
                "functional": {"passed": 100, "total": 100},
                "visual_interaction": {"passed": 99, "total": 100},
                "edge_experience": {"passed": 100, "total": 100},
            },
            "critical_requirements": {"passed": 4, "total": 4},
            "hard_failures": {"p0_p1_open": 0, "forbidden_scope_changes": 0, "missing_evidence": 0},
        },
        "efficiency": {
            "time_to_first_candidate_seconds": 100, "total_duration_seconds": 200,
            "rework_rounds": 1, "product_correction_batches": 1,
            "process_failures": 0, "process_waste_seconds": 0, "process_interventions": 0,
            "input_tokens": 1000,
            "baseline": {
                "time_to_first_candidate_seconds": 100, "total_duration_seconds": 200,
                "rework_rounds": 1, "product_correction_batches": 1,
                "process_failures": 0, "process_waste_seconds": 0, "process_interventions": 0,
            },
        },
        "diagnosis": {"findings": [], "primary_finding_id": None},
    }


class ExecutionAssessmentTest(unittest.TestCase):
    def test_passing_quality_and_efficiency_are_derived_without_composite_score(self) -> None:
        value = build_assessment("feature-one", "run-01", passing_input())
        self.assertEqual("pass", value["quality"]["verdict"])
        self.assertEqual("pass", value["efficiency"]["verdict"])
        self.assertEqual(95.0, value["quality"]["first_pass"]["rate_pct"])
        self.assertFalse(value["quality"]["hard_failures"]["false_ready"])
        self.assertNotIn("score", value)

    def test_ready_with_missing_or_subthreshold_evidence_is_false_ready(self) -> None:
        for mutation in ("missing", "first_pass", "visual", "critical", "forbidden"):
            with self.subTest(mutation=mutation):
                raw = passing_input()
                if mutation == "missing":
                    raw["quality"]["hard_failures"]["missing_evidence"] = 1
                elif mutation == "first_pass":
                    raw["quality"]["first_pass"]["passed"] = 269
                elif mutation == "visual":
                    raw["quality"]["final"]["visual_interaction"]["passed"] = 98
                elif mutation == "critical":
                    raw["quality"]["critical_requirements"]["passed"] = 3
                else:
                    raw["quality"]["hard_failures"]["forbidden_scope_changes"] = 1
                value = build_assessment("feature-one", f"run-{mutation}", raw)
                self.assertNotEqual("pass", value["quality"]["verdict"])
                self.assertTrue(value["quality"]["hard_failures"]["false_ready"])

    def test_failed_execution_preserves_insufficient_evidence_without_inventing_scores(self) -> None:
        raw = passing_input()
        raw["result"] = "failed"
        raw["quality"]["first_pass"] = None
        raw["quality"]["final"]["functional"] = None
        raw["quality"]["critical_requirements"] = None
        raw["efficiency"]["time_to_first_candidate_seconds"] = None
        raw["efficiency"]["baseline"] = None
        value = build_assessment("feature-one", "run-failed", raw)
        self.assertEqual("insufficient_evidence", value["quality"]["verdict"])
        self.assertEqual("not_assessed", value["efficiency"]["verdict"])
        self.assertFalse(value["quality"]["hard_failures"]["false_ready"])

    def test_efficiency_cannot_pass_with_process_waste_or_excess_rework(self) -> None:
        for field, amount in (("rework_rounds", 2), ("process_failures", 1), ("process_waste_seconds", 1)):
            with self.subTest(field=field):
                raw = passing_input()
                raw["efficiency"][field] = amount
                value = build_assessment("feature-one", f"run-{field}", raw)
                self.assertEqual("pass", value["quality"]["verdict"])
                self.assertEqual("fail", value["efficiency"]["verdict"])

    def test_not_applicable_visual_dimension_requires_a_reason(self) -> None:
        raw = passing_input()
        raw["context"]["surfaces"] = ["api"]
        raw["context"]["visual_applicable"] = False
        raw["context"]["acceptance_items"] = 200
        raw["quality"]["first_pass"].update({"passed": 190, "total": 200})
        raw["quality"]["final"]["visual_interaction"] = {
            "status": "not_applicable", "reason": "No user-visible surface changed.",
        }
        self.assertEqual("pass", build_assessment("feature-one", "run-api", raw)["quality"]["verdict"])
        raw["quality"]["final"]["visual_interaction"]["reason"] = ""
        with self.assertRaisesRegex(ValueError, "reason must be non-empty"):
            build_assessment("feature-one", "run-api-invalid", raw)

    def test_denominators_are_bound_and_thresholds_do_not_round_up(self) -> None:
        raw = passing_input()
        raw["context"]["acceptance_items"] = 301
        with self.assertRaisesRegex(ValueError, "first_pass.total"):
            build_assessment("feature-one", "run-denominator", raw)

        raw = passing_input()
        raw["quality"]["first_pass"].update({"passed": 17999, "total": 20000})
        raw["context"]["acceptance_items"] = 20000
        raw["quality"]["final"] = {
            "functional": {"passed": 6600, "total": 6600},
            "visual_interaction": {"passed": 6600, "total": 6600},
            "edge_experience": {"passed": 6800, "total": 6800},
        }
        value = build_assessment("feature-one", "run-rounded", raw)
        self.assertEqual(90.0, value["quality"]["first_pass"]["rate_pct"])
        self.assertEqual("fail", value["quality"]["first_pass"]["status"])

        raw = passing_input()
        raw["quality"]["first_pass"]["critical_total"] = 3
        with self.assertRaisesRegex(ValueError, "critical_total"):
            build_assessment("feature-one", "run-critical-denominator", raw)

        raw = passing_input()
        raw["quality"]["critical_requirements"].update({"passed": 19999, "total": 20000})
        raw["quality"]["first_pass"].update({"critical_passed": 19999, "critical_total": 20000})
        value = build_assessment("feature-one", "run-critical-rounded", raw)
        self.assertEqual(100.0, value["quality"]["critical_requirements"]["rate_pct"])
        self.assertEqual("fail", value["quality"]["verdict"])

    def test_quality_failure_skips_efficiency_comparison_and_timing_must_be_ordered(self) -> None:
        raw = passing_input()
        raw["quality"]["first_pass"]["passed"] = 1
        value = build_assessment("feature-one", "run-quality-fail", raw)
        self.assertEqual("not_assessed", value["efficiency"]["baseline_comparison"]["status"])

        raw = passing_input()
        raw["efficiency"]["time_to_first_candidate_seconds"] = 201
        with self.assertRaisesRegex(ValueError, "cannot exceed"):
            build_assessment("feature-one", "run-invalid-time", raw)

    def test_record_and_delayed_feedback_are_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            assessment_input = root / "assessment.json"
            assessment_input.write_text(json.dumps(passing_input()), encoding="utf-8")
            path = record(root, "feature-one", "run-01", assessment_input)
            self.assertTrue(path.is_file())
            self.assertRegex(json.loads(path.read_text())["record_sha256"], r"^[0-9a-f]{64}$")
            with self.assertRaisesRegex(ValueError, "already exists"):
                record(root, "feature-one", "run-01", assessment_input)

            feedback_input = root / "feedback.json"
            feedback_input.write_text(json.dumps({
                "source": "production", "p0": 0, "p1": 0, "p2": 1,
                "evidence": "One minor post-delivery issue was confirmed.",
            }), encoding="utf-8")
            feedback_path = append_feedback(root, "feature-one", "run-01", "feedback-01", feedback_input)
            self.assertEqual(1, json.loads(feedback_path.read_text())["escaped_defects"]["p2"])
            with self.assertRaisesRegex(ValueError, "already exists"):
                append_feedback(root, "feature-one", "run-01", "feedback-01", feedback_input)

            path.write_text('{"tampered": true}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "intact write-once"):
                append_feedback(root, "feature-one", "run-01", "feedback-02", feedback_input)

    def test_diagnosis_keeps_all_findings_and_one_primary_target(self) -> None:
        raw = passing_input()
        raw["diagnosis"] = {
            "findings": [
                {"id": "obs-source", "stage": "source_capture", "evidence": "Scope was truncated."},
                {"id": "obs-state", "stage": "state_recovery", "evidence": "A retry lost state."},
            ],
            "primary_finding_id": "obs-source",
        }
        value = build_assessment("feature-one", "run-diagnosis", raw)
        self.assertEqual(2, len(value["diagnosis"]["findings"]))
        self.assertEqual("obs-source", value["diagnosis"]["primary_finding_id"])
        raw["diagnosis"]["primary_finding_id"] = "unknown"
        with self.assertRaisesRegex(ValueError, "must reference"):
            build_assessment("feature-one", "run-invalid-primary", raw)

    def test_non_finite_duration_is_rejected(self) -> None:
        for value in (math.nan, math.inf, 10**4000):
            raw = passing_input()
            raw["efficiency"]["total_duration_seconds"] = value
            with self.assertRaisesRegex(ValueError, "non-negative finite number"):
                build_assessment("feature-one", "run-non-finite", raw)

    def test_public_cli_records_every_terminal_result_and_reports_bad_input(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            for result in ("DELIVERY_READY", "failed", "blocked", "cancelled"):
                raw = passing_input()
                raw["result"] = result
                source = root / f"{result}.json"
                source.write_text(json.dumps(raw), encoding="utf-8")
                with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                    self.assertEqual(0, main([
                        "feature-one", "--root", str(root), "record",
                        "--run-id", f"run-{result.lower()}", "--input", str(source),
                    ]))
            malformed = root / "malformed.json"
            malformed.write_text("[]", encoding="utf-8")
            error = StringIO()
            with redirect_stdout(StringIO()), redirect_stderr(error):
                self.assertEqual(1, main([
                    "feature-one", "--root", str(root), "record",
                    "--run-id", "run-malformed", "--input", str(malformed),
                ]))
            self.assertIn("must contain a JSON object", error.getvalue())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO input is POSIX-only")
    def test_fifo_input_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            fifo = root / "assessment.fifo"
            os.mkfifo(fifo)
            error = StringIO()
            with redirect_stdout(StringIO()), redirect_stderr(error):
                self.assertEqual(1, main([
                    "feature-one", "--root", str(root), "record",
                    "--run-id", "run-fifo", "--input", str(fifo),
                ]))
            self.assertIn("must be regular", error.getvalue())

    def test_concurrent_record_publish_allows_exactly_one_writer(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            source = root / "assessment.json"
            source.write_text(json.dumps(passing_input()), encoding="utf-8")

            def publish() -> str:
                try:
                    record(root, "feature-one", "run-race", source)
                    return "created"
                except ValueError:
                    return "duplicate"

            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(executor.map(lambda _: publish(), range(2)))
            self.assertEqual(["created", "duplicate"], sorted(outcomes))
            stored = json.loads((root / ".dlv/assessments/feature-one/run-race.json").read_text())
            self.assertRegex(stored["record_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
