#!/usr/bin/env python3
"""Record non-blocking quality and efficiency telemetry for one DLV execution."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

from delivery_graph import confined_project_path, timestamp, validate_feature_id
from delivery_proof import load_json, value_digest


ASSESSMENT_SCHEMA_VERSION = 1
MAX_INPUT_BYTES = 256 * 1024
MAX_COUNT = 1_000_000
MAX_DURATION_SECONDS = 365 * 24 * 60 * 60
MAX_INPUT_TOKENS = 1_000_000_000_000
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
FEEDBACK_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
RESULTS = {"DELIVERY_READY", "failed", "blocked", "cancelled"}
DIMENSIONS = ("functional", "visual_interaction", "edge_experience")
STAGES = {
    "source_capture", "product_synthesis", "implementation",
    "runtime_proof", "review_finding", "state_recovery",
}


def _load_bounded_regular(path: Path, label: str) -> dict[str, Any]:
    path = path.expanduser()
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as exc:
        raise ValueError(f"{label} must be a regular, non-symlink JSON file") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_INPUT_BYTES:
            raise ValueError(f"{label} must be regular and no larger than {MAX_INPUT_BYTES} bytes")
        chunks: list[bytes] = []
        remaining = MAX_INPUT_BYTES + 1
        while remaining and (chunk := os.read(descriptor, min(64 * 1024, remaining))):
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if len(content) > MAX_INPUT_BYTES or identity(before) != identity(after):
            raise ValueError(f"{label} changed while being read or exceeds {MAX_INPUT_BYTES} bytes")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(
            content.decode("utf-8"),
            parse_constant=lambda constant: (_ for _ in ()).throw(ValueError(f"non-finite number: {constant}")),
        )
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} must be UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def _exact_keys(value: Any, required: set[str], optional: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing or unknown:
        details = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if unknown:
            details.append("unknown " + ", ".join(sorted(unknown)))
        raise ValueError(f"{label} has invalid fields: {'; '.join(details)}")
    return value


def _nonnegative_int(value: Any, label: str, *, maximum: int = MAX_COUNT) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise ValueError(f"{label} must be a non-negative integer no greater than {maximum}")
    return value


def _nonnegative_number(
    value: Any, label: str, *, optional: bool = False, maximum: int = MAX_DURATION_SECONDS,
) -> int | float | None:
    if optional and value is None:
        return None
    if (
        isinstance(value, bool) or not isinstance(value, (int, float))
        or value < 0 or value > maximum
        or (isinstance(value, float) and not math.isfinite(value))
    ):
        raise ValueError(
            f"{label} must be a non-negative finite number no greater than {maximum}"
            + (" or null" if optional else "")
        )
    return value


def _count_measure(value: Any, label: str, *, allow_not_applicable: bool = False) -> dict[str, Any] | None:
    if value is None:
        return None
    if allow_not_applicable and isinstance(value, dict) and value.get("status") == "not_applicable":
        _exact_keys(value, {"status", "reason"}, set(), label)
        if not isinstance(value["reason"], str) or not value["reason"].strip():
            raise ValueError(f"{label}.reason must be non-empty")
        return {"status": "not_applicable", "reason": value["reason"]}
    item = _exact_keys(value, {"passed", "total"}, set(), label)
    passed = _nonnegative_int(item["passed"], f"{label}.passed")
    total = _nonnegative_int(item["total"], f"{label}.total")
    if total == 0 or passed > total:
        raise ValueError(f"{label} requires 0 <= passed <= total and total > 0")
    return {"passed": passed, "total": total}


def _score(value: dict[str, Any] | None, threshold: int) -> dict[str, Any]:
    if value is None:
        return {"status": "insufficient_evidence", "passed": None, "total": None, "rate_pct": None}
    if value.get("status") == "not_applicable":
        return value
    rate = round(100 * value["passed"] / value["total"], 2)
    passes = value["passed"] * 100 >= threshold * value["total"]
    return {**value, "rate_pct": rate, "status": "pass" if passes else "fail"}


def _publish_json(path: Path, value: dict[str, Any], duplicate_message: str) -> None:
    """Publish once without a blocking lock or overwrite window."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.resolve() != path.absolute():
        raise ValueError("assessment destination must not be relocated through a symlink")
    content = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise ValueError(duplicate_message) from exc
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _skill_version() -> str:
    manifest = Path(__file__).resolve().parents[3] / ".codex-plugin" / "plugin.json"
    try:
        value = load_json(manifest)
    except (OSError, json.JSONDecodeError):
        return "unknown"
    version = value.get("version") if isinstance(value, dict) else None
    return version if isinstance(version, str) and version else "unknown"


def build_assessment(feature_id: str, run_id: str, raw: dict[str, Any]) -> dict[str, Any]:
    validate_feature_id(feature_id)
    if not RUN_ID.fullmatch(run_id):
        raise ValueError("run_id is invalid")
    _exact_keys(raw, {"result", "context", "quality", "efficiency", "diagnosis"}, set(), "input")
    if raw["result"] not in RESULTS:
        raise ValueError("input.result is invalid")

    context = _exact_keys(
        raw["context"], {"acceptance_items", "surfaces", "contract_sensitive", "visual_applicable"}, set(), "context",
    )
    acceptance_items = _nonnegative_int(context["acceptance_items"], "context.acceptance_items")
    surfaces = context["surfaces"]
    if not isinstance(surfaces, list) or not all(isinstance(item, str) and item.strip() for item in surfaces):
        raise ValueError("context.surfaces must be an array of non-empty strings")
    if len(set(surfaces)) != len(surfaces):
        raise ValueError("context.surfaces must not contain duplicates")
    if type(context["contract_sensitive"]) is not bool:
        raise ValueError("context.contract_sensitive must be boolean")
    if type(context["visual_applicable"]) is not bool:
        raise ValueError("context.visual_applicable must be boolean")

    quality = _exact_keys(raw["quality"], {"first_pass", "final", "critical_requirements", "hard_failures"}, set(), "quality")
    first = None
    if quality["first_pass"] is not None:
        first_raw = _exact_keys(
            quality["first_pass"], {"passed", "total", "critical_passed", "critical_total"}, set(), "quality.first_pass",
        )
        first = _count_measure({"passed": first_raw["passed"], "total": first_raw["total"]}, "quality.first_pass")
        critical_total = _nonnegative_int(first_raw["critical_total"], "quality.first_pass.critical_total")
        critical_passed = _nonnegative_int(first_raw["critical_passed"], "quality.first_pass.critical_passed")
        if critical_passed > critical_total:
            raise ValueError("quality.first_pass requires critical_passed <= critical_total")
        first = {**first, "critical_passed": critical_passed, "critical_total": critical_total}

    final_raw = _exact_keys(quality["final"], set(DIMENSIONS), set(), "quality.final")
    final_scores = {
        name: _score(_count_measure(final_raw[name], f"quality.final.{name}", allow_not_applicable=True), 99)
        for name in DIMENSIONS
    }
    if final_scores["functional"].get("status") == "not_applicable":
        raise ValueError("quality.final.functional cannot be not_applicable")
    if final_scores["edge_experience"].get("status") == "not_applicable":
        raise ValueError("quality.final.edge_experience cannot be not_applicable")
    visual_not_applicable = final_scores["visual_interaction"].get("status") == "not_applicable"
    if visual_not_applicable == context["visual_applicable"]:
        raise ValueError("quality.final.visual_interaction must match context.visual_applicable")

    critical = _score(_count_measure(quality["critical_requirements"], "quality.critical_requirements"), 100)
    hard_raw = _exact_keys(
        quality["hard_failures"], {"p0_p1_open", "forbidden_scope_changes", "missing_evidence"}, set(), "quality.hard_failures",
    )
    hard = {key: _nonnegative_int(hard_raw[key], f"quality.hard_failures.{key}") for key in hard_raw}
    first_score = _score(first, 90)
    if first is not None:
        if acceptance_items == 0 or first["total"] != acceptance_items:
            raise ValueError("quality.first_pass.total must equal context.acceptance_items")
        if critical.get("status") == "insufficient_evidence" or first["critical_total"] != critical["total"]:
            raise ValueError("quality.first_pass.critical_total must equal final critical requirement total")
        first_critical_rate = round(100 * first["critical_passed"] / first["critical_total"], 2)
        first_score.update({
            "critical_passed": first["critical_passed"], "critical_total": first["critical_total"],
            "critical_rate_pct": first_critical_rate,
        })
        if first["critical_passed"] != first["critical_total"]:
            first_score["status"] = "fail"

    applicable_final = [item for item in final_scores.values() if item["status"] != "not_applicable"]
    if all(item["status"] != "insufficient_evidence" for item in applicable_final):
        final_total = sum(item["total"] for item in applicable_final)
        if final_total != acceptance_items:
            raise ValueError("applicable final dimension totals must partition context.acceptance_items")

    dimension_statuses = [item["status"] for item in applicable_final]
    evidence_complete = (
        first_score["status"] != "insufficient_evidence"
        and critical["status"] != "insufficient_evidence"
        and dimension_statuses
        and "insufficient_evidence" not in dimension_statuses
        and hard["missing_evidence"] == 0
    )
    hard_failure = hard["p0_p1_open"] > 0 or hard["forbidden_scope_changes"] > 0
    quality_pass = (
        evidence_complete and first_score["status"] == "pass" and critical["status"] == "pass"
        and all(status == "pass" for status in dimension_statuses) and not hard_failure
    )
    quality_verdict = "pass" if quality_pass else ("insufficient_evidence" if not evidence_complete else "fail")
    false_ready = raw["result"] == "DELIVERY_READY" and not quality_pass

    efficiency = _exact_keys(
        raw["efficiency"],
        {
            "time_to_first_candidate_seconds", "total_duration_seconds", "rework_rounds",
            "product_correction_batches", "process_failures", "process_waste_seconds",
            "process_interventions", "input_tokens", "baseline",
        }, set(), "efficiency",
    )
    first_seconds = _nonnegative_number(
        efficiency["time_to_first_candidate_seconds"], "efficiency.time_to_first_candidate_seconds", optional=True,
    )
    total_seconds = _nonnegative_number(efficiency["total_duration_seconds"], "efficiency.total_duration_seconds")
    input_tokens = _nonnegative_int(
        efficiency["input_tokens"], "efficiency.input_tokens", maximum=MAX_INPUT_TOKENS,
    ) if efficiency["input_tokens"] is not None else None
    counters = {
        key: _nonnegative_int(efficiency[key], f"efficiency.{key}")
        for key in ("rework_rounds", "product_correction_batches", "process_failures", "process_interventions")
    }
    process_waste = _nonnegative_number(efficiency["process_waste_seconds"], "efficiency.process_waste_seconds")
    if first_seconds is not None and first_seconds > total_seconds:
        raise ValueError("time to first candidate cannot exceed total duration")
    if process_waste > total_seconds:
        raise ValueError("process waste cannot exceed total duration")
    invariant_pass = (
        counters["rework_rounds"] <= 1 and counters["product_correction_batches"] <= 1
        and counters["process_failures"] == 0 and counters["process_interventions"] == 0
        and process_waste == 0
    )
    baseline_raw = efficiency["baseline"]
    baseline_comparison: dict[str, Any]
    if not quality_pass:
        baseline_comparison = {"status": "not_assessed", "reason": "quality must pass before efficiency comparison"}
    elif baseline_raw is None:
        baseline_comparison = {"status": "not_assessed", "reason": "no comparable quality-qualified baseline"}
    else:
        baseline = _exact_keys(
            baseline_raw,
            {
                "time_to_first_candidate_seconds", "total_duration_seconds", "rework_rounds",
                "product_correction_batches", "process_failures", "process_waste_seconds",
                "process_interventions",
            }, set(), "efficiency.baseline",
        )
        baseline_first = _nonnegative_number(
            baseline["time_to_first_candidate_seconds"], "efficiency.baseline.time_to_first_candidate_seconds",
        )
        baseline_total = _nonnegative_number(
            baseline["total_duration_seconds"], "efficiency.baseline.total_duration_seconds",
        )
        baseline_counters = {
            key: _nonnegative_int(baseline[key], f"efficiency.baseline.{key}")
            for key in ("rework_rounds", "product_correction_batches", "process_failures", "process_interventions")
        }
        baseline_waste = _nonnegative_number(
            baseline["process_waste_seconds"], "efficiency.baseline.process_waste_seconds",
        )
        if baseline_first > baseline_total or baseline_waste > baseline_total:
            raise ValueError("baseline first-candidate/process-waste time cannot exceed baseline total duration")
        if first_seconds is None:
            baseline_comparison = {"status": "not_assessed", "reason": "first candidate was not reached"}
        else:
            no_regression = (
                first_seconds <= baseline_first and total_seconds <= baseline_total
                and all(counters[key] <= baseline_counters[key] for key in baseline_counters)
                and process_waste <= baseline_waste
            )
            baseline_comparison = {
                "status": "pass" if no_regression else "fail",
                "first_candidate_ratio": round(first_seconds / baseline_first, 4) if baseline_first else (1.0 if first_seconds == 0 else None),
                "total_duration_ratio": round(total_seconds / baseline_total, 4) if baseline_total else (1.0 if total_seconds == 0 else None),
                "rework_rounds_delta": counters["rework_rounds"] - baseline_counters["rework_rounds"],
                "product_correction_batches_delta": counters["product_correction_batches"] - baseline_counters["product_correction_batches"],
                "process_failures_delta": counters["process_failures"] - baseline_counters["process_failures"],
                "process_waste_seconds_delta": process_waste - baseline_waste,
                "process_interventions_delta": counters["process_interventions"] - baseline_counters["process_interventions"],
            }
    efficiency_verdict = (
        "fail" if not invariant_pass or baseline_comparison["status"] == "fail"
        else "pass" if baseline_comparison["status"] == "pass" and quality_pass
        else "not_assessed"
    )

    diagnosis = _exact_keys(raw["diagnosis"], {"findings", "primary_finding_id"}, set(), "diagnosis")
    if not isinstance(diagnosis["findings"], list):
        raise ValueError("diagnosis.findings must be an array")
    findings: list[dict[str, str]] = []
    finding_ids: set[str] = set()
    for index, finding in enumerate(diagnosis["findings"]):
        item = _exact_keys(finding, {"id", "stage", "evidence"}, set(), f"diagnosis.findings[{index}]")
        if not isinstance(item["id"], str) or not RUN_ID.fullmatch(item["id"]) or item["id"] in finding_ids:
            raise ValueError(f"diagnosis.findings[{index}].id is invalid or duplicate")
        if item["stage"] not in STAGES:
            raise ValueError(f"diagnosis.findings[{index}].stage is invalid")
        if not isinstance(item["evidence"], str) or not item["evidence"].strip():
            raise ValueError(f"diagnosis.findings[{index}].evidence must be non-empty")
        finding_ids.add(item["id"])
        findings.append({"id": item["id"], "stage": item["stage"], "evidence": item["evidence"]})
    primary = diagnosis["primary_finding_id"]
    if primary is not None and primary not in finding_ids:
        raise ValueError("diagnosis.primary_finding_id must reference a finding")

    assessment = {
        "assessment_schema_version": ASSESSMENT_SCHEMA_VERSION,
        "feature_id": feature_id,
        "run_id": run_id,
        "skill_version": _skill_version(),
        "recorded_at": timestamp(),
        "result": raw["result"],
        "context": {
            "acceptance_items": acceptance_items,
            "surfaces": sorted(surfaces),
            "contract_sensitive": context["contract_sensitive"],
            "visual_applicable": context["visual_applicable"],
        },
        "quality": {
            "first_pass": first_score,
            "final": final_scores,
            "critical_requirements": critical,
            "hard_failures": {**hard, "false_ready": false_ready},
            "verdict": quality_verdict,
        },
        "efficiency": {
            "time_to_first_candidate_seconds": first_seconds,
            "total_duration_seconds": total_seconds,
            **counters,
            "process_waste_seconds": process_waste,
            "input_tokens": input_tokens,
            "baseline_comparison": baseline_comparison,
            "verdict": efficiency_verdict,
        },
        "diagnosis": {"findings": findings, "primary_finding_id": primary},
    }
    assessment["record_sha256"] = value_digest(assessment)
    return assessment


def record(root: Path, feature_id: str, run_id: str, input_path: Path) -> Path:
    root = root.expanduser().resolve()
    value = build_assessment(feature_id, run_id, _load_bounded_regular(input_path, "assessment input"))
    destination = confined_project_path(
        root, Path(".dlv") / "assessments" / feature_id / f"{run_id}.json", "assessment record",
    )
    _publish_json(destination, value, f"assessment record already exists: {run_id}")
    return destination


def append_feedback(root: Path, feature_id: str, run_id: str, feedback_id: str, input_path: Path) -> Path:
    root = root.expanduser().resolve()
    validate_feature_id(feature_id)
    if not RUN_ID.fullmatch(run_id) or not FEEDBACK_ID.fullmatch(feedback_id):
        raise ValueError("run_id or feedback_id is invalid")
    assessment = confined_project_path(
        root, Path(".dlv") / "assessments" / feature_id / f"{run_id}.json", "assessment record",
    )
    assessment_value = _load_bounded_regular(assessment, "assessment record")
    assessment_sha256 = assessment_value.get("record_sha256")
    if (
        not isinstance(assessment_sha256, str)
        or assessment_sha256 != value_digest({key: value for key, value in assessment_value.items() if key != "record_sha256"})
    ):
        raise ValueError("feedback requires an intact write-once assessment record")
    raw = _load_bounded_regular(input_path, "feedback input")
    _exact_keys(raw, {"source", "p0", "p1", "p2", "evidence"}, set(), "feedback")
    if raw["source"] not in {"user", "review", "production"}:
        raise ValueError("feedback.source is invalid")
    values = {key: _nonnegative_int(raw[key], f"feedback.{key}") for key in ("p0", "p1", "p2")}
    if not isinstance(raw["evidence"], str) or not raw["evidence"].strip():
        raise ValueError("feedback.evidence must be non-empty")
    destination = confined_project_path(
        root,
        Path(".dlv") / "assessments" / feature_id / f"{run_id}.feedback" / f"{feedback_id}.json",
        "assessment feedback",
    )
    feedback = {
        "assessment_schema_version": ASSESSMENT_SCHEMA_VERSION,
        "feature_id": feature_id,
        "run_id": run_id,
        "feedback_id": feedback_id,
        "assessment_record_sha256": assessment_sha256,
        "recorded_at": timestamp(),
        "source": raw["source"],
        "escaped_defects": values,
        "evidence": raw["evidence"],
    }
    feedback["record_sha256"] = value_digest(feedback)
    _publish_json(destination, feedback, f"assessment feedback already exists: {feedback_id}")
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    commands = parser.add_subparsers(dest="command", required=True)
    record_parser = commands.add_parser("record")
    record_parser.add_argument("--run-id", required=True)
    record_parser.add_argument("--input", required=True)
    feedback_parser = commands.add_parser("feedback")
    feedback_parser.add_argument("--run-id", required=True)
    feedback_parser.add_argument("--feedback-id", required=True)
    feedback_parser.add_argument("--input", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "record":
            path = record(Path(args.root), args.feature_id, args.run_id, Path(args.input))
        else:
            path = append_feedback(
                Path(args.root), args.feature_id, args.run_id, args.feedback_id, Path(args.input),
            )
    except (OSError, ValueError, json.JSONDecodeError, ArithmeticError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
