#!/usr/bin/env python3
"""Regression and forward tests for the schema-v7 verification kernel."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import finalize_delivery
import invalidate_downstream
import seal_proof_contract
from delivery_proof import (
    acquire_windows_lock,
    extract_state,
    evaluate_oracle,
    validate_finalization,
    proof_contract_digest,
    resolve_source,
    repository_fingerprint,
    value_digest,
    validate_proof_contract,
    write_state,
)
from validate_feature import validate_database_section, validate_document
from validate_verification_evidence import validate_verification_run
from verification_run import MAX_CAPTURE_BYTES, record, render, run_bounded, start

SCRIPTS = Path(__file__).resolve().parent
ENV_SPEC = {
    "runtime": "postgres",
    "version": "16.4",
    "services": {"redis": "7.2"},
    "preflight": [{"id": "python", "argv": ["python3", "-c", "print('ready')"]}],
}


def init_git(root: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "tests@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "DLV Tests"], cwd=root, check=True)
    (root / "source.txt").write_text("initial\n", encoding="utf-8")
    subprocess.run(["git", "add", "source.txt"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=root, check=True)


def contract() -> dict[str, object]:
    value: dict[str, object] = {
        "status": "completed",
        "code_spec_fingerprint": "c" * 64,
        "environments": [{"id": "ENV-01", "target": "integration stack", "spec": json.loads(json.dumps(ENV_SPEC))}],
        "obligations": [{
            "id": "PO-01",
            "product_ids": ["AC-01"],
            "trace_ids": ["BP-01", "R-D01-1", "T-B01-1", "B01"],
            "proof_type": "boundary",
            "surface": "POST /api/tasks",
            "environment_id": "ENV-01",
            "critical": True,
            "runner": {
                "argv": [
                    "python3", "-c",
                    "from pathlib import Path; print(Path('.dlv/inputs/runtime-observation.json').read_text())",
                ],
                "cwd": ".",
                "observation_adapter": "json_stdout",
            },
            "assertions": [
                {
                    "id": "ASRT-01",
                    "description": "draft result is not counted as completed",
                    "oracle": {"kind": "json_path", "source": "/observation/draft_count", "operator": "eq", "expected": 0},
                },
                {
                    "id": "ASRT-02",
                    "description": "request returns success",
                    "oracle": {"kind": "http_status", "source": "/observation/http_status", "operator": "eq", "expected": 200},
                },
            ],
        }],
        "approval": {"approved_by": "test-owner", "reference": "test-approval-01"},
        "sealed_at": "2026-08-21T00:00:00+08:00",
        "seal": None,
    }
    value["seal"] = proof_contract_digest(value)
    return value


def prepare(root: Path, feature_id: str = "kernel-test") -> tuple[Path, Path]:
    init_git(root)
    subprocess.run(
        ["python3", str(SCRIPTS / "init_feature.py"), feature_id, "--root", str(root)],
        check=True, capture_output=True, text=True,
    )
    state_path = root / "delivery" / feature_id / "state.md"
    environment = root / "environment.json"
    environment.write_text(json.dumps(ENV_SPEC), encoding="utf-8")
    content, state = extract_state(state_path)
    state["proof_contract"] = contract()
    (state_path.parent / "proof-contract.json").write_text(
        json.dumps(state["proof_contract"], ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    state["stages"]["code_spec"].update({"status": "completed", "fingerprint": "c" * 64})
    state["stages"]["code"].update({
        "status": "completed",
        "result": {"repository_fingerprint": repository_fingerprint(root, feature_id)},
    })
    write_state(state_path, content, state)
    start(feature_id, root, "run-001", [f"ENV-01={environment}"])
    return state_path, environment


def result_file(root: Path, *, status: str = "passed") -> Path:
    inputs = root / ".dlv" / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    anchor = inputs / f"anchor-{status}.log"
    anchor.write_text(f"observed {status}\n", encoding="utf-8")
    (inputs / "runtime-observation.json").write_text(
        json.dumps({"draft_count": 0 if status == "passed" else 1, "http_status": 200 if status == "passed" else 500}),
        encoding="utf-8",
    )
    value = {
        "po_id": "PO-01",
        "proof_type": "boundary",
        "outcome": "evaluate",
        "anchors": [str(anchor)],
    }
    path = inputs / f"result-{status}.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


class ContractTests(unittest.TestCase):
    def test_windows_lock_retries_until_the_long_running_owner_releases(self) -> None:
        attempts = 0

        def fake_locking(_fd: int, _mode: int, _size: int) -> None:
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise OSError(13, "permission denied")

        with patch("delivery_proof.time.sleep", return_value=None):
            acquire_windows_lock(fake_locking, 7, 1)
        self.assertEqual(3, attempts)

    def test_valid_structured_contract_passes(self) -> None:
        errors: list[str] = []
        obligations = validate_proof_contract(contract(), {"AC-01"}, "c" * 64, False, errors)
        self.assertEqual([], errors)
        self.assertEqual({"PO-01"}, set(obligations))

    def test_contract_mutation_breaks_seal(self) -> None:
        value = contract()
        value["obligations"][0]["assertions"][0]["oracle"]["expected"] = 99  # type: ignore[index]
        errors: list[str] = []
        validate_proof_contract(value, {"AC-01"}, "c" * 64, False, errors)
        self.assertTrue(any("seal" in error for error in errors))

    def test_all_sealed_metadata_is_covered_by_the_seal(self) -> None:
        mutations = {
            "status": "stale",
            "sealed_at": "2099-01-01T00:00:00Z",
            "approval": {"approved_by": "test-owner", "reference": "forged"},
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                value = contract()
                value[field] = replacement
                errors: list[str] = []
                validate_proof_contract(value, {"AC-01"}, "c" * 64, False, errors)
                self.assertTrue(any("seal" in error for error in errors), errors)

    def test_every_oracle_operator_has_deterministic_semantics(self) -> None:
        cases = [
            (2, {"operator": "ne", "expected": 1}),
            ([1, 2], {"operator": "contains", "expected": 2}),
            ("abc", {"operator": "not_contains", "expected": "z"}),
            ("abc123", {"operator": "matches", "expected": r"\d+"}),
            (None, {"operator": "exists"}),
            (2, {"operator": "lte", "expected": 3}),
            (3, {"operator": "gte", "expected": 2}),
        ]
        for actual, oracle in cases:
            with self.subTest(operator=oracle["operator"]):
                self.assertTrue(evaluate_oracle(actual, oracle))

    def test_absent_distinguishes_missing_path_from_explicit_null(self) -> None:
        missing = resolve_source({"observation": {}}, "/observation/secret")
        explicit_null = resolve_source({"observation": {"secret": None}}, "/observation/secret")
        self.assertTrue(evaluate_oracle(missing, {"operator": "absent"}))
        self.assertFalse(evaluate_oracle(explicit_null, {"operator": "absent"}))
        self.assertTrue(evaluate_oracle(explicit_null, {"operator": "exists"}))

    def test_free_text_expected_cannot_replace_assertions(self) -> None:
        value = contract()
        obligation = value["obligations"][0]  # type: ignore[index]
        obligation["expected"] = "looks good"
        obligation["assertions"] = []
        value["seal"] = proof_contract_digest(value)
        errors: list[str] = []
        validate_proof_contract(value, {"AC-01"}, "c" * 64, False, errors)
        self.assertTrue(any("assertions" in error for error in errors))

    def test_visual_prototype_requires_visual_obligation(self) -> None:
        errors: list[str] = []
        validate_proof_contract(contract(), {"AC-01"}, "c" * 64, True, errors)
        self.assertTrue(any("visual proof" in error for error in errors))

    def test_preflight_check_id_cannot_escape_run_directory(self) -> None:
        value = contract()
        value["environments"][0]["spec"]["preflight"][0]["id"] = "../../escape"  # type: ignore[index]
        value["seal"] = proof_contract_digest(value)
        errors: list[str] = []
        validate_proof_contract(value, {"AC-01"}, "c" * 64, False, errors)
        self.assertTrue(any("requires id and argv" in error for error in errors))

    def test_seal_command_is_one_way(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["python3", str(SCRIPTS / "init_feature.py"), "seal-test", "--root", str(root)], check=True)
            state_path = root / "delivery" / "seal-test" / "state.md"
            (state_path.parent / "prd.md").write_text("AC-01", encoding="utf-8")
            content, state = extract_state(state_path)
            pending = contract()
            pending.update({"status": "pending", "sealed_at": None, "seal": None})
            state["proof_contract"] = pending
            state["stages"]["code_spec"].update({"status": "completed", "fingerprint": "c" * 64})
            write_state(state_path, content, state)
            command = [
                "python3", str(SCRIPTS / "seal_proof_contract.py"), "seal-test", "--root", str(root),
                "--approved-by", "test-owner", "--approval-reference", "test-approval-01",
            ]
            first = subprocess.run(command, capture_output=True, text=True)
            second = subprocess.run(command, capture_output=True, text=True)
            _, sealed = extract_state(state_path)
            self.assertEqual(0, first.returncode, first.stdout + first.stderr)
            self.assertNotEqual(0, second.returncode)
            self.assertEqual(proof_contract_digest(sealed["proof_contract"]), sealed["proof_contract"]["seal"])

    def test_seal_recovers_an_orphaned_snapshot_and_serializes_concurrent_writers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run([sys.executable, str(SCRIPTS / "init_feature.py"), "seal-recovery", "--root", str(root)], check=True)
            state_path = root / "delivery/seal-recovery/state.md"
            (state_path.parent / "prd.md").write_text("AC-01", encoding="utf-8")
            content, state = extract_state(state_path)
            pending = contract()
            pending.update({"status": "pending", "approval": None, "sealed_at": None, "seal": None})
            state["proof_contract"] = pending
            state["stages"]["code_spec"].update({"status": "completed", "fingerprint": "c" * 64})
            write_state(state_path, content, state)
            orphan = contract()
            (state_path.parent / "proof-contract.json").write_text(json.dumps(orphan), encoding="utf-8")
            recovered = seal_proof_contract.seal_contract("seal-recovery", root, "test-owner", "test-approval-01")
            _, updated = extract_state(state_path)
            self.assertEqual(orphan["seal"], recovered)
            self.assertEqual(orphan, updated["proof_contract"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run([sys.executable, str(SCRIPTS / "init_feature.py"), "seal-concurrent", "--root", str(root)], check=True)
            state_path = root / "delivery/seal-concurrent/state.md"
            (state_path.parent / "prd.md").write_text("AC-01", encoding="utf-8")
            content, state = extract_state(state_path)
            pending = contract()
            pending.update({"status": "pending", "approval": None, "sealed_at": None, "seal": None})
            state["proof_contract"] = pending
            state["stages"]["code_spec"].update({"status": "completed", "fingerprint": "c" * 64})
            write_state(state_path, content, state)

            def attempt(reference: str) -> str:
                try:
                    return seal_proof_contract.seal_contract("seal-concurrent", root, "test-owner", reference)
                except ValueError:
                    return "rejected"

            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(executor.map(attempt, ("approval-a", "approval-b")))
            artifact = json.loads((state_path.parent / "proof-contract.json").read_text())
            _, updated = extract_state(state_path)
            self.assertEqual(1, outcomes.count("rejected"))
            self.assertEqual(artifact, updated["proof_contract"])


class ArchitectureDocumentTests(unittest.TestCase):
    def test_sql_ddl_is_required(self) -> None:
        errors: list[str] = []
        validate_database_section("字段与索引见正文。", errors)
        self.assertTrue(any("SQL DDL" in error for error in errors))

    def test_markdown_schema_table_is_rejected_even_with_sql(self) -> None:
        text = """```sql
CREATE TABLE task (id bigint PRIMARY KEY);
```
| 字段 | 类型 |
|---|---|
| id | bigint |
"""
        errors: list[str] = []
        validate_database_section(text, errors)
        self.assertTrue(any("Markdown schema tables" in error for error in errors))

    def test_sql_only_database_shape_passes(self) -> None:
        errors: list[str] = []
        validate_database_section("```sql\nCREATE TABLE task (id bigint PRIMARY KEY);\n```", errors)
        self.assertEqual([], errors)

    def test_sql_comment_cannot_fake_ddl(self) -> None:
        errors: list[str] = []
        validate_database_section("```sql\n-- CREATE TABLE fake (id bigint);\nSELECT 1;\n```", errors)
        self.assertTrue(any("SQL DDL" in error for error in errors))


class VerificationRunTests(unittest.TestCase):
    def test_runner_timeout_terminates_descendant_processes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            started = time.monotonic()
            result = run_bounded([
                sys.executable, "-c",
                "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import os,time; os.setsid(); time.sleep(10)']); time.sleep(10)",
            ], Path(temporary), timeout_seconds=1)
            self.assertLess(time.monotonic() - started, 4)
            self.assertEqual(124, result["exit_code"])
            self.assertTrue(result["timed_out"])

    def test_runner_output_is_bounded_and_common_secrets_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = run_bounded([
                sys.executable, "-c",
                f"print('token=super-secret'); print('{{\"password\": \"json-secret\"}}'); print('x'*{MAX_CAPTURE_BYTES + 1024})",
            ], Path(temporary), timeout_seconds=5)
            self.assertNotIn("super-secret", result["stdout"])
            self.assertNotIn("json-secret", result["stdout"])
            self.assertIn("token=[REDACTED]", result["stdout"])
            self.assertIn("[TRUNCATED", result["stdout"])
            self.assertLess(len(result["stdout"]), MAX_CAPTURE_BYTES + 200)

    def test_feature_id_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "feature-id"):
                start("../escape", Path(temporary), "run-001", [])

    def test_failed_preflight_creates_blocked_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            init_git(root)
            subprocess.run(["python3", str(SCRIPTS / "init_feature.py"), "preflight-block", "--root", str(root)], check=True)
            state_path = root / "delivery" / "preflight-block" / "state.md"
            bad_contract = contract()
            bad_contract["environments"][0]["spec"]["preflight"] = [  # type: ignore[index]
                {"id": "unavailable", "argv": ["python3", "-c", "raise SystemExit(9)"]}
            ]
            bad_contract["seal"] = proof_contract_digest(bad_contract)
            environment = root / "blocked-env.json"
            environment.write_text(json.dumps(bad_contract["environments"][0]["spec"]), encoding="utf-8")  # type: ignore[index]
            content, state = extract_state(state_path)
            state["proof_contract"] = bad_contract
            (state_path.parent / "proof-contract.json").write_text(json.dumps(bad_contract), encoding="utf-8")
            state["stages"]["code_spec"].update({"status": "completed", "fingerprint": "c" * 64})
            state["stages"]["code"].update({"status": "completed", "result": {"repository_fingerprint": repository_fingerprint(root, "preflight-block")}})
            write_state(state_path, content, state)
            with self.assertRaisesRegex(ValueError, "preflight blocked"):
                start("preflight-block", root, "run-001", [f"ENV-01={environment}"])
            _, blocked = extract_state(state_path)
            metadata = json.loads((root / ".dlv" / "runs" / "preflight-block" / "run-001" / "run.json").read_text())
            self.assertEqual("blocked", blocked["stages"]["verification"]["status"])
            self.assertEqual("BLOCKED", metadata["preflight_verdict"])

    def test_start_rejects_environment_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            init_git(root)
            subprocess.run(["python3", str(SCRIPTS / "init_feature.py"), "env-drift", "--root", str(root)], check=True)
            state_path = root / "delivery" / "env-drift" / "state.md"
            wrong = root / "wrong.json"
            wrong.write_text(json.dumps({"runtime": "postgres", "version": "15"}), encoding="utf-8")
            content, state = extract_state(state_path)
            state["proof_contract"] = contract()
            (state_path.parent / "proof-contract.json").write_text(json.dumps(state["proof_contract"]), encoding="utf-8")
            state["stages"]["code_spec"].update({"status": "completed", "fingerprint": "c" * 64})
            state["stages"]["code"].update({"status": "completed", "result": {"repository_fingerprint": repository_fingerprint(root, "env-drift")}})
            write_state(state_path, content, state)
            with self.assertRaisesRegex(ValueError, "does not match"):
                start("env-drift", root, "run-001", [f"ENV-01={wrong}"])

    def test_record_copies_anchor_and_validates_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            evidence_id = record("kernel-test", root, "run-001", result_file(root), [])
            _, state = extract_state(state_path)
            errors: list[str] = []
            verdict, digest = validate_verification_run(root, "kernel-test", state, errors)
            self.assertEqual("EVID-0001", evidence_id)
            self.assertEqual("PASS", verdict)
            self.assertEqual([], errors)
            self.assertRegex(str(digest), r"^[0-9a-f]{64}$")

    def test_preflight_status_and_anchor_are_recomputed_not_trusted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root), [])
            run_path = root / ".dlv/runs/kernel-test/run-001/run.json"
            metadata = json.loads(run_path.read_text())
            metadata["preflight"][0]["status"] = "blocked"
            run_path.write_text(json.dumps(metadata), encoding="utf-8")
            _, state = extract_state(state_path)
            errors: list[str] = []
            self.assertEqual("BLOCKED", validate_verification_run(root, "kernel-test", state, errors)[0])
            self.assertTrue(any("preflight check is not passed" in error for error in errors))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root), [])
            run_path = root / ".dlv/runs/kernel-test/run-001/run.json"
            metadata = json.loads(run_path.read_text())
            anchor = root / ".dlv/runs/kernel-test/run-001" / metadata["preflight"][0]["anchor"]
            anchor_value = json.loads(anchor.read_text())
            anchor_value["status"] = "blocked"
            anchor.write_text(json.dumps(anchor_value), encoding="utf-8")
            metadata["preflight"][0]["sha256"] = hashlib.sha256(anchor.read_bytes()).hexdigest()
            run_path.write_text(json.dumps(metadata), encoding="utf-8")
            _, state = extract_state(state_path)
            errors = []
            self.assertEqual("BLOCKED", validate_verification_run(root, "kernel-test", state, errors)[0])
            self.assertTrue(any("anchor disagrees" in error for error in errors))

    def test_caller_cannot_self_award_pass_against_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            malicious = json.loads(result_file(root, status="failed").read_text())
            malicious_path = root / ".dlv" / "inputs" / "malicious.json"
            malicious_path.write_text(json.dumps(malicious), encoding="utf-8")
            record("kernel-test", root, "run-001", malicious_path, [])
            _, state = extract_state(state_path)
            errors: list[str] = []
            verdict, _ = validate_verification_run(root, "kernel-test", state, errors)
            manifest = json.loads((root / ".dlv" / "runs" / "kernel-test" / "run-001" / "evidence.jsonl").read_text())
            self.assertEqual("failed", manifest["status"])
            self.assertEqual("BLOCKED", verdict)

    def test_caller_supplied_command_result_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepare(root)
            forged = json.loads(result_file(root).read_text())
            forged["command"] = {"argv": ["false"], "cwd": ".", "exit_code": 0}
            forged["observation"] = {"draft_count": 0, "http_status": 200}
            path = root / ".dlv" / "inputs" / "forged.json"
            path.write_text(json.dumps(forged), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "observation is forbidden"):
                record("kernel-test", root, "run-001", path, [])

    def test_skip_outcome_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepare(root)
            skipped = json.loads(result_file(root).read_text())
            skipped["outcome"] = "skipped"
            path = root / ".dlv" / "inputs" / "skipped.json"
            path.write_text(json.dumps(skipped), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "skips are forbidden"):
                record("kernel-test", root, "run-001", path, [])

    def test_old_run_and_completed_run_are_not_mutable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, environment = prepare(root)
            start("kernel-test", root, "run-002", [f"ENV-01={environment}"])
            with self.assertRaisesRegex(ValueError, "active Verification Run"):
                record("kernel-test", root, "run-001", result_file(root), [])
            record("kernel-test", root, "run-002", result_file(root), [])
            content, state = extract_state(state_path)
            state["stages"]["verification"]["status"] = "completed"
            write_state(state_path, content, state)
            with self.assertRaisesRegex(ValueError, "in_progress"):
                record("kernel-test", root, "run-002", result_file(root), [])
            with self.assertRaisesRegex(ValueError, "active in-progress"):
                render("kernel-test", root, "run-001")

    def test_concurrent_recorders_preserve_unique_ids_chain_and_state_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            result = result_file(root)
            with ThreadPoolExecutor(max_workers=2) as executor:
                ids = list(executor.map(lambda _: record("kernel-test", root, "run-001", result, []), range(2)))
            records = [json.loads(line) for line in (root / ".dlv/runs/kernel-test/run-001/evidence.jsonl").read_text().splitlines()]
            _, state = extract_state(state_path)
            self.assertEqual(["EVID-0001", "EVID-0002"], sorted(ids))
            self.assertEqual(records[0]["record_hash"], records[1]["previous_hash"])
            self.assertEqual(2, state["stages"]["verification"]["evidence_count"])
            self.assertEqual(records[-1]["record_hash"], state["stages"]["verification"]["evidence_head"])

    def test_interrupted_append_is_recovered_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            result = result_file(root)
            with patch("verification_run.write_state", side_effect=OSError("simulated crash")):
                with self.assertRaisesRegex(OSError, "simulated crash"):
                    record("kernel-test", root, "run-001", result, [])
            self.assertTrue((root / ".dlv/runs/kernel-test/run-001/pending-record.json").is_file())
            self.assertEqual("EVID-0001", record("kernel-test", root, "run-001", result, []))
            _, state = extract_state(state_path)
            errors: list[str] = []
            self.assertEqual("PASS", validate_verification_run(root, "kernel-test", state, errors)[0])
            self.assertEqual([], errors)
            self.assertFalse((root / ".dlv/runs/kernel-test/run-001/pending-record.json").exists())

    @unittest.skipUnless(sys.platform == "darwin", "macOS path alias regression")
    def test_macos_var_alias_resolves_to_one_run_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepare(root)
            alias = Path(str(root.resolve()).replace("/private/var/", "/var/", 1))
            self.assertEqual("EVID-0001", record("kernel-test", alias, "run-001", result_file(root), []))

    def test_cli_record_render_and_validate_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, environment = prepare(root)
            result = result_file(root)
            commands = [
                [sys.executable, str(SCRIPTS / "verification_run.py"), "start", "kernel-test", "--root", str(root), "--run-id", "run-002", "--environment", f"ENV-01={environment}"],
                [sys.executable, str(SCRIPTS / "verification_run.py"), "record", "kernel-test", "--root", str(root), "--run-id", "run-002", "--result", str(result)],
                [sys.executable, str(SCRIPTS / "verification_run.py"), "render", "kernel-test", "--root", str(root), "--run-id", "run-002"],
                [sys.executable, str(SCRIPTS / "validate_verification_evidence.py"), "kernel-test", "--root", str(root), "--run-id", "run-002"],
            ]
            for command in commands:
                completed = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    def test_manifest_status_tampering_breaks_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root, status="failed"), [])
            manifest_path = root / ".dlv" / "runs" / "kernel-test" / "run-001" / "evidence.jsonl"
            value = json.loads(manifest_path.read_text())
            value["status"] = "passed"
            for item in value["assertion_results"]:
                item["status"] = "passed"
            manifest_path.write_text(json.dumps(value) + "\n")
            _, state = extract_state(state_path)
            errors: list[str] = []
            verdict, _ = validate_verification_run(root, "kernel-test", state, errors)
            self.assertEqual("BLOCKED", verdict)
            self.assertTrue(any("hash chain" in error for error in errors))

    def test_rehashed_manifest_tampering_disagrees_with_state_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root, status="failed"), [])
            manifest_path = root / ".dlv" / "runs" / "kernel-test" / "run-001" / "evidence.jsonl"
            value = json.loads(manifest_path.read_text())
            value["status"] = "passed"
            value["observation"] = {"draft_count": 0, "http_status": 200}
            for item in value["assertion_results"]:
                item["status"] = "passed"
                item["actual"] = 0 if item["assertion_id"] == "ASRT-01" else 200
            value["record_hash"] = value_digest({key: item for key, item in value.items() if key != "record_hash"})
            manifest_path.write_text(json.dumps(value) + "\n")
            _, state = extract_state(state_path)
            errors: list[str] = []
            verdict, _ = validate_verification_run(root, "kernel-test", state, errors)
            self.assertEqual("BLOCKED", verdict)
            self.assertTrue(any("state-anchored" in error for error in errors))

    def test_contract_snapshot_mismatch_blocks_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            artifact = state_path.parent / "proof-contract.json"
            value = json.loads(artifact.read_text())
            value["approval"]["reference"] = "forged"
            artifact.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "disagrees"):
                record("kernel-test", root, "run-001", result_file(root), [])

    def test_anchor_tampering_blocks_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root), [])
            anchor = next((root / ".dlv" / "runs" / "kernel-test" / "run-001" / "anchors").iterdir())
            anchor.write_text("tampered\n", encoding="utf-8")
            _, state = extract_state(state_path)
            errors: list[str] = []
            verdict, _ = validate_verification_run(root, "kernel-test", state, errors)
            self.assertEqual("BLOCKED", verdict)
            self.assertTrue(any("hash mismatch" in error for error in errors))

    def test_failed_evidence_blocks_until_explicitly_superseded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            failed_id = record("kernel-test", root, "run-001", result_file(root, status="failed"), [])
            _, state = extract_state(state_path)
            errors: list[str] = []
            self.assertEqual("BLOCKED", validate_verification_run(root, "kernel-test", state, errors)[0])
            passed_id = record("kernel-test", root, "run-001", result_file(root), [failed_id])
            _, state = extract_state(state_path)
            errors = []
            self.assertEqual("PASS", validate_verification_run(root, "kernel-test", state, errors)[0])
            self.assertEqual("EVID-0002", passed_id)

    def test_code_change_stales_only_the_run_not_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root), [])
            (root / "source.txt").write_text("changed\n", encoding="utf-8")
            _, state = extract_state(state_path)
            errors: list[str] = []
            self.assertEqual("BLOCKED", validate_verification_run(root, "kernel-test", state, errors)[0])
            self.assertEqual("completed", state["proof_contract"]["status"])
            self.assertTrue(any("stale code" in error for error in errors))

    def test_open_structured_blocker_prevents_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root), [])
            content, state = extract_state(state_path)
            state["risks"] = [{
                "id": "RISK-01", "type": "blocker", "severity": "high", "status": "open",
                "statement": "production credential unavailable", "owner": "release-owner",
            }]
            write_state(state_path, content, state)
            errors: list[str] = []
            self.assertEqual("BLOCKED", validate_verification_run(root, "kernel-test", state, errors)[0])
            self.assertTrue(any("open blocker" in error for error in errors))

    def test_blocker_cannot_be_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root), [])
            content, state = extract_state(state_path)
            state["risks"] = [{
                "id": "RISK-01", "type": "blocker", "severity": "high", "status": "accepted",
                "statement": "oracle unavailable", "owner": "verification-owner", "accepted_by": "owner",
            }]
            write_state(state_path, content, state)
            errors: list[str] = []
            self.assertEqual("BLOCKED", validate_verification_run(root, "kernel-test", state, errors)[0])
            self.assertTrue(any("cannot be accepted" in error for error in errors))

    def test_generated_report_is_derived_from_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepare(root)
            record("kernel-test", root, "run-001", result_file(root), [])
            report = render("kernel-test", root, "run-001")
            text = report.read_text(encoding="utf-8")
            document_errors: list[str] = []
            validate_document("verification", text, document_errors)
            self.assertIn("EVID-0001", text)
            self.assertIn("ASRT-01=passed", text)
            self.assertIn("append-only Evidence Bundle", text)
            self.assertEqual([], document_errors)

    def test_generated_report_escapes_markdown_table_cells(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root), [])
            content, state = extract_state(state_path)
            state["risks"] = [{
                "id": "RISK-01", "type": "residual", "severity": "low", "status": "accepted",
                "statement": "line one | line two\nnext", "owner": "owner", "accepted_by": "owner",
            }]
            write_state(state_path, content, state)
            text = render("kernel-test", root, "run-001").read_text(encoding="utf-8")
            self.assertIn(r"line one \| line two<br>next", text)


class MigrationTests(unittest.TestCase):
    def test_invalidation_clears_the_sealed_contract_and_active_verification_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            message = invalidate_downstream.invalidate(root, "kernel-test", "code_spec")
            _, state = extract_state(state_path)
            self.assertIn("stale from code_spec", message)
            self.assertEqual("stale", state["proof_contract"]["status"])
            self.assertIsNone(state["proof_contract"]["seal"])
            self.assertEqual("stale", state["stages"]["verification"]["status"])
            self.assertFalse((state_path.parent / "proof-contract.json").exists())

    def test_upgrade_dry_run_is_non_mutating_and_wrong_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run([sys.executable, str(SCRIPTS / "init_feature.py"), "upgrade-preview", "--root", str(root)], check=True)
            state_path = root / "delivery/upgrade-preview/state.md"
            content, state = extract_state(state_path)
            state["schema_version"] = 6
            write_state(state_path, content, state)
            before = state_path.read_text(encoding="utf-8")
            dry = subprocess.run([sys.executable, str(SCRIPTS / "upgrade_v6_to_v7.py"), "upgrade-preview", "--root", str(root)], capture_output=True, text=True)
            self.assertEqual(0, dry.returncode)
            self.assertEqual(before, state_path.read_text(encoding="utf-8"))
            content, state = extract_state(state_path)
            state["schema_version"] = 7
            write_state(state_path, content, state)
            wrong = subprocess.run([sys.executable, str(SCRIPTS / "upgrade_v6_to_v7.py"), "upgrade-preview", "--root", str(root), "--apply"], capture_output=True, text=True)
            self.assertEqual(2, wrong.returncode)
    def test_v6_upgrade_invalidates_code_spec_and_downstream(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["python3", str(SCRIPTS / "init_feature.py"), "upgrade-test", "--root", str(root)], check=True)
            state_path = root / "delivery" / "upgrade-test" / "state.md"
            content, state = extract_state(state_path)
            state["schema_version"] = 6
            state["blockers"] = ["legacy blocker"]
            state.pop("risks")
            for stage in ("code_spec", "code", "verification"):
                state["stages"][stage]["status"] = "completed"
            write_state(state_path, content, state)
            result = subprocess.run(
                ["python3", str(SCRIPTS / "upgrade_v6_to_v7.py"), "upgrade-test", "--root", str(root), "--apply"],
                capture_output=True, text=True,
            )
            _, upgraded = extract_state(state_path)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual(7, upgraded["schema_version"])
            self.assertEqual("pending", upgraded["proof_contract"]["status"])
            self.assertEqual("open", upgraded["risks"][0]["status"])
            self.assertTrue(all(upgraded["stages"][stage]["status"] == "stale" for stage in ("code_spec", "code", "verification")))


class FinalizationTests(unittest.TestCase):
    def test_finalizer_cli_failure_rolls_back_generated_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root, "finalizer-cli-failure")
            record("finalizer-cli-failure", root, "run-001", result_file(root), [])
            before = state_path.read_text(encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(SCRIPTS / "finalize_delivery.py"), "finalizer-cli-failure", "--root", str(root)],
                capture_output=True, text=True,
            )
            self.assertEqual(1, completed.returncode)
            self.assertEqual(before, state_path.read_text(encoding="utf-8"))
            self.assertFalse((state_path.parent / "verification.md").exists())

    def test_finalizer_binds_run_and_generated_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root, "finalizer-test")
            record("finalizer-test", root, "run-001", result_file(root), [])
            ok = subprocess.CompletedProcess([], 0, "VALID\n", "")
            with patch.object(finalize_delivery, "validate", return_value=ok), patch(
                "sys.argv", ["finalize_delivery.py", "finalizer-test", "--root", str(root)]
            ):
                outcome = finalize_delivery.main()
            _, state = extract_state(state_path)
            errors: list[str] = []
            validate_finalization(state, errors)
            self.assertEqual(0, outcome)
            self.assertEqual("completed", state["stages"]["verification"]["status"])
            self.assertEqual("PASS", state["stages"]["verification"]["verdict"])
            self.assertEqual([], errors)
            self.assertIn("EVID-0001", (state_path.parent / "verification.md").read_text())

            state["stages"]["verification"]["finalization"]["finalized_at"] = "2099-01-01T00:00:00Z"
            tamper_errors: list[str] = []
            validate_finalization(state, tamper_errors)
            self.assertTrue(any("token is stale" in error for error in tamper_errors))

    def test_finalizer_restores_state_and_report_when_validation_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root, "finalizer-rollback")
            record("finalizer-rollback", root, "run-001", result_file(root), [])
            report_path = state_path.parent / "verification.md"
            report_path.write_text("user prior report\n", encoding="utf-8")
            original_state = state_path.read_text(encoding="utf-8")
            failed = subprocess.CompletedProcess([], 1, "INVALID\n", "")
            with patch.object(finalize_delivery, "validate", return_value=failed), patch(
                "sys.argv", ["finalize_delivery.py", "finalizer-rollback", "--root", str(root)]
            ):
                outcome = finalize_delivery.main()
            self.assertEqual(1, outcome)
            self.assertEqual(original_state, state_path.read_text(encoding="utf-8"))
            self.assertEqual("user prior report\n", report_path.read_text(encoding="utf-8"))

    def test_finalizer_preserves_concurrent_edits_on_failed_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root, "finalizer-concurrent")
            record("finalizer-concurrent", root, "run-001", result_file(root), [])
            report_path = state_path.parent / "verification.md"
            calls = 0

            def concurrent_validate(*_args: object) -> subprocess.CompletedProcess[str]:
                nonlocal calls
                calls += 1
                if calls == 1:
                    state_path.write_text("CONCURRENT STATE UPDATE\n", encoding="utf-8")
                    report_path.write_text("CONCURRENT REPORT UPDATE\n", encoding="utf-8")
                    return subprocess.CompletedProcess([], 1, "INVALID\n", "")
                return subprocess.CompletedProcess([], 0, "VALID\n", "")

            with patch.object(finalize_delivery, "validate", side_effect=concurrent_validate), patch(
                "sys.argv", ["finalize_delivery.py", "finalizer-concurrent", "--root", str(root)]
            ):
                outcome = finalize_delivery.main()
            self.assertEqual(1, outcome)
            self.assertEqual("CONCURRENT STATE UPDATE\n", state_path.read_text(encoding="utf-8"))
            self.assertEqual("CONCURRENT REPORT UPDATE\n", report_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
