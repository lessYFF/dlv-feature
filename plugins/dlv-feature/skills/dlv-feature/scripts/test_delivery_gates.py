#!/usr/bin/env python3
"""Regression tests for the schema-v6 delivery proof kernel."""

from __future__ import annotations

import unittest
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import finalize_delivery
from validate_boundary_proofs import validate_boundary_proofs
from validate_verification_evidence import validate_verification_evidence
from delivery_proof import (
    extract_state,
    finalization_token,
    repository_fingerprint,
    value_digest,
    validate_finalization,
    validate_proof_contract,
    write_state,
)


TARGET_ENVIRONMENT = "wechat-mini-program lib=3.16.1 devtools=1.06.2504010"
FINGERPRINTS = f"truth={'a' * 64} code={'b' * 64} env={value_digest(TARGET_ENVIRONMENT)}"
OBLIGATIONS = {
    "PO-01": {
        "id": "PO-01",
        "product_ids": ["AC-01"],
        "proof_type": "boundary",
        "surface": "POST /api/quotes/from-product",
        "critical": True,
        "expected": "missing permission returns 403 with zero write",
        "environment": TARGET_ENVIRONMENT,
        "states": [],
    }
}


def init_git(root: str) -> Path:
    path = Path(root)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "tests@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "DLV Tests"], cwd=path, check=True)
    (path / "source.txt").write_text("initial\n", encoding="utf-8")
    subprocess.run(["git", "add", "source.txt"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=path, check=True)
    return path


def proof(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": "BP-01",
        "fact": "PLAN quote creation consumes an active completed product snapshot",
        "owner": "PlanProductQuoteService.create",
        "product_ids": ["AC-01"],
        "authorization": "quote:create AND plan-product:view AND product.status=ACTIVE",
        "entrypoints": [{"route": "POST /api/quotes/from-product", "symbol": "QuoteController.createFromProduct", "guard": "require plan-product:view before PlanProductQuoteService.create"}],
        "lineage": {"selector": "product.publishedVersionId", "source": "completed plan product snapshot", "forbidden": ["sourceQuoteId current QuoteResponse"]},
        "projection": {"safe_when_denied": ["403 only; no quote payload"], "sensitive": ["source quote cost", "client contact"]},
        "probes": ["direct POST without plan-product:view returns 403 and service is not invoked", "mutate source quote after completion and verify exported PDF remains on selected snapshot"],
        "verdict": "PASS",
    }
    value.update(overrides)
    return value


def packet(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {"applicable": True, "reason": "new PLAN access and snapshot boundary", "proofs": [proof()], "verdict": "PASS"}
    value.update(overrides)
    return value


class BoundaryProofTests(unittest.TestCase):
    def validate(self, value: dict[str, object], *, architecture: str = "BP-01", code_spec: str = "BP-01", verification: str = "BP-01") -> list[str]:
        errors: list[str] = []
        validate_boundary_proofs(value, {"AC-01"}, architecture, code_spec, verification, True, errors)
        return errors

    def test_valid_proof_passes(self) -> None:
        self.assertEqual([], self.validate(packet()))

    def test_generic_entrypoint_fails(self) -> None:
        item = proof(entrypoints=[{"route": "all relevant routes", "symbol": "service", "guard": "permission"}])
        self.assertTrue(any("exact route" in error for error in self.validate(packet(proofs=[item]))))

    def test_missing_service_guard_fails(self) -> None:
        item = proof(entrypoints=[{"route": "POST /api/quotes/from-product", "symbol": "QuoteController.create"}])
        self.assertTrue(any("guard" in error for error in self.validate(packet(proofs=[item]))))

    def test_generic_authorization_or_guard_fails(self) -> None:
        item = proof(authorization="authorized user", entrypoints=[{"route": "POST /api/quotes/from-product", "symbol": "QuoteController.create", "guard": "permission"}])
        errors = self.validate(packet(proofs=[item]))
        self.assertTrue(any("authorization" in error for error in errors))
        self.assertTrue(any("exact route" in error for error in errors))

    def test_missing_direct_probe_fails(self) -> None:
        item = proof(probes=["role test rejects unauthorised access", "mutate source and inspect export"])
        self.assertTrue(any("direct-entry" in error for error in self.validate(packet(proofs=[item]))))

    def test_missing_forbidden_lineage_source_fails(self) -> None:
        item = proof(lineage={"selector": "product.publishedVersionId", "source": "completed snapshot", "forbidden": []})
        self.assertTrue(any("forbidden" in error for error in self.validate(packet(proofs=[item]))))

    def test_missing_denied_projection_fails(self) -> None:
        item = proof(projection={"sensitive": ["cost"]})
        self.assertTrue(any("projection" in error for error in self.validate(packet(proofs=[item]))))

    def test_missing_code_spec_consumption_fails(self) -> None:
        self.assertTrue(any("code-spec" in error for error in self.validate(packet(), code_spec="D01")))

    def test_range_and_generic_evidence_fail(self) -> None:
        report = f"""
## 5. 执行结果
| 证据 | 证明义务 | 覆盖 | 证明类型 | 环境 | 指纹 | 命令或步骤 | 状态 | 退出码 | 观察结果 | 锚点 |
|---|---|---|---|---|---|---|---|---|---|---|
| EVID-01 | PO-01 | AC-01～AC-02 BP-01 PO-01 | boundary | local | {FINGERPRINTS} | 测试通过 | passed | 0 | 通过 | 见上 |

## 6. 验收追踪
| ID | 证据 |
|---|---|
| AC-01 | EVID-01 |
| BP-01 | EVID-01 |
"""
        errors: list[str] = []
        validate_verification_evidence(report, {"AC-01", "BP-01"}, {"BP-01"}, "PASS", errors)
        self.assertTrue(any("range evidence" in error for error in errors))
        self.assertTrue(any("exact command" in error for error in errors))
        self.assertTrue(any("concrete observed" in error for error in errors))

    def test_valid_boundary_evidence_passes(self) -> None:
        report = f"""
## 5. 执行结果
| 证据 | 证明义务 | 覆盖 | 证明类型 | 环境 | 指纹 | 命令或步骤 | 状态 | 退出码 | 观察结果 | 锚点 |
|---|---|---|---|---|---|---|---|---|---|---|
| EVID-01 | PO-01 | AC-01 BP-01 PO-01 | boundary | {TARGET_ENVIRONMENT} | {FINGERPRINTS} | direct POST /api/quotes/from-product as quote:create-only role | passed | 0 | HTTP 403; response body excludes cost and client contact; service not invoked, zero write | QuoteControllerPlanProductTest:112 |

## 6. 验收追踪
| ID | 证据 |
|---|---|
| AC-01 | EVID-01 |
| BP-01 | EVID-01 |
| PO-01 | EVID-01 |
"""
        errors: list[str] = []
        validate_verification_evidence(
            report,
            {"AC-01", "BP-01", "PO-01"},
            {"BP-01"},
            "PASS",
            errors,
            proof_obligations=OBLIGATIONS,
            expected_fingerprints={"truth": "a" * 64, "code": "b" * 64},
        )
        self.assertEqual([], errors)

    def test_pass_rejects_conflicting_failed_evidence(self) -> None:
        report = f"""
## 5. 执行结果
| 证据 | 证明义务 | 覆盖 | 证明类型 | 环境 | 指纹 | 命令或步骤 | 状态 | 退出码 | 观察结果 | 锚点 |
|---|---|---|---|---|---|---|---|---|---|---|
| EVID-01 | PO-01 | AC-01 BP-01 PO-01 | boundary | {TARGET_ENVIRONMENT} | {FINGERPRINTS} | direct POST /api/quotes/from-product without permission | passed | 0 | HTTP 403; zero write and service not invoked | run:1 |
| EVID-02 | PO-01 | AC-01 BP-01 PO-01 | boundary | {TARGET_ENVIRONMENT} | {FINGERPRINTS} | direct POST /api/quotes/from-product without permission | failed | 1 | HTTP 200; write unexpectedly observed | run:2 |

## 6. 验收追踪
| ID | 证据 |
|---|---|
| AC-01 | EVID-01 EVID-02 |
| BP-01 | EVID-01 EVID-02 |
| PO-01 | EVID-01 EVID-02 |
"""
        errors: list[str] = []
        validate_verification_evidence(
            report, {"AC-01", "BP-01", "PO-01"}, {"BP-01"}, "PASS", errors,
            proof_obligations=OBLIGATIONS,
            expected_fingerprints={"truth": "a" * 64, "code": "b" * 64},
        )
        self.assertTrue(any("unresolved evidence" in error for error in errors))

    def test_environment_fingerprint_and_target_must_match(self) -> None:
        wrong_environment = "browser chromium=140"
        report = f"""
## 5. 执行结果
| 证据 | 证明义务 | 覆盖 | 证明类型 | 环境 | 指纹 | 命令或步骤 | 状态 | 退出码 | 观察结果 | 锚点 |
|---|---|---|---|---|---|---|---|---|---|---|
| EVID-01 | PO-01 | AC-01 BP-01 PO-01 | boundary | {wrong_environment} | {FINGERPRINTS} | direct POST /api/quotes/from-product without permission | passed | 0 | HTTP 403; zero write and service not invoked | run:1 |

## 6. 验收追踪
| ID | 证据 |
|---|---|
| AC-01 | EVID-01 |
| BP-01 | EVID-01 |
| PO-01 | EVID-01 |
"""
        errors: list[str] = []
        validate_verification_evidence(
            report, {"AC-01", "BP-01", "PO-01"}, {"BP-01"}, "PASS", errors,
            proof_obligations=OBLIGATIONS,
            expected_fingerprints={"truth": "a" * 64, "code": "b" * 64},
        )
        self.assertTrue(any("env fingerprint" in error for error in errors))
        self.assertTrue(any("target environment" in error for error in errors))

    def test_v5_state_is_rejected(self) -> None:
        scripts = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as root:
            subprocess.run(["python3", str(scripts / "init_feature.py"), "v4-rejection", "--root", root], check=True, capture_output=True, text=True)
            state_path = Path(root) / "delivery" / "v4-rejection" / "state.md"
            state_path.write_text(state_path.read_text(encoding="utf-8").replace('"schema_version": 6', '"schema_version": 5'), encoding="utf-8")
            result = subprocess.run(["python3", str(scripts / "validate_feature.py"), "v4-rejection", "--root", root], capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("schema_version must be 6", result.stdout)

    def test_visible_ui_requires_visual_proof(self) -> None:
        contract = {
            "status": "completed",
            "code_spec_fingerprint": "d" * 64,
            "obligations": list(OBLIGATIONS.values()),
            "verdict": "PASS",
        }
        errors: list[str] = []
        validate_proof_contract(contract, {"AC-01"}, "d" * 64, True, errors)
        self.assertTrue(any("visual proof obligation" in error for error in errors))

    def test_malformed_product_ids_report_error_instead_of_crashing(self) -> None:
        malformed = dict(OBLIGATIONS["PO-01"], product_ids=[{}, [], 7, None])
        contract = {
            "status": "completed",
            "code_spec_fingerprint": "d" * 64,
            "obligations": [malformed],
            "verdict": "PASS",
        }
        errors: list[str] = []
        validate_proof_contract(contract, {"AC-01"}, "d" * 64, False, errors)
        self.assertTrue(any("unknown or invalid" in error for error in errors))

    def test_finalization_token_becomes_stale_when_code_result_changes(self) -> None:
        state = {
            "schema_version": 6,
            "feature_id": "token-test",
            "proof_contract": {"status": "completed", "obligations": [], "verdict": "PASS"},
            "stages": {
                "prd": {"fingerprint": "a" * 64},
                "prototype": {"status": "not_applicable", "fingerprint": None},
                "architecture": {"fingerprint": "b" * 64},
                "code_spec": {"fingerprint": "c" * 64},
                "code": {"result": {"commit": "old"}},
                "verification": {
                    "status": "completed",
                    "fingerprint": "d" * 64,
                    "inputs": {"repositories": {"repo": "base"}},
                    "verdict": "PASS",
                    "finalization": {"tool": "finalize_delivery.py", "finalized_at": "2026-08-19T00:00:00+08:00"},
                },
            },
        }
        state["stages"]["verification"]["finalization"]["token"] = finalization_token(state)
        self.assertEqual([], (errors := []))
        validate_finalization(state, errors)
        self.assertEqual([], errors)
        state["stages"]["code"]["result"] = {"commit": "new"}
        validate_finalization(state, errors)
        self.assertTrue(any("token is stale" in error for error in errors))

    def test_invalidation_propagates_and_clears_verdict(self) -> None:
        scripts = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as root:
            init_git(root)
            subprocess.run(
                ["python3", str(scripts / "init_feature.py"), "stale-test", "--root", root],
                check=True,
                capture_output=True,
                text=True,
            )
            state_path = Path(root) / "delivery" / "stale-test" / "state.md"
            content, state = extract_state(state_path)
            for stage in ("prd", "prototype", "architecture", "code_spec", "code", "verification"):
                state["stages"][stage]["status"] = "completed"
            state["stages"]["prd"]["fingerprint"] = "0" * 64
            state["stages"]["verification"]["verdict"] = "PASS"
            state["stages"]["verification"]["finalization"] = {"token": "x"}
            state["stages"]["code"]["result"] = {
                "repository_fingerprint": repository_fingerprint(Path(root), "stale-test")
            }
            state["proof_contract"].update({"status": "completed", "verdict": "PASS"})
            write_state(state_path, content, state)
            (state_path.parent / "prd.md").write_text("changed", encoding="utf-8")
            result = subprocess.run(
                ["python3", str(scripts / "invalidate_downstream.py"), "stale-test", "--root", root],
                capture_output=True,
                text=True,
            )
            _, updated = extract_state(state_path)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertTrue(all(updated["stages"][stage]["status"] == "stale" for stage in ("prd", "prototype", "architecture", "code_spec", "code", "verification")))
        self.assertEqual("stale", updated["proof_contract"]["status"])
        self.assertIsNone(updated["stages"]["verification"]["verdict"])
        self.assertIsNone(updated["stages"]["verification"]["finalization"])

    def test_repository_change_invalidates_code_and_verification(self) -> None:
        scripts = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as root:
            init_git(root)
            subprocess.run(
                ["python3", str(scripts / "init_feature.py"), "repo-stale", "--root", root],
                check=True, capture_output=True, text=True,
            )
            state_path = Path(root) / "delivery" / "repo-stale" / "state.md"
            content, state = extract_state(state_path)
            state["stages"]["code"]["status"] = "completed"
            state["stages"]["verification"]["status"] = "completed"
            state["stages"]["verification"]["verdict"] = "PASS"
            state["stages"]["verification"]["finalization"] = {"token": "old"}
            state["stages"]["code"]["result"] = {
                "repository_fingerprint": repository_fingerprint(Path(root), "repo-stale")
            }
            write_state(state_path, content, state)
            (Path(root) / "source.txt").write_text("changed\n", encoding="utf-8")
            result = subprocess.run(
                ["python3", str(scripts / "invalidate_downstream.py"), "repo-stale", "--root", root],
                capture_output=True, text=True,
            )
            _, updated = extract_state(state_path)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual("stale", updated["stages"]["code"]["status"])
        self.assertEqual("stale", updated["stages"]["verification"]["status"])
        self.assertIsNone(updated["stages"]["verification"]["finalization"])

    def test_v5_upgrade_invalidates_code_spec_and_downstream(self) -> None:
        scripts = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as root:
            subprocess.run(
                ["python3", str(scripts / "init_feature.py"), "upgrade-test", "--root", root],
                check=True,
                capture_output=True,
                text=True,
            )
            state_path = Path(root) / "delivery" / "upgrade-test" / "state.md"
            content, state = extract_state(state_path)
            state["schema_version"] = 5
            state["stages"]["prototype"]["status"] = "not_applicable"
            for stage in ("code_spec", "code", "verification"):
                state["stages"][stage]["status"] = "completed"
            state.pop("proof_contract")
            write_state(state_path, content, state)
            result = subprocess.run(
                ["python3", str(scripts / "upgrade_v5_to_v6.py"), "upgrade-test", "--root", root, "--apply"],
                capture_output=True,
                text=True,
            )
            _, updated = extract_state(state_path)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(6, updated["schema_version"])
        self.assertEqual("pending", updated["proof_contract"]["status"])
        self.assertTrue(all(updated["stages"][stage]["status"] == "stale" for stage in ("code_spec", "code", "verification")))

    def test_finalizer_rejects_non_pass_without_mutating_state(self) -> None:
        scripts = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as root:
            subprocess.run(
                ["python3", str(scripts / "init_feature.py"), "finalizer-test", "--root", root],
                check=True,
                capture_output=True,
                text=True,
            )
            state_path = Path(root) / "delivery" / "finalizer-test" / "state.md"
            (state_path.parent / "verification.md").write_text("not ready", encoding="utf-8")
            before = state_path.read_text(encoding="utf-8")
            result = subprocess.run(
                ["python3", str(scripts / "finalize_delivery.py"), "finalizer-test", "--root", root],
                capture_output=True,
                text=True,
            )
            after = state_path.read_text(encoding="utf-8")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("verdict must be PASS", result.stderr)
        self.assertEqual(before, after)

    def make_finalizer_fixture(self, root: str, feature_id: str = "finalizer-flow") -> Path:
        scripts = Path(__file__).resolve().parent
        subprocess.run(
            ["python3", str(scripts / "init_feature.py"), feature_id, "--root", root],
            check=True, capture_output=True, text=True,
        )
        state_path = Path(root) / "delivery" / feature_id / "state.md"
        (state_path.parent / "verification.md").write_text("verification\n", encoding="utf-8")
        content, state = extract_state(state_path)
        state["stages"]["verification"]["verdict"] = "PASS"
        write_state(state_path, content, state)
        return state_path

    def test_finalizer_success_writes_bound_token(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            state_path = self.make_finalizer_fixture(root)
            ok = subprocess.CompletedProcess([], 0, "valid\n", "")
            with patch.object(finalize_delivery, "validate", return_value=ok), patch(
                "sys.argv", ["finalize_delivery.py", "finalizer-flow", "--root", root]
            ):
                result = finalize_delivery.main()
            _, state = extract_state(state_path)
        self.assertEqual(0, result)
        self.assertEqual("completed", state["stages"]["verification"]["status"])
        errors: list[str] = []
        validate_finalization(state, errors)
        self.assertEqual([], errors)

    def test_finalizer_preflight_failure_restores_original_state(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            state_path = self.make_finalizer_fixture(root)
            before = state_path.read_text(encoding="utf-8")
            failed = subprocess.CompletedProcess([], 1, "invalid\n", "")
            with patch.object(finalize_delivery, "validate", return_value=failed), patch(
                "sys.argv", ["finalize_delivery.py", "finalizer-flow", "--root", root]
            ):
                result = finalize_delivery.main()
            after = state_path.read_text(encoding="utf-8")
        self.assertEqual(1, result)
        self.assertEqual(before, after)

    def test_finalizer_final_validation_failure_restores_original_state(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            state_path = self.make_finalizer_fixture(root)
            before = state_path.read_text(encoding="utf-8")
            outcomes = [
                subprocess.CompletedProcess([], 0, "valid\n", ""),
                subprocess.CompletedProcess([], 1, "invalid final\n", ""),
            ]
            with patch.object(finalize_delivery, "validate", side_effect=outcomes), patch(
                "sys.argv", ["finalize_delivery.py", "finalizer-flow", "--root", root]
            ):
                result = finalize_delivery.main()
            after = state_path.read_text(encoding="utf-8")
        self.assertEqual(1, result)
        self.assertEqual(before, after)

    def test_finalizer_refuses_to_overwrite_concurrent_edit(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            state_path = self.make_finalizer_fixture(root)

            def concurrent_failure(*_: object) -> subprocess.CompletedProcess[str]:
                state_path.write_text(state_path.read_text(encoding="utf-8") + "\nconcurrent edit\n", encoding="utf-8")
                return subprocess.CompletedProcess([], 1, "invalid\n", "")

            with patch.object(finalize_delivery, "validate", side_effect=concurrent_failure), patch(
                "sys.argv", ["finalize_delivery.py", "finalizer-flow", "--root", root]
            ):
                result = finalize_delivery.main()
            after = state_path.read_text(encoding="utf-8")
        self.assertEqual(1, result)
        self.assertIn("concurrent edit", after)


if __name__ == "__main__":
    unittest.main()
