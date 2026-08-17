#!/usr/bin/env python3
"""Regression tests for the v5 Boundary Proof Gate."""

from __future__ import annotations

import unittest
import subprocess
import tempfile
from pathlib import Path

from validate_boundary_proofs import validate_boundary_proofs
from validate_verification_evidence import validate_verification_evidence


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
        report = """
## 5. 执行结果
| 证据 | 覆盖 | 环境 | 命令或步骤 | 状态 | 退出码 | 观察结果 | 锚点 |
|---|---|---|---|---|---|---|---|
| EVID-01 | AC-01～AC-02 BP-01 | local | 测试通过 | passed | 0 | 通过 | 见上 |

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
        report = """
## 5. 执行结果
| 证据 | 覆盖 | 环境 | 命令或步骤 | 状态 | 退出码 | 观察结果 | 锚点 |
|---|---|---|---|---|---|---|---|
| EVID-01 | AC-01 BP-01 | local | direct POST /api/quotes/from-product as quote:create-only role | passed | 0 | HTTP 403; response body excludes cost and client contact; service not invoked, zero write | QuoteControllerPlanProductTest:112 |

## 6. 验收追踪
| ID | 证据 |
|---|---|
| AC-01 | EVID-01 |
| BP-01 | EVID-01 |
"""
        errors: list[str] = []
        validate_verification_evidence(report, {"AC-01", "BP-01"}, {"BP-01"}, "PASS", errors)
        self.assertEqual([], errors)

    def test_v4_state_is_rejected(self) -> None:
        scripts = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as root:
            subprocess.run(["python3", str(scripts / "init_feature.py"), "v4-rejection", "--root", root], check=True, capture_output=True, text=True)
            state_path = Path(root) / "delivery" / "v4-rejection" / "state.md"
            state_path.write_text(state_path.read_text(encoding="utf-8").replace('"schema_version": 5', '"schema_version": 4'), encoding="utf-8")
            result = subprocess.run(["python3", str(scripts / "validate_feature.py"), "v4-rejection", "--root", root], capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("schema_version must be 5", result.stdout)


if __name__ == "__main__":
    unittest.main()
