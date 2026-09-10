#!/usr/bin/env python3
"""Domain omission/mutation controls and implementation-evidence binding."""

import copy
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from high_risk_contracts import high_risk_issues
from review_evidence import implementation_evidence
import test_delivery_graph as fixtures


class DomainContractTest(unittest.TestCase):
    def test_existing_concurrency_contract_is_complete(self):
        self.assertEqual([], high_risk_issues(fixtures.valid_graph()))

    def test_missing_contract_cannot_hide_behind_generic_proof(self):
        graph = fixtures.valid_graph()
        next(node for node in graph["nodes"] if node["id"] == "RISK-001")["attributes"].pop("verification")
        self.assertIn("HIGH_RISK_CONTRACT_MISSING", {item["code"] for item in high_risk_issues(graph)})

    def test_observed_or_source_axis_requires_explicit_domain(self):
        for axis in ("PERSISTENCE", "API_CONTRACT", "AUTHORIZATION", "TENANCY", "MONEY"):
            with self.subTest(axis=axis):
                self.assertIn("HIGH_RISK_UNMODELED", {item["code"] for item in high_risk_issues(fixtures.valid_graph(), {axis: "present"})})

    def test_missing_aliased_unrelated_and_boolean_checks_block(self):
        for mutation in ("missing", "alias", "unrelated", "boolean", "weak", "subjects"):
            graph = fixtures.valid_graph()
            risk = next(node for node in graph["nodes"] if node["id"] == "RISK-001")
            checks = risk["attributes"]["verification"]["domains"]["concurrency"]["checks"]
            assertion = next(node for node in graph["nodes"] if node["id"] == "ASRT-015")
            if mutation == "missing":
                checks.pop("interleaving")
            elif mutation == "alias":
                checks["interleaving"] = checks["invariant_readback"]
            elif mutation == "unrelated":
                checks["interleaving"] = "ASRT-001"
            elif mutation == "boolean":
                assertion["attributes"]["oracle"]["expected"] = True
            elif mutation == "subjects":
                assertion["attributes"]["subject_ids"] = ["REQ-001"]
            else:
                next(node for node in graph["nodes"] if node["id"] == "PO-002")["attributes"]["proof_type"] = "artifact"
            with self.subTest(mutation=mutation):
                self.assertTrue(high_risk_issues(graph))

    def test_code_snapshot_changes_and_refuses_missing_or_symlink_source(self):
        graph = fixtures.valid_graph()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            fixtures.bind_test_runtime_files(root, graph)
            (root / "src").mkdir()
            source = root / "src/domain_service.py"
            with self.assertRaisesRegex(ValueError, "missing"):
                implementation_evidence(root, graph, {"RISK-001"}, "UNBORN")
            source.write_text("version = 1\n")
            old = implementation_evidence(root, graph, {"RISK-001"}, "UNBORN")
            source.write_text("version = 2\n")
            new = implementation_evidence(root, graph, {"RISK-001"}, "UNBORN")
            self.assertNotEqual(old[0]["after_sha256"], new[0]["after_sha256"])
            source.unlink()
            source.symlink_to(root / "outside.py")
            with self.assertRaisesRegex(ValueError, "symlink"):
                implementation_evidence(root, graph, {"RISK-001"}, "UNBORN")

    def test_each_domain_has_a_complete_positive_control_and_missing_check_mutant(self):
        from high_risk_contracts import domain_roles
        contexts = {
            "database": ({"PERSISTENCE"}, {"engine": "PostgreSQL", "engine_version": "16", "change_kind": "destructive_schema", "from_schema": "v1", "to_schema": "v2", "consumers": ["old-job"], "rollback_boundary": "before contract", "recovery_method": "restore and replay", "destructive_execution_conditions": "no active old consumers"}),
            "compatibility": ({"CROSS_CLIENT"}, {"supported_clients": ["mini-program-v1"], "historical_state": "pending payment", "rollout_order": "server first", "reverse_combination": "required"}),
            "authorization": ({"AUTHORIZATION", "TENANCY"}, {"principal_scope": "account and tenant", "resource_scope": "orders", "revocation_max_seconds": 0}),
            "money": ({"MONEY"}, {"currency": "CNY", "unit": "minor", "business_key": "payment ID"}),
        }
        for domain, (axes, context) in contexts.items():
            graph = fixtures.valid_graph()
            risk = next(node for node in graph["nodes"] if node["id"] == "RISK-001")
            risk["attributes"]["risk_axes"] = sorted(axes)
            roles, errors = domain_roles(domain, context, axes)
            self.assertEqual([], errors)
            checks = {}
            for index, role in enumerate(sorted(roles), 100):
                aid = f"ASRT-{index:03}"
                checks[role] = aid
                graph["nodes"].append(fixtures.node(aid, "Assertion", role, role, oracle={"kind": "json_path", "source": f"/observation/{role}", "operator": "lte" if role == "revocation_window" else "eq", "expected": 0}, subject_ids=["RISK-001"]))
                graph["edges"].append(fixtures.edge(aid, "proves", "PO-002"))
            risk["attributes"]["verification"]["domains"] = {domain: {"context": context, "checks": checks}}
            with self.subTest(domain=domain):
                self.assertEqual([], high_risk_issues(graph))
                if domain == "authorization":
                    risk["attributes"]["risk_axes"] = ["AUTHORIZATION"]
                    saved = checks.pop("tenant_isolation")
                    self.assertEqual([], high_risk_issues(graph))
                    self.assertTrue(high_risk_issues(graph, {"TENANCY": "present"}))
                    risk["attributes"]["risk_axes"] = sorted(axes)
                    checks["tenant_isolation"] = saved
                    window = next(node for node in graph["nodes"] if node["id"] == checks["revocation_window"])
                    window["attributes"]["oracle"]["expected"] = 30
                    self.assertIn("HIGH_RISK_REVOCATION_WINDOW", {item["code"] for item in high_risk_issues(graph)})
                    window["attributes"]["oracle"]["expected"] = 0
                for role in checks:
                    broken = copy.deepcopy(graph)
                    next(node for node in broken["nodes"] if node["id"] == "RISK-001")["attributes"]["verification"]["domains"][domain]["checks"].pop(role)
                    self.assertTrue(high_risk_issues(broken), role)

    def test_runner_sources_and_explicit_dependencies_are_bound(self):
        graph = fixtures.valid_graph()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            fixtures.bind_test_runtime_files(root, graph)
            (root / "src").mkdir()
            (root / "src/domain_service.py").write_text("# service\n")
            (root / "runner.py").write_text("# runner\n")
            (root / "helper.py").write_text("# helper\n")
            proof = next(node for node in graph["nodes"] if node["id"] == "PO-002")
            proof["attributes"]["runner"]["argv"] = [sys.executable, "runner.py"]
            proof["attributes"]["review_paths"] = ["helper.py"]
            evidence = implementation_evidence(root, graph, {"RISK-001"}, "UNBORN")
            self.assertEqual({"runner.py", "helper.py"}, {item["runner_path"] for item in evidence if "runner_path" in item})
            (root / "helper.py").write_text("# changed helper\n")
            self.assertNotEqual(evidence, implementation_evidence(root, graph, {"RISK-001"}, "UNBORN"))

    def test_malformed_axes_and_database_kind_report_issues(self):
        from high_risk_contracts import domain_roles
        for axes in (None, "MONEY", [{}], []):
            graph = fixtures.valid_graph()
            next(node for node in graph["nodes"] if node["id"] == "RISK-001")["attributes"]["risk_axes"] = axes
            self.assertIn("HIGH_RISK_AXES_INVALID", {item["code"] for item in high_risk_issues(graph)})
        self.assertTrue(domain_roles("database", {"change_kind": {}}, {"PERSISTENCE"})[1])

    def test_baseline_and_unchanged_fixture_are_in_snapshot(self):
        graph = fixtures.valid_graph()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            fixtures.bind_test_runtime_files(root, graph)
            (root / "src").mkdir()
            source = root / "src/domain_service.py"
            source.write_text("# old consumer\n")
            for command in (["init", "-q"], ["add", "src/domain_service.py"], ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "baseline"]):
                subprocess.run(["git", *command], cwd=root, check=True, capture_output=True)
            baseline = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
            source.write_text("# new consumer\n")
            evidence = implementation_evidence(root, graph, {"RISK-001"}, baseline)
            self.assertEqual("# old consumer\n", evidence[0]["before"])
            self.assertEqual("# new consumer\n", evidence[0]["after"])
            self.assertTrue(any(item.get("environment_id") == "ENV-001" for item in evidence))

    def test_oversized_source_stale_fixture_and_understated_ddl_fail_closed(self):
        from review_evidence import MAX_FILE_BYTES
        graph = fixtures.valid_graph()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            fixtures.bind_test_runtime_files(root, graph)
            (root / "src").mkdir()
            source = root / "src/domain_service.py"
            source.write_text("x" * (MAX_FILE_BYTES + 1))
            with self.assertRaises(ValueError):
                implementation_evidence(root, graph, {"RISK-001"}, "UNBORN")
            source.write_text("DROP TABLE orders;\n")
            risk = next(node for node in graph["nodes"] if node["id"] == "RISK-001")
            risk["attributes"]["verification"]["domains"] = {"database": {"context": {"change_kind": "schema"}}}
            with self.assertRaisesRegex(ValueError, "understates"):
                implementation_evidence(root, graph, {"RISK-001"}, "UNBORN")
            source.write_text("# implementation\n")
            fixture = next(node for node in graph["nodes"] if node["id"] == "ENV-001")["attributes"]["spec"]["fixture"]
            (root / fixture["path"]).write_text("{}\n")
            with self.assertRaisesRegex(ValueError, "fixture digest is stale"):
                implementation_evidence(root, graph, {"RISK-001"}, "UNBORN")


if __name__ == "__main__":
    unittest.main()
