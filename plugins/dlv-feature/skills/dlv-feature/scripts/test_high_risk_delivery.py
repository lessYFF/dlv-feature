#!/usr/bin/env python3
"""Local SQL accidents through signed evidence, sealing and finalization.

LLM responses and target transport are test doubles. Database observations,
RSA verification, kernel assertion evaluation and finalization are real.
"""

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_delivery_graph as f
from high_risk_baseline import observe


CONTEXTS = {
    "database": {"engine": "SQLite", "engine_version": "fixture-runtime", "change_kind": "data"},
    "compatibility": {"supported_clients": ["fixed-v1-pay-sequence"], "historical_state": "awaiting_payment", "rollout_order": "server first", "reverse_combination": "unreachable", "reverse_reason": "fixture client is not replaced"},
    "authorization": {"principal_scope": "account 1 and account 2", "resource_scope": "resource 7 owned by account 1", "revocation_max_seconds": 0},
    "money": {"currency": "CNY", "unit": "minor", "business_key": "payment-7"},
    "concurrency": {"schedule": "read/read/write/write", "failure_point": "both absence checks before either write"},
}
CASES = {
    "deleted_column_old_service": ({"PERSISTENCE"}, {"database": {"data_preservation": ("new_amount", 1099), "legacy_io": ("old_service_errors", 0), "migration_recovery": ("recovery_amount", 1099)}}),
    "money_precision_loss": ({"MONEY", "PERSISTENCE"}, {"database": {"data_preservation": ("mismatched_rows", 0)}, "money": {"amount_invariant": ("amounts", [1099, -1099, 1]), "side_effect_count": ("row_count", 3)}}),
    "old_client_payment": ({"CROSS_CLIENT"}, {"compatibility": {"legacy_workflow": ("pay_http_status", 200), "legacy_readback": ("order_status", "paid")}}),
    "disabled_account_session": ({"AUTHORIZATION"}, {"authorization": {"allowed_access": ("owner_visible_rows", 1), "denied_access": ("other_account_visible_rows", 0), "denied_side_effects": ("mutation_count", 0), "revoked_session": ("request_http_status", 403), "revocation_window": ("accepted_after_revocation_seconds", 0)}}),
    "duplicate_payment_callback": ({"MONEY", "CONCURRENCY"}, {"money": {"amount_invariant": ("charged_minor", 1099), "side_effect_count": ("posting_count", 1)}, "concurrency": {"interleaving": ("prewrite_counts", [0, 0]), "invariant_readback": ("posting_count", 1)}}),
}


def configure(root, case, defective):
    graph = f.delivery_graph.load_graph(root, "cross-domain-feature")
    axes, domains = CASES[case]
    risk = next(node for node in graph["nodes"] if node["id"] == "RISK-001")
    risk["attributes"]["risk_axes"] = sorted(axes)
    risk["attributes"]["verification"]["domains"] = {}
    for domain, checks in domains.items():
        context = copy.deepcopy(CONTEXTS[domain])
        if case == "deleted_column_old_service":
            context.update(change_kind="schema", from_schema="orders.amount", to_schema="orders.amount and amount_minor", consumers=["old-service-v1"], rollback_boundary="before dropping old column")
        bound = {}
        for role, (measurement, expected) in checks.items():
            aid = f"ASRT-{100 + len([node for node in graph['nodes'] if node['type'] == 'Assertion']):03}"
            graph["nodes"].append(f.node(aid, "Assertion", role, f"Measured {role}", oracle={"kind": "json_path", "source": f"/observation/{measurement}", "operator": "lte" if role == "revocation_window" else "eq", "expected": expected}, subject_ids=["RISK-001"]))
            graph["edges"].append(f.edge(aid, "proves", "PO-002"))
            bound[role] = aid
        risk["attributes"]["verification"]["domains"][domain] = {"context": context, "checks": bound}
    spec = next(node for node in graph["nodes"] if node["id"] == "ENV-001")["attributes"]["spec"]
    fixture = root / spec["fixture"]["path"]
    f.write_json(fixture, {"case": case, "defective": defective})
    spec["fixture"]["sha256"] = f.delivery_proof.file_digest(fixture)
    f.write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
    return graph


class HighRiskDeliveryTest(unittest.TestCase):
    def setUp(self):
        # Model execution is already a test double. Binary copying/code-signing
        # belongs to the dedicated isolation tests, not these domain controls.
        executable = patch.object(f.graph_review, "prepare_isolated_codex_executable", return_value="codex")
        executable.start()
        self.addCleanup(executable.stop)

    def test_all_accidents_reach_correct_final_gate_with_signed_measurements(self):
        helper = f.GraphTestCase()
        for case in CASES:
            for defective in (False, True):
                with self.subTest(case=case, defective=defective):
                    temporary, root = helper.make_root()
                    with temporary:
                        graph = configure(root, case, defective)
                        helper.review_all(root)
                        f.graph_contract.seal_contract(root, "cross-domain-feature")
                        f.delivery_graph.mark_code_complete(root, "cross-domain-feature")
                        spec = f.contracted_environment_spec(root)
                        environment = root / ".dlv/domain-env.json"
                        f.write_json(environment, spec)
                        destination = f.graph_verification.start("cross-domain-feature", root, "domain-run", [f"ENV-001={environment}"])
                        result = root / ".dlv/domain-result.json"
                        f.write_json(result, {"po_id": "PO-001", "proof_type": "boundary", "outcome": "evaluate", "anchors": []})
                        f.graph_verification.record("cross-domain-feature", root, "domain-run", result, [])
                        f.write_json(result, {"po_id": "PO-002", "proof_type": "invariant", "outcome": "evaluate", "anchors": []})

                        def target(*args, **kwargs):
                            nonce = kwargs["environment"]["DLV_CHALLENGE_NONCE"]
                            measured = observe(case, defective)
                            # Existing cross-type fixture assertions remain
                            # independent of the accident-specific obligations.
                            measured.update(fact_version=1, transition_version=1, writer_count=1, rejected_count=1, duplicate_count=0)
                            measured.update(challenge_nonce=nonce, target_identity=spec["target_identity"])
                            f.sign_target_observation(measured, spec, nonce)
                            return {"exit_code": 0, "stdout": json.dumps(measured), "stderr": "", "timed_out": False}

                        with patch.object(f.graph_verification, "run_bounded", side_effect=target):
                            f.graph_verification.record("cross-domain-feature", root, "domain-run", result, [])
                        records = f.graph_verification.load_manifest(destination / "evidence.jsonl")
                        self.assertEqual("failed" if defective else "passed", records[-1]["status"])
                        if defective:
                            with self.assertRaisesRegex(ValueError, "BLOCKED"):
                                f.graph_finalize.finalize(root, "cross-domain-feature")
                            state = f.delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
                            self.assertNotEqual("DELIVERY_READY", state["delivery_status"])
                        else:
                            f.graph_finalize.finalize(root, "cross-domain-feature")
                            self.assertEqual([], f.graph_validation.validate(root, "cross-domain-feature", final=True))

    def test_missing_domain_check_blocks_before_model_or_budget(self):
        helper = f.GraphTestCase()
        temporary, root = helper.make_root()
        with temporary:
            graph = configure(root, "old_client_payment", False)
            next(node for node in graph["nodes"] if node["id"] == "RISK-001")["attributes"]["verification"]["domains"]["compatibility"]["checks"].pop("legacy_readback")
            f.write_json(root / "delivery/cross-domain-feature/delivery-graph.json", graph)
            helper.seal_product(root)
            with patch.object(f.graph_review, "_run_semantic_unit") as reviewer:
                with self.assertRaises(ValueError):
                    f.graph_review.run_isolated_readiness_review(root, "cross-domain-feature", "missing-check")
                reviewer.assert_not_called()
            self.assertEqual([], f.load_ledger(root, "cross-domain-feature")["campaigns"])

    def test_code_change_invalidates_only_reviews_bound_to_implementation(self):
        helper = f.GraphTestCase()
        temporary, root = helper.make_root()
        with temporary:
            helper.review_all(root)
            before = f.delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")["attestations"]
            bound = set()
            for uid, summary in before.items():
                record = json.loads((root / summary["record_path"]).read_text())
                if "implementation_sha256" in record["execution"]:
                    bound.add(uid)
            self.assertTrue(bound)
            (root / "src/domain_service.py").write_text("# changed implementation\n")
            errors = f.graph_validation.validate(root, "cross-domain-feature")
            self.assertTrue(any("implementation evidence" in error for error in errors), errors)
            state = f.delivery_graph.compile_graph(root, "cross-domain-feature")
            self.assertFalse(bound & set(state["attestations"]))
            self.assertEqual(set(before) - bound, set(state["attestations"]))

    def test_missing_or_oversized_source_blocks_before_model_or_budget(self):
        from review_evidence import MAX_FILE_BYTES
        helper = f.GraphTestCase()
        for missing in (True, False):
            with self.subTest(missing=missing):
                temporary, root = helper.make_root()
                with temporary:
                    helper.seal_product(root)
                    source = root / "src/domain_service.py"
                    if missing:
                        source.unlink()
                    else:
                        source.write_text("x" * (MAX_FILE_BYTES + 1))
                    with patch.object(f.graph_review, "_run_semantic_unit") as reviewer:
                        with self.assertRaises(ValueError):
                            f.graph_review.run_isolated_readiness_review(root, "cross-domain-feature", "unavailable-source")
                        reviewer.assert_not_called()
                    self.assertEqual([], f.load_ledger(root, "cross-domain-feature")["campaigns"])

    def test_source_change_before_review_publication_rejects_results(self):
        helper = f.GraphTestCase()
        temporary, root = helper.make_root()
        with temporary:
            helper.seal_product(root)
            record = f.graph_review._record_units

            def change_before_record(*args, **kwargs):
                (root / "src/domain_service.py").write_text("# changed after all reviewers finished\n")
                return record(*args, **kwargs)

            with patch.object(f.graph_review, "run_bounded", side_effect=helper.fake_semantic_run), patch.object(f.graph_review, "_record_units", side_effect=change_before_record):
                with self.assertRaisesRegex(ValueError, "implementation changed"):
                    f.graph_review.run_isolated_readiness_review(root, "cross-domain-feature", "source-race")
            state = f.delivery_graph.load_state(root / "delivery/cross-domain-feature/state.json")
            self.assertEqual({}, state["attestations"])
            with self.assertRaises(ValueError):
                f.graph_contract.seal_contract(root, "cross-domain-feature")


if __name__ == "__main__":
    unittest.main()
