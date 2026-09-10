#!/usr/bin/env python3
"""Executable accident controls and before/after risk-discovery regressions."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from delivery_graph import observed_code_risk_vector
from high_risk_baseline import evaluate, run_baseline


class AccidentBaselineTest(unittest.TestCase):
    def test_correct_controls_pass_and_defects_fail_existing_oracles(self) -> None:
        report = run_baseline()
        self.assertEqual(5, len(report["cases"]))
        for case in report["cases"]:
            with self.subTest(case=case["id"]):
                self.assertTrue(case["controls"]["correct"]["accepted"], case)
                self.assertFalse(case["controls"]["defective"]["accepted"], case)
                self.assertTrue(case["controls"]["defective"]["weak_check_accepted"], case)
        self.assertEqual("passed", report["status"])
        self.assertEqual("not_assessed", report["delivery_ready"])

    def test_missing_business_readback_fails(self) -> None:
        self.assertEqual([{"id": "amount", "passed": False}], evaluate({}, [{
            "id": "amount", "oracle": {"source": "/observation/amount", "operator": "eq", "expected": 1099},
        }]))


class RiskDiscoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.git("init", "-q")
        self.git("config", "user.name", "DLV regression")
        self.git("config", "user.email", "regression@example.invalid")

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=self.root, check=True, capture_output=True, text=True,
        ).stdout.strip()

    def graph(self, path: str = "service.py") -> dict:
        return {"nodes": [{"id": "SYM-001", "type": "Symbol", "attributes": {"path": path}}]}

    def baseline(self, content: str, path: str = "service.py") -> str:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        self.git("add", "--", path)
        self.git("commit", "-qm", "baseline")
        return self.git("rev-parse", "HEAD")

    def test_destructive_ddl_is_detected_without_sql_comments(self) -> None:
        for sql in (
            "DROP TABLE accounts;", "ALTER TABLE orders DROP COLUMN amount;",
            "TRUNCATE TABLE ledger;", "ALTER TABLE orders ALTER COLUMN amount TYPE DECIMAL(6, 1);",
        ):
            with self.subTest(sql=sql):
                (self.root / "change.sql").write_text(sql, encoding="utf-8")
                risk = observed_code_risk_vector(self.root, self.graph("change.sql"))
                self.assertEqual("present", risk["PERSISTENCE"])
                self.assertEqual("present", risk["IRREVERSIBLE_SIDE_EFFECT"])

    def test_client_version_identifiers_escalate_without_explanatory_comments(self) -> None:
        for identifier in ("clientVersion", "appVersion", "client_version", "miniProgram"):
            with self.subTest(identifier=identifier):
                (self.root / "service.py").write_text(f"{identifier} = 'previous'\n", encoding="utf-8")
                self.assertEqual("present", observed_code_risk_vector(self.root, self.graph())["CROSS_CLIENT"])

    def test_additive_ddl_is_persistent_without_automatic_destructive_label(self) -> None:
        (self.root / "change.sql").write_text("ALTER TABLE orders ADD COLUMN note TEXT;", encoding="utf-8")
        risk = observed_code_risk_vector(self.root, self.graph("change.sql"))
        self.assertEqual("present", risk["PERSISTENCE"])
        self.assertEqual("absent", risk["IRREVERSIBLE_SIDE_EFFECT"])

    def test_deleted_tracked_file_retains_old_risk(self) -> None:
        self.baseline("SELECT amount FROM orders; // clientVersion\n")
        (self.root / "service.py").unlink()
        risk = observed_code_risk_vector(self.root, self.graph())
        for axis in ("PERSISTENCE", "MONEY", "CROSS_CLIENT"):
            self.assertEqual("present", risk[axis], axis)

    def test_removed_authorization_and_compatibility_logic_retains_risk(self) -> None:
        self.baseline("permission = True\nclient_version = 'old'\n")
        (self.root / "service.py").write_text("result = 1\n", encoding="utf-8")
        risk = observed_code_risk_vector(self.root, self.graph())
        self.assertEqual("present", risk["AUTHORIZATION"])
        self.assertEqual("present", risk["CROSS_CLIENT"])

    def test_git_display_configuration_cannot_hide_removed_risk(self) -> None:
        self.baseline("permission = True\n")
        self.git("config", "color.ui", "always")
        self.git("config", "diff.outputIndicatorOld", "!")
        (self.root / "service.py").unlink()
        self.assertEqual("present", observed_code_risk_vector(self.root, self.graph())["AUTHORIZATION"])

    def test_committed_deletion_uses_frozen_baseline(self) -> None:
        baseline = self.baseline("SELECT amount FROM orders;\n")
        self.git("rm", "--", "service.py")
        self.git("commit", "-qm", "remove old service")
        risk = observed_code_risk_vector(self.root, self.graph(), baseline)
        self.assertEqual("present", risk["PERSISTENCE"])
        self.assertEqual("present", risk["MONEY"])

    def test_directory_subject_includes_removed_child(self) -> None:
        self.baseline("permission = True\n", "src/guard.py")
        (self.root / "src/guard.py").unlink()
        self.assertEqual("present", observed_code_risk_vector(self.root, self.graph("src"))["AUTHORIZATION"])

    def test_renamed_old_subject_and_unicode_paths_retain_risk(self) -> None:
        old = "src/旧 接口.py"
        self.baseline("client_version = 'old'\n", old)
        self.git("mv", "--", old, "src/new.py")
        self.assertEqual("present", observed_code_risk_vector(self.root, self.graph(old))["CROSS_CLIENT"])

    def test_pathspec_metacharacters_are_literal(self) -> None:
        self.baseline("permission = True\n", "literal-secret.py")
        (self.root / "literal-secret.py").unlink()
        (self.root / "literal*.py").write_text("caption = 'Hello'\n", encoding="utf-8")
        self.assertEqual("absent", observed_code_risk_vector(self.root, self.graph("literal*.py"))["AUTHORIZATION"])

    def test_symlinked_parent_does_not_read_outside_subjects(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            (Path(outside) / "service.py").write_text("permission = True\n", encoding="utf-8")
            (self.root / "linked").symlink_to(outside, target_is_directory=True)
            risk = observed_code_risk_vector(self.root, self.graph("linked/service.py"))
            self.assertEqual("absent", risk["AUTHORIZATION"])

    def test_plain_local_change_does_not_inherit_unrelated_repository_risk(self) -> None:
        self.baseline("DROP TABLE accounts;\n", "unrelated.sql")
        (self.root / "service.py").write_text("caption = 'Hello'\n", encoding="utf-8")
        self.assertTrue(all(value == "absent" for value in observed_code_risk_vector(self.root, self.graph()).values()))

    def test_missing_explicit_baseline_fails_closed(self) -> None:
        self.baseline("caption = 'Hello'\n")
        with self.assertRaisesRegex(ValueError, "baseline"):
            observed_code_risk_vector(self.root, self.graph(), "f" * 40)


if __name__ == "__main__":
    unittest.main()
