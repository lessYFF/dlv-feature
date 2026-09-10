#!/usr/bin/env python3
"""Run local accident controls through the delivery oracle (not semantic Review).

Fixtures execute SQLite operations and fixed legacy request sequences. They do
not attest a production target, exercise an LLM, or grant DELIVERY_READY.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from delivery_proof import evaluate_oracle, resolve_source


def observe(case: str, defective: bool) -> dict:
    with closing(sqlite3.connect(":memory:")) as db:
        if case == "deleted_column_old_service":
            db.executescript("CREATE TABLE orders (id INTEGER PRIMARY KEY, amount INTEGER); INSERT INTO orders VALUES (1, 1099);")
            db.execute("ALTER TABLE orders ADD COLUMN amount_minor INTEGER")
            db.execute("UPDATE orders SET amount_minor = amount")
            # Replay the backfill before contract/cleanup; measure recovery
            # instead of declaring that a migration command returned success.
            db.execute("UPDATE orders SET amount_minor = amount")
            recovered = db.execute("SELECT amount_minor FROM orders WHERE id = 1").fetchone()[0]
            if defective:
                db.execute("ALTER TABLE orders DROP COLUMN amount")
            try:
                old_amount = db.execute("SELECT amount FROM orders WHERE id = 1").fetchone()[0]
                old_errors = 0
            except sqlite3.OperationalError:
                old_amount, old_errors = None, 1
            return {
                "migration_completed": 1, "old_service_errors": old_errors,
                "old_amount": old_amount,
                "new_amount": db.execute("SELECT amount_minor FROM orders WHERE id = 1").fetchone()[0],
                "recovery_amount": recovered,
            }

        if case == "money_precision_loss":
            # Exact minor units avoid floating point ambiguity in the oracle.
            db.executescript("CREATE TABLE ledger (id INTEGER PRIMARY KEY, amount_minor INTEGER); INSERT INTO ledger VALUES (1, 1099), (2, -1099), (3, 1);")
            db.execute("CREATE TABLE migrated_ledger (id INTEGER PRIMARY KEY, amount_minor INTEGER)")
            expression = "(amount_minor / 100) * 100" if defective else "amount_minor"
            db.execute(f"INSERT INTO migrated_ledger SELECT id, {expression} FROM ledger")
            mismatch = db.execute(
                "SELECT COUNT(*) FROM ledger a JOIN migrated_ledger b ON a.id = b.id WHERE a.amount_minor != b.amount_minor"
            ).fetchone()[0]
            return {
                "migration_completed": 1, "mismatched_rows": mismatch,
                "row_count": db.execute("SELECT COUNT(*) FROM migrated_ledger").fetchone()[0],
                "amounts": [row[0] for row in db.execute("SELECT amount_minor FROM migrated_ledger ORDER BY id")],
            }

        if case == "old_client_payment":
            db.executescript("CREATE TABLE orders (id INTEGER PRIMARY KEY, status TEXT, charged_minor INTEGER); INSERT INTO orders VALUES (7, 'awaiting_payment', 0);")
            # Frozen old behavior: the historical endpoint carries the user's
            # payment intent. No new confirmation field or new request is added.
            requests = (("GET", "/orders/7", {}), ("POST", "/orders/7/pay", {"order_id": 7}))
            statuses = []
            for method, path, body in requests:
                if method == "GET":
                    statuses.append(200)
                elif defective and "price_confirmed" not in body:
                    statuses.append(409)
                else:
                    db.execute("UPDATE orders SET status = 'paid', charged_minor = 1099 WHERE id = ?", (body["order_id"],))
                    statuses.append(200)
            status, charged = db.execute("SELECT status, charged_minor FROM orders WHERE id = 7").fetchone()
            return {"detail_http_status": statuses[0], "pay_http_status": statuses[1], "order_status": status, "charged_minor": charged}

        if case == "disabled_account_session":
            db.executescript("CREATE TABLE accounts (id INTEGER PRIMARY KEY, enabled INTEGER); INSERT INTO accounts VALUES (1, 1); CREATE TABLE mutations (account_id INTEGER);")
            db.executescript("CREATE TABLE resources (id INTEGER PRIMARY KEY, owner_id INTEGER); INSERT INTO resources VALUES (7, 1);")
            owner_rows = db.execute("SELECT COUNT(*) FROM resources WHERE id = 7 AND owner_id = 1").fetchone()[0]
            other_rows = db.execute("SELECT COUNT(*) FROM resources WHERE id = 7 AND owner_id = 2").fetchone()[0]
            # Fixture policy: disabling takes effect on the next request,
            # including a session issued before the account was disabled.
            cached_enabled = db.execute("SELECT enabled FROM accounts WHERE id = 1").fetchone()[0]
            db.execute("UPDATE accounts SET enabled = 0 WHERE id = 1")
            authorized = cached_enabled if defective else db.execute("SELECT enabled FROM accounts WHERE id = 1").fetchone()[0]
            if authorized:
                db.execute("INSERT INTO mutations VALUES (1)")
            return {
                "account_enabled": db.execute("SELECT enabled FROM accounts WHERE id = 1").fetchone()[0],
                "request_http_status": 200 if authorized else 403,
                "mutation_count": db.execute("SELECT COUNT(*) FROM mutations").fetchone()[0],
                "owner_visible_rows": owner_rows, "other_account_visible_rows": other_rows,
                # Controlled fixture clock: disable at t=0, use the old session
                # at t=1. Production runners must measure their actual schedule.
                "accepted_after_revocation_seconds": 1 if authorized else 0,
            }

        if case == "duplicate_payment_callback":
            db.execute("CREATE TABLE postings (business_id TEXT, amount_minor INTEGER)")
            if not defective:
                db.execute("CREATE UNIQUE INDEX one_posting ON postings (business_id)")
            # Force the dangerous read/read/write/write schedule: both workers
            # see absence before either inserts. This is not a load benchmark.
            seen = [db.execute("SELECT COUNT(*) FROM postings WHERE business_id = 'payment-7'").fetchone()[0] for _ in range(2)]
            for count in seen:
                if count == 0:
                    try:
                        db.execute("INSERT INTO postings VALUES ('payment-7', 1099)")
                    except sqlite3.IntegrityError:
                        pass  # This fixed fixture only has the unique constraint.
            return {
                "callback_count": len(seen), "prewrite_counts": seen,
                "posting_count": db.execute("SELECT COUNT(*) FROM postings").fetchone()[0],
                "charged_minor": db.execute("SELECT SUM(amount_minor) FROM postings").fetchone()[0],
            }
        raise ValueError(f"unknown accident case: {case}")


def evaluate(observation: dict, assertions: list[dict]) -> list[dict]:
    return [
        {"id": assertion["id"], "passed": evaluate_oracle(
            resolve_source({"observation": observation}, assertion["oracle"]["source"]), assertion["oracle"],
        )}
        for assertion in assertions
    ]


def run_baseline() -> dict:
    contract_path = Path(__file__).resolve().parents[1] / "references/high-risk-baseline.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    results = []
    for case in contract["cases"]:
        controls = {}
        for name, defective in (("correct", False), ("defective", True)):
            observation = observe(case["id"], defective)
            assertions = evaluate(observation, case["assertions"])
            controls[name] = {
                "observation": observation, "assertions": assertions,
                "accepted": bool(assertions) and all(item["passed"] for item in assertions),
                "weak_check_accepted": all(item["passed"] for item in evaluate(observation, case["weak_assertions"])),
            }
        results.append({"id": case["id"], "controls": controls})
    passed = bool(results) and all(
        case["controls"]["correct"]["accepted"] and not case["controls"]["defective"]["accepted"]
        and case["controls"]["defective"]["weak_check_accepted"]
        for case in results
    )
    return {
        "status": "passed" if passed else "failed",
        "scope": "local SQLite/request fixtures and existing deterministic oracle; no LLM or target attestation",
        "semantic_review": "not_assessed", "delivery_ready": "not_assessed",
        "cases": results,
    }


if __name__ == "__main__":
    report = run_baseline()
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["status"] == "passed" else 1)
