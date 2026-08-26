#!/usr/bin/env python3
"""Perform explicit Owner decisions on a schema-v11 Finding Ledger entry."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from delivery_governance import FINDING_STATUSES, NON_WAIVABLE_AXES, load_ledger, timestamp, write_ledger
from delivery_graph import compile_graph, feature_dir
from delivery_proof import exclusive_file_lock


def transition(root: Path, feature_id: str, finding_id: str, status: str, owner: str, reason: str) -> None:
    root = root.expanduser().resolve()
    feature_dir(root, feature_id)
    if status not in {"FIXED_PENDING_REVIEW", "OUT_OF_SCOPE", "ACCEPTED_RISK", "SUPERSEDED"}:
        raise ValueError("finding transition must set FIXED_PENDING_REVIEW or an Owner decision outcome")
    if not owner.strip() or not reason.strip():
        raise ValueError("Owner decision requires a non-empty owner and reason")
    lock = root / ".dlv" / "runs" / feature_id / ".feature.lock"
    with exclusive_file_lock(lock):
        ledger = load_ledger(root, feature_id)
        entry = ledger["entries"].get(finding_id)
        if not isinstance(entry, dict):
            raise ValueError("unknown finding id")
        if status == "FIXED_PENDING_REVIEW" and entry.get("status") not in {"OPEN", "FIXED_PENDING_REVIEW"}:
            raise ValueError("only an active Finding can move to FIXED_PENDING_REVIEW")
        if status == "ACCEPTED_RISK" and any(axis in entry["risk_path"] for axis in NON_WAIVABLE_AXES):
            raise ValueError("non-waivable tenancy, authorization, money, or irreversible-side-effect risk cannot be accepted")
        entry["status"] = status
        entry["waiver"] = {"owner": owner, "reason": reason, "decided_at": timestamp()} if status == "ACCEPTED_RISK" else None
        entry["last_seen_at"] = timestamp()
        write_ledger(root, feature_id, ledger)
    compile_graph(root, feature_id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--finding", required=True)
    parser.add_argument("--status", required=True, choices=sorted(FINDING_STATUSES))
    parser.add_argument("--owner", required=True)
    parser.add_argument("--reason", required=True)
    args = parser.parse_args(argv)
    try:
        transition(Path(args.root), args.feature_id, args.finding, args.status, args.owner, args.reason)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
