#!/usr/bin/env python3
"""Perform explicit Owner decisions on a schema-v12 Finding Ledger entry."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from delivery_governance import FINDING_STATUSES, load_ledger, timestamp, write_ledger
from delivery_graph import compile_graph, feature_dir
from delivery_proof import exclusive_file_lock


def transition(
    root: Path, feature_id: str, finding_id: str, status: str, owner: str, reason: str,
    superseded_by: str | None = None,
) -> None:
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
        if status == "FIXED_PENDING_REVIEW" and entry.get("status") not in {"OPEN", "FIXED_PENDING_REVIEW", "MERGE_CANDIDATE"}:
            raise ValueError("only an active Finding can move to FIXED_PENDING_REVIEW")
        if status == "ACCEPTED_RISK" and entry.get("severity") in {"critical", "major"}:
            raise ValueError("P0/P1 critical or major Findings cannot be accepted as delivery risk")
        if status == "SUPERSEDED":
            target = ledger["entries"].get(superseded_by or "")
            if not isinstance(target, dict) or superseded_by == finding_id:
                raise ValueError("SUPERSEDED requires a distinct existing --superseded-by target")
            if target.get("status") == "SUPERSEDED" or target.get("supersedes") is not None:
                raise ValueError("SUPERSEDED target must be a direct non-superseded canonical Finding")
            if any(
                other_id != finding_id and other.get("supersedes") == finding_id
                for other_id, other in ledger["entries"].items()
                if isinstance(other, dict)
            ):
                raise ValueError("a canonical Finding with existing aliases cannot itself be superseded")
            related = superseded_by in entry.get("merge_candidates", []) or finding_id in target.get("merge_candidates", [])
            if entry.get("status") != "MERGE_CANDIDATE" or not related:
                raise ValueError("only a MERGE_CANDIDATE may be superseded by its explicit semantic-overlap target")
            entry["supersedes"] = superseded_by
        elif superseded_by is not None:
            raise ValueError("--superseded-by is valid only with SUPERSEDED")
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
    parser.add_argument("--superseded-by")
    args = parser.parse_args(argv)
    try:
        transition(
            Path(args.root), args.feature_id, args.finding, args.status, args.owner, args.reason,
            args.superseded_by,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
