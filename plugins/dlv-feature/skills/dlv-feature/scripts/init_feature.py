#!/usr/bin/env python3
"""Initialize the minimal delivery state for dlv-feature."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


FEATURE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
STAGES = ("prd", "prototype", "architecture", "code_spec", "code", "verification")
STATE_START = "<!-- DLV_STATE_START -->"
STATE_END = "<!-- DLV_STATE_END -->"


def timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def stage_state(name: str) -> dict:
    state = {"status": "pending"}
    if name in {"prd", "prototype", "architecture", "code_spec", "verification"}:
        state.update({"fingerprint": None})
    if name in {"prd", "prototype", "architecture", "code_spec"}:
        state.update({"reviewed_at": None})
    if name == "code":
        state.update(
            {
                "inputs": {"code_spec": None, "repositories": {}},
                "result": None,
                "simplicity_gate": None,
            }
        )
    if name == "verification":
        state.update(
            {
                "inputs": {
                    "prd": None,
                    "prototype": None,
                    "architecture": None,
                    "code_spec": None,
                    "code_result": None,
                    "proof_contract": None,
                    "repositories": {},
                },
                "active_run_id": None,
                "run_digest": None,
                "evidence_count": 0,
                "evidence_head": None,
                "verdict": None,
                "finalization": None,
            }
        )
    if name == "prototype":
        state.update({"inputs": {"prd": None}, "contract": None})
    if name == "architecture":
        state.update({"inputs": {"prd": None, "prototype": None, "repositories": {}}})
    if name == "code_spec":
        state.update({"inputs": {"prd": None, "architecture": None, "repositories": {}}})
    return state


def render_state(state: dict) -> str:
    payload = json.dumps(state, ensure_ascii=False, indent=2)
    return (
        "# 需求交付状态\n\n"
        "> 此文件由 dlv-feature 维护。仅修改下方状态块，不在块外复制状态字段。\n\n"
        f"{STATE_START}\n"
        "```json\n"
        f"{payload}\n"
        "```\n"
        f"{STATE_END}\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id", help="Lowercase hyphen-case feature ID")
    parser.add_argument("--root", default=".", help="Project root; defaults to current directory")
    args = parser.parse_args()

    if not FEATURE_ID.fullmatch(args.feature_id):
        print("error: feature-id must use lowercase letters, digits, and single hyphens", file=sys.stderr)
        return 2

    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        print(f"error: project root is not a directory: {root}", file=sys.stderr)
        return 2

    feature_dir = root / "delivery" / args.feature_id
    state_path = feature_dir / "state.md"
    if state_path.exists():
        print(f"exists: {state_path}")
        return 0
    if feature_dir.exists() and any(feature_dir.iterdir()):
        print(f"error: non-empty feature directory has no state.md: {feature_dir}", file=sys.stderr)
        return 1

    feature_dir.mkdir(parents=True, exist_ok=True)
    state = {
        "schema_version": 9,
        "feature_id": args.feature_id,
        "current_stage": "prd",
        "requirement_review": {
            "status": "pending",
            "source_fingerprint": None,
            "confirmed_ids": [],
            "summary": None,
            "reviewed_at": None,
        },
        "quality_reviews": {"product": None, "architecture": None, "code_spec": None},
        "architecture_review": {
            "status": "pending",
            "inputs": {"prd": None, "prototype": None, "repositories": {}},
            "existing_capabilities": [],
            "fact_owners": [],
            "additions": [],
            "api_decisions": [],
            "isolation": {"applicable": False, "verdict": "N/A"},
            "concurrency": {"applicable": False, "verdict": "N/A"},
            "rule_variants": {"applicable": False, "verdict": "N/A"},
            "boundary_proofs": {
                "applicable": None,
                "reason": None,
                "proofs": [],
                "verdict": "PENDING",
            },
            "material_decisions": [],
            "reviewed_at": None,
        },
        "proof_contract": {
            "status": "pending",
            "code_spec_fingerprint": None,
            "environments": [],
            "obligations": [],
            "quality_review": None,
            "sealed_at": None,
            "seal": None,
        },
        "stages": {name: stage_state(name) for name in STAGES},
        "risks": [],
        "last_updated": timestamp(),
    }
    state_path.write_text(render_state(state), encoding="utf-8")
    print(state_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
