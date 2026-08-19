#!/usr/bin/env python3
"""Finalize a schema-v6 delivery only after every deterministic gate passes."""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from delivery_proof import (
    atomic_write_text,
    file_digest,
    finalization_token,
    proof_contract_digest,
    extract_state,
    write_state,
)


def timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def validate(scripts: Path, feature_id: str, root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(scripts / "validate_feature.py"), feature_id, "--root", str(root)],
        capture_output=True,
        text=True,
    )


def restore_if_unchanged(path: Path, expected: str, original: str) -> bool:
    if path.read_text(encoding="utf-8") != expected:
        return False
    atomic_write_text(path, original)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve()
    state_path = root / "delivery" / args.feature_id / "state.md"
    verification_path = state_path.parent / "verification.md"
    if not state_path.is_file() or not verification_path.is_file():
        print("error: state.md and verification.md are required", file=sys.stderr)
        return 2
    content, state = extract_state(state_path)
    if state.get("schema_version") != 6:
        print("error: finalize_delivery.py only accepts schema_version=6", file=sys.stderr)
        return 2
    verification = state.get("stages", {}).get("verification", {})
    if verification.get("verdict") != "PASS":
        print("error: verification verdict must be PASS", file=sys.stderr)
        return 1

    original = content
    verification["status"] = "in_progress"
    verification["fingerprint"] = file_digest(verification_path)
    verification["finalization"] = None
    stages = state["stages"]
    inputs = verification.setdefault("inputs", {})
    inputs.update(
        {
            "prd": stages.get("prd", {}).get("fingerprint"),
            "prototype": (
                stages.get("prototype", {}).get("fingerprint")
                if stages.get("prototype", {}).get("status") == "completed"
                else None
            ),
            "architecture": stages.get("architecture", {}).get("fingerprint"),
            "code_spec": stages.get("code_spec", {}).get("fingerprint"),
            "code_result": stages.get("code", {}).get("result"),
            "proof_contract": proof_contract_digest(state.get("proof_contract")),
        }
    )
    state["last_updated"] = timestamp()
    write_state(state_path, content, state)
    preflight_state = state_path.read_text(encoding="utf-8")
    preflight = validate(Path(__file__).resolve().parent, args.feature_id, root)
    if preflight.returncode != 0:
        restored = restore_if_unchanged(state_path, preflight_state, original)
        print(preflight.stdout, end="")
        message = "state restored" if restored else "state changed concurrently; refusing destructive rollback"
        print(f"error: delivery gates failed; {message}", file=sys.stderr)
        return 1

    content, state = extract_state(state_path)
    verification = state["stages"]["verification"]
    verification["status"] = "completed"
    verification["finalization"] = {
        "tool": "finalize_delivery.py",
        "finalized_at": timestamp(),
        "token": None,
    }
    verification["finalization"]["token"] = finalization_token(state)
    state["current_stage"] = "verification"
    state["last_updated"] = timestamp()
    write_state(state_path, content, state)
    finalized_state = state_path.read_text(encoding="utf-8")
    final = validate(Path(__file__).resolve().parent, args.feature_id, root)
    if final.returncode != 0:
        restored = restore_if_unchanged(state_path, finalized_state, original)
        print(final.stdout, end="")
        message = "state restored" if restored else "state changed concurrently; refusing destructive rollback"
        print(f"error: finalization validation failed; {message}", file=sys.stderr)
        return 1
    print(final.stdout, end="")
    print(f"finalized: {state_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
