#!/usr/bin/env python3
"""Render and finalize schema-v9 delivery from one fresh Verification Run."""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from delivery_proof import (
    atomic_write_text,
    exclusive_file_lock,
    file_digest,
    finalization_token,
    proof_contract_digest,
    extract_state,
    write_state,
    validate_feature_id,
)
from validate_verification_evidence import validate_verification_run
from verification_run import recover_pending_transaction, render_locked


def timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def validate(scripts: Path, feature_id: str, root: Path, *, final: bool = False) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(scripts / "validate_feature.py"), feature_id, "--root", str(root)]
    if final:
        command.append("--final")
    return subprocess.run(
        command,
        capture_output=True, text=True,
    )


def current_text(path: Path) -> str | None:
    return path.read_text(encoding="utf-8") if path.is_file() else None


def restore_if_unchanged(path: Path, original: str | None, expected: str | None) -> bool:
    """Compare-and-swap rollback: never overwrite an external concurrent edit."""
    if current_text(path) != expected:
        return False
    if original is None:
        path.unlink(missing_ok=True)
    else:
        atomic_write_text(path, original)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve()
    try:
        validate_feature_id(args.feature_id)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    state_path = root / "delivery" / args.feature_id / "state.md"
    report_path = state_path.parent / "verification.md"
    if not state_path.is_file():
        print("error: state.md is required", file=sys.stderr)
        return 2
    content, state = extract_state(state_path)
    if state.get("schema_version") != 9:
        print("error: finalize_delivery.py only accepts schema_version=9", file=sys.stderr)
        return 2
    run_id = state.get("stages", {}).get("verification", {}).get("active_run_id")
    if not isinstance(run_id, str) or not run_id:
        print("error: Verification requires an active run", file=sys.stderr)
        return 1
    destination = root / ".dlv" / "runs" / args.feature_id / run_id
    with exclusive_file_lock(root / ".dlv" / "runs" / args.feature_id / ".feature.lock"), exclusive_file_lock(destination / ".run.lock"):
        original_state = current_text(state_path)
        original_report = current_text(report_path)
        expected_state = original_state
        expected_report = original_report
        run_errors: list[str] = []
        try:
            recover_pending_transaction(args.feature_id, root, run_id)
            content, state = extract_state(state_path)
            original_state = current_text(state_path)
            expected_state = original_state
            verdict, digest = validate_verification_run(root, args.feature_id, state, run_errors)
            if verdict != "PASS":
                raise ValueError("Verification Run is BLOCKED: " + "; ".join(run_errors))

            verification = state["stages"]["verification"]
            stages = state["stages"]
            verification.update({"status": "in_progress", "run_digest": digest, "verdict": "PASS", "finalization": None})
            verification["inputs"] = {
                "prd": stages.get("prd", {}).get("fingerprint"),
                "prototype": stages.get("prototype", {}).get("fingerprint") if stages.get("prototype", {}).get("status") == "completed" else None,
                "architecture": stages.get("architecture", {}).get("fingerprint"),
                "code_spec": stages.get("code_spec", {}).get("fingerprint"),
                "code_result": stages.get("code", {}).get("result"),
                "proof_contract": proof_contract_digest(state.get("proof_contract")),
                "repositories": stages.get("code", {}).get("inputs", {}).get("repositories", {}),
            }
            state["last_updated"] = timestamp()
            write_state(state_path, content, state)
            expected_state = current_text(state_path)

            render_locked(args.feature_id, root, run_id)
            expected_report = current_text(report_path)
            content, state = extract_state(state_path)
            state["stages"]["verification"]["fingerprint"] = file_digest(report_path)
            write_state(state_path, content, state)
            expected_state = current_text(state_path)
            preflight = validate(Path(__file__).resolve().parent, args.feature_id, root)
            if preflight.returncode != 0:
                raise ValueError(preflight.stdout.strip() or preflight.stderr.strip())

            content, state = extract_state(state_path)
            verification = state["stages"]["verification"]
            verification["status"] = "completed"
            verification["finalization"] = {"tool": "finalize_delivery.py", "finalized_at": timestamp(), "token": None}
            verification["finalization"]["token"] = finalization_token(state)
            state["last_updated"] = timestamp()
            write_state(state_path, content, state)
            expected_state = current_text(state_path)
            final = validate(Path(__file__).resolve().parent, args.feature_id, root, final=True)
            if final.returncode != 0:
                raise ValueError(final.stdout.strip() or final.stderr.strip())
        except Exception as exc:
            state_restored = restore_if_unchanged(state_path, original_state, expected_state)
            report_restored = restore_if_unchanged(report_path, original_report, expected_report)
            suffix = ""
            if not state_restored or not report_restored:
                suffix = "; concurrent edits were preserved and require manual reconciliation"
            print(f"error: finalization failed; safe rollback attempted: {exc}{suffix}", file=sys.stderr)
            return 1
    print(final.stdout, end="")
    print(f"DELIVERY COMPLETE: {state_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
