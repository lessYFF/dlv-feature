#!/usr/bin/env python3
"""Deterministically finalize a schema-v13 Delivery Graph Verification Run."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from delivery_graph import atomic_write_json, confined_project_path, feature_dir, load_state, timestamp
from delivery_proof import atomic_write_text, exclusive_file_lock, file_digest
from graph_validation import finalization_token, validate
from delivery_manifest import build_manifest
from graph_verification import recover_pending_transaction, render, run_directory, validate_run


def _text(path: Path) -> str | None:
    return path.read_text(encoding="utf-8") if path.is_file() else None


def _restore(path: Path, original: str | None, expected: str | None) -> bool:
    if _text(path) != expected:
        return False
    if original is None:
        path.unlink(missing_ok=True)
    else:
        atomic_write_text(path, original)
    return True


def finalize(root: Path, feature_id: str) -> Path:
    root = root.expanduser().resolve()
    directory = feature_dir(root, feature_id)
    state_path = directory / "state.json"
    report_path = directory / "verification.md"
    manifest_path = directory / "delivery-manifest.json"
    state = load_state(state_path)
    run_id = state.get("verification", {}).get("active_run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("Verification requires an active run")
    destination = run_directory(root, feature_id, run_id)
    feature_lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    with exclusive_file_lock(feature_lock), exclusive_file_lock(destination / ".run.lock"):
        # WAL recovery is a committed evidence transaction, not part of the
        # finalization mutation. Establish the rollback baseline after it so a
        # later validation failure cannot strand manifest and state at
        # different hash-chain heads.
        recover_pending_transaction(root, feature_id, run_id)
        original_state, original_report, original_manifest = _text(state_path), _text(report_path), _text(manifest_path)
        expected_state, expected_report, expected_manifest = original_state, original_report, original_manifest
        try:
            state = load_state(state_path)
            errors = validate(root, feature_id)
            verdict, digest = validate_run(root, feature_id, run_id, errors)
            if verdict != "PASS" or errors:
                raise ValueError("Verification Run is BLOCKED: " + "; ".join(errors))
            render(feature_id, root, run_id, locked=True)
            expected_report = _text(report_path)
            state = load_state(state_path)
            verification = state["verification"]
            verification.update({
                "status": "completed",
                "run_digest": digest,
                "verdict": "PASS",
                "finalization": {
                    "tool": "finalize_delivery.py",
                    "finalized_at": timestamp(),
                    "token": None,
                },
            })
            verification["finalization"]["token"] = finalization_token(state, file_digest(report_path))
            atomic_write_json(state_path, state)
            expected_state = _text(state_path)
            atomic_write_json(manifest_path, build_manifest(directory, feature_id))
            expected_manifest = _text(manifest_path)
            final_errors = validate(root, feature_id, final=True)
            if final_errors:
                raise ValueError("; ".join(final_errors))
        except BaseException:
            state_restored = _restore(state_path, original_state, expected_state)
            report_restored = _restore(report_path, original_report, expected_report)
            manifest_restored = _restore(manifest_path, original_manifest, expected_manifest)
            if not state_restored or not report_restored or not manifest_restored:
                raise ValueError("finalization failed and concurrent edits were preserved")
            raise
    return state_path


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    try:
        path = finalize(Path(args.root), args.feature_id)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: finalization failed; safe rollback attempted: {exc}", file=sys.stderr)
        return 1
    print(f"DELIVERY COMPLETE: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
