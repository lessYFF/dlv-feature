#!/usr/bin/env python3
"""Quality-preserving frontend fast path for schema-v12 deliveries."""

from __future__ import annotations

import argparse
import json
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

from delivery_contracts import claim_errors, prototype_review_blockers
from delivery_graph import (
    SAFE_RUN_ID,
    OBSERVED_RISK_PATTERNS,
    confined_project_path,
    graph_digest,
    graph_risk_vector,
    load_graph,
    observed_code_risk_vector,
    prototype_errors,
    structural_errors,
)
from delivery_governance import RISK_AXES, load_ledger, load_source_revision, recover_review_transaction, union_risk_vectors
from delivery_proof import atomic_write_text, exclusive_file_lock, repository_fingerprint, value_digest
from graph_review import run_isolated_readiness_review
from graph_validation import validate as validate_delivery_state
from repository_adapter import execute_capability, load_adapter, repository_snapshot


ELEVATED_AXES = {
    "API_CONTRACT", "PERSISTENCE", "AUTHORIZATION", "TENANCY", "MONEY",
    "CONCURRENCY", "IRREVERSIBLE_SIDE_EFFECT", "CROSS_CLIENT",
}
REQUIRED_CAPABILITIES = ("changes", "lint", "targeted_tests", "typecheck", "build")
FAST_PATH_SURFACES = {"frontend", "frontend_test", "documentation"}
FRONTEND_SUFFIXES = {".css", ".html", ".js", ".jsx", ".less", ".md", ".mjs", ".scss", ".svelte", ".ts", ".tsx", ".vue"}
MAX_FAST_PATH_SOURCE_BYTES = 8 * 1024 * 1024
MAX_FAST_PATH_RESERVATION_BYTES = 64 * 1024
PATH_RISK_MARKERS = {
    "API_CONTRACT": {"api", "controller", "endpoint", "route", "server"},
    "PERSISTENCE": {"db", "database", "migration", "model", "repository", "schema", "sql"},
    "AUTHORIZATION": {"auth", "authorization", "permission", "role"},
    "TENANCY": {"org", "tenant"},
    "MONEY": {"billing", "money", "payment", "price", "settlement"},
    "IRREVERSIBLE_SIDE_EFFECT": {"delete", "email", "publish", "send", "webhook"},
    "CROSS_CLIENT": {"event", "push", "sync", "websocket"},
}
PATH_TOKEN = re.compile(r"[A-Z]+(?=[A-Z][a-z]|[^A-Za-z]|$)|[A-Z]?[a-z]+|[0-9]+")


def _eligibility_snapshot(root: Path, feature_id: str) -> tuple[list[str], dict[str, Any]]:
    graph = load_graph(root, feature_id)
    reasons = structural_errors(graph, feature_id) + claim_errors(graph)
    reasons += prototype_errors(root, feature_id, graph) + prototype_review_blockers(graph)
    reasons += [
        f"delivery state is not current: {error}"
        for error in validate_delivery_state(root, feature_id)
    ]
    source: dict[str, Any] = {}
    try:
        source = load_source_revision(root / "delivery" / feature_id, feature_id, graph["source_revision"])
    except (OSError, ValueError, KeyError) as exc:
        reasons.append(str(exc))
        source_risk = {}
    else:
        source_risk = source["risk_vector"]
    vector = union_risk_vectors(source_risk, graph_risk_vector(graph), observed_code_risk_vector(root, graph))
    elevated = sorted(axis for axis in ELEVATED_AXES if vector.get(axis) != "absent")
    if elevated:
        reasons.append("frontend fast path is ineligible for elevated risk axes: " + ", ".join(elevated))
    if graph.get("metadata", {}).get("delivery_mode") != "frontend_fast_path":
        reasons.append("Delivery Graph delivery_mode is not frontend_fast_path")
    ledger = load_ledger(root, feature_id)
    if ledger.get("campaigns"):
        reasons.append("frontend fast path permits only one initial composite review campaign")
    try:
        adapter, adapter_sha256 = load_adapter(root)
    except (OSError, ValueError) as exc:
        reasons.append(str(exc))
    else:
        missing = sorted(set(REQUIRED_CAPABILITIES) - set((adapter or {}).get("capabilities", {})))
        if missing:
            reasons.append("repository adapter lacks fast-path capabilities: " + ", ".join(missing))
        matches = [
            item for item in source.get("attachments", []) if isinstance(item, dict)
            and item.get("ref") == (adapter or {}).get("source_ref")
            and item.get("kind") == "repository_adapter"
            and item.get("sha256") == adapter_sha256
        ]
        if len(matches) != 1:
            reasons.append("repository adapter and frontend_roots lack confirmed Source Revision provenance")
    return reasons, {
        "graph": graph, "graph_sha256": graph_digest(graph),
        "source": source, "source_sha256": value_digest(source),
        "ledger_sha256": value_digest(ledger),
        "repository_fingerprint": repository_fingerprint(root, feature_id),
        "adapter": adapter if "adapter" in locals() else None,
        "adapter_sha256": adapter_sha256 if "adapter_sha256" in locals() else None,
    }


def eligibility(root: Path, feature_id: str) -> list[str]:
    reasons, _ = _eligibility_snapshot(root.expanduser().resolve(), feature_id)
    return reasons


def run(root: Path, feature_id: str, run_id: str) -> dict[str, Any]:
    root = root.expanduser().resolve()
    if not SAFE_RUN_ID.fullmatch(run_id):
        raise ValueError("run-id must use lowercase letters, digits, dots, underscores, or hyphens")
    lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    with exclusive_file_lock(lock):
        recover_review_transaction(root, feature_id)
        journal = _journal_path(root, feature_id, run_id)
        if journal.exists() or journal.is_symlink():
            raise ValueError(f"fast-path journal already exists: {journal}")
        reservation = _load_reservation(root, feature_id)
        if reservation is not None:
            output = {
                "status": "ROUTE_STANDARD",
                "reasons": [f"frontend fast path is already reserved by run {reservation['run_id']}"],
                "steps": [],
            }
            _write_journal_unlocked(root, feature_id, run_id, output)
            return output
        reasons, eligibility_state = _eligibility_snapshot(root, feature_id)
        if reasons:
            output = {"status": "ROUTE_STANDARD", "reasons": reasons, "steps": []}
            _write_journal_unlocked(root, feature_id, run_id, output)
            return output
        _write_reservation(root, feature_id, run_id, eligibility_state)
    try:
        with repository_snapshot(root) as snapshot_base:
            return _run_eligible(root, feature_id, run_id, eligibility_state, snapshot_base)
    except Exception as exc:
        output = {
            "status": "BLOCKED",
            "reasons": [f"frontend fast-path execution failed: {type(exc).__name__}"],
            "steps": [],
        }
        _write_journal(root, feature_id, run_id, output)
        return output


def _run_eligible(
    root: Path, feature_id: str, run_id: str, eligibility_state: dict[str, Any], snapshot_base: Path,
) -> dict[str, Any]:
    graph = eligibility_state["graph"]
    adapter = eligibility_state["adapter"]
    adapter_sha256 = eligibility_state["adapter_sha256"]
    if not isinstance(adapter, dict) or not isinstance(adapter_sha256, str):
        raise ValueError("repository adapter eligibility snapshot is incomplete")
    steps: list[dict[str, Any]] = [{"name": "provenance", "status": "passed"}]
    kernel_snapshot, kernel_error = kernel_git_snapshot(root)
    if kernel_error:
        output = {"status": "ROUTE_STANDARD", "adapter_sha256": adapter_sha256, "reasons": [kernel_error], "steps": steps}
        _write_journal(root, feature_id, run_id, output)
        return output
    code_snapshot = repository_fingerprint(root, feature_id)
    if code_snapshot != eligibility_state["repository_fingerprint"]:
        output = {
            "status": "ROUTE_STANDARD", "adapter_sha256": adapter_sha256,
            "reasons": ["Code changed after frontend fast-path eligibility was established"], "steps": steps,
        }
        _write_journal(root, feature_id, run_id, output)
        return output

    def integrity_error(*, check_ledger: bool = True) -> str | None:
        current, current_error = kernel_git_snapshot(root)
        if current_error:
            return current_error
        try:
            _, current_adapter_sha256 = load_adapter(root)
            current_graph = load_graph(root, feature_id)
            current_source = load_source_revision(
                root / "delivery" / feature_id, feature_id, current_graph["source_revision"],
            )
            current_ledger_sha256 = value_digest(load_ledger(root, feature_id))
        except (OSError, ValueError):
            current_adapter_sha256 = None
            current_graph = {}
            current_source = {}
            current_ledger_sha256 = None
        if (
            current != kernel_snapshot
            or repository_fingerprint(root, feature_id) != code_snapshot
            or current_adapter_sha256 != adapter_sha256
            or graph_digest(current_graph) != eligibility_state["graph_sha256"]
            or value_digest(current_source) != eligibility_state["source_sha256"]
            or (check_ledger and current_ledger_sha256 != eligibility_state["ledger_sha256"])
        ):
            return "repository adapter mutated the frozen Git baseline or Code during frontend fast path"
        return None

    changes = execute_capability(root, adapter or {}, "changes", snapshot_base)
    changes_passed = changes["result"]["exit_code"] == 0 and not changes["result"]["timed_out"]
    steps.append({"name": "changes", "status": "passed" if changes_passed else "failed", "evidence_sha256": value_digest(changes)})
    if not changes_passed:
        output = {"status": "BLOCKED", "adapter_sha256": adapter_sha256, "steps": steps}
        _write_journal(root, feature_id, run_id, output)
        return output
    mutation = integrity_error()
    if mutation:
        steps.append({"name": "repository_integrity", "status": "failed"})
        output = {"status": "BLOCKED", "adapter_sha256": adapter_sha256, "reasons": [mutation], "steps": steps}
        _write_journal(root, feature_id, run_id, output)
        return output
    kernel_paths = kernel_snapshot["paths"]
    change_reasons = _change_routing_reasons(
        root, changes["result"]["stdout"], kernel_paths, adapter.get("frontend_roots", []),
    )
    if change_reasons:
        output = {"status": "ROUTE_STANDARD", "adapter_sha256": adapter_sha256, "reasons": change_reasons, "steps": steps}
        _write_journal(root, feature_id, run_id, output)
        return output
    for capability in ("lint", "targeted_tests", "typecheck", "build"):
        result = execute_capability(root, adapter or {}, capability, snapshot_base)
        passed = result["result"]["exit_code"] == 0 and not result["result"]["timed_out"]
        steps.append({"name": capability, "status": "passed" if passed else "failed", "evidence_sha256": value_digest(result)})
        if not passed:
            output = {"status": "BLOCKED", "adapter_sha256": adapter_sha256, "steps": steps}
            _write_journal(root, feature_id, run_id, output)
            return output
        mutation = integrity_error()
        if mutation:
            steps.append({"name": "repository_integrity", "status": "failed"})
            output = {"status": "BLOCKED", "adapter_sha256": adapter_sha256, "reasons": [mutation], "steps": steps}
            _write_journal(root, feature_id, run_id, output)
            return output
    records = run_isolated_readiness_review(root, feature_id, run_id)
    steps.append({"name": "composite_review", "status": "recorded", "records": [path.relative_to(root).as_posix() for path in records]})
    mutation = integrity_error(check_ledger=False)
    if mutation:
        steps.append({"name": "repository_integrity", "status": "failed"})
        output = {"status": "BLOCKED", "adapter_sha256": adapter_sha256, "reasons": [mutation], "steps": steps}
        _write_journal(root, feature_id, run_id, output)
        return output
    output = {
        "status": "PROOF_REQUIRED",
        "adapter_sha256": adapter_sha256,
        "steps": steps,
        "reason": "fast scheduling never weakens fresh Proof or Ready semantics",
    }
    _write_journal(root, feature_id, run_id, output)
    return output


def _write_journal(root: Path, feature_id: str, run_id: str, value: dict[str, Any]) -> None:
    lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    with exclusive_file_lock(lock):
        reservation = _load_reservation(root, feature_id)
        if reservation is None or reservation["run_id"] != run_id:
            raise ValueError("frontend fast-path reservation is missing or belongs to another run")
        _write_journal_unlocked(root, feature_id, run_id, value)
        _reservation_path(root, feature_id).unlink()


def _write_journal_unlocked(root: Path, feature_id: str, run_id: str, value: dict[str, Any]) -> None:
    path = _journal_path(root, feature_id, run_id)
    if path.exists() or path.is_symlink():
        raise ValueError(f"fast-path journal already exists: {path}")
    atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _reservation_path(root: Path, feature_id: str) -> Path:
    return confined_project_path(
        root, Path(".dlv") / "fast-path" / feature_id / "active-reservation.json", "fast-path reservation",
    )


def _load_reservation(root: Path, feature_id: str) -> dict[str, Any] | None:
    path = _reservation_path(root, feature_id)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > MAX_FAST_PATH_RESERVATION_BYTES:
        raise ValueError("frontend fast-path reservation is not a bounded regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("frontend fast-path reservation is invalid") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "feature_id", "run_id", "eligibility_sha256"}
        or value.get("schema_version") != 12
        or value.get("feature_id") != feature_id
        or not isinstance(value.get("run_id"), str)
        or not SAFE_RUN_ID.fullmatch(value["run_id"])
        or not re.fullmatch(r"[0-9a-f]{64}", value.get("eligibility_sha256", ""))
    ):
        raise ValueError("frontend fast-path reservation is invalid")
    return value


def _write_reservation(
    root: Path, feature_id: str, run_id: str, eligibility_state: dict[str, Any],
) -> None:
    path = _reservation_path(root, feature_id)
    if path.exists() or path.is_symlink():
        raise ValueError("frontend fast path already has an active reservation")
    value = {
        "schema_version": 12,
        "feature_id": feature_id,
        "run_id": run_id,
        "eligibility_sha256": value_digest({
            key: eligibility_state[key]
            for key in (
                "graph_sha256", "source_sha256", "ledger_sha256",
                "repository_fingerprint", "adapter_sha256",
            )
        }),
    }
    atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _journal_path(root: Path, feature_id: str, run_id: str) -> Path:
    return confined_project_path(
        root, Path(".dlv") / "fast-path" / feature_id / f"{run_id}.json", "fast-path journal",
    )


def kernel_git_snapshot(root: Path) -> tuple[dict[str, Any], str | None]:
    def git(*argv: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(["git", *argv], cwd=root, capture_output=True, check=False)

    symbolic = git("symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD")
    try:
        symbolic_ref = symbolic.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        return {}, "kernel Git baseline contains invalid UTF-8"
    candidates = [symbolic_ref] if symbolic.returncode == 0 else []
    candidates.extend(["origin/main", "main", "master"])
    base = next((candidate for candidate in candidates if candidate and git("rev-parse", "--verify", "--quiet", candidate).returncode == 0), None)
    if base is None or git("rev-parse", "--verify", "--quiet", "HEAD").returncode != 0:
        return {}, "kernel cannot establish a trusted Git baseline for frontend fast path"
    base_oid_result = git("rev-parse", "--verify", base)
    merge_base = git("merge-base", "HEAD", base)
    if base_oid_result.returncode != 0 or merge_base.returncode != 0:
        return {}, "kernel cannot compute the Git baseline identities for frontend fast path"
    try:
        base_oid = base_oid_result.stdout.decode("ascii", errors="strict").strip()
        baseline = merge_base.stdout.decode("utf-8", errors="strict").strip()
    except (UnicodeDecodeError, UnicodeError):
        return {}, "kernel Git baseline identity contains invalid bytes"
    changed = git("diff", "--name-status", "-z", "--no-ext-diff", baseline)
    untracked = git("ls-files", "--others", "--exclude-standard", "-z")
    if changed.returncode != 0 or untracked.returncode != 0:
        return {}, "kernel cannot enumerate repository changes for frontend fast path"
    try:
        changed_fields = changed.stdout.split(b"\0")
        changed_paths: list[str] = []
        index = 0
        while index < len(changed_fields) and changed_fields[index]:
            status = changed_fields[index].decode("ascii", errors="strict")
            index += 1
            path_count = 2 if status[:1] in {"R", "C"} else 1
            if not status or index + path_count > len(changed_fields):
                return {}, "kernel Git diff has invalid name-status framing"
            changed_paths.extend(
                changed_fields[index + offset].decode("utf-8", errors="strict")
                for offset in range(path_count)
            )
            index += path_count
        untracked_paths = untracked.stdout.decode("utf-8", errors="strict").split("\0")
    except UnicodeDecodeError:
        return {}, "kernel Git diff contains invalid UTF-8 paths"
    paths = sorted({
        path for path in [*changed_paths, *untracked_paths]
        if path and not path.startswith(("delivery/", ".dlv/"))
    })
    if any(Path(path).is_absolute() or ".." in Path(path).parts for path in paths):
        return {}, "kernel Git diff contains an unsafe path"
    return {"base_ref": base, "base_oid": base_oid, "merge_base_oid": baseline, "paths": paths}, None


def kernel_changed_paths(root: Path) -> tuple[list[str], str | None]:
    snapshot, error = kernel_git_snapshot(root)
    return snapshot.get("paths", []), error


def _change_routing_reasons(
    root: Path, stdout: str, kernel_paths: list[str], frontend_roots: list[str],
) -> list[str]:
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        return ["changes capability must emit schema-v12 JSON"]
    required = {"schema_version", "paths", "surfaces", "risk_axes"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != 12:
        return ["changes capability output has an invalid shape/schema"]
    paths, surfaces, axes = value.get("paths"), value.get("surfaces"), value.get("risk_axes")
    if (
        not isinstance(paths, list) or paths != sorted(set(paths))
        or not all(isinstance(path, str) and path and not Path(path).is_absolute() and ".." not in Path(path).parts for path in paths)
        or not isinstance(surfaces, list) or surfaces != sorted(set(surfaces))
        or not all(isinstance(surface, str) and surface for surface in surfaces)
        or not isinstance(axes, list) or axes != sorted(set(axes))
        or not all(axis in RISK_AXES for axis in axes)
    ):
        return ["changes capability output contains invalid paths/surfaces/risk axes"]
    reasons: list[str] = []
    elevated = sorted(axis for axis in ELEVATED_AXES if axis in axes)
    disallowed = sorted(set(surfaces) - FAST_PATH_SURFACES)
    if elevated:
        reasons.append("changes capability detected elevated risk axes: " + ", ".join(elevated))
    if disallowed:
        reasons.append("changes capability detected non-frontend surfaces: " + ", ".join(disallowed))
    if not paths:
        reasons.append("changes capability reported no concrete changed paths")
    if paths != kernel_paths:
        reasons.append("changes capability paths disagree with the kernel-owned Git diff")
    root_parts = [Path(item).parts for item in frontend_roots]
    outside_roots = [
        relative for relative in kernel_paths
        if not any(Path(relative).parts[:len(parts)] == parts for parts in root_parts)
    ]
    if outside_roots:
        reasons.append("kernel diff escapes declared frontend_roots: " + ", ".join(outside_roots))
    kernel_axes: set[str] = set()
    unsafe_paths: list[str] = []
    for relative in kernel_paths:
        path = Path(relative)
        lowered = {
            token.lower()
            for part in path.parts
            for token in PATH_TOKEN.findall(part)
        }
        if path.suffix.lower() not in FRONTEND_SUFFIXES:
            unsafe_paths.append(relative)
        for axis, markers in PATH_RISK_MARKERS.items():
            if lowered & markers:
                kernel_axes.add(axis)
        target = root / path
        try:
            metadata = target.lstat()
            target.resolve(strict=True).relative_to(root.resolve())
        except (OSError, ValueError):
            unsafe_paths.append(relative)
            continue
        if target.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FAST_PATH_SOURCE_BYTES:
            unsafe_paths.append(relative)
            continue
        try:
            content = target.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError):
            unsafe_paths.append(relative)
        else:
            kernel_axes.update(axis for axis, pattern in OBSERVED_RISK_PATTERNS.items() if pattern.search(content))
    elevated_kernel = sorted(kernel_axes & ELEVATED_AXES)
    if elevated_kernel:
        reasons.append("kernel diff scan detected elevated risk axes: " + ", ".join(elevated_kernel))
    if unsafe_paths:
        reasons.append("kernel diff contains non-frontend/unreadable paths: " + ", ".join(sorted(set(unsafe_paths))))
    return reasons


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    try:
        result = run(Path(args.root), args.feature_id, args.run_id)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result["status"] == "PROOF_REQUIRED" else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
