#!/usr/bin/env python3
"""Read bounded before/after implementation bytes for domain Review."""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any

from delivery_governance import read_bounded_regular
from delivery_proof import value_digest
from high_risk_contracts import evidence_symbol_ids

MAX_FILE_BYTES = 128 * 1024
MAX_TOTAL_BYTES = 512 * 1024


def implementation_evidence(root: Path, graph: dict[str, Any], selected: set[str], baseline: str | None) -> list[dict[str, Any]]:
    root = root.resolve()
    nodes = {node["id"]: node for node in graph.get("nodes", [])}
    result: list[dict[str, Any]] = []
    total = 0
    for symbol_id in sorted(evidence_symbol_ids(graph, selected)):
        node = nodes.get(symbol_id, {})
        path = node.get("attributes", {}).get("path")
        if not isinstance(path, str) or not Path(path).parts or Path(path).is_absolute() or ".." in Path(path).parts or Path(path).parts[0] in {".git", ".dlv", "delivery"} or any(part.startswith(".env") for part in Path(path).parts):
            raise ValueError(f"implementation evidence requires a scoped source file: {symbol_id}")
        target = root / path
        if target.resolve() != target or not target.is_relative_to(root):
            raise ValueError(f"implementation evidence refuses symlinked source: {path}")
        after = read_bounded_regular(target, MAX_FILE_BYTES, "implementation evidence", missing_ok=True)
        before = None
        if baseline and baseline != "UNBORN":
            if not re.fullmatch(r"[0-9a-f]{40,64}", baseline):
                raise ValueError("implementation evidence baseline must be a frozen commit OID")
            commit = subprocess.run(["git", "cat-file", "-t", baseline], cwd=root, capture_output=True, check=False, timeout=15)
            if commit.returncode or commit.stdout.strip() != b"commit":
                raise ValueError("implementation evidence baseline is unavailable")
            tree = subprocess.run(["git", "ls-tree", "-z", baseline, "--", path], cwd=root, capture_output=True, check=True, timeout=15)
            entries = [entry for entry in tree.stdout.split(b"\0") if entry]
            if entries:
                if len(entries) != 1:
                    raise ValueError("implementation evidence requires one exact baseline file")
                header, stored_path = entries[0].split(b"\t", 1)
                mode, kind, oid = header.split()
                if stored_path.decode("utf-8") != path or mode not in {b"100644", b"100755"} or kind != b"blob":
                    raise ValueError("implementation evidence baseline is not a regular source file")
                size = subprocess.run(["git", "cat-file", "-s", oid.decode()], cwd=root, capture_output=True, check=True, timeout=15)
                if int(size.stdout) > MAX_FILE_BYTES:
                    raise ValueError("implementation evidence baseline exceeds byte limit")
                before = subprocess.run(["git", "cat-file", "blob", oid.decode()], cwd=root, capture_output=True, check=True, timeout=15).stdout
        if before is None and after is None:
            raise ValueError(f"implementation evidence is missing: {path}; implement before high-risk Review")
        total += len(before or b"") + len(after or b"")
        if total > MAX_TOTAL_BYTES:
            raise ValueError("implementation evidence exceeds total byte limit; split independent failure boundaries")
        result.append({
            "symbol_id": symbol_id, "path": path, "baseline_oid": baseline,
            "before_sha256": hashlib.sha256(before).hexdigest() if before is not None else None,
            "after_sha256": hashlib.sha256(after).hexdigest() if after is not None else None,
            "before": before.decode("utf-8") if before is not None else None,
            "after": after.decode("utf-8") if after is not None else None,
        })
    for risk in graph.get("nodes", []):
        if risk.get("type") != "Risk" or risk.get("id") not in selected:
            continue
        verification = risk.get("attributes", {}).get("verification", {})
        database = verification.get("domains", {}).get("database")
        if not isinstance(database, dict):
            continue
        text = "\n".join(item["after"] or "" for item in result if item["symbol_id"] in verification.get("symbols", []))
        kind = database.get("context", {}).get("change_kind")
        destructive = re.search(r"\b(?:(?:drop|truncate)\s+table|alter\s+table\b[^;]*?\b(?:drop|alter|modify|change|rename)\b)", text, re.I)
        schema = re.search(r"\b(?:create|alter|drop|truncate)\s+table\b", text, re.I)
        if (destructive and kind != "destructive_schema") or (schema and kind == "data"):
            raise ValueError("database verification change_kind understates observed table DDL")
    # Old-client sequences and historical data often are unchanged fixtures,
    # not changed Symbols. Include the existing sealed Environment fixture so
    # the Reviewer can inspect it without inventing a changed implementation.
    risk_ids = {node["id"] for node in graph.get("nodes", []) if node.get("type") == "Risk" and node["id"] in selected and node.get("attributes", {}).get("verification")}
    proof_ids = {pid for claim in graph.get("claims", []) if risk_ids & set(claim.get("subjects", [])) for pid in claim.get("proof_ids", [])}
    runner_paths: set[str] = set()
    for proof_id in sorted(proof_ids):
        attrs = nodes.get(proof_id, {}).get("attributes", {})
        runner = attrs.get("runner", {})
        cwd = root / runner.get("cwd", ".")
        if cwd.resolve() != cwd or not cwd.is_relative_to(root):
            raise ValueError("implementation Review runner cwd must stay inside the project")
        for argument in runner.get("argv", []):
            if not isinstance(argument, str) or not argument or argument.startswith("-") or "\x00" in argument:
                continue
            candidate = cwd / argument
            try:
                if candidate.is_relative_to(root) and candidate.is_file():
                    runner_paths.add(candidate.relative_to(root).as_posix())
            except OSError:
                # Inline -c programs are not paths; the Graph already embeds
                # their exact bytes. Explicit review_paths never use this path.
                continue
        extra = attrs.get("review_paths", [])
        if not isinstance(extra, list) or any(not isinstance(path, str) or not path for path in extra):
            raise ValueError("Proof.review_paths must be an array of repository source paths")
        runner_paths.update(extra)
    for path in sorted(runner_paths):
        relative = Path(path)
        if not relative.parts or relative.is_absolute() or ".." in relative.parts or relative.parts[0] == ".git" or any(part.startswith(".env") for part in relative.parts):
            raise ValueError("implementation Review runner dependency must be a scoped source path")
        target = root / relative
        if target.resolve() != target:
            raise ValueError("implementation Review runner dependency must not be symlinked")
        content = read_bounded_regular(target, MAX_FILE_BYTES, "Review runner dependency")
        assert content is not None
        total += len(content)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("implementation evidence exceeds total byte limit")
        result.append({"runner_path": path, "sha256": hashlib.sha256(content).hexdigest(), "content": content.decode("utf-8")})
    environment_ids = {edge["target"] for edge in graph.get("edges", []) if edge.get("type") == "runs_in" and edge.get("source") in proof_ids}
    for environment_id in sorted(environment_ids):
        fixture = nodes.get(environment_id, {}).get("attributes", {}).get("spec", {}).get("fixture", {})
        path = fixture.get("path")
        if not isinstance(path, str) or not Path(path).parts or Path(path).is_absolute() or ".." in Path(path).parts or Path(path).parts[0] == ".git":
            raise ValueError("implementation Review requires a scoped Environment fixture")
        target = root / path
        if target.resolve() != target or not target.is_relative_to(root):
            raise ValueError("implementation Review fixture must not be symlinked")
        content = read_bounded_regular(target, MAX_FILE_BYTES, "Review fixture")
        assert content is not None
        digest = hashlib.sha256(content).hexdigest()
        if digest != fixture.get("sha256"):
            raise ValueError("implementation Review fixture digest is stale")
        total += len(content)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("implementation evidence exceeds total byte limit")
        result.append({"environment_id": environment_id, "path": path, "sha256": digest, "content": content.decode("utf-8")})
    return result


def evidence_digest(root: Path, graph: dict[str, Any], unit: dict[str, Any]) -> str | None:
    # Read state only for the existing frozen implementation baseline, never
    # accept an author-supplied digest as proof of the live bytes.
    import json
    path = root / "delivery" / graph["feature_id"] / "state.json"
    state = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    evidence = implementation_evidence(root, graph, set(unit["node_ids"]), state.get("subject_reconciliation", {}).get("baseline_oid"))
    return value_digest(evidence) if evidence else None


def evidence_execution_errors(root: Path, graph: dict[str, Any], unit: dict[str, Any], execution: dict[str, Any]) -> list[str]:
    if execution.get("mode") == "isolated_deterministic_lens":
        # Diagnostic graph-only records cannot seal a Proof Contract; preserve
        # that existing mode without misrepresenting it as implementation Review.
        return []
    try:
        expected = evidence_digest(root, graph, unit)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as exc:
        return [f"implementation evidence unavailable: {exc}"]
    if execution.get("implementation_sha256") != expected:
        return ["implementation evidence is missing or stale; rerun affected Review units"]
    return []
