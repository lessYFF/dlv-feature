#!/usr/bin/env python3
"""Deterministic first-pass quality contracts for DLV Feature.

The helpers in this module derive views from immutable Source, the Delivery
Graph, and Git.  They never create a second editable truth.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

from delivery_proof import file_digest, repository_fingerprint, value_digest


MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024
NON_MATERIALIZED_KINDS = {
    "convergence_authority", "target_attestation_jwk", "repository_adapter",
}
CRITICAL_ANCHOR_KINDS = {
    "requirement", "decision", "prohibition", "state", "error", "artifact_structure",
}
_CLASSIFIERS = (
    ("prohibition", re.compile(r"(?:\b(?:must not|shall not|never|forbid|prohibit)\b|禁止|不得|不能)", re.I)),
    ("state", re.compile(r"(?:\b(?:state|status|transition|pending|complete|ready|blocked)\b|状态|流转|待处理|完成|阻塞)", re.I)),
    ("error", re.compile(r"(?:\b(?:error|failure|failed|invalid|reject|exception|fallback)\b|错误|失败|异常|拒绝|兜底)", re.I)),
    ("artifact_structure", re.compile(r"(?:\b(?:artifact|schema|field|format|file|directory|section|structure)\b|产物|结构|字段|格式|文件|目录|章节)", re.I)),
    ("requirement", re.compile(r"(?:\b(?:must|shall|required?|need(?:s|ed)? to|should)\b|必须|需要|应当|应该|要求|验收)", re.I)),
)


def _attachment_bytes(attachment: dict[str, Any]) -> bytes | None:
    encoding = attachment.get("content_encoding")
    content = attachment.get("content")
    if encoding == "utf-8" and isinstance(content, str):
        return content.encode("utf-8")
    if encoding == "base64" and isinstance(content, str):
        try:
            return base64.b64decode(content, validate=True)
        except ValueError:
            return None
    return None


def materialize_attachments(feature_directory: Path, attachments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Copy caller-provided attachment bytes into the immutable Source record."""
    root = feature_directory.parents[1].resolve()
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(attachments):
        item = dict(raw)
        if item.get("kind") in NON_MATERIALIZED_KINDS:
            result.append(item)
            continue
        existing = _attachment_bytes(item)
        if existing is not None:
            if len(existing) > MAX_ATTACHMENT_BYTES:
                raise ValueError(f"source input attachments[{index}] exceeds {MAX_ATTACHMENT_BYTES} bytes")
            if (
                len(existing) != item.get("size_bytes")
                or hashlib.sha256(existing).hexdigest() != item.get("sha256")
            ):
                raise ValueError(f"source input attachments[{index}] materialized content is stale")
            result.append(item)
            continue
        inline = item.pop("inline_content", None)
        if inline is not None:
            if isinstance(inline, str):
                content = inline.encode("utf-8")
            else:
                content = json.dumps(inline, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        else:
            locator = item.get("locator")
            if not isinstance(locator, str) or not locator.strip():
                raise ValueError(f"source input attachments[{index}] requires inline_content or a local locator")
            candidate = Path(locator).expanduser()
            path = candidate if candidate.is_absolute() else root / candidate
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(root)
            except (OSError, ValueError) as exc:
                raise ValueError(
                    f"source input attachments[{index}] locator must stay inside the project root"
                ) from exc
            if not resolved.is_file() or resolved != path.absolute():
                raise ValueError(f"source input attachments[{index}] locator must be a regular non-symlink file")
            descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_ATTACHMENT_BYTES:
                    raise ValueError(f"source input attachments[{index}] is not regular or exceeds {MAX_ATTACHMENT_BYTES} bytes")
                chunks: list[bytes] = []
                size = 0
                while chunk := os.read(descriptor, min(1024 * 1024, MAX_ATTACHMENT_BYTES + 1 - size)):
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > MAX_ATTACHMENT_BYTES:
                        raise ValueError(f"source input attachments[{index}] exceeds {MAX_ATTACHMENT_BYTES} bytes")
                content = b"".join(chunks)
                after = os.fstat(descriptor)
                identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
                if identity(metadata) != identity(after):
                    raise ValueError(f"source input attachments[{index}] changed while being captured")
            finally:
                os.close(descriptor)
        if len(content) > MAX_ATTACHMENT_BYTES:
            raise ValueError(f"source input attachments[{index}] exceeds {MAX_ATTACHMENT_BYTES} bytes")
        digest = hashlib.sha256(content).hexdigest()
        if item.get("sha256") not in {None, digest}:
            raise ValueError(f"source input attachments[{index}] sha256 disagrees with materialized content")
        try:
            encoded = content.decode("utf-8")
            content_encoding = "utf-8"
        except UnicodeDecodeError:
            encoded = base64.b64encode(content).decode("ascii")
            content_encoding = "base64"
        item.update({
            "sha256": digest,
            "content_encoding": content_encoding,
            "content": encoded,
            "size_bytes": len(content),
        })
        result.append(item)
    return result


def attachment_materialization_errors(source: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for index, attachment in enumerate(source.get("attachments", [])):
        if not isinstance(attachment, dict) or attachment.get("kind") in NON_MATERIALIZED_KINDS:
            continue
        content = _attachment_bytes(attachment)
        if content is None:
            errors.append(f"attachments[{index}] is locator-only; recapture Source with materialized content")
            continue
        if len(content) != attachment.get("size_bytes") or hashlib.sha256(content).hexdigest() != attachment.get("sha256"):
            errors.append(f"attachments[{index}] materialized content digest/size is stale")
    return errors


def attachment_interpretation_errors(source: dict[str, Any]) -> list[str]:
    """Report binary Sources that lack an explicit format-aware extraction."""
    errors: list[str] = []
    for index, attachment in enumerate(source.get("attachments", [])):
        if not isinstance(attachment, dict) or attachment.get("kind") in NON_MATERIALIZED_KINDS:
            continue
        if attachment.get("content_encoding") != "base64":
            continue
        extracted = attachment.get("extracted_text")
        adapter = attachment.get("extraction_adapter")
        if not isinstance(extracted, str) or not extracted.strip() or not isinstance(adapter, str) or not adapter.strip():
            errors.append(
                f"attachments[{index}] binary content requires extracted_text and extraction_adapter"
            )
    return errors


def _segments(text: str) -> list[str]:
    values = re.split(r"(?:\r?\n\s*(?:[-*+]\s+|\d+[.)]\s+)?|(?<=[。！？.!?;；])\s*)", text)
    return [re.sub(r"\s+", " ", value).strip() for value in values if value.strip()]


def _kind(text: str, *, decision: bool = False) -> str:
    if decision:
        return "decision"
    for kind, pattern in _CLASSIFIERS:
        if pattern.search(text):
            return kind
    return "context"


def source_anchors(source: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive stable clause-level Source anchors without manual annotation."""
    raw: list[tuple[str, str, bool]] = []
    revision = source["revision_id"]
    raw.extend((f"{revision}:title", value, False) for value in _segments(source.get("title", "")))
    raw.extend((f"{revision}:description", value, False) for value in _segments(source.get("description", "")))
    for index, comment in enumerate(source.get("comments", []), 1):
        raw.extend((f"{revision}:comment:{index:03d}", value, False) for value in _segments(comment))
    for attachment in source.get("attachments", []):
        if not isinstance(attachment, dict) or attachment.get("kind") in NON_MATERIALIZED_KINDS:
            continue
        content = _attachment_bytes(attachment)
        if content is not None and attachment.get("content_encoding") == "utf-8":
            raw.extend((str(attachment["ref"]), value, False) for value in _segments(content.decode("utf-8")))
        elif content is not None:
            raw.append((
                str(attachment["ref"]),
                "Binary attachment " + json.dumps({
                    "ref": attachment.get("ref"), "kind": attachment.get("kind"),
                    "sha256": attachment.get("sha256"), "size_bytes": attachment.get("size_bytes"),
                }, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                False,
            ))
            extracted = attachment.get("extracted_text")
            if isinstance(extracted, str) and extracted.strip():
                raw.extend((str(attachment["ref"]), value, False) for value in _segments(extracted))
    for decision in source.get("decisions", []):
        if isinstance(decision, dict):
            raw.append((str(decision["id"]), f"{decision['question']} {decision['answer']}", True))
    anchors: list[dict[str, Any]] = []
    seen: set[str] = set()
    per_ref: dict[str, int] = {}
    for source_ref, text, decision in raw:
        per_ref[source_ref] = per_ref.get(source_ref, 0) + 1
        kind = "artifact_structure" if text.startswith("Binary attachment {") else _kind(text, decision=decision)
        anchor_id = source_ref if decision else "ANC-" + value_digest({
            "source_ref": source_ref, "ordinal": per_ref[source_ref], "text": text, "kind": kind,
        })[:16]
        if anchor_id in seen:
            continue
        seen.add(anchor_id)
        anchors.append({
            "id": anchor_id, "source_ref": source_ref, "kind": kind,
            "critical": kind in CRITICAL_ANCHOR_KINDS, "text": text,
        })
    return sorted(anchors, key=lambda item: item["id"])


def critical_anchor_coverage(graph: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    product_nodes = [
        node for node in graph.get("nodes", [])
        if isinstance(node, dict) and node.get("type") in {"Requirement", "Behavior", "Acceptance", "Exception"}
    ]
    anchors = [item for item in source_anchors(source) if item["critical"]]
    covered: list[str] = []
    for anchor in anchors:
        origin_kind = "derived" if anchor["kind"] == "decision" else "direct"
        origin_key = "constraint_ref" if anchor["kind"] == "decision" else "source_ref"
        if any(
            any(
                isinstance(origin, dict) and origin.get("kind") == origin_kind
                and origin.get(origin_key) == anchor["id"]
                for origin in node.get("origins", [])
            )
            for node in product_nodes
        ):
            covered.append(anchor["id"])
    missing = sorted(set(item["id"] for item in anchors) - set(covered))
    return {
        "total": len(anchors), "covered": len(covered), "missing": missing,
        "coverage_pct": 100 if not anchors else int(100 * len(covered) / len(anchors)),
    }


def planned_subjects(graph: dict[str, Any]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for node in graph.get("nodes", []):
        if not isinstance(node, dict) or node.get("type") != "Symbol":
            continue
        path = node.get("attributes", {}).get("path")
        if isinstance(path, str) and path.strip():
            normalized = Path(path).as_posix()
            if normalized.startswith("./"):
                normalized = normalized[2:]
            result.append({"subject_id": node["id"], "path": normalized})
    return sorted(result, key=lambda item: (item["path"], item["subject_id"]))


def _git_oid(root: Path, revision: str = "HEAD") -> str | None:
    completed = subprocess.run(
        ["git", "rev-parse", "--verify", revision], cwd=root,
        capture_output=True, text=True, check=False,
    )
    value = completed.stdout.strip()
    return value if completed.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", value) else None


def _git_paths(root: Path, feature_id: str, baseline_oid: str | None) -> tuple[str | None, str | None, list[str]]:
    head_oid = _git_oid(root)
    baseline = baseline_oid or head_oid or "UNBORN"
    if baseline != "UNBORN" and _git_oid(root, baseline) != baseline:
        raise ValueError("Subject reconciliation implementation baseline is missing from Git")
    paths: set[str] = set()
    if head_oid is not None:
        committed_argv = (
            ["git", "ls-tree", "-r", "--name-only", head_oid]
            if baseline == "UNBORN"
            else ["git", "diff", "--name-only", "--diff-filter=ACMRD", f"{baseline}..{head_oid}", "--"]
        )
        committed = subprocess.run(
            committed_argv,
            cwd=root, capture_output=True, text=True, check=False,
        )
        if committed.returncode != 0:
            raise ValueError("Subject reconciliation cannot compare the implementation baseline")
        paths.update(committed.stdout.splitlines())
        dirty = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMRD", "HEAD", "--"],
            cwd=root, capture_output=True, text=True, check=False,
        )
        if dirty.returncode != 0:
            raise ValueError("Subject reconciliation cannot inspect tracked worktree changes")
        paths.update(dirty.stdout.splitlines())
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"], cwd=root,
        capture_output=True, text=True, check=False,
    )
    if untracked.returncode != 0:
        raise ValueError("Subject reconciliation cannot inspect untracked worktree changes")
    paths.update(untracked.stdout.splitlines())
    excluded = (f"delivery/{feature_id}/", ".dlv/")
    return baseline, head_oid, sorted(path for path in paths if path and not path.startswith(excluded))


def reconcile_subjects(
    root: Path, feature_id: str, graph: dict[str, Any], baseline_oid: str | None = None,
) -> dict[str, Any]:
    root = root.expanduser().resolve()
    planned = planned_subjects(graph)
    baseline, head, observed = _git_paths(root, feature_id, baseline_oid)
    mappings: list[dict[str, str]] = []
    unmapped: list[str] = []
    for path in observed:
        matches = [item for item in planned if path == item["path"] or path.startswith(item["path"].rstrip("/") + "/")]
        if matches:
            mappings.extend({"path": path, "subject_id": item["subject_id"]} for item in matches)
        else:
            unmapped.append(path)
    bound_subjects = {item["subject_id"] for item in mappings}
    unobserved_subject_ids = sorted(
        item["subject_id"] for item in planned if item["subject_id"] not in bound_subjects
    )
    return {
        "baseline_oid": baseline,
        "repository_fingerprint": repository_fingerprint(root, feature_id),
        "planned": planned, "observed_paths": observed,
        "bindings": sorted(mappings, key=lambda item: (item["path"], item["subject_id"])),
        "unmapped_paths": unmapped, "unobserved_subject_ids": unobserved_subject_ids,
        "status": "blocked" if (unmapped or (observed and unobserved_subject_ids)) else ("reconciled" if observed else "pending_observation"),
    }


def derive_risk_frontier(graph: dict[str, Any], effective_risk: dict[str, str]) -> list[dict[str, Any]]:
    """Group independent Claim failure boundaries into the smallest review frontier."""
    groups: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}
    lens_axes = {
        "PROVENANCE_INTEGRITY": ("API_CONTRACT", "CROSS_CLIENT", "VISUAL_CONTRACT"),
        "STATE_AND_ATOMICITY": ("PERSISTENCE", "MONEY", "IRREVERSIBLE_SIDE_EFFECT"),
        "BOUNDARY_AND_CONCURRENCY": ("AUTHORIZATION", "TENANCY", "CONCURRENCY"),
        "RUNTIME_AUTHENTICITY": tuple(effective_risk),
    }
    for claim in graph.get("claims", []):
        if not isinstance(claim, dict) or claim.get("critical") is not True:
            continue
        axes = tuple(sorted(axis for axis in lens_axes.get(claim.get("lens"), ()) if effective_risk.get(axis) != "absent"))
        key = (str(claim.get("failure_boundary")), axes)
        item = groups.setdefault(key, {
            "failure_boundary": key[0], "risk_axes": list(axes), "claim_ids": [],
            "subject_ids": [], "proof_ids": [],
        })
        item["claim_ids"].append(claim["id"])
        item["subject_ids"].extend(claim.get("subjects", []))
        item["proof_ids"].extend(claim.get("proof_ids", []))
    result: list[dict[str, Any]] = []
    for item in groups.values():
        for key in ("claim_ids", "subject_ids", "proof_ids"):
            item[key] = sorted(set(item[key]))
        item["id"] = "RFR-" + value_digest(item)[:16]
        item["requires_early_evidence"] = any(effective_risk.get(axis) == "critical" for axis in item["risk_axes"])
        result.append(item)
    return sorted(result, key=lambda item: item["id"])


def experiment_binding(graph: dict[str, Any], frontier: dict[str, Any]) -> dict[str, Any]:
    nodes = {item.get("id"): item for item in graph.get("nodes", []) if isinstance(item, dict)}
    edges = [item for item in graph.get("edges", []) if isinstance(item, dict)]
    proofs: list[dict[str, Any]] = []
    for proof_id in frontier.get("proof_ids", []):
        proof = nodes.get(proof_id)
        if not isinstance(proof, dict) or proof.get("type") != "Proof":
            continue
        assertions = sorted(
            (
                nodes[edge["source"]] for edge in edges
                if edge.get("target") == proof_id and edge.get("type") == "proves"
                and nodes.get(edge.get("source"), {}).get("type") == "Assertion"
            ), key=lambda item: item["id"],
        )
        environment_ids = sorted(
            edge["target"] for edge in edges
            if edge.get("source") == proof_id and edge.get("type") == "runs_in"
            and nodes.get(edge.get("target"), {}).get("type") == "Environment"
        )
        proofs.append({
            "id": proof_id,
            "proof_type": proof.get("attributes", {}).get("proof_type"),
            "runner": proof.get("attributes", {}).get("runner"),
            "assertions": [{
                "id": item["id"], "oracle": item.get("attributes", {}).get("oracle"),
                "subject_ids": item.get("attributes", {}).get("subject_ids", []),
            } for item in assertions],
            "environment": nodes.get(environment_ids[0]) if len(environment_ids) == 1 else None,
        })
    return {
        "feature_id": graph.get("feature_id"),
        "frontier": frontier,
        "claims": sorted(
            (item for item in graph.get("claims", []) if item.get("id") in frontier.get("claim_ids", [])),
            key=lambda item: item["id"],
        ),
        "subjects": sorted(
            (nodes[item] for item in frontier.get("subject_ids", []) if item in nodes),
            key=lambda item: item["id"],
        ),
        "proofs": proofs,
    }


def experiment_plan(
    root: Path, feature_id: str, frontier: list[dict[str, Any]], graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = root.expanduser().resolve()
    directory = root / ".dlv" / "experiments" / feature_id
    source_revision = None
    if graph is not None:
        try:
            from delivery_governance import load_source_revision
            source_revision = load_source_revision(
                root / "delivery" / feature_id, feature_id, str(graph.get("source_revision")),
            )
        except (OSError, ValueError):
            source_revision = None
    experiments: list[dict[str, Any]] = []
    for item in frontier:
        binding = experiment_binding(graph or {"feature_id": feature_id}, item)
        binding_sha256 = value_digest(binding)
        experiment_id = "EXP-" + value_digest({
            "feature_id": feature_id, "frontier_id": item["id"], "binding_sha256": binding_sha256,
        })[:16]
        evidence = []
        if directory.is_dir():
            for path in sorted(directory.glob(f"{experiment_id}-*.json")):
                if path.is_file() and path.resolve() == path.absolute():
                    try:
                        record = json.loads(path.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        continue
                    expected_keys = {
                        "schema_version", "feature_id", "experiment_id", "frontier_id",
                        "frontier_sha256", "graph_sha256", "binding_sha256", "recorded_at",
                        "verdict", "proof_results", "kernel_receipt", "record_sha256",
                    }
                    signed_payload = {
                        key: value for key, value in record.items()
                        if key not in {"kernel_receipt", "record_sha256"}
                    }
                    receipt_valid = False
                    if source_revision is not None:
                        try:
                            from delivery_governance import verify_kernel_receipt
                            verify_kernel_receipt(
                                signed_payload, record.get("kernel_receipt"), source_revision,
                                label="critical experiment",
                            )
                            receipt_valid = True
                        except ValueError:
                            pass
                    if (
                        isinstance(record, dict) and set(record) == expected_keys
                        and record.get("schema_version") == 13
                        and record.get("feature_id") == feature_id
                        and record.get("experiment_id") == experiment_id
                        and record.get("frontier_id") == item["id"]
                        and record.get("frontier_sha256") == value_digest(item)
                        and record.get("binding_sha256") == binding_sha256
                        and (graph is None or record.get("graph_sha256") == value_digest(graph))
                        and record.get("verdict") == "PASS"
                        and isinstance(record.get("proof_results"), list) and record["proof_results"]
                        and receipt_valid
                        and record.get("record_sha256") == value_digest({
                            key: value for key, value in record.items() if key != "record_sha256"
                        })
                        and path.name == f"{experiment_id}-{record.get('record_sha256', '')[:12]}.json"
                    ):
                        evidence.append({"path": path.relative_to(root).as_posix(), "sha256": file_digest(path)})
        experiments.append({
            "id": experiment_id, "frontier_id": item["id"], "claim_ids": item["claim_ids"],
            "proof_ids": item["proof_ids"], "required": item["requires_early_evidence"],
            "binding_sha256": binding_sha256,
            "evidence": evidence,
        })
    missing = [item["id"] for item in experiments if item["required"] and not item["evidence"]]
    return {"experiments": experiments, "missing_required": missing, "status": "blocked" if missing else "ready"}


def derive_delivery_status(state: dict[str, Any]) -> str:
    verification = state.get("verification", {})
    finalization = verification.get("finalization")
    finalization_shape_valid = (
        isinstance(finalization, dict)
        and set(finalization) == {"tool", "finalized_at", "token"}
        and finalization.get("tool") == "finalize_delivery.py"
        and isinstance(finalization.get("finalized_at"), str) and bool(finalization["finalized_at"].strip())
        and isinstance(finalization.get("token"), str) and bool(re.fullmatch(r"[0-9a-f]{64}", finalization["token"]))
    )
    if (
        state.get("readiness", {}).get("status") == "ready"
        and state.get("subject_reconciliation", {}).get("status") in {"pending_observation", "reconciled"}
        and state.get("critical_experiments", {}).get("status") == "ready"
    ):
        if (
            state.get("subject_reconciliation", {}).get("status") == "reconciled"
            and state.get("code", {}).get("status") == "completed"
            and state.get("proof_contract", {}).get("status") == "sealed"
            and verification.get("status") == "completed"
            and verification.get("verdict") == "PASS"
            and finalization_shape_valid
        ):
            return "DELIVERY_READY"
        return "REVIEWABLE"
    return "AUTHORING"
