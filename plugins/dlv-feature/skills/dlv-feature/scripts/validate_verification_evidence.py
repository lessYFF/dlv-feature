#!/usr/bin/env python3
"""Validate exact verification evidence, including executable boundary proofs."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


EVIDENCE_ID = re.compile(r"^EVID-[0-9]+$")
TRACE_ID = re.compile(
    r"\b(?:AC|EX)-[0-9]+\b|\bR-D[0-9]{2,}-[0-9]+\b|\bT-B[0-9]{2,}-[0-9]+\b|"
    r"\bB[0-9]{2,}\b|\b(?:CONTRACT|SHAPE)-[A-Za-z0-9][A-Za-z0-9-]*\b|\bBP-[0-9]+\b"
)
RANGE_ID = re.compile(
    r"\b(?:AC|EX|FR|BR|R-D[0-9]{2,}|T-B[0-9]{2,}|B|BP)-[0-9]+\s*"
    r"(?:~|～|—|–|\.\.|至|-(?![A-Za-z]))\s*(?:(?:AC|EX|FR|BR|BP)-)?[0-9]+\b"
)
STATUSES = {"passed", "failed", "blocked", "skipped", "manual"}
REQUIRED_HEADERS = {"证据", "覆盖", "环境", "命令或步骤", "状态", "退出码", "观察结果", "锚点"}
DIRECT_PROBE = re.compile(r"(?:\bdirect\b|直接|curl|http|postman|api\s*(?:call|请求)|playwright)", re.I)
OBSERVED_BOUNDARY = re.compile(
    r"(?:\b(?:200|201|400|401|403|404|409|500)\b|status|状态|payload|响应|body|"
    r"零写入|zero\s+(?:write|side effect)|service\s+not\s+invoked|未调用|"
    r"敏感字段|absent|不包含|快照|source|来源变更|扰动)",
    re.I,
)


def _read_state(feature_dir: Path) -> dict[str, Any]:
    content = (feature_dir / "state.md").read_text(encoding="utf-8")
    match = re.search(r"<!-- DLV_STATE_START -->\s*```json\s*\n([\s\S]*?)\n```\s*<!-- DLV_STATE_END -->", content)
    if not match:
        raise ValueError("state.md has no valid DLV JSON block")
    return json.loads(match.group(1))


def _sections(text: str) -> dict[str, str]:
    matches = list(re.finditer(r"(?m)^##\s+(.+?)\s*$", text))
    return {
        match.group(1).strip(): text[match.end(): matches[index + 1].start() if index + 1 < len(matches) else len(text)].strip()
        for index, match in enumerate(matches)
    }


def _tables(content: str) -> list[tuple[list[str], list[list[str]]]]:
    lines, result, index = content.splitlines(), [], 0
    separator = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?\s*$")
    while index + 1 < len(lines):
        if "|" not in lines[index] or not separator.fullmatch(lines[index + 1]):
            index += 1
            continue
        headers = [cell.strip() for cell in lines[index].strip().strip("|").split("|")]
        rows: list[list[str]] = []
        index += 2
        while index < len(lines) and "|" in lines[index] and lines[index].strip():
            row = [cell.strip() for cell in lines[index].strip().strip("|").split("|")]
            if len(row) == len(headers):
                rows.append(row)
            index += 1
        result.append((headers, rows))
    return result


def _short_or_verdict(value: str) -> bool:
    cleaned = re.sub(r"[`*\s]", "", value)
    return len(cleaned) < 4 or bool(re.fullmatch(r"(?i)(?:pass|passed|测试通过|成功|通过|ok|见上|n/?a|-)", value))


def validate_verification_evidence(
    verification_text: str,
    required_ids: set[str],
    boundary_ids: set[str],
    verdict: Any,
    errors: list[str],
) -> None:
    if not verification_text:
        return
    if RANGE_ID.search(verification_text):
        errors.append("verification.md must enumerate exact IDs; range evidence is forbidden")
    sections = _sections(verification_text)
    execution, trace = sections.get("5. 执行结果", ""), sections.get("6. 验收追踪", "")
    tables = [(headers, rows) for headers, rows in _tables(execution) if REQUIRED_HEADERS <= set(headers)]
    if not tables:
        errors.append("verification.md 执行结果 requires an evidence table with exact headers: 证据/覆盖/环境/命令或步骤/状态/退出码/观察结果/锚点")
        return

    rows_by_id: dict[str, dict[str, str]] = {}
    coverage: dict[str, set[str]] = {}
    for headers, rows in tables:
        for row in rows:
            values = dict(zip(headers, row))
            evidence = values["证据"].strip("` ")
            if not EVIDENCE_ID.fullmatch(evidence):
                errors.append(f"verification evidence row has invalid ID: {values['证据']}")
                continue
            if evidence in rows_by_id:
                errors.append(f"duplicate verification evidence ID: {evidence}")
                continue
            rows_by_id[evidence] = values
            status = values["状态"].strip("` ").lower()
            if status not in STATUSES:
                errors.append(f"{evidence} has invalid status: {values['状态']}")
            command, observed, anchor = values["命令或步骤"].strip(), values["观察结果"].strip(), values["锚点"].strip()
            if _short_or_verdict(command):
                errors.append(f"{evidence} requires an exact command or reproducible manual step")
            if _short_or_verdict(observed):
                errors.append(f"{evidence} requires a concrete observed result, not a verdict label")
            if len(re.sub(r"[`*\s]", "", anchor)) < 3 or anchor in {"-", "见上", "N/A"}:
                errors.append(f"{evidence} requires a concrete evidence anchor")
            exit_code = values["退出码"].strip("` ")
            explained_na = bool(re.search(r"(?i)n/?a.+(?:原因|reason|无进程退出码|人工|环境|阻塞|跳过)", exit_code))
            if status in {"passed", "failed"} and not re.fullmatch(r"[0-9]+", exit_code) and not explained_na:
                errors.append(f"{evidence} requires a numeric exit code or N/A plus a tool-specific reason")
            if status in {"manual", "blocked", "skipped"} and not explained_na:
                errors.append(f"{evidence} {status} result requires N/A plus a reason in 退出码")
            for trace_id in set(TRACE_ID.findall(values["覆盖"])):
                coverage.setdefault(trace_id, set()).add(evidence)
            if not TRACE_ID.findall(values["覆盖"]):
                errors.append(f"{evidence} must cover at least one exact traceability ID")

    missing = required_ids - set(coverage)
    if missing:
        errors.append(f"verification evidence does not cover exact IDs: {', '.join(sorted(missing))}")
    for required in sorted(required_ids):
        if not any(required in line and re.search(r"\bEVID-[0-9]+\b", line) for line in trace.splitlines()):
            errors.append(f"verification trace row for {required} lacks an exact EVID-* reference")
    if verdict == "PASS":
        for boundary_id in sorted(boundary_ids):
            evidence_ids = coverage.get(boundary_id, set())
            passed_rows = [rows_by_id[item] for item in evidence_ids if rows_by_id[item]["状态"].strip("` ").lower() == "passed"]
            if not passed_rows:
                errors.append(f"PASS verdict requires passed executable evidence for {boundary_id}")
                continue
            if not any(DIRECT_PROBE.search(row["命令或步骤"]) for row in passed_rows):
                errors.append(f"{boundary_id} requires passed direct-entry/API/runtime evidence")
            if not any(OBSERVED_BOUNDARY.search(row["观察结果"]) for row in passed_rows):
                errors.append(f"{boundary_id} requires observed status/payload/zero-write/snapshot result")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_dir")
    args = parser.parse_args()
    errors: list[str] = []
    try:
        feature_dir = Path(args.feature_dir).expanduser().resolve()
        state = _read_state(feature_dir)
        prd = (feature_dir / "prd.md").read_text(encoding="utf-8") if (feature_dir / "prd.md").is_file() else ""
        code_spec = (feature_dir / "code-spec.md").read_text(encoding="utf-8") if (feature_dir / "code-spec.md").is_file() else ""
        verification = (feature_dir / "verification.md").read_text(encoding="utf-8") if (feature_dir / "verification.md").is_file() else ""
        boundary_ids = {
            item.get("id") for item in state.get("architecture_review", {}).get("boundary_proofs", {}).get("proofs", [])
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        required = set(re.findall(r"\b(?:AC|EX)-[0-9]+\b", prd)) | set(TRACE_ID.findall(code_spec)) | boundary_ids
        validate_verification_evidence(verification, required, boundary_ids, state.get("stages", {}).get("verification", {}).get("verdict"), errors)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, AttributeError) as exc:
        errors.append(str(exc))
    for error in errors:
        print(f"ERROR: {error}")
    print("VALID" if not errors else f"INVALID: {len(errors)} error(s)")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
