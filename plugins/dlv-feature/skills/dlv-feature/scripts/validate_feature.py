#!/usr/bin/env python3
"""Validate dlv-feature state, semantic alignment, context, simplicity, and evidence gates."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from validate_boundary_proofs import validate_boundary_proofs
from validate_verification_evidence import validate_verification_evidence


FEATURE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
STATUSES = {"pending", "in_progress", "completed", "stale", "blocked", "not_applicable"}
STAGES = ("prd", "prototype", "architecture", "code_spec", "code", "verification")
ARTIFACTS = {
    "prd": "prd.md",
    "prototype": "prototype.html",
    "architecture": "architecture-design.md",
    "code_spec": "code-spec.md",
    "verification": "verification.md",
}
ALLOWED_FILES = {"state.md", *ARTIFACTS.values()}
STATE_START = "<!-- DLV_STATE_START -->"
STATE_END = "<!-- DLV_STATE_END -->"
FORBIDDEN_GOVERNANCE = re.compile(
    r"(?im)^##\s+(?:0\.|附录\s*[A-Z：:]*)?\s*(?:模块)?适用性(?:矩阵|判定)|"
    r"上下文胶囊|Context\s+Capsule|DLV_CONTEXT_CAPSULES"
)
PLACEHOLDER = re.compile(r"(?:TODO|TBD|待填写|待补充|template placeholder|fill this section)", re.I)
VERDICTS = {None, "PASS", "CONDITIONAL", "BLOCKED"}
SIMPLICITY_ITEMS = {"delete", "kiss", "dry", "responsibility", "dependency"}
SIMPLICITY_STATUSES = {"PASS", "FAIL", "N/A"}

TITLE_SUFFIXES = {
    "prd": "— 产品需求文档（PRD）",
    "architecture": "— 技术方案",
    "code_spec": "— 代码实现规格（Code Spec）",
    "verification": "— 测试与验收报告",
}
MANDATORY_SECTIONS = {
    "prd": (
        "1. 需求背景与目标",
        "2. 范围与约束",
        "3. 功能需求",
        "4. 业务流程",
        "7. 验收标准",
        "9. 风险与待确认事项",
        "10. 需求追踪",
    ),
    "architecture": (
        "1. 概述",
        "2. 现状",
        "3. 方案",
        "4. 流程",
        "8. 质量保障",
        "9. 影响范围",
        "10. 发布与回滚",
        "11. 需求追踪",
    ),
    "code_spec": (
        "1. 实现概述",
        "2. 实现映射",
        "6. 规则与异常",
        "7. 测试规格",
        "8. 实现批次",
        "9. 变更控制",
    ),
    "verification": (
        "1. 验证概述",
        "2. 实现核对",
        "3. 代码审查",
        "4. 测试方案",
        "5. 执行结果",
        "6. 验收追踪",
        "7. 问题与风险",
        "8. 验收结论",
    ),
}

ID_PATTERNS = {
    "SRC": re.compile(r"\bSRC-[0-9]+\b"),
    "FR": re.compile(r"\bFR-[0-9]+\b"),
    "BR": re.compile(r"\bBR-[0-9]+\b"),
    "AC": re.compile(r"\bAC-[0-9]+\b"),
    "EX": re.compile(r"\bEX-[0-9]+\b"),
    "US": re.compile(r"\bUS-[0-9]+\b"),
    "ARCH": re.compile(r"\bARCH-[0-9]+\b"),
    "FLOW": re.compile(r"\bFLOW-[0-9]+\b"),
    "API": re.compile(r"\bAPI-[0-9]+\b"),
    "DATA": re.compile(r"\bDATA-[0-9]+\b"),
    "UI": re.compile(r"\bUI-[0-9]+\b"),
    "IMPACT": re.compile(r"\bIMPACT-[0-9]+\b"),
    "CONTRACT": re.compile(r"\bCONTRACT-[A-Za-z0-9][A-Za-z0-9-]*\b"),
    "SHAPE": re.compile(r"\bSHAPE-[A-Za-z0-9][A-Za-z0-9-]*\b"),
    "DOMAIN": re.compile(r"\bD[0-9]{2,}\b"),
    "RULE": re.compile(r"\bR-D[0-9]{2,}-[0-9]+\b"),
    "TEST": re.compile(r"\bT-B[0-9]{2,}-[0-9]+\b"),
    "BATCH": re.compile(r"\bB[0-9]{2,}\b"),
    "BP": re.compile(r"\bBP-[0-9]+\b"),
    "EVID": re.compile(r"\bEVID-[0-9]+\b"),
}
ARCH_KINDS = ("ARCH", "FLOW", "API", "DATA", "UI", "IMPACT", "CONTRACT", "SHAPE")
ADDITION_TYPES = {"table", "link_table", "field", "api", "state", "service", "policy", "interface", "event", "queue"}
REVIEW_VERDICTS = {"PASS", "BLOCKED", "N/A"}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ids(text: str, kind: str) -> set[str]:
    return set(ID_PATTERNS[kind].findall(text))


def read_text(path: Path, label: str, errors: list[str]) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        errors.append(f"cannot read {label}: {exc}")
        return None


def extract_state(path: Path, errors: list[str]) -> dict[str, Any] | None:
    content = read_text(path, "state.md", errors)
    if content is None:
        return None
    if content.count(STATE_START) != 1 or content.count(STATE_END) != 1:
        errors.append("state.md must contain exactly one DLV state marker pair")
        return None
    start, end = content.find(STATE_START), content.find(STATE_END)
    if end <= start:
        errors.append("state.md DLV state markers are out of order")
        return None
    body = content[start + len(STATE_START):end]
    match = re.fullmatch(r"\s*```json\s*\n([\s\S]*?)\n```\s*", body)
    if not match:
        errors.append("state.md marker pair must contain exactly one fenced json block")
        return None
    try:
        state = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        errors.append(f"invalid state.md JSON block: {exc}")
        return None
    if not isinstance(state, dict):
        errors.append("state.md JSON block must be an object")
        return None
    outside = content[:start] + content[end + len(STATE_END):]
    if re.search(r'(?m)^\s*["\']?(?:schema_version|feature_id|current_stage|stages|blockers|last_updated)["\']?\s*[:：]', outside):
        errors.append("state.md must not duplicate state fields outside the machine state block")
    return state


def parse_sections(text: str, level: int = 2) -> dict[str, str]:
    marks = "#" * level
    matches = list(re.finditer(rf"(?m)^{marks}\s+(.+?)\s*$", text))
    result: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        result[match.group(1).strip()] = text[match.end():end].strip()
    return result


def markdown_anchor(title: str) -> str:
    return re.sub(r"[^\w\-\u4e00-\u9fff]", "", title.strip().lower().replace(" ", "-"))


def meaningful(content: str) -> bool:
    if not content or PLACEHOLDER.search(content):
        return False
    return len(re.sub(r"[`#|*_:>\-\s]", "", content)) >= 12


def has_markdown_table(content: str) -> bool:
    lines = content.splitlines()
    separator = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?\s*$")
    return any(index > 0 and "|" in lines[index - 1] and separator.fullmatch(line) for index, line in enumerate(lines))


def has_list(content: str, ordered: bool | None = None) -> bool:
    if ordered is True:
        pattern = r"(?m)^\s*\d+[.)]\s+\S"
    elif ordered is False:
        pattern = r"(?m)^\s*[-*+]\s+\S"
    else:
        pattern = r"(?m)^\s*(?:[-*+]|\d+[.)])\s+\S"
    return bool(re.search(pattern, content))


def long_prose_paragraphs(content: str, limit: int = 300) -> list[int]:
    """Return visible lengths for prose walls, ignoring structured Markdown blocks."""
    lengths: list[int] = []
    paragraph: list[str] = []
    in_fence = False

    def flush() -> None:
        if not paragraph:
            return
        visible = re.sub(r"[`*_>#\[\]()\s]", "", " ".join(paragraph))
        if len(visible) > limit:
            lengths.append(len(visible))
        paragraph.clear()

    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            flush()
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        structured = (
            not stripped
            or stripped.startswith("#")
            or stripped.startswith("|")
            or bool(re.match(r"^(?:[-*+]\s+|\d+[.)]\s+)", stripped))
            or bool(re.match(r"^[-:|\s]{3,}$", stripped))
        )
        if structured:
            flush()
        else:
            paragraph.append(stripped)
    flush()
    return lengths


def require_structure(
    sections: dict[str, str], heading: str, kinds: tuple[str, ...], document: str, errors: list[str]
) -> None:
    content = sections.get(heading)
    if content is None:
        return
    checks = {
        "table": has_markdown_table(content),
        "list": has_list(content),
        "ordered-list": has_list(content, ordered=True),
        "mermaid": bool(re.search(r"```mermaid\s*\n", content)),
    }
    if not any(checks[kind] for kind in kinds):
        errors.append(f"{document} section ## {heading} requires readable structure: {' or '.join(kinds)}")


def contains_any(content: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, content, re.I) for pattern in patterns)


def has_positive_change_signal(content: str, pattern: str) -> bool:
    """Detect an asserted addition while ignoring nearby negation/rejection."""
    for match in re.finditer(pattern, content, re.I):
        prefix = content[max(0, match.start() - 16):match.start()]
        if re.search(r"(?:不|无|未|无需|禁止|拒绝|删除|避免)\s*$", prefix):
            continue
        return True
    return False


def reports_legacy_bypass(content: str) -> bool:
    lowered = content.lower()
    if "未覆盖" in content:
        return True
    for match in re.finditer(r"bypass|旁路", lowered):
        prefix = lowered[max(0, match.start() - 12):match.start()]
        if re.search(r"(?:无|没有|不存在|禁止|消除|避免|no)\s*$", prefix):
            continue
        return True
    return False


def validate_readability(stage: str, sections: dict[str, str], errors: list[str]) -> None:
    name = ARTIFACTS[stage]
    for heading, content in sections.items():
        if not re.match(r"^[1-9][0-9]*\.\s+", heading):
            continue
        walls = long_prose_paragraphs(content)
        if walls:
            errors.append(
                f"{name} section ## {heading} contains a dense prose paragraph ({max(walls)} visible chars); "
                "split by semantic subheading, list, table, or diagram"
            )

    if stage == "prd":
        for heading in ("3. 功能需求", "7. 验收标准", "9. 风险与待确认事项", "10. 需求追踪"):
            require_structure(sections, heading, ("table",), name, errors)
        require_structure(sections, "4. 业务流程", ("list", "mermaid"), name, errors)
    elif stage == "architecture":
        require_structure(sections, "1. 概述", ("list", "table"), name, errors)
        for heading in ("2. 现状", "3. 方案", "5. 接口", "8. 质量保障", "9. 影响范围", "11. 需求追踪"):
            require_structure(sections, heading, ("table",), name, errors)
        require_structure(sections, "4. 流程", ("mermaid",), name, errors)
        require_structure(sections, "6. 数据", ("table", "mermaid"), name, errors)
        require_structure(sections, "7. 前端", ("table", "mermaid"), name, errors)
        require_structure(sections, "10. 发布与回滚", ("ordered-list",), name, errors)
        if "10. 发布与回滚" in sections and not has_markdown_table(sections["10. 发布与回滚"]):
            errors.append(f"{name} section ## 10. 发布与回滚 requires a rollback trigger/action table")
    elif stage == "code_spec":
        for heading in ("2. 实现映射", "6. 规则与异常", "7. 测试规格", "9. 变更控制"):
            require_structure(sections, heading, ("table",), name, errors)
    elif stage == "verification":
        for heading in ("2. 实现核对", "3. 代码审查", "4. 测试方案", "5. 执行结果", "6. 验收追踪", "7. 问题与风险"):
            require_structure(sections, heading, ("table",), name, errors)


def validate_document(stage: str, text: str, errors: list[str]) -> dict[str, str]:
    name = ARTIFACTS[stage]
    titles = re.findall(r"(?m)^#\s+(.+?)\s*$", text)
    suffix = TITLE_SUFFIXES[stage]
    if len(titles) != 1:
        errors.append(f"{name} must contain exactly one top-level title")
    elif not titles[0].endswith(suffix) or not re.search(r"[\u4e00-\u9fff]", titles[0]):
        errors.append(f"{name} title must be Chinese and end with: {suffix}")
    if FORBIDDEN_GOVERNANCE.search(text):
        errors.append(f"{name} contains forbidden governance content (chapter 0, applicability matrix, or Context Capsule)")
    sections = parse_sections(text)
    toc = sections.get("目录")
    if toc is None:
        errors.append(f"{name} missing required section: ## 目录")
    numbered = re.findall(r"(?m)^##\s+([1-9][0-9]*\.\s+.+?)\s*$", text)
    if re.search(r"(?m)^##\s+0\.", text):
        errors.append(f"{name} must not contain chapter 0")
    if toc is not None:
        toc_pos = text.find("## 目录")
        first_pos = min((text.find(f"## {heading}") for heading in numbered), default=len(text))
        if toc_pos > first_pos:
            errors.append(f"{name} table of contents must precede numbered body sections")
        links = re.findall(r"(?m)^\s*[-*]\s+\[([^\]]+)\]\((#[^)]+)\)\s*$", toc)
        labels = [label.strip() for label, _ in links]
        if labels != numbered:
            errors.append(f"{name} table of contents must exactly cover numbered sections in order: expected={numbered}, actual={labels}")
        for label, anchor in links:
            expected = f"#{markdown_anchor(label)}"
            if anchor != expected:
                errors.append(f"{name} table of contents anchor for {label!r} must be {expected}")
    for required in MANDATORY_SECTIONS[stage]:
        if required not in sections:
            errors.append(f"{name} missing required section: ## {required}")
        elif not meaningful(sections[required]):
            errors.append(f"{name} section has no concrete content: ## {required}")
    validate_readability(stage, sections, errors)
    return sections


def require_ids(container: str, required: set[str], location: str, errors: list[str]) -> None:
    present = set().union(*(ids(container, kind) for kind in ID_PATTERNS))
    missing = sorted(required - present)
    if missing:
        errors.append(f"{location} missing traceability IDs: {', '.join(missing)}")


def validate_requirement_review(review: Any, stages: dict[str, Any], errors: list[str]) -> set[str]:
    if not isinstance(review, dict):
        errors.append("requirement_review must be an object")
        return set()
    status = review.get("status")
    if status not in {"pending", "completed"}:
        errors.append("requirement_review.status must be pending or completed")
        return set()
    active_prd = stages.get("prd", {}).get("status") in {"in_progress", "blocked", "completed", "stale"}
    confirmed = review.get("confirmed_ids")
    confirmed_ids = set(confirmed) if isinstance(confirmed, list) and all(isinstance(x, str) for x in confirmed) else set()
    if active_prd and status != "completed":
        errors.append("PRD work requires completed requirement review")
    if status == "completed":
        if not isinstance(review.get("source_fingerprint"), str) or not SHA256.fullmatch(review["source_fingerprint"]):
            errors.append("completed requirement review requires a lowercase SHA-256 source_fingerprint")
        if not confirmed_ids or not all(ID_PATTERNS["SRC"].fullmatch(x) for x in confirmed_ids):
            errors.append("completed requirement review requires confirmed_ids containing only SRC-* IDs")
        summary = review.get("summary")
        required = {"goal", "users_scenarios", "in_scope", "out_scope", "key_rules", "ui_impact", "open_questions"}
        if not isinstance(summary, dict) or required - summary.keys():
            errors.append(f"completed requirement review summary missing: {', '.join(sorted(required - summary.keys())) if isinstance(summary, dict) else ', '.join(sorted(required))}")
        else:
            if summary.get("ui_impact") not in {"visible", "non_visible", "none"}:
                errors.append("requirement review ui_impact must be visible, non_visible, or none")
            for key in required - {"ui_impact"}:
                if summary.get(key) is None or summary.get(key) == "" or summary.get(key) == [] or summary.get(key) == {}:
                    errors.append(f"requirement review summary.{key} must be non-empty; use an explicit none/no-open-items statement")
        if not review.get("approved_at"):
            errors.append("completed requirement review requires approved_at")
    return confirmed_ids


def non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def require_object_fields(value: Any, required: set[str], location: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{location} must be an object")
        return False
    missing = required - value.keys()
    if missing:
        errors.append(f"{location} missing: {', '.join(sorted(missing))}")
        return False
    for key in required:
        if value.get(key) is None or value.get(key) == "" or value.get(key) == [] or value.get(key) == {}:
            errors.append(f"{location}.{key} must be non-empty")
    return True


def validate_architecture_review(
    review: Any, stages: dict[str, Any], prd_fp: Any, prototype_fp: Any, errors: list[str]
) -> dict[str, Any]:
    if not isinstance(review, dict):
        errors.append("architecture_review must be an object")
        return {}
    status = review.get("status")
    if status not in {"pending", "completed"}:
        errors.append("architecture_review.status must be pending or completed")
        return review
    arch_status = stages.get("architecture", {}).get("status")
    # A blocked Architecture may mean the convergence review is waiting for
    # evidence or user approval; detailed design has not started in that case.
    active = arch_status in {"in_progress", "completed", "stale"} or (
        arch_status == "blocked" and status == "completed"
    )
    if active and status != "completed":
        errors.append("architecture work requires completed architecture convergence review")
    inputs = review.get("inputs")
    if not isinstance(inputs, dict):
        errors.append("architecture_review.inputs must be an object")
    elif status == "completed":
        if inputs.get("prd") != prd_fp or inputs.get("prototype") != prototype_fp:
            errors.append("architecture_review inputs are stale")
        validate_repository_map(inputs.get("repositories"), "architecture_review.inputs.repositories", errors)
        if active and inputs.get("repositories") != stages.get("architecture", {}).get("inputs", {}).get("repositories"):
            errors.append("architecture_review repository baselines do not match architecture inputs")

    completed = status == "completed"
    capabilities = review.get("existing_capabilities")
    if not isinstance(capabilities, list) or not all(non_empty_string(x) for x in capabilities):
        errors.append("architecture_review.existing_capabilities must be a string array")
    elif completed and not capabilities:
        errors.append("completed architecture_review requires non-empty existing_capabilities")
    owners = review.get("fact_owners")
    if not isinstance(owners, list):
        errors.append("architecture_review.fact_owners must be an array")
        owners = []
    elif completed and not owners:
        errors.append("completed architecture_review requires fact_owners")
    for index, owner in enumerate(owners):
        require_object_fields(
            owner,
            {"id", "fact", "canonical_owner", "snapshot_or_reference", "lifecycle", "forbidden_duplicates", "evidence"},
            f"architecture_review.fact_owners[{index}]",
            errors,
        )

    additions = review.get("additions")
    if not isinstance(additions, list):
        errors.append("architecture_review.additions must be an array")
        additions = []
    for index, addition in enumerate(additions):
        location = f"architecture_review.additions[{index}]"
        if not require_object_fields(
            addition,
            {"id", "type", "object", "existing_alternative", "why_not_reuse", "evidence", "second_source_risk", "verdict"},
            location,
            errors,
        ):
            continue
        if not re.fullmatch(r"ADD-[0-9]+", str(addition.get("id", ""))):
            errors.append(f"{location}.id must use ADD-nn")
        if addition.get("type") not in ADDITION_TYPES:
            errors.append(f"{location}.type is invalid: {addition.get('type')}")
        if addition.get("verdict") not in {"APPROVED", "REJECTED", "BLOCKED"}:
            errors.append(f"{location}.verdict must be APPROVED, REJECTED, or BLOCKED")
        if completed and addition.get("verdict") == "BLOCKED":
            errors.append(f"completed architecture review contains blocked addition: {addition.get('id')}")
        risk = str(addition.get("second_source_risk", "")).lower()
        if addition.get("verdict") == "APPROVED" and risk not in {"none", "no", "无", "已消除", "false"}:
            errors.append(f"approved addition {addition.get('id')} has unresolved second-source risk")
        if addition.get("type") in {"policy", "interface"} and addition.get("verdict") == "APPROVED":
            variants = addition.get("real_variants")
            if not isinstance(variants, list) or len(variants) < 2:
                errors.append(f"approved {addition.get('type')} {addition.get('id')} requires at least two real variants")
        if addition.get("type") == "link_table" and addition.get("verdict") == "APPROVED":
            relation = addition.get("independent_relation_fact")
            if not non_empty_string(relation):
                errors.append(f"approved link table {addition.get('id')} requires independent_relation_fact")
        if addition.get("type") == "field" and addition.get("verdict") == "APPROVED":
            category = addition.get("fact_category")
            if category not in {"canonical", "snapshot", "derived", "cache"}:
                errors.append(f"approved field {addition.get('id')} requires fact_category")
            if category == "snapshot" and not non_empty_string(addition.get("freeze_point")):
                errors.append(f"snapshot field {addition.get('id')} requires freeze_point")

    api_decisions = review.get("api_decisions")
    if not isinstance(api_decisions, list):
        errors.append("architecture_review.api_decisions must be an array")
        api_decisions = []
    for index, decision in enumerate(api_decisions):
        location = f"architecture_review.api_decisions[{index}]"
        if not require_object_fields(
            decision,
            {"id", "resource", "existing_api", "decision", "reason", "compatibility", "verdict"},
            location,
            errors,
        ):
            continue
        if decision.get("verdict") not in {"APPROVED", "REJECTED", "BLOCKED"}:
            errors.append(f"{location}.verdict is invalid")
        if completed and decision.get("verdict") == "BLOCKED":
            errors.append(f"completed architecture review contains blocked API decision: {decision.get('id')}")
        if decision.get("decision") == "parallel_api_same_semantics" and decision.get("verdict") == "APPROVED":
            errors.append(f"API decision {decision.get('id')} approves a same-semantics parallel API")
        if decision.get("long_term_write_entries", 1) not in {0, 1} and not non_empty_string(decision.get("sunset_plan")):
            errors.append(f"API decision {decision.get('id')} has multiple write entries without sunset_plan")

    isolation = review.get("isolation")
    if not isinstance(isolation, dict) or isolation.get("verdict") not in REVIEW_VERDICTS:
        errors.append("architecture_review.isolation must contain a valid verdict")
    elif isolation.get("applicable"):
        required = {"tenant_source", "storage_boundary", "missing_context", "setup_failure", "cross_entity_check", "async_context", "two_tenant_test", "migration_scope", "verdict"}
        require_object_fields(isolation, required, "architecture_review.isolation", errors)
        if completed and isolation.get("verdict") != "PASS":
            errors.append("applicable isolation review must PASS")
        if isolation.get("verdict") == "PASS" and "fail-closed" not in str(isolation.get("setup_failure", "")).lower() and "拒绝" not in str(isolation.get("setup_failure", "")):
            errors.append("tenant boundary setup failure must be fail-closed")

    concurrency = review.get("concurrency")
    if not isinstance(concurrency, dict) or concurrency.get("verdict") not in REVIEW_VERDICTS:
        errors.append("architecture_review.concurrency must contain a valid verdict")
    elif concurrency.get("applicable"):
        required = {"write_operations", "lock_order", "legacy_entry_coverage", "allowed_races", "verdict"}
        require_object_fields(concurrency, required, "architecture_review.concurrency", errors)
        operations = concurrency.get("write_operations")
        if not isinstance(operations, list) or not operations:
            errors.append("applicable concurrency review requires write_operations")
        else:
            for index, operation in enumerate(operations):
                require_object_fields(operation, {"operation", "root", "token", "transaction", "unique_constraint", "failure_result"}, f"architecture_review.concurrency.write_operations[{index}]", errors)
        if completed and concurrency.get("verdict") != "PASS":
            errors.append("applicable concurrency review must PASS")
        coverage = str(concurrency.get("legacy_entry_coverage", ""))
        if reports_legacy_bypass(coverage):
            errors.append("legacy write entry can bypass concurrency protection")

    variants = review.get("rule_variants")
    if not isinstance(variants, dict) or variants.get("verdict") not in REVIEW_VERDICTS:
        errors.append("architecture_review.rule_variants must contain a valid verdict")
    elif variants.get("applicable"):
        required = {"actual_variants", "shared_rules", "varying_rules", "dispatch_point", "frontend_boundary", "error_codes", "verdict"}
        require_object_fields(variants, required, "architecture_review.rule_variants", errors)
        if completed and variants.get("verdict") != "PASS":
            errors.append("applicable rule-variant review must PASS")
        policies = variants.get("new_policies")
        actual = variants.get("actual_variants")
        if not isinstance(policies, list):
            errors.append("architecture_review.rule_variants.new_policies must be an array")
        if isinstance(policies, list) and policies and (not isinstance(actual, list) or len(actual) < 2):
            errors.append("new Policy/interface requires at least two current real variants")

    material_decisions = review.get("material_decisions")
    if not isinstance(material_decisions, list):
        errors.append("architecture_review.material_decisions must be an array")
        material_decisions = []
    for index, decision in enumerate(material_decisions):
        valid = require_object_fields(
            decision,
            {"id", "addition_ids", "decision", "reason", "reversible", "approval"},
            f"architecture_review.material_decisions[{index}]",
            errors,
        )
        if valid and not re.fullmatch(r"MAT-[0-9]+", str(decision.get("id", ""))):
            errors.append(f"architecture_review.material_decisions[{index}].id must use MAT-nn")
        if isinstance(decision, dict) and decision.get("approval") not in {"PENDING", "APPROVED"}:
            errors.append(f"material architecture decision {decision.get('id')} approval must be PENDING or APPROVED")
        if completed and isinstance(decision, dict) and decision.get("approval") != "APPROVED":
            errors.append(f"material architecture decision {decision.get('id')} is not approved")
    material_types = {"table", "link_table", "api", "event", "queue"}
    material_additions = [
        item for item in additions
        if isinstance(item, dict) and item.get("verdict") == "APPROVED" and item.get("type") in material_types
    ]
    material_ids = {str(item.get("id")) for item in material_additions}
    covered_material_ids: set[str] = set()
    for index, decision in enumerate(material_decisions):
        if not isinstance(decision, dict):
            continue
        addition_ids = decision.get("addition_ids")
        if not isinstance(addition_ids, list) or not addition_ids or not all(isinstance(item, str) for item in addition_ids):
            errors.append(f"architecture_review.material_decisions[{index}].addition_ids must be a non-empty string array")
            continue
        unknown = set(addition_ids) - material_ids
        if unknown:
            errors.append(f"material architecture decision {decision.get('id')} references unknown material additions: {', '.join(sorted(unknown))}")
        covered_material_ids |= set(addition_ids) & material_ids
    uncovered = material_ids - covered_material_ids
    if uncovered:
        errors.append(f"approved material additions lack MAT-* approval coverage: {', '.join(sorted(uncovered))}")
    if not isinstance(review.get("boundary_proofs"), dict):
        errors.append("architecture_review.boundary_proofs must be an object")
    if completed and not review.get("approved_at"):
        errors.append("completed architecture_review requires approved_at")
    return review


def validate_repository_map(value: Any, location: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{location} must be an object")
        return
    for name, baseline in value.items():
        if not isinstance(name, str) or not name.strip() or not isinstance(baseline, str) or not baseline.strip():
            errors.append(f"{location} repository names and baselines must be non-empty strings")


def validate_inputs_shape(stage: str, item: dict[str, Any], errors: list[str]) -> None:
    required = {
        "prototype": {"prd"},
        "architecture": {"prd", "prototype", "repositories"},
        "code_spec": {"prd", "architecture", "repositories"},
        "code": {"code_spec", "repositories"},
        "verification": {"prd", "architecture", "code_spec", "code_result", "repositories"},
    }
    if stage not in required:
        return
    inputs = item.get("inputs")
    if not isinstance(inputs, dict):
        errors.append(f"stages.{stage}.inputs must be an object")
        return
    missing = required[stage] - inputs.keys()
    if missing:
        errors.append(f"stages.{stage}.inputs missing: {', '.join(sorted(missing))}")
    if "repositories" in required[stage] and "repositories" in inputs:
        validate_repository_map(inputs["repositories"], f"stages.{stage}.inputs.repositories", errors)


def validate_completed_inputs(stages: dict[str, Any], errors: list[str]) -> None:
    prd_fp = stages.get("prd", {}).get("fingerprint")
    proto = stages.get("prototype", {})
    proto_fp = proto.get("fingerprint") if proto.get("status") == "completed" else None
    arch_fp = stages.get("architecture", {}).get("fingerprint")
    spec_fp = stages.get("code_spec", {}).get("fingerprint")
    code_result = stages.get("code", {}).get("result")
    expected = {
        "prototype": {"prd": prd_fp},
        "architecture": {"prd": prd_fp, "prototype": proto_fp},
        "code_spec": {"prd": prd_fp, "architecture": arch_fp},
        "code": {"code_spec": spec_fp},
        "verification": {"prd": prd_fp, "architecture": arch_fp, "code_spec": spec_fp, "code_result": code_result},
    }
    for stage, values in expected.items():
        status = stages.get(stage, {}).get("status")
        if status != "completed" and not (stage == "prototype" and status == "not_applicable"):
            continue
        inputs = stages.get(stage, {}).get("inputs")
        if not isinstance(inputs, dict):
            continue
        for key, current in values.items():
            if inputs.get(key) != current:
                errors.append(f"completed stage {stage} has stale input {key}; mark it and downstream stages stale")


def validate_prototype_contract(item: dict[str, Any], prd_text: str, errors: list[str]) -> None:
    contract = item.get("contract")
    if not isinstance(contract, dict):
        errors.append("completed prototype requires stages.prototype.contract")
        return
    required = {"target_app", "target_surface", "source_refs", "story_ids", "covered_states", "prd_fingerprint", "deviations"}
    missing = required - contract.keys()
    if missing:
        errors.append(f"prototype contract missing: {', '.join(sorted(missing))}")
    for key in ("target_app", "target_surface"):
        if not isinstance(contract.get(key), str) or not contract[key].strip():
            errors.append(f"prototype contract.{key} must be non-empty")
    for key in ("source_refs", "story_ids", "covered_states", "deviations"):
        value = contract.get(key)
        if not isinstance(value, list) or (key != "deviations" and not value):
            errors.append(f"prototype contract.{key} must be {'a' if key == 'deviations' else 'a non-empty'} array")
    for story in contract.get("story_ids", []) if isinstance(contract.get("story_ids"), list) else []:
        if not isinstance(story, str) or not ID_PATTERNS["US"].fullmatch(story) or story not in prd_text:
            errors.append(f"prototype contract has unknown story ID: {story}")
    if contract.get("prd_fingerprint") != hashlib.sha256(prd_text.encode()).hexdigest():
        errors.append("prototype contract PRD fingerprint is stale")


def validate_prototype_html(path: Path, contract: dict[str, Any], errors: list[str]) -> None:
    html = read_text(path, "prototype.html", errors)
    if html is None:
        return
    for story in contract.get("story_ids", []) if isinstance(contract.get("story_ids"), list) else []:
        if not re.search(rf'data-story-id\s*=\s*["\'][^"\']*\b{re.escape(story)}\b', html):
            errors.append(f"prototype.html does not expose data-story-id for {story}")
    html_states = set(re.findall(r'data-state\s*=\s*["\']([^"\']+)', html))
    for state in contract.get("covered_states", []) if isinstance(contract.get("covered_states"), list) else []:
        if state not in html_states:
            errors.append(f"prototype.html does not expose contracted data-state: {state}")


def subsection(text: str, heading: str) -> str:
    match = re.search(rf"(?m)^####\s+{re.escape(heading)}\s*$", text)
    if not match:
        return ""
    next_match = re.search(r"(?m)^#{3,4}\s+", text[match.end():])
    end = match.end() + next_match.start() if next_match else len(text)
    return text[match.end():end].strip()


def list_items(content: str) -> list[str]:
    items = []
    for line in content.splitlines():
        match = re.match(r"\s*[-*]\s+(.+?)\s*$", line)
        if match and not re.match(r"(?i)(?:无|none|N/A)(?:\s*[:：]|$)", match.group(1)):
            items.append(match.group(1))
    return items


def validate_batches(text: str, arch_ids: set[str], errors: list[str]) -> tuple[set[str], set[str], set[str]]:
    matches = list(re.finditer(r"(?m)^###\s+(B[0-9]{2,})(?:\s*[：:].*)?\s*$", text))
    batches, objectives, rules = set(), set(), set()
    required_parts = ("目标", "架构锚点", "仓库与基线", "候选路径", "源码必读", "测试/配置必读", "允许修改", "排除范围", "依赖深度", "测试与完成条件")
    for index, match in enumerate(matches):
        batch = match.group(1)
        body_end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = text[match.end():body_end]
        batches.add(batch)
        for part in required_parts:
            if not subsection(body, part):
                errors.append(f"Code Spec batch {batch} missing subsection: #### {part}")
        objective = subsection(body, "目标")
        batch_rules = ids(objective, "RULE")
        batch_acceptance = ids(objective, "AC") | ids(objective, "EX")
        rules |= batch_rules
        objectives |= batch_acceptance
        if not batch_rules or not batch_acceptance:
            errors.append(f"Code Spec batch {batch} objective requires R-* and AC-* or EX-*")
        anchor_text = subsection(body, "架构锚点")
        batch_arch = set().union(*(ids(anchor_text, kind) for kind in ARCH_KINDS))
        if not batch_arch:
            errors.append(f"Code Spec batch {batch} requires at least one architecture anchor")
        unknown = batch_arch - arch_ids
        if unknown:
            errors.append(f"Code Spec batch {batch} uses unapproved architecture IDs: {', '.join(sorted(unknown))}")
        candidates = list_items(subsection(body, "候选路径"))
        source_reads = list_items(subsection(body, "源码必读"))
        support_reads = list_items(subsection(body, "测试/配置必读"))
        writes = list_items(subsection(body, "允许修改"))
        if len(candidates) > 20 or len(source_reads) > 8 or len(support_reads) > 4:
            expansion = subsection(body, "扩容说明")
            if not expansion or not re.search(r"(?i)(?:理由|reason)\s*[:：]", expansion) or not re.search(r"(?i)(?:证据关系|evidence[_ ]relation)\s*[:：]", expansion):
                errors.append(f"Code Spec batch {batch} exceeds Context Gate without reason and evidence relation")
        if not writes:
            errors.append(f"Code Spec batch {batch} requires at least one allowed write")
        if re.search(r"(?i)(?:status|状态)\s*[:：|]\s*`?(?:candidate|gap)\b", subsection(body, "允许修改")):
            errors.append(f"Code Spec batch {batch} write scope contains candidate or gap")
        depth_text = subsection(body, "依赖深度")
        depth_match = re.search(r"\b([0-9]+)\b", depth_text)
        if not depth_match:
            errors.append(f"Code Spec batch {batch} dependency depth must be an integer")
        elif int(depth_match.group(1)) > 1 and not subsection(body, "扩容说明"):
            errors.append(f"Code Spec batch {batch} dependency depth exceeds 1 without expansion")
    if not batches:
        errors.append("code-spec.md requires at least one ### Bxx implementation batch")
    return batches, objectives, rules


def validate_simplicity_gate(item: dict[str, Any], errors: list[str]) -> None:
    gate = item.get("simplicity_gate")
    if not isinstance(gate, dict):
        errors.append("completed code requires simplicity_gate object")
        return
    if gate.keys() != SIMPLICITY_ITEMS:
        errors.append("code simplicity_gate must contain exactly delete, kiss, dry, responsibility, dependency")
    for name in sorted(SIMPLICITY_ITEMS & gate.keys()):
        result = gate[name]
        if not isinstance(result, dict) or result.get("status") not in SIMPLICITY_STATUSES:
            errors.append(f"code simplicity_gate.{name} must have PASS, FAIL, or N/A status")
            continue
        if result["status"] == "FAIL":
            errors.append(f"completed code is blocked by simplicity_gate.{name}=FAIL")
        elif result["status"] == "PASS" and not result.get("evidence"):
            errors.append(f"code simplicity_gate.{name}=PASS requires evidence")
        elif result["status"] == "N/A" and not result.get("reason"):
            errors.append(f"code simplicity_gate.{name}=N/A requires reason")


def validate_semantics(
    feature_dir: Path,
    stages: dict[str, Any],
    confirmed_src: set[str],
    architecture_review: dict[str, Any],
    errors: list[str],
) -> None:
    docs: dict[str, str] = {}
    sections: dict[str, dict[str, str]] = {}
    for stage in MANDATORY_SECTIONS:
        stage_status = stages.get(stage, {}).get("status")
        if stage_status not in {"in_progress", "blocked", "completed", "stale"}:
            continue
        if stage == "architecture" and stage_status == "blocked" and architecture_review.get("status") != "completed":
            continue
        path = feature_dir / ARTIFACTS[stage]
        if not path.is_file() or path.stat().st_size == 0:
            errors.append(f"stage {stage} requires non-empty {ARTIFACTS[stage]}")
            continue
        text = read_text(path, ARTIFACTS[stage], errors)
        if text is None:
            continue
        docs[stage] = text
        sections[stage] = validate_document(stage, text, errors)

    product: dict[str, set[str]] = {}
    if "prd" in docs:
        product = {kind: ids(docs["prd"], kind) for kind in ("SRC", "FR", "BR", "AC", "EX", "US")}
        if product["SRC"] != confirmed_src:
            errors.append(f"prd.md SRC IDs must exactly match requirement review: review={sorted(confirmed_src)}, prd={sorted(product['SRC'])}")
        if not product["FR"]:
            errors.append("prd.md requires at least one FR-*")
        if not product["AC"] and not product["EX"]:
            errors.append("prd.md requires at least one AC-* or EX-*")
        trace = sections["prd"].get("10. 需求追踪", "")
        require_ids(trace, product["SRC"] | product["FR"] | product["AC"] | product["EX"], "prd.md 需求追踪", errors)
        visible = bool(re.search(r"(?i)(?:UI\s*影响|界面影响)\s*[:：|]\s*`?visible\b", docs["prd"]))
        if visible and "8. UI 需求" not in sections["prd"]:
            errors.append("visible UI work requires ## 8. UI 需求")
        if visible and not product["US"]:
            errors.append("visible UI work requires at least one US-*")
        if stages.get("prd", {}).get("status") == "completed":
            prototype_status = stages.get("prototype", {}).get("status")
            if visible and prototype_status != "completed":
                errors.append("completed visible-UI PRD requires completed prototype experiment")
            if not visible and prototype_status != "not_applicable":
                errors.append("completed non-visible PRD requires prototype=not_applicable")
        nfr = bool(re.search(r"(?:性能|安全|隐私|可靠性|可观测性|兼容性|权限|超时|并发|容量|限流|审计)(?:要求|目标|规则)", docs["prd"]))
        if nfr and "6. 非功能需求" not in sections["prd"]:
            errors.append("declared non-functional behavior requires ## 6. 非功能需求")
        review_isolation = architecture_review.get("isolation", {})
        product_isolation_signal = bool(re.search(r"(?:持久化|数据库|异步任务|多租户|tenant)", docs["prd"], re.I))
        if architecture_review.get("status") == "completed" and product_isolation_signal:
            if not (isinstance(review_isolation, dict) and review_isolation.get("applicable")):
                errors.append("PRD persistence/async/multi-tenant signal requires applicable isolation review")

    arch_ids: set[str] = set()
    boundary_ids: set[str] = set()
    if architecture_review.get("status") == "completed":
        boundary_ids = validate_boundary_proofs(
            architecture_review.get("boundary_proofs"),
            product.get("AC", set()) | product.get("EX", set()),
            docs.get("architecture", ""),
            docs.get("code_spec", ""),
            docs.get("verification", ""),
            "architecture" in docs,
            errors,
        )

    if "architecture" in docs:
        for kind in ARCH_KINDS:
            arch_ids |= ids(docs["architecture"], kind)
        if not ids(sections["architecture"].get("3. 方案", ""), "ARCH"):
            errors.append("architecture-design.md 方案 requires at least one ARCH-*")
        current_section = sections["architecture"].get("2. 现状", "")
        current_semantics = {
            "可复用能力": (r"可复用|复用能力|沿用",),
            "事实所有权": (r"事实所有权|事实所有者|正典所有者|正典报价|正典实体",),
            "API/事务/权限边界": (r"(?:API|接口).*(?:事务|权限|授权)", r"(?:事务|权限|授权).*(?:API|接口)"),
            "系统性缺口": (r"系统性缺口|系统缺口|缺口",),
        }
        for label, patterns in current_semantics.items():
            if not contains_any(current_section, patterns):
                errors.append(f"architecture-design.md 现状 missing required analysis: {label}")
        solution_section = sections["architecture"].get("3. 方案", "")
        solution_semantics = {
            "复用/扩展/替换/新增裁决": (r"复用.*扩展.*(?:替换|新增)|复用、扩展与新增裁决|裁决",),
            "被拒绝方案": (r"被拒绝方案|拒绝原因|拒绝方案",),
            "规则分派": (r"规则分派|分派边界|唯一分派",),
        }
        for label, patterns in solution_semantics.items():
            if not contains_any(solution_section, patterns):
                errors.append(f"architecture-design.md 方案 missing required convergence result: {label}")
        for addition in architecture_review.get("additions", []) if isinstance(architecture_review.get("additions"), list) else []:
            if isinstance(addition, dict) and addition.get("id") not in solution_section:
                errors.append(f"architecture-design.md 方案 does not consume architecture review addition: {addition.get('id')}")
        for decision in architecture_review.get("api_decisions", []) if isinstance(architecture_review.get("api_decisions"), list) else []:
            if isinstance(decision, dict) and decision.get("id") not in solution_section:
                errors.append(f"architecture-design.md 方案 does not consume API review decision: {decision.get('id')}")
        if len(ids(docs["architecture"], "API")) > 1 and not architecture_review.get("api_decisions"):
            errors.append("multiple architecture APIs require explicit API reuse/evolution decisions")
        approved_additions: dict[str, set[str]] = {kind: set() for kind in ADDITION_TYPES}
        for addition in architecture_review.get("additions", []) if isinstance(architecture_review.get("additions"), list) else []:
            if isinstance(addition, dict) and addition.get("verdict") == "APPROVED" and addition.get("type") in approved_additions:
                approved_additions[addition["type"]].add(str(addition.get("id")))
        new_signals = {
            "table": r"(?:新增|新建)(?:一个|新的|数据库)?\s*[`\w-]*\s*表\b|CREATE\s+TABLE",
            "link_table": r"(?:新增|新建)(?:一个|新的)?\s*[`\w-]*\s*(?:link|关联|关系)表",
            "field": r"(?:新增|增加)(?:一个|新的|以下)?\s*[`\w-]*\s*字段",
            "api": r"(?:新增|新建)(?:一个|新的)?\s*[`\w/-]*\s*(?:API|接口)",
            "state": r"(?:新增|增加)(?:一个|新的)?\s*[`\w-]*\s*状态",
            "service": r"(?:新增|新建)(?:一个|新的)?\s*[`\w-]*\s*Service",
            "policy": r"(?:新增|新建)(?:一个|新的)?\s*[`\w-]*\s*Policy",
            "interface": r"(?:新增|新建)(?:一个|新的)?\s*[`\w-]*\s*(?:interface|抽象接口)",
            "event": r"(?:新增|新建)(?:一个|新的)?\s*[`\w-]*\s*(?:事件|event)",
            "queue": r"(?:新增|新建)(?:一个|新的)?\s*[`\w-]*\s*(?:队列|queue|topic)",
        }
        for kind, pattern in new_signals.items():
            approved_for_kind = approved_additions[kind]
            if kind == "table":
                approved_for_kind = approved_for_kind | approved_additions["link_table"]
            if has_positive_change_signal(docs["architecture"], pattern) and not approved_for_kind:
                errors.append(f"architecture declares a new {kind} without an approved ADD-* evidence decision")
        flow_section = sections["architecture"].get("4. 流程", "")
        if not ids(flow_section, "FLOW"):
            errors.append("architecture-design.md 流程 requires at least one FLOW-*")
        if not re.search(r"```mermaid\s*\n\s*flowchart\s+(?:TD|LR)", flow_section):
            errors.append("architecture-design.md 核心流程 requires a Mermaid flowchart")
        if not ids(sections["architecture"].get("9. 影响范围", ""), "IMPACT"):
            errors.append("architecture-design.md 影响范围 requires at least one IMPACT-*")
        if re.search(r"(?i)(?:status|状态)\s*[:：|]\s*`?(?:candidate|gap)\b", sections["architecture"].get("9. 影响范围", "")):
            errors.append("architecture impact scope contains candidate or gap")
        if ids(docs["architecture"], "API") and "5. 接口" not in sections["architecture"]:
            errors.append("API-* requires architecture section ## 5. 接口")
        if ids(docs["architecture"], "DATA") and "6. 数据" not in sections["architecture"]:
            errors.append("DATA-* requires architecture section ## 6. 数据")
        if ids(docs["architecture"], "DATA"):
            data_section = sections["architecture"].get("6. 数据", "")
            required_terms = {
                "事实所有权": (r"事实所有权|事实所有者|所有权",),
                "正典": (r"正典",),
                "快照": (r"快照",),
                "删除/保留": (r"删除|保留|生命周期",),
                "字段": (r"字段",),
                "约束": (r"约束",),
                "索引": (r"索引",),
                "容量": (r"容量",),
                "一致性": (r"一致性",),
                "事务": (r"事务",),
                "锁顺序": (r"锁顺序|按.*(?:升序|顺序).*锁",),
                "迁移": (r"迁移|migration",),
                "回滚": (r"回滚",),
            }
            missing_terms = [term for term, patterns in required_terms.items() if not contains_any(data_section, patterns)]
            if missing_terms:
                errors.append(f"architecture database design missing semantics: {', '.join(missing_terms)}")
            if "erDiagram" not in data_section and not re.search(r"(?m)^\s*\|.*字段.*\|", data_section):
                errors.append("architecture data model change requires ER diagram or field relationship table")
        if (ids(docs["architecture"], "UI") or ids(docs["architecture"], "SHAPE")) and "7. 前端" not in sections["architecture"]:
            errors.append("UI/SHAPE architecture requires section ## 7. 前端")
        if product.get("US") and not (ids(docs["architecture"], "UI") or ids(docs["architecture"], "SHAPE")):
            errors.append("visible UI product stories require UI-* or SHAPE-* architecture decisions")
        trace = sections["architecture"].get("11. 需求追踪", "")
        required_product = set().union(*(product.get(k, set()) for k in ("FR", "BR", "AC", "EX")))
        require_ids(trace, required_product, "architecture-design.md 需求追踪", errors)
        repositories = stages.get("architecture", {}).get("inputs", {}).get("repositories", {})
        if isinstance(repositories, dict) and len(repositories) > 1 and "sequenceDiagram" not in flow_section:
            errors.append("multi-repository architecture requires a Mermaid sequenceDiagram")
        quality_section = sections["architecture"].get("8. 质量保障", "")
        persistence_signal = bool(ids(docs["architecture"], "DATA") or re.search(r"(?:数据库|持久化|异步|多租户|tenant)", docs["architecture"], re.I))
        if persistence_signal:
            quality_semantics = {
                "数据隔离": (r"数据隔离|租户隔离|隔离与",),
                "失败模式": (r"失败|拒绝|冲突|回滚",),
                "用户可见结果": (r"错误|结果码|不可见|冲突|拒绝",),
            }
            for label, patterns in quality_semantics.items():
                if not contains_any(quality_section, patterns):
                    errors.append(f"architecture quality section missing: {label}")
        async_signal = bool(re.search(r"(?:异步处理|异步任务|消息队列|队列消费|worker|event)", docs["architecture"], re.I))
        if async_signal:
            for label in ("上下文传播", "失败恢复"):
                if label not in quality_section:
                    errors.append(f"asynchronous architecture quality section missing: {label}")
        multi_write_signal = bool(re.search(r"(?:多写入口|多个写入口|旧入口|并发写|旁路写)", docs["architecture"]))
        if multi_write_signal:
            whole_design = docs["architecture"]
            concurrency_semantics = {
                "并发令牌": (r"并发令牌|If-Match|\bversion\b",),
                "事务": (r"事务",),
                "锁顺序": (r"锁顺序|按.*(?:升序|顺序).*锁",),
                "冲突结果": (r"冲突结果|版本冲突|最多一个成功|QUOTE_VERSION_CONFLICT",),
            }
            for label, patterns in concurrency_semantics.items():
                if not contains_any(whole_design, patterns):
                    errors.append(f"multi-write architecture missing: {label}")
        variant_signal = bool(re.search(r"(?:产品类型|业务变体|Policy|策略分派)", docs["architecture"], re.I))
        if variant_signal:
            whole_design = docs["architecture"]
            variant_semantics = {
                "真实变体": (r"真实变体|STANDARD.*CUSTOM.*BUNDLE|三种类型",),
                "共享规则": (r"共享规则|共享的租户|统一执行",),
                "变化规则": (r"变化规则|自身.*规则|各.*类型.*规则",),
                "分派点": (r"分派点|唯一分派|按.*productType.*分派",),
                "机器错误码": (r"机器错误码|稳定错误|[A-Z][A-Z_]{4,}",),
                "前端边界": (r"前端边界|无 UI|服务端.*规则",),
            }
            for label, patterns in variant_semantics.items():
                if not contains_any(whole_design, patterns):
                    errors.append(f"rule extensibility analysis missing: {label}")
        review_isolation = architecture_review.get("isolation", {})
        review_concurrency = architecture_review.get("concurrency", {})
        review_variants = architecture_review.get("rule_variants", {})
        if persistence_signal and not (isinstance(review_isolation, dict) and review_isolation.get("applicable")):
            errors.append("persistence/async/multi-tenant architecture requires applicable isolation review")
        if multi_write_signal and not (isinstance(review_concurrency, dict) and review_concurrency.get("applicable")):
            errors.append("multi-write architecture requires applicable concurrency review")
        if variant_signal and not (isinstance(review_variants, dict) and review_variants.get("applicable")):
            errors.append("product variants or policy dispatch require applicable rule-variant review")
        # The approved review packet is canonical. Detailed design may distribute
        # those decisions across quality, data, flow, and interface sections; do
        # not force duplicate fixed labels into the quality section.

    rules: set[str] = set()
    tests: set[str] = set()
    batches: set[str] = set()
    assurance_ids = {
        str(item.get("id"))
        for item in (
            architecture_review.get("boundary_proofs", {}).get("proofs", [])
            if isinstance(architecture_review.get("boundary_proofs"), dict)
            else []
        )
        if isinstance(item, dict) and item.get("id")
    }
    if "code_spec" in docs:
        code_arch = set().union(*(ids(docs["code_spec"], kind) for kind in ARCH_KINDS))
        missing_arch = arch_ids - code_arch
        extra_arch = code_arch - arch_ids
        if missing_arch:
            errors.append(f"code-spec.md does not consume architecture IDs: {', '.join(sorted(missing_arch))}")
        if extra_arch:
            errors.append(f"code-spec.md introduces unapproved architecture IDs: {', '.join(sorted(extra_arch))}")
        mapping = sections["code_spec"].get("2. 实现映射", "")
        if not ids(mapping, "DOMAIN"):
            errors.append("code-spec.md 实现映射 requires at least one Dxx")
        rules = ids(sections["code_spec"].get("6. 规则与异常", ""), "RULE")
        tests = ids(sections["code_spec"].get("7. 测试规格", ""), "TEST")
        if not rules or not tests:
            errors.append("code-spec.md requires at least one R-Dxx-xx and T-Bxx-xx")
        batches, objectives, batch_rules = validate_batches(sections["code_spec"].get("8. 实现批次", ""), arch_ids, errors)
        if rules - batch_rules:
            errors.append(f"implementation batches do not consume rules: {', '.join(sorted(rules - batch_rules))}")
        required_acceptance = product.get("AC", set()) | product.get("EX", set())
        missing_acceptance = required_acceptance - objectives
        if missing_acceptance:
            errors.append(f"implementation batches do not consume product acceptance IDs: {', '.join(sorted(missing_acceptance))}")
        missing_rule_products = (product.get("FR", set()) | product.get("BR", set()) | product.get("AC", set())) - ids(sections["code_spec"].get("6. 规则与异常", ""), "FR") - ids(sections["code_spec"].get("6. 规则与异常", ""), "BR") - ids(sections["code_spec"].get("6. 规则与异常", ""), "AC")
        if missing_rule_products:
            errors.append(f"Code Spec rules do not consume product IDs: {', '.join(sorted(missing_rule_products))}")
        if ids(docs["architecture"], "API") and "5. 接口与数据实现" not in sections["code_spec"]:
            errors.append("architecture API decisions require Code Spec ## 5. 接口与数据实现")
        if ids(docs["architecture"], "DATA") and "5. 接口与数据实现" not in sections["code_spec"]:
            errors.append("architecture DATA decisions require Code Spec ## 5. 接口与数据实现")
        if (ids(docs["architecture"], "UI") or ids(docs["architecture"], "SHAPE")) and "4. 前端实现" not in sections["code_spec"]:
            errors.append("architecture UI decisions require Code Spec ## 4. 前端实现")
        for heading in ("2. 实现映射", "7. 测试规格", "8. 实现批次"):
            require_ids(sections["code_spec"].get(heading, ""), assurance_ids, f"code-spec.md {heading}", errors)

    if "verification" in docs:
        trace = sections["verification"].get("6. 验收追踪", "")
        required = product.get("AC", set()) | product.get("EX", set()) | rules | tests | batches | assurance_ids
        required |= ids(docs.get("architecture", ""), "CONTRACT") | ids(docs.get("architecture", ""), "SHAPE")
        require_ids(trace, required, "verification.md 验收追踪", errors)
        verdict = stages.get("verification", {}).get("verdict")
        if verdict and verdict not in sections["verification"].get("8. 验收结论", ""):
            errors.append("verification.md 验收结论 does not contain state verdict")
        validate_verification_evidence(
            docs["verification"],
            required | boundary_ids,
            boundary_ids,
            verdict,
            errors,
        )


def report(errors: list[str], warnings: list[str]) -> int:
    for warning in warnings:
        print(f"WARN: {warning}")
    for error in errors:
        print(f"ERROR: {error}")
    if errors:
        print(f"INVALID: {len(errors)} error(s), {len(warnings)} warning(s)")
        return 1
    print(f"VALID: 0 errors, {len(warnings)} warning(s)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    errors: list[str] = []
    warnings: list[str] = []
    if not FEATURE_ID.fullmatch(args.feature_id):
        errors.append("feature-id must use lowercase letters, digits, and single hyphens")
    root = Path(args.root).expanduser().resolve()
    feature_dir = root / "delivery" / args.feature_id
    state_path = feature_dir / "state.md"
    if not state_path.is_file():
        errors.append(f"missing state file: {state_path}")
        return report(errors, warnings)
    state = extract_state(state_path, errors)
    if state is None:
        return report(errors, warnings)
    if state.get("schema_version") != 5:
        errors.append("state.md schema_version must be 5; compatibility with older schemas is intentionally unsupported")
        return report(errors, warnings)
    if state.get("feature_id") != args.feature_id:
        errors.append("state.md feature_id does not match directory/argument")
    if state.get("current_stage") not in STAGES:
        errors.append("invalid current_stage")
    if not isinstance(state.get("blockers"), list):
        errors.append("blockers must be an array")
    stages = state.get("stages")
    if not isinstance(stages, dict):
        errors.append("stages must be an object")
        return report(errors, warnings)
    confirmed_src = validate_requirement_review(state.get("requirement_review"), stages, errors)
    prd_fp = stages.get("prd", {}).get("fingerprint")
    prototype_item = stages.get("prototype", {})
    prototype_fp = prototype_item.get("fingerprint") if prototype_item.get("status") == "completed" else None
    architecture_review = validate_architecture_review(
        state.get("architecture_review"), stages, prd_fp, prototype_fp, errors
    )
    if architecture_review.get("status") != "completed" and (feature_dir / "architecture-design.md").exists():
        errors.append("architecture-design.md must not exist before architecture convergence review approval")

    for name in STAGES:
        item = stages.get(name)
        if not isinstance(item, dict):
            errors.append(f"missing or invalid stage object: {name}")
            continue
        validate_inputs_shape(name, item, errors)
        status = item.get("status")
        if status not in STATUSES:
            errors.append(f"invalid status for {name}: {status!r}")
            continue
        if status == "not_applicable" and name != "prototype":
            errors.append(f"not_applicable is only valid for prototype, not {name}")
        artifact_name = ARTIFACTS.get(name)
        if artifact_name and status == "completed":
            artifact = feature_dir / artifact_name
            if not artifact.is_file() or artifact.stat().st_size == 0:
                errors.append(f"completed stage {name} requires non-empty {artifact_name}")
            else:
                expected, actual = item.get("fingerprint"), digest(artifact)
                if not isinstance(expected, str) or not SHA256.fullmatch(expected):
                    errors.append(f"completed stage {name} requires a lowercase SHA-256 fingerprint")
                elif expected != actual:
                    errors.append(f"fingerprint mismatch for {artifact_name}")

    prereqs = {"architecture": ("prd", "prototype"), "code_spec": ("architecture",), "code": ("code_spec",), "verification": ("code",)}
    for name, required in prereqs.items():
        if stages.get(name, {}).get("status") == "completed":
            for prerequisite in required:
                allowed = {"completed", "not_applicable"} if prerequisite == "prototype" else {"completed"}
                if stages.get(prerequisite, {}).get("status") not in allowed:
                    errors.append(f"completed stage {name} requires {prerequisite} completed")
    validate_completed_inputs(stages, errors)

    prd_path = feature_dir / "prd.md"
    prd_text = prd_path.read_text(encoding="utf-8") if prd_path.is_file() else ""
    prototype = stages.get("prototype", {})
    if prototype.get("status") == "completed":
        validate_prototype_contract(prototype, prd_text, errors)
        if isinstance(prototype.get("contract"), dict) and (feature_dir / "prototype.html").is_file():
            validate_prototype_html(feature_dir / "prototype.html", prototype["contract"], errors)
    if prototype.get("status") == "not_applicable" and (feature_dir / "prototype.html").exists():
        errors.append("prototype.html exists while prototype is not_applicable")

    code = stages.get("code", {})
    if code.get("status") == "completed":
        if code.get("result") is None or code.get("result") == "" or code.get("result") == [] or code.get("result") == {}:
            errors.append("completed code requires a non-empty result")
        validate_simplicity_gate(code, errors)
    verdict = stages.get("verification", {}).get("verdict")
    if verdict not in VERDICTS:
        errors.append("invalid verification verdict")
    if stages.get("verification", {}).get("status") == "completed" and verdict not in {"PASS", "CONDITIONAL"}:
        errors.append("completed verification requires PASS or CONDITIONAL verdict")

    validate_semantics(feature_dir, stages, confirmed_src, architecture_review, errors)
    if feature_dir.is_dir():
        for entry in feature_dir.iterdir():
            if entry.is_file() and entry.name not in ALLOWED_FILES:
                errors.append(f"unexpected feature artifact: {entry.name}")
            elif entry.is_dir():
                errors.append(f"unexpected directory in minimal feature artifact set: {entry.name}/")
    if not state.get("last_updated"):
        warnings.append("state.md has no last_updated timestamp")
    return report(errors, warnings)


if __name__ == "__main__":
    raise SystemExit(main())
