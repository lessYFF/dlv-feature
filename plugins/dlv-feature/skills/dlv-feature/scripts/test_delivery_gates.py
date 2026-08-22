#!/usr/bin/env python3
"""Regression and forward tests for the schema-v9 delivery kernel."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import struct
import sys
import tempfile
import time
import unittest
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import finalize_delivery
import invalidate_downstream
import quality_review
import seal_proof_contract
import upgrade_v7_to_v8
import upgrade_v8_to_v9
import verification_run
from delivery_proof import (
    acquire_windows_lock,
    extract_state,
    evaluate_oracle,
    finalization_token,
    validate_finalization,
    proof_contract_digest,
    resolve_source,
    repository_fingerprint,
    value_digest,
    validate_proof_contract,
    write_state,
)
from validate_feature import validate_database_section, validate_document, validate_v9_gates
from quality_gates import (
    REQUIRED_CHECKS,
    expected_review_coverage,
    proof_contract_draft_digest,
    prototype_decision_digest,
    requirement_review_digest,
    review_artifacts,
    validate_review_context,
    validate_review_payload,
)
from validate_verification_evidence import validate_verification_run
from verification_run import MAX_CAPTURE_BYTES, record, render, run_bounded, start

SCRIPTS = Path(__file__).resolve().parent
ENV_SPEC = {
    "runtime": "postgres",
    "version": "16.4",
    "services": {"redis": "7.2"},
    "preflight": [{"id": "python", "argv": ["python3", "-c", "print('ready')"]}],
}


def init_git(root: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "tests@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "DLV Tests"], cwd=root, check=True)
    (root / "source.txt").write_text("initial\n", encoding="utf-8")
    subprocess.run(["git", "add", "source.txt"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=root, check=True)


def contract() -> dict[str, object]:
    value: dict[str, object] = {
        "status": "completed",
        "code_spec_fingerprint": "c" * 64,
        "environments": [{"id": "ENV-01", "target": "integration stack", "spec": json.loads(json.dumps(ENV_SPEC))}],
        "obligations": [{
            "id": "PO-01",
            "product_ids": ["AC-01"],
            "trace_ids": ["BP-01", "R-D01-1", "T-B01-1", "B01"],
            "proof_type": "boundary",
            "surface": "POST /api/tasks",
            "environment_id": "ENV-01",
            "critical": True,
            "runner": {
                "argv": [
                    "python3", "-c",
                    "from pathlib import Path; print(Path('.dlv/inputs/runtime-observation.json').read_text())",
                ],
                "cwd": ".",
                "observation_adapter": "json_stdout",
            },
            "assertions": [
                {
                    "id": "ASRT-01",
                    "description": "draft result is not counted as completed",
                    "oracle": {"kind": "json_path", "source": "/observation/draft_count", "operator": "eq", "expected": 0},
                },
                {
                    "id": "ASRT-02",
                    "description": "request returns success",
                    "oracle": {"kind": "http_status", "source": "/observation/http_status", "operator": "eq", "expected": 200},
                },
            ],
        }],
        "quality_review": {
            "status": "completed",
            "review_run_id": "code-spec-review-01",
            "artifact_sha256": "c" * 64,
            "proof_contract_sha256": "f" * 64,
            "bound_artifacts": {"code_spec": "c" * 64, "proof_contract": "f" * 64},
            "verdict": "PASS",
            "record_sha256": "d" * 64,
        },
        "sealed_at": "2026-08-21T00:00:00+08:00",
        "seal": None,
    }
    value["seal"] = proof_contract_digest(value)
    return value


def prepare(root: Path, feature_id: str = "kernel-test") -> tuple[Path, Path]:
    init_git(root)
    subprocess.run(
        ["python3", str(SCRIPTS / "init_feature.py"), feature_id, "--root", str(root)],
        check=True, capture_output=True, text=True,
    )
    state_path = root / "delivery" / feature_id / "state.md"
    environment = root / "environment.json"
    environment.write_text(json.dumps(ENV_SPEC), encoding="utf-8")
    content, state = extract_state(state_path)
    state["proof_contract"] = contract()
    (state_path.parent / "proof-contract.json").write_text(
        json.dumps(state["proof_contract"], ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    state["stages"]["code_spec"].update({"status": "completed", "fingerprint": "c" * 64})
    state["stages"]["code"].update({
        "status": "completed",
        "result": {"repository_fingerprint": repository_fingerprint(root, feature_id)},
    })
    write_state(state_path, content, state)
    start(feature_id, root, "run-001", [f"ENV-01={environment}"])
    return state_path, environment


def result_file(root: Path, *, status: str = "passed") -> Path:
    inputs = root / ".dlv" / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    anchor = inputs / f"anchor-{status}.log"
    anchor.write_text(f"observed {status}\n", encoding="utf-8")
    (inputs / "runtime-observation.json").write_text(
        json.dumps({"draft_count": 0 if status == "passed" else 1, "http_status": 200 if status == "passed" else 500}),
        encoding="utf-8",
    )
    value = {
        "po_id": "PO-01",
        "proof_type": "boundary",
        "outcome": "evaluate",
        "anchors": [str(anchor)],
    }
    path = inputs / f"result-{status}.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def png_bytes(red: int, green: int, blue: int) -> bytes:
    def chunk(name: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + name + payload + struct.pack(">I", zlib.crc32(name + payload) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    pixels = zlib.compress(bytes((0, red, green, blue, 255)))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", pixels) + chunk(b"IEND", b"")


def prepare_sealable(root: Path, feature_id: str) -> Path:
    return prepare_approved_delivery(root, feature_id, seal=False)


def prepare_profile_run(root: Path, proof_type: str) -> tuple[Path, Path]:
    feature_id = f"{proof_type}-profile"
    init_git(root)
    subprocess.run([sys.executable, str(SCRIPTS / "init_feature.py"), feature_id, "--root", str(root)], check=True)
    state_path = root / "delivery" / feature_id / "state.md"
    value = contract()
    observation = (
        {"viewport": "1280x720", "dpr": 2, "font_fingerprints": ["font-a"], "pixel_diff_ratio": 0, "geometry_diff_max": 0, "forbidden_elements_count": 0}
        if proof_type == "visual"
        else {"runtime": "api", "action": "create task", "result_readback": {"status": "created"}}
    )
    value["environments"][0]["spec"] = {  # type: ignore[index]
        "runtime": "browser" if proof_type == "visual" else "api",
        "preflight": [{"id": "python", "argv": ["python3", "-c", "print('ready')"]}],
    }
    obligation = value["obligations"][0]  # type: ignore[index]
    obligation["proof_type"] = proof_type
    obligation["runner"] = {
        "argv": ["python3", "-c", f"import json; print(json.dumps({observation!r}))"],
        "cwd": ".",
        "observation_adapter": "visual_bundle" if proof_type == "visual" else "runtime_trace",
    }
    sources = (
        [("pixel", "/observation/pixel_diff_ratio", 0), ("geometry", "/observation/geometry_diff_max", 0), ("forbidden", "/observation/forbidden_elements_count", 0)]
        if proof_type == "visual"
        else [("readback", "/observation/result_readback/status", "created")]
    )
    obligation["assertions"] = [
        {"id": f"ASRT-{index:02d}", "description": label, "oracle": {"kind": "json_path", "source": source, "operator": "eq", "expected": expected}}
        for index, (label, source, expected) in enumerate(sources, 1)
    ]
    value["seal"] = proof_contract_digest(value)
    environment = root / f"{proof_type}-environment.json"
    environment.write_text(json.dumps(value["environments"][0]["spec"]), encoding="utf-8")  # type: ignore[index]
    content, state = extract_state(state_path)
    state["proof_contract"] = value
    (state_path.parent / "proof-contract.json").write_text(json.dumps(value), encoding="utf-8")
    state["stages"]["code_spec"].update({"status": "completed", "fingerprint": "c" * 64})
    state["stages"]["code"].update({"status": "completed", "result": {"repository_fingerprint": repository_fingerprint(root, feature_id)}})
    write_state(state_path, content, state)
    start(feature_id, root, "run-001", [f"ENV-01={environment}"])
    inputs = root / ".dlv" / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    result = inputs / f"{proof_type}-result.json"
    result.write_text(json.dumps({"po_id": "PO-01", "proof_type": proof_type, "outcome": "evaluate", "anchors": []}), encoding="utf-8")
    return state_path, result


PRD_DOCUMENT = """# 最小交付 — 产品需求文档（PRD）

## 目录

- [1. 需求背景与目标](#1-需求背景与目标)
- [2. 范围与约束](#2-范围与约束)
- [3. 功能需求](#3-功能需求)
- [4. 业务流程](#4-业务流程)
- [7. 验收标准](#7-验收标准)
- [9. 风险与待确认事项](#9-风险与待确认事项)
- [10. 需求追踪](#10-需求追踪)

## 1. 需求背景与目标

SRC-01 要求交付一个可以被机器验证的最小行为，目标是让交付状态与真实执行结果一致。

## 2. 范围与约束

- 范围内：验证一个固定输入并返回确定结果。
- 范围外：用户界面和外部系统集成。
- 界面影响: none

## 3. 功能需求

| ID | 要求 |
|---|---|
| FR-01 | 系统读取输入并产生确定结果。 |
| BR-01 | 草稿结果不得计为完成。 |

## 4. 业务流程

1. 调用者提交固定输入。
2. 系统计算并返回结果。
3. 验证器读取结果并裁决。

## 7. 验收标准

| ID | 标准 |
|---|---|
| AC-01 | 执行后草稿计数为零且状态码为成功。 |

## 9. 风险与待确认事项

| 项目 | 结论 |
|---|---|
| 未决问题 | 无未决问题，固定输入已确认。 |

## 10. 需求追踪

| 来源 | 功能 | 业务规则 | 验收 |
|---|---|---|---|
| SRC-01 | FR-01 | BR-01 | AC-01 |
"""


ARCHITECTURE_DOCUMENT = """# 最小交付 — 技术方案

## 目录

- [1. 概述](#1-概述)
- [2. 现状](#2-现状)
- [3. 方案](#3-方案)
- [4. 流程](#4-流程)
- [8. 质量保障](#8-质量保障)
- [9. 影响范围](#9-影响范围)
- [10. 发布与回滚](#10-发布与回滚)
- [11. 需求追踪](#11-需求追踪)

## 1. 概述

- 输入：调用者提供的固定输入。
- 处理：交给现有校验器执行。
- 输出：结构化结果作为唯一事实。

## 2. 现状

| 分析 | 结论 |
|---|---|
| 可复用能力 | 沿用现有校验器。 |
| 事实所有权 | 校验器是结果的正典事实所有者。 |
| API/事务/权限边界 | 现有接口内完成校验，不改变事务与权限边界。 |
| 系统性缺口 | 缺口是缺少确定性结果绑定。 |

## 3. 方案

| ID | 裁决 |
|---|---|
| ARCH-01 | 复用、扩展与新增裁决：复用现有校验器，仅绑定结构化结果。 |
| ALT-01 | 被拒绝方案：拒绝手写通过状态，因为无法证明真实执行。 |
| RULE-01 | 规则分派：唯一分派点是现有校验器。 |

## 4. 流程

FLOW-01 描述固定执行顺序。

```mermaid
flowchart TD
  A[读取输入] --> B[执行校验]
  B --> C[记录结果]
```

## 8. 质量保障

| 维度 | 保障 |
|---|---|
| 正确性 | 结构化断言从执行输出计算，不接受手填结果。 |
| 失败处理 | 任一断言失败即拒绝完成。 |

## 9. 影响范围

| ID | 范围 | 状态 |
|---|---|---|
| IMPACT-01 | 校验器与对应测试 | approved |

## 10. 发布与回滚

1. 先运行完整测试，再发布校验规则。
2. 触发条件命中时恢复上一版本规则。

| 回滚触发 | 动作 |
|---|---|
| 确定性测试失败 | 恢复上一版本并重新执行测试。 |

## 11. 需求追踪

| 产品要求 | 架构 |
|---|---|
| FR-01 BR-01 AC-01 | ARCH-01 FLOW-01 IMPACT-01 |
"""


CODE_SPEC_DOCUMENT = """# 最小交付 — 代码实现规格（Code Spec）

## 目录

- [1. 实现概述](#1-实现概述)
- [2. 实现映射](#2-实现映射)
- [6. 规则与异常](#6-规则与异常)
- [7. 测试规格](#7-测试规格)
- [8. 实现批次](#8-实现批次)
- [9. 变更控制](#9-变更控制)

## 1. 实现概述

按既有校验器模式实现一个批次，并用 Proof Contract 绑定真实执行结果。

## 2. 实现映射

| Domain | 架构 | 影响 | Proof |
|---|---|---|---|
| D01 | ARCH-01 FLOW-01 | IMPACT-01 | PO-01 |

## 6. 规则与异常

| 规则 | 产品输入 | 行为 |
|---|---|---|
| R-D01-1 | FR-01 BR-01 AC-01 | 草稿计数非零时不得完成。 |

## 7. 测试规格

| 测试 | 规则 | Proof | 预期 |
|---|---|---|---|
| T-B01-1 | R-D01-1 | PO-01 | 固定输入返回成功且草稿计数为零。 |

## 8. 实现批次

### B01: 最小确定性行为

#### 目标

完成 R-D01-1 与 AC-01，并由 PO-01 提供执行证据。

#### 架构锚点

- ARCH-01

#### 仓库与基线

- 当前仓库的已提交基线。

#### 候选路径

- source.txt

#### 源码必读

- source.txt

#### 测试/配置必读

- 本测试文件中的交付门回归测试。

#### 允许修改

- source.txt

#### 排除范围

- 不修改外部系统。

#### 依赖深度

1

#### 测试与完成条件

- T-B01-1 与 PO-01 必须通过，B01 才完成。

## 9. 变更控制

| 变化 | 处理 |
|---|---|
| ARCH-01 或 AC-01 改变 | 重新审查 Code Spec 并重跑 PO-01。 |
"""


def run_delivery_cli(root: Path, script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        [sys.executable, str(SCRIPTS / script), *arguments, "--root", str(root)],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stdout + completed.stderr)
    return completed


def review_checks(
    review_type: str, *, prototype: bool = False,
    coverage: dict[str, set[str]] | None = None,
) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    for check_id in sorted(REQUIRED_CHECKS[review_type]):
        value: dict[str, object] = {
            "id": check_id,
            "status": "PASS",
            "evidence": f"fixture evidence for {check_id}",
        }
        if check_id.endswith("coverage"):
            if "prototype" in check_id and not prototype:
                value["status"] = "N/A"
                value["not_applicable_reason"] = "fixture has no visible UI prototype"
            else:
                value["coverage_pct"] = 100
                value["covered_ids"] = sorted((coverage or {}).get(check_id, set()))
        if check_id == "unmapped-changes":
            value["unmapped_count"] = 0
        checks.append(value)
    return checks


def review_result_payload(review_type: str, checks: list[dict[str, object]]) -> dict[str, object]:
    return {
        "review_type": review_type,
        "reviewer": "independent-test-reviewer",
        "review_reference": f"fresh-context:{review_type}",
        "execution": {
            "mode": "fresh_context", "provider": "test-runner",
            "invocation_id": f"{review_type}-invocation",
            "transcript_sha256": hashlib.sha256(review_type.encode()).hexdigest(),
        },
        "verdict": "PASS", "findings": [], "checks": checks,
    }


def test_review_execution(root: Path, feature_id: str, run_id: str) -> dict[str, str]:
    invocation_id = f"invocation-{run_id}"
    transcript = root / ".dlv" / "reviews" / feature_id / f"{run_id}.{invocation_id}.transcript.jsonl"
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text(json.dumps({"event": "isolated-test-review", "run_id": run_id}) + "\n", encoding="utf-8")
    return {
        "mode": "isolated_process", "provider": "test-runner", "invocation_id": invocation_id,
        "transcript_path": transcript.relative_to(root).as_posix(),
        "transcript_sha256": hashlib.sha256(transcript.read_bytes()).hexdigest(),
    }


def record_test_review(root: Path, feature_id: str, review_type: str, run_id: str, *, prototype: bool = False) -> None:
    review_dir = root / ".dlv" / "inputs"
    review_dir.mkdir(parents=True, exist_ok=True)
    result = review_dir / f"{run_id}.json"
    _, state = extract_state(root / "delivery" / feature_id / "state.md")
    payload = review_result_payload(
        review_type,
        review_checks(review_type, prototype=prototype, coverage=expected_review_coverage(root / "delivery" / feature_id, review_type, state)),
    )
    payload["review_reference"] = f"fresh-context:{run_id}"
    payload["execution"]["invocation_id"] = run_id  # type: ignore[index]
    result.write_text(json.dumps(payload), encoding="utf-8")
    quality_review._record_review(
        feature_id, root, review_type, run_id, result,
        execution=test_review_execution(root, feature_id, run_id),
        reviewed_artifacts=review_artifacts(root, feature_id, review_type, state),
    )


def prepare_product_review(root: Path, feature_id: str) -> Path:
    init_git(root)
    run_delivery_cli(root, "init_feature.py", feature_id)
    state_path = root / "delivery" / feature_id / "state.md"
    content, state = extract_state(state_path)
    state["requirement_review"].update({
        "status": "in_progress",
        "source_fingerprint": "b" * 64,
        "confirmed_ids": ["SRC-01"],
        "summary": {
            "goal": "machine-owned review",
            "users_scenarios": "delivery owner runs an isolated review",
            "in_scope": "review binding",
            "out_scope": "external attestation",
            "key_rules": "callers cannot submit verdict JSON",
            "ui_impact": "none",
            "open_questions": "none",
        },
    })
    state["stages"]["prd"]["status"] = "in_progress"
    write_state(state_path, content, state)
    (state_path.parent / "prd.md").write_text(PRD_DOCUMENT, encoding="utf-8")
    return state_path


def prepare_approved_delivery(root: Path, feature_id: str, *, seal: bool = True) -> Path:
    init_git(root)
    run_delivery_cli(root, "init_feature.py", feature_id)
    state_path = root / "delivery" / feature_id / "state.md"
    content, state = extract_state(state_path)
    state["requirement_review"].update({
        "status": "in_progress",
        "source_fingerprint": "b" * 64,
        "confirmed_ids": ["SRC-01"],
        "summary": {
            "goal": "machine-verified delivery",
            "users_scenarios": "delivery owner runs one deterministic check",
            "in_scope": "fixed input validation",
            "out_scope": "user interface and integrations",
            "key_rules": "draft results never count as complete",
            "ui_impact": "none",
            "open_questions": "no open questions",
        },
    })
    state["stages"]["prd"]["status"] = "in_progress"
    write_state(state_path, content, state)
    (state_path.parent / "prd.md").write_text(PRD_DOCUMENT, encoding="utf-8")
    record_test_review(root, feature_id, "product", "product-review-01")

    (state_path.parent / "architecture-design.md").write_text(ARCHITECTURE_DOCUMENT, encoding="utf-8")
    content, state = extract_state(state_path)
    prd_sha = state["stages"]["prd"]["fingerprint"]
    state["stages"]["architecture"]["inputs"] = {"prd": prd_sha, "prototype": None, "repositories": {}}
    state["architecture_review"].update({
        "status": "in_progress",
        "inputs": {"prd": prd_sha, "prototype": None, "repositories": {}},
        "existing_capabilities": ["existing deterministic validator"],
        "fact_owners": [{
            "id": "FACT-01", "fact": "validation outcome", "canonical_owner": "validator",
            "snapshot_or_reference": "reference", "lifecycle": "one run",
            "forbidden_duplicates": "handwritten pass state", "evidence": "source.txt",
        }],
        "additions": [],
        "api_decisions": [],
        "isolation": {"applicable": False, "verdict": "N/A"},
        "concurrency": {"applicable": False, "verdict": "N/A"},
        "rule_variants": {"applicable": False, "verdict": "N/A"},
        "boundary_proofs": {"applicable": False, "reason": "No access boundary changes", "proofs": [], "verdict": "N/A"},
        "material_decisions": [],
        "reviewed_at": None,
    })
    state["stages"]["architecture"]["status"] = "in_progress"
    write_state(state_path, content, state)
    record_test_review(root, feature_id, "architecture", "architecture-review-01")

    (state_path.parent / "code-spec.md").write_text(CODE_SPEC_DOCUMENT, encoding="utf-8")
    content, state = extract_state(state_path)
    state["stages"]["code_spec"]["inputs"] = {
        "prd": state["stages"]["prd"]["fingerprint"],
        "architecture": state["stages"]["architecture"]["fingerprint"],
        "repositories": {},
    }
    draft = contract()
    draft["obligations"][0]["trace_ids"] = ["ARCH-01", "FLOW-01", "R-D01-1", "T-B01-1", "B01"]  # type: ignore[index]
    draft.update({"status": "pending", "code_spec_fingerprint": None, "quality_review": None, "sealed_at": None, "seal": None})
    state["proof_contract"] = draft
    state["stages"]["code_spec"]["status"] = "in_progress"
    write_state(state_path, content, state)
    record_test_review(root, feature_id, "code_spec", "code-spec-review-01")
    if seal:
        run_delivery_cli(root, "seal_proof_contract.py", feature_id)
    return state_path


class ContractTests(unittest.TestCase):
    def test_three_automated_quality_reviews_execute_end_to_end_without_approvals(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_approved_delivery(root, "approval-workflow")
            _, state = extract_state(state_path)
            self.assertEqual("completed", state["requirement_review"]["status"])
            self.assertEqual("completed", state["stages"]["prd"]["status"])
            self.assertEqual("not_applicable", state["stages"]["prototype"]["status"])
            self.assertEqual("PASS", state["quality_reviews"]["product"]["verdict"])
            self.assertEqual("PASS", state["quality_reviews"]["architecture"]["verdict"])
            self.assertEqual("completed", state["stages"]["architecture"]["status"])
            self.assertEqual("PASS", state["quality_reviews"]["code_spec"]["verdict"])
            self.assertEqual("completed", state["stages"]["code_spec"]["status"])
            self.assertEqual("code", state["current_stage"])
            self.assertNotIn("approvals", state)
            self.assertEqual(state["quality_reviews"]["code_spec"], state["proof_contract"]["quality_review"])
            self.assertEqual("completed", state["proof_contract"]["status"])

    def test_quality_review_rejects_feature_id_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = root / "review.json"
            result.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "feature-id"):
                quality_review._record_review(
                    "../escape", root, "architecture", "review-01", result,
                    execution={}, reviewed_artifacts={},
                )

    def test_product_completion_without_quality_review_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run([sys.executable, str(SCRIPTS / "init_feature.py"), "approval-gate", "--root", str(root)], check=True)
            state_path = root / "delivery/approval-gate/state.md"
            content, state = extract_state(state_path)
            state["requirement_review"] = {
                "status": "completed",
                "source_fingerprint": "b" * 64,
                "confirmed_ids": ["SRC-01"],
                "summary": {"goal": "goal"},
                "reviewed_at": "2026-08-21T00:00:00+08:00",
            }
            write_state(state_path, content, state)
            errors: list[str] = []
            validate_v9_gates(root, "approval-gate", state_path.parent, state, errors)
            self.assertTrue(any("completed product requires a quality review" in error for error in errors))

    def test_product_review_is_bound_to_exact_prd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_approved_delivery(root, "product-binding")
            (state_path.parent / "prd.md").write_text(PRD_DOCUMENT + "\nchanged\n", encoding="utf-8")
            _, state = extract_state(state_path)
            errors: list[str] = []
            validate_v9_gates(root, "product-binding", state_path.parent, state, errors)
            self.assertTrue(any("product is stale" in error for error in errors), errors)

    def test_quality_review_cannot_pass_with_open_major_finding(self) -> None:
        errors: list[str] = []
        validate_review_payload({
            "review_type": "architecture", "review_run_id": "architecture-review-01",
            "reviewer": "reviewer", "review_reference": "review-1", "reviewed_at": "now",
            "execution": {"mode": "fresh_context", "provider": "test-runner", "invocation_id": "review-1", "transcript_sha256": "e" * 64},
            "verdict": "PASS", "artifact_sha256": "a" * 64,
            "bound_artifacts": {"architecture": "a" * 64},
            "checks": review_checks("architecture"),
            "findings": [{"id": "ARQ-1", "severity": "major", "status": "open", "statement": "unsafe write path", "evidence": "architecture-design.md"}],
        }, "architecture", errors)
        self.assertTrue(any("cannot PASS" in error for error in errors))

    def test_windows_lock_retries_until_the_long_running_owner_releases(self) -> None:
        attempts = 0

        def fake_locking(_fd: int, _mode: int, _size: int) -> None:
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise OSError(13, "permission denied")

        with patch("delivery_proof.time.sleep", return_value=None):
            acquire_windows_lock(fake_locking, 7, 1)
        self.assertEqual(3, attempts)

    def test_valid_structured_contract_passes(self) -> None:
        errors: list[str] = []
        obligations = validate_proof_contract(contract(), {"AC-01"}, "c" * 64, False, errors)
        self.assertEqual([], errors)
        self.assertEqual({"PO-01"}, set(obligations))

    def test_contract_mutation_breaks_seal(self) -> None:
        value = contract()
        value["obligations"][0]["assertions"][0]["oracle"]["expected"] = 99  # type: ignore[index]
        errors: list[str] = []
        validate_proof_contract(value, {"AC-01"}, "c" * 64, False, errors)
        self.assertTrue(any("seal" in error for error in errors))

    def test_all_sealed_metadata_is_covered_by_the_seal(self) -> None:
        mutations = {
            "status": "stale",
            "sealed_at": "2099-01-01T00:00:00Z",
            "quality_review": {"verdict": "PASS", "record_sha256": "0" * 64},
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                value = contract()
                value[field] = replacement
                errors: list[str] = []
                validate_proof_contract(value, {"AC-01"}, "c" * 64, False, errors)
                self.assertTrue(any("seal" in error for error in errors), errors)

    def test_every_oracle_operator_has_deterministic_semantics(self) -> None:
        cases = [
            (2, {"operator": "ne", "expected": 1}),
            ([1, 2], {"operator": "contains", "expected": 2}),
            ("abc", {"operator": "not_contains", "expected": "z"}),
            ("abc123", {"operator": "matches", "expected": r"\d+"}),
            (None, {"operator": "exists"}),
            (2, {"operator": "lte", "expected": 3}),
            (3, {"operator": "gte", "expected": 2}),
        ]
        for actual, oracle in cases:
            with self.subTest(operator=oracle["operator"]):
                self.assertTrue(evaluate_oracle(actual, oracle))

    def test_absent_distinguishes_missing_path_from_explicit_null(self) -> None:
        missing = resolve_source({"observation": {}}, "/observation/secret")
        explicit_null = resolve_source({"observation": {"secret": None}}, "/observation/secret")
        self.assertTrue(evaluate_oracle(missing, {"operator": "absent"}))
        self.assertFalse(evaluate_oracle(explicit_null, {"operator": "absent"}))
        self.assertTrue(evaluate_oracle(explicit_null, {"operator": "exists"}))

    def test_free_text_expected_cannot_replace_assertions(self) -> None:
        value = contract()
        obligation = value["obligations"][0]  # type: ignore[index]
        obligation["expected"] = "looks good"
        obligation["assertions"] = []
        value["seal"] = proof_contract_digest(value)
        errors: list[str] = []
        validate_proof_contract(value, {"AC-01"}, "c" * 64, False, errors)
        self.assertTrue(any("assertions" in error for error in errors))

    def test_visual_prototype_requires_visual_obligation(self) -> None:
        errors: list[str] = []
        validate_proof_contract(contract(), {"AC-01"}, "c" * 64, True, errors)
        self.assertTrue(any("visual proof" in error for error in errors))

    def test_visual_proof_rejects_build_runtime_and_generic_adapter(self) -> None:
        value = contract()
        value["environments"][0]["spec"]["runtime"] = "node-build"  # type: ignore[index]
        obligation = value["obligations"][0]  # type: ignore[index]
        obligation["proof_type"] = "visual"
        errors: list[str] = []
        validate_proof_contract(value, {"AC-01"}, "c" * 64, False, errors)
        self.assertTrue(any("visual proof requires" in error for error in errors))
        self.assertTrue(any("observation_adapter" in error for error in errors))

    def test_runtime_proof_requires_target_runtime_and_readback(self) -> None:
        value = contract()
        value["environments"][0]["spec"]["runtime"] = "node-build"  # type: ignore[index]
        obligation = value["obligations"][0]  # type: ignore[index]
        obligation["proof_type"] = "runtime"
        errors: list[str] = []
        validate_proof_contract(value, {"AC-01"}, "c" * 64, False, errors)
        self.assertTrue(any("build-only runtime" in error for error in errors))
        self.assertTrue(any("result_readback" in error for error in errors))

    def test_node_target_runtime_is_distinct_from_node_build(self) -> None:
        value = contract()
        value["environments"][0]["spec"]["runtime"] = "node"  # type: ignore[index]
        obligation = value["obligations"][0]  # type: ignore[index]
        obligation["proof_type"] = "runtime"
        obligation["runner"]["observation_adapter"] = "runtime_trace"
        obligation["assertions"] = [{
            "id": "ASRT-01", "description": "result is read back",
            "oracle": {"kind": "state", "source": "/observation/result_readback", "operator": "eq", "expected": {"status": "created"}},
        }]
        value["seal"] = proof_contract_digest(value)
        errors: list[str] = []
        validate_proof_contract(value, {"AC-01"}, "c" * 64, False, errors)
        self.assertEqual([], errors)

    def test_visual_contract_requires_exact_zero_difference(self) -> None:
        value = contract()
        value["environments"][0]["spec"]["runtime"] = "browser"  # type: ignore[index]
        obligation = value["obligations"][0]  # type: ignore[index]
        obligation["proof_type"] = "visual"
        obligation["runner"]["observation_adapter"] = "visual_bundle"
        obligation["assertions"] = [
            {"id": "ASRT-01", "description": "pixel", "oracle": {"kind": "json_path", "source": "/observation/pixel_diff_ratio", "operator": "lte", "expected": 0.01}},
            {"id": "ASRT-02", "description": "geometry", "oracle": {"kind": "json_path", "source": "/observation/geometry_diff_max", "operator": "eq", "expected": 0}},
            {"id": "ASRT-03", "description": "forbidden", "oracle": {"kind": "json_path", "source": "/observation/forbidden_elements_count", "operator": "eq", "expected": 0}},
        ]
        value["seal"] = proof_contract_digest(value)
        errors: list[str] = []
        validate_proof_contract(value, {"AC-01"}, "c" * 64, True, errors)
        self.assertTrue(any("pixel_diff_ratio" in error and "exact zero" in error for error in errors), errors)

    def test_preflight_check_id_cannot_escape_run_directory(self) -> None:
        value = contract()
        value["environments"][0]["spec"]["preflight"][0]["id"] = "../../escape"  # type: ignore[index]
        value["seal"] = proof_contract_digest(value)
        errors: list[str] = []
        validate_proof_contract(value, {"AC-01"}, "c" * 64, False, errors)
        self.assertTrue(any("requires id and argv" in error for error in errors))

    def test_seal_command_is_one_way(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_sealable(root, "seal-test")
            command = [
                "python3", str(SCRIPTS / "seal_proof_contract.py"), "seal-test", "--root", str(root),
            ]
            first = subprocess.run(command, capture_output=True, text=True)
            second = subprocess.run(command, capture_output=True, text=True)
            _, sealed = extract_state(state_path)
            self.assertEqual(0, first.returncode, first.stdout + first.stderr)
            self.assertNotEqual(0, second.returncode)
            self.assertEqual(proof_contract_digest(sealed["proof_contract"]), sealed["proof_contract"]["seal"])

    def test_seal_recovers_an_orphaned_snapshot_and_serializes_concurrent_writers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_sealable(root, "seal-recovery")
            _, state = extract_state(state_path)
            orphan = json.loads(json.dumps(state["proof_contract"]))
            review = state["quality_reviews"]["code_spec"]
            orphan.update({
                "status": "completed",
                "code_spec_fingerprint": review["artifact_sha256"],
                "quality_review": dict(review),
                "sealed_at": "2026-08-21T00:00:00+08:00",
            })
            orphan["seal"] = proof_contract_digest(orphan)
            (state_path.parent / "proof-contract.json").write_text(json.dumps(orphan), encoding="utf-8")
            recovered = seal_proof_contract.seal_contract("seal-recovery", root)
            _, updated = extract_state(state_path)
            self.assertEqual(orphan["seal"], recovered)
            self.assertEqual(orphan, updated["proof_contract"])
            self.assertEqual("completed", updated["stages"]["code_spec"]["status"])
            self.assertEqual("code", updated["current_stage"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_sealable(root, "seal-concurrent")

            def attempt(_reference: str) -> str:
                try:
                    return seal_proof_contract.seal_contract("seal-concurrent", root)
                except ValueError:
                    return "rejected"

            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(executor.map(attempt, ("approval-a", "approval-b")))
            artifact = json.loads((state_path.parent / "proof-contract.json").read_text())
            _, updated = extract_state(state_path)
            self.assertEqual(1, outcomes.count("rejected"))
            self.assertEqual(artifact, updated["proof_contract"])


class AutomatedQualityReviewTests(unittest.TestCase):
    def payload(self, review_type: str) -> dict[str, object]:
        return {
            "review_type": review_type, "review_run_id": f"{review_type.replace('_', '-')}-review-01",
            "reviewer": "independent-reviewer", "review_reference": "fresh-context",
            "execution": {"mode": "fresh_context", "provider": "test-runner", "invocation_id": "review-01", "transcript_sha256": "e" * 64},
            "reviewed_at": "2026-08-21T00:00:00+08:00", "verdict": "PASS",
            "artifact_sha256": "a" * 64, "proof_contract_sha256": "b" * 64,
            "bound_artifacts": {"artifact": "a" * 64}, "findings": [],
            "checks": review_checks(review_type),
        }

    def test_required_checks_cannot_be_omitted(self) -> None:
        payload = self.payload("architecture")
        payload["checks"] = payload["checks"][:-1]  # type: ignore[index]
        errors: list[str] = []
        validate_review_payload(payload, "architecture", errors)
        self.assertTrue(any("missing required checks" in error for error in errors), errors)

    def test_coverage_cannot_pass_below_one_hundred_percent(self) -> None:
        payload = self.payload("product")
        check = next(item for item in payload["checks"] if item["id"] == "source-coverage")  # type: ignore[index]
        check["coverage_pct"] = 99
        errors: list[str] = []
        validate_review_payload(payload, "product", errors)
        self.assertTrue(any("coverage_pct must be 100" in error for error in errors), errors)

    def test_failed_required_check_blocks_pass(self) -> None:
        payload = self.payload("architecture")
        payload["checks"][0]["status"] = "FAIL"  # type: ignore[index]
        errors: list[str] = []
        validate_review_payload(payload, "architecture", errors)
        self.assertTrue(any("cannot PASS with failed checks" in error for error in errors), errors)

    def test_not_applicable_check_requires_reason(self) -> None:
        payload = self.payload("product")
        check = next(item for item in payload["checks"] if item["id"] == "prototype-state-coverage")  # type: ignore[index]
        check.pop("not_applicable_reason")
        errors: list[str] = []
        validate_review_payload(payload, "product", errors)
        self.assertTrue(any("not_applicable_reason" in error for error in errors), errors)

    def test_existing_prototype_cannot_be_skipped_as_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            feature_dir = Path(temporary)
            (feature_dir / "prototype.html").write_text("<html></html>", encoding="utf-8")
            payload = self.payload("product")
            errors: list[str] = []
            validate_review_context(payload, "product", feature_dir, errors)
            self.assertTrue(any("cannot be N/A" in error for error in errors), errors)

    def test_applicable_architecture_risks_cannot_be_skipped_as_not_applicable(self) -> None:
        cases = {
            "database-risk": {"additions": [{"type": "table"}]},
            "api-compatibility": {"api_decisions": [{"id": "API-01"}]},
            "authorization-and-isolation": {"isolation": {"applicable": True}},
        }
        for check_id, review_update in cases.items():
            with self.subTest(check_id=check_id), tempfile.TemporaryDirectory() as temporary:
                payload = self.payload("architecture")
                check = next(item for item in payload["checks"] if item["id"] == check_id)  # type: ignore[index]
                check.update({"status": "N/A", "not_applicable_reason": "incorrect skip"})
                state = {"architecture_review": review_update}
                errors: list[str] = []
                validate_review_context(payload, "architecture", Path(temporary), errors, state)
                self.assertTrue(any(check_id in error and "cannot be N/A" in error for error in errors), errors)

    def test_pass_that_fails_intermediate_validation_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            init_git(root)
            run_delivery_cli(root, "init_feature.py", "invalid-product-pass")
            state_path = root / "delivery/invalid-product-pass/state.md"
            content, state = extract_state(state_path)
            state["requirement_review"].update({
                "status": "in_progress", "source_fingerprint": "b" * 64,
                "confirmed_ids": ["SRC-01"],
                "summary": {"goal": "goal", "users_scenarios": "scenario", "in_scope": "scope", "out_scope": "none", "key_rules": "rules", "ui_impact": "none", "open_questions": "none"},
            })
            state["stages"]["prd"]["status"] = "in_progress"
            write_state(state_path, content, state)
            (state_path.parent / "prd.md").write_text("# malformed\n", encoding="utf-8")
            result = root / "product-review.json"
            coverage = expected_review_coverage(state_path.parent, "product", state)
            result.write_text(json.dumps(review_result_payload("product", review_checks("product", coverage=coverage))), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "failed intermediate validation"):
                quality_review._record_review(
                    "invalid-product-pass", root, "product", "product-review-01", result,
                    execution=test_review_execution(root, "invalid-product-pass", "product-review-01"),
                    reviewed_artifacts=review_artifacts(root, "invalid-product-pass", "product", state),
                )
            _, rolled_back = extract_state(state_path)
            self.assertEqual("in_progress", rolled_back["stages"]["prd"]["status"])
            self.assertIsNone(rolled_back["quality_reviews"]["product"])
            self.assertFalse((root / ".dlv/reviews/invalid-product-pass/product-review-01.json").exists())

    def test_isolated_runner_owns_result_identity_and_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_product_review(root, "isolated-runner")
            state = extract_state(state_path)[1]
            response = review_result_payload(
                "product",
                review_checks("product", coverage=expected_review_coverage(state_path.parent, "product", state)),
            )
            real_run = subprocess.run

            def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                if command[0] != "codex":
                    return real_run(command, **kwargs)
                self.assertIn("--ephemeral", command)
                self.assertEqual("read-only", command[command.index("--sandbox") + 1])
                output = Path(command[command.index("--output-last-message") + 1])
                output.write_text(json.dumps(response), encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, '{"type":"review.completed"}\n', "")

            with patch("quality_review.subprocess.run", side_effect=fake_run):
                record_path = quality_review.run_isolated_review(
                    "isolated-runner", root, "product", "product-isolated-01",
                )
            record_payload = json.loads(record_path.read_text(encoding="utf-8"))
            execution = record_payload["execution"]
            transcript = root / execution["transcript_path"]
            self.assertEqual("codex-exec", record_payload["reviewer"])
            self.assertEqual(execution["invocation_id"], record_payload["review_reference"])
            self.assertTrue(transcript.is_file())
            self.assertEqual(hashlib.sha256(transcript.read_bytes()).hexdigest(), execution["transcript_sha256"])

    def test_public_isolated_runner_rejects_path_traversal_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch("quality_review.subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "feature-id"):
                    quality_review.run_isolated_review("../escape", root, "product", "product-review-01")
                with self.assertRaisesRegex(ValueError, "review-run-id"):
                    quality_review.run_isolated_review("feature-id", root, "product", "../../escape")
                with self.assertRaisesRegex(ValueError, "review_type"):
                    quality_review.run_isolated_review("feature-id", root, "unknown", "product-review-01")
                run.assert_not_called()

    def test_isolated_runner_rejects_relocated_review_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as external:
            root = Path(temporary)
            prepare_product_review(root, "review-symlink")
            reviews = root / ".dlv/reviews"
            reviews.parent.mkdir(parents=True, exist_ok=True)
            reviews.symlink_to(Path(external), target_is_directory=True)
            with patch("quality_review.subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "escapes the project root|relocated through a symlink"):
                    quality_review.run_isolated_review(
                        "review-symlink", root, "product", "product-review-01",
                    )
                run.assert_not_called()

    def test_snapshot_digest_rejects_aba_before_reviewer_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_product_review(root, "snapshot-aba")
            prd = state_path.parent / "prd.md"
            original = prd.read_text(encoding="utf-8")
            real_copy = shutil.copy2

            def racing_copy(source: Path, target: Path) -> Path:
                if Path(source).resolve() == prd.resolve():
                    prd.write_text(original + "\nintermediate B\n", encoding="utf-8")
                    copied = real_copy(source, target)
                    prd.write_text(original, encoding="utf-8")
                    return Path(copied)
                return Path(real_copy(source, target))

            with (
                patch("quality_review.shutil.copy2", side_effect=racing_copy),
                patch("quality_review.subprocess.run") as run,
            ):
                with self.assertRaisesRegex(ValueError, "immutable snapshot"):
                    quality_review.run_isolated_review(
                        "snapshot-aba", root, "product", "product-review-01",
                    )
                run.assert_not_called()

    def test_snapshot_presence_rejects_delete_restore_aba(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_product_review(root, "snapshot-presence")
            prd = state_path.parent / "prd.md"
            original = prd.read_text(encoding="utf-8")
            real_copy = shutil.copy2

            def delete_restore_copy(source: Path, target: Path) -> Path:
                if Path(source).resolve() == prd.resolve():
                    prd.unlink()
                    prd.write_text(original, encoding="utf-8")
                    return Path(target)
                return Path(real_copy(source, target))

            with (
                patch("quality_review.shutil.copy2", side_effect=delete_restore_copy),
                patch("quality_review.subprocess.run") as run,
            ):
                with self.assertRaisesRegex(ValueError, "input presence changed"):
                    quality_review.run_isolated_review(
                        "snapshot-presence", root, "product", "product-review-01",
                    )
                run.assert_not_called()

    def test_final_rehash_rolls_back_late_review_input_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_product_review(root, "late-review-race")
            state = extract_state(state_path)[1]
            result = root / "product-review.json"
            result.write_text(json.dumps(review_result_payload(
                "product",
                review_checks("product", coverage=expected_review_coverage(state_path.parent, "product", state)),
            )), encoding="utf-8")
            reviewed = review_artifacts(root, "late-review-race", "product", state)
            prd = state_path.parent / "prd.md"

            def validation_then_change(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
                prd.write_text(PRD_DOCUMENT + "\nlate change\n", encoding="utf-8")
                return subprocess.CompletedProcess([], 0, "VALID INTERMEDIATE\n", "")

            with patch("quality_review.subprocess.run", side_effect=validation_then_change):
                with self.assertRaisesRegex(ValueError, "changed during final validation"):
                    quality_review._record_review(
                        "late-review-race", root, "product", "product-review-01", result,
                        execution=test_review_execution(root, "late-review-race", "product-review-01"),
                        reviewed_artifacts=reviewed,
                    )
            rolled_back = extract_state(state_path)[1]
            self.assertIsNone(rolled_back["quality_reviews"]["product"])
            self.assertEqual("in_progress", rolled_back["stages"]["prd"]["status"])

    def test_isolated_runner_rejects_inputs_changed_during_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_product_review(root, "review-race")
            state = extract_state(state_path)[1]
            response = review_result_payload(
                "product",
                review_checks("product", coverage=expected_review_coverage(state_path.parent, "product", state)),
            )

            def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                output = Path(command[command.index("--output-last-message") + 1])
                output.write_text(json.dumps(response), encoding="utf-8")
                (state_path.parent / "prd.md").write_text(PRD_DOCUMENT + "\nchanged\n", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "review transcript\n", "")

            with patch("quality_review.subprocess.run", side_effect=fake_run):
                with self.assertRaisesRegex(ValueError, "inputs changed during"):
                    quality_review.run_isolated_review("review-race", root, "product", "product-race-01")
            self.assertFalse((root / ".dlv/reviews/review-race/product-race-01.json").exists())
            self.assertEqual([], list((root / ".dlv/reviews/review-race").glob("product-race-01.*.transcript.jsonl")))

    def test_duplicate_run_cleanup_preserves_winning_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_product_review(root, "duplicate-run")
            state = extract_state(state_path)[1]
            response = review_result_payload(
                "product",
                review_checks("product", coverage=expected_review_coverage(state_path.parent, "product", state)),
            )
            real_run = subprocess.run

            def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                if command[0] != "codex":
                    return real_run(command, **kwargs)
                output = Path(command[command.index("--output-last-message") + 1])
                output.write_text(json.dumps(response), encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "review transcript\n", "")

            with (
                patch("quality_review.subprocess.run", side_effect=fake_run),
                patch("quality_review.secrets.token_hex", side_effect=["a" * 32, "b" * 32]),
            ):
                record_path = quality_review.run_isolated_review(
                    "duplicate-run", root, "product", "product-duplicate-01",
                )
                winning = root / json.loads(record_path.read_text(encoding="utf-8"))["execution"]["transcript_path"]
                with self.assertRaisesRegex(ValueError, "review run already exists"):
                    quality_review.run_isolated_review(
                        "duplicate-run", root, "product", "product-duplicate-01",
                    )
            self.assertTrue(winning.is_file())
            losing = root / ".dlv/reviews/duplicate-run" / f"product-duplicate-01.review-{'b' * 32}.transcript.jsonl"
            self.assertFalse(losing.exists())

    def test_quality_review_cli_rejects_caller_supplied_result(self) -> None:
        result = subprocess.run(
            [
                sys.executable, str(SCRIPTS / "quality_review.py"), "product", "feature-id",
                "--run-id", "product-review-01", "--result", "/tmp/forged-pass.json",
            ],
            capture_output=True, text=True,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("unrecognized arguments: --result", result.stderr)

    def test_transcript_tampering_invalidates_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_approved_delivery(root, "transcript-tamper")
            transcript = next((root / ".dlv/reviews/transcript-tamper").glob("product-review-01.*.transcript.jsonl"))
            transcript.write_text("tampered\n", encoding="utf-8")
            validation = subprocess.run(
                [sys.executable, str(SCRIPTS / "validate_feature.py"), "transcript-tamper", "--root", str(root)],
                capture_output=True, text=True,
            )
            self.assertNotEqual(0, validation.returncode)
            self.assertIn("transcript hash is stale", validation.stdout + validation.stderr)
            self.assertTrue(state_path.is_file())

    def test_transcript_tampering_invalidates_review_and_downstream(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_approved_delivery(root, "transcript-invalidate")
            transcript = next((root / ".dlv/reviews/transcript-invalidate").glob("product-review-01.*.transcript.jsonl"))
            transcript.write_text("tampered\n", encoding="utf-8")
            message = invalidate_downstream.invalidate(root, "transcript-invalidate", None)
            self.assertIn("stale from prd", message)
            invalidated = extract_state(state_path)[1]
            self.assertEqual({"product": None, "architecture": None, "code_spec": None}, invalidated["quality_reviews"])

    def test_review_run_ids_are_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_approved_delivery(root, "immutable-review")
            record = root / ".dlv/reviews/immutable-review/product-review-01.json"
            payload = root / "duplicate.json"
            duplicate = json.loads(record.read_text(encoding="utf-8"))
            execution = duplicate["execution"]
            for field in ("review_run_id", "reviewed_at", "artifact_sha256", "proof_contract_sha256", "bound_artifacts"):
                duplicate.pop(field, None)
            payload.write_text(json.dumps(duplicate), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "already exists"):
                quality_review._record_review(
                    "immutable-review", root, "product", "product-review-01", payload,
                    execution=execution,
                    reviewed_artifacts=review_artifacts(root, "immutable-review", "product", extract_state(state_path)[1]),
                )
            self.assertTrue(state_path.is_file())

    def test_review_invocation_id_cannot_be_reused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_product_review(root, "invocation-reuse")
            state = extract_state(state_path)[1]
            result = root / "product-review.json"
            result.write_text(json.dumps(review_result_payload(
                "product",
                review_checks("product", coverage=expected_review_coverage(state_path.parent, "product", state)),
            )), encoding="utf-8")
            invocation_id = "shared-invocation"
            transcript_dir = root / ".dlv/reviews/invocation-reuse"
            transcript_dir.mkdir(parents=True, exist_ok=True)
            first_transcript = transcript_dir / f"product-review-01.{invocation_id}.transcript.jsonl"
            first_transcript.write_text("first\n", encoding="utf-8")
            execution = {
                "mode": "isolated_process", "provider": "test-runner", "invocation_id": invocation_id,
                "transcript_path": first_transcript.relative_to(root).as_posix(),
                "transcript_sha256": hashlib.sha256(first_transcript.read_bytes()).hexdigest(),
            }
            snapshot = review_artifacts(root, "invocation-reuse", "product", state)
            quality_review._record_review(
                "invocation-reuse", root, "product", "product-review-01", result,
                execution=execution, reviewed_artifacts=snapshot,
            )
            current_state = extract_state(state_path)[1]
            second_transcript = transcript_dir / f"product-review-02.{invocation_id}.transcript.jsonl"
            second_transcript.write_text("second\n", encoding="utf-8")
            reused_execution = dict(execution)
            reused_execution.update({
                "transcript_path": second_transcript.relative_to(root).as_posix(),
                "transcript_sha256": hashlib.sha256(second_transcript.read_bytes()).hexdigest(),
            })
            with self.assertRaisesRegex(ValueError, "invocation_id cannot be reused"):
                quality_review._record_review(
                    "invocation-reuse", root, "product", "product-review-02", result,
                    execution=reused_execution,
                    reviewed_artifacts=review_artifacts(root, "invocation-reuse", "product", current_state),
                )

    def test_architecture_review_requires_product_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            init_git(root)
            run_delivery_cli(root, "init_feature.py", "review-order")
            state_path = root / "delivery/review-order/state.md"
            (state_path.parent / "prd.md").write_text(PRD_DOCUMENT, encoding="utf-8")
            (state_path.parent / "architecture-design.md").write_text(ARCHITECTURE_DOCUMENT, encoding="utf-8")
            content, state = extract_state(state_path)
            state["stages"]["prd"]["fingerprint"] = hashlib.sha256((state_path.parent / "prd.md").read_bytes()).hexdigest()
            state["architecture_review"]["status"] = "in_progress"
            write_state(state_path, content, state)
            result = root / "architecture-review.json"
            result.write_text(json.dumps(review_result_payload("architecture", review_checks("architecture"))), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "passed Product review"):
                quality_review._record_review(
                    "review-order", root, "architecture", "architecture-review-01", result,
                    execution=test_review_execution(root, "review-order", "architecture-review-01"),
                    reviewed_artifacts=review_artifacts(root, "review-order", "architecture", extract_state(state_path)[1]),
                )

    def test_code_spec_review_requires_architecture_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_approved_delivery(root, "code-review-order")
            content, state = extract_state(state_path)
            state["stages"]["architecture"]["status"] = "in_progress"
            state["quality_reviews"]["code_spec"] = None
            state["proof_contract"]["quality_review"] = None
            state["proof_contract"]["status"] = "pending"
            state["proof_contract"]["seal"] = None
            (state_path.parent / "proof-contract.json").unlink()
            write_state(state_path, content, state)
            result = root / "code-review.json"
            coverage = expected_review_coverage(state_path.parent, "code_spec", state)
            result.write_text(json.dumps(review_result_payload("code_spec", review_checks("code_spec", coverage=coverage))), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "passed Architecture review"):
                quality_review._record_review(
                    "code-review-order", root, "code_spec", "code-spec-review-02", result,
                    execution=test_review_execution(root, "code-review-order", "code-spec-review-02"),
                    reviewed_artifacts=review_artifacts(root, "code-review-order", "code_spec", state),
                )

    def test_forged_product_stage_cannot_bypass_product_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_approved_delivery(root, "forged-product-stage")
            content, state = extract_state(state_path)
            state["quality_reviews"]["product"] = None
            state["stages"]["prd"]["status"] = "completed"
            state["quality_reviews"]["architecture"] = None
            state["stages"]["architecture"]["status"] = "in_progress"
            state["current_stage"] = "architecture"
            write_state(state_path, content, state)
            result = root / "forged-architecture-review.json"
            result.write_text(json.dumps(review_result_payload("architecture", review_checks("architecture"))), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "failed intermediate validation"):
                quality_review._record_review(
                    "forged-product-stage", root, "architecture", "architecture-review-02", result,
                    execution=test_review_execution(root, "forged-product-stage", "architecture-review-02"),
                    reviewed_artifacts=review_artifacts(root, "forged-product-stage", "architecture", state),
                )
            _, rolled_back = extract_state(state_path)
            self.assertIsNone(rolled_back["quality_reviews"]["architecture"])

    def test_legacy_approval_command_returns_migration_guidance(self) -> None:
        result = subprocess.run([sys.executable, str(SCRIPTS / "approve_stage.py")], capture_output=True, text=True)
        self.assertEqual(2, result.returncode)
        self.assertIn("upgrade_v8_to_v9.py", result.stderr)
        self.assertIn("quality_review.py", result.stderr)

    def test_blocked_architecture_review_is_a_recoverable_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_approved_delivery(root, "blocked-architecture")
            invalidate_downstream.invalidate(root, "blocked-architecture", "architecture")
            result = root / "blocked-review.json"
            checks = review_checks("architecture")
            checks[0]["status"] = "FAIL"
            payload = review_result_payload("architecture", checks)
            payload["verdict"] = "BLOCKED"
            payload["findings"] = [{"id": "ARQ-1", "severity": "major", "status": "open", "statement": "unsafe boundary", "evidence": "architecture-design.md"}]
            result.write_text(json.dumps(payload), encoding="utf-8")
            current_state = extract_state(state_path)[1]
            quality_review._record_review(
                "blocked-architecture", root, "architecture", "architecture-blocked-01", result,
                execution=test_review_execution(root, "blocked-architecture", "architecture-blocked-01"),
                reviewed_artifacts=review_artifacts(root, "blocked-architecture", "architecture", current_state),
            )
            validation = subprocess.run([sys.executable, str(SCRIPTS / "validate_feature.py"), "blocked-architecture", "--root", str(root)], capture_output=True, text=True)
            self.assertNotIn("Traceback", validation.stdout + validation.stderr)
            self.assertEqual(0, validation.returncode, validation.stdout + validation.stderr)
            _, state = extract_state(state_path)
            self.assertEqual("blocked", state["stages"]["architecture"]["status"])


class ArchitectureDocumentTests(unittest.TestCase):
    def test_sql_ddl_is_required(self) -> None:
        errors: list[str] = []
        validate_database_section("字段与索引见正文。", errors)
        self.assertTrue(any("SQL DDL" in error for error in errors))

    def test_markdown_schema_table_is_rejected_even_with_sql(self) -> None:
        text = """```sql
CREATE TABLE task (id bigint PRIMARY KEY);
```
| 字段 | 类型 |
|---|---|
| id | bigint |
"""
        errors: list[str] = []
        validate_database_section(text, errors)
        self.assertTrue(any("Markdown schema tables" in error for error in errors))

    def test_sql_only_database_shape_passes(self) -> None:
        errors: list[str] = []
        validate_database_section("```sql\nCREATE TABLE task (id bigint PRIMARY KEY);\nCOMMENT ON COLUMN task.id IS 'identifier';\n```", errors)
        self.assertEqual([], errors)

    def test_inline_comments_after_column_commas_pass(self) -> None:
        errors: list[str] = []
        validate_database_section("""```sql
CREATE TABLE task (
  id bigint PRIMARY KEY, -- identifier
  status varchar(32) NOT NULL -- lifecycle status
);
```""", errors)
        self.assertEqual([], errors)

    def test_nested_type_parentheses_do_not_truncate_column_validation(self) -> None:
        errors: list[str] = []
        validate_database_section("""```sql
CREATE TABLE invoice (
  id bigint PRIMARY KEY,
  amount numeric(14,2) NOT NULL,
  state varchar(20) DEFAULT 'draft'
);
COMMENT ON COLUMN invoice.id IS 'identifier';
COMMENT ON COLUMN invoice.amount IS 'money amount';
COMMENT ON COLUMN invoice.state IS 'lifecycle state';
```""", errors)
        self.assertEqual([], errors)

    def test_alter_table_added_column_requires_comment(self) -> None:
        errors: list[str] = []
        validate_database_section("```sql\nALTER TABLE task ADD COLUMN completed_at timestamptz;\n```", errors)
        self.assertTrue(any("task.completed_at" in error for error in errors))

    def test_procedural_migration_logic_is_rejected(self) -> None:
        errors: list[str] = []
        validate_database_section("""```sql
CREATE TABLE task (id bigint);
COMMENT ON COLUMN task.id IS 'identifier';
DO $$ BEGIN LOOP INSERT INTO task VALUES (1); END LOOP; END $$;
```""", errors)
        self.assertTrue(any("migration execution logic" in error for error in errors))

    def test_migration_numbering_is_rejected_from_schema_contract(self) -> None:
        errors: list[str] = []
        validate_database_section("""```sql
-- V20260822__create_task
CREATE TABLE task (id bigint);
COMMENT ON COLUMN task.id IS 'identifier';
```""", errors)
        self.assertTrue(any("migration numbering" in error for error in errors))

    def test_sql_comment_cannot_fake_ddl(self) -> None:
        errors: list[str] = []
        validate_database_section("```sql\n-- CREATE TABLE fake (id bigint);\nSELECT 1;\n```", errors)
        self.assertTrue(any("SQL DDL" in error for error in errors))


class VerificationRunTests(unittest.TestCase):
    def test_visual_evidence_requires_three_image_roles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, result = prepare_profile_run(root, "visual")
            with self.assertRaisesRegex(ValueError, "prototype_screenshot"):
                record("visual-profile", root, "run-001", result, [])

    def test_visual_evidence_roles_cannot_alias_one_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, result = prepare_profile_run(root, "visual")
            image = root / ".dlv/inputs/same.png"
            image.write_bytes(b"not-a-real-image-but-a-distinct-anchor-test")
            payload = json.loads(result.read_text(encoding="utf-8"))
            payload["anchors"] = [
                {"role": role, "path": str(image)}
                for role in ("prototype_screenshot", "implementation_screenshot", "visual_diff")
            ]
            result.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "three distinct"):
                record("visual-profile", root, "run-001", result, [])

    def test_visual_evidence_rejects_text_renamed_as_png(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, result = prepare_profile_run(root, "visual")
            anchors = []
            anchor_dir = root / ".dlv" / "inputs"
            for role in ("prototype_screenshot", "implementation_screenshot", "visual_diff"):
                path = anchor_dir / f"{role}.png"
                path.write_bytes(f"fake-{role}".encode())
                anchors.append({"role": role, "path": str(path)})
            payload = json.loads(result.read_text(encoding="utf-8"))
            payload["anchors"] = anchors
            result.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "truncated PNG|pixel comparison"):
                record("visual-profile", root, "run-001", result, [])

    def test_visual_evidence_rejects_png_decompression_bomb(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bomb.png"

            def chunk(name: bytes, payload: bytes) -> bytes:
                return struct.pack(">I", len(payload)) + name + payload + struct.pack(">I", zlib.crc32(name + payload) & 0xFFFFFFFF)

            header = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
            oversized_scanlines = zlib.compress(b"\x00" * 1_000_000)
            path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", oversized_scanlines) + chunk(b"IEND", b""))
            with self.assertRaisesRegex(ValueError, "PNG scanline size mismatch"):
                verification_run.load_png_rgba(path)

    def test_visual_evidence_rejects_short_ihdr_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "short-ihdr.png"

            def chunk(name: bytes, payload: bytes) -> bytes:
                return struct.pack(">I", len(payload)) + name + payload + struct.pack(">I", zlib.crc32(name + payload) & 0xFFFFFFFF)

            path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", b"short") + chunk(b"IEND", b""))
            with self.assertRaisesRegex(ValueError, "exactly one 13-byte IHDR"):
                verification_run.load_png_rgba(path)

    def test_visual_evidence_cannot_self_report_zero_for_different_pixels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, result = prepare_profile_run(root, "visual")
            anchor_dir = root / ".dlv" / "inputs"
            prototype = anchor_dir / "prototype.png"
            implementation = anchor_dir / "implementation.png"
            visual_diff = anchor_dir / "diff.png"
            prototype.write_bytes(png_bytes(255, 0, 0))
            implementation.write_bytes(png_bytes(0, 0, 255))
            visual_diff.write_bytes(png_bytes(255, 255, 255))
            payload = json.loads(result.read_text(encoding="utf-8"))
            payload["anchors"] = [
                {"role": "prototype_screenshot", "path": str(prototype)},
                {"role": "implementation_screenshot", "path": str(implementation)},
                {"role": "visual_diff", "path": str(visual_diff)},
            ]
            result.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "visual_diff must contain zero RGB difference pixels"):
                record("visual-profile", root, "run-001", result, [])

    def test_visual_evidence_accepts_computed_zero_difference(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, result = prepare_profile_run(root, "visual")
            anchor_dir = root / ".dlv" / "inputs"
            anchors = []
            for role, color in (("prototype_screenshot", (0, 128, 0)), ("implementation_screenshot", (0, 128, 0)), ("visual_diff", (0, 0, 0))):
                path = anchor_dir / f"{role}.png"
                path.write_bytes(png_bytes(*color))
                anchors.append({"role": role, "path": str(path)})
            payload = json.loads(result.read_text(encoding="utf-8"))
            payload["anchors"] = anchors
            result.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual("EVID-0001", record("visual-profile", root, "run-001", result, []))

    def test_visual_source_swap_after_snapshot_cannot_change_stored_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, result = prepare_profile_run(root, "visual")
            anchor_dir = root / ".dlv" / "inputs"
            anchors = []
            implementation: Path | None = None
            for role, color in (("prototype_screenshot", (0, 128, 0)), ("implementation_screenshot", (0, 128, 0)), ("visual_diff", (0, 0, 0))):
                path = anchor_dir / f"{role}.png"
                path.write_bytes(png_bytes(*color))
                anchors.append({"role": role, "path": str(path)})
                if role == "implementation_screenshot":
                    implementation = path
            payload = json.loads(result.read_text(encoding="utf-8"))
            payload["anchors"] = anchors
            result.write_text(json.dumps(payload), encoding="utf-8")
            real_metrics = verification_run.computed_visual_metrics

            def swap_source_after_snapshot(snapshot: list[tuple[str | None, Path]]) -> tuple[float, int]:
                assert implementation is not None
                implementation.write_bytes(png_bytes(255, 0, 0))
                return real_metrics(snapshot)

            with patch("verification_run.computed_visual_metrics", side_effect=swap_source_after_snapshot):
                self.assertEqual("EVID-0001", record("visual-profile", root, "run-001", result, []))
            records = json.loads((root / ".dlv/runs/visual-profile/run-001/evidence.jsonl").read_text(encoding="utf-8"))
            stored = {item.get("role"): root / ".dlv/runs/visual-profile/run-001" / item["path"] for item in records["anchors"] if item.get("role")}
            self.assertEqual(real_metrics(list(stored.items())), (0.0, 0))
            errors: list[str] = []
            state = extract_state(root / "delivery/visual-profile/state.md")[1]
            validate_verification_run(root, "visual-profile", state, errors)
            self.assertEqual([], errors)

    def test_runtime_evidence_requires_trace_role(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, result = prepare_profile_run(root, "runtime")
            with self.assertRaisesRegex(ValueError, "runtime_trace anchor"):
                record("runtime-profile", root, "run-001", result, [])

    def test_runtime_evidence_binds_target_runtime_and_structured_trace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, result = prepare_profile_run(root, "runtime")
            trace = root / ".dlv" / "inputs" / "runtime-trace.json"
            trace.write_text(json.dumps({"runtime": "api", "action": "create task", "result_readback": {"status": "created"}}), encoding="utf-8")
            payload = json.loads(result.read_text(encoding="utf-8"))
            payload["anchors"] = [{"role": "runtime_trace", "path": str(trace)}]
            result.write_text(json.dumps(payload), encoding="utf-8")
            with patch.object(verification_run, "run_bounded", return_value={
                "exit_code": 0,
                "stdout": json.dumps({"runtime": "wrong", "action": "create task", "result_readback": {"status": "created"}}),
                "stderr": "",
                "timed_out": False,
            }):
                with self.assertRaisesRegex(ValueError, "sealed target environment runtime"):
                    record("runtime-profile", root, "run-001", result, [])
            trace.write_text("not json", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "valid JSON"):
                record("runtime-profile", root, "run-001", result, [])

    def test_runtime_evidence_accepts_matching_structured_trace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, result = prepare_profile_run(root, "runtime")
            trace = root / ".dlv" / "inputs" / "runtime-trace.json"
            trace.write_text(json.dumps({"runtime": "api", "action": "create task", "result_readback": {"status": "created"}}), encoding="utf-8")
            payload = json.loads(result.read_text(encoding="utf-8"))
            payload["anchors"] = [{"role": "runtime_trace", "path": str(trace)}]
            result.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual("EVID-0001", record("runtime-profile", root, "run-001", result, []))

    def test_runner_timeout_terminates_descendant_processes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            started = time.monotonic()
            result = run_bounded([
                sys.executable, "-c",
                "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import os,time; os.setsid(); time.sleep(10)']); time.sleep(10)",
            ], Path(temporary), timeout_seconds=1)
            self.assertLess(time.monotonic() - started, 4)
            self.assertEqual(124, result["exit_code"])
            self.assertTrue(result["timed_out"])

    def test_runner_output_is_bounded_and_common_secrets_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = run_bounded([
                sys.executable, "-c",
                f"print('token=super-secret'); print('{{\"password\": \"json-secret\"}}'); print('x'*{MAX_CAPTURE_BYTES + 1024})",
            ], Path(temporary), timeout_seconds=5)
            self.assertNotIn("super-secret", result["stdout"])
            self.assertNotIn("json-secret", result["stdout"])
            self.assertIn("token=[REDACTED]", result["stdout"])
            self.assertIn("[TRUNCATED", result["stdout"])
            self.assertLess(len(result["stdout"]), MAX_CAPTURE_BYTES + 200)

    def test_feature_id_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "feature-id"):
                start("../escape", Path(temporary), "run-001", [])

    def test_failed_preflight_creates_blocked_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            init_git(root)
            subprocess.run(["python3", str(SCRIPTS / "init_feature.py"), "preflight-block", "--root", str(root)], check=True)
            state_path = root / "delivery" / "preflight-block" / "state.md"
            bad_contract = contract()
            bad_contract["environments"][0]["spec"]["preflight"] = [  # type: ignore[index]
                {"id": "unavailable", "argv": ["python3", "-c", "raise SystemExit(9)"]}
            ]
            bad_contract["seal"] = proof_contract_digest(bad_contract)
            environment = root / "blocked-env.json"
            environment.write_text(json.dumps(bad_contract["environments"][0]["spec"]), encoding="utf-8")  # type: ignore[index]
            content, state = extract_state(state_path)
            state["proof_contract"] = bad_contract
            (state_path.parent / "proof-contract.json").write_text(json.dumps(bad_contract), encoding="utf-8")
            state["stages"]["code_spec"].update({"status": "completed", "fingerprint": "c" * 64})
            state["stages"]["code"].update({"status": "completed", "result": {"repository_fingerprint": repository_fingerprint(root, "preflight-block")}})
            write_state(state_path, content, state)
            with self.assertRaisesRegex(ValueError, "preflight blocked"):
                start("preflight-block", root, "run-001", [f"ENV-01={environment}"])
            _, blocked = extract_state(state_path)
            metadata = json.loads((root / ".dlv" / "runs" / "preflight-block" / "run-001" / "run.json").read_text())
            self.assertEqual("blocked", blocked["stages"]["verification"]["status"])
            self.assertEqual("BLOCKED", metadata["preflight_verdict"])
            self.assertTrue((state_path.parent / "verification.md").is_file())
            self.assertIn("当前状态：`BLOCKED`", (state_path.parent / "verification.md").read_text(encoding="utf-8"))

    def test_start_rejects_environment_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            init_git(root)
            subprocess.run(["python3", str(SCRIPTS / "init_feature.py"), "env-drift", "--root", str(root)], check=True)
            state_path = root / "delivery" / "env-drift" / "state.md"
            wrong = root / "wrong.json"
            wrong.write_text(json.dumps({"runtime": "postgres", "version": "15"}), encoding="utf-8")
            content, state = extract_state(state_path)
            state["proof_contract"] = contract()
            (state_path.parent / "proof-contract.json").write_text(json.dumps(state["proof_contract"]), encoding="utf-8")
            state["stages"]["code_spec"].update({"status": "completed", "fingerprint": "c" * 64})
            state["stages"]["code"].update({"status": "completed", "result": {"repository_fingerprint": repository_fingerprint(root, "env-drift")}})
            write_state(state_path, content, state)
            with self.assertRaisesRegex(ValueError, "does not match"):
                start("env-drift", root, "run-001", [f"ENV-01={wrong}"])

    def test_record_copies_anchor_and_validates_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            evidence_id = record("kernel-test", root, "run-001", result_file(root), [])
            _, state = extract_state(state_path)
            errors: list[str] = []
            verdict, digest = validate_verification_run(root, "kernel-test", state, errors)
            self.assertEqual("EVID-0001", evidence_id)
            self.assertEqual("PASS", verdict)
            self.assertEqual([], errors)
            self.assertRegex(str(digest), r"^[0-9a-f]{64}$")

    def test_preflight_status_and_anchor_are_recomputed_not_trusted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root), [])
            run_path = root / ".dlv/runs/kernel-test/run-001/run.json"
            metadata = json.loads(run_path.read_text())
            metadata["preflight"][0]["status"] = "blocked"
            run_path.write_text(json.dumps(metadata), encoding="utf-8")
            _, state = extract_state(state_path)
            errors: list[str] = []
            self.assertEqual("BLOCKED", validate_verification_run(root, "kernel-test", state, errors)[0])
            self.assertTrue(any("preflight check is not passed" in error for error in errors))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root), [])
            run_path = root / ".dlv/runs/kernel-test/run-001/run.json"
            metadata = json.loads(run_path.read_text())
            anchor = root / ".dlv/runs/kernel-test/run-001" / metadata["preflight"][0]["anchor"]
            anchor_value = json.loads(anchor.read_text())
            anchor_value["status"] = "blocked"
            anchor.write_text(json.dumps(anchor_value), encoding="utf-8")
            metadata["preflight"][0]["sha256"] = hashlib.sha256(anchor.read_bytes()).hexdigest()
            run_path.write_text(json.dumps(metadata), encoding="utf-8")
            _, state = extract_state(state_path)
            errors = []
            self.assertEqual("BLOCKED", validate_verification_run(root, "kernel-test", state, errors)[0])
            self.assertTrue(any("anchor disagrees" in error for error in errors))

    def test_caller_cannot_self_award_pass_against_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            malicious = json.loads(result_file(root, status="failed").read_text())
            malicious_path = root / ".dlv" / "inputs" / "malicious.json"
            malicious_path.write_text(json.dumps(malicious), encoding="utf-8")
            record("kernel-test", root, "run-001", malicious_path, [])
            _, state = extract_state(state_path)
            errors: list[str] = []
            verdict, _ = validate_verification_run(root, "kernel-test", state, errors)
            manifest = json.loads((root / ".dlv" / "runs" / "kernel-test" / "run-001" / "evidence.jsonl").read_text())
            self.assertEqual("failed", manifest["status"])
            self.assertEqual("BLOCKED", verdict)

    def test_caller_supplied_command_result_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepare(root)
            forged = json.loads(result_file(root).read_text())
            forged["command"] = {"argv": ["false"], "cwd": ".", "exit_code": 0}
            forged["observation"] = {"draft_count": 0, "http_status": 200}
            path = root / ".dlv" / "inputs" / "forged.json"
            path.write_text(json.dumps(forged), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "observation is forbidden"):
                record("kernel-test", root, "run-001", path, [])

    def test_skip_outcome_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepare(root)
            skipped = json.loads(result_file(root).read_text())
            skipped["outcome"] = "skipped"
            path = root / ".dlv" / "inputs" / "skipped.json"
            path.write_text(json.dumps(skipped), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "skips are forbidden"):
                record("kernel-test", root, "run-001", path, [])

    def test_old_run_and_completed_run_are_not_mutable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, environment = prepare(root)
            start("kernel-test", root, "run-002", [f"ENV-01={environment}"])
            with self.assertRaisesRegex(ValueError, "active Verification Run"):
                record("kernel-test", root, "run-001", result_file(root), [])
            record("kernel-test", root, "run-002", result_file(root), [])
            content, state = extract_state(state_path)
            state["stages"]["verification"]["status"] = "completed"
            write_state(state_path, content, state)
            with self.assertRaisesRegex(ValueError, "in_progress"):
                record("kernel-test", root, "run-002", result_file(root), [])
            with self.assertRaisesRegex(ValueError, "active Verification Run"):
                render("kernel-test", root, "run-001")

    def test_concurrent_recorders_preserve_unique_ids_chain_and_state_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            result = result_file(root)
            with ThreadPoolExecutor(max_workers=2) as executor:
                ids = list(executor.map(lambda _: record("kernel-test", root, "run-001", result, []), range(2)))
            records = [json.loads(line) for line in (root / ".dlv/runs/kernel-test/run-001/evidence.jsonl").read_text().splitlines()]
            _, state = extract_state(state_path)
            self.assertEqual(["EVID-0001", "EVID-0002"], sorted(ids))
            self.assertEqual(records[0]["record_hash"], records[1]["previous_hash"])
            self.assertEqual(2, state["stages"]["verification"]["evidence_count"])
            self.assertEqual(records[-1]["record_hash"], state["stages"]["verification"]["evidence_head"])

    def test_interrupted_append_is_recovered_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            result = result_file(root)
            with patch("verification_run.write_state", side_effect=OSError("simulated crash")):
                with self.assertRaisesRegex(OSError, "simulated crash"):
                    record("kernel-test", root, "run-001", result, [])
            self.assertTrue((root / ".dlv/runs/kernel-test/run-001/pending-record.json").is_file())
            self.assertEqual("EVID-0001", record("kernel-test", root, "run-001", result, []))
            _, state = extract_state(state_path)
            errors: list[str] = []
            self.assertEqual("PASS", validate_verification_run(root, "kernel-test", state, errors)[0])
            self.assertEqual([], errors)
            self.assertFalse((root / ".dlv/runs/kernel-test/run-001/pending-record.json").exists())

    @unittest.skipUnless(sys.platform == "darwin", "macOS path alias regression")
    def test_macos_var_alias_resolves_to_one_run_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepare(root)
            alias = Path(str(root.resolve()).replace("/private/var/", "/var/", 1))
            self.assertEqual("EVID-0001", record("kernel-test", alias, "run-001", result_file(root), []))

    def test_cli_record_render_and_validate_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, environment = prepare(root)
            result = result_file(root)
            commands = [
                [sys.executable, str(SCRIPTS / "verification_run.py"), "start", "kernel-test", "--root", str(root), "--run-id", "run-002", "--environment", f"ENV-01={environment}"],
                [sys.executable, str(SCRIPTS / "verification_run.py"), "record", "kernel-test", "--root", str(root), "--run-id", "run-002", "--result", str(result)],
                [sys.executable, str(SCRIPTS / "verification_run.py"), "render", "kernel-test", "--root", str(root), "--run-id", "run-002"],
                [sys.executable, str(SCRIPTS / "validate_verification_evidence.py"), "kernel-test", "--root", str(root), "--run-id", "run-002"],
            ]
            for command in commands:
                completed = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    def test_manifest_status_tampering_breaks_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root, status="failed"), [])
            manifest_path = root / ".dlv" / "runs" / "kernel-test" / "run-001" / "evidence.jsonl"
            value = json.loads(manifest_path.read_text())
            value["status"] = "passed"
            for item in value["assertion_results"]:
                item["status"] = "passed"
            manifest_path.write_text(json.dumps(value) + "\n")
            _, state = extract_state(state_path)
            errors: list[str] = []
            verdict, _ = validate_verification_run(root, "kernel-test", state, errors)
            self.assertEqual("BLOCKED", verdict)
            self.assertTrue(any("hash chain" in error for error in errors))

    def test_rehashed_manifest_tampering_disagrees_with_state_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root, status="failed"), [])
            manifest_path = root / ".dlv" / "runs" / "kernel-test" / "run-001" / "evidence.jsonl"
            value = json.loads(manifest_path.read_text())
            value["status"] = "passed"
            value["observation"] = {"draft_count": 0, "http_status": 200}
            for item in value["assertion_results"]:
                item["status"] = "passed"
                item["actual"] = 0 if item["assertion_id"] == "ASRT-01" else 200
            value["record_hash"] = value_digest({key: item for key, item in value.items() if key != "record_hash"})
            manifest_path.write_text(json.dumps(value) + "\n")
            _, state = extract_state(state_path)
            errors: list[str] = []
            verdict, _ = validate_verification_run(root, "kernel-test", state, errors)
            self.assertEqual("BLOCKED", verdict)
            self.assertTrue(any("state-anchored" in error for error in errors))

    def test_contract_snapshot_mismatch_blocks_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            artifact = state_path.parent / "proof-contract.json"
            value = json.loads(artifact.read_text())
            value["quality_review"]["record_sha256"] = "0" * 64
            artifact.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "disagrees"):
                record("kernel-test", root, "run-001", result_file(root), [])

    def test_anchor_tampering_blocks_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root), [])
            anchor = next((root / ".dlv" / "runs" / "kernel-test" / "run-001" / "anchors").iterdir())
            anchor.write_text("tampered\n", encoding="utf-8")
            _, state = extract_state(state_path)
            errors: list[str] = []
            verdict, _ = validate_verification_run(root, "kernel-test", state, errors)
            self.assertEqual("BLOCKED", verdict)
            self.assertTrue(any("hash mismatch" in error for error in errors))

    def test_failed_evidence_blocks_until_explicitly_superseded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            failed_id = record("kernel-test", root, "run-001", result_file(root, status="failed"), [])
            _, state = extract_state(state_path)
            errors: list[str] = []
            self.assertEqual("BLOCKED", validate_verification_run(root, "kernel-test", state, errors)[0])
            passed_id = record("kernel-test", root, "run-001", result_file(root), [failed_id])
            _, state = extract_state(state_path)
            errors = []
            self.assertEqual("PASS", validate_verification_run(root, "kernel-test", state, errors)[0])
            self.assertEqual("EVID-0002", passed_id)

    def test_code_change_stales_only_the_run_not_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root), [])
            (root / "source.txt").write_text("changed\n", encoding="utf-8")
            _, state = extract_state(state_path)
            errors: list[str] = []
            self.assertEqual("BLOCKED", validate_verification_run(root, "kernel-test", state, errors)[0])
            self.assertEqual("completed", state["proof_contract"]["status"])
            self.assertTrue(any("stale code" in error for error in errors))

    def test_open_structured_blocker_prevents_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root), [])
            content, state = extract_state(state_path)
            state["risks"] = [{
                "id": "RISK-01", "type": "blocker", "severity": "high", "status": "open",
                "statement": "production credential unavailable", "owner": "release-owner",
            }]
            write_state(state_path, content, state)
            errors: list[str] = []
            self.assertEqual("BLOCKED", validate_verification_run(root, "kernel-test", state, errors)[0])
            self.assertTrue(any("open blocker" in error for error in errors))

    def test_blocker_cannot_be_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root), [])
            content, state = extract_state(state_path)
            state["risks"] = [{
                "id": "RISK-01", "type": "blocker", "severity": "high", "status": "accepted",
                "statement": "oracle unavailable", "owner": "verification-owner", "accepted_by": "owner",
            }]
            write_state(state_path, content, state)
            errors: list[str] = []
            self.assertEqual("BLOCKED", validate_verification_run(root, "kernel-test", state, errors)[0])
            self.assertTrue(any("cannot be accepted" in error for error in errors))

    def test_generated_report_is_derived_from_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepare(root)
            record("kernel-test", root, "run-001", result_file(root), [])
            report = render("kernel-test", root, "run-001")
            text = report.read_text(encoding="utf-8")
            document_errors: list[str] = []
            validate_document("verification", text, document_errors)
            self.assertIn("EVID-0001", text)
            self.assertIn("ASRT-01=passed", text)
            self.assertIn("append-only Evidence Bundle", text)
            self.assertEqual([], document_errors)

    def test_generated_report_escapes_markdown_table_cells(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            record("kernel-test", root, "run-001", result_file(root), [])
            content, state = extract_state(state_path)
            state["risks"] = [{
                "id": "RISK-01", "type": "residual", "severity": "low", "status": "accepted",
                "statement": "line one | line two\nnext", "owner": "owner", "accepted_by": "owner",
            }]
            write_state(state_path, content, state)
            text = render("kernel-test", root, "run-001").read_text(encoding="utf-8")
            self.assertIn(r"line one \| line two<br>next", text)


class MigrationTests(unittest.TestCase):
    def test_sql_comments_cannot_hide_uncommented_columns(self) -> None:
        errors: list[str] = []
        validate_database_section(
            "```sql\nCREATE TABLE users (\n  id bigint, -- identifier (\n  secret text\n);\nCOMMENT ON COLUMN users.id IS 'id';\n```",
            errors,
        )
        self.assertTrue(any("users.secret" in error for error in errors), errors)

    def test_artifact_change_invalidates_quality_review_and_downstream_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run([sys.executable, str(SCRIPTS / "init_feature.py"), "review-stale", "--root", str(root)], check=True)
            state_path = root / "delivery/review-stale/state.md"
            architecture = state_path.parent / "architecture-design.md"
            architecture.write_text("version one\n", encoding="utf-8")
            content, state = extract_state(state_path)
            state["stages"]["architecture"].update({"status": "completed", "fingerprint": hashlib.sha256(architecture.read_bytes()).hexdigest()})
            state["quality_reviews"]["architecture"] = {"review_run_id": "architecture-review-01"}
            write_state(state_path, content, state)
            architecture.write_text("version two\n", encoding="utf-8")
            invalidate_downstream.invalidate(root, "review-stale", None)
            _, updated = extract_state(state_path)
            self.assertIsNone(updated["quality_reviews"]["architecture"])
            self.assertEqual("stale", updated["stages"]["architecture"]["status"])

    def test_bound_non_file_inputs_invalidate_their_reviews(self) -> None:
        mutations = {
            "requirement": lambda state_path, state: state["requirement_review"]["summary"].update({"goal": "changed"}),
            "prototype": lambda state_path, state: (state_path.parent / "prototype.html").write_text("<html>new</html>", encoding="utf-8"),
            "architecture-review": lambda state_path, state: state["architecture_review"]["existing_capabilities"].append("changed capability"),
            "proof-draft": lambda state_path, state: state["proof_contract"]["obligations"][0].update({"surface": "changed surface"}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state_path = prepare_approved_delivery(root, f"invalidate-{name}", seal=False)
                content, state = extract_state(state_path)
                mutate(state_path, state)
                write_state(state_path, content, state)
                message = invalidate_downstream.invalidate(root, f"invalidate-{name}", None)
                self.assertIn("stale from", message)
                _, updated = extract_state(state_path)
                if name in {"requirement", "prototype"}:
                    self.assertIsNone(updated["quality_reviews"]["product"])
                elif name == "architecture-review":
                    self.assertIsNone(updated["quality_reviews"]["architecture"])
                else:
                    self.assertIsNone(updated["quality_reviews"]["code_spec"])

    def test_requirement_change_requires_three_fresh_reviews_before_reseal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            feature_id = "fresh-review-chain"
            state_path = prepare_approved_delivery(root, feature_id)
            content, state = extract_state(state_path)
            state["requirement_review"]["summary"]["goal"] = "changed reviewed requirement"
            write_state(state_path, content, state)
            invalidate_downstream.invalidate(root, feature_id, None)
            stale = extract_state(state_path)[1]
            self.assertEqual({"product": None, "architecture": None, "code_spec": None}, stale["quality_reviews"])
            self.assertFalse((state_path.parent / "proof-contract.json").exists())

            record_test_review(root, feature_id, "product", "product-review-02")
            record_test_review(root, feature_id, "architecture", "architecture-review-02")
            record_test_review(root, feature_id, "code_spec", "code-spec-review-02")
            run_delivery_cli(root, "seal_proof_contract.py", feature_id)
            validation = subprocess.run(
                [sys.executable, str(SCRIPTS / "validate_feature.py"), feature_id, "--root", str(root)],
                capture_output=True, text=True,
            )
            self.assertEqual(0, validation.returncode, validation.stdout + validation.stderr)
            refreshed = extract_state(state_path)[1]
            self.assertEqual("code", refreshed["current_stage"])
            self.assertEqual("completed", refreshed["proof_contract"]["status"])

    def test_review_record_identity_must_match_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_approved_delivery(root, "review-identity")
            record_path = root / ".dlv/reviews/review-identity/product-review-01.json"
            payload = json.loads(record_path.read_text(encoding="utf-8"))
            payload["review_run_id"] = "different-review"
            record_path.write_text(json.dumps(payload), encoding="utf-8")
            content, state = extract_state(state_path)
            state["quality_reviews"]["product"]["record_sha256"] = hashlib.sha256(record_path.read_bytes()).hexdigest()
            write_state(state_path, content, state)
            errors: list[str] = []
            validate_v9_gates(root, "review-identity", state_path.parent, state, errors)
            self.assertTrue(any("record filename" in error for error in errors), errors)

    def test_v7_to_v8_dry_run_is_non_mutating(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run([sys.executable, str(SCRIPTS / "init_feature.py"), "v8-preview", "--root", str(root)], check=True)
            state_path = root / "delivery/v8-preview/state.md"
            content, state = extract_state(state_path)
            state["schema_version"] = 7
            write_state(state_path, content, state)
            before = state_path.read_bytes()
            result = subprocess.run([sys.executable, str(SCRIPTS / "upgrade_v7_to_v8.py"), "v8-preview", "--root", str(root)], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual(before, state_path.read_bytes())

    def test_v7_to_v8_never_promotes_old_pass_or_approvals(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run([sys.executable, str(SCRIPTS / "init_feature.py"), "v8-upgrade", "--root", str(root)], check=True)
            state_path = root / "delivery/v8-upgrade/state.md"
            content, state = extract_state(state_path)
            state["schema_version"] = 7
            state["approvals"] = {"architecture": {"stage": "architecture"}}
            state["quality_reviews"] = {"architecture": {"verdict": "PASS"}, "code_spec": {"verdict": "PASS"}}
            state["architecture_review"]["material_decisions"] = [{
                "id": "MAT-01", "addition_ids": ["ADD-01"], "decision": "add",
                "reason": "legacy decision", "reversible": True, "approval": "APPROVED",
            }]
            for name in state["stages"]:
                state["stages"][name]["status"] = "completed"
            state["stages"]["verification"].update({"verdict": "PASS", "finalization": {"tool": "legacy"}})
            state["proof_contract"] = contract()
            (state_path.parent / "proof-contract.json").write_text(json.dumps(state["proof_contract"]), encoding="utf-8")
            write_state(state_path, content, state)
            result = subprocess.run([sys.executable, str(SCRIPTS / "upgrade_v7_to_v8.py"), "v8-upgrade", "--root", str(root), "--apply"], capture_output=True, text=True)
            _, upgraded = extract_state(state_path)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual(8, upgraded["schema_version"])
            self.assertEqual({}, upgraded["approvals"])
            self.assertEqual({"architecture": None, "code_spec": None}, upgraded["quality_reviews"])
            self.assertIsNone(upgraded["stages"]["verification"]["verdict"])
            self.assertIsNone(upgraded["stages"]["verification"]["finalization"])
            self.assertEqual("stale", upgraded["proof_contract"]["status"])
            self.assertEqual(contract()["environments"], upgraded["proof_contract"]["environments"])
            self.assertEqual(contract()["obligations"], upgraded["proof_contract"]["obligations"])
            self.assertFalse((state_path.parent / "proof-contract.json").exists())
            self.assertEqual("open", upgraded["risks"][-1]["status"])

    def test_v7_to_v8_write_failure_preserves_state_and_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run([sys.executable, str(SCRIPTS / "init_feature.py"), "upgrade-atomic", "--root", str(root)], check=True)
            state_path = root / "delivery/upgrade-atomic/state.md"
            content, state = extract_state(state_path)
            state["schema_version"] = 7
            state["proof_contract"] = contract()
            write_state(state_path, content, state)
            snapshot = state_path.parent / "proof-contract.json"
            snapshot.write_text(json.dumps(state["proof_contract"]), encoding="utf-8")
            before = state_path.read_bytes()
            with patch.object(upgrade_v7_to_v8, "write_state", side_effect=OSError("disk full")), patch(
                "sys.argv", ["upgrade_v7_to_v8.py", "upgrade-atomic", "--root", str(root), "--apply"]
            ):
                with self.assertRaisesRegex(OSError, "disk full"):
                    upgrade_v7_to_v8.main()
            self.assertEqual(before, state_path.read_bytes())
            self.assertTrue(snapshot.is_file())

    def test_v8_to_v9_dry_run_is_non_mutating(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_delivery_cli(root, "init_feature.py", "v9-preview")
            state_path = root / "delivery/v9-preview/state.md"
            content, state = extract_state(state_path)
            state["schema_version"] = 8
            state.pop("approval_trust", None)
            state.pop("approval_challenges", None)
            write_state(state_path, content, state)
            before = state_path.read_bytes()
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / "upgrade_v8_to_v9.py"), "v9-preview", "--root", str(root)],
                capture_output=True, text=True,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual(before, state_path.read_bytes())

    def test_v8_to_v9_removes_approval_state_and_requires_three_fresh_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_delivery_cli(root, "init_feature.py", "v9-upgrade")
            state_path = root / "delivery/v9-upgrade/state.md"
            content, state = extract_state(state_path)
            state["schema_version"] = 8
            state.pop("approval_trust", None)
            state.pop("approval_challenges", None)
            state["approvals"] = {"architecture": {"approved_by": "caller", "approval_reference": "generic-continue"}}
            state["quality_reviews"] = {"architecture": {"verdict": "PASS"}, "code_spec": {"verdict": "PASS"}}
            state["proof_contract"] = contract()
            state["architecture_review"]["material_decisions"] = [{
                "id": "MAT-01", "addition_ids": ["ADD-01"], "decision": "add",
                "reason": "legacy decision", "reversible": True, "approval": "APPROVED",
            }]
            (state_path.parent / "proof-contract.json").write_text(json.dumps(state["proof_contract"]), encoding="utf-8")
            for item in state["stages"].values():
                item["status"] = "completed"
            write_state(state_path, content, state)
            result = subprocess.run(
                [
                    sys.executable, str(SCRIPTS / "upgrade_v8_to_v9.py"), "v9-upgrade", "--root", str(root),
                    "--apply",
                ],
                capture_output=True, text=True,
            )
            _, upgraded = extract_state(state_path)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual(9, upgraded["schema_version"])
            self.assertNotIn("approvals", upgraded)
            self.assertNotIn("approval_challenges", upgraded)
            self.assertNotIn("approval_trust", upgraded)
            self.assertEqual({"product": None, "architecture": None, "code_spec": None}, upgraded["quality_reviews"])
            self.assertEqual("PENDING", upgraded["architecture_review"]["material_decisions"][0]["verdict"])
            self.assertNotIn("approval", upgraded["architecture_review"]["material_decisions"][0])
            self.assertEqual("in_progress", upgraded["requirement_review"]["status"])
            self.assertEqual("stale", upgraded["proof_contract"]["status"])
            self.assertFalse((state_path.parent / "proof-contract.json").exists())

    def test_upgraded_completed_v8_delivery_can_run_three_reviews_and_reseal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            feature_id = "v9-forward-upgrade"
            state_path = prepare_approved_delivery(root, feature_id)
            content, state = extract_state(state_path)
            state["schema_version"] = 8
            state["approvals"] = {"architecture": {"stage": "architecture"}, "code_spec": {"stage": "code_spec"}}
            state["quality_reviews"] = {"architecture": state["quality_reviews"]["architecture"], "code_spec": state["quality_reviews"]["code_spec"]}
            state["requirement_review"]["approved_at"] = state["requirement_review"].pop("reviewed_at")
            state["architecture_review"]["approved_at"] = state["architecture_review"].pop("reviewed_at")
            state["proof_contract"]["approval"] = {"stage": "code_spec"}
            state["proof_contract"].pop("quality_review", None)
            write_state(state_path, content, state)
            result = subprocess.run([sys.executable, str(SCRIPTS / "upgrade_v8_to_v9.py"), feature_id, "--root", str(root), "--apply"], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            record_test_review(root, feature_id, "product", "product-review-v9")
            record_test_review(root, feature_id, "architecture", "architecture-review-v9")
            record_test_review(root, feature_id, "code_spec", "code-spec-review-v9")
            run_delivery_cli(root, "seal_proof_contract.py", feature_id)
            validation = subprocess.run([sys.executable, str(SCRIPTS / "validate_feature.py"), feature_id, "--root", str(root)], capture_output=True, text=True)
            self.assertEqual(0, validation.returncode, validation.stdout + validation.stderr)
            _, upgraded = extract_state(state_path)
            self.assertEqual("completed", upgraded["proof_contract"]["status"])
            self.assertEqual("code", upgraded["current_stage"])

    def test_not_applicable_prototype_is_bound_by_product_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = prepare_approved_delivery(root, "product-receipt")
            _, updated = extract_state(state_path)
            prd_sha = hashlib.sha256((state_path.parent / "prd.md").read_bytes()).hexdigest()
            self.assertEqual("not_applicable", updated["stages"]["prototype"]["status"])
            self.assertEqual(prototype_decision_digest(prd_sha), updated["quality_reviews"]["product"]["bound_artifacts"]["prototype"])
            updated["quality_reviews"]["product"]["bound_artifacts"]["prototype"] = "0" * 64
            errors: list[str] = []
            validate_v9_gates(root, "product-receipt", state_path.parent, updated, errors)
            self.assertTrue(any("quality_reviews.product disagrees" in error for error in errors), errors)

    def test_current_stage_must_point_to_earliest_incomplete_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run([sys.executable, str(SCRIPTS / "init_feature.py"), "stage-coherence", "--root", str(root)], check=True)
            state_path = root / "delivery/stage-coherence/state.md"
            content, state = extract_state(state_path)
            state["current_stage"] = "code"
            write_state(state_path, content, state)
            completed = subprocess.run(
                [sys.executable, str(SCRIPTS / "validate_feature.py"), "stage-coherence", "--root", str(root)],
                capture_output=True, text=True,
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertIn("earliest incomplete stage: prd", completed.stdout)

    def test_invalidation_clears_the_sealed_contract_and_active_verification_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            message = invalidate_downstream.invalidate(root, "kernel-test", "code_spec")
            _, state = extract_state(state_path)
            self.assertIn("stale from code_spec", message)
            self.assertEqual("stale", state["proof_contract"]["status"])
            self.assertIsNone(state["proof_contract"]["seal"])
            self.assertEqual("stale", state["stages"]["verification"]["status"])
            self.assertFalse((state_path.parent / "proof-contract.json").exists())

    def test_invalidation_write_failure_preserves_sealed_contract_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root)
            snapshot = state_path.parent / "proof-contract.json"
            before_state = state_path.read_bytes()
            before_snapshot = snapshot.read_bytes()
            with patch.object(invalidate_downstream, "write_state", side_effect=OSError("disk full")):
                with self.assertRaisesRegex(OSError, "disk full"):
                    invalidate_downstream.invalidate(root, "kernel-test", "code_spec")
            self.assertEqual(before_state, state_path.read_bytes())
            self.assertEqual(before_snapshot, snapshot.read_bytes())

    def test_upgrade_dry_run_is_non_mutating_and_wrong_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run([sys.executable, str(SCRIPTS / "init_feature.py"), "upgrade-preview", "--root", str(root)], check=True)
            state_path = root / "delivery/upgrade-preview/state.md"
            content, state = extract_state(state_path)
            state["schema_version"] = 6
            write_state(state_path, content, state)
            before = state_path.read_text(encoding="utf-8")
            dry = subprocess.run([sys.executable, str(SCRIPTS / "upgrade_v6_to_v7.py"), "upgrade-preview", "--root", str(root)], capture_output=True, text=True)
            self.assertEqual(0, dry.returncode)
            self.assertEqual(before, state_path.read_text(encoding="utf-8"))
            content, state = extract_state(state_path)
            state["schema_version"] = 7
            write_state(state_path, content, state)
            wrong = subprocess.run([sys.executable, str(SCRIPTS / "upgrade_v6_to_v7.py"), "upgrade-preview", "--root", str(root), "--apply"], capture_output=True, text=True)
            self.assertEqual(2, wrong.returncode)
    def test_v6_upgrade_invalidates_code_spec_and_downstream(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["python3", str(SCRIPTS / "init_feature.py"), "upgrade-test", "--root", str(root)], check=True)
            state_path = root / "delivery" / "upgrade-test" / "state.md"
            content, state = extract_state(state_path)
            state["schema_version"] = 6
            state["blockers"] = ["legacy blocker"]
            state.pop("risks")
            for stage in ("code_spec", "code", "verification"):
                state["stages"][stage]["status"] = "completed"
            write_state(state_path, content, state)
            result = subprocess.run(
                ["python3", str(SCRIPTS / "upgrade_v6_to_v7.py"), "upgrade-test", "--root", str(root), "--apply"],
                capture_output=True, text=True,
            )
            _, upgraded = extract_state(state_path)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual(7, upgraded["schema_version"])
            self.assertEqual("pending", upgraded["proof_contract"]["status"])
            self.assertEqual("open", upgraded["risks"][0]["status"])
            self.assertTrue(all(upgraded["stages"][stage]["status"] == "stale" for stage in ("code_spec", "code", "verification")))


class FinalizationTests(unittest.TestCase):
    def test_real_v9_delivery_finalizes_and_passes_independent_final_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            feature_id = "real-finalization"
            state_path = prepare_approved_delivery(root, feature_id)
            content, state = extract_state(state_path)
            code_spec_sha = state["stages"]["code_spec"]["fingerprint"]
            state["stages"]["code"].update({
                "status": "completed",
                "inputs": {"code_spec": code_spec_sha, "repositories": {}},
                "result": {"repository_fingerprint": repository_fingerprint(root, feature_id)},
                "simplicity_gate": {
                    name: {"status": "N/A", "reason": "fixture has no production code change"}
                    for name in ("delete", "kiss", "dry", "responsibility", "dependency")
                },
            })
            state["current_stage"] = "verification"
            write_state(state_path, content, state)
            inputs = root / ".dlv" / "inputs"
            environment = inputs / "final-environment.json"
            environment.write_text(json.dumps(ENV_SPEC), encoding="utf-8")
            (inputs / "runtime-observation.json").write_text(
                json.dumps({"draft_count": 0, "http_status": 200}), encoding="utf-8"
            )
            start(feature_id, root, "run-001", [f"ENV-01={environment}"])
            result = inputs / "final-result.json"
            anchor = inputs / "final-anchor.log"
            anchor.write_text("deterministic boundary observation\n", encoding="utf-8")
            result.write_text(json.dumps({
                "po_id": "PO-01", "proof_type": "boundary", "outcome": "evaluate",
                "anchors": [str(anchor)],
            }), encoding="utf-8")
            self.assertEqual("EVID-0001", record(feature_id, root, "run-001", result, []))
            finalized = subprocess.run(
                [sys.executable, str(SCRIPTS / "finalize_delivery.py"), feature_id, "--root", str(root)],
                capture_output=True, text=True,
            )
            self.assertEqual(0, finalized.returncode, finalized.stdout + finalized.stderr)
            self.assertIn("DELIVERY COMPLETE", finalized.stdout)
            independent = subprocess.run(
                [sys.executable, str(SCRIPTS / "validate_feature.py"), feature_id, "--root", str(root), "--final"],
                capture_output=True, text=True,
            )
            self.assertEqual(0, independent.returncode, independent.stdout + independent.stderr)
            self.assertIn("DELIVERY COMPLETE", independent.stdout)

    def test_finalizer_cli_failure_rolls_back_generated_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root, "finalizer-cli-failure")
            record("finalizer-cli-failure", root, "run-001", result_file(root), [])
            before = state_path.read_text(encoding="utf-8")
            report_path = state_path.parent / "verification.md"
            before_report = report_path.read_text(encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(SCRIPTS / "finalize_delivery.py"), "finalizer-cli-failure", "--root", str(root)],
                capture_output=True, text=True,
            )
            self.assertEqual(1, completed.returncode)
            self.assertEqual(before, state_path.read_text(encoding="utf-8"))
            self.assertEqual(before_report, report_path.read_text(encoding="utf-8"))

    def test_finalizer_binds_run_and_generated_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root, "finalizer-test")
            record("finalizer-test", root, "run-001", result_file(root), [])
            ok = subprocess.CompletedProcess([], 0, "VALID\n", "")
            with patch.object(finalize_delivery, "validate", return_value=ok), patch(
                "sys.argv", ["finalize_delivery.py", "finalizer-test", "--root", str(root)]
            ):
                outcome = finalize_delivery.main()
            _, state = extract_state(state_path)
            errors: list[str] = []
            validate_finalization(state, errors)
            self.assertEqual(0, outcome)
            self.assertEqual("completed", state["stages"]["verification"]["status"])
            self.assertEqual("PASS", state["stages"]["verification"]["verdict"])
            self.assertEqual([], errors)
            self.assertIn("EVID-0001", (state_path.parent / "verification.md").read_text())

            original_token = finalization_token(state)
            state["quality_reviews"]["product"] = {"record_sha256": "a" * 64}
            self.assertNotEqual(original_token, finalization_token(state))
            review_tamper_errors: list[str] = []
            validate_finalization(state, review_tamper_errors)
            self.assertTrue(any("token is stale" in error for error in review_tamper_errors))

            state["stages"]["verification"]["finalization"]["finalized_at"] = "2099-01-01T00:00:00Z"
            tamper_errors: list[str] = []
            validate_finalization(state, tamper_errors)
            self.assertTrue(any("token is stale" in error for error in tamper_errors))

    def test_finalizer_restores_state_and_report_when_validation_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root, "finalizer-rollback")
            record("finalizer-rollback", root, "run-001", result_file(root), [])
            report_path = state_path.parent / "verification.md"
            report_path.write_text("user prior report\n", encoding="utf-8")
            original_state = state_path.read_text(encoding="utf-8")
            failed = subprocess.CompletedProcess([], 1, "INVALID\n", "")
            with patch.object(finalize_delivery, "validate", return_value=failed), patch(
                "sys.argv", ["finalize_delivery.py", "finalizer-rollback", "--root", str(root)]
            ):
                outcome = finalize_delivery.main()
            self.assertEqual(1, outcome)
            self.assertEqual(original_state, state_path.read_text(encoding="utf-8"))
            self.assertEqual("user prior report\n", report_path.read_text(encoding="utf-8"))

    def test_finalizer_preserves_concurrent_edits_on_failed_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, _ = prepare(root, "finalizer-concurrent")
            record("finalizer-concurrent", root, "run-001", result_file(root), [])
            report_path = state_path.parent / "verification.md"
            calls = 0

            def concurrent_validate(*_args: object) -> subprocess.CompletedProcess[str]:
                nonlocal calls
                calls += 1
                if calls == 1:
                    state_path.write_text("CONCURRENT STATE UPDATE\n", encoding="utf-8")
                    report_path.write_text("CONCURRENT REPORT UPDATE\n", encoding="utf-8")
                    return subprocess.CompletedProcess([], 1, "INVALID\n", "")
                return subprocess.CompletedProcess([], 0, "VALID\n", "")

            with patch.object(finalize_delivery, "validate", side_effect=concurrent_validate), patch(
                "sys.argv", ["finalize_delivery.py", "finalizer-concurrent", "--root", str(root)]
            ):
                outcome = finalize_delivery.main()
            self.assertEqual(1, outcome)
            self.assertEqual("CONCURRENT STATE UPDATE\n", state_path.read_text(encoding="utf-8"))
            self.assertEqual("CONCURRENT REPORT UPDATE\n", report_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
