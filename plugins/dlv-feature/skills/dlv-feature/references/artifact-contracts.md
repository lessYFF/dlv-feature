# 产物合同

## 通用规则

只持久化 `state.md`、`prd.md`、`architecture-design.md`、`code-spec.md`、`verification.md` 与适用的 `prototype.html`。正式文档用简洁中文标题、目录在编号正文前；不创建 request/matrix/manifest/capsule/checklist/evidence sidecar。所有 ID 精确枚举，禁止范围。

## state.md

状态块外只允许标题和维护提示。仅接受下列 v5 形态；禁止兼容 v4：

```json
{
  "schema_version": 5,
  "feature_id": "feature-id",
  "current_stage": "prd",
  "requirement_review": {"status": "pending", "source_fingerprint": null, "confirmed_ids": [], "summary": null, "approved_at": null},
  "architecture_review": {
    "status": "pending",
    "inputs": {"prd": null, "prototype": null, "repositories": {}},
    "existing_capabilities": [], "fact_owners": [], "additions": [], "api_decisions": [],
    "isolation": {"applicable": false, "verdict": "N/A"},
    "concurrency": {"applicable": false, "verdict": "N/A"},
    "rule_variants": {"applicable": false, "verdict": "N/A"},
    "boundary_proofs": {
      "applicable": true,
      "reason": "新增计划团读取与导出边界",
      "proofs": [{
        "id": "BP-01", "fact": "完成快照导出", "owner": "PlanExportService",
        "product_ids": ["AC-01"],
        "authorization": "plan-product:view AND product.status=ACTIVE",
        "entrypoints": [{"route": "GET /api/products/{id}/plan-pdf-data", "symbol": "ProductController.planPdfData", "guard": "requireProductViewPermission before source read"}],
        "lineage": {"selector": "product.publishedVersionId", "source": "completed plan snapshot", "forbidden": ["sourceQuoteId current quote"]},
        "projection": {"safe_when_denied": ["403 without quote DTO"], "sensitive": ["cost", "client contact"]},
        "probes": ["direct GET without product permission returns 403 and no service read", "mutate source quote then verify PDF still selects completed snapshot"],
        "verdict": "PASS"
      }],
      "verdict": "PASS"
    },
    "material_decisions": [], "approved_at": null
  },
  "stages": {}, "blockers": [], "last_updated": "2026-01-01T00:00:00+08:00"
}
```

`architecture_review` 保存压缩裁决，不复制详细方案。每个 material `ADD-*` 必须由 `MAT-*` 的 `addition_ids` 精确批准。`boundary_proofs` 是唯一跨边界保证结构；一个 BP 覆盖事实 owner、入口、授权、lineage、projection 与实际 probe，不得恢复 `CC/RB/MP` 平行结构。

## PRD 合同

标题为 `# {功能名} — 产品需求文档（PRD）`。目录后按需使用：概述、背景、目标与范围、角色与场景、功能需求、业务规则、非功能需求、UI 需求、异常与边界、需求追踪。`SRC/FR/BR/AC/EX/US` 可追溯且不虚构未确认事实；可见 UI 必须有原型合同或明确不适用理由。

## 技术方案合同

标题为 `# {功能名} — 技术方案`。目录后按需使用：

1. 概述
2. 现状
3. 方案
4. 流程
5. 接口
6. 数据
7. 前端
8. 质量保障
9. 影响范围
10. 发布与回滚
11. 需求追踪

“现状”必须给出可复用能力、事实所有者、API/事务/权限边界和系统性缺口。“方案”包含 `ARCH-*`、复用/扩展/替换/新增裁决、被拒绝方案、材料批准和规则分派。“质量保障”逐项消费 `BP-*`，包括完整授权表达式、Service guard-before-write、version/source selector、forbidden sources、denied projection、direct negative probes、租户/并发/规则变体。`DATA-*` 明确正典/快照、冻结时点、事务、锁、约束、迁移与回滚；`IMPACT-*` 仅能标 `verified|proposed`。

## Code Spec 合同

标题为 `# {功能名} — 代码实现规格（Code Spec）`。目录后使用：概述、实现映射、后端实现、前端实现、接口与数据实现、规则与异常、测试规格、实现批次、变更控制。`Dxx/R-Dxx-xx/T-Bxx-xx/Bxx` 映射产品与架构 ID、路径、符号和最小写入范围。每个 `BP-*` 必须进入至少一个 D、R、T、B，并包含 direct API、缺权限、零副作用、投影与适用的来源扰动/历史快照精确断言。

## 验证合同

标题为 `# {功能名} — 测试与验收报告`。目录后使用：概述、范围与环境、计划—实际核对、质量门、执行结果、验收追踪、问题与风险、验收结论。执行结果表必须为：

| 证据 | 覆盖 | 环境 | 命令或步骤 | 状态 | 退出码 | 观察结果 | 锚点 |
|---|---|---|---|---|---|---|---|

每个 `EVID-*` 精确覆盖上游 ID。每个 BP 的 PASS 至少有 direct-entry/API/runtime 的 passed 证据，观察结果必须包含 HTTP/status、payload 字段、zero write/service-not-invoked 或 snapshot/source perturbation 的具体结果；禁止泛化 PASS 或 ID 范围。

## 五层硬门

- Truth：candidate/gap 不进入写入范围；技术事实有锚点。
- Context：批次预算受控；超限有证据关系。
- Simplicity：Delete、KISS、DRY、Responsibility、Dependency 均通过或合理 N/A。
- Boundary Proof：每个关键 access/owner/lineage/projection/lifecycle 变化有完整 `BP-*`。
- Evidence Integrity：`EVID-*` 有精确命令/步骤、环境、退出码、观察结果与锚点。

直接输入变更以文件字节 SHA-256 使下游 stale。无批准或 verdict 为 BLOCKED 时不得跨阶段完成。
