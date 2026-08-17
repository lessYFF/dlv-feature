# 工作流与状态

## 阶段顺序与门

```text
需求复核 → PRD ↔ 原型实验（按需）→ 架构收敛预审 → 技术方案 → Code Spec → Code → 验证
```

| 阶段 | 进入条件 | 完成条件 |
|---|---|---|
| 需求复核 | 收到原始需求 | 用户确认目标、场景、IN/OUT、规则、UI 影响和待决问题 |
| PRD | 需求复核已确认 | 用户批准产品行为、业务规则和验收标准；原型支线收口 |
| 架构收敛预审 | PRD 已批准、现状已核验 | 用户批准事实所有权、Boundary Proof、隔离/并发/规则分派和材料决策 |
| 技术方案 | PRD 已批准 | PRD 全覆盖，适用流程/API/数据/质量/回滚完整 |
| Code Spec | 技术方案 fresh | 决策映射到文件、符号、规则、测试和有界批次并获批准 |
| Code | Code Spec 已批准 | Scope Gate 获批，完成实现与计划—实际核对 |
| 验证 | Code 结果已知 | fresh 证据支持 PASS、CONDITIONAL 或 BLOCKED |

材料改变产品范围、公共合同、数据迁移、安全、运行成本或回滚安全时暂停确认；普通可逆技术细节不得制造额外会议。

## 状态、失效与恢复

需求复核确认前不得创建完整 PRD；修改阶段产物前标为 `in_progress`，只有通过出口门并存储指纹才可 `completed`。关键事实或授权缺失用 `blocked`，上游变化用 `stale`；`not_applicable` 只允许 Prototype。`architecture_review.status != completed` 时 Architecture 必须 pending/blocked 且无技术方案文件。

| 变化 | 必须失效 |
|---|---|
| 需求复核基线 | PRD、Prototype、Architecture、Code Spec、Code、Verification |
| PRD 产品行为或 UI 意图 | Prototype（适用）、Architecture、Code Spec、Code、Verification |
| 架构预审事实、BP 决策或材料决定 | Architecture、Code Spec、Code、Verification |
| 技术方案决策、数据或影响范围 | Code Spec、Code、Verification |
| Code Spec 规则、批次、写入范围或测试合同 | Code、Verification |
| Code 结果后的产品代码 | Verification；越界时 Code 也失效 |

保存 Requirement Review、Prototype、Architecture、Code Spec、Code、Verification 的直接输入 SHA-256 与仓库基线。Architecture Review 保存事实 owner、`BP-*`、新增举证、API 演进、隔离、并发、规则扩展性和材料批准。恢复时从最早 pending/in_progress/stale/blocked 项读取其产物、直接输入和引用锚点；不得从“看起来完成”推断批准。

只接受 `schema_version=5`。v4 不兼容：旧状态没有 Boundary Proof 所需的事实，禁止兼容读取、自动升级或沿用批准；继续交付必须按 v5 重新复核。

## 多仓库、上下文与语义链

一个需求只用一个协调目录。技术方案与 Code Spec 写明每仓库路径、基线、职责和验证命令，代码留在仓库内。默认预算：3 仓库、20 路径；每批 8 源码、4 测试/配置、1 hop、200 行失败摘录；超限按删除无关候选、拆批、有证据扩容的顺序。

```text
SRC → FR / BR / AC / EX
    → ARCH / FLOW / API / DATA / UI / IMPACT → BP
    → D / R / symbol / T / B → verification evidence
```

正式文档服务于决策，不服务于校验器外观。校验器阻断需求漂移、入口旁路、权限缺合取、字段泄露、错误版本/来源、未执行负向路径、假证据、未批准扩张、上下文超限和指纹失效。
