# 工作流与状态

## 阶段顺序与门

```text
需求复核确认 → PRD ↔ 原型产品确认（按需）→ 架构收敛 → 技术方案 → Architecture Quality Review → 人工确认 → Code Spec + Proof Contract 草案 → Code Spec Quality Review → 人工确认/实现授权 → Seal → Code → Verification Run → 确定性收口
```

| 阶段 | 进入条件 | 完成条件 |
|---|---|---|
| 需求复核 | 收到原始需求 | 用户确认目标、场景、IN/OUT、规则、UI 影响和待决问题 |
| PRD | 需求复核已确认 | 用户批准产品行为、业务规则和验收标准；原型支线收口 |
| 架构收敛 | PRD 已批准、现状已核验 | 事实所有权、Boundary Proof、隔离/并发/规则分派和材料决策完整，无需单独人工门 |
| 技术方案 | PRD 已批准 | PRD 全覆盖；AQR fresh PASS；用户确认绑定方案指纹和 AQR run |
| Code Spec | 技术方案已确认 | 文件、符号、规则、有界批次、`ENV/PO/ASRT` 完整；CSQ fresh PASS；用户确认绑定 Code Spec、CSQ 和 Proof Contract 草案 |
| Code | Code Spec 确认并 seal，确认即授权约定范围 | 完成实现与计划—实际核对；越界先失效并重审 |
| 验证 | Code 结果已知 | fresh run 的 preflight 通过；每个 `PO-*` 恰有一条 active 证据并满足全部结构化断言 |
| 确定性收口 | Verification verdict=PASS | `finalize_delivery.py` 独占写入 completed 与 finalization token |

材料改变产品范围、公共合同、数据迁移、安全、运行成本或回滚安全时暂停确认；普通可逆技术细节不得制造额外会议。

## 状态、失效与恢复

需求复核确认前不得创建完整 PRD；修改阶段产物前标为 `in_progress`，只有通过出口门并存储指纹才可 `completed`。关键事实、授权、环境或证据缺失用 `blocked`，上游变化用 `stale`；`not_applicable` 只允许 Prototype。`architecture_review.status != completed` 时 Architecture 必须 pending/blocked 且无技术方案文件。Proof Contract seal 后不可原地修改；Verification 的 PASS/completed 不得手工写入。

| 变化 | 必须失效 |
|---|---|
| 需求复核基线 | PRD、Prototype、Architecture、Code Spec、Code、Verification |
| PRD 产品行为或 UI 意图 | Prototype（适用）、Architecture、Code Spec、Code、Verification |
| 架构预审事实、BP 决策或材料决定 | Architecture、Code Spec、Code、Verification |
| 技术方案决策、数据或影响范围 | Architecture Quality Review/人工确认、Code Spec、Code、Verification |
| Code Spec 规则、批次、写入范围或 `ENV/PO/ASRT` | Code Spec Quality Review/人工确认、Proof Contract seal、Code、Verification |
| Code 结果后的产品代码 | Verification；越界时 Code 也失效 |
| 目标工具、浏览器、基础库、配置、网络或凭证 | 仅对应 ENV 的 run/evidence；产品合同不因此失效 |

保存 Requirement Review、Prototype、Architecture、Code Spec、Code 的直接输入 SHA-256 与仓库基线。Architecture Review 保存事实 owner、`BP-*`、新增举证、API 演进、隔离、并发、规则扩展性和材料批准。Verification 以 run ID、run digest 和 finalization token 引用 `.dlv/runs/`，不把证据复制进状态。恢复时从最早 pending/in_progress/stale/blocked 项读取其产物、合同、run 与引用锚点；不得从“看起来完成”推断批准。

每次恢复先运行 `invalidate_downstream.py`；用户修正已批准行为时用 `--from-stage` 指明最早变化层。只接受 `schema_version=8`。v7 用 `upgrade_v7_to_v8.py` 保守迁移；旧批准、quality PASS、Proof seal、手写 Verification 和完成裁决一律不沿用。中间校验成功输出 `VALID INTERMEDIATE`；只有 `validate_feature.py --final` 可输出 `DELIVERY COMPLETE`。

## 多仓库、上下文与语义链

一个需求只用一个协调目录。技术方案与 Code Spec 写明每仓库路径、基线、职责和验证命令，代码留在仓库内。默认预算：3 仓库、20 路径；每批 8 源码、4 测试/配置、1 hop、200 行失败摘录；超限按删除无关候选、拆批、有证据扩容的顺序。

```text
SRC → FR / BR / AC / EX
    → ARCH / FLOW / API / DATA / UI / IMPACT → BP
    → D / R / symbol / T / B → ENV / PO / ASRT + seal
    → RUN(contract + code + env + preflight) → append-only EVID + anchors
    → deterministic verdict
```

正式文档服务于决策，不服务于校验器外观。`PO-*` 只允许 `visual/runtime/boundary/invariant/artifact` 五类；按声明的用户结果选择最强证据，不能按最方便的工具降级。校验器阻断需求漂移、原型—实现偏差、入口旁路、权限缺合取、字段泄露、错误版本/来源、未执行真实任务、假证据、未批准扩张、上下文超限和指纹失效。
