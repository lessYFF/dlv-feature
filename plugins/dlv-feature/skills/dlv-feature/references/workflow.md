# 工作流与状态

## 阶段顺序与门

```text
需求复核 + PRD ↔ 原型 → Product Contract Review → 架构收敛与技术方案 → Architecture Risk Review → Code Spec + Proof Contract 草案 → Code Spec Coverage Review → Seal → Code → Verification Run → 确定性收口
```

| 阶段 | 进入条件 | 完成条件 |
|---|---|---|
| 需求复核与 PRD | 收到原始需求 | Product Review 对原始需求、PRD、原型/不做原型决定完成 100% 联合复核 |
| 架构收敛与技术方案 | Product Review fresh PASS、现状已核验 | Architecture Review 对数据库、API、现有业务、授权/租户隔离、事实所有权全部复核并 PASS |
| Code Spec | Architecture Review fresh PASS | 文件、符号、规则、有界批次、`ENV/PO/ASRT` 完整；Code Spec Review 100% 覆盖且零 unmapped change |
| Code | Code Spec Review fresh PASS 且 Proof Contract 已 seal | 完成实现与计划—实际核对；越界先失效并重审 |
| 验证 | Code 结果已知 | fresh run 的 preflight 通过；每个 `PO-*` 恰有一条 active 证据并满足全部结构化断言 |
| 确定性收口 | Verification verdict=PASS | `finalize_delivery.py` 独占写入 completed 与 finalization token |

真实需求歧义可暂停并请求澄清；日常复核不得制造人工确认门。

## 状态、失效与恢复

需求基线形成前不得创建完整 PRD；修改阶段产物前标为 `in_progress`，只有通过出口门并存储指纹才可 `completed`。关键事实、环境或证据缺失用 `blocked`，上游变化用 `stale`；`not_applicable` 只允许 Prototype。Architecture draft 可在 review `in_progress/blocked` 时保留为候选，但不得标记 completed 或进入 Code Spec；升级保留的 stale 候选同样不获信任。Proof Contract seal 后不可原地修改；Verification 的 PASS/completed 不得手工写入。

| 变化 | 必须失效 |
|---|---|
| 需求复核基线 | PRD、Prototype、Architecture、Code Spec、Code、Verification |
| PRD 产品行为或 UI 意图 | Prototype（适用）、Architecture、Code Spec、Code、Verification |
| 架构预审事实、BP 决策或材料决定 | Architecture、Code Spec、Code、Verification |
| 技术方案决策、数据或影响范围 | Architecture Risk Review、Code Spec、Code、Verification |
| Code Spec 规则、批次、写入范围或 `ENV/PO/ASRT` | Code Spec Coverage Review、Proof Contract seal、Code、Verification |
| Code 结果后的产品代码 | Verification；越界时 Code 也失效 |
| 目标工具、浏览器、基础库、配置、网络或凭证 | 仅对应 ENV 的 run/evidence；产品合同不因此失效 |

保存 Requirement Review、Prototype、Architecture、Code Spec、Code 的直接输入 SHA-256 与仓库基线。Architecture Review 保存事实 owner、`BP-*`、新增举证、API 演进、隔离、并发、规则扩展性和材料裁决。Verification 以 run ID、run digest 和 finalization token 引用 `.dlv/runs/`，不把证据复制进状态。恢复时从最早 pending/in_progress/stale/blocked 项读取其产物、合同、run 与引用锚点；不得从“看起来完成”推断复核通过。

每次恢复先运行 `invalidate_downstream.py`；产品行为变化时用 `--from-stage` 指明最早变化层。只接受 `schema_version=9`。v8 用 `upgrade_v8_to_v9.py` 保守迁移；v7 先升级到 v8，再升级到 v9。所有旧式批准、旧 quality PASS、Proof seal、手写 Verification 和完成裁决一律不沿用。

三个自动复核记录必须来自独立 fresh context，完整列出 required checks、证据、finding 和 verdict，并绑定精确输入哈希。缺项、覆盖率不足 100%、unmapped change 非零、required check FAIL 或 open critical/major finding 都阻断 PASS。输入变化使本复核及下游 stale。中间校验成功输出 `VALID INTERMEDIATE`；只有 `validate_feature.py --final` 可输出 `DELIVERY COMPLETE`。

## 多仓库、上下文与语义链

一个需求只用一个协调目录。技术方案与 Code Spec 写明每仓库路径、基线、职责和验证命令，代码留在仓库内。默认预算：3 仓库、20 路径；每批 8 源码、4 测试/配置、1 hop、200 行失败摘录；超限按删除无关候选、拆批、有证据扩容的顺序。

```text
SRC → FR / BR / AC / EX
    → ARCH / FLOW / API / DATA / UI / IMPACT → BP
    → D / R / symbol / T / B → ENV / PO / ASRT + seal
    → RUN(contract + code + env + preflight) → append-only EVID + anchors
    → deterministic verdict
```

正式文档服务于决策，不服务于校验器外观。`PO-*` 只允许 `visual/runtime/boundary/invariant/artifact` 五类；按声明的用户结果选择最强证据，不能按最方便的工具降级。校验器阻断需求漂移、原型—实现偏差、入口旁路、权限缺合取、字段泄露、错误版本/来源、未执行真实任务、假证据、未复核扩张、上下文超限和指纹失效。
