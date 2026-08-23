# Code Spec 阶段

## 目标

把 fresh 技术方案展开为文件、符号、规则、测试、批次和证明义务；实现者不重新发现产品行为或重做架构决策。

## 就绪检查

路径/符号必须 verified，或新路径为有父目录模式证据的 proposed；API、数据、UI、兼容和回滚合同完整；每个适用 `BP-*` 已复核并能落到具体文件、符号和断言；测试入口、命令与位置已知。否则返回上游。

## 实现映射

使用稳定 ID：`D01`、`R-D01-01`、`T-B01-01`、`B01`。每个 `ARCH/FLOW/API/DATA/UI/IMPACT` 映射仓库、路径、符号、变更类型、输入输出、校验/默认/错误、调用关系、副作用、产品 ID、规则和可观察测试结果。

每个 `BP-*` 必须映射到至少一个 `D/R/T/B`，并明确 exact route/symbol/Service guard、guard-before-write、直接 POST/已知 ID 入口、缺 action permission、缺 entity/product-line permission、适用的错租户/生命周期，以及 zero side effect。读取边界还必须断言 denied JSON 不含 sensitive fields；lineage 边界还必须断言 source perturbation、draft mutation、recomplete/history snapshot 的正确选择。不能以 UI 测试或“已有权限校验”代替。

接口映射到 DTO/Controller/Caller/Adapter；数据映射到 migration、Model/Entity、Repository、转换和测试；UI 映射到路由、组件、状态、handler、API 绑定和 shape 验证。沿用户入口展开一跳直接依赖，覆盖样式、helper、权限、配置与构建；未知跨切依赖是 gap，不以手工路径白名单假装闭合。

## Proof Contract

为每个 `AC/EX` 建立至少一个 `PO-*`，且精确选择一种证明类型：

| 类型 | 最低证明 |
|---|---|
| `visual` | 原型与实现使用相同终端、视口、状态、数据和字体截图；原型截图、实现截图、diff 截图、结构/禁止元素检查、关键几何和零未解释像素差异 |
| `runtime` | 在目标浏览器、开发者工具或真机执行用户动作并观察结果；原生副作用必须读取结果回证 |
| `boundary` | direct API/入口的允许与拒绝角色、zero write/service-not-invoked、投影与 lineage probe |
| `invariant` | 服务/数据库状态转换、跨事实一致性、租户和历史数据不变量 |
| `artifact` | build、目录隔离、配置、bundle、产物哈希、console/lifecycle 或发布健康 |

先定义可复用 `ENV-*`：`id/target/spec`。`spec` 是结构化运行时事实，并包含至少一个可执行 `preflight`（`id/argv`），不得只写 local/dev/test。再定义 `PO-*`：`id/product_ids/trace_ids/proof_type/surface/environment_id/critical/assertions`。每个 `ASRT-*` 使用 `description + oracle.kind + oracle.source + oracle.operator + oracle.expected`；source 以 JSON Pointer 从 recorder 保存的 `/command/*` 或 `/observation/*` 取实际值，`exists/absent` 可省 expected。禁止用自由文本 `expected` 或执行方自报 status 代替机器裁决。

一个 PO 只覆盖一个 persona 边界和一个主要副作用；若角色、状态或副作用需要不同 oracle，拆成多个 PO。核心 CTA、权限、安全、数据完整性和发布阻断项必须 `critical=true`，不能降级为人工或 conditional。`visual` 只能使用 `visual_bundle` 且 ENV runtime 必须是浏览器/开发者工具/设备；`runtime` 只能使用 `runtime_trace` 且必须回读 `/observation/result_readback`。Node/build 环境只能证明 artifact，不能自称 visual/runtime。

## 实现批次与对齐门

每个 `Bxx` 是唯一最小执行边界：目标（至少一条 `R-*` 和 `AC/EX`）、架构锚点、仓库与基线、候选路径、源码/测试必读、允许与排除范围、依赖深度、test-first red/green/回归命令、消费的 `BP-*` 精确断言、完成/回滚条件、Simplicity 合同和超限理由。默认预算 3 仓库、20 路径、8 源码、4 测试/配置、1 hop。

技术方案的每个影响项必须被消费；Code Spec 不得新增未复核的表、接口、组件、依赖、公共抽象或写入目标。每个 `BP-*` 必须进入至少一个 `Dxx`、`T-*` 和 `Bxx`；每个 `PO-*` 必须进入实现映射、测试规格和实现批次，`trace_ids` 必须精确枚举这些上游 ID。缺口返回上游并传播 stale。

写完 Code Spec 与 Proof Contract 草案后必须执行 Code Spec Coverage Review。finding 使用 `CSQ-*`，verdict 为 `PASS|REVISE|BLOCKED`。PRD、Prototype、Architecture risk 与 Proof Contract coverage 必须为 100%，`unmapped-changes` 必须为 0；任一 required check FAIL 或 open critical/major finding 禁止 PASS。fresh PASS 后运行 `seal_proof_contract.py`；Code Spec、草案或任一绑定输入变化会使 review 与 seal stale，必须重新复核，seal 后合同不可原地修改。
