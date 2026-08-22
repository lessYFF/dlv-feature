# PRD 阶段

## 目标

先复核需求理解，再把结果写成可验收的产品真值。不得直接从一句话脑补完整 PRD。

## 需求复核

1. 保存用户原始要求或忠实归一化，并分配 `SRC-*`。
2. 仅用产品资料和外部可见行为建立候选理解；默认不扫描实现代码。
3. 形成一份紧凑复核摘要：
   - 要解决的问题和目标；
   - 用户与核心场景；
   - IN / OUT；
   - 已确认规则和成功标准；
   - UI 影响：`visible / non_visible / none`；
   - 待决问题与推荐项（推荐不是事实）。
4. 来源变化时更新摘要；真实歧义保留 gap 并请求澄清，不能猜测。
5. 摘要与 PRD、原型或不做原型决定一起进入 Product Contract Review，不设置单独人工确认门。

## PRD 生成

1. 只消费需求来源和已解决的 gap，不增加产品行为。
2. 分配 `FR-* / BR-* / AC-* / EX-* / US-* / GAP-*`。
3. 每个关键行为覆盖正向、反向、边界和异常样例；确认的验收使用可观察 Given/When/Then。把可独立丢失的输入、选择、空值、错误、权限、状态和数据时点拆成独立 `AC-* / EX-*`，禁止用一个宽泛 AC 打包多个契约事实。
4. 未知字段、默认值、角色、限制、时区、时长、保留期和性能目标保留 gap，不采用常见做法脑补。
5. 构建 `SRC → FR → BR/N/A → AC/EX` 追踪并回指复核 ID；正文出现的每个 `SRC/FR/AC/EX` 必须在追踪节出现，不能只追踪主路径。
6. 按 `artifact-contracts.md` 写简洁中文标题；目录在正文之前；不生成第 0 章、矩阵或 N/A 章节。

## 原型支线

当 UI 影响为 `visible` 时，在 Product Contract Review 前读取 `prototype-stage.md`：

```text
PRD UI 初稿 ↔ 原型实验 → 差异收口 → 最终 PRD
```

原型不允许绕过需求复核，也不允许覆盖 PRD 产品真值。

## 质量门

阻断条件：

- 需求来源存在会改变实现的未决歧义；
- PRD 出现需求来源中不存在的产品行为；
- 目标、IN/OUT、关键角色或关键规则不清，会迫使架构猜测；
- `SRC-*` 缺少功能和验收覆盖；
- UI 可见但缺少 UI 需求或原型差异未收口；
- 正文包含第 0 章、适用性矩阵、Context Capsule、空章节或模板占位符。

非阻断 gap 必须有 Owner 和最晚解决点。

## Product Contract Review 与状态

运行 `quality_review.py product`，联合复核需求摘要、PRD 与 Prototype 或 `{status:not_applicable, prd_sha256}` 决定。required checks 必须覆盖全部 `SRC-*`、验收、原型状态、PRD/原型一致性与无新增范围；coverage PASS 必须为 100%，open critical/major finding 或任一 required check FAIL 都阻断。fresh PASS 自动完成 Requirement Review、PRD 与 Prototype 决定并进入 Architecture。任一绑定输入变化都使 Product Review 及下游 stale。
