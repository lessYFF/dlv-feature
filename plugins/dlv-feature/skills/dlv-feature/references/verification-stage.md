# 验证阶段

## 目标与输入

独立判断实际实现是否满足批准行为和技术合同，不把计划报告为通过。只从变化批次和 `AC/EX/R/T/B/BP` 开始，沿缺失断言、调用/依赖、事实所有权或失败测试关系扩展。

## 计划与执行

1. 建立 `AC/EX/R/T/B/CONTRACT/SHAPE/BP → exact check → EVID-*` 追踪；逐项枚举，禁止 ID 范围。
2. 优先 P0 核心验收、授权、数据完整性、公共合同和关键回滚；选择最强且不重复的单元、合同、API/集成、浏览器、build/static 或人工层。
3. 每次执行生成唯一 `EVID-*`：精确覆盖、环境、命令/可复现步骤、退出码、状态、具体观察结果和锚点。环境不可用是 gap，不是 pass。
4. 每个 `BP-*` 以真实角色执行 direct API/真实入口负向路径：缺 action permission、缺 entity/product-line permission、适用的错数据范围/租户/生命周期；断言 Service not invoked 或 zero write，以及 denied payload 不含 sensitive fields。
5. 适用 lineage 的 BP 执行来源扰动：source mutation、draft mutation、recomplete/history 后分别断言选择的完成快照；禁止以来源当前对象替代。
6. 前端验证 UI shape、导航、状态、可访问性、错误/加载/空状态；跨系统证据必须串联真实输入输出。
7. 审查完整 diff 的 Truth、Context、Simplicity、Boundary Proof、安全和稳健性。

## 裁决

`PASS` 仅在 P0 与必需 P1 有 fresh `EVID-*`、每个适用 `BP-*` 有通过的 direct/runtime 证据、无阻断失败/不安全残余时成立；`CONDITIONAL` 只允许有界非关键人工/环境项；其余为 `BLOCKED`。

按 `artifact-contracts.md` 写 `verification.md`。执行结果表固定为“证据｜覆盖｜环境｜命令或步骤｜状态｜退出码｜观察结果｜锚点”；每个上游 ID 映射 fresh `EVID-*` 或阻断说明。最终运行 `validate_feature.py`。
