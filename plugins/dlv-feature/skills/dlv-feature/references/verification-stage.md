# 验证阶段

## 目标与输入

独立判断实际实现是否满足批准行为和技术合同，不把计划报告为通过。只从变化批次和 `AC/EX/R/T/B/BP/PO` 开始，沿缺失断言、调用/依赖、事实所有权或失败测试关系扩展。

## 计划与执行

1. 建立 `AC/EX/R/T/B/CONTRACT/SHAPE/BP → PO → exact check → EVID-*` 追踪；逐项枚举，禁止 ID 范围。
2. 先执行目标环境 preflight，再按 `visual/runtime/boundary/invariant/artifact` 的声明结果选择证据；source、mock、build、DOM 存在不能替代更高层结果。
3. 每次执行生成唯一 `EVID-*`：证明义务、精确覆盖、证明类型、环境、`truth/code/env` 指纹、命令/可复现步骤、退出码、状态、具体观察结果和锚点。环境不可用是 blocked，不是 pass。
4. 每个 `BP-*` 以真实角色执行 direct API/真实入口负向路径：缺 action permission、缺 entity/product-line permission、适用的错数据范围/租户/生命周期；断言 Service not invoked 或 zero write，以及 denied payload 不含 sensitive fields。
5. 适用 lineage 的 BP 执行来源扰动：source mutation、draft mutation、recomplete/history 后分别断言选择的完成快照；禁止以来源当前对象替代。
6. `visual` 在相同终端、视口、DPR、字体、数据和状态下比较批准原型与实现：结构和禁止元素零偏差、关键几何阈值、感知 diff；动态区域只允许有界 mask。
7. `runtime` 执行完整用户任务并观察副作用；复制必须回读剪贴板，登录必须验证回跳上下文，切换/关闭必须验证旧异步结果不回填。
8. `artifact` 检查构建输出隔离、配置、console、生命周期、bundle/性能预算和发布健康；跨系统证据串联真实输入输出。
9. 审查完整 diff 的 Truth、Context、Simplicity、Boundary Proof、安全和稳健性。

## 裁决

`PASS` 仅在每个 critical `PO-*` 有类型匹配且指纹 fresh 的 passed `EVID-*`、每个适用 `BP-*` 有通过的 direct/runtime 证据、无阻断失败/不安全残余时成立。非关键项只可凭明确批准理由 skipped；其余为 `BLOCKED`。不再使用 `CONDITIONAL` 完成交付。

按 `artifact-contracts.md` 写 `verification.md`。执行结果表固定为“证据｜证明义务｜覆盖｜证明类型｜环境｜指纹｜命令或步骤｜状态｜退出码｜观察结果｜锚点”；每个上游 ID 与 PO 映射 fresh `EVID-*` 或阻断说明。先保持 Verification `in_progress` 并运行 `validate_feature.py`；verdict=PASS 后只能运行 `finalize_delivery.py` 收口。
