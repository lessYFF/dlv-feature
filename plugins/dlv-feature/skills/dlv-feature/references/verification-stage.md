# 验证阶段

## 目标与输入

独立判断实际实现是否满足 sealed Proof Contract，不把计划、关键词或手写报告当作证据。输入只有 fresh 产品/技术真值、代码指纹、`ENV/PO/ASRT` 合同、结构化风险和真实执行产物。

## Verification Run

1. 为每个 `ENV-*` 生成与合同 `spec` 完全一致的 JSON；其中 `preflight` 命令必须能核对目标工具、运行时、服务、端口或凭证可用性。
2. 用 `verification_run.py start` 创建唯一 run。脚本核对合同 seal、Git 代码指纹和环境 spec，并实际执行全部 preflight。validator 会从每个 contracted check 及其哈希锚点重算身份、argv、exit code 和状态，不信任顶层 PASS 汇总。失败形成 blocked run，不修改业务代码规避环境。
3. 按 PO 声明的 `visual/runtime/boundary/invariant/artifact` 强度执行完整任务。source、mock、build、DOM 存在不能代替更高层结果。
4. 命令的 `argv/cwd/observation_adapter/timeout_seconds` 固化在 sealed PO runner。每次执行的 result 只写 `po_id/proof_type/outcome/blocked_reason/anchors/supersedes`；禁止调用方替换命令或写 exit code、stdout/stderr、observation、status、skip 或 assertion_results。recorder 实际执行 sealed runner，从 stdout 解析 observation，再按 `ASRT-*` oracle source 计算断言与 PO 状态。
5. 只用 `verification_run.py record` 追加。脚本用跨平台 run lock 串行化 writer，限制执行时间和保留输出大小，清理常见 secret，分配 `EVID-*`、以权限 `0600` 复制有大小上限的锚点、记录 SHA-256，并通过 `pending-record.json` 写前日志完成 JSONL + state head 事务。进程中断后同一 result 重试会幂等恢复。禁止直接编辑 manifest。
6. 失败重跑不删除历史；新记录必须用 `--supersedes EVID-*` 明确替代同一 PO 的旧记录。未替代的 failed/blocked 与并存多条 active evidence 都阻止 PASS。

## 证明强度

- Boundary：真实角色执行 direct API/真实入口；覆盖缺 action/entity 权限、错租户/生命周期、zero write/service-not-invoked、denied payload 和适用的 lineage/source 扰动。
- Visual：批准原型与实现使用相同终端、视口、DPR、字体、数据和状态；结构/禁止元素零偏差，关键几何和感知 diff 有界。
- Runtime：执行完整用户动作并读取副作用；剪贴板、回跳、异步切换等必须回读结果。
- Invariant：观察数据库/服务状态和跨事实一致性，不只断言 HTTP 成功。
- Artifact：检查真实 build、输出隔离、配置、console、生命周期、bundle/性能或发布健康。

## 问题与风险

问题统一写入 `state.md -> risks[]`，字段为 `id/type/severity/status/statement/owner`；`type=blocker|residual`。open blocker 阻止 PASS。residual risk 只有 `mitigated/closed`，或带 `accepted_by` 的 `accepted` 才可收口。不要在 `verification.md` 中维护第二份风险真值。

## 裁决与报告

`validate_verification_evidence.py` 直接校验 run identity、sealed contract snapshot、contract/code/env freshness、sealed runner 一致性、preflight 逐项重算、hash-chain 与 state head、结构化断言重算、锚点存在性与哈希、PO 唯一 active evidence 和风险。`verification.md` 仅由 active in-progress run 在 feature/run 双锁内生成，可随时重建。本地 hash-chain 防普通篡改和误编辑；拥有代码、state、validator 与全部 artifact 写权限的恶意主体不在本地 proof kernel 的真实性威胁模型内，这类场景必须接外部签名或远端 attestation。

不要手填 PASS 或 completed。运行 `finalize_delivery.py`；它持有同一 run lock，先恢复中断事务，再独立计算 verdict、生成报告、写入 run digest/fingerprint/finalization token，并进行第二次完整校验。失败时只在文件仍等于 finalizer 自己最后写入内容时回滚，绝不覆盖并发编辑。`CONDITIONAL` 不是完成裁决。
