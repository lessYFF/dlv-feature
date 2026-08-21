# 代码实现阶段

## 目标与范围

使用最小上下文和受控写入执行已批准 Code Spec 与 Proof Contract。Code Spec 人工确认已授权其绑定的实现范围，不再增加重复 Scope Gate。写业务代码前仍展示仓库/基线、用户入口的一跳依赖闭包、文件与符号、测试命令、配置或迁移影响、风险、排除范围和未决 gap；若实际范围超出确认边界，先使 Code Spec stale 并重审，不能自行扩张。

## 分批实现

每批只加载自身、引用锚点、有界源码/测试和一跳依赖；复核事实冲突即返回上游。先检查本批工具链，再写最小有效测试、运行 red（例外须批准）、写最小实现、运行目标与回归、只在范围内重构。实际文件/符号、red/green、质量审查和 diff 核对作为后续结构化 evidence 输入，不手写进 `verification.md`。环境失败标 blocked，不以业务改动兼容错误工具链。

### Boundary Delta Audit

仅审当前 diff 与一跳依赖。若出现 Controller route、public Service、`||` 权限、`hasAny`/`canView`/`canEdit`、`require*Permission`、`sourceQuoteId`/`publishVersionId`、DTO 返回字段、export/preview/record 或辅助已知-ID入口，必须刷新关联 `BP-*`。未批准的新增边界返回 Code Spec/Architecture；不得靠测试名称补偿。

逐项复核 `BP-*`：每个 route 与直接入口均有完整授权合取；写 guard 在第一次 mapper/repository 副作用前；selector 使用批准的 owner/version/source；forbidden source 未被读取；denied projection 不含敏感字段。任何新旧入口可绕过时阻断。

写入集重叠、共享迁移顺序、共享生成文件或测试资源不隔离的批次不得并行。worker 只接收本批与允许路径，协调者统一写状态和核心产物。

## 简洁性与结果门

Delete、KISS、DRY、Responsibility、Dependency 必须逐项 `PASS/FAIL/N/A` 并有证据；单实现接口、一次性工厂、推测性扩展点默认失败，KISS 高于仪式化 SOLID。任一 FAIL 阻断 Code 完成。

完成时核对完整 diff 的越界修改、迁移安全、密钥、调试代码、未处理错误、Boundary Delta 和 `PO-*` 可执行性；Code Spec 与已封存 Proof Contract 保持不可变。实际依赖超出批准闭包时使 Code Spec stale，不在 Verification 中补写理由绕过。所有批次已执行、所有适用 BP 已核对、每个 PO 仍可执行且无阻断偏差后，运行 `python3 <skill-dir>/scripts/delivery_proof.py repository-fingerprint <feature-id> --root <project-root>`，把输出写入 `stages.code.result.repository_fingerprint`，才可标记 `code=completed`。不得手填或复用旧指纹；`delivery/` 与 `.dlv/` 不进入代码指纹。
