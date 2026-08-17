# 代码实现阶段

## 目标与范围

使用最小上下文和受控写入执行已批准 Code Spec。写业务代码前展示仓库/基线、文件与符号、测试命令、配置或迁移影响、风险、排除范围和未决 gap，并取得明确 Scope Gate 批准。

## 分批实现

每批只加载自身、引用锚点、有界源码/测试和一跳依赖；复核事实冲突即返回上游。先写最小有效测试、运行 red（例外须批准）、写最小实现、运行目标与回归、只在范围内重构，并把实际文件/符号、red/green、质量审查和 diff 核对记录进 `verification.md`。

### Boundary Delta Audit

仅审当前 diff 与一跳依赖。若出现 Controller route、public Service、`||` 权限、`hasAny`/`canView`/`canEdit`、`require*Permission`、`sourceQuoteId`/`publishVersionId`、DTO 返回字段、export/preview/record 或辅助已知-ID入口，必须刷新关联 `BP-*`。未批准的新增边界返回 Code Spec/Architecture；不得靠测试名称补偿。

逐项复核 `BP-*`：每个 route 与直接入口均有完整授权合取；写 guard 在第一次 mapper/repository 副作用前；selector 使用批准的 owner/version/source；forbidden source 未被读取；denied projection 不含敏感字段。任何新旧入口可绕过时阻断。

写入集重叠、共享迁移顺序、共享生成文件或测试资源不隔离的批次不得并行。worker 只接收本批与允许路径，协调者统一写状态和核心产物。

## 简洁性与结果门

Delete、KISS、DRY、Responsibility、Dependency 必须逐项 `PASS/FAIL/N/A` 并有证据；单实现接口、一次性工厂、推测性扩展点默认失败，KISS 高于仪式化 SOLID。任一 FAIL 阻断 Code 完成。

完成时核对完整 diff 的越界修改、迁移安全、密钥、调试代码、未处理错误和 Boundary Delta；Code Spec 保持不可变，计划—实际差异放 verification。所有批次已执行、所有适用 BP 已核对且无阻断偏差，才可标记 `code=completed`。
