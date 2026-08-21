# 产物合同

## 通用规则

产品/技术真值只持久化为 `state.md`、`prd.md`、`architecture-design.md`、`code-spec.md`、sealed `proof-contract.json`、适用的 `prototype.html`；`verification.md` 是生成视图。运行证据只放 `.dlv/runs/{feature-id}/{run-id}/`。不创建平行 request/matrix/capsule/checklist/snapshot/test-plan 或手写 evidence ledger。所有 ID 精确枚举，禁止范围。

## state.md（schema v7）

状态块外只允许标题和维护提示。v7 的关键结构如下；完整 stage 形态以 `init_feature.py` 为准：

```json
{
  "schema_version": 7,
  "feature_id": "feature-id",
  "current_stage": "code_spec",
  "proof_contract": {
    "status": "completed",
    "code_spec_fingerprint": "<sha256>",
    "environments": [
      {
        "id": "ENV-01",
        "target": "postgres integration runtime",
        "spec": {
          "runtime": "postgres",
          "version": "16.4",
          "preflight": [
            {"id": "database-ready", "argv": ["pg_isready", "-h", "127.0.0.1"]}
          ]
        }
      }
    ],
    "obligations": [
      {
        "id": "PO-01",
        "product_ids": ["AC-01"],
        "trace_ids": ["BP-01", "R-D01-01", "T-B01-01", "B01"],
        "proof_type": "boundary",
        "surface": "POST /api/tasks/draft",
        "environment_id": "ENV-01",
        "critical": true,
        "runner": {
          "argv": ["python3", "tests/verify_task_kpi.py", "--json"],
          "cwd": ".",
          "observation_adapter": "json_stdout",
          "timeout_seconds": 300
        },
        "assertions": [
          {
            "id": "ASRT-01",
            "description": "草稿结果不进入完成 KPI",
            "oracle": {"kind": "json_path", "source": "/observation/draft_kpi_count", "operator": "eq", "expected": 0}
          }
        ]
      }
    ],
    "approval": {"approved_by": "product-owner", "reference": "review-message-42"},
    "sealed_at": "2026-08-21T10:00:00+08:00",
    "seal": "<sha256>"
  },
  "stages": {
    "verification": {
      "status": "in_progress",
      "active_run_id": "run-20260821-01",
      "run_digest": null,
      "evidence_count": 0,
      "evidence_head": "0000000000000000000000000000000000000000000000000000000000000000",
      "fingerprint": null,
      "verdict": null,
      "finalization": null
    }
  },
  "risks": [
    {
      "id": "RISK-01",
      "type": "residual",
      "severity": "low",
      "status": "accepted",
      "statement": "生产历史重复数据需发布前只读预检",
      "owner": "release-owner",
      "accepted_by": "product-owner"
    }
  ]
}
```

Proof Contract 的 seal 由 `seal_proof_contract.py` 基于除 seal 字段本身之外的完整合同（含 status、approval、sealed_at、runner）生成，同时写一次性 `proof-contract.json` 快照。state 与快照必须逐字段一致。seal 后任何 metadata、environment、PO、runner、trace 或 assertion 改动都会使合同无效；不能手工更新 seal 来掩盖变化，必须从 Code Spec 失效并重审。该本地 seal 是内容完整性锚，不是敌对写权限下的身份签名；需要抵抗能同步修改代码与全部本地产物的主体时，必须增加外部签名/远端 attestation。

风险只有一份结构化真值。`type=blocker|residual`，`status=open|mitigated|accepted|closed`；open blocker 阻断，accepted residual 必须有 `accepted_by`。

## 文档合同

PRD 标题为 `# {功能名} — 产品需求文档（PRD）`，维护 `SRC/FR/BR/AC/EX/US`。Architecture 标题为 `# {功能名} — 技术方案`，维护 `ARCH/FLOW/API/DATA/UI/IMPACT/BP`。Code Spec 标题为 `# {功能名} — 代码实现规格（Code Spec）`，维护 `D/R/T/B/ENV/PO/ASRT` 映射。三者均有目录、编号章节、精确追踪和批准指纹。

Architecture 的数据库章节必须用 fenced `sql` 写 DDL。列、类型、NULL/default、约束、FK、索引只能以 SQL 为结构真值；禁止 Markdown schema 表。例如：

```sql
ALTER TABLE sales_follow_up_task
    ADD COLUMN completed_at timestamptz;

CREATE INDEX idx_follow_up_completed_result
    ON sales_follow_up_task (completed_at, result_code)
    WHERE status = 'COMPLETED';
```

正文只补充事实所有权、快照、事务、锁、容量、迁移和回滚，不重复表格字段清单。

## Verification Run 合同

`.dlv/runs/{feature-id}/{run-id}/run.json` 由 start 命令创建，包含：schema/feature/run identity、创建时间、contract digest、code fingerprint、每个 ENV 的结构化 snapshot/digest、preflight 结果及其锚点哈希。run 不进入代码 fingerprint。

`evidence.jsonl` 仅由 record 命令 append，每行一个 canonical JSON object。result JSON 只提供 PO identity、`evaluate|blocked` outcome、可选 blocked reason 和额外 anchors；supersedes 只通过 record CLI 的 `--supersedes EVID-*` 参数声明。recorder 只能执行 sealed PO runner，并生成 `command/observation/status/assertion_results/previous_hash/record_hash`：

```json
{
  "schema_version": 7,
  "evidence_id": "EVID-0001",
  "po_id": "PO-01",
  "proof_type": "boundary",
  "status": "passed",
  "contract_digest": "<sha256>",
  "code_fingerprint": "<sha256>",
  "environment_id": "ENV-01",
  "environment_digest": "<sha256>",
  "command": {"argv": ["python3", "tests/verify_task_kpi.py", "--json"], "cwd": ".", "exit_code": 0, "stdout": "{\"draft_kpi_count\": 0}", "stderr": "", "timed_out": false},
  "assertion_results": [
    {"assertion_id": "ASRT-01", "status": "passed", "present": true, "actual": 0}
  ],
  "observation": {"draft_kpi_count": 0},
  "anchors": [
    {"path": "anchors/evid-0001-command.json", "sha256": "<sha256>", "size": 256},
    {"path": "anchors/evid-0001-observation.json", "sha256": "<sha256>", "size": 32}
  ],
  "supersedes": [],
  "previous_hash": "<sha256>",
  "record_hash": "<sha256>"
}
```

每个 PO 最终恰有一条 active evidence。failed/blocked 不可被后来的 PASS 默默覆盖；必须由同 PO 新 evidence 显式 `supersedes`。所有 skip 均禁止。每个 anchor 必须在 run 内存在且 hash 一致。manifest 逐条 hash-chain，state 保存 count/head；start/record/render/finalizer 统一按 feature lock → run lock 的顺序串行，recorder 在 append 前写 `pending-record.json`，中断后可确定性重放 manifest/state head，成功后删除 journal。命令默认 300 秒超时、保留的 stdout/stderr 各不超过 1 MiB并清理常见 secret；额外 anchor 最大 10 MiB，复制后权限为 `0600`。这些机制发现误编辑和普通重写，但不声称抵抗可同时修改 validator、state 和全部本地 artifact 的恶意主体。

## 生成报告与 Finalization

`verification.md` 固定由 bundle 渲染，包含 run/contract/code digest、计划—实际核对、证明义务、active evidence、assertion actual、anchor hash、结构化风险和当前裁决。它可删除重建，不能作为 evidence 输入。

`finalize_delivery.py` 是唯一完成入口：持有 `.run.lock` → 恢复 pending transaction → 验证 run → 写临时 PASS/run digest → 生成报告并 fingerprint → 完整 validate → 写 completed/token → 再 validate。任一步失败使用 compare-and-swap 回滚原 `state.md` 和 `verification.md`；检测到外部并发编辑时保留外部内容并明确报错。

## 硬门

- 合同：Code Spec fingerprint fresh，seal 匹配，AC/EX 全覆盖，ENV/PO/ASRT 结构完整。
- 环境：每个 ENV spec 精确匹配，所有 preflight 实际执行并通过。
- 代码：Git worktree fingerprint 与 Code result/run 完全一致。
- 证据：类型匹配、断言精确覆盖、active evidence 唯一、锚点存在且 hash 匹配。
- 边界：BP 的 direct negative/zero-side-effect/projection/lineage 进入 PO trace 和 assertion。
- 风险：无 open blocker；accepted residual 有批准人。
- 报告：仅由当前 run 生成，fingerprint 与 finalization token fresh。
