# 产物合同

## 通用规则

产品/技术真值只持久化为 `state.md`、`prd.md`、`architecture-design.md`、`code-spec.md`、sealed `proof-contract.json`、适用的 `prototype.html`；`verification.md` 是生成视图。运行证据只放 `.dlv/runs/{feature-id}/{run-id}/`，质量审查记录只放 `.dlv/reviews/{feature-id}/{review-run-id}.json`。不创建平行 request/matrix/capsule/checklist/snapshot/test-plan 或手写 evidence ledger。所有 ID 精确枚举，禁止范围。

## state.md（schema v9）

状态块外只允许标题和维护提示。v9 的关键结构如下；完整 stage 形态以 `init_feature.py` 为准：

```json
{
  "schema_version": 9,
  "feature_id": "feature-id",
  "current_stage": "code",
  "quality_reviews": {
    "product": {
      "status": "completed",
      "review_run_id": "product-review-01",
      "artifact_sha256": "<sha256>",
      "proof_contract_sha256": null,
      "bound_artifacts": {"requirements": "<sha256>", "prd": "<sha256>", "prototype": "<sha256>"},
      "verdict": "PASS",
      "record_sha256": "<sha256>"
    },
    "architecture": {
      "status": "completed",
      "review_run_id": "architecture-review-01",
      "artifact_sha256": "<sha256>",
      "proof_contract_sha256": null,
      "bound_artifacts": {"architecture": "<sha256>", "architecture_review": "<sha256>", "product_review": "<sha256>", "prd": "<sha256>", "prototype": "<sha256>"},
      "verdict": "PASS",
      "record_sha256": "<sha256>"
    },
    "code_spec": {
      "status": "completed",
      "review_run_id": "code-spec-review-01",
      "artifact_sha256": "<sha256>",
      "proof_contract_sha256": "<sha256>",
      "bound_artifacts": {"code_spec": "<sha256>", "proof_contract": "<sha256>", "prd": "<sha256>", "prototype": "<sha256>", "architecture": "<sha256>", "architecture_review": "<sha256>", "risks": "<sha256>"},
      "verdict": "PASS",
      "record_sha256": "<sha256>"
    }
  },
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
    "quality_review": {
      "status": "completed",
      "review_run_id": "code-spec-review-01",
      "artifact_sha256": "<sha256>",
      "proof_contract_sha256": "<sha256>",
      "bound_artifacts": {"code_spec": "<sha256>", "proof_contract": "<sha256>", "prd": "<sha256>", "prototype": "<sha256>", "architecture": "<sha256>", "architecture_review": "<sha256>", "risks": "<sha256>"},
      "verdict": "PASS",
      "record_sha256": "<sha256>"
    },
    "sealed_at": "2026-08-21T10:00:00+08:00",
    "seal": "<sha256>"
  },
  "stages": {
    "code": {
      "status": "in_progress",
      "result": null
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

Proof Contract 的 seal 由 `seal_proof_contract.py` 基于除 seal 字段本身之外的完整合同（含 status、quality_review、sealed_at、runner）生成，同时写一次性 `proof-contract.json` 快照。state 与快照必须逐字段一致。seal 后任何 metadata、environment、PO、runner、trace 或 assertion 改动都会使合同无效；不能手工更新 seal 来掩盖变化，必须从 Code Spec 失效并重审。该本地 seal 是内容完整性锚，不是敌对写权限下的身份签名；需要抵抗能同步修改代码与全部本地产物的主体时，必须增加外部签名/远端 attestation。

风险只有一份结构化真值。`type=blocker|residual`，`status=open|mitigated|accepted|closed`；open blocker 阻断，accepted residual 必须有 `accepted_by`。

## 文档合同

PRD 标题为 `# {功能名} — 产品需求文档（PRD）`，维护 `SRC/FR/BR/AC/EX/US`。Architecture 标题为 `# {功能名} — 技术方案`，维护 `ARCH/FLOW/API/DATA/UI/IMPACT/BP`。Code Spec 标题为 `# {功能名} — 代码实现规格（Code Spec）`，维护 `D/R/T/B/ENV/PO/ASRT` 映射。三者均有目录、编号章节、精确追踪和复核指纹。

Architecture 的数据库章节必须用 fenced `sql` 写 DDL。列、类型、NULL/default、约束、FK、索引只能以 SQL 为结构真值；禁止 Markdown schema 表。例如：

```sql
ALTER TABLE sales_follow_up_task
    ADD COLUMN completed_at timestamptz; -- 实际完成时间，可为空

CREATE INDEX idx_follow_up_completed_result
    ON sales_follow_up_task (completed_at, result_code)
    WHERE status = 'COMPLETED';
```

正文只补充事实所有权、快照、事务、锁、容量、迁移和回滚，不重复表格字段清单。每个 column 必须有行内注释或 `COMMENT ON COLUMN`。DDL 只描述 schema，禁止 `DO/EXECUTE/LOOP`、tenant iteration、DML、schema create/drop 和 migration 编号等执行逻辑。

## Automated Quality Review

Product、Architecture 与 Code Spec review 使用独立 append-only JSON record。字段为 `review_type/review_run_id/reviewer/review_reference/reviewed_at/execution/verdict/artifact_sha256/proof_contract_sha256/bound_artifacts/findings/checks`。`execution` 必须声明 `mode=fresh_context|isolated_process`、provider、invocation ID、受项目根目录约束且同时绑定 run/invocation identity 的 transcript path 与 transcript SHA-256，例如：`{"mode":"isolated_process","provider":"codex-exec","invocation_id":"review-<random>","transcript_path":".dlv/reviews/feature-id/product-review-01.review-<random>.transcript.jsonl","transcript_sha256":"<sha256>"}`。finding 分别使用 `PRQ-n`、`ARQ-n`、`CSQ-n`，并包含 `severity=critical|major|minor`、`status=open|resolved`、`statement/evidence`。

每类 review 有固定 required checks；不得省略。coverage check 提供 `covered_ids`，内核从绑定产物独立推导期望 ID 并要求集合精确相等，且仅允许 `coverage_pct=100` 时 PASS；Architecture 的 `material-decision-coverage` 必须精确覆盖收敛状态中的全部 `MAT-*`。`unmapped-changes` 仅允许 `unmapped_count=0` 时 PASS。适用的数据库、API、授权/隔离或 Prototype 检查不得 N/A。任一 required check FAIL 或 open critical/major finding 与 PASS 互斥。Product review 绑定 Requirement Review、PRD 与 Prototype/不适用决定；Architecture review 绑定技术方案、收敛状态、Product review、PRD 与 Prototype；Code Spec review 绑定 Code Spec、Proof Contract 草案、Architecture review、risks、PRD 与 Architecture。state 只保存 record 摘要和 SHA-256；任一绑定输入变化后，本 review 与下游同时 stale。

## Verification Run 合同

`.dlv/runs/{feature-id}/{run-id}/run.json` 由 start 命令创建，包含：schema/feature/run identity、创建时间、contract digest、code fingerprint、每个 ENV 的结构化 snapshot/digest、preflight 结果及其锚点哈希。run 不进入代码 fingerprint。

`evidence.jsonl` 仅由 record 命令 append，每行一个 canonical JSON object。Verification record 自身继续使用独立的 schema v8；它不是 `state.md` 的 delivery schema。result JSON 只提供 PO identity、`evaluate|blocked` outcome、可选 blocked reason 和额外 anchors；supersedes 只通过 record CLI 的 `--supersedes EVID-*` 参数声明。recorder 只能执行 sealed PO runner，并生成 `command/observation/status/assertion_results/previous_hash/record_hash`：

```json
{
  "schema_version": 8,
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

Typed evidence 不得降级：`visual` 使用 `visual_bundle`，记录 viewport/DPR/font fingerprints/pixel diff/geometry diff/forbidden count，并为 `prototype_screenshot/implementation_screenshot/visual_diff` 各提供一个不同的非交错 8-bit PNG。recorder 解码两张截图，独立重算 pixel diff 与 geometry diff，并要求合同以 `eq 0` 裁决，不能信任 runner 自报。`runtime` 使用 `runtime_trace`，记录 runtime/action/result_readback；observation runtime 必须等于 sealed ENV runtime，唯一的 `runtime_trace` anchor 必须是与 runner-derived observation 完全一致的 JSON object。Node/build runtime 只能支撑 artifact proof。

## 生成报告与 Finalization

`verification.md` 从 Verification Run start 起固定由 bundle 渲染，pending 和 blocked 也必须存在。它包含 run/contract/code digest、计划—实际核对、证明义务、active evidence、assertion actual、anchor hash、结构化风险和当前裁决，可删除重建，不能作为 evidence 输入。

`finalize_delivery.py` 是唯一完成入口：持有 `.run.lock` → 恢复 pending transaction → 验证 run → 写临时 PASS/run digest → 生成报告并 fingerprint → intermediate validate → 写 completed/token → `validate_feature.py --final`。任一步失败使用 compare-and-swap 回滚原 `state.md` 和 `verification.md`；检测到外部并发编辑时保留外部内容并明确报错。普通成功只输出 `VALID INTERMEDIATE`，final 成功才输出 `DELIVERY COMPLETE`。

## 硬门

- 合同：Code Spec fingerprint fresh，seal 匹配，AC/EX 全覆盖，ENV/PO/ASRT 结构完整。
- 环境：每个 ENV spec 精确匹配，所有 preflight 实际执行并通过。
- 代码：Git worktree fingerprint 与 Code result/run 完全一致。
- 证据：类型匹配、断言精确覆盖、active evidence 唯一、锚点存在且 hash 匹配。
- 边界：BP 的 direct negative/zero-side-effect/projection/lineage 进入 PO trace 和 assertion。
- 风险：无 open blocker；accepted residual 有批准人。
- 报告：仅由当前 run 生成，fingerprint 与 finalization token fresh。
