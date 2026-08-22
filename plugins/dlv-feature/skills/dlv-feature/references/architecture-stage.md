# 技术方案阶段

## 目标

先收敛事实所有权与关键边界，再展开详细方案。复用无需证明不能新增；新增必须证明不能安全复用或扩展。Code Spec 不得替本阶段做架构决策。

## 输入

- fresh `prd.md`、已复核原型（如适用）、仓库规则与架构/API/数据资料；
- 为证明现状所需的源码、schema、migration、测试和 Git 基线。

记录仓库与 commit 基线。搜索只产生 candidate；读源码才产生 verified 事实。

## 架构收敛检查

按以下顺序形成紧凑收敛包；这是技术方案的输入检查，不增加人工确认点：

```text
现状证据核验 → 事实所有权 → 复用/扩展/替换/新增裁决
→ Boundary Proof → 隔离/并发/规则扩展性 → 材料决定 → 详细方案
```

收敛检查必须回答：当前可复用能力与正典所有者；最小改动与第二事实源/双写风险；每个新增对象为何不能安全扩展现有事实与合同；以及数据隔离、并发旁路、规则分派和不可逆决策是否有缺口。材料决定用 `MAT-*` 逐项绑定 `ADD-*`，统一纳入 Architecture Risk Review。

## Boundary Proof Gate

当变更涉及角色/权限码/宽权限 helper、新产品线或生命周期、新增或扩展 API、导出/预览/记录/辅助读入口、响应含其他对象 ID 或元数据，或事实 owner、版本/来源选择改变时，必须 `applicable=true` 并创建 `BP-*`。仅纯展示文案且无上述边界时，可 `N/A`，但理由必须具体。

先用有界 `rg` 扫描 route annotation、public Service、sub-resource 读写、export/preview/record、权限 helper 全部调用点和已知 ID 辅助入口。搜索结果只作候选；逐个读源码后才进入 BP。

每个 `BP-*` 记录并证明：

- 受保护事实和其唯一 owner，映射的 `AC/EX`；
- 精确 `route + Controller/Service symbol + guard`；写操作的 Service guard 必须在首次 mapper/repository 副作用之前；
- 完整授权合取表达式，不得以“相关权限”或前端入口代替；
- 版本/来源 selector、正典 source 与明确禁止来源；
- 授权失败时安全返回字段和绝不返回的敏感字段；
- 至少两条可执行 probe，其中一条是 direct API/真实入口负向 probe；适用时覆盖错租户、错产品线、错生命周期、来源扰动或历史快照。

`BP-*` 同时取代旧的契约守恒、复用边界和任务链检查；不再使用 `CC/RB/MP`。它不要求平行清单：一个事实只保留一份能实际阻断旁路与泄露的证明。

## 新增举证、API 与三项预审

每个 `additions[]` 记录现有替代、不能复用原因、证据、第二事实源风险和裁决。表/link 表只用于独立事实、关系生命周期或关系属性；字段仅用于正典事实、明确冻结快照、不可按需计算的派生/缓存；API 仅用于新资源、新生命周期命令或本质不同授权/只读形态。仅产品类型不同默认服务端分派，禁止长期平行写入口。

涉及持久化、异步或多租户时落实租户来源、fail-closed、跨实体同租户验证、异步上下文与双租户测试。多写入口必须统一通过版本/If-Match、约束、事务与锁顺序，旧入口不可绕过。规则扩展只为当前至少两个真实变体引入 Policy；列出唯一分派点、稳定错误码与前后端边界。

## 详细设计与完成门

收敛检查通过后，技术方案必须覆盖 `FR/BR/AC/EX/US → ARCH/FLOW/API/DATA/UI/IMPACT`，明确事实所有者、快照时点、事务、迁移/回滚、失败模式和用户可见结果；适用时用流程/时序/状态图表达复杂关系。质量保障逐项消费 `BP-*`、隔离、并发与规则变体。

### 数据库章节硬约束

只要技术方案存在“6. 数据”章节，无论是否已分配 `DATA-*`，都必须用 fenced `sql` 展示实际或 proposed DDL，包括 `CREATE/ALTER TABLE`、列类型、NULL/default、PK/FK/unique/check、索引及必要注释。例如：

```sql
CREATE TABLE sales_follow_up_task (
    id bigint PRIMARY KEY,              -- 任务主键
    status varchar(32) NOT NULL,        -- 生命周期状态
    result_code varchar(64),            -- 完成结果码，可为空
    CONSTRAINT ck_task_result_requires_completion
        CHECK (result_code IS NULL OR status = 'COMPLETED')
);

CREATE INDEX idx_sales_follow_up_task_status_result
    ON sales_follow_up_task (status, result_code);
```

SQL 后用短段落说明正典、快照时点、事务、锁顺序、容量、迁移与回滚。禁止用 Markdown 的“字段｜类型｜约束”表格模拟 schema；ER/流程图可补充关系，但不能替代 SQL。校验器会硬阻断缺少 DDL 或出现 schema Markdown 表的技术方案。

SQL 只表达目标 schema，不展示可执行迁移程序。禁止 `DO`、`EXECUTE`、`LOOP`、tenant iteration、`INSERT/UPDATE/DELETE`、`CREATE/DROP SCHEMA` 或 migration 编号。每个字段必须有非空行内注释或 `COMMENT ON COLUMN`。

完成条件：输入 fresh；新增举证、隔离、并发、规则分派无 blocker；所有适用 `BP-*` 的入口、授权、lineage、projection 与 probe 完整且被技术方案消费；无第二事实源、fail-open 隔离、旧入口写旁路或散落规则。技术事实有仓库/基线/路径/符号锚点，新目标标为 proposed。

写完后必须执行 Architecture Risk Review。review 记录写入 `.dlv/reviews/{feature}/{run-id}.json`，finding 使用 `ARQ-*`，verdict 为 `PASS|REVISE|BLOCKED`。数据库改动、API 兼容、现有业务影响、授权/租户隔离与事实所有权五项 required check 必须逐项给证据；适用项不得 N/A，任一 FAIL 或 open critical/major finding 禁止 PASS。fresh PASS 自动进入 Code Spec；技术方案或任一绑定输入变化都使本 review 与下游 stale。
