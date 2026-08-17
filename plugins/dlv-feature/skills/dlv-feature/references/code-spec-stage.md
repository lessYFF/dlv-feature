# Code Spec 阶段

## 目标

把 fresh 技术方案展开为文件、符号、规则、测试和批次级实现合同；实现者不重新发现产品行为或重做架构决策。

## 就绪检查

路径/符号必须 verified，或新路径为有父目录模式证据的 proposed；API、数据、UI、兼容和回滚合同完整；每个适用 `BP-*` 已批准并能落到具体文件、符号和断言；测试入口、命令与位置已知。否则返回上游。

## 实现映射

使用稳定 ID：`D01`、`R-D01-01`、`T-B01-01`、`B01`。每个 `ARCH/FLOW/API/DATA/UI/IMPACT` 映射仓库、路径、符号、变更类型、输入输出、校验/默认/错误、调用关系、副作用、产品 ID、规则和可观察测试结果。

每个 `BP-*` 必须映射到至少一个 `D/R/T/B`，并明确 exact route/symbol/Service guard、guard-before-write、直接 POST/已知 ID 入口、缺 action permission、缺 entity/product-line permission、适用的错租户/生命周期，以及 zero side effect。读取边界还必须断言 denied JSON 不含 sensitive fields；lineage 边界还必须断言 source perturbation、draft mutation、recomplete/history snapshot 的正确选择。不能以 UI 测试或“已有权限校验”代替。

接口映射到 DTO/Controller/Caller/Adapter；数据映射到 migration、Model/Entity、Repository、转换和测试；UI 映射到路由、组件、状态、handler、API 绑定和 shape 验证。

## 实现批次与对齐门

每个 `Bxx` 是唯一最小执行边界：目标（至少一条 `R-*` 和 `AC/EX`）、架构锚点、仓库与基线、候选路径、源码/测试必读、允许与排除范围、依赖深度、test-first red/green/回归命令、消费的 `BP-*` 精确断言、完成/回滚条件、Simplicity 合同和超限理由。默认预算 3 仓库、20 路径、8 源码、4 测试/配置、1 hop。

技术方案的每个影响项必须被消费；Code Spec 不得新增未批准的表、接口、组件、依赖、公共抽象或写入目标。每个 `BP-*` 必须进入至少一个 `Dxx`、`T-*` 和 `Bxx`，缺口返回 Architecture 并传播 stale。用户批准后记录指纹并进入 Code；批准不等于授权写业务代码。
