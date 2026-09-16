# 需求追踪

本文追踪的接口版本为 **0.2.1**，属于历史记录，不代表当前 Java 0.3.4 的需求状态。`build/validation/v021/validation.json` 已记录本版冻结制品、单测、四腿矩阵和 product E2E 的 `pass` 结果；包外解包与官方 CycloneDX Schema 结果以发行目录的 `securitycontext-0.2.1-validation.json` 为准。旧 candidate3/0.2.0 结果只作为历史资料。强杀/主机故障恢复、trace 重放、Collector/WAL 和外部后端 ACK 保持为本轮未运行或明确未测边界。

状态含义：

- **接口已落盘**：源码存在相应字段、状态或控制路径；
- **测试阶段已通过**：2026-09-08 非 root OrbStack `user501:20` 的 `./gradlew --no-daemon test --offline --rerun-tasks` 返回 BUILD SUCCESSFUL，53 tests，0 failures/errors/skips；结果已与四腿矩阵和 product E2E 一并记录在 v0.2.1 证据中；
- **待验证**：仅用于尚未执行的后续验证项；本版已完成项不再使用此状态；
- **已验收**：对应版本的固定扩展和原始产物已完成行为闭环；旧 candidate3 只在历史章节使用此状态；
- **历史 baseline**：旧版本产物只用于说明此前已覆盖的范围；
- **边界**：计划明确不支持或必须保留为 incomplete/unresolved 的语义。

## 0.2.1 产品需求

| ID | 需求 | 代码/文档锚点 | 当前状态 |
| --- | --- | --- | --- |
| P-01 | stable `finding_id`、每请求 occurrence、按 finding/site 聚合、首次/周期/新 run 代表样本和周期 summary | `SecurityState.evidence`、`RuntimeLedger.end/tick`、[证据与 SBOM 语义](evidence-and-sbom.md) | 已验证：v0.2.1 四腿矩阵与 product E2E 在声明条件下完成账本、occurrence、run 和样本检查 |
| P-02 | 健康输出持续实际计数，明确 observed counters，不把计数解释为漏洞召回率 | `RuntimeLedger.health`、`health.json`、[运行运维与 CLI](operations.md) | 已验证：四腿和 product E2E 保留 observed counters、active=0 和 `coverage_semantics=observed_counters_not_vulnerability_recall` |
| P-03 | 区分 `observation`/`candidate_risk`、验证 outcome 为 `observed`/`not_observed`/`inconclusive`，验证仅在指定条件下成立，不写 fixed | `SecurityState.evidence`、`scripts/securityctl.py verify` | 已验证：product E2E 产生三种 outcome；同一受控演示进程和声明 fixture 内有效，不表示 fixed 或完整覆盖 |
| P-04 | 自包含证据带 code repository/commit/build、case/run、HTTP 上下文和 source/sink 计数；代码身份缺失保持 unknown | `Identity.context`、`RuntimeLedger`、[证据与 SBOM 语义](evidence-and-sbom.md) | 已验证：四腿 association 为 0 unresolved，product E2E 保留 7 条 evidence；`commit=product-e2e` 仅为 fixture 标签 |
| P-05 | SBOM application/release/instance 分层；重扫、重试、删除 delta、history、quality/freshness、build SBOM 合并和 unresolved | `SbomInventory`、`ArtifactCache`、`sbom-history.json` | 已验证运行时结构/关联与 CodeSource 边界；组件数为 26/24/48/48，官方 CycloneDX Schema 结果见包外验收报告，不完整依赖图仍按契约保留 |
| P-06 | 实例请求/事件/字节预算；安全与 SBOM 独立有界队列；control.json pause/run/exception | `RuntimeLedger.begin`、`EvidenceExporter`、`control.json` | 已验证：单测、四腿投递计数及 product E2E 的 pause/resume/exception/control 检查通过；后端 ACK 仍为 unknown |
| P-07 | 本地 CLI 查询/比较/验证、投递阶段语义、debug 与 Collector 持久队列示例 | `scripts/securityctl.py`、`deploy/docker-compose.persistent.yml`、[运行运维与 CLI](operations.md) | CLI、run、compare/verify 和本地投递语义已验证；本轮未重跑 Collector/WAL，trace 重放和外部后端 ACK 未测 |
| P-08 | `SecurityState.put` 读取 `StringBuffer.length` 不在状态锁内获取 buffer monitor，避免锁顺序倒置 | `SecurityState.put`、[架构与范围](architecture.md) | 已验证：Extension LockOrder 1 项及锁顺序/真实线程回归通过；锁顺序与 shell 选项共 7 个新增回归（1+6） |
| P-09 | 已识别 POSIX 组合短参数 `-lc`/`-ec`/`-xc` 的脚本文本识别，普通 argv/脚本文件不误判；Windows cmd/PowerShell 保留未运行验证边界 | `SinkRules.command`、[配置参考](configuration.md) | 已验证：SinkRules 6 个用例内含多种真实子进程组合；四腿 `/api/command/lc` 各记录 2 条 `command_injection`/`candidate_risk`/`shell_command`；Windows 未运行 |
| P-10 | SBOM 基础设施按 Agent 实际入口和扩展自身 CodeSource 排除，不按 `net.bytebuddy`/`io.opentelemetry` 包名前缀排除外层应用 Boot JAR | `SbomInventory.refresh`、[证据与 SBOM 语义](evidence-and-sbom.md) | 已验证运行时结构/关联：SBOM 20 项及 ByteBuddy 回归、四腿 0 unresolved 通过；官方 Schema 结果见包外验收报告 |

### 0.2.1 验收证据索引

当前索引指向实际 v0.2.1 证据；不能从旧目录推导本版状态：

- 制品、版本化 checksum 和包摘要：`build/validation/v021/artifacts.json`、`build/validation/v021/`；
- 四腿矩阵与样例：`build/validation/v021/verified_matrix/`、`build/validation/v021/example_fixture/`；
- 三项 P1 回归、CLI、开关、SBOM 和 product E2E：`build/validation/v021/` 下对应实际报告文件；Collector/WAL 本轮未重跑。

### 0.2.0 历史 candidate3 验收证据索引

以下路径是 0.2.0 candidate3 最终验收产物，仅用于历史追溯：

- 制品和扩展 SHA-256：`build/validation/v02-candidate3/artifacts.json`；
- Core 11 + RuntimeLedger 5：`build/validation/v02-candidate3/unit-test-counts.json`；SBOM 19：`build/validation/sbom/gradle-test-candidate.log`；Exporter 非 root 10：`build/validation/exports/candidate-results/`；
- 四腿路由、负对照、async、smoke、SBOM 关联：`build/validation/v02-candidate3-matrix-final/`；Boot3 Java 17/21 正常退出 ledger flush：`build/validation/v02-candidate3-matrix-finalflush/`；
- 产品 E2E 三种 verify outcome：`build/validation/product-e2e-v02-candidate3-boot2-java17/`；四项开关：`build/validation/v02-candidate3-switches/`；
- benchmark 和两份官方 CycloneDX schema 文件：`build/validation/benchmark/89550-1788783127/`、`build/validation/sbom/cyclonedx-candidate3-final-benchmark-validation.log`；
- Collector logs WAL 优雅停止/相同 WAL 重启重放：`build/validation/persistent-collector/run-06/summary.json`。该产物只有 `/v1/logs` 的 503→200 重放，trace 重放不在结论内。

### P-01 的 ID 和周期约束

`finding_id` 的 fingerprint 使用 application、rule、role、归一化 sink function、logical site 和 source signature；JDBC 代理统一归一为 `java.sql.Statement.<method>`，logical site 可包含文件行号，因此改行号可能形成新的 finding ID。它不应包含请求原文或 instance UUID。单次请求的 `evidence_id` 同时作为 `occurrence_id`，聚合 finding 只保留有界代表样本和 occurrences 计数。跨进程或重启聚合由后端按 application ID + finding ID 完成，output 文件不是历史数据库。

### P-02 的健康约束

`health.status`、`counts`、`delivery.counters`、`snapshot_failures`、queue depth、quality counters 和 SBOM completeness reasons 都必须解读为实际观察计数。健康页必须保留 `coverage_semantics=observed_counters_not_vulnerability_recall` 和 `coverage_scope=modeled_calls_only`。预算跳过、截断、coverage gap 和 export loss 不能被计为“无 finding”。

### P-03/P-04 的验证约束

验证 run 要求 suite、fixture、case、rule、expected requests、application identity 和完整 code 字段。baseline/candidate 必须 closed、可比较、source/sink 计数达到门槛且没有 incomplete/error/delivery loss/snapshot failure。baseline 还必须提供实际风险输入的 `risk_source_signatures`；candidate 需重新观察每个 `type|name`，不能以任意 Header 与常量 SQL 满足负向条件。结果 `not_observed` 只能说明指定条件下未观察到；`compare` 只是 snapshot membership comparison；例外 annotation 保留采集和计数，不是安全证明。控制错误仅在 `control_error_revision` 与当前控制 revision 相同才归属该操作。

### P-05 的 SBOM 约束

release identity 由 application identity 和 artifact digest 组成，不含路径和 process instance；CycloneDX serial/revision/content hash 仍标识具体 instance snapshot。运行时 classpath 扫描不猜 dependency edge，只有已导入构建 SBOM 的可解析声明边进入 dependencies，并保留 `runtime_dependency_graph_incomplete`。质量计数是实际字段数量，不是质量分数。

### P-06/P-07 的投递约束

安全默认 100 events/s、524288 bytes/s；SBOM 默认 200 events/s、262144 bytes/s；独立队列和 worker 不互相挤占。OTel API emit 不能确认 SDK/Collector/backend ACK，本地文件是 flush-not-fsync。control 文件是本地信任边界，CLI 不提供 HTTP 管理端口。持久化 Collector 示例只增加 Collector 到 backend 的磁盘重试路径，不能把 extension API 调用视为 ACK。

## 首版范围与 0.2.1 验证状态

下表保留原始计划要求的追踪摘要；v0.2.1 状态以本版实际证据为准，旧 candidate3 只在历史章节成立：

| 范围 | 原始要求 | 当前验收状态 |
| --- | --- | --- |
| 构建和兼容 | 独立 extension JAR、OTel Agent 2.31.1、extension API 2.31.1-alpha、Java 8 字节码、Boot2/3 与 javax/jakarta | 已验证：冻结 JAR SHA-256 `beee8448...f57677`、class major 52、四腿 Boot2/3 Java8/11/17/21；包外解包结果见发行目录报告 |
| Source 与传播 | 参数/Header/表单/JSON/body，身份与范围传播，Builder/indy/转换 | 已验证：四腿路由和 product E2E 在声明 fixture/条件下通过；无 class 资源动态类仍是盲区 |
| Sink | SQL、命令、SSRF、文件；参数化 SQL、已识别 POSIX 组合短参数、普通 argv/脚本文件、目标/path/query 边界 | 已验证：四腿路由、`/api/command/lc` 和 product E2E 对照通过；Windows cmd/PowerShell 未运行，URL 受控不代表响应受控 |
| 证据 | SecurityEvidence v1、trace/server/current span、OTel Logs、可选 JSONL、隐私 | 已验证：四腿 association 0 unresolved，product E2E 7 条 evidence；`commit=product-e2e` 仅为 fixture 标签 |
| SBOM | CycloneDX 1.7、JAR/Boot/WAR、元数据、哈希、嵌入 build SBOM、按实际 CodeSource 过滤基础设施、原子发布 | 运行时结构/关联已验证，组件 26/24/48/48；官方 Schema 与包验收见发行目录报告，不完整依赖图按契约保留 |
| 故障与边界 | Collector 不可用、队列/资源超限、业务透明、Windows cmd/PowerShell 和 WebFlux/跨服务等排除 | 单测、四腿与 product E2E 已验证声明范围；Collector/WAL、性能、Windows、强杀/主机恢复和外部后端 ACK 本轮未运行或未测 |

## 明确边界

- 无可读 class 资源的动态生成类跳过调用点预扫描；SBOM 的 CodeSource 观察不等于方法执行或数据流覆盖。
- 跨 instance finding 计数需要 backend 聚合；本地账本不提供历史数据库。
- runtime classpath 不猜测 dependency edge；无法解析的 build declaration 必须保持 incomplete/unresolved。
- exception annotation 不隐藏采集、不改变验证计数、不构成安全证明。
- OTel HTTP Server instrumenter 是请求状态前提；关闭整体 OTel SDK/HTTP instrumentation 不在保证范围。
- WebFlux、跨服务传播、响应结束后的后台任务、任意二进制请求体、反射/native 数据流、JDBC batch、XSS、反序列化、在线 CVE 和动态 attach 不在首版范围。
