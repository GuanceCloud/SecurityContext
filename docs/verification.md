# 验证矩阵与 0.2.1 验收协议

当前实现版本为 **0.2.1**。本版重建后的 `build/validation/v021/validation.json` 状态为 `pass`，覆盖冻结 JAR、单测、四腿注入矩阵和 product E2E；包外解包与官方 CycloneDX Schema 结果以发行目录的 `securitycontext-0.2.1-validation.json` 为准。强杀/主机故障恢复、trace 重放、Collector/WAL 和外部后端 ACK 仍属于本轮未运行或原型边界，不会被静态检查改写为已验证。

## 0.2.1 独立验证状态

最终 dist 独立验收已通过：[发行验收报告](../dist/securitycontext-0.2.1-validation.json)。在仓库外的含空格目录解包，139 个 tar/zip 文件的内容和权限一致；仅挂载发行包的 OrbStack Java 17 / Boot 2 启动、SQL 与命令正反例、SBOM 关联和正常停止均通过。运行时及包内样例 SBOM 均通过 CycloneDX 1.7 官方 Schema。该验收没有重跑 Collector/WAL、性能或 Windows。

下表记录本版实际完成的验证及对应证据，未重测范围单独注明。

| 范围 | 当前状态 | 证据 |
| --- | --- | --- |
| v0.2.1 固定制品与包清单 | 冻结扩展 JAR SHA-256 为 `beee844870986effd9795eefd687fd5b92768318bc5b9dd407cfd13563f57677`、自有 class major 为 52；`artifacts.json` 与 `validation.json` 已记录版本化样例/Agent 制品和四腿清单；归档、standalone JAR 与包外结果见发行目录验收报告 | `build/validation/v021/artifacts.json`、`build/validation/v021/validation.json` |
| 模块与回归测试 | 已通过：非 root OrbStack `user501:20` 执行 `./gradlew --no-daemon test --offline --rerun-tasks`，BUILD SUCCESSFUL；Core 11 + Exporter 10 + RuntimeLedger 5 + Extension LockOrder 1 + SinkRules 6 + SBOM 20 = 53 tests，0 failures/errors/skips。锁顺序与 shell 选项共 7 个新增回归（1+6，真实子进程与线程行为）及 SBOM ByteBuddy 回归均通过 | `build/validation/v021/unit-summary.json`、`build/validation/v021/validation.json` |
| 四腿真实注入矩阵 | 已通过：Boot 2 Java 8/11 各 55 条 dataflow、67/67 requests、active=0；Boot 3 Java 17/21 各 57 条 dataflow、71/71 requests、active=0；四腿 SBOM association 均 0 unresolved | `build/validation/v021/matrix-final/`、`build/validation/v021/validation.json` |
| 产品 E2E、开关与 CLI | 已通过：同一个受控演示进程完成 11/11 requests、active=0、health `observed`、current SBOM 24 components、7 条 evidence；SQL 参数化为 `not_observed`，同风险 positive 为 `observed`，风险 source 不匹配为 `inconclusive`；`commit=product-e2e` 仅为 fixture 标签，不是真实 Git commit 或跨版本修复证明 | `build/validation/v021/product-e2e/`、`build/validation/v021/validation.json` |
| POSIX shell 组合短参数 | 已通过：SinkRules 6 个用例，内含多种真实子进程组合；四腿各自 `/api/command/lc` 记录 2 条 `command_injection`、`candidate_risk`、`shell_command`；Windows cmd/PowerShell 未运行 | `build/validation/v021/matrix-final/*/evidence-routes.log`、`build/validation/v021/unit-summary.json` |
| SBOM CodeSource 过滤 | 已通过运行结构/关联范围：SBOM 20 项及 ByteBuddy 回归通过；四腿 association 均 0 unresolved，组件数依次为 Boot 2 Java 8=26、Boot 2 Java 11=24、Boot 3 Java 17=48、Boot 3 Java 21=48。各腿 `sbom-check.log` 不是官方 CycloneDX Schema 验证，官方结果见发行目录验收报告 | `build/validation/v021/matrix-final/`、`build/validation/v021/validation.json` |
| CycloneDX 与 Collector | 每腿 SBOM 结构/关联检查已通过；官方 CycloneDX Schema 结果见发行目录 `securitycontext-0.2.1-validation.json`。本轮未重跑 Collector/WAL | `build/validation/v021/matrix-final/`、发行目录外部验收报告 |

### 0.2.1 product E2E 结果

product E2E 在同一个受控演示进程和声明路由内完成 11/11 requests，active=0，health 为 `observed`，当前 SBOM 为 24 components，并产生 7 条 evidence。三种验证结果分别为：参数化 SQL `not_observed`、继续执行同一风险输入的 positive case `observed`、风险 source 不匹配 `inconclusive`。`repository=securitycontext-validation`、`commit=product-e2e` 和对应 build identity 是 fixture 身份；它们不是真实 Git 提交，也不构成跨版本修复证明。结果只适用于声明的 suite、fixture、请求门槛及 source/sink 计数。

### 0.2.1 验收协议

本版回填时至少保留以下判断边界：

- `SecurityState.put` 的锁顺序回归必须对应真实测试或运行证据；源码静态阅读只能标为静态检查。
- POSIX 只声明已识别的 `-lc`、`-ec`、`-xc` 组合短参数；普通 argv、脚本文件以及 Windows cmd/PowerShell 不得从本轮结果扩展为通用支持。
- SBOM 过滤必须以实际 Agent 入口和扩展 CodeSource 为证据；`net.bytebuddy`/`io.opentelemetry` 包名前缀不能单独作为外层 Boot JAR 排除理由。
- 矩阵、CLI、schema、Collector、benchmark 和包检查都必须引用 v0.2.1 原始产物；旧 0.2.0/candidate3 结果只能放在下方历史章节。
- 任何 benchmark 都只能作为当前测量环境的记录，不得写成生产容量、性能或 SLA 结论。

> **历史证据可用性说明（2026-09-08）**：Java 验证 agent 误执行 `scripts/orbstack_build.sh clean --offline`，导致源码仓库的 `build/validation/` 目录被删除。当前没有从 Time Machine 或本地快照恢复该目录；旧 dist 内的验证报告、manifest 和示例仍保留。下列旧日志路径仅作为历史索引，当前无法逐项复查，不表示原始日志已恢复或已重新验证。0.2.1 的任何结论必须由本次重新运行生成的 v0.2.1 证据支撑。

## 0.2.0 历史 candidate3 最终验收证据

以下内容完整保留以便追溯，但只描述 0.2.0 candidate3；它不构成 0.2.1 验收。

| 范围 | 结果 | 原始产物 |
| --- | --- | --- |
| 固定制品 | 扩展 JAR、Boot 2/3 样例和 SHA-256 已登记；扩展 JAR SHA-256 为 `3bcd81479425fdbf3303270aa4cb700201d8311edd6d7ce95bdcfe00cb7a9c73` | `build/validation/v02-candidate3/artifacts.json` |
| 单元测试 | Core 11 + RuntimeLedger 5 = 16 tests，SBOM 19 tests，Exporter 非 root 10 tests，合计 45；全部 0 failure、0 error、0 skipped | `build/validation/v02-candidate3/unit-test-counts.json`、`build/validation/sbom/gradle-test-candidate.log`、`build/validation/exports/candidate-results/` |
| 四腿真实矩阵 | `matrix-final` 的 Boot 2 Java 8/11、Boot 3 Java 17/21 路由证据、负对照、Servlet async、smoke 和 SBOM 关联全部通过；Boot 3 Java 17/21 的 `finalflush` 以正常退出完成 ledger flush 检查：两腿各自 43 started/43 completed、active=0，33 条 dataflow、33 行 finding、39 occurrences，SBOM 各 48 components、关联 33 records 且 0 unresolved。对应 `ledger-flush-check.log` 和 `evidence-association.log` 均通过。两个目录分别表示完整路由矩阵和聚焦正常退出统计，不能合并解读 | `build/validation/v02-candidate3-matrix-final/`、`build/validation/v02-candidate3-matrix-finalflush/` |
| 产品 E2E | baseline SQL 1 次 observation；参数化 candidate 0 次 observation，`not_observed`；positive candidate 为 `observed`；仅 Header 等不匹配 baseline 风险 source 时为 `inconclusive`。这验证了 `source_signatures`/`risk_source_signatures` 约束 | `build/validation/product-e2e-v02-candidate3-boot2-java17/` |
| 开关 | security-only、SBOM-only、SQL rule off、both off 四项通过 | `build/validation/v02-candidate3-switches/` |
| CycloneDX | 最终 benchmark 的两份应用 SBOM 通过官方 CycloneDX 1.7 JSON Schema；四腿矩阵的 `sbom-check.log` 仅作为每腿结构和关联检查，不能混称为官方 schema 日志 | `build/validation/sbom/cyclonedx-candidate3-final-benchmark-validation.log`、`build/validation/benchmark/89550-1788783127/` |
| 持久 Collector | 受控本地端点上的 `/v1/logs` 503 → 相同 file-backed WAL 优雅重启 → 200 重放通过；仅验证 logs，trace 重放、强杀/主机故障和外部后端 ACK 未验证 | `build/validation/persistent-collector/run-06/summary.json` |

### 产品 E2E 的验证结果

candidate3 产品目录同时保留三种结果：参数化 SQL 的 `not_observed`、继续执行同一风险输入的 `observed`，以及 baseline 风险输入缺失时的 `inconclusive`。结果只表示指定 suite、fixture、代码身份、请求门槛和 source/sink 计数下的观察，不表示 fixed、没有漏洞或完整覆盖。例外过期、pause/resume 和无流量的 `inconclusive` 也已保留在同一目录中。

### Benchmark

以下是一轮共享 OrbStack、Java 17、Spring Boot 2 的串行比较；每个模式 100 次预热、1000 次测量，每种模式只运行一次：

| 模式 | 启动时间 | 吞吐 | p95 | workload 后 RSS |
| --- | ---: | ---: | ---: | ---: |
| OTel only | 2.463 s | 1240.65 req/s | 1.344 ms | 575744 KiB |
| OTel + SBOM | 2.726 s | 1106.14 req/s | 1.546 ms | 570496 KiB |
| 全部安全能力 | 2.953 s | 916.04 req/s | 1.824 ms | 569824 KiB |

全能力模式记录 1100 requests、1100 sinks、1 finding、1100 occurrences、1099 个代表样本抑制、0 drops 和 0 `budget_skipped`。这些数值是该次小样本记录，不能推导容量、性能改善或 SLA；OTel API 和本地文件写入也不包含 Collector/外部后端确认。

benchmark 产物为 `build/validation/benchmark/89550-1788783127/` 和 `build/validation/benchmark/summary-candidate3-89550.json`。

## 0.2.0 历史验收协议

### 四版本注入矩阵

| 场景 | Java | 应用/Servlet | 需要在 0.2 run 中核对 | 状态 |
| --- | --- | --- | --- | --- |
| A | 8 | Spring Boot 2、javax | Java 8 Builder、HTTP source、四类 Sink、finding occurrence 和 run counters | 通过 |
| B | 11 | Spring Boot 2、javax | 注入、同步请求、客户端路由、SBOM component association | 通过 |
| C | 17 | Spring Boot 3、jakarta | indy 拼接、请求体绑定、DeferredResult、健康/预算/投递 | 通过；finalflush 已核对正常退出和 ledger flush |
| D | 21 | Spring Boot 3、jakarta | 现代客户端、SBOM revision/release/instance、验证结果 | 通过；finalflush 已核对正常退出和 ledger flush |

每个 run 必须显式记录 `case_id`、`rule`、`suite`、`fixture`、`expected_requests` 和完整代码身份（`repository`、`commit`、`build_id`）。run 同时累计一般 `source_signatures` 与实际风险事件的 `risk_source_signatures`；candidate 的负向结果必须重观察 baseline 风险输入的 `type|name`。测试流量必须独占该进程，因为 active verification run 覆盖该进程在有效期内接收的所有 HTTP 请求。

### Finding 账本和健康

验收需要同时检查：

- 同一 site 的 `finding_id` 跨请求稳定，单次请求保留 `occurrence_id`/evidence；
- `occurrences`、代表样本周期（首次/300 秒/新 run）和 30 秒 summary 的关系；
- active request 或每秒请求预算超限时整请求 `budget_skipped`，而不是把它当成无风险；
- `health.status`、`counts`、`coverage_scope=modeled_calls_only` 和 `coverage_semantics=observed_counters_not_vulnerability_recall`；
- finding 代表样本、JSONL、OTel LogRecord 和 SBOM component 的引用一致性；
- 重启后只保留新的 process-local instance，跨 instance 统计必须由后端用 application ID + finding ID 完成。

健康状态和 quality counter 只能表达实际观察计数，不能换算成漏洞召回率。

### 验证语义

用 CLI 产生 baseline/candidate run 后运行：

```bash
python3 scripts/securityctl.py verify \
  --baseline ./baseline.run.json \
  --candidate ./candidate.run.json \
  --output ./verification.json
```

`verify` 只接受三种结果：

| outcome | 可声明的内容 | 不可声明的内容 |
| --- | --- | --- |
| `observed` | 指定 suite、fixture、请求门槛下观察到风险路径 | 攻击已成功、漏洞一定可利用 |
| `not_observed` | 指定条件下没有观察到风险，且 source/sink/错误/投递门槛满足 | fixed、没有漏洞、完整覆盖 |
| `inconclusive` | 条件不可比或观察不完整 | 负向安全结论 |

baseline/candidate 必须有相同 case/rule/profile/conditions/application identity，代码字段完整、run 已关闭、请求数准确、source/sink 计数达到门槛、没有 incomplete/error/delivery loss/snapshot failure。baseline 必须产生实际风险 observation 和 `risk_source_signatures`；candidate 必须用 `source_signatures` 重新观察这些风险输入，否则负向结果为 `inconclusive`，而非成功的 `not_observed`。静态 schema、源码检查和单测不能替代实际 source/sink 请求验收。

### SBOM

0.2.0 candidate3 已在四腿和独立样例上核对：

- application、release、instance 三层身份；release identity 不含路径和 instance；
- `serialNumber/sbom_id`、revision、`content_sha256` 与证据中的 component `bom-ref` 同一已发布 snapshot；
- 普通 JAR、Boot nested JAR、WAR、动态 CodeSource、多位置、改名和同坐标异内容；
- `deployed`、`loaded`、`declared`、版本/PURL/哈希/许可证 quality counter；
- 仅导入构建 CycloneDX 的可解析 dependency edge；`runtime_dependency_graph_incomplete` 和 `aggregate=incomplete`；
- 300 秒 artifact cache、替换已加载来源后的 unresolved；
- 归档超限发布有效部分，publish/refresh 未处理失败才保留旧文件并产生 update_failed；
- 官方 CycloneDX 1.7 JSON Schema 是格式门槛；最终 benchmark 两份清单已通过，四腿矩阵使用结构检查和 evidence association 检查。

### 投递和故障

需要分别观察安全与 SBOM 队列：

- 安全 100 events/s、524288 bytes/s；
- SBOM 200 events/s、262144 bytes/s；
- queue full、budget exceeded、serialization/file/OTel API failure 的 counters；
- JSONL flush/not-fsync；
- OTel API emit 后 ACK 仍为 unknown；
- debug Collector 与 disk-backed persistent queue 的差异；
- Collector/backend 不可用时业务响应不受影响，但 run 必须把 delivery loss 保留下来。run06 证明 logs 在受控本地端点上的优雅停止/同 WAL 重启重放；不覆盖 crash、SIGKILL、主机/掉电，也没有单独验证 trace 重放或外部后端 ACK。

### 成本记录

成本报告已固定扩展 JAR、正式样例、Java/OrbStack、预热次数、请求数和串行方式。该 benchmark 只有一轮串行请求，不能推断容量、吞吐提升或 RSS 改善；启动、p95、RSS 和 queue/quality counters 仅作为该测量环境的记录。

## 0.1 历史 baseline 归档

下列路径属于之前 e604/da99 实现的基线资料，仅用于回溯旧能力；0.2.0 结论以 candidate3 产物为准：

| 内容 | 历史产物 |
| --- | --- |
| 扩展 JAR | e604 SHA-256：`e6044cbf5e8a5e1d6ad5c5c9b22fe7726ad7325dfa863fe82a9f04de189f9394` |
| 四腿逐请求证据 | `build/validation/matrix-final-20260907/` |
| 四腿 smoke/SBOM 关联 | `build/validation/matrix-final-ad40-20260907/` |
| body/raw/control 复核 | `body-e604-boot2-java8-171513/`、`body-e604-boot3-java21-171628/` |
| 并发和 DeferredResult | `concurrency-final-boot2-java17-170412/` |
| 旧开关验证 | `switches-e604-final2-20260907/` |
| 旧最终真实 SBOM schema | `build/validation/sbom/cyclonedx-e604-frozen-benchmark-validation.log` |
| 旧 benchmark | `build/validation/benchmark/32063-1788772754/summary.json` |

历史四腿曾覆盖 Boot 2 Java 8/11、Boot 3 Java 17/21 的请求体、SQL、命令、HTTP、文件、Servlet async 和旧 SBOM 关联；这些结果没有验证 0.2.0 新账本、health、run verify、控制文件、预算和 persistent queue 语义。历史 benchmark 也只是一轮共享 OrbStack 测量，不是容量结论。

## 当前边界

无可读 class 资源的动态生成类会跳过调用点预扫描；SBOM CodeSource 观察不等于调用点已插桩。请求状态依赖 OTel HTTP Server instrumenter。WebFlux、跨服务传播、响应结束后的任务、任意二进制请求体、反射/native 数据流、JDBC batch、XSS、反序列化漏洞、在线 CVE 查询、漏洞可利用性判断和动态 attach 仍不在范围内。
