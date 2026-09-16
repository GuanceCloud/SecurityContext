# 运行运维与 CLI

SecurityContext 0.3.4 把进程内安全观察、SBOM 快照和验证控制放在同一个 output 目录，提供本地 `securityctl.py` 读取和控制。CLI 只操作本地 JSON 文件，不启动 HTTP 管理端口，也不替代后端持久化。当前版本的运行结论必须引用对应发行记录；[验证矩阵](verification.md)保留的是 0.2.1 历史记录，不能用于证明 0.3.4。自有快照和 CLI 报告带顶层 `source=security_context`，控制/报告自身 schema 可以保持 v1。

## 输出目录

默认目录由 `security.output` 决定，默认值为 `./security-output/<instanceUUID>`。常见文件如下：

| 文件 | 内容 | 写入者 |
| --- | --- | --- |
| `health.json` | 当前配置、有效状态、请求计数、质量、投递阶段、SBOM 状态 | exporter 的 RuntimeLedger |
| `findings.json` | 按稳定 `finding_id` 聚合的 finding、代表样本、occurrences 和 triage | RuntimeLedger |
| `runs.json` | 验证 run 的条件、请求/source/sink 计数、finding_counts、损失和关闭状态 | RuntimeLedger |
| `control.json` | pause、run、例外和 revision；CLI 写入，agent 轮询应用 | CLI/agent |
| `application.cdx.json` | CycloneDX 1.7 当前 SBOM | security-sbom 的 SbomInventory |
| `sbom-history.json` | 组件 added/updated/removed 的 process-local 历史 | security-sbom |

SBOM 输出默认跟随 `security.output`；显式 `security.sbom.output` 时，history 文件写在该 SBOM 文件的 sibling 路径。安全 JSONL 由 `security.evidence.file` 单独指定，不会因为启用 SBOM 而自动生成。

快照使用临时文件和 atomic move。SBOM archive scanner 遇到可表达的超限或读取失败时可以发布带完整性原因的有效部分；publish/refresh 未处理失败才保留上一份有效文件并增加 `update_failed`。这些文件是有界 process-local 状态，进程重启后不会自动读取为历史数据库。跨 instance 聚合应由后端按 `application_id` 与 `finding_id` 完成。

## 健康状态

`securityctl.py status` 直接读取 health 文件，并把超过 15 秒的快照标为 `stale`。常见 `health.status` 值：

- `disabled`：安全采集配置关闭；
- `paused`：控制文件暂停；
- `no_traffic`：进程尚未开始请求；
- `in_flight`：首个请求已经开始但仍在途；
- `incomplete`：出现请求预算跳过、coverage gap、截断或 finding 容量丢弃；
- `no_source_observed` / `no_sink_observed`：有请求但尚未观察到对应类别；
- `observed`：进程观察到了 source 和 sink，仍不等于漏洞召回率。

health 中的 `coverage_semantics` 是 `observed_counters_not_vulnerability_recall`，`coverage_scope` 是 `modeled_calls_only`。`counts`、`delivery.counters`、`snapshot_failures`、`queue_depth` 和 `quality` 都是实际观察到的计数；它们不能推导“已覆盖漏洞百分比”。active/per-second 请求预算超限会令请求状态为 `budget_skipped`，并在健康和 run 中保留计数。

投递状态按阶段解释：

1. 事件进入安全或 SBOM 内存队列；
2. 对应 worker 通过每秒事件/字节预算；
3. worker 调用 OTel LogRecord API，或 flush 本地安全 JSONL；
4. Collector 重试并向后端发送。

第 3 步的 API emit 不能确认 SDK、Collector 或后端 ACK。health 明确输出 `backend_acknowledgement=unknown`、`delivery_guarantee=bounded_best_effort_no_agent_replay` 和 `file_write_semantics=flushed_not_fsynced`。安全与 SBOM 使用独立队列和线程，拥塞时分别增加 channel 的 dropped/budget 计数。

## CLI

所有命令都以一个进程 output 目录为作用域。执行前将 `<instance-id>` 替换为实际进程目录名；全局参数 `--dir` 和 `--control` 放在子命令之前：

```bash
python3 scripts/securityctl.py --dir './security-output/<instance-id>' status
python3 scripts/securityctl.py --dir './security-output/<instance-id>' query findings
python3 scripts/securityctl.py --dir './security-output/<instance-id>' query findings --rule sql_injection
python3 scripts/securityctl.py --dir './security-output/<instance-id>' query runs --case sql-dynamic
python3 scripts/securityctl.py --dir './security-output/<instance-id>' query sbom
python3 scripts/securityctl.py --dir './security-output/<instance-id>' query history
```

`query` 支持 `findings`、`runs`、`sbom` 和 `history`，并支持 `--rule`、`--finding`、`--run`、`--case`、`--offset` 和 `--limit`。CLI 对输入 JSON 设有 128 MiB 读取上限，返回带 `total`、`offset` 和 `next_offset` 的分页结果。快照查询隐藏 `loss_start`、`snapshot_failures_start`、`last_sample_millis`、`sample_run_id` 等内部起始/采样计时字段；这是输出整形，不表示这些计数在运行时不存在。

### 暂停和恢复

```bash
python3 scripts/securityctl.py --dir './security-output/<instance-id>' pause
python3 scripts/securityctl.py --dir './security-output/<instance-id>' resume
```

CLI 写入带 UUID revision 的 `control.json`，随后等待 health 的 `control_revision` 确认，最长等待 10 秒。health 过期、agent 拒绝控制或超时都返回错误；超时只能说明动作没有得到确认，不能推断 agent 已执行或未执行。暂停不会卸载已经加载的字节码；重新启动并不加载本扩展时才会停止该进程的插桩。

### 受控验证 run

run 把指定 case、rule、suite、fixture 和 expected request 数量写入控制文件，生效范围是该进程在 run 期间的所有 HTTP 请求，因此必须隔离测试流量：

```bash
python3 scripts/securityctl.py --dir './security-output/<instance-id>' run-start \
  --case sql-dynamic \
  --rule sql_injection \
  --suite security-matrix \
  --fixture boot2-java8 \
  --expected-requests 1 \
  --ttl 300

# 只发送这一个 case 的预期请求
python3 scripts/securityctl.py --dir './security-output/<instance-id>' run-stop \
  --output ./run-sql-dynamic.json
```

run 关闭前会 drain active requests。run 记录包含 `source_requests`、`sink_requests`、`observations`、`incomplete_requests`、`error_requests`、`delivery_loss` 和 `snapshot_failures`。这些计数用于判断验证条件，不是生产漏洞统计。

HTTP Server Span 的 `security.finding.ids` 是聚合 finding ID，`security.evidence.ids` 是本次逻辑观察 ID。finding 代表样本按周期抑制时，occurrence 仍可能计数而没有对应的本地代表样本导出。

### 验证、比较和例外

baseline 与 candidate 必须是关闭的 run JSON，并且 case、rule、instrumentation profile、conditions 和 application identity 可比较。两套 run 的 `identity.code.repository`、`commit`、`build_id` 必须完整；工具不会猜测代码版本。验证命令：

```bash
python3 scripts/securityctl.py verify \
  --baseline ./baseline-run.json \
  --candidate ./candidate-run.json \
  --output ./verification.json
```

结果只有三种：

- `observed`：候选条件下观察到风险数据流；不表示攻击成功；
- `not_observed`：在指定 suite、fixture、请求数量、source/sink 计数和无损条件下没有观察到风险；不表示 fixed，也不表示完整覆盖；
- `inconclusive`：条件不可比、代码身份/请求门槛缺失、run 不完整、存在错误/投递损失或其他原因使负向结论不成立。

报告同时保留 `reasons`、baseline/candidate identity、finding counts 和 conditions；任何 reason 都必须随 outcome 一起审查，不能把 `observed` 解释成攻击成功或把快照变化解释成修复。baseline 的 `risk_source_signatures` 记录实际风险 evidence 的 `type|name`；candidate 必须在自己的 `source_signatures` 中重新观察这些签名并达到请求门槛。仅发送 Header 让 source 计数增加，或将常量 SQL 作为候选输入，不能替代 baseline 风险输入。缺少 baseline 风险签名或 candidate 未重观察时，负向结果是 `inconclusive`。

控制文件的错误必须与 revision 配对：CLI 只在 health 的 `control_error_revision` 等于本次控制 revision 时报告该操作被 agent 拒绝；旧 revision 的错误不会污染新操作。控制文件仍是本机信任边界。

验证只声明“在指定条件下观察到/未观察到”。静态 schema 校验、源码检查或单元测试不能直接替代真实 source/sink 请求验证。命令对 `inconclusive` 返回退出码 3，对参数/输入错误返回 2。

`compare` 只比较两个 findings 快照中的 finding ID 集合：

```bash
python3 scripts/securityctl.py compare \
  --before ./before-output \
  --after ./after-output
```

输出的 `not_observed_in_snapshot` 是快照成员消失，不是修复证明；finding fingerprint 含归一化 sink function 和源码位置行号，JDBC 代理统一到 `java.sql.Statement.<method>`，改行号可能导致新的 finding ID。例外只是一条带 reason、decision 和 expiry 的本地 triage annotation：

```bash
python3 scripts/securityctl.py --dir './security-output/<instance-id>' exception-add \
  --finding 'finding-<id>' \
  --decision accepted_risk \
  --reason "review reference and scope" \
  --ttl 86400
python3 scripts/securityctl.py --dir './security-output/<instance-id>' exception-remove \
  --finding 'finding-<id>'
```

`accepted_risk` 或 `false_positive` 不会隐藏采集、减少 occurrence、改变 source/sink 计数，也不是安全证明。

## Collector 投递

无持久化的调试 fixture：

```bash
docker --context orbstack compose -f deploy/docker-compose.collector.yml up -d
curl --fail http://127.0.0.1:13133/
```

带磁盘队列的示例：

```bash
export SECURITY_BACKEND_OTLP_ENDPOINT=https://collector-backend.example/v1/otlp
export SECURITY_BACKEND_AUTHORIZATION=
docker --context orbstack compose -f deploy/docker-compose.persistent.yml up -d
```

`deploy/otel-collector-persistent.yaml` 使用挂载卷的 `file_storage`、每个 pipeline 10000 个导出请求/批次的发送队列和无限时长重试（`max_elapsed_time: 0s`），并通过 `SECURITY_BACKEND_OTLP_ENDPOINT` 与可选的 `SECURITY_BACKEND_AUTHORIZATION` 发送 logs/traces。`queue_size` 的单位是 Collector 导出请求/批次，不是 10000 条日志。示例不使用 batch processor，避免额外的响应后内存窗口。它提供 Collector 侧的持久重试路径，但不能把 extension 的 OTel API emit 或 Collector 入队解释为后端 ACK。完整启动/停止说明见[Collector 部署示例](../deploy/README.md)。

## 安全边界

control 文件是本机信任边界，任何能写该文件的本地用户都能暂停、启动 run 或添加 triage annotation。CLI 不提供远程管理 API。证据和 SBOM 的默认隐私策略不输出请求值、完整 SQL、命令文本和 URL 原文；需要更宽留存策略时必须另行设计和验证。

## 升级

升级或回滚前停止应用，只替换部署实际引用的那一份扩展 JAR：归档包部署使用 `lib/securitycontext.jar`，独立部署使用根目录 standalone JAR；同一个应用不要同时加载两份。核对当前包的 `SHA256SUMS`，然后使用匹配的 OTel Java Agent 2.31.1 重启。运行中的 JVM 不会热加载替换后的 JAR；重启会创建新的 process-local instance，旧 output 需要按保留策略归档。旧 0.2.1 校验清单不能替代当前版本清单。
