# 配置参考

本页以当前 SecurityContext Java 0.3.4 源码读取的键为准。JVM system property 优先于同名环境变量；环境变量把小写点号和连字符转换为大写下划线，例如 `security.max.objects` 对应 `SECURITY_MAX_OBJECTS`。大多数配置在 exporter、请求状态或 SBOM 库存创建时读取，不能通过改 system property 热更新。pause、verification run 和例外是 `control.json` 的运行时控制，见[运行运维与 CLI](operations.md)。

## 加载扩展

```bash
java \
  -javaagent:/path/to/opentelemetry-javaagent-2.31.1.jar \
  -Dotel.javaagent.extensions=/path/to/securitycontext.jar \
  -Dsecurity.enabled=true \
  -Dsecurity.sbom.enabled=true \
  -Dsecurity.application.id=my-application \
  -Dsecurity.code.repository=https://example.invalid/repository \
  -Dsecurity.code.commit=git-commit \
  -Dsecurity.code.build-id=build-identifier \
  -jar application.jar
```

`otel.javaagent.extensions` 是 OTel Agent 的扩展入口；`security.*` 键由 SecurityContext 读取。未列出的键不会被该配置层使用。

## 功能、身份和路径

| 键 | 默认值 | 语义 |
| --- | --- | --- |
| `security.enabled` | `true` | 开关安全数据流采集和检测 |
| `security.sbom.enabled` | `true` | 独立开关 SBOM 发现与输出 |
| `security.instrumentation.exclude` | 空 | 逗号分隔的类名前缀，追加到内置排除规则，不是通用正则 |
| `security.application.id` | 根据 OTel Resource 的 namespace/name 生成 | 关联 finding、SBOM 和验证 run 的应用身份；显式值优先 |
| `security.code.repository` | 空 | 代码仓库标识；不配置时保持未知 |
| `security.code.commit` | 空 | 代码提交标识；不配置时保持未知 |
| `security.code.build-id` | 空 | 构建标识；不配置时保持未知 |
| `security.output` | `./security-output/<instanceUUID>` | findings、runs、health、control 的默认目录；instance UUID 每次进程启动生成 |
| `security.control.file` | `<security.output>/control.json` | 本地控制文件路径；CLI 使用 `--control` 时必须指向同一文件 |
| `security.evidence.file` | 未配置 | 配置后开启安全证据 JSONL；不写 `app-dependencies-loaded` 或 SBOM 诊断事件 |
| `security.evidence.file.max.bytes` | `10485760` | JSONL 当前文件轮转阈值 |
| `security.evidence.file.backups` | `3`（最多 20） | JSONL 轮转备份数 |
| `security.sbom.output` | `<security.output>/application.cdx.json` | CycloneDX 1.7 当前快照路径；显式路径优先 |
| `security.sbom.build.file` | 未配置 | 可选的构建期 CycloneDX 文件，作为声明依赖来源导入 |
| `security.sbom.build.artifact` | `external-build-sbom` | 构建 SBOM 声明组件的来源标签 |

`security.output` 与 `security.sbom.output` 会转为绝对路径。SBOM 历史文件固定写在当前 SBOM 文件的同一目录下，文件名为 `sbom-history.json`。默认目录名不是应用名，而是本次进程的 instance UUID。

## 规则开关

下列规则默认均为 `true`：

```text
security.rules.sql_injection.enabled
security.rules.command_execution.enabled
security.rules.command_injection.enabled
security.rules.path_traversal.enabled
security.rules.ssrf.enabled
security.rules.http_request_input.enabled
```

关闭规则只抑制对应证据，不改变业务调用、其他规则、运行计数或 SBOM。PreparedStatement 占位符参数绑定属于已建模的防护语义；污染的 SQL 模板在实际执行时仍可产生 SQL 证据。命令规则只对已识别的 POSIX `-c`、`-lc`、`-ec`、`-xc` 组合区分 shell 脚本文本和普通 argv；普通 argv、脚本文件以及 Windows cmd/PowerShell 本轮未运行验证。

## 请求、finding 和 run 上限

| 键 | 默认值 | 限制对象 |
| --- | ---: | --- |
| `security.max.active.requests` | `256` | 同时进行中的请求数；超过时跳过整个请求的安全采集预算 |
| `security.requests-per-second` | `1000` | 进程每秒请求预算；超过时跳过整个请求的安全采集预算 |
| `security.max.objects` | `4096` | 单请求对象身份登记数；所有 carrier 共用 |
| `security.max.tracked.bytes` | `1048576` | 单请求追踪表、字符串和传播节点的保守估算字节预算 |
| `security.max.process.tracked.bytes` | `67108864` | 进程内所有未关闭请求共用的追踪字节预算 |
| `security.max.nodes` | `8192` | 单请求传播节点数 |
| `security.max.findings` | `32` | 单请求证据条数 |
| `security.max.marks-per-object` | `64` | 单对象传播标记数 |
| `security.findings.max` | `4096` | process-local 聚合 finding 数 |
| `security.runs.max` | `256` | process-local verification run 数 |
| `security.runs.max.bytes` | `8388608` | 所有 run 的 finding/source/risk-source 计数项共用的估算字节预算 |
| `security.findings.sample.seconds` | `300` | 同一 finding 的代表样本最小周期；新 run 可立即产生样本 |
| `security.findings.flush.seconds` | `30` | finding 周期 summary 的刷新周期 |
| `security.findings.max.bytes` | `33554432` | 所有 finding 代表样本估算 JSON 字节上限 |
| `security.evidence.max.bytes` | `65536` | OTel/JSONL 单条序列化记录上限 |

finding 的聚合是 process-local：同一个 `finding_id` 在多个请求中累加 `occurrences`，代表样本默认保留首次、每 300 秒一次或新 run 的样本；周期 summary 默认每 30 秒发送一次。请求仍有独立的 `occurrence_id`/证据记录，不能用聚合计数代替请求级证据。达到容量时会增加 quality/health 计数并标记不完整，不阻塞业务。

run 计数项达到数量或总字节预算后，拒绝新增键，已有键继续累加；`run_counter_capacity_dropped`、run 的 `incomplete_requests` 和 health 会反映缺口。快照共享不变计数表，后续更新按表写时复制；序列化和文件提交不占用请求账本锁。字节预算是保留计数项的估算，不是整个进程的精确堆上限。Python 对应环境变量为 `SECURITY_RUNS_MAX_BYTES`，默认同为 8 MiB；health 的 `retention.run_counter_bytes_estimated` 和 `run_counter_bytes_max` 分别记录已用估算值和上限，该上限参与 Python `instrumentation_profile` 计算。

超过 active 或 per-second 请求预算时，整个请求进入 `budget_skipped`，不是只丢一个字段。HTTP 请求结束时，截断、coverage gap、预算跳过、暂停中断或导出损失会反映在 `security.collection.incomplete`、`health.json` 和 run 计数中。

Java 追踪表按对象身份使用弱引用，业务不再引用的中间值可以在请求结束前回收。字节预算包含字符串长度、登记元数据和传播节点的保守估算，不是 JVM 精确堆计量，也不限制业务自身分配。预算不足时拒绝新增追踪并标记不完整；请求关闭时释放剩余预算。两个字节预算均参与 `instrumentation_profile` 计算。

## SBOM 扫描上限

| 键 | 默认值 | 限制对象 |
| --- | ---: | --- |
| `security.sbom.max.components` | `10000` | 组件与历史记录上限 |
| `security.sbom.max.archive.bytes` | `67108864` | 单个嵌套归档读取上限 |
| `security.sbom.max.entries` | `100000` | 单次归档条目数上限 |
| `security.sbom.max.scan.bytes` | `536870912` | 一次扫描累计读取量 |
| `security.sbom.cache.seconds` | `300` | 制品解析缓存有效期 |
| `security.sbom.refresh.seconds` | `5` | 后台刷新间隔 |

缓存以 size、mtime 和 file key 形成指纹，最长 300 秒复用。替换已加载 class 的来源后，旧加载类与新制品可能无法唯一对应，库存会以 completeness reason 和 `unresolved` 状态表达，不把新文件哈希冒充旧类来源。

## 投递队列与字节预算

安全和 SBOM 使用独立的有界队列及后台线程，因此一侧拥塞不会直接占用另一侧队列：

| 键 | 默认值 | 语义 |
| --- | ---: | --- |
| `security.export.queue.size` | `1024` | 安全事件内存队列条数 |
| `security.export.sbom.queue.size` | `256` | SBOM 事件内存队列条数 |
| `security.export.security.events-per-second` | `100` | 安全 worker 每秒事件预算 |
| `security.export.security.bytes-per-second` | `524288` | 安全 worker 每秒字节预算 |
| `security.export.sbom.events-per-second` | `200` | SBOM worker 每秒事件预算 |
| `security.export.sbom.bytes-per-second` | `262144` | SBOM worker 每秒字节预算 |
| `security.export.close.timeout.millis` | `3000` | exporter 关闭的总等待上限，包含快照及两个 worker 的等待 |

队列满仍会增加对应通道的 `dropped`。安全事件超出每秒预算时丢弃；SBOM 事件可以放入单秒预算时，由后台等待下一预算窗口再发，记录 `sbom.budget_deferred`，不增加丢弃计数。单条事件本身大于每秒字节预算时仍拒收，避免永久阻塞队列；关闭超过总期限时未发送记录计入 `sbom.shutdown_pending`。这些等待不占用业务线程，也不阻塞安全通道。

`app-dependencies-loaded` 快照按 `security.evidence.max.bytes` 和 SBOM 每秒字节预算中的较小值分片，使用相同 `sbom_id`、`revision` 和 `part_count`。消费端必须收齐该修订的全部分片再替换库存。单条依赖或公共 envelope 都无法放入预算时报告快照发布失败，不将删减后的清单冒充完整快照。其他事件超出单条记录上限时仍使用 `security.export.truncated` 降级。文件写入是 flush 后写入，不做 fsync；API emit、Collector 接收和后端 ACK 仍是不同阶段。

关闭时由现有守护监控线程执行最终快照，调用方仅等待到统一截止时间；超时记录 `security.shutdown_failed`，待后台恢复后反映到 health，并保守地将已有请求的保留 run 标记为投递不完整。已阻塞的文件系统或 SDK 操作不能被强制取消，超时也不代表投递完成。控制路径必须指向普通文件。JVM shutdown hook 在 exporter 之前还会等待 SBOM 关闭，后者有独立的 3 秒上限。

## 输出、隐私与失败处理

`java/security-sbom` 的 `SbomInventory.publish` 负责 SBOM 临时文件和 atomic move；`java/security-exporter` 只负责 OTel Logs、安全证据 JSONL、有界队列和轮转。ArchiveScanner 能处理的扫描失败或超限会发布带 completeness reasons 的有效部分快照；publish/refresh 未处理失败时保留上一份有效 SBOM，并发出 `security.sbom.update_failed`。

默认输出只包含来源类型、字段名、传播关系、规则、代码位置、Span/Trace 关联、组件引用和完整性状态，不包含请求正文、完整 SQL、命令文本、URL 原文或命令参数值。证据和 SBOM 都是有界 process-local 观察，不是漏洞召回率或后端持久化保证。

更多字段语义见[证据与 SBOM 语义](evidence-and-sbom.md)和[schema v2 日志结构](security-context-log-schema.md)；当前 Java 0.3.4 的端到端验收结果必须以对应发行记录为准，不能由旧四 JVM 门禁推导。旧 0.2.1 与 candidate3 结果只作历史资料。
