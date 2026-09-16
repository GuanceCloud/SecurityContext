# SecurityContext Java 0.3.4 使用指南

本指南随 `securitycontext-0.3.4` Java 发行包分发，可脱离源码仓库使用。`validation.json` 和 `manifest.json`、`SHA256SUMS` 是包内确定存在的制品记录；独立解包后的 `release-validation.json` 是 bundle `java/` 目录中与归档并列的可选发行验收报告，不放入 JAR/tar.gz/zip，避免验收归档形成循环。本指南不复制测试数字，也不把历史结果当作当前门禁结论。

## 1. 包结构与依赖

```text
securitycontext-0.3.4/
├── lib/
│   ├── securitycontext.jar
│   └── opentelemetry-javaagent-2.31.1.jar
├── bin/
│   ├── run-demo.sh
│   └── securityctl.py
├── examples/apps/
├── examples/observed/
├── collector/
├── docs/guide.zh-CN.md
├── docs/guide.en.md
├── validation.json
├── manifest.json
├── SHA256SUMS
└── licenses/
```

Java 扩展文件名是 `securitycontext.jar`，库命名空间为 `io.securitycontext.*`。扩展编译为 Java 8 字节码，目标运行时为 Java 8、11、17 和 21；配套 OTel Java Agent 为 `2.31.1`，extension API 为 `2.31.1-alpha`。包内 Agent 只是配套版本，若使用已有 Agent，必须让扩展和 Agent 的版本、校验清单来自同一包。

解压后先校验包身份：

```bash
shasum -a 256 -c SHA256SUMS       # macOS
sha256sum -c SHA256SUMS           # Linux
```

随后阅读包内 `validation.json` 中对应的实际结果；若 bundle 的 `java/` 目录提供了与归档并列的 `release-validation.json`，再用它核对独立解包和收件结果。缺少包内清单、校验和或 `validation.json` 时，不要把目录当作可复核发行包。

## 2. 最小启动

扩展必须和 OTel Java Agent 一起加载。已有 OTel Agent 时只追加扩展，不要启动第二个 Agent：

```bash
java \
  -javaagent:/absolute/path/to/lib/opentelemetry-javaagent-2.31.1.jar \
  -Dotel.javaagent.extensions=/absolute/path/to/lib/securitycontext.jar \
  -Dotel.service.name=orders \
  -Dsecurity.enabled=true \
  -Dsecurity.sbom.enabled=true \
  -Dsecurity.application.id=orders \
  -Dsecurity.output="$PWD/security-output" \
  -Dsecurity.evidence.file="$PWD/security-output/evidence.jsonl" \
  -jar application.jar
```

加载顺序是：JVM 启动 OTel Agent，Agent 加载 SecurityContext extension，HTTP Server instrumentation 建立请求上下文，应用再处理请求。没有 HTTP Server instrumentation 时仍可产生部分事件，但不能保证 request、`server_span_id` 和生命周期状态完整。

包内演示使用同一顺序：

```bash
./bin/run-demo.sh boot2
./bin/run-demo.sh boot3
```

`boot2` 和 `boot3` 只用于包内示例；实际支持组合和本次结果以随包 validation 文件为准。脚本默认将输出写到独立目录，也可以通过 `SECURITY_OUTPUT_DIR`、`DEMO_PORT` 和 `JAVA_BIN` 调整。

### 连接本地 Collector 并查看一次请求

包内 `collector/otel-collector-config.yaml` 使用 OTLP gRPC `4317`、OTLP HTTP `4318` 接收 traces/logs，经过 `memory_limiter` 和 `batch` 后写到 `debug` exporter，并在 `13133` 提供 health check。用与该配置匹配的 Collector 二进制启动：

```bash
otelcol --config collector/otel-collector-config.yaml
```

在另一个终端让应用把 traces/logs 送到 OTLP HTTP，并固定输出目录。以下使用演示代码身份；进行验证 run 前应替换为实际仓库、commit 和 build ID：

```bash
OUT="$PWD/output/otlp-demo"
java \
  -javaagent:"$PWD/lib/opentelemetry-javaagent-2.31.1.jar" \
  -Dotel.javaagent.extensions="$PWD/lib/securitycontext.jar" \
  -Dotel.service.name=security-demo \
  -Dotel.traces.exporter=otlp \
  -Dotel.logs.exporter=otlp \
  -Dotel.metrics.exporter=none \
  -Dotel.exporter.otlp.protocol=http/protobuf \
  -Dotel.exporter.otlp.endpoint=http://127.0.0.1:4318 \
  -Dsecurity.enabled=true \
  -Dsecurity.sbom.enabled=true \
  -Dsecurity.application.id=security-demo \
  -Dsecurity.code.repository=https://example.invalid/securitycontext \
  -Dsecurity.code.commit=local-commit \
  -Dsecurity.code.build-id=local-build \
  -Dsecurity.output="$OUT" \
  -Dsecurity.evidence.file="$OUT/evidence.jsonl" \
  -Dserver.address=127.0.0.1 \
  -Dserver.port=18080 \
  -jar examples/apps/security-validation-boot2.jar
```

发送一个实际请求并查看本地 ledger/evidence；Collector 的 `debug` exporter 同时会打印收到的 OTLP records：

```bash
OUT="$PWD/output/otlp-demo"
curl 'http://127.0.0.1:18080/api/sql?value=demo'
python3 bin/securityctl.py --dir "$OUT" status
python3 bin/securityctl.py --dir "$OUT" query findings
tail -n 5 "$OUT/evidence.jsonl"
```

这条链路证明的是指定请求的传输和本地记录路径；process-level health/SBOM 仍使用自己的观察时间和身份。

## 3. 配置

| JVM property | 默认值 | 作用 |
| --- | --- | --- |
| `security.enabled` | `true` | 安全数据流采集总开关 |
| `security.sbom.enabled` | `true` | 独立开启运行时 SBOM |
| `security.output` | `./security-output/<instance-id>` | health、finding、run、control 和 SBOM 默认目录 |
| `security.evidence.file` | 未配置 | 安全 evidence/diagnostic JSONL 路径 |
| `security.application.id` | 由 OTel service identity 回退生成 | finding、SBOM、run 的应用身份；建议显式设置 |
| `security.code.repository` | 空 | 真实仓库标识，验证 run 必须显式提供 |
| `security.code.commit` | 空 | 真实 commit 标识 |
| `security.code.build-id` | 空 | 真实构建标识 |
| `security.rules.<rule>.enabled` | `true` | `sql_injection`、`command_execution`、`command_injection`、`ssrf`、`http_request_input`、`path_traversal` |
| `security.max.active.requests` | `256` | 并发 request 上限 |
| `security.max.nodes` | `8192` | 单请求传播节点上限 |
| `security.max.findings` | `32` | 单请求 finding 上限 |
| `security.evidence.max.bytes` | `65536` | 单条 OTel/JSONL 记录字节上限 |
| `security.export.queue.size` | `1024` | security 队列条数 |
| `security.export.sbom.queue.size` | `256` | SBOM 队列条数 |

环境变量形式是 system property 的大写下划线形式，例如 `SECURITY_ENABLED`、`SECURITY_SBOM_ENABLED` 和 `SECURITY_APPLICATION_ID`。修改 JVM property 不会热更新正在运行的进程；修改后应重启并使用新的 instance output。

## 4. 输出与 schema v2

常见输出包括 `health.json`、`findings.json`、`runs.json`、`control.json`、`application.cdx.json`、`sbom-history.json` 和可选 `evidence.jsonl`。事件与自有快照顶层都有：

```json
{
  "source": "security_context",
  "schema_version": 2,
  "event_name": "security.dataflow.observed",
  "observed_at": "2026-09-08T00:00:00.123Z"
}
```

普通 schema v2 事件还平铺六个 identity 字段：`application_id`、`instance_id`、`service`、`code`、`runtime`、`identity_status`；未知身份字段按字段契约保持空字符串或 `null`，不能猜测补齐。`runtime` 固定包含 `language`、`implementation`、`version`、`os`、`architecture`、`details`；Java 的 `details` 保存 `vendor` 和 `vm_name`。OTel envelope 的 `scope.name` 固定为 `SecurityContext`，不是 body 字段；native `eventName`、OTel `event.name` attribute、body 的 `event_name` 必须相同，OTel `source` attribute 必须与 body 的 `source` 一致。

SBOM 上报（`app-dependencies-loaded` 和 `security.sbom.*`）使用 `source=security_context_sbom`，其他安全事件使用 `source=security_context`；OTLP log 的 `attributes.source` 与 JSON body 的 `source` 一致。截断 summary/minimal 保留原事件的 source。`sources[]` 中每个来源条目使用六字段 `id/type/name/location/value_type/value_length`，ID 为 `src-` 前缀，名称最多 256 个字符；sink 使用完整的 `function/role/location/operation/path_role/input_part` 结构。canonical role 包括 `sql_template`、`shell_script`、`argument`、`executable`、`destination_address`、`destination_unknown`、`path_or_query` 和 `file_path`。文件 operation 保留 `read/write/copy/rename/delete/unknown`；不能确认路径是 source 还是 target 时写 `unknown`。

`security.sbom.snapshot` 是 OTel 事件，平铺 identity；文件快照 `health.json`、`findings.json`、`runs.json`、`sbom-history.json` 只保留各自状态契约。health、SBOM 和 history 是进程级快照，不强行关联某个请求 trace；请求 dataflow evidence 才记录请求关联。CycloneDX 顶层不增加自定义字段，source marker 放在标准 `properties[]`，组件 ref 使用 `urn:securitycontext:component:`，properties 使用 `securitycontext:` namespace。SBOM 事件不写入 security JSONL；JSONL 只接收 security evidence 和 diagnostic 白名单。

## 5. trace 与交付

请求 dataflow 的 `trace_id`、`server_span_id` 来自 HTTP Server span，`current_span_id` 在 sink 处从当前 span 捕获；事件生成后冻结这些字段和 `trace_flags`。没有有效 server span 时 ID 为空、flags 为 `0`，不能仅凭 trace ID 声称后端存在 trace。进程级 health、SBOM 和 history 使用自己的观察时间与身份，不强行填入请求 span；exporter 不用发送时的当前线程或 span 改写 dataflow 字段。

OTel API `emit` 只表示调用 SDK API，不代表 Collector receipt、后端写入或 ACK。安全和 SBOM 使用独立队列，`security_dropped` 和 `sbom_dropped` 分开计数；只有 security channel 的丢失、失败和截断进入 security ledger 的 `delivery_loss`。

超过字节预算时先删除 `propagation`、`ranges`、`sources`，再输出 `security.export.truncated` summary。summary 固定保留 `original_event`、`evidence_id`、`sbom_id`（无值写 `null`）和 `truncated=true`，但与 minimal 一样不要求 identity 和 `observed_at`。minimal 固定四字段 `source`、`schema_version`、`event_name`、`truncated`；连四字段都放不下时记录 `record_too_small_for_envelope` 并递增对应 channel 的 `.failed`，不直接计入 dropped。

## 6. CLI 与验证 run

所有命令针对一个 process output 目录：

```bash
OUT=/absolute/path/to/security-output
python3 bin/securityctl.py --dir "$OUT" status
python3 bin/securityctl.py --dir "$OUT" query findings
python3 bin/securityctl.py --dir "$OUT" query runs
python3 bin/securityctl.py --dir "$OUT" query sbom
python3 bin/securityctl.py --dir "$OUT" pause
python3 bin/securityctl.py --dir "$OUT" resume
```

验证 run 覆盖该进程窗口内的所有 HTTP 请求，必须隔离流量，并填写真实代码 identity：

```bash
python3 bin/securityctl.py --dir "$OUT" run-start \
  --case sql-dynamic --rule sql_injection --suite java-sample \
  --fixture boot2-java17 --expected-requests 1 --ttl 300
python3 bin/securityctl.py --dir "$OUT" run-stop \
  --output "$OUT/candidate.json"
python3 bin/securityctl.py verify \
  --baseline "$OUT/baseline.json" \
  --candidate "$OUT/candidate.json" \
  --output "$OUT/verification.json"
```

`observed` 表示在指定条件下观察到数据流，`not_observed` 表示指定条件下没有观察到，`inconclusive` 表示 identity、流量、source/sink、完整性或交付证据不足；它们都不是漏洞确认或完整覆盖证明。CLI report/control 输出带 `source=security_context`，自身状态 schema 可以保持 v1。

## 7. 升级、停用和卸载

旧归档中的包名、JAR 文件名和旧命名空间不提供自动兼容 shim。升级时手动替换为 `securitycontext.jar`、`io.securitycontext.*` 和 schema v2；读取历史事件的 reader 需要自行兼容 v1。`fingerprint_version=2` 使用 language segment、每段 UTF-8 4-byte big-endian 长度前缀和 UTF-16 signature 排序，不能与 v1 finding ID 直接合并。

停用安全采集或 SBOM：

```bash
java -Dsecurity.enabled=false -Dsecurity.sbom.enabled=false \
  -javaagent:/path/to/opentelemetry-javaagent-2.31.1.jar \
  -Dotel.javaagent.extensions=/path/to/securitycontext.jar \
  -jar application.jar
```

彻底卸载前先停止 JVM，从 `otel.javaagent.extensions` 移除扩展，确认没有进程引用后再删除 `securitycontext.jar` 和其 output。运行中的 JVM 不会热卸载 extension。

## 8. 故障排查与边界

- 没有事件：确认扩展和 Agent 路径、`security.enabled`、HTTP Server instrumentation、应用是否在目标 JVM 内，以及日志 exporter 是否由宿主 SDK 配置。
- 没有请求级 trace：确认 server instrumentation 在请求前注册；没有 server span 时 dataflow 仍可存在，但 `server_span_id` 为空是预期行为。
- 没有 JSONL：确认 `security.evidence.file` 父目录可写；SBOM 事件不会进入该文件。
- health stale 或控制超时：确认 `--dir` 指向同一 instance 目录，进程仍在运行，且未把多个 worker/JVM 的文件合并。
- `incomplete` 或 `truncated`：查看 `coverage_gaps`、`counts`、预算和各通道 dropped/failed；这不表示无风险。
- SBOM unresolved：确认 archive/metadata 可读；未知版本、hash、依赖边和加载映射会保留 reason，不会猜测。

默认不输出请求原文、完整 SQL、命令文本、完整 URL 或命令参数值。WebFlux、跨服务传播、响应结束后的后台任务、任意二进制请求体、反射/native 数据流、JDBC batch、XSS、反序列化、在线 CVE 查询、动态 attach、强杀/主机故障恢复、trace replay 和外部 backend ACK 不在默认保证范围内。
