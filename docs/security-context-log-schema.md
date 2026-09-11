# SecurityContext 日志结构（schema v2）

> 文档日期：2026-09-08。本文定义 Node.js、Python 和 Java 共享的 SecurityContext 输出契约。
> 字段说明以当前三种 schema helper、exporter 和状态快照实现为准；本次运行验证的范围和限制见第 15 节，不将局部验证等同于完整发布门禁。
> 本文只描述结构，不把旧 `build/`、`dist/` 或 `release/` 目录中的 0.2.1 证据当作当前版本的发布验证。

## 1. 名称、版本和范围

SecurityContext 是品牌名，也是三种实现使用的 OpenTelemetry instrumentation scope。三种实现对外使用以下名称和版本：

| 实现 | 对外包/命名空间 | 当前 schema 版本 | 版本 | OTel scope |
| --- | --- | ---: | ---: | --- |
| Node.js | npm `securitycontext` | 2 | `0.2.0` | `SecurityContext` |
| Python | distribution/import `securitycontext` | 2 | `0.2.0` | `SecurityContext` |
| Java | `io.securitycontext.*`，扩展 `securitycontext.jar` | 2 | `0.3.0` | `SecurityContext` |

仓库中保留的旧构建、发行和验证文件属于历史 0.2.1 记录。它们可以用于追溯旧实现，不能证明上述新版本已经完成打包、发布或收件方验收。

本文覆盖：

- OTel Logs 中的安全数据流、诊断、截断、交付和 SBOM 事件；
- 可选 JSONL 证据文件中使用的同一事件主体；
- `health.json`、`findings.json`、`runs.json` 和 SBOM snapshot 的身份与质量字段；
- 三种语言必须保持一致的根字段、来源、范围、sink、组件引用和 fingerprint 规则。

本文不把 OTel API `emit` 解释成 Collector 或后端 ACK，也不把运行时观察解释成漏洞确认或完整覆盖保证。

## 2. 统一 `source` 标识

每条 SecurityContext 日志在 JSON body 和 OTLP `attributes` 中携带一致的 `source`，用于按数据类型筛选和路由：

| 日志类型 | `source` |
| --- | --- |
| SBOM 快照 `app-dependencies-loaded` | `security_context_sbom` |
| SBOM 诊断 `security.sbom.*`，包括 health、update_failed、export.dropped | `security_context_sbom` |
| 其他安全事件 | `security_context` |

截断 summary/minimal 的 `event_name` 可以变为 `security.export.truncated`，但 `source` 保留原事件的值。因此收集全部 SBOM 日志时按 `source=security_context_sbom` 筛选；只处理依赖快照时再加 `event_name=app-dependencies-loaded`。

本地 `health.json`、`findings.json`、`runs.json` 和 `sbom-history.json` 保留顶层 `source=security_context`。`securityctl` 的 report/control 输出也保留该字段，但自身状态 schema 可以继续为 v1。`source` 与 `sources[]`（数据流输入来源）是两个不同概念，不能互相替代。

CycloneDX 顶层对象必须保持官方标准结构，不能直接增加未被标准允许的顶层字段。当前实现把 source 标识放在 CycloneDX 顶层标准 `properties` 数组中（`name=source`、`value=security_context`）；不要把非标准顶层 `source` 写入 `application.cdx.json`。

## 3. 事件主体和 OTel envelope

每条事件主体都是 JSON object，并包含以下公共根字段：

| 字段 | 类型 | 语义 |
| --- | --- | --- |
| `source` | string | SBOM 日志为 `security_context_sbom`，其他安全事件为 `security_context`。 |
| `schema_version` | integer | 固定为 `2`。 |
| `event_name` | string | 事件分派主名。 |
| `observed_at` | UTC ISO 8601 string | 事件被观察或生成的时间，统一为毫秒精度，例如 `2026-09-08T00:00:00.123Z`。 |
| `application_id` | string | 应用稳定身份。 |
| `instance_id` | string | 当前进程或 JVM 实例身份。 |
| `service` | object | OTel 服务身份；保留可用的服务属性。 |
| `code` | object | `repository`、`commit`、`build_id`、`service_version` 等代码身份。 |
| `runtime` | object | 运行时结构，见第 5 节。 |
| `identity_status` | string | `configured`、`fallback` 或 `incomplete`。 |

事件不再使用嵌套 `identity` 作为身份来源。事件根部的六个 identity 字段必须使用相同键名和语义；值不可确认时保持空、`null` 或按该事件契约省略，不能凭空生成业务身份。预算降级的截断 summary 和 minimal 都是 envelope 例外：二者不要求六个 identity 字段和 `observed_at`。summary 保留第 11 节规定的摘要字段；minimal 只保留 `source`、`schema_version`、`event_name`、`truncated`。

`health.json`、`findings.json`、`runs.json` 和 `sbom-history.json` 是自有状态快照，不是逐条事件；它们保留顶层 `source=security_context`。事件主体去掉嵌套 `identity`；`app-dependencies-loaded` 是 OTel 事件，遵守平铺 identity 规则。`sbom-history.json` 使用 application/release 等字段，不要求 identity 对象。

OTel Logs 的三种实现必须提供同一事件名：

| OTel 位置 | 规则 |
| --- | --- |
| instrumentation scope | 名称为 `SecurityContext`，版本使用对应实现版本。 |
| severity | `severityText=INFO`、`severityNumber=9`；事件主体的 `severity` 是独立的风险分级字段。 |
| native event name | `eventName` 为 `event_name` 的同一字符串。 |
| attributes | `event.name` 和 `source` 分别与 body 的 `event_name` 和 `source` 一致。 |
| body | UTF-8 JSON 字符串；其中 `event_name` 与以上两处完全一致。 |

消费者应解析 body，再用 `event_name` 分派。LogRecord 的发送时间和 body 内 `observed_at` 可能不同。外层 Resource 的 `service.instance.id` 也不自动等于 body 的 `instance_id`。

可选 JSONL 文件写入同一个事件主体，不带 OTel envelope。三种实现的 security 通道只写 evidence 或诊断白名单事件；SBOM 通道事件不写入 JSONL。完整 SBOM 文件不是日志事件。

## 4. 共同事件字段

### 4.1 `security.dataflow.observed`

三种实现的 dataflow 记录使用相同的根字段和对象形状。以下字段在事件出现时必须遵守相同语义；预算或上下文不足时可按截断规则减少数组内容，但不得改名或用猜测值填充。

| 字段 | 类型 | 语义 |
| --- | --- | --- |
| `source` | string | 固定为 `security_context`。 |
| `evidence_id` | string | 一次观察的事件 ID，通常为 `ev-` 前缀。 |
| `finding_id` | string | `finding-` 加 SHA-256 十六进制摘要，算法见第 9 节。 |
| `fingerprint_version` | integer | 固定为 `2`。 |
| `rule` | string | `sql_injection`、`command_injection`、`command_execution`、`ssrf`、`http_request_input` 或 `path_traversal`。 |
| `assessment` | string | 当前建模标签，例如 `candidate_risk` 或 `observation`；不等于漏洞确认。 |
| `validation` | string | 运行时观察默认为 `unvalidated`。 |
| `severity` | string | 未分级时为 `unassigned`。 |
| `confidence` | string | `modeled_flow` 或 `conservative_flow`。 |
| `execution_observation` | string | `invocation_attempt` 只表示观察到调用尝试。 |
| `precision` | string | `exact` 或 `conservative`。 |
| `trace_id` | string | 有效的 32 位十六进制 trace ID，未知时为空。 |
| `server_span_id` | string | 有效的 16 位十六进制服务端 span ID，未知时为空。 |
| `current_span_id` | string | sink 处当前 span ID，未知时为空。 |
| `trace_flags` | integer | 发送时冻结的 trace flags；没有有效 server span 时为 `0`。 |
| `trace_availability` | string | `not_guaranteed_by_trace_id` 表示 ID 存在不代表后端有 trace。 |
| `sources` | array | 统一来源结构，见第 6 节。 |
| `propagation` | array | 来源到 sink 的关系节点。 |
| `ranges` | array | 来源范围和单位，见第 7 节。 |
| `sink` | object | 统一 sink 结构，见第 8 节。 |
| `stack` | array of strings | 当前调用栈，最多 24 帧；不可用时为 `[]`，帧格式依语言而异。 |
| `truncated` | boolean | 采集或导出存在不完整状态。 |
| `coverage` | string | 当前实现覆盖边界，通常为 `modeled_calls_only`。 |
| `coverage_gaps` | array | 已知缺口名称。 |
| `component` | object | 固定组件引用结构，见第 10 节。 |
| `request` | object | 固定的请求方法、route、状态、生命周期和框架字段，见下文。 |
| `run` | object | 可选的验证 run；未运行时可以是 `{}`。 |
| `triage` | object | 例如 `{"decision":"unreviewed"}`；不改变检测事实。 |

一次请求内按 v2 `finding_id` 去重：同一个 fingerprint 在同一请求中只输出一个 finding。`evidence_id` 表示单次输出，`finding_id` 表示稳定聚合键；二者不能互换。

`request` 固定包含 `method`、`route`、`route_status`、`status_code`、`started_at`、`ended_at`、`framework`、`transport`、`error_type`。未知的状态码和时间为 `null`，未知字符串为 `""`，未观察到路由时 `route_status=unavailable`。dataflow、collection-incomplete、finding 快照中的 `request` 和 run 快照中的 `last_request` 使用同一结构。Python 适配器可在 `framework`、`transport` 中保留实际框架名和 `asgi` / `wsgi` 接口；其他实现未采集这些信息时保留空字符串。

### 4.2 诊断、summary 和交付

公共诊断事件仍使用 `source`、`schema_version`、`event_name`、`observed_at` 和六个根 identity 字段。诊断计数统一放在 `counts` 中：

```json
{
  "objects": 12,
  "nodes": 20,
  "sources": 3,
  "findings": 2,
  "retained_bytes": null
}
```

`counts` 的键固定为 `objects`、`nodes`、`sources`、`findings`、`retained_bytes`。实现无法提供某个计数时写 `null`，不能用 `0` 冒充未知，也不能删除键后让消费者猜测。

| 事件 | 共同字段和语义 |
| --- | --- |
| `security.finding.summary` | `source`、`finding_id`、累计 `occurrences_total`、`first_seen`、`last_seen`、`triage`。 |
| `security.collection.incomplete` | `source`、`truncated`、`coverage_gaps`、`collection_status`、统一 `counts`，并带可用 trace 字段。 |
| `security.snapshot.failed` | `source`、`error_type` 和失败计数；不能把快照失败解释为无风险。 |
| `security.export.dropped` | `source`、交付丢弃计数和 `delivery`。 |
| `security.sbom.export.dropped` | `source`、SBOM 通道交付丢弃计数和 `delivery`。 |
| `security.export.truncated` | `source`、统一截断 summary 或最小事件，见第 11 节。 |

`delivery` 至少保留 `counters`、`dropped`、`security_dropped`、`sbom_dropped`、队列深度、最近写入时间和 OTel 调用时间。`security_dropped` 与 `sbom_dropped` 分别表示安全事件队列和 SBOM 事件队列的丢弃，不得合并成一个无法区分的数值。`backend_acknowledgement` 为 `unknown` 时，表示 agent 没有后端确认能力。

### 4.3 SBOM 事件

SBOM snapshot、health、update-failed 和 export-dropped 事件使用 `source=security_context_sbom`，同样遵守 `schema_version=2`、`event_name`、`observed_at`、六个根 identity 字段和 `SecurityContext` scope。三种实现的组件生态可以不同，但事件的外层字段和组件引用字段不能不同。

依赖上报统一为 `app-dependencies-loaded`，替代原来的 `security.sbom.component` 增量和 `security.sbom.snapshot` 元数据事件。它上报该进程实际观察到加载的依赖快照，不将仅安装、构建声明或扫描到的组件当作已加载。公共 identity、`sbom_id`、`revision`、`release_id`、`status`、`completeness`、`reasons` 和 `dropped_observations` 保留。

依赖项只包含 `name`、`version`，坐标或版本不足且有真实制品 SHA-256 时增加 `hash`（64 位十六进制）；未知版本写空字符串，不能使用声明的 lock integrity 或元数据摘要冒充制品 hash。Java 有 Maven 坐标时使用 `groupId:artifactId`，缺少 Maven 元数据时使用可确认的 manifest 名称或制品文件名；Node 保留完整 npm 名称（包括 scope），Python 使用发行包名称。相同 name/version/hash 的条目去重。下面省略公共 envelope 字段：

```json
{
  "source": "security_context_sbom",
  "event_name": "app-dependencies-loaded",
  "sbom_id": "urn:uuid:example",
  "revision": 2,
  "part_index": 0,
  "part_count": 1,
  "component_count": 1,
  "dependencies": [
    {"name": "org.springframework:spring-core", "version": "6.2.7"}
  ]
}
```

`component_count` 是该修订去重后的已加载依赖总数。超出事件字节上限时分片，`part_index` 从 0 开始；同一 `sbom_id`/`revision` 的全部 `part_count` 片共同构成一份快照。消费端收齐后整体替换，不能把单片或缺片当作完整库存；空列表也会发布一片以清空此前库存。新版消费端需要切换事件名和读取 `dependencies`。

本地 `application.cdx.json` 继续保存 CycloneDX 1.7 的组件、许可证、PURL、依赖图和质量信息；`sbom-history.json` 保留 current/removed 历史。dataflow 事件中的轻量 `component` 引用仍对应本地 CycloneDX 的 `bom-ref`，不变成上述依赖项。

`security.sbom.health` 的公共字段为 `sbom_id`、`revision`、`release_id`、`status`、`last_refresh_at`、`last_failure_at`、`last_error_type`、`current_components`、`history_count`、`completeness`、`reasons` 和 `dropped_observations`，并保留应用/实例 identity。无法提供的计数或时间写 `null`。`security.sbom.update_failed` 至少包含 `sbom_id`、`revision` 和 `error_type`。

## 5. 运行时 identity

`runtime` 的固定形状为：

```json
{
  "language": "javascript",
  "implementation": "nodejs",
  "version": "24.11.1",
  "os": "linux",
  "architecture": "arm64",
  "details": {}
}
```

| 实现 | 固定值/语言差异 |
| --- | --- |
| Node.js | `language=javascript`、`implementation=nodejs`；`details` 可以为空对象。 |
| Python | `language=python`、`implementation=cpython`；`details.gil_build` 为 `standard` 或 `free-threaded`。 |
| Java | `language=java`、`implementation=jvm`；`details.vendor` 和 `details.vm_name` 保存 JVM 信息。 |

`version`、`os` 和 `architecture` 都来自实际运行时。`service` 保存可确认的 OTel service 属性；`code` 保存显式配置的 repository、commit、build_id 和 service_version。`identity_status=fallback` 表示使用了回退 application identity；`identity_status=incomplete` 表示调用者提供的 identity 不完整。两者都不允许用猜测值补齐缺失字段。

## 6. source 和 propagation

每个 `sources[]` 条目统一使用以下六个字段，字段名和语义固定：

| 字段 | 语义 |
| --- | --- |
| `id` | 请求内唯一字符串，统一使用 `src-` 前缀。 |
| `type` | 来源类型，例如 HTTP 参数、Header、body 或框架绑定结果。 |
| `name` | 字段或载体名称，三种实现统一限制为最多 256 个字符。 |
| `location` | 代码或适配器位置字符串。 |
| `value_type` | 可确认的值类型，例如 `string`、`bytes`。 |
| `value_length` | 可确认时的长度；按实现和值类型使用下述单位，未知时保持 `null`。 |

`value_length` 与 `ranges[].unit` 使用同一长度语义：Node.js 的字符串和 number/boolean/bigint 转换值按 JavaScript UTF-16 code unit 计数，`Buffer` 按 `byte` 计数；Python `str` 按 Unicode code point 计数，`bytes`/`bytearray` 按 `byte` 计数；Java source 只捕获 `String`，按 JVM UTF-16 code unit 计数。Java `StringBuilder`、`StringBuffer` 等值可以传播到 sink，但不作为 source 值，因此不能写成 Java byte source。

`propagation[]` 使用 `id`、`parent_id`、`source_id`、`operation`、`location`。`source_id` 必须引用同一事件中的 source；`parent_id` 是原始传播图关系：源节点没有父节点时为 `null`，图预算截断导致父节点记录未随事件保留时仍保留原 parent ID，不主动改写为 `null`。关系数组可能因图遍历或截断而不是调用时序。

不记录请求原文、完整 SQL、命令正文、完整 URL 或命令参数值。名称、位置、类型和范围能确认多少就记录多少；不确定时保留缺失、空或未知标记，不能把推测写成事实。

## 7. ranges

`ranges[]` 的形状固定为：

```json
{
  "source_id": "src-1",
  "start": 0,
  "end": 3,
  "exact": true,
  "unit": "utf16_code_unit"
}
```

范围是零基半开区间 `[start, end)`。`end` 不可确认时可以为 `null`，`exact=false` 表示边界是保守范围。单位按实际值类型固定：

| 运行时 | 文本单位 | bytes 单位 |
| --- | --- | --- |
| JVM | `utf16_code_unit` | `byte` |
| JavaScript | `utf16_code_unit` | `byte` |
| Python | `unicode_code_point` | `byte` |

消费者不能用 Python code point 下标解释 JVM/JavaScript 范围，也不能把 bytes 的字节数当作字符数。

## 8. sink

每个 sink 都使用完整的固定结构，即使某个字段不适用也不能改名：

```json
{
  "function": "sqlite3.Cursor.execute",
  "role": "sql_template",
  "location": "app#search(app.py:16)",
  "operation": "",
  "path_role": "",
  "input_part": ""
}
```

`role` 使用 canonical 值。历史适配器输入必须在输出前归一化：

| 输入别名 | canonical role |
| --- | --- |
| `template` | `sql_template` |
| `shell`、`shell_command` | `shell_script` |
| `argv`、`ordinary_argument` | `argument` |
| `unknown_target` | `destination_unknown` |
| `request_path`、`request_query`、`path_query` | `path_or_query` |

其它 canonical role 为 `executable`、`destination_address` 和 `file_path`。`file_path` 保留实际文件 `operation`，可用值包括 `read`、`write`、`copy`、`rename`、`delete` 和 `unknown`。`path_role` 只允许 `source`、`target` 或 `unknown`；当调用不能确定路径是源还是目标时必须写 `unknown`。不能因为函数名相似就捏造 operation 或 path role。

对 `http_request_input`，`input_part` 只能是 `path`、`query` 或 `path_or_query`；其它规则不适用时保留空字符串。`function` 和 `location` 是有界字符串，不能放入请求值。

## 9. fingerprint v2

`finding_id` 使用 `fingerprint_version=2`。三种 helper 使用同一字段顺序：

```text
2
application_id
language
rule
sink.role
sink.function
sink.location
sink.operation
sink.path_role
sink.input_part
sorted(unique(signatures))
```

具体规则如下：

1. 每个上面列出的元素都是一个独立 segment，空字符串也保留为 segment；`language` 是必需字段，因此 Java、Python、Node 的相同调用不会因意外跨语言合并。
2. source signatures 先去重，再按 UTF-16 code unit 顺序排序。排序规则跨语言一致；不能使用本地化排序或平台默认 locale。
3. 每个 segment 规范化为 Unicode 后编码为 UTF-8；在 SHA-256 输入中先写入该 segment UTF-8 字节长度的 4-byte big-endian 前缀，再写入 segment 字节本身。不能用字符数、UTF-16 字节数或 JSON 分隔符代替长度前缀。
4. 对完整输入计算 SHA-256，输出为 `finding-` 加小写十六进制摘要。

签名来源通常是 `source.type + "|" + source.name`。请求 identity 去重发生在事件生成前；fingerprint 只使用稳定结构字段，不包含请求原文、`instance_id`、`evidence_id` 或时间。

## 10. SBOM quality、properties 和 refs

SBOM `quality` 使用统一计数键：

```json
{
  "components": 12,
  "with_purl": 10,
  "with_version": 11,
  "with_hash": 8,
  "with_license": 7,
  "loaded_components": 5
}
```

`loaded_components` 表示运行时观察到组件被加载或导入，不表示方法执行、漏洞可达或所有运行时依赖都已枚举。质量数据是实际计数，不是漏洞覆盖率。

CycloneDX properties 的 namespace 固定为 `securitycontext:`，例如 `securitycontext:sbom:loaded`、`securitycontext:application-id` 和 `securitycontext:process-instance-id`。组件引用必须使用 `urn:securitycontext:component:` 前缀；不同内容的组件不能只按包名合并。

dataflow 中的 `component` 固定为以下轻量引用结构：

```json
{
  "status": "resolved",
  "sbom_id": "sbom-1",
  "revision": 2,
  "release_id": "release-1",
  "application_id": "orders",
  "bom-ref": "urn:securitycontext:component:abc",
  "reason": "",
  "observed_url": "",
  "query": ""
}
```

`revision` 是整数，明确未知时为 `null`；其余字段按事件契约保留为空或未知。`reason` 只写真实原因，例如未启用 SBOM 或无法解析组件；不能用 `resolved` 状态推导不存在的 URL、query 或 release。

## 11. trace、截断和 delivery

服务端 span 关联由请求生命周期在事件生成时建立，导出时使用冻结的 `trace_id`、`server_span_id`、`current_span_id` 和 `trace_flags`。exporter 不在事件发送后用当前线程或当前 span 重写这些字段。无有效 server span 时仍可产生 dataflow，但 ID 为空、flags 为 `0`，不能据此声称有 trace 关联。

记录超过字节预算时，三种实现使用同一降级顺序：

1. 删除 `propagation`、`ranges`、`sources`，保留根身份、sink 和 `truncated=true`、`truncation_reason=record_byte_limit`；
2. 仍超限则输出统一 summary：保留原事件的 `source`、`schema_version=2`、`event_name=security.export.truncated`、`original_event`、`evidence_id`、`sbom_id` 和 `truncated=true`；两个 ID 没有对应值时写 `null`。summary 与 minimal 一样不要求 identity 和 `observed_at`；
3. summary 仍超限则输出最小对象，仍保留原事件的 `source`（SBOM 为 `security_context_sbom`）。以下是普通安全事件的示例：`{"source":"security_context","schema_version":2,"event_name":"security.export.truncated","truncated":true}`。

`security.export.truncated` 的 `eventName`、`event.name` attribute、`source` attribute 和 body 的 `event_name`/`source` 也必须完全一致。summary 始终保留 `original_event`、`evidence_id`、`sbom_id` 三个字段；没有对应 ID 时写 `null`。截断 summary 不能被当成原始 dataflow 或 SBOM 事件；它只说明原记录无法在当前预算下交付。若连四字段 `source`、`schema_version`、`event_name`、`truncated` 都无法序列化，记录不应直接增加 dropped；对应通道记录 `record_too_small_for_envelope`，并使 `<channel>.failed` 递增，两个计数共同表达该失败诊断。

安全和 SBOM 队列独立计数。`delivery.security_dropped`、`delivery.sbom_dropped` 以及对应 dropped 诊断必须保留各自通道语义；只有 security channel 的丢失、失败和截断进入 security ledger 的 `delivery_loss`，SBOM channel 不得污染安全 finding 交付计数。API emit、文件 flush、Collector receipt 和后端 ACK 是不同阶段。

## 12. 语言差异

公共字段、对象名、canonical sink role、scope、事件名和 fingerprint 规则不随语言改变。只允许以下实现差异：

| 维度 | Node.js | Python | Java |
| --- | --- | --- | --- |
| 包/版本 | `securitycontext` 0.2.0 | `securitycontext` 0.2.0 | `io.securitycontext.*` / `securitycontext.jar` 0.3.0 |
| runtime | `javascript` / `nodejs` | `python` / `cpython` | `java` / `jvm` |
| runtime details | 可为空 | `gil_build` | `vendor`、`vm_name` |
| 文本 range | `utf16_code_unit` | `unicode_code_point` | `utf16_code_unit` |
| source value | JavaScript `string`、`number`、`boolean`、`bigint` 或 `Buffer` | Python `str`、`bytes`、`bytearray` | 仅 JVM `String`；`StringBuilder`/`StringBuffer` 可传播但不是 source |
| server span | 可用时关联 | 可用时关联 | 由 HTTP server instrumentation 提供时关联 |

Node.js、Python 和 Java 可以有不同的适配器、代码位置格式和组件生态，但不能恢复历史 role 别名、不同的 source ID 前缀、不同的 identity 层级或不同的 diagnostic counts 结构。

## 13. v1 → v2 和 fingerprint v2 迁移

迁移旧版本时按以下顺序处理：

| v1 形式 | v2 处理 |
| --- | --- |
| `schema_version=1` | 解析后标记为旧事件；新输出固定为 `schema_version=2`。 |
| `identity` 嵌套在事件主体 | 展开为根部 `application_id`、`instance_id`、`service`、`code`、`runtime`、`identity_status`；状态快照可以保留 `identity`。 |
| 只有部分实现带 runtime | 按统一 runtime 结构补充实际语言和实现；Java 的 JVM 信息放入 `details`，Python 的 GIL 信息放入 `details.gil_build`。未知值保持未知。 |
| Node `source-*` 或语言专属来源形状 | 新输出统一为 `src-*` 和六个 source 字段。历史事件的 ID 不要静默改写成新 ID。 |
| sink role 别名 | 迁移显示层可映射到 canonical role；保留原始 v1 事件以便审计。新输出使用第 8 节的 role 和完整 sink 结构。 |
| 未声明 range unit | 不能猜测；JVM/JavaScript 新输出为 `utf16_code_unit`，Python 文本为 `unicode_code_point`，bytes 为 `byte`。 |
| 语言专属 diagnostic counts | 映射到 `counts.objects/nodes/sources/findings/retained_bytes`；无法恢复的值写 `null`。 |
| 旧 component 引用 | 新输出固定九个引用字段，`revision` 未知时为 `null`；新 SBOM 使用 `urn:securitycontext:component:` 和 `securitycontext:` properties。 |
| `fingerprint_version=1` | 不重算为同一个 ID。新事件使用 `fingerprint_version=2` 和第 9 节的 UTF-8 长度前缀、UTF-16 排序、language segment 规则；v1/v2 finding 必须分开聚合。 |

旧发行物中的历史名称只由迁移说明识别。当前没有旧 package/import/JAR/命名空间的自动兼容 shim；消费者必须手动更新包名、import、JAR 文件名和命名空间。读取历史 v1 事件的 reader 负责兼容旧字段和旧名称，新写出固定使用本页的 SecurityContext 名称。

## 14. 实现索引

以下 helper 是公共契约的最小实现锚点；其它 exporter、ledger 和 SBOM 模块必须调用或遵守同一结构：

- [Node.js schema.mjs](../nodejs/src/schema.mjs)
- [Python schema.py](../python/src/securitycontext/schema.py)
- [Java Events.java](../security-core/src/main/java/io/securitycontext/core/Events.java)
- [Node.js identity/exporter](../nodejs/src/config.mjs)、[Node.js exporter](../nodejs/src/exporter/index.mjs)
- [Python identity/state/exporter](../python/src/securitycontext/config.py)、[Python state](../python/src/securitycontext/state.py)、[Python exporter](../python/src/securitycontext/exporter.py)
- [Java identity](../security-core/src/main/java/io/securitycontext/core/Identity.java)、[Java state](../security-core/src/main/java/io/securitycontext/core/SecurityState.java)、[Java exporter](../security-exporter/src/main/java/io/securitycontext/exporter/EvidenceExporter.java)

解析器应先按 body 的 `event_name` 分派，再按事件类型读取可选字段；应保留 `source`、`truncated`、`coverage_gaps`、`identity_status`、`trace_availability`、`counts` 和 delivery 丢弃计数。不要把缺失字段补成成功、零计数、完整 trace、已解析组件或安全结论。

## 15. 本次验证范围

2026-09-08 的日志统一阶段在 OrbStack 完成以下检查，证据保存在仓库的 `build/validation/output-v2/`：

| 实现 | 实际检查 | 结果 |
| --- | --- | --- |
| Node.js | Node 22 / 24 单元测试、统一 Unicode fingerprint、真实 exporter 的截断 OTel envelope、request 与 ledger 快照、Express 5 ESM 实际 HTTP | 两个版本各 34 项通过；最后的 request 回归 2 项、runtime controls 5 项通过；HTTP harness 的 21 项检查通过，未配置 DSN 的两个数据库场景跳过。 |
| Python | CPython 3.12 单元测试、request 回归、新 wheel 在干净 venv 中通过自动加载运行 FastAPI | 54 项单元和 2 项 request 回归通过；FastAPI 观察到 19 条 dataflow，正例、参数化 SQL 负例和请求结束排空检查通过。 |
| Java | Java 17 单元、Boot2/Java8 和 Boot3/Java17 HTTP、OTel Collector | 全量 55 项中 53 项通过、2 项跳过；最后的 request 改动重跑 core/exporter，28 项中 27 项通过、1 项跳过，并用新 JAR 验证实际 HTTP 输出。 |

三种实现使用同一份 [跨语言 fixture](../tests/fixtures/output-v2-cross-language.json) 校验 fingerprint 和公共字段。实际 exporter 检查覆盖 `source`、截断后事件名、trace context 和通道交付计数。文档中的 7 个 JSON 示例及相对链接已做静态检查。

对三种实现的实际 HTTP dataflow 样例逐项比较，事件根部及 `request`、`sink`、`component`、`runtime`、`sources[]`、`ranges[]`、`propagation[]` 的键集合一致，日志和自有快照均保留 `source=security_context`。Node/Python 样例仍如实记录未建模调用等 `coverage_gaps`；Node 样例的 health 为 `incomplete`，安全通道丢弃为 0，SBOM 通道预算丢弃为 233。这些状态不代表字段不一致，也不能被解释为完整采集或零交付损失。

以上是日志统一阶段的范围：当时没有重跑完整发布矩阵、全部数据库 client 或长时间性能检查，Node tarball 导入使用了已有依赖。随后生成的本地发行版及扩展验收记录集中在[多语言发行目录](../dist/securitycontext-releases-20260908/README.zh-CN.md)，包括 Java `0.3.0`、Node.js/Python `0.2.0` 的制品、双语指南、校验和及各语言 `release-validation.json`；当前发行结论以这些记录为准。没有向远程包仓库发布。
