# 证据与 SBOM 语义

本文补充 SecurityContext schema v2 的证据与 SBOM 语义。旧 0.2.1 的独立运行证据和 candidate3 结果只作历史资料，不能替代当前 0.3.0/0.2.0 门禁。强杀/主机故障恢复、trace 重放和外部后端 ACK 不在当前原型边界内。

SBOM 上报（`app-dependencies-loaded` 和 `security.sbom.*`）使用 `source=security_context_sbom`，其他安全事件使用 `source=security_context`；OTLP log 的 `attributes.source` 与 JSON body 的 `source` 一致。截断 summary/minimal 保留原事件的 source。本地 CycloneDX 和状态文件保持原有结构及 source。

## SecurityContext schema v2

每条 `security.dataflow.observed` 记录代表一次观察到的 Source → 传播/转换 → Sink 路径。它是运行时风险路径证据，不是攻击成功证明、漏洞召回率或任意业务校验的安全证明。

证据结构的主要字段如下：

| 类别 | 字段和语义 |
| --- | --- |
| 事件 | `source=security_context`、`schema_version=2`、`event_name`、`observed_at`；普通事件还平铺 `application_id`、`instance_id`、`service`、`code`、`runtime`、`identity_status` |
| finding | `finding_id`、`fingerprint_version`、`rule`、`assessment`、`validation` |
| 执行 | `execution_observation=invocation_attempt`；表示调用点被观察到，不表示攻击成功 |
| 关联 | `trace_id`、`server_span_id`、Sink 调用时的 `current_span_id`、`trace_availability` |
| HTTP | method、route、status code、route 是否可用和请求时间，放在 `request` |
| 代码 | repository、commit、build_id、service_version，放在根 `code`；空值保持未知 |
| 路径 | `sources`、`propagation`、`ranges`、`precision`、`coverage_gaps` |
| Sink | function、role、location，以及有界调用栈 `stack` |
| SBOM | `sbom_id`、revision、release_id 和 `component.bom-ref`；无法准确解析时保留 `status=unresolved` 及 reason |
| 完整性 | `truncated`、`coverage`、`coverage_gaps` 和 `component` 解析状态 |

Python 0.2.0、Node.js 0.2.0 和 Java 0.3.0 共用 `schema_version=2`。Python 的 `ranges[].unit` 对 `str` 为 `unicode_code_point`，对 `bytes` 为 `byte`；JVM 和 JavaScript 文本为 `utf16_code_unit`。范围单位不能混用。三种语言的模块、函数、文件和行号参与 finding 指纹；fingerprint v2 额外包含 language，并使用 UTF-8 长度前缀和 UTF-16 signature 排序，详见[schema v2 文档](security-context-log-schema.md)。

代码身份必须由配置显式提供：

```text
security.code.repository
security.code.commit
security.code.build-id
```

扩展不会从当前目录、JAR 文件名或调用栈猜测仓库和提交。缺少调试符号时保留类名、方法名和可用的调用位置，不伪造行号。HTTP request 上下文来自 OTel HTTP Server instrumenter；没有 route 时写 `route_status=unavailable`。

### 稳定 finding 与请求 occurrence

`finding_id` 是跨请求聚合键，当前由应用身份、rule、role、归一化的 sink function、逻辑调用 site 和 source signature 形成 SHA-256 指纹。逻辑 site 尽量包含类、方法、文件和行号；JDBC 代理统一归一为 `java.sql.Statement.<method>`，避免同一 SQL API 因代理实现不同而分裂；因此修改源码行号可能改变 fingerprint 和 finding ID。它不包含 instance UUID，也不应该用请求值作 ID。

一次请求中的实际证据使用 `evidence_id`，结束时复制为 `occurrence_id`。RuntimeLedger 按 `finding_id` 增加 `occurrences`，并把当前请求的 `request`、`run`、最后一次 trace/evidence 和 triage 放进聚合 finding。代表样本有独立字节预算，默认首次、每 300 秒或新 run 时更新；其余 occurrence 仍增加计数，并可以通过 OTel Logs 的周期 summary 观察。默认 summary 周期为 30 秒。

这两个层次不能互相替代：finding 计数适合健康和趋势，occurrence/evidence 才包含一次请求的 source、传播和 sink 上下文。跨进程或重启后的聚合需要后端按 `application_id + finding_id` 完成；output 文件不是历史数据库。

### assessment、precision 和验证

当前 `assessment` 有两种主要语义：

- `candidate_risk`：规则或 Sink 角色满足首版风险候选条件，例如 SQL/命令注入，或受控可执行文件/目标地址；
- `observation`：观察到来源或调用事实，但不满足该候选风险边界。

`precision=exact` 表示字符范围可以映射；`precision=conservative` 表示传播被支持但范围无法精确计算。URL 编码、路径规范化、HTML 转义等转换不能自动变成安全证明。当前 `validation=unvalidated` 只表示运行时证据没有被 CLI 验证 run 改写；它不是 “fixed” 或 “safe”。

`securityctl.py verify` 的结果是：

- `observed`：在候选 run 的指定 suite、fixture、请求数和 source/sink 计数条件下观察到风险路径；不证明攻击成功；
- `not_observed`：在这些明确条件下没有观察到风险；不证明 fixed、没有漏洞或完整覆盖；
- `inconclusive`：代码身份、条件可比性、run 完成、source/sink 门槛、错误、coverage 或投递完整性不足。

验证必须有完整的 `repository`、`commit`、`build_id`，并且 baseline/candidate 的 case、rule、instrumentation profile、conditions 和 application identity 可比。baseline 还要保存实际风险事件的 `risk_source_signatures`（`source.type|source.name` 计数）；candidate 的 `source_signatures` 必须重新观察每个 baseline 风险签名，才有资格把 0 observation 判为 `not_observed`。仅增加一个 Header source 或执行常量 SQL 不能满足这项条件，缺少签名时应为 `inconclusive`。静态 schema 检查、源码审查或单测不能单独产生上述实际观察结论。

### Source、传播和 Sink

Source 只在应用或框架完成读取/绑定时登记，不主动消费输入流。三种实现统一输出 `src-` 加 `id`、`type`、`name`、`location`、`value_type`、`value_length` 六个字段；Node.js 可记录 `string`、`number`、`boolean`、`bigint` 和 `Buffer`，Python 可记录 `str`、`bytes`、`bytearray`，Java 只从 `String` 登记 source。Java `StringBuilder`/`StringBuffer` 可以传播，但不作为 byte source；长度单位遵循运行时文本/byte 规则，不能凭猜测补齐：

- Servlet 参数、参数集合、Header 和 Enumeration；
- Spring MVC `readWithMessageConverters` 返回后的文本、Map/List、POJO、`@RequestParam` 和 `@ModelAttribute`；
- 应用执行 `Reader.readLine` 或 Jackson `readValue` 后的请求体值。

对象身份和字符范围用于区分独立对象。相同字符串值不代表来源相同，字符串包含关系也不能代替传播证据。可精确映射的操作保留范围，其他已建模转换标为 conservative。对象、容器和 URL carrier 共用请求对象预算，不全局增强 JDK String 或容器；递归遍历受深度、元素和数量上限约束，超限写 coverage gap。

首版 Sink 与边界：

| 规则 | 入口 | 语义 |
| --- | --- | --- |
| `sql_injection` | JDBC execute/executeQuery/executeUpdate、PreparedStatement 执行 | 污染 SQL 模板在实际执行时出证据；占位符参数绑定不直接报 SQL 注入 |
| `command_execution`/`command_injection` | Runtime.exec、ProcessBuilder.start | 已识别的 POSIX `-c`、`-lc`、`-ec`、`-xc` 后脚本文本与普通 argv 分开；普通参数和脚本文件不自动判 shell 注入 |
| `ssrf`/`http_request_input` | URLConnection、JDK HttpClient、Apache HttpClient 4/5、OkHttp 3/4 | 实际发送才算 Sink；目标 address、path/query 和未知目标分开；只构造 URL 不算发送 |
| `path_traversal` | File/Path 到 FileInputStream、FileOutputStream、Files 读写/删除 | 记录不可信路径抵达实际文件操作 |

URL/URI 的 `getHost`、`getPath`、`getQuery`、`getAuthority` 和 `getFile` 按结构区段裁剪来源，避免 query 来源污染 host。URL 受控不表示响应值受控。RestTemplate 在统一 execute(String/URI, ...) 入口观察目的地，getForObject 等便利方法不会重复计数；固定地址中的 query 来源只报告 HTTP 输入，响应值不继承 URL 来源。URI 模板变量和 RequestEntity 载体仍可能缺少传播模型，报告明确 gap。

## OTel 输出和本地 JSONL

完整证据作为 JSON body 写入 OTel LogRecord，复用 OTel Resource 和导出配置，不以 Trace sampling 作为安全日志开关。HTTP Server Span 只增加有界摘要属性：

```text
security.detected
security.types
security.finding_count
security.finding.ids
security.evidence.ids
security.truncated
```

`security.finding.ids` 指向聚合 finding，`security.evidence.ids` 指向本次逻辑观察；代表样本周期抑制时，某个 occurrence 仍可能计数但没有对应的本地代表样本导出。没有 finding 的请求不增加这些摘要属性。传播不创建 Span；Sink 时的 current span 可能是普通应用 span、客户端 span、不存在或不是预期的数据库 span，不能仅凭 span 类型作结论。

配置 `security.evidence.file` 后，安全证据异步写为一行一条 JSONL，并按大小轮转。该文件只接收 security 通道的 evidence 或诊断白名单，不包含 `app-dependencies-loaded` 或 SBOM health 事件；SBOM 通道不写入 JSONL。默认不写请求原文、完整 SQL、命令文本、URL 原文或命令参数值。单条记录超限时先删除传播细节，再输出 `security.export.truncated` 摘要；队列满、预算超限、写盘失败和 OTel API 失败通过 health/counter/诊断反映，不改变业务返回值。

投递语义分层为“进入本地队列 → worker 预算处理 → OTel API emit/文件 flush → Collector/backend”。API emit 不是 SDK、Collector 或 backend ACK；本地 JSONL flush 也不是 fsync。安全和 SBOM 通道使用独立队列、线程与预算。

## CycloneDX 1.7 SBOM

### application、release 和 instance

当前清单是 CycloneDX 1.7 JSON：

- **application**：CycloneDX metadata component，`bom-ref=application_id`；复用 OTel Resource 的 service.name、service.version、service.namespace、service.instance.id 和 deployment.environment.name；
- **release**：`securitycontext:release-id`/事件中的 `release_id`，由 application identity 和已确认的 artifact SHA-256 形成，排除路径和 process instance；`securitycontext:release:identity-status` 表达 digest 是否完整；
- **instance**：`serialNumber=sbom_id`、revision/version 和 `securitycontext:process-instance-id`；它标识本次进程库存快照，CycloneDX snapshot `content_sha256` 也属于该实例发布内容。

因此，release identity 可以用于跨部署比较；instance SBOM 和 revision 用于具体进程的证据关联。安全事件带 `sbom_id`、revision 和 `bom-ref`，解析不确定时不猜组件。

### 组件识别

组件在有数据时包含 name、group、version、Maven PURL、实际 SHA-256、许可证、identity source、occurrence location 和属性。0.2.1 的基础设施排除依据 OTel Agent 实际入口和扩展自身 CodeSource，而不是 `net.bytebuddy` 或 `io.opentelemetry` 包名前缀；因此包含这些命名空间类的外层应用 Boot JAR 仍可作为应用制品扫描：

- `securitycontext:sbom:deployed`：扫描到的实际 artifact 为 `true`；build SBOM 声明和 shaded metadata 组件为 `unknown`；
- `securitycontext:sbom:loaded`：运行时观察到相关 class 被加载；
- `securitycontext:sbom:declared`：组件来自导入的构建 SBOM；
- `securitycontext:sbom:version-status=unknown`：没有可确认版本。

缺失版本或坐标时保留未知，不从文件名猜测。外层 JAR SHA-256 不能代表 nested 或 shaded 组件。真实 artifact 的 `bom-ref` 按内容 SHA-256，因此改名不产生重复；同坐标不同内容保留不同引用。没有内容哈希的 shaded Maven metadata 组件按 metadata identity 加 container scope 生成引用。组件 occurrence 只保留显示用的制品文件名和 nested suffix，不输出绝对路径。

class 被加载只表示观察到加载行为，不表示方法执行、漏洞可达或调用点已插桩。没有可读 class resource 的动态生成类会跳过调用点预扫描；SBOM 仍可能从 CodeSource 观察其制品位置。

### 依赖、质量和完整性

普通 classpath、Boot nested JAR、WAR 和类加载扫描不会猜测传递依赖，也不会把所有 JAR 伪装成 application 的直接依赖。只有可读取的嵌入式 `META-INF/sbom/*.json` 构建 SBOM 才能提供依赖边；旧 `bom-ref` 只有在唯一 PURL 映射成功时才映射到当前组件。无法解析或有歧义的边增加 completeness reason，清单固定带 `runtime_dependency_graph_incomplete` 和 `compositions.aggregate=incomplete`。

本地 CycloneDX 的 quality 是实际计数，不是评分或估算，包含：

```text
components
with_purl
with_version
with_hash
with_license
  loaded_components
```

完整性原因覆盖 metadata/许可证缺失、不可读 artifact、归档深度/条目/读取量超限、shaded identity 不完整、依赖边不可解析和替换来源后 class identity 不确定。ArchiveScanner 可表达的错误会发布带 reason 的有效部分；只有 publish/refresh 未处理失败才保留旧文件并发出 `security.sbom.update_failed`。

### 生命周期和缓存

启动后 SBOM 在后台刷新，默认每 5 秒检查 classpath 和已加载 class 的 CodeSource。制品解析缓存按 size、mtime 和 file key 形成指纹，默认 300 秒有效。发现新位置、加载证据或 artifact 变化时，只有内容发生变化才发布新 revision；OTel Logs 使用 `app-dependencies-loaded` 上报 name/version/必要时 hash 的已加载依赖快照，大快照按修订号分片；added/updated/removed 历史保留在本地 history，完整 CycloneDX 文件由 `security-sbom/SbomInventory.publish` 临时写入后 atomic move。

SBOM health 的 `last_refresh_at`、`last_failure_at`、revision、current component count 和 history count 是新鲜度/库存状态指标；它们不表示扫描覆盖率或漏洞召回率。扫描失败、重试和删除 delta 要结合 completeness reasons、已加载依赖快照和 history 的 current/removed 状态解释。

`security-exporter` 不直接写 `application.cdx.json`，只发送 SBOM LogRecord、维护独立 SBOM 队列和投递诊断。`security.evidence.file` 不包含 SBOM 事件。SBOM 扫描、归档读取和哈希计算不在请求路径运行；请求路径的组件 resolve 只查已经发布的 mapping，不触发扫描或哈希。

## SBOM 与证据的隐私边界

证据默认记录字段名、来源类型、代码位置、传播关系、组件引用和完整性状态，不记录用户输入原文、完整 SQL、命令文本、URL 原文或命令参数值。SBOM 默认 occurrence 使用文件名而不是绝对路径。任何需要扩大留存范围的配置或实现都必须单独定义脱敏、保留期和验证条件。
