# 架构与范围

本文描述当前 SecurityContext Java 0.3.0 的模块边界和 schema v2 运行契约。旧 0.2.1 构建与运行证据只作历史资料，不能替代当前门禁。强杀/主机故障恢复、trace 重放和外部后端 ACK 仍是明确未测边界。架构文档不把静态源码核对当成运行验证。

## 运行形态

SecurityContext 作为 OpenTelemetry Java Agent extension 加载，与 OTel Java Agent 共用一个 JVM：

```bash
java \
  -javaagent:/path/to/opentelemetry-javaagent-2.31.1.jar \
  -Dotel.javaagent.extensions=/path/to/securitycontext.jar \
  -jar application.jar
```

HTTP Server instrumenter 的操作开始时创建 `SecurityState`，把状态放进 OTel Context，并记录 HTTP Server Span 的 trace/span ID。操作结束时更新 method、route、status code 和生命周期，发送证据/诊断摘要并关闭状态。Servlet async 以 OTel HTTP server operation 的 onEnd 为结束边界，不能以 `service()` 返回作为结束条件。没有 OTel HTTP Server instrumenter，扩展不能保证建立请求级状态；关闭整体 OTel SDK 或 HTTP Server instrumentation 不在保证范围内。

```text
OTel HTTP Server operation
          │
          ▼
 OTel Context → SecurityState（当前请求）
          │
  ┌───────┼───────────────┐
  ▼       ▼               ▼
 Source  身份/范围传播     Sink
          │               │
          └──────► SecurityContext schema v2
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
      OTel LogRecord              可选 Security JSONL
          │
          └── Security/ SBOM 独立队列和 worker
```

请求之间不共享污点登记表。对象、container、URL destination 和 propagation marks 共用当前请求的对象预算。线程池复用、并发、异常和 async 完成后都释放状态；请求结束后继续运行的任务只有在 OTel Context 仍传播且仍位于 HTTP operation 生命周期内时才属于首版支持范围。

## 四个模块

| 模块 | 责任 | 不负责的内容 |
| --- | --- | --- |
| `security-core` | `SecurityState`、对象身份、Source/传播图、范围、规则、finding fingerprint 和 schema v2 事件模型 | OTel、Servlet、SBOM、文件和应用框架 |
| `security-otel-extension` | extension service 注册、Byte Buddy/ASM 调用点插桩、Servlet/Spring source、Sink 适配、HTTP Context 生命周期和最终 JAR | SBOM 文件持久化和后端 ACK |
| `security-sbom` | classpath/CodeSource/归档发现、Maven/Manifest/许可证解析、哈希、构建 SBOM 合并、release/instance snapshot、history 和 CycloneDX atomic publish | 请求热路径扫描；不猜运行时依赖边 |
| `security-exporter` | OTel LogRecord、安全证据 JSONL、有界队列、按通道预算、health/findings/runs snapshot、控制读取和投递诊断 | `application.cdx.json` 完整文件写入 |

`SbomInventory.publish` 负责 SBOM 临时文件和 atomic move。exporter 只把 `app-dependencies-loaded`/SBOM health 作为 OTel Logs 事件进入独立 SBOM 队列，并不直接写完整 SBOM 文件。

## 请求状态和安全账本

`RuntimeLedger` 在进程内维护；自有快照带顶层 `source=security_context`：

- 进程-local 的 `finding_id` 聚合、occurrence 计数、代表样本和 triage；
- verification run 的 case、rule、suite、fixture、expected request、source/sink/error/loss 计数；
- `health.json`、`findings.json`、`runs.json` 的原子快照；
- pause、run、exception 的 `control.json` revision 与错误；
- active request、每秒请求预算、请求不完整和导出质量计数。

0.2.1 保持状态锁和 carrier 对象锁的顺序约束：`SecurityState.put` 在进入状态锁保护的状态更新前读取 `StringBuffer.length`，不会在状态锁内获取 buffer monitor，避免锁顺序倒置。该并发修复的运行回归结果以 `build/validation/v021/` 为准。

安全请求和 SBOM 分别使用独立队列与线程。默认安全通道为 100 events/s、524288 bytes/s；SBOM 通道为 200 events/s、262144 bytes/s。队列满和预算超限不会阻塞业务，会写入 dropped/budget counter。OTel API emit 只表示调用 API，不能确认 SDK、Collector 或后端 ACK；JSONL 只保证 flush，不保证 fsync。完整字段与命令见[运行运维与 CLI](operations.md)。

### finding 生命周期

`SecurityState.evidence` 根据 application ID、rule、role、logical site 和 source signature 生成稳定 `finding_id`；逻辑 site 尽量包含调用点文件/行号，因此源码行号变化可能形成新的 ID。一次请求的 `evidence_id` 同时作为 `occurrence_id` 输出，聚合账本增加该 finding 的 occurrences 并按 300 秒/新 run 产生代表样本。summary 默认每 30 秒发送。

这套账本是有界、进程-local 的观察，不是跨重启历史数据库。后端如需跨 instance 统计，必须使用 application ID 和 finding ID 聚合。

### 请求预算

在请求开始时，active request 超过 `security.max.active.requests=256`，或每秒请求超过 `security.requests-per-second=1000`，该请求整体进入 `budget_skipped`。达到对象、传播、证据、代表样本或 finding 容量时，设置截断或不完整原因；请求结束仍发送 `security.collection.incomplete` 诊断，即使没有 finding。

对象身份表使用弱引用，避免把业务已丢弃的中间字符串或载体保留到请求结束。追踪元数据、字符串长度和传播节点同时受单请求默认 1 MiB、进程默认 64 MiB 的估算字节预算约束。进程预算使用原子预留，超限停止新增追踪；请求关闭释放剩余预留。这些预算控制采集状态，不构成业务 JVM 的总堆上限。

## Source 与传播

Source 捕获在应用读取或框架绑定完成时发生：

- Servlet 参数、参数集合、Header 和 Enumeration；
- Spring MVC `AbstractMessageConverterMethodArgumentResolver.readWithMessageConverters` 返回的文本、Map/List、POJO；
- `@RequestParam`/`@ModelAttribute` 完成绑定后的结果；
- 应用执行 `BufferedReader.readLine`、Jackson `readValue` 后的请求体值。

`getReader`/`getInputStream` 只登记 carrier，不提前消费请求流。body 递归遍历有深度、总值和每层元素上限；超限留下 coverage gap。传播依据对象身份和字符范围，不使用相等或包含关系猜测污点。Java 8 Builder、现代 `invokedynamic`、字符串转换、URL/HTTP carrier、Map/List 和有限容器边界按实现支持；不全局增强 JDK String 或容器，不为传播创建 Span。HTTP Server Span 的 `security.finding.ids` 指向聚合 finding，`security.evidence.ids` 指向逻辑观察；代表样本周期抑制时，后者不保证每个 occurrence 都有对应导出记录。

调用点预扫描通过 `ClassFileLocator` 读取原类资源。动态生成且无可读 class 资源的类会跳过调用点插桩；SBOM 仍可能通过 CodeSource 观察其制品，但不能把这种观察解释为数据流覆盖。

## Sink 和风险边界

| 类型 | 实际入口 | 首版边界 |
| --- | --- | --- |
| SQL | JDBC Statement execute/executeQuery/executeUpdate、PreparedStatement 执行 | 污染 SQL 模板到达实际执行才出证据；占位符绑定不直接报 SQL 注入 |
| 命令 | Runtime.exec、ProcessBuilder.start | 已识别的 POSIX 组合 `-c`、`-lc`、`-ec`、`-xc` 后脚本文本是 shell 角色；普通 argv 和脚本文件保持普通参数语义 |
| HTTP | URLConnection 实际连接、JDK HttpClient、Apache HttpClient 4/5、OkHttp 3/4 | 只构造 URL/Request 不算发送；目标地址、path/query 和未知地址分开 |
| 文件 | FileInputStream/FileOutputStream/RandomAccessFile、常见 Files 读写/删除/移动 | String → File/Path → 实际文件操作才形成路径事实 |

URL/URI accessor 以结构区段裁剪 source，避免 query 污染 host。编码、转义和规范化是转换记录，不是通用安全证明。非建模的通用 execute/回调响应传播保留边界，因此 URL 受控不等于响应值受控。

## SBOM 库存

SBOM 后台线程扫描 classpath、普通 JAR、Spring Boot nested JAR、WAR 依赖和已加载类的 CodeSource，读取 Maven metadata、Manifest、受限许可证和嵌入式 CycloneDX。外层 artifact 和 nested JAR 只有在实际读取相应字节时才计算 SHA-256；shaded metadata 没有外层哈希冒充。基础设施只按 OTel Agent 实际入口和扩展自身 CodeSource 排除；`net.bytebuddy`/`io.opentelemetry` 包名前缀不会排除包含这些类的外层应用 Boot JAR。

清单分 application、release 和 instance 语义：

- application 是 CycloneDX metadata component，`bom-ref=application_id`；
- release ID 根据 application identity 和已确认 artifact digest 形成，不含路径和 instance；
- instance 由 `sbom_id`、revision 和 process-instance-id 表示，安全证据引用这层。

普通 classpath 扫描不猜 dependency edge；只有可解析的构建 CycloneDX declaration 关系进入 `dependencies`。清单保留 `runtime_dependency_graph_incomplete` 与 `aggregate=incomplete`，表达运行时扫描限制。

组件 parse、归档读取和哈希在后台完成，缓存默认 300 秒。已发布 snapshot 把 revision 与 location mapping 一并发布，Sink resolve 只查同一 snapshot；替换已加载 class 来源导致无法唯一映射时标记 unresolved。质量字段是实际计数（PURL、版本、哈希、许可证、class loaded），不是漏洞覆盖率。

## 输出目录和部署

默认 `security.output=./security-output/<instanceUUID>`，包含：

```text
health.json
findings.json
runs.json
control.json
application.cdx.json
sbom-history.json
```

`security.evidence.file` 可另行配置安全 JSONL。Collector 调试 fixture 与磁盘队列/重试示例见[deploy/README.md](../deploy/README.md)。Collector 持久队列只能改善 Collector 到 backend 的重试路径，不能改变扩展端 API emit 的 ACK 语义。

## 明确范围外

WebFlux、跨服务污点传播、响应结束后的后台任务、任意二进制请求体、反射/native 数据流、JDBC batch、XSS、反序列化漏洞、在线 CVE 查询、漏洞可利用性判断和动态 attach 不属于本原型。
