# SecurityContext Node.js 0.2.5

`securitycontext` 在 Node.js 进程内记录有界的安全数据流证据和运行时 SBOM。它只变换 `SECURITY_NODE_INCLUDE` 指定的绝对路径下的业务 JavaScript；`node_modules`、OpenTelemetry 包、插件自身和 Node 内建模块保留各自的加载边界。事件表示实际观察到的建模调用，不代表漏洞召回率、漏洞确认或生产 SLA。

完整的独立发行说明见[中文指南](docs/guide.zh-CN.md)和[English guide](docs/guide.en.md)。

## 安装与启动

在应用入口之前预加载注册模块和自己的 OpenTelemetry bootstrap：

```sh
# 在发行 bundle 的 nodejs/ 目录执行，或调整 tarball 路径
npm install ./securitycontext-0.2.5.tgz \
  @opentelemetry/api@1.9.1 \
  @opentelemetry/sdk-node@0.222.0 \
  @opentelemetry/instrumentation-http@0.222.0 \
  @opentelemetry/instrumentation-express@0.70.0 \
  express@5.2.1
export SECURITY_NODE_INCLUDE=/absolute/path/to/your/business
node --import securitycontext/register \
  --import ./otel-bootstrap.mjs ./app.mjs
```

`otel-bootstrap.mjs` 应在应用导入 Express、Fastify 或其他被追踪库之前注册宿主 SDK、HTTP/framework instrumentation 和 exporter。没有活动的 OTel server span 时，安全事件仍可写入本地快照，但不能描述为已完成 trace 关联。

应用也可以把同一个 `SecurityInstrumentation` 实例交给宿主 SDK：

```js
import { NodeSDK } from '@opentelemetry/sdk-node';
import { SecurityInstrumentation, shutdown } from 'securitycontext';

const instrumentation = new SecurityInstrumentation();
const sdk = new NodeSDK({ instrumentations: [instrumentation] });
sdk.start();
// 退出时先结束插件自己的有界队列，再由宿主负责关闭 SDK。
await shutdown({ timeoutMillis: 2000 });
await sdk.shutdown();
```

重复导入 register 或重复构造 `SecurityInstrumentation` 会复用同一实例。插件 shutdown 是有界的尽力操作；队列、预算、exporter 和快照故障会记录为丢弃或诊断事件。`shutdown()` 默认等待 1500ms，需要其他边界时传入 `timeoutMillis`。

## 配置

常用开关使用 `SECURITY_*` 环境变量：`SECURITY_ENABLED` 控制安全数据流，SBOM 由独立的 `SECURITY_SBOM_ENABLED` 控制，`SECURITY_NODE_INCLUDE`/`SECURITY_NODE_EXCLUDE` 控制业务文件范围，`SECURITY_OUTPUT` 指定输出目录，`SECURITY_CONTROL_FILE` 和 `SECURITY_EVIDENCE_FILE` 指定控制与证据路径。资源限制包括 `SECURITY_MAX_TRACKED_BYTES`、`SECURITY_MAX_PROCESS_TRACKED_BYTES`、`SECURITY_MAX_ACTIVE_REQUESTS`、`SECURITY_REQUESTS_PER_SECOND`、`SECURITY_EXPORT_QUEUE_SIZE` 和 `SECURITY_EXPORT_SBOM_QUEUE_SIZE`。规则可以用 `SECURITY_RULES_<RULE>_ENABLED` 逐项开关，例如 `SECURITY_RULES_SQL_INJECTION_ENABLED` 和 `SECURITY_RULES_PATH_TRAVERSAL_ENABLED`。

默认输出目录包含 `health.json`、`findings.json`、`runs.json` 和控制状态；启用 SBOM 时还会产生 `application.cdx.json` 与 `sbom-history.json`。SecurityContext 自有状态快照带顶层 `source=security_context`。health、SBOM 与 history 是进程级快照，不强行关联请求 trace；dataflow evidence 才记录请求 trace。SBOM 以锁文件声明依赖为基础，并结合运行时加载观察；包解析、哈希或运行时依赖图不完整时会保留 `incomplete` 状态，不能当作完整部署清单。

当前建模的 sink 包括文件路径（如 `fs.readFile`）、命令可执行文件/argv（如 `child_process.exec`/`execFile`）、出站 HTTP 的 host/path/query（HTTP client/fetch）和 SQL 模板（`pg`/`mysql2`）。这些是显式建模调用的观察结果，不是所有第三方库、私有动态模块、generator 或任意 JavaScript 语法的覆盖承诺。

单模块源码超过 2 MiB 或 AST 超过 50,000 个节点时保留原代码执行，并记录覆盖缺口。重导出的标记查询按次去重，并限制查询量和深度；达到上限时可能缺少传播证据，业务值仍由原生模块系统提供。具体边界见[兼容性说明](docs/compatibility.md)。

## 打包安装和 CLI

从发行 bundle 的 `nodejs/` 目录安装本地 tarball；创建应用与 bootstrap 的完整步骤见上方指南：

```sh
npm install ./securitycontext-0.2.5.tgz @opentelemetry/api@1.9.1
export SECURITY_OUTPUT=./security-output
node --import securitycontext/register \
  --import ./otel-bootstrap.mjs ./app.mjs
python3 node_modules/securitycontext/data/securityctl.py \
  --dir ./security-output status
```

当前 Node 22 目标为 `>=22.22.3 <23`，Node 24 目标为 `>=24.11.1 <25`；Express 4/5 与 Fastify 5 的 ESM/CommonJS 边界见[兼容性说明](docs/compatibility.md)。验证文档只报告已实际运行的组合，不把静态文件检查当作运行验收。

## 事件契约

Node.js 与 Python、Java 共用 schema v2 契约；随包的[中文指南](docs/guide.zh-CN.md)和[English guide](docs/guide.en.md)包含事件字段、source、SBOM、trace 与截断规则。OTel envelope 的 scope.name 为 `SecurityContext`，native `eventName`、`event.name` attribute 和 body 的 `event_name` 必须一致；SBOM 上报（`app-dependencies-loaded` 和 `security.sbom.*`）使用 `source=security_context_sbom`，其他安全事件使用 `source=security_context`；OTLP log 的 `attributes.source` 与 JSON body 的 `source` 一致。截断 summary/minimal 保留原事件的 source。`sources[]` 中每个来源条目有六个统一字段，另有六个 identity 字段和统一 runtime/source/sink/component 结构。Node.js 文本范围使用 `utf16_code_unit`，Buffer 使用 `byte`。

## 文档与边界

- [中文完整指南](docs/guide.zh-CN.md)
- [English guide](docs/guide.en.md)
- [兼容性](docs/compatibility.md)
- [验证记录](docs/verification.md)
- [发行清单](docs/release-checklist.md)
- [样例入口](samples/README.md)

数据流、ledger 和 JSONL 不依赖 span 存在；请求 dataflow 的 `trace_id`/`server_span_id` 来自 server span，`current_span_id` 在 sink 处捕获，事件生成后冻结；只有应用启用 provider/server instrumentation 且存在有效 server span 时，事件才带有可用 trace 关联。health、SBOM 和 history 是进程级输出，不因没有请求 span 而改写身份。OTel API emit 不是 SDK、Collector 或后端 ACK；本地 JSONL flush 也不是 `fsync`。

## 已加载依赖上报

依赖上报使用 `app-dependencies-loaded`，`dependencies` 数组中的每项只保留 `name`、`version`，缺少完整坐标或版本且有真实制品 SHA-256 时增加 `hash`。只上报实际观察到加载的依赖；本地 `application.cdx.json` 继续保留 CycloneDX，`sbom-history.json` 保留组件历史及原有容量限制。

大快照使用相同 `sbom_id`/`revision` 分片，`part_index` 从 0 开始；消费端收齐 `part_count` 片后整体替换。SBOM 每秒预算不足时在后台等待下一窗口，记录 `sbom.budget_deferred`；队列容量和关闭期限仍有上限，API emit 不代表后端 ACK。此事件替代旧的组件增量和 snapshot 上报，消费端需要调整订阅及解析。
