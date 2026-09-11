# SecurityContext Node.js 0.2.5 使用指南

本指南随 `securitycontext-0.2.5.tgz` 分发，可脱离源码仓库使用。包版本、依赖锁定和本次实际验证以包内 metadata、`data/dependency-lock.json` 与随发布 bundle 的 validation/release-validation 记录为准；指南不复制历史测试数字。

## 1. 版本、依赖与本地安装

目标运行时为 Node.js `>=22.22.3 <23` 或 `>=24.11.1 <25`。包名和 import 名均为 `securitycontext`，OTel API peer dependency 为 `>=1.9.1 <1.10.0`；当前锁定的 OTel SDK/instrumentation 版本为 `0.222.0`，`@opentelemetry/api` 为 `1.9.1`。应用仍需提供自己的框架、HTTP instrumentation 和 logs provider。

从发行 bundle 的 Node 目录安装本地 tarball，避免从 registry 获取同名但无关的包：

```bash
cd nodejs
npm install ./securitycontext-0.2.5.tgz \
  @opentelemetry/api@1.9.1 \
  @opentelemetry/sdk-node@0.222.0 \
  @opentelemetry/instrumentation-http@0.222.0 \
  @opentelemetry/instrumentation-express@0.70.0 \
  @opentelemetry/exporter-trace-otlp-http@0.222.0 \
  @opentelemetry/exporter-logs-otlp-http@0.222.0 \
  express@5.2.1
```

安装后，`securitycontext/register`、`securitycontext`、`data/securityctl.py` 和本目录 `docs/` 来自同一个 tarball。不要把源码 checkout 外的共享文档路径写入部署脚本。

## 2. 最小可运行示例

先创建 `otel-bootstrap.mjs`，让 SDK、HTTP/Express instrumentation 和 SecurityContext 在应用导入前完成注册：

```js
import { NodeSDK } from '@opentelemetry/sdk-node';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { ExpressInstrumentation } from '@opentelemetry/instrumentation-express';
import { SecurityInstrumentation } from 'securitycontext';

const sdk = new NodeSDK({
  instrumentations: [
    new HttpInstrumentation(),
    new ExpressInstrumentation(),
    new SecurityInstrumentation(),
  ],
});
sdk.start();
```

再创建 `app.mjs`。这个最小 Express 5 路由把 `req.query.name` 传到文件读取边界，便于观察一个实际的 source-to-sink 请求：

```js
import express from 'express';
import { readFile } from 'node:fs/promises';

const app = express();
app.get('/read', async (req, res) => {
  const requested = String(req.query.name ?? 'README.md');
  try {
    const body = await readFile(requested, 'utf8');
    res.type('text/plain').send(body.slice(0, 256));
  } catch {
    res.status(404).send('not found');
  }
});
const server = app.listen(3000, '127.0.0.1');
process.once('SIGTERM', () => server.close());
```

使用 Express/Fastify 等应用时，先安装并配置宿主 SDK，再启动应用：

```bash
export SECURITY_NODE_INCLUDE="$PWD"
export SECURITY_OUTPUT="$PWD/security-output"
export SECURITY_EVIDENCE_FILE="$PWD/security-output/evidence.jsonl"
export SECURITY_ENABLED=true
export SECURITY_SBOM_ENABLED=true
export OTEL_SERVICE_NAME=orders
node --import securitycontext/register \
  --import ./otel-bootstrap.mjs ./app.mjs
# 另开终端发送请求，触发 req.query -> fs.readFile 观察
curl 'http://127.0.0.1:3000/read?name=README.md'
```

`otel-bootstrap.mjs` 必须早于 Express、Fastify、`pg`、`mysql2` 或 `undici` 的应用导入；`securitycontext/register` 只建立包自己的 scoped require/import hooks，不替宿主 SDK 接管 provider。没有 HTTP server span 时仍可能生成 dataflow，但 trace 关联字段会为空。

### 连接本地 Collector 并查看请求

下面的最小 Collector 配置接收 OTLP HTTP `4318`（traces/logs），使用 `memory_limiter`、`batch` 和 `debug` exporter。将它保存为 `otel-collector-config.yaml`，再用与配置匹配的 Collector 二进制启动：

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 256
  batch:
    timeout: 2s
exporters:
  debug:
    verbosity: detailed
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [debug]
    logs:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [debug]
```

```bash
otelcol --config ./otel-collector-config.yaml
```

在另一个终端加入 OTLP 环境变量后启动上面的 `app.mjs`，再请求并查看本地输出：

```bash
export SECURITY_NODE_INCLUDE="$PWD"
export SECURITY_OUTPUT="$PWD/security-output"
export SECURITY_EVIDENCE_FILE="$PWD/security-output/evidence.jsonl"
export SECURITY_ENABLED=true
export SECURITY_SBOM_ENABLED=true
export OTEL_SERVICE_NAME=orders
export OTEL_TRACES_EXPORTER=otlp
export OTEL_LOGS_EXPORTER=otlp
export OTEL_METRICS_EXPORTER=none
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
node --import securitycontext/register \
  --import ./otel-bootstrap.mjs ./app.mjs
```

再开终端执行 `curl 'http://127.0.0.1:3000/read?name=README.md'`，随后运行：

```bash
python3 node_modules/securitycontext/data/securityctl.py \
  --dir "$PWD/security-output" status
python3 node_modules/securitycontext/data/securityctl.py \
  --dir "$PWD/security-output" query findings
tail -n 5 "$PWD/security-output/evidence.jsonl"
```

Collector 的 `debug` exporter 会打印收到的 OTLP records；health、SBOM 和 history 仍是进程级快照。

## 3. 配置

| 环境变量 | 默认值 | 作用 |
| --- | --- | --- |
| `SECURITY_ENABLED` | `true` | 安全数据流采集总开关 |
| `SECURITY_NODE_INCLUDE` | 空 | 必须是绝对路径；只转换该路径下业务 JavaScript |
| `SECURITY_NODE_EXCLUDE` | 空 | 逗号分隔的排除路径 |
| `SECURITY_SBOM_ENABLED` | `true` | 独立开启 runtime SBOM |
| `SECURITY_OUTPUT` | `./security-output/<instance-id>` | health、findings、runs、control 和 SBOM 目录 |
| `SECURITY_CONTROL_FILE` | output 下 `control.json` | 本地控制文件 |
| `SECURITY_EVIDENCE_FILE` | 未配置 | security evidence/diagnostic JSONL；不写 SBOM 事件 |
| `SECURITY_APPLICATION_ID` | 由 OTel service identity 回退生成 | 应用身份，建议显式设置 |
| `SECURITY_CODE_REPOSITORY` | 空 | 验证 run 的真实代码仓库身份 |
| `SECURITY_CODE_COMMIT` | 空 | 验证 run 的真实提交身份 |
| `SECURITY_CODE_BUILD_ID` | 空 | 验证 run 的真实构建身份 |
| `SECURITY_RULES_<RULE>_ENABLED` | `true` | SQL、命令、SSRF、HTTP input、path traversal 规则 |
| `SECURITY_MAX_ACTIVE_REQUESTS` | `256` | 并发 request 预算 |
| `SECURITY_MAX_NODES` | `8192` | 单请求传播节点预算 |
| `SECURITY_MAX_FINDINGS` | `32` | 单请求 finding 预算 |
| `SECURITY_RUNS_MAX_BYTES` | `8388608` | 所有 run 计数器的键和值保留预算估计；超限增加 incomplete 和 health 计数 |
| `SECURITY_EVIDENCE_MAX_BYTES` | `65536` | 单条记录字节预算 |
| `SECURITY_EXPORT_QUEUE_SIZE` / `SECURITY_EXPORT_SBOM_QUEUE_SIZE` | `1024` / `256` | 两个独立队列容量 |

值通过 process 环境读取，修改后应重启并使用新的 instance output。`SECURITY_NODE_INCLUDE` 为空、路径不是绝对路径或运行时不在 Node 22/24 目标范围时，不会得到完整 collection。

run 快照复用未变化记录，只向 worker 发送变化行；已发布计数表在下一次更新时复制，写入成功后才确认版本。对象 source 采集最多读取 128 个字段描述符，不调用 getter；JavaScript 的键枚举仍随输入字段数增长，因此应用仍应限制请求体大小。若 direct eval 可见的业务绑定名为 `Symbol` 或 `globalThis`，该模块保留原生代码，并记录 `direct_eval_helper_binding` 采集缺口。

## 4. 输出与 schema v2

`health.json`、`findings.json`、`runs.json`、`control.json`、`application.cdx.json`、`sbom-history.json` 和可选 `evidence.jsonl` 是主要输出。自有状态快照顶层保留 `source="security_context"`。health、SBOM 与 sbom-history 是进程级快照，不强行关联某个请求 trace；dataflow evidence 才按请求保存 trace 关联。schema v2 事件平铺：

`application_id`、`instance_id`、`service`、`code`、`runtime`、`identity_status`。

OTel envelope 的 `scope.name` 为 `SecurityContext`，不是 body 字段；native `eventName`、`event.name` attribute、body 的 `event_name` 必须一致，OTel `source` attribute 必须与 body 的 `source` 一致。runtime 的 `language=javascript`、`implementation=nodejs`；文本 range 使用 `utf16_code_unit`，Buffer 使用 `byte`。SBOM 上报（`app-dependencies-loaded` 和 `security.sbom.*`）使用 `source=security_context_sbom`，其他安全事件使用 `source=security_context`；OTLP log 的 `attributes.source` 与 JSON body 的 `source` 一致。截断 summary/minimal 保留原事件的 source。`sources[]` 中每个来源条目有 `id/type/name/location/value_type/value_length` 六字段，`sources[].name` 最多 256 字符；Node source 可为 `string`、`number`、`boolean`、`bigint` 或 `Buffer`。

sink role 使用 canonical `sql_template`、`shell_script`、`argument`、`executable`、`destination_address`、`destination_unknown`、`path_or_query`、`file_path`；文件 `operation` 保留 read/write/copy/rename/delete/unknown，无法确定路径 source/target 时用 `unknown`。fingerprint v2 包含 language、每段 UTF-8 长度前缀和 UTF-16 signature 排序；同一请求按 v2 `finding_id` 去重。

SBOM 事件走独立 channel。CycloneDX 顶层保持标准结构，source marker 放在标准 `properties[]`，properties namespace 为 `securitycontext:`，component ref 使用 `urn:securitycontext:component:`。security JSONL 只写 evidence/diagnostic 白名单，不写 `security.sbom.*` 事件。

## 5. Trace、截断与交付

请求 dataflow 的 `trace_id`、`server_span_id` 来自 HTTP Server span，`current_span_id` 在 sink 处从当前 span 捕获；事件生成后冻结这些字段和 `trace_flags`，exporter 不以之后的当前线程/span 重写它们。没有有效 server span 时 ID 为空、flags 为 `0`，trace ID 本身不代表后端有 trace。进程级 health、SBOM 和 history 使用自己的观察时间与身份，不强行填入请求 span。OTel API emit 不等于 SDK、Collector 或 backend ACK。

记录超出 `SECURITY_EVIDENCE_MAX_BYTES` 时先删除 `propagation`、`ranges`、`sources`，再输出 `security.export.truncated` summary。summary 保留 `original_event`、`evidence_id`、`sbom_id`（无值为 `null`）和 `truncated=true`，与 minimal 一样不要求 identity/`observed_at`。minimal 固定为 `source`、`schema_version`、`event_name`、`truncated` 四字段；四字段也放不下时记录 `record_too_small_for_envelope` 并增加 channel `.failed`，不直接增加 dropped。`security_dropped`、`sbom_dropped` 分开统计，只有 security channel loss/failure/truncation 进入 security ledger `delivery_loss`。

## 6. CLI 与验证 run

Node 包内 CLI 是随包复制的 Python 标准库脚本：

```bash
CLI=node_modules/securitycontext/data/securityctl.py
OUT="$PWD/security-output"
python3 "$CLI" --dir "$OUT" status
python3 "$CLI" --dir "$OUT" query findings
python3 "$CLI" --dir "$OUT" query runs
python3 "$CLI" --dir "$OUT" query sbom
python3 "$CLI" --dir "$OUT" pause
python3 "$CLI" --dir "$OUT" resume
```

run 覆盖进程窗口内全部 HTTP 请求，必须隔离流量：

```bash
python3 "$CLI" --dir "$OUT" run-start \
  --case sql-dynamic --rule sql_injection --suite node-sample \
  --fixture express5-node24 --expected-requests 1 --ttl 300
python3 "$CLI" --dir "$OUT" run-stop --output "$OUT/candidate.json"
python3 "$CLI" verify --baseline "$OUT/baseline.json" \
  --candidate "$OUT/candidate.json" --output "$OUT/verification.json"
```

`observed`、`not_observed` 和 `inconclusive` 只描述指定条件下的运行时观察，不能解释为漏洞确认、修复或完整覆盖。control/report 输出带 source，但自身状态 schema 可以为 v1。

## 7. 升级、停用和卸载

旧 package/import/JAR/namespace 没有自动兼容 shim。消费者需手动改为 `securitycontext` 和当前 import 路径；历史事件 reader 需自行兼容 v1。fingerprint v1/v2 必须分开聚合，v2 不可静默重算为 v1 ID。

运行期可以通过 `instrumentation.disable()` 停止新的 collection；完整停用应设置 `SECURITY_ENABLED=false`、停止进程并重启。退出时先调用：

```js
await shutdown({ timeoutMillis: 2000 });
await sdk.shutdown();
```

卸载前停止 Node 进程，删除 `securitycontext` 依赖和 output；Node 不会在运行中的 process 内热卸载已建立的 hooks。

## 8. 故障排查与边界

- 没有事件：检查 `SECURITY_NODE_INCLUDE` 是绝对业务路径，register/bootstrap 早于应用导入，并确认宿主 logs provider。
- 只有快照没有 trace：确认 HTTP instrumentation 与 provider 在请求前启动；无 server span 时为空是预期行为。
- 没有 JSONL：检查 `SECURITY_EVIDENCE_FILE` 父目录权限；SBOM 不写该文件。
- `incomplete`/`truncated`：检查 `coverage_gaps`、对象/节点/finding/字节预算及两个 channel 的 dropped/failed。
- 适配器不工作：确认 Express 4/5、Fastify 5、`pg` 8、`mysql2` 3、`undici` 8，并避免私有 loader、动态模块和已提前导入的目标模块。
- SBOM unresolved：确认 package-lock、archive 和 runtime load metadata 可读；未知版本/hash/dependency edge 保留 reason，不猜测。

默认不输出请求原文、完整 SQL、命令正文、完整 URL 或命令参数值。任意 JavaScript 语法、私有动态模块、跨服务 taint、响应结束后的后台任务、任意二进制 body、反射/native 数据流、强杀/主机故障恢复、trace replay、Collector/backend ACK、性能和 SLA 不在默认保证范围内。
