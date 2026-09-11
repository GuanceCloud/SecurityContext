# SecurityContext Python 0.2.5 使用指南

本指南随 `securitycontext-0.2.5` 的 wheel 和 sdist 分发，可脱离源码仓库阅读。包名和 import 名均为 `securitycontext`，目标解释器为 CPython 3.11–3.14。包内的 `securitycontext/data/docs/` 保存随包文档；发行目录中的 `validation` 与 `release-validation` 记录具体构建和运行结果，发行说明不把历史验收数字当作本版门禁结论。

## 版本、依赖与安装

核心运行依赖固定为 `opentelemetry-api==1.44.0`、`opentelemetry-instrumentation==0.65b0`、`opentelemetry-instrumentation-threading==0.65b0`、`wrapt>=1.17,<3` 和 `packaging>=24`。可选的框架适配器为 FastAPI、Flask、Django；OTLP 启动组合为 `opentelemetry-distro==0.65b0` 与 `opentelemetry-exporter-otlp-proto-http==1.44.0`。应用自己的框架、ASGI/WSGI server、数据库和 HTTP client 仍由应用环境提供。当前目标不包括 PyPy、无 GIL/free-threaded Python 或非 CPython 解释器。

从发行 bundle 中安装本地文件，避免从 registry 取得同名但无关的包：

```bash
python -m pip install ./securitycontext-0.2.5-py3-none-any.whl
# 或者
python -m pip install ./securitycontext-0.2.5.tar.gz
python -m pip install \
  opentelemetry-distro==0.65b0 \
  opentelemetry-exporter-otlp-proto-http==1.44.0 \
  opentelemetry-instrumentation-fastapi==0.65b0
```

只按应用实际框架安装 `fastapi`、`flask`、`django` 或 `otlp` extra。安装后，样例、Collector 配置、constraints、CLI 和文档从 `securitycontext/data/` 读取；样例不是生产依赖，也不会成为顶层应用包。

## OTel 接入顺序和最小示例

普通 ASGI/WSGI 进程通过 OTel 的 pre-instrument/instrumentor entry point 启动。安全入口必须在应用模块和数据库/HTTP client 导入前加载：

```bash
export SECURITY_ENABLED=true
export SECURITY_PYTHON_INCLUDE=myapp,mycompany.service
export SECURITY_PYTHON_EXCLUDE=myapp.migrations
export SECURITY_OUTPUT="$PWD/security-output"
export SECURITY_EVIDENCE_FILE="$PWD/security-output/evidence.jsonl"
export SECURITY_SBOM_ENABLED=true
export OTEL_SERVICE_NAME=orders
export OTEL_LOGS_EXPORTER=otlp

opentelemetry-instrument uvicorn myapp.main:app \
  --host 127.0.0.1 --port 8000
```

`SECURITY_PYTHON_INCLUDE` 必须包含至少一个应用模块前缀；空值不会安装 Python AST loader。`SECURITY_PYTHON_EXCLUDE` 优先于 include。已经在 instrumentation 前导入的模块不会被回溯转换，因而应把 `opentelemetry-instrument` 放在最外层启动命令。

也可以直接运行包内 FastAPI 样例。它随 wheel 位于 `securitycontext/data/samples/security_sample`，下面的命令会从已安装包取得目录、启动真实应用并发送请求：

```bash
python -m pip install fastapi uvicorn requests opentelemetry-instrumentation-fastapi==0.65b0
SAMPLES_DIR="$(python - <<'PY'
from importlib.resources import files
print(files("securitycontext").joinpath("data", "samples"))
PY
)"
SECURITY_ENABLED=true \
SECURITY_PYTHON_INCLUDE=security_sample \
SECURITY_OUTPUT="$PWD/security-output" \
SECURITY_EVIDENCE_FILE="$PWD/security-output/evidence.jsonl" \
OTEL_SERVICE_NAME=security-sample \
PYTHONPATH="$SAMPLES_DIR" \
  opentelemetry-instrument python -m uvicorn \
  security_sample.fastapi_app:app --host 127.0.0.1 --port 8000

# 另开终端：POST /probe 会读取 query/path/header/body 并触发样例中的建模 sink
curl -X POST -H 'content-type: application/json' \
  --data '{"query":"sample","filename":"safe.txt"}' \
  'http://127.0.0.1:8000/probe/demo?q=sample'
```

### 连接本地 Collector 并查看请求

下面的最小 Collector 配置接收 OTLP HTTP `4318` 的 traces/logs，经过 `memory_limiter` 和 `batch` 后由 `debug` exporter 打印。保存为 `otel-collector-config.yaml`，再用匹配的 Collector 二进制启动：

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

在另一个终端，用前面的包内样例命令增加 OTLP 环境变量并启动，再从第三个终端发请求和查看输出：

```bash
export OTEL_TRACES_EXPORTER=otlp
export OTEL_LOGS_EXPORTER=otlp
export OTEL_METRICS_EXPORTER=none
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
# 重复前面的 SAMPLES_DIR/PYTHONPATH 与 opentelemetry-instrument 命令
```

```bash
curl -X POST -H 'content-type: application/json' \
  --data '{"query":"sample","filename":"safe.txt"}' \
  'http://127.0.0.1:8000/probe/demo?q=sample'
securityctl --dir "$PWD/security-output" status
securityctl --dir "$PWD/security-output" query findings
tail -n 5 "$PWD/security-output/evidence.jsonl"
```

Collector 的 `debug` exporter 会打印收到的 OTLP records；health、SBOM 和 history 仍是进程级快照。

Gunicorn 必须在 worker 中初始化 OTel：

```bash
gunicorn -c python:securitycontext.gunicorn \
  --bind 127.0.0.1:8000 myapp.wsgi:application
```

该配置在 `post_fork` 隔离每个 worker 的输出目录，然后调用 OTel `initialize()`。`preload_app=True` 会被拒绝；不要用 `opentelemetry-instrument gunicorn`，因为它会在 master/fork 前初始化 SDK。

## 配置

配置通过环境变量读取；修改后重启进程。布尔值只有不区分大小写的 `true` 开启，数字预算至少为 1。

| 环境变量 | 默认值 | 作用 |
| --- | --- | --- |
| `SECURITY_ENABLED` | `true` | 安全数据流采集总开关 |
| `SECURITY_PYTHON_INCLUDE` | 空 | 逗号分隔的应用模块前缀，必须显式设置 |
| `SECURITY_PYTHON_EXCLUDE` | 空 | 优先排除的模块前缀 |
| `SECURITY_OUTPUT` | `./security-output/<instance_id>` | health、findings、runs、control 和 SBOM 输出目录 |
| `SECURITY_EVIDENCE_FILE` | 未配置 | 安全 evidence/diagnostic JSONL；不写 SBOM 事件 |
| `SECURITY_CONTROL_FILE` | output 下 `control.json` | pause、resume、run、例外控制文件 |
| `SECURITY_SBOM_ENABLED` | `true` | 独立开启 runtime SBOM |
| `SECURITY_SBOM_OUTPUT` | output 下 `application.cdx.json` | SBOM 快照路径 |
| `SECURITY_RULES_SQL_INJECTION_ENABLED` | `true` | SQL 模板拼接数据流；绑定参数不会提升为 SQL 注入证据 |
| `SECURITY_RULES_COMMAND_EXECUTION_ENABLED` | `true` | executable 与 argument 观察 |
| `SECURITY_RULES_COMMAND_INJECTION_ENABLED` | `true` | shell script 观察 |
| `SECURITY_RULES_SSRF_ENABLED` | `true` | 实际 HTTP destination 观察 |
| `SECURITY_RULES_HTTP_REQUEST_INPUT_ENABLED` | `true` | outbound URL path/query carrier |
| `SECURITY_RULES_PATH_TRAVERSAL_ENABLED` | `true` | 文件路径边界观察 |
| `SECURITY_MAX_TRACKED_BYTES` / `SECURITY_MAX_PROCESS_TRACKED_BYTES` | 1 MiB / 64 MiB | 单请求/进程传播字节预算 |
| `SECURITY_MAX_ACTIVE_REQUESTS` / `SECURITY_REQUESTS_PER_SECOND` | 256 / 1000 | 并发请求与速率预算 |
| `SECURITY_MAX_NODES` / `SECURITY_MAX_FINDINGS` | 8192 / 32 | 单请求图节点与 finding 预算 |
| `SECURITY_EVIDENCE_MAX_BYTES` | 65536 | 单条 evidence 字节预算 |
| `SECURITY_EXPORT_QUEUE_SIZE` / `SECURITY_EXPORT_SBOM_QUEUE_SIZE` | 1024 / 256 | 安全和 SBOM 两条独立队列 |
| `SECURITY_APPLICATION_ID`、`OTEL_SERVICE_NAME` | fallback | 应用与服务身份，建议显式设置 |

进程外停用也可设置 `OTEL_PYTHON_DISABLED_INSTRUMENTATIONS=securitycontext` 或 `*`。已加载的 import finder 不会在运行中卸载；停用后需停止并重启进程。

## 输出、schema v2 与 source

主要输出为 `health.json`、`findings.json`、`runs.json`、`control.json`、`application.cdx.json` 和 `sbom-history.json`。自有快照 `health`、`findings`、`runs` 的顶层都有 `source`（SBOM 日志为 `security_context_sbom`，其他安全事件为 `security_context`）；`sbom-history` 使用 app/release 等历史身份字段；控制和报告可以保持自身 schema v1，但也写入相同 source。安全事件写入配置的 evidence JSONL，SBOM 事件走独立 channel，不进入安全 JSONL。

事件 schema v2 的共同根字段为：

- `schema_version=2`、`event_name`、UTC 毫秒精度的 `observed_at`、`source`（SBOM 日志为 `security_context_sbom`，其他安全事件为 `security_context`）；
- 平铺的 `application_id`、`instance_id`、`service`、`code`、`runtime`、`identity_status`；调用者只提供了部分身份时允许 `identity_status=incomplete`，未知身份字段按字段契约保持空字符串或 `null`，不能猜测补齐；
- `runtime={language,implementation,version,os,architecture,details}`，Python 的 GIL/build 信息放在 `details`；
- OTel envelope 的 `scope.name="SecurityContext"`；它不是 body 字段。native `eventName`、`event.name` attribute 与 body 的 `event_name` 必须一致，OTel `source` attribute 必须与 body 的 `source` 一致。

SBOM 上报（`app-dependencies-loaded` 和 `security.sbom.*`）使用 `source=security_context_sbom`，其他安全事件使用 `source=security_context`；OTLP log 的 `attributes.source` 与 JSON body 的 `source` 一致。截断 summary/minimal 保留原事件的 source。`sources[]` 中每个来源条目固定有 `id`、`type`、`name`、`location`、`value_type`、`value_length` 六个字段，名称最多 256 个字符。Python 支持 `str`、`bytes` 和 `bytearray` 来源；字符串长度使用 `unicode_code_point`，bytes/bytearray 使用 `byte`。`sink.role` 只使用 canonical `sql_template`、`shell_script`、`argument`、`executable`、`destination_address`、`destination_unknown`、`path_or_query`、`file_path`；文件 `operation` 保留，路径参数 `source`、`target` 不确定时写 `unknown`，不能猜测。

SBOM 快照保持 CycloneDX 标准结构；source 放在标准 `properties[]` 的 `{name:"source",value:"security_context"}`，namespace 为 `securitycontext:`，component ref 使用 `urn:securitycontext:component:`。SBOM 的 `quality.loaded_components` 记录已观察到加载的组件数；证据中的组件引用通过 `status`/`reason` 说明解析结果，不推测未知版本或依赖关系。

## Trace、截断和交付

请求 dataflow 的 `trace_id`、`server_span_id` 来自 HTTP server span，`current_span_id` 在 sink 处从当前 span 捕获；事件生成后冻结这些字段及 `trace_flags`。没有有效 server span 时 ID 为空、flags 为 `0`。进程级 health、SBOM 和 history 使用自己的观察时间与身份，不强行填入请求 span。OTel API `emit` 不等于 SDK、Collector 或后端 ACK；事件和 ledger 可以在没有 span 时产生，但空 trace ID 不能作为关联证据。

超过单条字节预算时，先移除可选 evidence，再写 `security.export.truncated` summary。summary 和 minimal 都可以缺少共同 identity/`observed_at`：summary 保留 `original_event`、`evidence_id`、`sbom_id`（无值为 `null`）与 `truncated=true`；minimal 固定为 `schema_version`、`source`、`event_name`、`truncated`。连最小 envelope 也放不下时记录 `record_too_small_for_envelope`，并增加对应 channel 的 `.failed` 计数，不直接增加 dropped。`security_dropped`、`sbom_dropped` 分开统计，只有 security channel 的丢失/失败/截断进入 security ledger 的 `delivery_loss`。

## CLI 与 run 流程

安装后的命令和 editable 环境都使用同一个 canonical CLI：

```bash
OUT="$PWD/security-output"
securityctl --dir "$OUT" status
securityctl --dir "$OUT" query findings --offset 0 --limit 100
securityctl --dir "$OUT" query runs --case my-case
securityctl --dir "$OUT" query sbom --offset 0 --limit 100
securityctl --dir "$OUT" pause
securityctl --dir "$OUT" resume
```

需要直接调用模块时使用 `python -m securitycontext.cli --dir "$OUT" status`。验证 run 必须隔离请求流量，并提供真实 identity：

```bash
securityctl --dir "$OUT" run-start \
  --case sql-dynamic --rule sql_injection --suite python-sample \
  --fixture fastapi-cpython312 --expected-requests 1 --ttl 300
securityctl --dir "$OUT" run-stop --output "$OUT/candidate.json"
securityctl verify --baseline "$OUT/baseline.json" \
  --candidate "$OUT/candidate.json" --output "$OUT/verification.json"
```

`observed`、`not_observed` 和 `inconclusive` 只表示给定条件下的运行时观察，不等于漏洞确认、修复或完整覆盖。status、control、report 的自有 schema 可为 v1；事件仍必须是 schema v2。

## 升级、停用与卸载

旧 package/import/JAR/namespace 没有自动兼容 shim。消费者需手动把依赖和 import 更新为 `securitycontext`，历史事件 reader 需自行兼容 v1。fingerprint v1 与 v2 必须分开聚合；v2 使用包含语言的 UTF-8 长度前缀和 UTF-16 顺序签名，不能静默重算为 v1 ID。

停用步骤：

```bash
export SECURITY_ENABLED=false
export OTEL_PYTHON_DISABLED_INSTRUMENTATIONS=securitycontext
# 停止旧进程后，以新的环境变量重启
python -m pip uninstall securitycontext
```

卸载前应先停止所有 worker，并保留或清理 output、evidence 和 SBOM 文件；卸载不会删除已经写出的账本。

## 故障排查与能力边界

- 没有事件：确认 `SECURITY_ENABLED=true`、include 是真实模块前缀、命令使用 `opentelemetry-instrument`，且目标模块没有提前导入。
- 只有快照没有 trace：确认 OTel provider、HTTP server instrumentation 和日志 exporter 在请求前启动；没有 server span 时为空是预期行为。
- Gunicorn worker 互相覆盖：确认使用 `python:securitycontext.gunicorn`，没有 `preload_app=True`，并针对具体 worker 输出目录运行 CLI。
- 只有 `incomplete` 或 `truncated`：检查 include/exclude、对象/节点/finding/字节预算、队列 dropped/failed 和 `coverage_gaps`。
- SBOM 不完整：确认 package metadata、已加载组件和运行时依赖可读；未知版本/hash/dependency edge 保留 reason，不猜测。
- JSONL 为空：检查 evidence 文件父目录权限；SBOM 事件不会写入安全 JSONL。

默认不输出请求原文、完整 SQL、命令正文、完整 URL 或命令参数值。未建模的任意 Python 语法、无源码 `.pyc`/native module、动态生成模块、跨服务 taint、任意二进制 body、强杀/主机故障恢复、trace replay、Collector/backend ACK、性能和 SLA 不在默认保证范围内。事件描述的是已建模调用的观察结果。

更多包内材料见 [配置](configuration.md)、[兼容性](compatibility.md)、[架构](architecture.md) 和 [验证记录](verification.md)。
