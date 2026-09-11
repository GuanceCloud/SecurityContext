# SecurityContext Python 0.2.0 配置

配置读取统一使用环境变量：小写点号和连字符转为大写下划线，例如 `security.max.objects` → `SECURITY_MAX_OBJECTS`。布尔值只有不区分大小写的 `true` 才开启；数字配置至少为 1。除 `control.json` 外，配置在 runtime/exporter/request state/SBOM 创建时读取，修改环境变量不会热更新已经运行的进程。

## 最小启动配置

```bash
export SECURITY_ENABLED=true
export SECURITY_PYTHON_INCLUDE=myapp,mycompany.service
export SECURITY_PYTHON_EXCLUDE=myapp.migrations
export SECURITY_OUTPUT="$PWD/security-output"
export SECURITY_EVIDENCE_FILE="$PWD/security-output/evidence.jsonl"
export SECURITY_SBOM_ENABLED=true
export OTEL_SERVICE_NAME=myapp
export OTEL_LOGS_EXPORTER=otlp
opentelemetry-instrument uvicorn myapp.main:app --host 127.0.0.1 --port 8000
```

Gunicorn 不使用 `opentelemetry-instrument gunicorn`。使用包提供的 post-fork 配置模块：

```bash
gunicorn -c python:securitycontext.gunicorn \
  --bind 127.0.0.1:8000 \
  myapp.wsgi:application
```

worker 在导入应用前初始化 OTel；`preload_app=True` 会被拒绝。post-fork 会为每个 worker 生成 `worker-{pid}-{random8}`，把 `SECURITY_OUTPUT`（默认根 `security-output`）改到该子目录，并把显式 `SECURITY_EVIDENCE_FILE`、`SECURITY_CONTROL_FILE`、`SECURITY_SBOM_OUTPUT` 隔离到相应的同级 worker 子目录。不要在 master/fork 前通过 `opentelemetry-instrument gunicorn` 初始化 SDK。

include 为空时不会启用 Python collection；exclude 对 include 命中的子树优先。stdlib、`securitycontext`、`opentelemetry`、`wrapt` 无论 include 如何设置都被排除。`OTEL_PYTHON_DISABLED_INSTRUMENTATIONS` 可填 `securitycontext` 或 `*` 禁用 OTel 入口。

## 开关、模块和身份

| 配置 | 默认值 | 作用 |
| --- | --- | --- |
| `security.enabled` | `true` | 安全 collection 总开关；pause 之外的有效状态还要求 include 和受支持运行时 |
| `security.python.include` | 空 | 要转换的模块前缀，逗号分隔；这是启用 collection 的必要条件 |
| `security.python.exclude` | 空 | 排除模块前缀 |
| `security.python.max-fields` | `256` | 框架 mapping/list/tuple/Pydantic 递归的单层字段上限 |
| `security.max.framework.carriers` | `256` | 每请求 framework carrier 弱引用登记上限；不可弱引用的可变容器只做有界快照，不保留容器 |
| `security.application.id` | 由 `service.namespace|service.name` 摘要生成 | finding、SBOM、run 的应用身份；显式值优先 |
| `security.code.repository` | 空 | verification identity 的真实仓库标识；不会自动编造 |
| `security.code.commit` | 空 | verification identity 的真实 commit；不会自动编造 |
| `security.code.build-id` | 空 | verification identity 的真实 build 标识；不会自动编造 |
| `otel.resource.attributes` | 空 | 从 OTel resource attributes 补充身份字段 |
| `otel.service.name` | 空 | 覆盖 OTel resource 的 `service.name` |
| `security.output` | `./security-output/<instance_id>`（非 Gunicorn） | health/findings/runs/control 的绝对输出目录；Gunicorn post-fork 会改为 `security-output/worker-{pid}-{random8}` |
| `otel.python.disabled.instrumentations` | 空 | 代码读取的 OTel 禁用列表；环境变量名为 `OTEL_PYTHON_DISABLED_INSTRUMENTATIONS` |

身份没有显式 application/service name 时会使用 fallback，并在 identity 中标记 `identity_status=fallback`。验证 run 要求 repository、commit、build-id 等真实 identity；文档和 CLI 都不替调用者填入假值。`instrumentation_profile` 是对版本、运行时、依赖版本、预算、适配器、include/exclude 和规则开关的摘要，不是独立的 CLI 子命令。

## 规则开关

以下规则默认都是 `true`：

| 规则 | 环境变量 | 主要边界 |
| --- | --- | --- |
| SQL | `SECURITY_RULES_SQL_INJECTION_ENABLED` | DB-API、SQLAlchemy、Django SQL execution/template |
| 命令执行 | `SECURITY_RULES_COMMAND_EXECUTION_ENABLED` | `subprocess.run`、`Popen`、`os.system` |
| 命令注入 | `SECURITY_RULES_COMMAND_INJECTION_ENABLED` | shell script/显式 shell 形式 |
| SSRF | `SECURITY_RULES_SSRF_ENABLED` | HTTP 实际发送/打开的 destination authority |
| HTTP request input | `SECURITY_RULES_HTTP_REQUEST_INPUT_ENABLED` | outbound URL path/query carrier |
| 路径遍历 | `SECURITY_RULES_PATH_TRAVERSAL_ENABLED` | builtins/os/pathlib 文件边界 |

关闭一条规则只抑制该规则的 evidence，不改变应用调用、其他规则、健康计数或 SBOM。SQL bind 参数不被隐式当作模板；普通 argv 不产生 `command_injection`；精确 URL query/path 不升级为 SSRF host；Request 构造器不是实际 send，也不传播响应体 taint。

## 跟踪、账本和输出预算

下表是代码中的默认值；所有数字均可通过同名环境变量调整，但改大后仍受进程内存、OS 和其它上限约束。

| 配置 | 默认值 | 作用 |
| --- | ---: | --- |
| `security.max.tracked.bytes` | `1048576` | 单请求跟踪值及 carrier 引用的保留字节预算（1 MiB）；图和 mark 另受计数预算限制 |
| `security.max.process.tracked.bytes` | `67108864` | 进程共享 tracking 字节预算（64 MiB） |
| `security.max.objects` | `4096` | 请求 side-table 对象数 |
| `security.max.nodes` | `8192` | propagation/sink site 节点上限 |
| `security.max.marks-per-object` | `64` | 单对象 mark 上限 |
| `security.max.findings` | `32` | 单请求 pending finding 上限 |
| `security.max.active.requests` | `256` | 并发请求上限；超过后新请求为 `budget_skipped` |
| `security.requests-per-second` | `1000` | 进程每秒请求预算；超过后新请求为 `budget_skipped` |
| `security.findings.max` | `4096` | 进程 finding ledger 上限 |
| `security.runs.max` | `256` | 进程 run ledger 上限 |
| `security.findings.sample.seconds` | `300` | 同一 finding 代表证据最小采样间隔 |
| `security.findings.max.bytes` | `33554432` | 所有 finding representative 的总字节预算 |
| `security.findings.flush.seconds` | `30` | finding summary 的周期 |
| `security.evidence.max.bytes` | `65536` | 单条 OTel/JSONL 记录上限；超限先删传播细节再输出摘要 |
| `security.export.queue.size` | `1024` | 安全队列条数 |
| `security.export.sbom.queue.size` | `256` | SBOM 队列条数 |
| `security.export.security.events-per-second` | `100` | 安全 worker 每秒事件预算 |
| `security.export.security.bytes-per-second` | `524288` | 安全 worker 每秒字节预算 |
| `security.export.sbom.events-per-second` | `200` | SBOM worker 每秒事件预算 |
| `security.export.sbom.bytes-per-second` | `262144` | SBOM worker 每秒字节预算 |
| `security.evidence.file.max.bytes` | `10485760` | JSONL 当前文件轮转阈值（10 MiB） |
| `security.evidence.file.backups` | `3`，最多 20 | JSONL 轮转备份数 |

达到上限会标记 `truncated` 并增加 `coverage_gaps`，不是“无风险”。安全和 SBOM 队列彼此独立；队列满、worker 预算超限、文件写入失败、OTel API 失败都会计入 delivery/health。OTel `emit` 不代表 Collector/backend ACK；本地文件只 flush，不 fsync。

## SBOM

| 配置 | 默认值 | 作用 |
| --- | --- | --- |
| `security.sbom.enabled` | `true` | 独立开启 SBOM worker 和 CycloneDX snapshot |
| `security.sbom.output` | `<security.output>/application.cdx.json` | 当前 CycloneDX 文件；配置 `.json` 视为文件，否则追加 `application.cdx.json` |
| `security.sbom.build.file` | 空 | 可选外部构建 CycloneDX 输入；仅其可解析 dependency edges 会被合并 |
| `security.sbom.refresh.seconds` | `5` | runtime inventory refresh 间隔 |
| `security.sbom.cache.seconds` | `300` | distribution/archive/build metadata cache |
| `security.sbom.max.components` | `10000` | CycloneDX 当前文档 component 总数上限，包含 `metadata.component` application；runtime/build records 使用剩余预算，history 也受其约束 |
| `security.sbom.max.entries` | `100000` | metadata、package map 和 archive entry discovery 的条目预算；不限制 CycloneDX component 输出数量 |
| `security.sbom.max.archive.bytes` | `67108864` | 单个真实本地 archive 的 hash 读取上限 |
| `security.sbom.max.scan.bytes` | `536870912` | 一次 refresh 的 archive 累计读取上限 |
| `security.sbom.max.build.bytes` | `1048576` | 外部构建 SBOM 输入上限 |
| `security.sbom.max.modules` | `100000` | loaded module mapping 上限 |

SBOM 只输出真实 metadata、真实可读 archive hash 和显式可解析的构建依赖；不从 wheel 文件名臆造 hash，不从 distribution metadata 或 import 名称猜 runtime dependencies。输出固定为 CycloneDX 1.7，使用 revision、`sbom_id` 和 component `bom-ref` 维护快照与事件的映射。

`max.components` 与 `max.entries` 是两个独立预算：前者限制最终 CycloneDX 文档的 component 数（application 占一个 metadata slot），后者在读取 metadata/package map/archive 时提前停止发现工作并留下相应完整性原因。`max.entries=1` 不应被解释为只允许一个 CycloneDX component。

数据流证据、ledger 和 JSONL 不以 span 为前提；框架适配器不创建 server span。只有应用已安装并启用 OTel provider/server instrumentation 时，事件才有可用的 trace/server-span ID；没有 span 时仍可记录事件，span summary 只是可选索引。runtime 先使用 OTel `Context`，必要时以进程内 `ContextVar` 保留请求状态；WSGI iterable 在 `next`/`close` 临时 attach，并在耗尽、close 或 error 时只完成一次。

## 控制文件与 CLI

`security.control.file` 未配置时默认为 `<security.output>/control.json`。控制 JSON 由 CLI 加锁、写入随机 `revision`，ledger 读取并在 `health.json.control_revision` 回显；拒绝时写入 `control_error`/`control_error_revision`。Gunicorn 下每个 worker 有独立 control 文件；CLI 必须以具体 `worker-{pid}-{random8}` 目录为 `--dir`。

```bash
securityctl --dir "$OUT" status
securityctl --dir "$OUT" pause
securityctl --dir "$OUT" resume
securityctl --dir "$OUT" query findings --rule sql_injection --offset 0 --limit 100
securityctl --dir "$OUT" query runs --case my-case
securityctl --dir "$OUT" query sbom --offset 0 --limit 100
securityctl --dir "$OUT" run-start --id candidate --case sql-dynamic --rule sql_injection \
  --suite python-sample --fixture parameterized-negative --expected-requests 1 --ttl 300
securityctl --dir "$OUT" run-stop --output "$OUT/candidate.json"
securityctl verify --baseline "$OUT/baseline.json" --candidate "$OUT/candidate.json" \
  --output "$OUT/verification.json"
```

`status` 将超过 15 秒的 health 标为 stale。pause/resume 和 run-start/run-stop 要求新鲜 health；run 覆盖该进程窗口内的全部 HTTP 请求，调用者必须隔离流量。`verify` 的 `observed` 只表示在条件下观察到风险数据流，`not_observed` 只表示本次条件未观察到，`inconclusive` 表示缺少 identity、流量、source/sink、完整性或投递证据，不能当作修复结论。

## 打包与包内数据

`python/setup.py` 的 `build_py`/`sdist` 类负责：

- 把仓库唯一脚本 `../scripts/securityctl.py` 构建复制为 `securitycontext/_securityctl.py`；
- 把仓库 `deploy/otel-collector-config.yaml` 复制为 `securitycontext/data/otel-collector-config.yaml`；
- 把 `python/samples/`、`python/docs/`、`README.md` 和 `constraints*.txt` 放入 `securitycontext/data/`；
- editable 模式下 `securitycontext.cli` 找不到 `_securityctl.py` 时回退到仓库 canonical script。

安装 wheel 后用 `importlib.resources.files("securitycontext").joinpath("data", "samples")` 取得样例目录，并将该目录加入 `PYTHONPATH` 后再导入 `security_sample`；常规 pip wheel 会提供文件系统路径，zip 资源应先用 `importlib.resources.as_file()` 解包到临时目录。`build/validation` 原始报告、Collector 日志和 `SHA256SUMS` 属于仓库验证证据，不随 wheel 发出。

仓库复现 server span 时应安装 `.[test,otlp,fastapi,flask,django]`；`test` extra 本身不安装三个官方 OTel framework instrumentor。不要在包内维护第二份 CLI 实现或手工填写 SBOM/verification 的虚构版本信息。构建时 README 是 project metadata 的必需输入。
