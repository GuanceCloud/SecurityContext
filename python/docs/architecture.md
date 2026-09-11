# SecurityContext Python 0.2.0 架构与数据流

本文按当前 `python/src/securitycontext` 实现说明边界。它描述“运行时观察到的调用和数据流”，不是漏洞召回率、漏洞可利用性或后端持久化保证。

## 总体路径

```text
OTel pre-instrument/bootstrap
        │
        ├─ config：enabled + include/exclude + CPython/GIL gate
        ├─ Finder：只接管可读 .py 的 included module
        └─ AST transform：调用、字符串运算、切片、f-string → ast_hooks
                         │
OTel instrumentor ───────┼─ framework adapters：ASGI/WSGI source + lifecycle
                         ├─ sink adapters：SQL/process/HTTP/filesystem
                         └─ threading context propagation
                                  │
                         SecurityState（Context/ContextVar）
                                  │
                 RuntimeLedger ───┼── Exporter：OTel Logs/body + optional JSONL
                    health/findings/runs
                                  └── SbomInventory：CycloneDX 1.7 snapshots
```

关键入口在 `securitycontext.__init__`：`opentelemetry_pre_instrument` entry point 指向 `bootstrap`，`opentelemetry_instrumentor` entry point 指向 `SecurityInstrumentor`。普通 Python/ASGI/WSGI 进程由 `opentelemetry-instrument` 触发这些入口；Gunicorn 使用 `gunicorn -c python:securitycontext.gunicorn ...`，由 `post_fork` 在 worker 中先隔离输出目录、调用 OTel `initialize()`，再导入应用。不要用 `opentelemetry-instrument gunicorn`，否则 SDK 会在 master/fork 前初始化；`preload_app=True` 也被明确拒绝。`bootstrap` 在配置满足时安装 import finder；instrumentor 再安装框架、sink 和 OTel threading 适配器并启动 runtime。实现不创建自己的 OTel provider，使用当前进程已有的 trace/log provider。dataflow evidence、ledger 和 JSONL 不以 span 为前提；框架适配器也不创建 server span。只有应用已经启用 provider/server instrumentation 且当前存在有效 server span 时，事件才会携带可用的 `trace_id`、`server_span_id` 和 LogRecord correlation；没有 span 时事件仍可产生，ID 为空不能被解释为有效关联证据。

## 模块选择与 AST 边界

`SECURITY_PYTHON_INCLUDE` 是必需的逗号分隔模块前缀；`SECURITY_PYTHON_EXCLUDE` 对匹配前缀拥有优先权。即使被 include，以下根模块仍被排除：Python stdlib、`securitycontext`、`opentelemetry`、`wrapt`。前缀匹配是完整模块名或 `prefix.` 子树，不是文件名模糊匹配。

`loader.Finder` 只为尚未加载且 loader 提供 `get_source()`、来源以 `.py` 结尾的模块替换 loader。`Loader` 对源码执行 `ast.parse`/`compile`，失败时恢复原始 loader 并记录 startup gap；已在 instrumentor 安装前导入的 included 模块不会被回溯转换。没有可读源码的 `.pyc`/native 模块、动态生成模块和直接执行但未进入此 import path 的入口代码不获得通用 AST 数据流。

`transform.Transformer` 在函数/方法/lambda 内转换：

- `+`、`%`、`/` 和字符串 `+=` 进入 `ast_hooks.binary`；
- 字符串/bytes 下标和连续切片进入 `ast_hooks.subscript`；
- f-string conversion/spec/join 进入 `formatted`/`joined`；
- 一般调用进入同步或异步 `call`/`acall`，`eval`/`exec` 等敏感动态代码只保留原调用并记录 `dynamic_code_execution` gap。

helper 在运行时返回应用原始结果；异常仍由应用抛出，参数求值顺序和一次性调用由重写后的 AST 保持。没有明确偏移映射的调用结果只产生 conservative mark 或 `unmodeled_call_result`/`unmodeled_subscript_conversion` 等 coverage gap。

`locals`、`eval`、`sys._getframe` 等依赖调用帧的函数，以及可静态识别的导入别名和简单赋值别名，保留业务帧上的原生调用。动态传入的任意 callable 不属于完整的调用帧兼容保证。

## 请求上下文与来源

框架适配器为每个 HTTP 请求创建 `SecurityState`。`current_state()` 先读取 OTel `Context`；当 server instrumentation 替换或丢失 OTel context 时，以进程内 `ContextVar` 作为 request-lifetime fallback。ASGI 在 `receive` 读取 body、在 terminal `send` 结束；WSGI 在迭代器的每次 `next`/`close` 临时 attach，避免响应流跨请求泄漏，并在耗尽、close 或 error 时只完成一次 ledger。当前 server span 若有效则被关联；适配器不主动创建 span。

已实现的来源类型包括：

| 来源 | 适配边界 |
| --- | --- |
| `http.request.parameter` | Starlette/FastAPI query params、Flask `request.args`、Django `GET`；FastAPI 绑定字段使用 alias |
| `http.request.path` | Starlette path params、Flask view args、Django URL resolver 参数 |
| `http.request.header` | Starlette/Flask/Django headers 及其字段访问 |
| `http.request.body` | ASGI body、Starlette `body/json/form/stream`、Flask `get_data/get_json`、Django `body/read`、Pydantic v2 字段递归 |

mapping/list/tuple/Pydantic 字段递归均有字段数、深度和 carrier 预算。来源值不会因内容相等而全局匹配；同一对象收到不同来源标签时进入 identity ambiguity，停止使用其 mark 并标记 `source_identity_ambiguous`。已预算的对象引用保留到请求关闭，避免歧义对象的 ID 被复用。

## 图、mark 和范围单位

每个请求状态维护 source、propagation node、object side table 和 sink occurrence。mark 至少包含 `source_id`、`node_id`、`start`、`end`、`exact` 和 `unit`；node 保存 parent、operation、source 和 code location。sink 从 mark 回溯有限长度的 parent 链形成 evidence graph。

Python 字符串使用 `unicode_code_point`，`bytes`/`bytearray` 使用 `byte`。对拼接、连续切片等操作可以保留精确范围；格式化、大小写、路径/URL/SQL 编译等无法证明字符映射时使用 `exact=false` 的 conservative 范围。Java 实现中的 `JavaUTF16` 是另一语言的兼容单位，不适用于 Python 事件。

对象和范围按身份管理，且只保留有界 carrier/字符串。共享短 scalar、不能安全登记的载体、同一对象多来源、超过节点/对象/mark/字节上限的路径会产生 gap；这些 gap 会进入 `security.collection.incomplete` 或 finding 的 `coverage_gaps`。框架内置可变容器若已完成有界值快照，不会仅因容器不能弱引用而产生缺口。

## Sink 适配器与非检测边界

`sinks.install()` 按可导入库安装 fail-open wrapper；wrapper 不改变应用返回值，且使用执行边界抑制已知的父子重复调用。

| rule | 观察边界 | 明确语义 |
| --- | --- | --- |
| `sql_injection` | DB-API cursor/connection、SQLite、psycopg、PyMySQL、SQLAlchemy、Django cursor/RawSQL | 只看 SQL template/statement/script 的 mark；bind 参数不会被隐式遍历，常量参数化 SQL 没有 SQL-template taint |
| `command_execution` | `subprocess.run`、`subprocess.Popen`、`os.system` | 区分 executable 与普通 argument；普通参数不表示可执行文件受控，也不等价于 shell injection |
| `command_injection` | shell 文本及识别出的 `sh/bash/cmd/powershell -c` 形式 | 普通 argv 本身不生成 shell-script 观察 |
| `ssrf` | requests/httpx/aiohttp/urllib 的实际 send/open/request 边界 | 精确 mark 只与 URL authority 相交时进入 destination address；query/path-only mark 不升级为 host taint |
| `http_request_input` | 同一实际 outbound 请求边界 | 记录 URL carrier 的 path/query 影响，与 SSRF address 分开 |
| `path_traversal` | builtins/os/pathlib 的 open/read/write/delete/rename 等边界 | 只报告到达文件路径 carrier 的 mark |

HTTP Request/PreparedRequest/ClientRequest 构造器只传播 URL carrier，不能单独形成 actual-send sink；构造 URL 也不会把 URL taint 传到响应体。`Request` 构造、实际发送和响应读取是不同边界。当前实现不提供通用 XSS、反序列化、native、反射或远程跨服务 taint 模型。

## 账本、投递和 Span 摘要

`RuntimeLedger` 在进程内聚合 finding、代表样本、verification run、pause/例外控制和计数器。`config.profile()` 将版本、运行时、已发现依赖、预算、适配器、include/exclude 和规则开关摘要为 `instrumentation_profile`，并写入 health/run。`Exporter` 有两条独立 FIFO 有界队列与后台线程：安全事件队列默认 1024 条，SBOM 队列默认 256 条。队列满和 worker 字节/事件预算会增加对应 dropped 计数；记录序列化、OTel API 或文件写入失败会增加对应 failed 计数。所有失败不会阻塞或改写业务返回值，并在可行时发出诊断事件；记录太小无法放下最小 envelope 时使用 `record_too_small_for_envelope`，不直接计入 dropped。

每个 OTel LogRecord 的 body 是 UTF-8 JSON 字符串，`event.name` 是属性；是否真正由 SDK、Collector 或 backend 导出由现有 OTel provider 决定。`security.evidence.file` 开启后，只有安全 evidence 和诊断事件进入可轮转 JSONL，不写 SBOM snapshot/component 事件。JSONL 只 flush，不 fsync；`backend_acknowledgement` 固定表达未知，`delivery_guarantee` 是有界 best-effort、无 agent replay。

观察到 finding 时，以及请求结束时，runtime 在仍 recording 的已有 server span 上更新 `security.detected`、finding count、types、finding/evidence IDs 及 truncated 标志；列表受请求 finding 上限约束。框架已提前结束 span 时不会再修改它。ledger 还按周期输出 bounded `security.finding.summary`。因此 Span/summary 是可选观测索引，不是完整证据副本，也不是 ACK；dataflow/ledger/JSONL 的生成不依赖该 summary。

账本的采集开关读取已发布的不可变策略，不获取请求记账锁。快照在锁内只复制可变外层记录及 run 计数表，代表样本作为账本拥有的不可变值共享；JSON 编码和文件写入位于锁外。finding/run 未改变时跳过其快照，成功写入后才确认版本。独立的快照锁串行化后台 tick 与强制 flush，避免旧文件覆盖新版本；该锁不参与请求记账。 同步 flush 与异步 aflush 共用单个在途守护线程和总截止时间；Uvicorn 异步等待结果，快照、SDK 或文件关闭阻塞不会无限拖住调用方。超时诊断不等待账本锁，存储恢复后的后续快照会写入不完整状态；永久阻塞时旧文件无法刷新。

## SBOM 与 component mapping

`SbomInventory` 在独立 daemon worker 中观察 `sys.modules`、`importlib.metadata`、`top_level.txt`/`direct_url.json` 和真实本地 archive。输出 CycloneDX `1.7`，同时维护 `application.cdx.json` 与 `sbom-history.json`。运行时 component 只有在 distribution metadata、模块 origin 和实际路径能匹配时才标记 resolved；namespace、未知 origin、重复 distribution、替换中的 artifact 等保持 unresolved/incomplete 原因。

可读取的本地 `.whl`/`.zip`/`.egg`/`.pyz`/`.jar` 才会在预算内计算真实 SHA-256；不会从文件名或猜测值填充 wheel hash。运行时扫描不会从 `Requires-Dist` 或模块名称猜传递依赖；只有 `security.sbom.build.file` 指向的可解析外部 CycloneDX 声明边才进入 dependencies。

每次稳定组件记录或 module map 改变生成 revision 和 content digest；安全事件的 `sbom_id`/revision/component `bom-ref` 来自同一个 published snapshot。`resolve(module_name, filename)` 只查询最近一次完整发布的 immutable mapping，并拒绝来源路径不匹配。`loaded=true` 的意义是模块被观察到加载，而非方法执行。`max.components` 是包含 metadata application 的 CycloneDX 输出预算；`max.entries` 只限制 metadata/package-map/archive entry discovery，不能替代 component budget。

## worker 输出隔离、运行时控制与有界失败

Gunicorn `post_fork` 为每个 worker 生成 `worker-{pid}-{random8}`。默认 `SECURITY_OUTPUT` 根为 `security-output`，runtime 实际写入该 worker 子目录；显式 `SECURITY_EVIDENCE_FILE`、`SECURITY_CONTROL_FILE` 和 `SECURITY_SBOM_OUTPUT` 也会被重写到相应的同级 worker 子目录。这样每个 worker 有自己的 health、ledger、control 和 SBOM 快照，CLI 必须针对具体 worker 目录操作，不能把多 worker 文件合并成一个 process-local ledger。

`security.control.file` 默认位于输出目录，ledger 每秒读取一次。`paused=true` 会让新请求进入 `paused` 状态；已经加载的 instrumentation 不会被卸载，恢复需要新的 revision。请求或进程达到默认 1 MiB/64 MiB tracking budget、active request/RPS、对象、节点、finding 或输出 budget 时，状态可能为 `budget_skipped`/`incomplete`，并保留 coverage gap。

CLI run 是 process-local、面向该进程全部 HTTP 请求的控制窗口，调用者必须隔离流量。`verify` 只有在 baseline/candidate identity、suite/fixture/expected request、source/sink、关闭状态和 delivery/incomplete 条件均可比较时才给出 `observed` 或 `not_observed`；缺少必要证据得到 `inconclusive`，不能解读成修复或完整覆盖。

## 当前明确边界

不支持或不承诺：`.pyc`-only、动态/未经过 Finder 的 `__main__`、`exec`/`eval` 生成代码、native/C 扩展内部数据流、free-threaded/no-GIL、gevent/eventlet 的专用调度、Gunicorn `preload_app=True`、远程/跨进程 taint、无法证明 identity 的共享值和未建模转换。实际运行/打包/性能结果以独立产品报告为准，本文不把未执行的性能或后端 ACK 写成已验证能力。

代码定位：启动与配置在 `src/securitycontext/__init__.py`、`config.py`、`loader.py`；图和范围在 `state.py`、`tracking.py`、`propagation.py`；框架和 sink 在 `frameworks/`、`sinks/`；投递/账本/SBOM 在 `exporter.py`、`ledger.py`、`sbom.py`。
