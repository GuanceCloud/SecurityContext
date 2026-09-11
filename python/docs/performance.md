# SecurityContext Python 历史 v0.1.0 性能记录

> 本页保留旧 benchmark 的运行边界和数值；归档 wheel、distribution 和 disabled-instrumentation 标识不属于当前公开包名。当前发行包和 import 使用 `securitycontext` 0.2.0，不能由本页推导当前版本已发布或已验证。

## 结论

本次最终 5 轮 benchmark **通过**，但结论仅为 `measured_not_sla`，不是容量、SLA 或生产部署承诺。

- runner 返回码：`0`
- 报告：[`benchmark-report.json`](../../build/validation/python-v01/benchmark-final-20260907/benchmark-report.json)
- 实际批次时长：`63.34443158400245 s`（15 个 mode-run；包含 warmup、实测请求、security drain barrier 和优雅退出；不含临时 venv 创建与 wheel 安装）
- 批次：5 轮、每轮每组 500 个 warmup + 5000 个 measured、并发 16；三组按固定交错顺序串行执行
- 运行位置：OrbStack 现有容器 `securitycontext-py-312`，repo 映射 `/workspace`

这是共享 OrbStack 容器中的 Linux/aarch64 CPython 3.12.14 实测。客户端请求线程与服务端进程在同一共享容器内竞争 CPU，因此不能作为容量基准；没有测 x86_64 或其它平台，也没有真实 Collector。

## 测试身份与 hash

本报告只代表实际测量时安装的 final2 wheel。新增本报告后最终 release wheel 会重建；不要把重建包的 hash 回填为本次实测 hash。主 agent 后续应核对生产代码与本次实测 wheel 对应的源码一致。

| 项目 | 实际值 |
| --- | --- |
| 测试 wheel | 历史 v0.1.0 benchmark wheel（原始文件路径只保留在归档验证产物中） |
| wheel SHA-256（本次实测） | `4c6d747b6889decd66e6809ed9fc9054099d6d4930ddd2e438b4ce6bb09b470e` |
| fixture | `/workspace/python/samples/security_sample/benchmark_app.py` |
| fixture SHA-256 | `8316f108a402097d421e8cada162cbe476dd59dd7ce7c0724afead7769686526` |
| constraints | `/workspace/python/constraints-python-v0.1.0-arm64.txt` |
| constraints SHA-256 | `d05911c80d7fbbdbd2572a0672ac9a5cb58128ae877345d37b84ffaa8170f1fe` |
| runner SHA-256（含本次 batch duration 记录修补） | `18798d78654165325dfe6f500eb411272acdbd07dae276df83820c6c880acfe8` |

## 精确运行时与依赖

测试应用由 benchmark 临时 venv 中的解释器启动，报告由 runner 汇总写出。wheel 以 non-editable、`--no-deps` 方式安装，并验证导入路径来自该 venv。实际观测到的 benchmark 依赖为：

```text
CPython 3.12.14
历史 Python distribution（v0.1.0；仅用于本页 benchmark）
opentelemetry-api==1.44.0
opentelemetry-sdk==1.44.0
opentelemetry-instrumentation==0.65b0
fastapi==0.141.1
starlette==1.6.0
uvicorn==0.52.4
pydantic==2.13.5
psutil==7.2.2
requests==2.34.2
```

constraints 文件的 75 个精确 pin 如下；其完整原文件和 hash 见上表：

```text
aiohappyeyeballs==2.7.1
aiohttp==3.14.3
aiosignal==1.4.0
annotated-doc==0.0.5
annotated-types==0.8.0
anyio==4.15.1
asgiref==3.12.1
attrs==26.1.0
blinker==1.9.0
build==1.6.0
certifi==2026.7.22
charset-normalizer==3.5.1
click==8.5.0
Django==5.2.17
fastapi==0.141.1
Flask==3.1.3
frozenlist==1.8.0
googleapis-common-protos==1.75.3
greenlet==3.5.5
gunicorn==26.2.0
h11==0.16.0
httpcore==1.0.9
httpx==0.28.1
idna==3.19
iniconfig==2.3.0
itsdangerous==2.2.0
Jinja2==3.1.6
jsonschema==4.26.0
jsonschema-specifications==2025.9.1
MarkupSafe==3.0.3
multidict==6.7.1
opentelemetry-api==1.44.0
opentelemetry-distro==0.65b0
opentelemetry-exporter-otlp-proto-common==1.44.0
opentelemetry-exporter-otlp-proto-http==1.44.0
opentelemetry-instrumentation==0.65b0
opentelemetry-instrumentation-asgi==0.65b0
opentelemetry-instrumentation-django==0.65b0
opentelemetry-instrumentation-fastapi==0.65b0
opentelemetry-instrumentation-flask==0.65b0
opentelemetry-instrumentation-threading==0.65b0
opentelemetry-instrumentation-wsgi==0.65b0
opentelemetry-proto==1.44.0
opentelemetry-sdk==1.44.0
opentelemetry-semantic-conventions==0.65b0
opentelemetry-util-http==0.65b0
packaging==26.3
pluggy==1.6.0
propcache==0.5.2
protobuf==7.36.1
psutil==7.2.2
psycopg==3.3.5
psycopg-binary==3.3.5
pydantic==2.13.5
pydantic-core==2.46.5
Pygments==2.21.0
pymysql==1.2.0
pyproject-hooks==1.2.0
pytest==9.1.1
python-multipart==0.0.32
referencing==0.37.0
requests==2.34.2
rpds-py==2026.6.3
SQLAlchemy==2.0.52
setuptools==84.0.0
sqlparse==0.6.0
starlette==1.6.0
typing-extensions==4.16.0
typing-inspection==0.4.4
urllib3==2.7.0
uvicorn==0.52.4
Werkzeug==3.1.8
wheel==0.48.0
wrapt==2.4.0
yarl==1.24.5
```

## 工作负载与配置

fixture 是 FastAPI `GET /bench`。固定 benign query 为 `benchmark-query`，执行字符串传播后进入参数化的内存 SQLite SQL 查询；响应固定为 `{"ok": true, "matched": 0}`。没有漏洞断言，不把 benign 请求解释成安全覆盖率或漏洞检出率。

每个 mode 都使用同一临时 venv、单 worker 和同一请求客户端：

| mode | 配置 |
| --- | --- |
| `baseline` | security disabled；不启用 OTel auto-instrumentation |
| `otel` | OTel auto-instrumentation；历史 security instrumentation disabled |
| `security` | `SECURITY_ENABLED=true`、`SECURITY_PYTHON_INCLUDE=security_sample`；local output/evidence JSONL path；`OTEL_PYTHON_DISABLED_INSTRUMENTATIONS` 未设置 |

全部 mode 的 OTel 配置为 `OTEL_TRACES_EXPORTER=none`、`OTEL_METRICS_EXPORTER=none`、`OTEL_LOGS_EXPORTER=none`、`OTEL_TRACES_SAMPLER=always_on`；`SECURITY_SBOM_ENABLED=false`。security mode 的 `SECURITY_OUTPUT` 和 `SECURITY_EVIDENCE_FILE` 均指向该 round 的本地输出目录，不依赖真实 Collector。

## 5 轮中位数

CPU 同时列出 runner 的服务端进程 CPU 秒数和按单核折算的百分比；RSS 为服务端进程采样到的峰值。

| mode（5 轮） | RPS median | p95 median | CPU seconds median | CPU % of one core median | startup median | RSS peak max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline | 3678.348 | 8.010 ms | 1.500 s | 113.483% | 0.166 s | 47.922 MiB |
| otel | 2342.511 | 12.172 ms | 2.710 s | 126.595% | 0.320 s | 71.027 MiB |
| security | 831.919 | 34.997 ms | 6.530 s | 108.981% | 0.482 s | 115.273 MiB |

以 OTel-only 为参照，security 的中位吞吐下降 `64.486%`（约 `64.5%`），p95 延迟为 `2.875x`（约 `2.88x`）；本 workload 上开销明显，但不外推为通用安全 instrumentation 保证。CPU% 是服务端进程全部线程的 user+system CPU 秒数按单核尺度折算，所以可超过 100%，不是宿主机总 CPU 使用率。baseline 的 measured batch 中位数只有 `1.3593 s`（约 `1.36 s`），样本短，RPS/p95/CPU/RSS 只能作为本次固定 workload 的相对比较，不能替代长时间或容量测试。

## Security health 逐轮验收

每轮的 health 文件均为 `status=observed`、`effective=true`、`collection_status=enabled`，且 drain barrier 通过。每轮 `requests_completed=5501` 是 1 次 readiness probe + 500 次 warmup + 5000 次 measured；因此大于 barrier 的 `expected_completed=5500` 是预期，不是丢失或重复请求判定。

| round | status | effective | active | requests completed | source requests | sink requests | incomplete | budget skipped | delivery loss/failure | drain |
| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | observed | true | 0 | 5501 | 5501 | 5501 | 0 | 0 | 0 / 0 | pass |
| 2 | observed | true | 0 | 5501 | 5501 | 5501 | 0 | 0 | 0 / 0 | pass |
| 3 | observed | true | 0 | 5501 | 5501 | 5501 | 0 | 0 | 0 / 0 | pass |
| 4 | observed | true | 0 | 5501 | 5501 | 5501 | 0 | 0 | 0 / 0 | pass |
| 5 | observed | true | 0 | 5501 | 5501 | 5501 | 0 | 0 | 0 / 0 | pass |

五个 security round 的 `health_drain_barrier` 均为 `passed=true`、`active_requests=0`、`completed_delta=5501`；所有 15 个 mode-run 都是 clean shutdown。health 中 `delivery.dropped=0`、`security_dropped=0`、`sbom_dropped=0`、`delivery_loss=0`，`snapshot_failures=0`。

安全 fixture 的参数化 benign SQL 没有产生漏洞 finding：每个 round 的 `findings.json` 的 `findings` 为空，`runs.json` 为空；evidence JSONL 路径已配置，但本次没有 evidence event 文件，这是因为 workload 没有触发 finding，不是把 collector 或收集关闭来制造通过结果。

## 已知输出与边界

- 每个 security `server.log` 各有一条 `Attempting to instrument while already instrumented`。它来自 OTel auto-instrumentation 与 security instrumentor 的 threading instrumentor 重复调用 warning；本轮请求响应、clean shutdown 和逐轮 health 均通过，runner 未将其隐藏。生产代码在本任务中未修改；若 release gate 禁止任何 stderr warning，应由主 agent 单独决定是否开后续修复，不应把本次有效数据改写成无 warning。
- 这是同一共享容器中的串行相对比较，不是独占 CPU、容量、SLA、长时间稳定性、x86_64 或其它平台验证。客户端与服务端竞争共享容器 CPU，CPU/RSS 只反映 runner 采集到的服务端进程指标。
- 本报告未验证真实 Collector backend acknowledgement；OTel exporters 明确为 `none`。

## 原始产物

主 agent 应保留以下产物用于最终 release 核验：

- [`benchmark-report.json`](../../build/validation/python-v01/benchmark-final-20260907/benchmark-report.json)：完整逐轮数据、依赖、hash、健康信息和中位数。
- [`runner-stdout.json`](../../build/validation/python-v01/benchmark-final-20260907/runner-stdout.json)：runner 原始 JSON 输出，和 report 内容一致。
- `baseline/round-{1..5}/server.log`、`otel/round-{1..5}/server.log`、`security/round-{1..5}/server.log`。
- `security/round-{1..5}/security-output/health.json`、`findings.json`、`runs.json`。
