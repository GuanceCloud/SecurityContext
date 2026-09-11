# SecurityContext Python 0.2.5

`securitycontext` 是 SecurityContext 的 Python 0.2.5 包。它通过 OpenTelemetry 的启动入口安装纯 Python import hook，只转换显式包含的应用模块，在请求上下文中记录有界的数据流证据，并把事件交给现有的 OTel Logs provider。它不是漏洞扫描器，也不改变应用函数的返回值。

完整的独立发行说明见[中文指南](docs/guide.zh-CN.md)和[English guide](docs/guide.en.md)。包内配置、兼容性、验收与性能材料见 `securitycontext/data/docs/`；发行 bundle 中的 validation/release-validation 记录该 bundle 的实际结果。静态代码检查或示例定义不能代替运行验证，也不构成性能/SLA 承诺。

## 安装与启动

发行包和 import 名都为 `securitycontext`，版本为 `0.2.5`：

```bash
python -m pip install ./securitycontext-0.2.5-py3-none-any.whl
# 或
python -m pip install ./securitycontext-0.2.5.tar.gz
```

在源码 checkout 中开发时可使用 `python -m pip install .`；发行验证应安装上面的本地 wheel 或 sdist。

仓库样例、测试和三个框架的 server-span 适配器需要完整测试组合：

```bash
python -m pip install -e ".[test,otlp,fastapi,flask,django]"
```

只运行单一框架时可以缩小组合；extras 只安装对应的 OTel 适配器，不替应用安装框架本身：

```bash
python -m pip install ".[fastapi,otlp]"
python -m pip install ".[flask,otlp]"
python -m pip install ".[django,otlp]"
```

应用自己的框架包、ASGI/WSGI server 和数据库/HTTP 客户端仍由应用环境管理。启动时通过 OTel 的 pre-instrument/instrumentor entry point 加载：

```bash
SECURITY_ENABLED=true \
SECURITY_PYTHON_INCLUDE=myapp,mycompany.service \
SECURITY_PYTHON_EXCLUDE=myapp.migrations \
SECURITY_OUTPUT="$PWD/security-output" \
SECURITY_EVIDENCE_FILE="$PWD/security-output/evidence.jsonl" \
SECURITY_SBOM_ENABLED=true \
OTEL_SERVICE_NAME=myapp \
OTEL_LOGS_EXPORTER=otlp \
opentelemetry-instrument uvicorn myapp.main:app --host 127.0.0.1 --port 8000
```

`SECURITY_PYTHON_INCLUDE` 为空、运行时不是受支持的 CPython/GIL 组合，或 `SECURITY_ENABLED=false` 时，不安装 Python AST loader。`SECURITY_PYTHON_EXCLUDE` 优先于 include。也可以通过 `OTEL_PYTHON_DISABLED_INSTRUMENTATIONS=securitycontext` 或 `*` 禁用该入口。

### 只使用 wheel 中的样例

wheel 不把 `security_sample` 安装为顶层发行包。构建类会把样例、文档、constraints 和 Collector 配置放到 `securitycontext/data/`；安装后的路径应通过 `importlib.resources` 取得：

```bash
SAMPLES_DIR="$(python - <<'PY'
from importlib.resources import files
print(files("securitycontext").joinpath("data", "samples"))
PY
)"
SECURITY_ENABLED=true \
SECURITY_PYTHON_INCLUDE=security_sample \
SECURITY_SBOM_ENABLED=true \
OTEL_SERVICE_NAME=security-sample \
PYTHONPATH="$SAMPLES_DIR" \
  opentelemetry-instrument python -m uvicorn \
  security_sample.fastapi_app:app --host 127.0.0.1 --port 8000
```

同样使用 `files("securitycontext").joinpath("data", "docs")`、`data/constraints*.txt` 和 `data/otel-collector-config.yaml` 访问包内资源。`PYTHONPATH=data/samples` 只是样例模块可导入的路径，不等于把样例声明为生产依赖。

Gunicorn 必须使用包提供的配置模块，并让 OTel 在 worker 中、应用导入前初始化：

```bash
gunicorn -c python:securitycontext.gunicorn \
  --bind 127.0.0.1:8000 \
  myapp.wsgi:application
```

`post_fork` 会拒绝 `preload_app=True`，为每个 worker 隔离输出目录，然后调用 OTel `initialize()`。不要用 `opentelemetry-instrument gunicorn` 代替该配置，它会在 master/fork 前初始化 SDK，破坏 worker 隔离边界。

## 仓库样例

`python/samples/security_sample/` 提供不导入 `securitycontext` 的 FastAPI、Flask、Django 样例。三个应用共用 SQL、命令、HTTP、文件、字符串转换、流式响应和参数化 SQL 负对照场景；样例只使用内存 SQLite、`/usr/bin/printf`、可配置的本机 HTTP 地址和临时目录，不代表通用业务安全结论。

样例运行器及环境变量在脚本中定义：

```bash
python python/scripts/run_python_matrix.py --python 312 --framework fastapi
```

该脚本面向名为 `securitycontext-py-312` 的 Linux/arm64 容器；未提供对应容器时会报告不可用。它是 QA 运行入口，不是本页的验证结果。

## 输出与 CLI

非 Gunicorn 启动时，每个进程默认使用 `./security-output/<instance_id>/` 作为输出目录。Gunicorn 使用上述配置模块时，输出根改为各 worker 的子目录。运行期账本会周期性写入：

| 文件 | 语义 |
| --- | --- |
| `health.json` | 当前配置、有效状态、计数器、规则、预算缺口、SBOM 和投递诊断；顶层 `source=security_context` |
| `findings.json` | 有界 finding 账本及代表证据；顶层 `source=security_context` |
| `runs.json` | CLI verification run 及 source/sink、丢失和不完整计数；顶层 `source=security_context` |
| `control.json` | pause、run、例外等运行时控制；控制文件保留自身 schema 版本，并带 `source=security_context` |
| `application.cdx.json` | 开启 SBOM 时的 CycloneDX 1.7 当前快照；使用标准允许的 properties 表达 source，不增加非标准顶层字段 |
| `sbom-history.json` | SBOM component revision 的有限历史；顶层 `source=security_context` |
| `evidence.jsonl` | 配置 `SECURITY_EVIDENCE_FILE` 后写入的安全证据/诊断 JSONL；事件使用 schema v2 |

安装后的命令和 editable 源码都使用同一 canonical CLI：

```bash
securityctl --dir "$PWD/security-output" status
securityctl --dir "$PWD/security-output" query findings --rule sql_injection --offset 0 --limit 100
securityctl --dir "$PWD/security-output" query runs --case my-case
securityctl --dir "$PWD/security-output" query sbom --offset 0 --limit 100
securityctl --dir "$PWD/security-output" pause
securityctl --dir "$PWD/security-output" resume
```

editable 环境也可运行：

```bash
python -m securitycontext.cli --dir "$PWD/security-output" status
```

CLI 的报告和控制输出也带 `source=security_context`；其中 control/report 自有状态 schema 可以保持 v1，不应与事件 schema v2 混淆。`status` 读取 `health.json`，过期 health 会标记 `stale`；run 和例外参数以 CLI 的 argparse 定义为准。

## 事件契约

Python 与 Node.js、Java 共用 schema v2 契约；随包的[中文指南](docs/guide.zh-CN.md)和[English guide](docs/guide.en.md)包含事件字段、source、SBOM、trace 与截断规则。OTel envelope 的 scope.name 为 `SecurityContext`，native `eventName`、`event.name` attribute 和 body 的 `event_name` 必须一致；SBOM 上报（`app-dependencies-loaded` 和 `security.sbom.*`）使用 `source=security_context_sbom`，其他安全事件使用 `source=security_context`；OTLP log 的 `attributes.source` 与 JSON body 的 `source` 一致。截断 summary/minimal 保留原事件的 source。`sources[]` 中每个来源条目有六个统一字段，另有六个 identity 字段和 runtime/source/sink/component 结构。Python 文本范围单位为 `unicode_code_point`，bytes/bytearray 为 `byte`。

## 语义边界

- 数据流标记按对象身份保存，不按字符串相等性搜索；冲突来源会产生 `source_identity_ambiguous`，并让该对象停止传播。
- SQL sink 只检查 SQL 模板。绑定到常量参数化模板的参数不会被隐式遍历或当作 SQL 模板污染。
- 普通 argv 参数属于 `command_execution` 的 argument 观察，不表示可执行文件受控；shell 文本或显式 shell 形式才进入 shell-script 语义。
- HTTP 请求构造器只传播 URL carrier，不报告实际发送，也不把 URL 变成响应体 taint。实际 send/open 边界才报告 HTTP sink。
- AST 转换保留应用返回值、调用一次和求值顺序；无法建模的转换会保守地产生 coverage gap，而不是伪造精确范围。
- 安全和 SBOM 使用独立有界队列及后台 worker。OTel API `emit` 不是 SDK、Collector 或后端 ACK；本地 JSONL flush 也不是 `fsync`。
- dataflow evidence、ledger 和 JSONL 不依赖 span 存在；`trace_id`/`server_span_id` 来自请求 server span，`current_span_id` 在 sink 处捕获，事件生成后冻结；没有有效 provider/span 时事件仍可产生，但 trace ID 不能当作有效关联证据。health、SBOM 和 history 是进程级快照，不强行关联请求 trace。

详细配置、架构、兼容性和当前验证边界见：

- [配置](docs/configuration.md)
- [架构与数据流](docs/architecture.md)
- [兼容性与明确边界](docs/compatibility.md)
- [验收总览](docs/verification.md)

## 已加载依赖上报

依赖上报使用 `app-dependencies-loaded`，`dependencies` 数组中的每项只保留 `name`、`version`，缺少完整坐标或版本且有真实制品 SHA-256 时增加 `hash`。只上报实际观察到加载的依赖；本地 `application.cdx.json` 继续保留 CycloneDX，`sbom-history.json` 保留组件历史及原有容量限制。

大快照使用相同 `sbom_id`/`revision` 分片，`part_index` 从 0 开始；消费端收齐 `part_count` 片后整体替换。SBOM 每秒预算不足时在后台等待下一窗口，记录 `sbom.budget_deferred`；队列容量和关闭期限仍有上限，API emit 不代表后端 ACK。此事件替代旧的组件增量和 snapshot 上报，消费端需要调整订阅及解析。
