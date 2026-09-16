# Python v0.1.0 产品契约验证记录

本记录是独立 QA 产品切片的实际运行结果，不代表完整发布验收，也不包含性能结论。验证只使用现有 OrbStack 容器和已安装依赖；未停止或修改其他共享容器，未安装新依赖。

## 环境与范围

| 项目 | 实际值 |
| --- | --- |
| 目标平台 | Linux；本次容器为 aarch64。Linux 是 Python v0.1.0 的官方 QA 平台，宿主机运行不作为缺陷判定。 |
| Python | CPython 3.11.16、3.12.14、3.13.15、3.14.7，均为 standard GIL build |
| OTel | `opentelemetry-api`/`opentelemetry-sdk` 1.44.0，`opentelemetry-instrumentation` 0.65b0；四个容器均实际读取到这些版本 |
| 容器 | `securitycontext-py-311`、`securitycontext-py-312`、`securitycontext-py-313`、`securitycontext-py-314` |
| 未执行 | 性能/benchmark；本切片不重复执行框架与 Gunicorn 矩阵；后端 ACK/故障恢复 |

本切片的产品 runner 是 [`run_product_case.py`](../scripts/run_product_case.py)，直接使用运行时 API，并调用仓库唯一的 [`scripts/securityctl.py`](../../scripts/securityctl.py)。每个版本的独立产物如下：

- [CPython 3.11 summary](../../build/validation/python-v01/product/py311/summary.json)
- [CPython 3.12 summary](../../build/validation/python-v01/product/py312-rerun/summary.json)
- [CPython 3.13 summary](../../build/validation/python-v01/product/py313/summary.json)
- [CPython 3.14 summary](../../build/validation/python-v01/product/py314/summary.json)

## 产品契约结果

四个版本的 runner 均通过以下 9 项检查：

- 复用应用已经安装的 OTel `LoggerProvider`，并保留队列记录的 trace/span context；
- security 与 SBOM 独立有界队列；满队列记录 drop/loss，另一通道不被阻塞或混用；
- JSONL 正常 flush、轮转，以及 OTel API 失败时本地 evidence 仍 fail-open；
- pause/resume 控制确认；ledger 聚合、正常 flush、`compare`、`exception-add/remove` 均完成；
- `securityctl.py verify` 实际产生 `observed`、`not_observed`、`inconclusive` 三种结果，inconclusive 返回码为 3。

每个版本的 `test_product_contract.py` 与 `test_sbom_contract.py` 合计均为 **9 passed**。产品 runner 的每个版本也均写出 JSONL evidence 和 OTel API 记录；这些 OTel API 记录只证明 SDK API 接收/处理，不证明 Collector 或后端 ACK。

## FastAPI → OTel Collector 实际接收

本次专用 leg 已实际启动并随后清理了一个新的、带 QA labels 的临时 Collector 容器，没有触碰其他共享容器：

| 项目 | 实际值 |
| --- | --- |
| source/sink | 既有 `securitycontext-py-312` 中的 FastAPI；一次 `POST /probe/collector-item`，HTTP 200 |
| OTLP | `OTEL_LOGS_EXPORTER=otlp`，HTTP endpoint 指向 Collector bridge IP `192.168.215.11:4318` |
| Collector | `securitycontext-python-v01-collector-ea511c23`，`otel/opentelemetry-collector-contrib:0.143.0` |
| image ID | `sha256:3bc07732530c87c53f9103b01a3afed972fdeba26087a590c1098781736e58c2` |
| config | [`collector-config-final.yaml`](../../build/validation/python-v01/product/collector-fastapi-ea511c23/collector-config-final.yaml)，以只读挂载提供 |
| 接收结果 | 本地 `evidence.jsonl` 10 条；Collector debug exporter 收到 10 条 JSON `security.dataflow.observed` body；10/10 与本地 evidence 匹配 |
| correlation | 所有 body 的 `trace_id=6dd1d284679fca5ced68d9158b73b2b7`、`server_span_id=adcb19cd939f8e59` 均同时匹配 Collector debug 行和本地 evidence |

这证明的是实际 Collector 接收了 JSON LogRecord body，不只是调用 InMemory/OTel API。原始 debug 日志、镜像、网络、请求和汇总证据见 [`collector-debug-final.log`](../../build/validation/python-v01/product/collector-fastapi-ea511c23/collector-debug-final.log)、[`collector-image-id.txt`](../../build/validation/python-v01/product/collector-fastapi-ea511c23/collector-image-id.txt)、[`request-response.json`](../../build/validation/python-v01/product/collector-fastapi-ea511c23/request-response.json) 和 [`collector-summary.json`](../../build/validation/python-v01/product/collector-fastapi-ea511c23/collector-summary.json)。日志保存后仅删除了上述新建容器，清理记录见 [`collector-cleanup.json`](../../build/validation/python-v01/product/collector-fastapi-ea511c23/collector-cleanup.json)。该 leg 有 provider/server instrumentation，因此其 trace ID 可用于本次 correlation；dataflow evidence 本身不以 span 存在为前提。

## SBOM 契约结果

本次按配置语义区分两个预算：

- `security.sbom.max.components` 严格限制 CycloneDX 输出组件总数，计入 `metadata.component` 的 application 以及顶层 runtime/build component；
- `security.sbom.max.entries` 是 metadata/archive 文件条目扫描预算，不是 build-SBOM 的组件输出上限。

实际测试结果：

- `max.components=1` 的严格测试通过；输出中 application 与顶层 records 不超过该总预算。该结果依赖当前实现为 application 预留一个 record budget，不再将 `max.entries` 错当组件上限。
- 使用真实三条目 `.whl` ZIP、`max.entries=1` 测试通过：返回 `archive_entry_limit`，不计算或缓存 artifact digest，扫描字节仍为 0。
- 新鲜 pip metadata 的 `pytest` 记录实际包含版本、PyPI PURL、`loaded=true`、`deployed=true`；未凭空生成 wheel hash，也未把 `RECORD` 当作组件证据。
- build 声明只在明确 PURL/bom-ref 可映射时建立依赖边；无 build 声明时依赖数组为空，未推断隐式 runtime dependency edges。
- 首次 loaded-origin 映射为 resolved；文件指纹变化后映射变为 `artifact_replaced_loaded_mapping_invalidated`，revision/sbom association 仍可追踪。`opentelemetry` namespace ambiguity 保持 unresolved，这是预期边界，不被强行解析。

四个版本实际生成的 `application.cdx.json` 均通过仓库现有的 CycloneDX 1.7 官方 JSON Schema validator：

```text
python tests/sbom/validate_cyclonedx_1_7.py \
  --schema-dir build/validation/sbom \
  build/validation/python-v01/product/<version>/application.cdx.json
```

SBOM 文档仍可能带有 `runtime_dependency_graph_incomplete`、namespace ambiguity 或 origin unmatched 等完整性原因；这表示观察模型的边界，不等于“已枚举所有依赖”。本次没有发明 wheel hash、依赖边或构建产物 `RECORD` 证据。

## 真实执行与未执行项

已执行的主要命令（均在对应容器内）：

```text
PYTHONPATH=python/src:python/samples pytest -q \
  python/tests/test_product_contract.py python/tests/test_sbom_contract.py

PYTHONPATH=python/src:python/samples \
  python python/scripts/run_product_case.py \
  --output build/validation/python-v01/product/<version>
```

已安装的 shared QA 容器记录的是历史 v0.1.0 Python distribution；本切片也只验证了该历史 package 的 canonical CLI 路径。安装 wheel 的 console script、包内样例/文档/constraints/Collector 资源和 canonical CLI 复制关系由独立 package validation 记录；当前 0.2.5 安装后应按主 README 的 `importlib.resources.files("securitycontext").joinpath("data", "samples")` 方式取得样例目录，并设置 `SECURITY_ENABLED=true` 与 `SECURITY_PYTHON_INCLUDE=security_sample`。

本报告中的 `build/validation` 链接、Collector 原始日志和最终外部 `SHA256SUMS` 都是仓库 checkout 的项目证据，不保证随 wheel 发出；当前 wheel 携带的构建类声明资源位于 `securitycontext/data/`。报告/产物目录不要用自身的 hash 代替最终外部 `SHA256SUMS`。

最终 package validation 报告为 [`package-report.json`](../../build/validation/python-v01/package-final-20260908/package-report.json)；用户交付目录固定为 [`python/dist`](../dist/)，其中外部发布校验文件为 [`release-validation.json`](../dist/release-validation.json)，发行物校验为 [`SHA256SUMS`](../dist/SHA256SUMS)。该运行验证了 sdist、checkout wheel、sdist 重建 wheel、console script/entry points、canonical CLI SHA-256、`importlib.resources` Collector resource 和非 editable 安装 wheel smoke，也验证了包内样例资源路径。框架 runner 的相对输出路径问题已在验证脚本入口修复；未修改生产代码。

## 全量测试旁证与边界

本报告仍是产品/SBOM 所有权切片，不替代全量发布报告。当前客户契约汇总为 [`client-qa.json`](../../build/validation/python-v01/clients/client-qa.json)：CPython 3.11–3.14 共 **52/52 passed**，failed/unverified 均为 0。最新全量 unit、未变更的 12/12 framework matrix、最终 package、三框架 CPython 3.12 安装 smoke（含 form/text 与 Flask cached-form 回归）、串行 benchmark 和 shutdown hook 结果统一见上方 external release manifest；本报告不重复旧矩阵，也不把历史切片计数冒充全量结果。

本报告没有覆盖或不会把下列边界写成已验证能力：`.pyc`-only、动态 main/`exec`、native extension、free-threaded Python、gevent/eventlet、Gunicorn preload、remote taint、identity ambiguity 未解决场景和未建模的 conversion。规则语义仍遵守参数化 SQL、ordinary argv、URL query 不是 host、Request 构造不等于 send、response body 不自动成为 taint；这些边界不由本次产品 runner 推导为更强结论。

全量阶段边界和最新结果见 [verification.md](verification.md)；Python 范围和配置边界见 [Python README](../README.md)；生命周期/shutdown 证据见 [verification-lifecycle.md](verification-lifecycle.md)，性能数字见 [performance.md](performance.md)，最终状态与发行物 hash 见上方 release manifest 和 `SHA256SUMS`。本报告保留产品/SBOM 历史切片性质，不重复或改写全量结果。
