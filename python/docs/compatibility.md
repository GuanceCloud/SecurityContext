# SecurityContext Python 0.2.0 兼容性与明确边界

本页区分三件事：代码中的运行时门控、仓库给出的依赖范围、已记录与尚未执行的真实验证证据。宽范围依赖声明不等于每个版本组合都经过验证；复现实验应使用精确 constraints 和明确的框架组合。

## 目标运行时

| 项目 | 当前代码/配置 | 结论 |
| --- | --- | --- |
| Python | `requires-python >=3.11,<3.15` | 目标 CPython 3.11、3.12、3.13、3.14 |
| 实现 | `platform.python_implementation() == "CPython"` | PyPy 等不在目标内 |
| GIL | 拒绝 `Py_GIL_DISABLED` 构建或 `sys._is_gil_enabled()` 为 false | 即使临时启用 GIL，free-threaded 构建也不在目标内 |
| OS | 运行时不阻止其他 OS 启动 | Linux 是正式验收环境；其他平台不据此获得已验证承诺 |
| 进程模型 | fork 后重置 runtime；Gunicorn post-fork 重新初始化 | Gunicorn 必须 `preload_app=False` |
| 调度器 | 依赖 OTel Context/ContextVar 和现有框架生命周期 | 没有 gevent/eventlet 专用适配，不作支持承诺 |

`config.collection_configured()` 要求安全开关、至少一个 include 前缀和上述 runtime 条件同时满足。版本/GIL gate 只阻止 collection；它不会把未支持解释器伪装成已验证。`config.profile()` 会把 budgets 纳入 `instrumentation_profile`，所以不同预算配置的 run 不应被当作同一 profile。

## 框架和依赖范围

源码适配器面向 Starlette/FastAPI ASGI、Flask WSGI、Django WSGI/ASGI，并递归捕获 Pydantic v2 model fields。`pyproject.toml` 的范围和当前仓库精确 pin 如下：

| 组件 | pyproject 范围 | `constraints-python-v0.1.0-arm64.txt` 中的复现 pin | 说明 |
| --- | --- | --- | --- |
| FastAPI | test extra 未限制版本；可选 OTel adapter `==0.65b0` | `fastapi==0.141.1` | 需要按实际 FastAPI/Starlette 组合复现，宽范围不代表全覆盖 |
| Pydantic | `>=2,<3`（test extra） | `pydantic==2.13.5` | v2 `model_fields` 中的 `str`/`bytes` 字段可递归追踪；numeric/custom 字段不伪造 taint，无法证明其转换时验证应为 `inconclusive`，不当作安全的 negative |
| Starlette | 间接依赖 | `starlette==1.6.0` | FastAPI/ASGI carrier 和 lifecycle 的具体组合 |
| Flask | `>=3.1,<3.2`（test extra） | `Flask==3.1.3` | 通过 WSGI request/response 迭代器绑定状态 |
| Django | `>=5.2,<5.3`（test extra） | `Django==5.2.17` | WSGI/ASGI handler、HttpRequest、resolver 和 cursor boundary |
| OTel API | `==1.44.0` | `opentelemetry-api==1.44.0` | 使用已有 provider，不创建独立 provider |
| OTel instrumentation | `==0.65b0` | `opentelemetry-instrumentation==0.65b0` | entry point、threading 和 contrib adapters |
| OTel distro/OTLP | optional `==0.65b0` / `==1.44.0` | `opentelemetry-distro==0.65b0`, exporter `1.44.0` | 提供 `opentelemetry-instrument`/OTLP 组合时使用 |
| wrapt / packaging | `wrapt>=1.17,<3`, `packaging>=24` | `wrapt==2.4.0`, `packaging==26.3` | wrapper 和 distribution metadata |

测试/样例 extras 还声明 `uvicorn`、`gunicorn`、`httpx`、`requests`、`aiohttp`、`SQLAlchemy>=2,<3`、`psycopg[binary]>=3,<4`、`PyMySQL>=1,<2` 等；这些是可选 sink/运行器依赖，不意味着每种 client、driver 或版本都已通过 QA。

精确复现入口：

```bash
cd python
python -m pip install -c constraints-python-v0.1.0-arm64.txt \
  -e ".[test,otlp,fastapi,flask,django]"
```

`test` extra 会安装框架包，但不会安装三个官方 OTel framework instrumentor；需要 server span 时必须同时选择对应的 `fastapi`、`flask`、`django` extras。该 constraints 文件声明的是一个 Linux/arm64 resolved environment；不要把它解释成 x86_64、Windows、macOS 或每个 Python/框架组合的证明。`python/scripts/run_python_matrix.py` 的默认版本集合是 3.11–3.14，默认框架集合是 fastapi/flask/django。

## 初始化、打包和 Gunicorn

包通过：

- `securitycontext:bootstrap` 的 `opentelemetry_pre_instrument` entry point 安装 import finder；
- `securitycontext:SecurityInstrumentor` 的 instrumentor entry point 安装 framework/sink/threading hooks；
- `python:securitycontext.gunicorn` 的 `post_fork` 在 worker 中调用 OTel `initialize()`。

只有可读 `.py` 且在 include/exclude 边界内的后续 import 模块获得 AST transform。以下情况保留原始执行或记录 gap：已提前导入模块、`.pyc`-only/native loader、动态生成模块、未进入 Finder 的动态/`__main__` 入口、`exec`/`eval` 生成代码。

Gunicorn 的安装启动命令是：

```bash
gunicorn -c python:securitycontext.gunicorn myapp.wsgi:application
```

该配置的 `post_fork` 在 worker 中生成隔离目录并初始化 OTel，然后才导入应用；`preload_app=True` 不支持。不要推荐 `opentelemetry-instrument gunicorn`，因为它会在 master/fork 前初始化 SDK。

`setup.py` 在构建时将 `scripts/securityctl.py` 单源复制到包内，并把样例、文档、constraints 和仓库 canonical collector config 放进 `securitycontext/data/`。安装 wheel 后使用 `importlib.resources.files("securitycontext").joinpath("data", "samples")` 取得样例目录，并将其加入 `PYTHONPATH` 后导入 `security_sample`；常规 pip wheel 是文件系统资源，zip 资源需要先通过 `importlib.resources.as_file()` 解包。安装命令是 `securityctl`，editable 源码可用 `python -m securitycontext.cli`；二者仍调用同一 canonical script，不应分叉维护。`build/validation`、Collector 原始日志和 `SHA256SUMS` 是仓库证据，不随 wheel 自动发出。

## 数据流与检测边界

支持的首批规则为 SQL、命令执行/命令注入、SSRF、HTTP request input 和路径遍历。需要特别区分：

- 参数化 SQL 的 bind value 不会被隐式搜索；只有带 taint 的 SQL template/statement 到达执行边界才会有 SQL evidence。
- 普通 argv 不是 shell script；普通参数以 argument 角色观察，不会自动生成 shell 注入或“可执行文件受控”的候选结论。
- URL 的 query/path mark 不会升级为固定 host 的 SSRF address；实际 send/open 才是 HTTP sink。
- `requests.Request`、`httpx.Request`、`aiohttp.ClientRequest`、`urllib.request.Request` 构造只传播 URL carrier；构造不等于发送，URL 不传播到响应 body。
- Python 范围单位是 `unicode_code_point` 或 `byte`；旧 Java 缺省单位为 UTF-16 码元，不可直接套用。
- 对象身份歧义、共享 scalar、无法建模的转换、超出 traversal/节点/字节预算的路径会进入 `coverage_gaps`，不是“无漏洞”。

请求状态优先从 OTel `Context` 读取；server instrumentation 改写该 context 时，进程内 `ContextVar` 作为 request-lifetime fallback。WSGI iterable 在每次 `next`/`close` 时临时 attach，耗尽、close 或 error 只完成一次请求；recording server span 上的 summary 是可选索引，不是 dataflow/ledger/JSONL 的前提。

当前明确不在通用模型内的还有跨服务/远程 taint、反射/native 数据流、XSS、反序列化、free-threaded 运行时和 gevent/eventlet 调度语义。

## SBOM 兼容性语义

SBOM 输出为 CycloneDX 1.7，组件来自运行时 distribution metadata、模块 origin 和真实本地 archive。只有实际可读 artifact 才计算 SHA-256；没有可证明来源时保留 unresolved/incomplete reason。运行时不猜依赖图；只有外部构建 CycloneDX 中可按稳定 PURL/bom-ref 解析的边被合并。

`revision`、`sbom_id`、`content_sha256` 和 component `bom-ref` 共同标识一次 published snapshot；事件和 module mapping 必须来自同一 revision。`loaded` 仅表示模块加载观察，不表示代码执行或漏洞可达。当前实现为每个 archive/模块和完整 snapshot 设置上限；`security.sbom.max.entries` 用于 metadata/package-map/archive entry discovery，不是 CycloneDX component 数量上限。

`security.sbom.max.components` 限制 CycloneDX 文档 component 总数，并为 `metadata.component` application 预留一个 slot；`security.sbom.max.entries` 独立限制 metadata/package-map/archive entry discovery，不限制 component 输出数量。真实测试还覆盖了 archive entry limit、revision 映射和 unresolved namespace/origin 边界。

产品契约的实际结果见 [产品验证报告](verification-product.md)；本页仍不把未执行项写成支持承诺：

- 性能/benchmark、x86_64、非 Linux、强杀/主机故障恢复和 OTel backend ACK 仍不是本页的验证结论；
- `.pyc`-only、动态 `__main__`/`exec`、native、free-threaded、gevent/eventlet、Gunicorn preload 和 remote taint 仍明确不支持；
- 12/12 framework matrix 已由主 QA 确认通过；本产品切片不重复执行该矩阵。

## 0.2.2 转换与传播工作量边界

- Node.js Promise 结果按元数据和结果身份去重，每次恢复最多处理 4,096 次访问/边操作；宽图超限记录 `promise_metadata_work_limit`，保留原 Promise 结果。去重状态不跨请求保存。结果数组被修改为 getter/proxy 时不会为采集额外触发用户代码，记录覆盖缺口。
- Node.js 数值绑定分析使用反向依赖工作队列，取消全量固定点扫描。单次分析最多 50,000 次工作操作，超限模块执行原代码并记录 `transform_analysis_limit`；原有 2 MiB 源码和 50,000 AST 节点上限保留。
- Python 帧敏感别名使用依赖队列传播，保留 locals/eval/super 等调用帧语义。转换新增 2 MiB 源码、50,000 AST 节点和 100,000 次别名分析工作上限；超限由原 loader 执行模块一次，并记录对应 `transform_*_limit`。

超限保留业务执行并产生覆盖缺口，具体限制见 [0.2.2 修复说明](release-notes.zh-CN.md)。
