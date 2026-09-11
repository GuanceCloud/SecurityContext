# Python v0.1.0 验收总览

本页是 Python v0.1.0 的阶段验收总览。数字和结论只引用仓库中已经生成的
JSON、JUnit、JSONL 和发行物报告；未完成或未覆盖的组合不按“通过”推断。
性能数字由独立 Darwin worker 写入 [`performance.md`](performance.md)，并由
最终外部 release manifest 引用。

## 环境、约束与版本边界

已验证环境是 OrbStack Linux arm64，CPython standard GIL：3.11.16、
3.12.14、3.13.15、3.14.7。OTel release pair 固定为
`opentelemetry-api`/SDK 1.44.0 与 contrib 0.65b0；其余实际测试 pins 见
[`constraints-python-v0.1.0-arm64.txt`](../constraints-python-v0.1.0-arm64.txt)。
所有已声明的运行时环境均为 aarch64；x86_64 没有本次实测证据，不能从本页
结论推导 x86_64 兼容性。

最后的全版本 framework matrix 在 cached-property descriptor 修复和 Uvicorn
shutdown hook 修复之前完成，不能冒充这些修复后的全矩阵重跑。最终发行 wheel
只对 CPython 3.12 做了 FastAPI、Flask、Django 三框架安装后重测；这三项以及
独立的 no-barrier shutdown hook gate 覆盖了最后生产修复。

## 阶段结果

| 验收切片 | 实际结果 | 主要证据 |
| --- | --- | --- |
| unit / loader / semantics / lifecycle | 51 passed | [`junit.xml`](../../build/validation/python-v01/unit-suite-final3-20260907/junit.xml) |
| 四版本、三框架 matrix | 12/12 passed；11 项复用原 rerun3，3.13 Django 使用修复后的 replacement leg | [`matrix-summary.json`](../../build/validation/python-v01/matrix-final-20260907-composed/matrix-summary.json) |
| client / native DB / HTTP / process / filesystem | 52/52 passed，failed/unverified 为 0；CPython 3.11、3.12、3.13、3.14 各 13/13 | [`verification-clients.md`](verification-clients.md)；[`client-qa-py311.json`](../../build/validation/python-v01/clients/client-qa-py311.json)、[`py312`](../../build/validation/python-v01/clients/client-qa-py312.json)、[`py313`](../../build/validation/python-v01/clients/client-qa-py313.json)、[`py314`](../../build/validation/python-v01/clients/client-qa-py314.json) |
| product / CLI / SBOM | 四版本产品切片均为 9 passed；CycloneDX 1.7 schema leg 通过 | [`verification-product.md`](verification-product.md) |
| 实际 Collector | FastAPI OTLP HTTP leg：本地 10 条、Collector 10 条、10/10 匹配 | [`collector-summary.json`](../../build/validation/python-v01/product/collector-fastapi-ea511c23/collector-summary.json) |
| final installed framework smoke | 3/3 passed；FastAPI/Flask 各 19 条 dataflow，Django 12 条；form/text 专属 source→sink 与 parameterized-negative checks 均通过 | [`final-installed-final3b-20260907`](../../build/validation/python-v01/final-installed-final3b-20260907/) |
| Uvicorn no-barrier shutdown hook | passed；HTTP 200、requests_completed=3、active_requests=0、findings=9、JSONL records=19，health/finding/evidence identity 一致 | [`shutdown-summary.json`](../../build/validation/python-v01/shutdown-hook-final3-20260907/shutdown-summary.json) |
| package | final release 由 sdist 重建 wheel；direct/from-sdist wheel、console entry point、canonical CLI SHA、包内资源和 non-editable smoke 已核对 | [`package-report.json`](../../build/validation/python-v01/package-final-20260908/package-report.json) |
| benchmark | 由 Darwin 独立执行五轮串行 workload；详见 [`performance.md`](performance.md)，最终 gate 以外部 manifest 为准 | [`benchmark-final-20260907`](../../build/validation/python-v01/benchmark-final-20260907/) |

Benchmark 的固定 workload 是 FastAPI `GET /bench`，query 为
`benchmark-query`，并发 16；每组 5 轮，每轮 500 warmup + 5000 measured，
三组串行交错，OTel traces/logs/metrics exporter 均为 `none`、trace sampler 为
`always_on`。报告的 5 轮中位数为：baseline **3678.348 RPS / 8.010 ms
p95**，OTel-only **2342.511 / 12.172 ms**，security **831.919 / 34.997 ms**；
security 相对 OTel-only 吞吐下降约 **64.5%**、p95 约 **2.88x**。security 五
轮均为 `observed/effective`，active=0、source/sink requests=5501、
incomplete/budget skip/delivery loss 均为 0。CPU、RSS、startup 和共享
OrbStack/短样本限制见 [`performance.md`](performance.md)；这些数字不是容量或
SLA 承诺。

`verification-product.md` 是 Mendel 的产品/SBOM 所有权切片，保留其历史切片
性质；本页不把其中 OTel API emit 当作 Collector 或后端 ACK。实际 Collector
接收证据另见上表。客户端的 PostgreSQL 16 与 MySQL 8.4.11 使用自有 QA 容器，
证据只覆盖列出的实际 cases，不扩展为未运行的数据库或驱动组合。

## 生命周期与关闭语义

普通 framework runner 和 benchmark 使用有界 drain barrier，结束前要求
`requests_completed` 达到预期且 `active_requests=0`。这用于避免读取初始
health snapshot，但不能替代 shutdown hook 验收。

独立 hook leg 在没有预先 drain barrier 的情况下发出 SIGTERM，Uvicorn 返回
`-15`，并由现有 `Server.shutdown` wrapper 的 `finally` 调用 bounded
`runtime.flush`。它不接管 signal handler，不关闭共享 OTel provider，也不
停止 runtime；force_flush 返回 False 或抛错时，业务返回/异常仍保持原样，已
关闭的 negative run 会标记 delivery loss/incomplete，不能继续作为
`not_observed`。本次 hook health 的状态为 `incomplete`，原因是样例有一个
request-completion gap；这不是把不完整运行包装成有效 negative。

JSONL 的 19 个 records 是 9 个 observed dataflow、9 个 finding summary 和
1 个 collection-incomplete diagnostic，不是 19 条独立风险链。旧 Django ASGI
初始 snapshot 只证明旧运行写出了请求期间数据，不证明最终 ledger flush；修复
后的 no-barrier 证据以上述 hook artifact 为准，旧说明见
[`verification-asgi.md`](verification-asgi.md)。

## 发行物与可复核路径

最终用户交付目录固定为 [`python/dist`](../dist/)。其中只放选定的 sdist 重建
wheel、sdist、`SHA256SUMS` 和外部
[`release-validation.json`](../dist/release-validation.json)；`SHA256SUMS` 只
覆盖同目录 wheel 和 sdist。最终 wheel hash、sdist hash、安装后 smoke、
源码/样例与实测 wheel 的内容同一性，以及各阶段 artifact SHA 由该外部 manifest
记录。报告不把自身 hash 嵌入 wheel，因此最终文档更新不会形成自引用 hash。

最终 package 的构建顺序是 checkout package → sdist → 从 sdist 重建 wheel →
安装重建 wheel smoke。`verification.md` 和 `performance.md` 必须在最终
package build 前进入 `securitycontext/data/docs/`；最终 manifest 在包外生成，
不再通过修改已打包报告改变发行物 hash。

## 未验证组合与阶段限制

以下项目没有被本次实测覆盖，不能写成支持或通过：

- x86_64、free-threaded/no-GIL CPython、gevent/eventlet、Gunicorn preload；
- 只有 `.pyc` 的模块、未经过 import loader 的动态 `__main__`/`exec`/`eval`、
  native/C extension 内部数据流和跨服务/remote taint；
- 完整的四版本 × 所有输入载体组合。form-urlencoded 与 text/plain 的专属
  source→sink leg 只在最终 3.12 三框架 smoke 中补验，不宣称四版本全组合；
- 旧 Django ASGI artifact 的最终 flush、客户端取消/断连、backpressure、
  concurrent streams，以及未列入 client JSON 的数据库/驱动组合；
- backend ACK、故障恢复、fsync 语义和性能/SLA。OTel API emit、本地 flushed
  JSONL 和 Collector receipt 的证据边界仍按产品与生命周期报告描述。

规则仍遵守参数化 SQL negative、普通 argv 角色、URL query 不继承固定 host、
Request 构造不等于 send；numeric/custom source conversion 无法证明时是
inconclusive，不是静默安全结论。

## 入口

- [Python README](../README.md)
- [产品/SBOM 验证切片](verification-product.md)
- [客户端验证切片](verification-clients.md)
- [生命周期与 shutdown](verification-lifecycle.md)
- [性能报告](performance.md)
- [外部 release manifest](../../build/validation/python-v01/release-validation-final3-20260907.json)
