# Node.js compatibility boundaries

The release target is Node 22 and Node 24 at or above `22.22.3` and
`24.11.1`. Historical 0.1.0 checks covered Express 4, Express 5, and Fastify 5
in ESM and CommonJS, plus Express 5 ESM requests on both minimum versions.
See [`verification.md`](verification.md) for those records. The complete
matrix has not been repeated as a 0.2.0 release gate; the current schema v2
checks are listed in `data/current-verification.json`.

Start the application in this order:

```sh
node --import securitycontext/register \
  --import ./otel-bootstrap.mjs ./app.mjs
```

The OTel bootstrap must register the host SDK, HTTP/framework instrumentation,
and exporter before the application imports Express, Fastify, or another
instrumented library. The security registration creates scoped require/import
hooks and transforms only files selected by the absolute
`SECURITY_NODE_INCLUDE` path. `node_modules`, the security package, OTel
packages, and Node built-ins remain outside the business AST transform. This
boundary is intentional: OTel owns framework/HTTP tracing and the security
transform owns explicitly included business code.

To bound synchronous loader work, sources over 2 MiB or parsed modules over
50,000 AST nodes retain native execution. They report `transform_source_limit`
or `transform_node_limit`, respectively; data flow inside those modules is not
instrumented. The AST limit is checked before scope analysis. Parsing and
conversion still run synchronously, so these size limits are not a wall-clock
latency guarantee.

The observed checks prove the tested fixture behavior, trace-context sharing,
and bounded cleanup. They do not establish compatibility with arbitrary
loaders, the old asynchronous `--experimental-loader` path, every framework
plugin, every driver release, worker-thread startup ordering, or all valid
JavaScript syntax. Private/dynamic module loading and generators do not have a
complete data-flow guarantee. Non-literal default expressions retain native
evaluation and are not re-evaluated or assigned a guessed source mark.

Optional chains containing private names retain native evaluation and report
`private_optional_chain` as a coverage gap. Object shorthand `__proto__`
retains its own data-property semantics. Promise detection uses Node's native
type predicate without invoking a returned Proxy's prototype traps. Simple
arithmetic loops over locals proven to remain numeric retain native execution;
unknown inputs, conversions, calls and dynamic scopes remain instrumented.

Finding and run snapshots are written only after their revisions change.
The exporter sends one row per acknowledged worker message, allowing the main
event loop to run between rows; JSON encoding and file writes happen in the
worker. A revision is acknowledged only after the complete snapshot is written,
so concurrent request updates and failed writes are retried on the next tick.

ESM export preservation, live-binding/cycle fixtures, and single execution are
covered by the current semantic and loader checks, but a passing fixture is not
a promise for arbitrary module graphs. Export-mark queries run only with an
active collection context and visit each module/export-name pair once per
query. A query is limited to 256 lookups and 32 nested modules, including named
re-exports; exhaustion reports `export_metadata_limit` or
`export_metadata_depth`. These bounds can omit propagation metadata without
changing the imported business value. Results are not cached across reads or
requests, so live bindings and request isolation remain intact.

Source maps are best effort and a failed/large map is reported as a coverage
gap. Events describe modeled calls
that were observed; they are not vulnerability recall, validation, or a
production SLA.

The CycloneDX loader currently accepts `specVersion` 1.7 only. The bundled
`securityctl.py` uses Python 3 and the POSIX `fcntl` module; Linux and macOS
are the exercised environments, and Windows CLI support is not verified.

The plugin shutdown is bounded and best effort. It drains what fits the
configured queues before timeout; queue, budget, exporter, and snapshot
failures are reported as delivery loss or diagnostic events. The 120-second
Node 24 soak in the verification record had zero drops and returned tracking
bytes, active requests, and queues to zero in idle samples, but that is still a
single controlled fixture run rather than a production capacity claim.

## 0.2.2 转换与传播工作量边界

- Node.js Promise 结果按元数据和结果身份去重，每次恢复最多处理 4,096 次访问/边操作；宽图超限记录 `promise_metadata_work_limit`，保留原 Promise 结果。去重状态不跨请求保存。结果数组被修改为 getter/proxy 时不会为采集额外触发用户代码，记录覆盖缺口。
- Node.js 数值绑定分析使用反向依赖工作队列，取消全量固定点扫描。单次分析最多 50,000 次工作操作，超限模块执行原代码并记录 `transform_analysis_limit`；原有 2 MiB 源码和 50,000 AST 节点上限保留。
- Python 帧敏感别名使用依赖队列传播，保留 locals/eval/super 等调用帧语义。转换新增 2 MiB 源码、50,000 AST 节点和 100,000 次别名分析工作上限；超限由原 loader 执行模块一次，并记录对应 `transform_*_limit`。

超限保留业务执行并产生覆盖缺口，具体限制见 [0.2.2 修复说明](release-notes.zh-CN.md)。
