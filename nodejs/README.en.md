# SecurityContext Node.js 0.2.5

`securitycontext` records bounded security data-flow evidence and a runtime SBOM in a Node.js process. It transforms only business JavaScript under the absolute `SECURITY_NODE_INCLUDE` path. `node_modules`, OpenTelemetry packages, the package itself, and Node built-ins keep their own loading boundaries. Events describe observed modeled calls; they are not a claim of vulnerability recall, exploit validation, or a production SLA.

See the package-contained [English guide](docs/guide.en.md) or [中文指南](docs/guide.zh-CN.md) for the complete independent distribution instructions.

## Install and start

Preload the registration module and your OpenTelemetry bootstrap before the application entry point:

```sh
# Run from the release bundle's nodejs/ directory, or adjust the tarball path.
npm install ./securitycontext-0.2.5.tgz \
  @opentelemetry/api@1.9.1 \
  @opentelemetry/sdk-node@0.222.0 \
  @opentelemetry/instrumentation-http@0.222.0 \
  @opentelemetry/instrumentation-express@0.70.0 \
  express@5.2.1
export SECURITY_NODE_INCLUDE=/absolute/path/to/your/business
node --import securitycontext/register \
  --import ./otel-bootstrap.mjs ./app.mjs
```

The bootstrap should register the host SDK, HTTP/framework instrumentation, and exporters before importing Express, Fastify, or another instrumented library. A security event can still be written without an active OTel server span, but it must not be described as trace-linked in that case.

The same `SecurityInstrumentation` instance can be passed to the host SDK:

```js
import { NodeSDK } from '@opentelemetry/sdk-node';
import { SecurityInstrumentation, shutdown } from 'securitycontext';

const instrumentation = new SecurityInstrumentation();
const sdk = new NodeSDK({ instrumentations: [instrumentation] });
sdk.start();
// Drain the package's bounded queues before the host owns SDK shutdown.
await shutdown({ timeoutMillis: 2000 });
await sdk.shutdown();
```

Repeated register imports and repeated construction reuse one package instance. Shutdown is bounded and best effort; queue, budget, exporter, and snapshot failures are surfaced as loss or diagnostic state. The default wait is 1500 ms; pass `timeoutMillis` to choose another bound.

## Configuration

Useful settings include `SECURITY_ENABLED` for data-flow collection, the independent `SECURITY_SBOM_ENABLED` switch, `SECURITY_NODE_INCLUDE` and `SECURITY_NODE_EXCLUDE` roots, `SECURITY_OUTPUT`, `SECURITY_CONTROL_FILE`, and `SECURITY_EVIDENCE_FILE`. Resource limits include `SECURITY_MAX_TRACKED_BYTES`, `SECURITY_MAX_PROCESS_TRACKED_BYTES`, `SECURITY_MAX_ACTIVE_REQUESTS`, `SECURITY_REQUESTS_PER_SECOND`, `SECURITY_EXPORT_QUEUE_SIZE`, and `SECURITY_EXPORT_SBOM_QUEUE_SIZE`. Rules can be enabled or disabled individually, for example with `SECURITY_RULES_SQL_INJECTION_ENABLED` and `SECURITY_RULES_PATH_TRAVERSAL_ENABLED`.

The output directory contains `health.json`, `findings.json`, `runs.json`, and control state; with SBOM enabled it also contains `application.cdx.json` and `sbom-history.json`. SecurityContext owned state snapshots carry top-level `source=security_context`. SBOM logs use `source=security_context_sbom` in both OTLP attributes and JSON body; truncated logs keep the original source. Health, SBOM, and history are process-level snapshots rather than request-trace records; data-flow evidence carries request trace association. The SBOM combines package-lock declarations with runtime load observations. Unresolved packages, hashes, or runtime graph edges retain an `incomplete` status and are not a completeness guarantee.

The modeled sinks cover file paths (`fs.readFile`), command executable or argv (`child_process.exec`/`execFile`), outbound HTTP host/path/query (HTTP clients and `fetch`), and SQL templates (`pg`/`mysql2`). This evidence does not promise coverage for every third-party library, private or dynamic module, generator, loader, or JavaScript syntax.

Modules exceeding 2 MiB of source or 50,000 AST nodes execute their original code and report a coverage gap. Re-export metadata queries deduplicate visits and limit work and depth per query. Reaching a limit can omit propagation evidence; the native module system still supplies business values. See [compatibility](docs/compatibility.md) for these boundaries.

## Packaged install and CLI

Install the local tarball from the release bundle's `nodejs/` directory; the guides above provide complete application and bootstrap files:

```sh
npm install ./securitycontext-0.2.5.tgz @opentelemetry/api@1.9.1
export SECURITY_OUTPUT=./security-output
node --import securitycontext/register \
  --import ./otel-bootstrap.mjs ./app.mjs
python3 node_modules/securitycontext/data/securityctl.py \
  --dir ./security-output status
```

The supported targets are Node 22 `>=22.22.3 <23` and Node 24 `>=24.11.1 <25`. Express 4/5 and Fastify 5 ESM/CommonJS boundaries are documented in [compatibility](docs/compatibility.md). Verification records only combinations that were actually run; static file checks do not replace a runtime request.

## Event contract

Node.js shares the schema v2 contract with Python and Java. The package-contained [English guide](docs/guide.en.md) and [中文指南](docs/guide.zh-CN.md) include the event fields, source, SBOM, trace, and truncation rules. The OTel envelope scope.name is `SecurityContext`; native `eventName`, the `event.name` attribute, and body `event_name` must be identical. SBOM event roots carry `source=security_context_sbom`; other event roots carry `source=security_context`; each `sources[]` entry has the six source fields, alongside the six identity fields and shared runtime/source/sink/component shapes. JavaScript text ranges use `utf16_code_unit`; Buffer ranges use `byte`.

## Documentation and boundaries

- [English guide](docs/guide.en.md)
- [中文指南](docs/guide.zh-CN.md)
- [Compatibility](docs/compatibility.md)
- [Verification record](docs/verification.md)
- [Release checklist](docs/release-checklist.md)
- [Sample entry points](samples/README.md)

Data-flow, ledger, and JSONL output do not require a span. For request data-flow, `trace_id` and `server_span_id` come from the server span, `current_span_id` is captured at the sink, and the event freezes those values and `trace_flags` when generated. A usable association exists only when provider/server instrumentation and an active server span are available. Health, SBOM, and history are process-level outputs and do not gain a request span merely because they are emitted during a request. An OTel API emit is not an SDK, Collector, or backend acknowledgement; a local JSONL flush is not `fsync`.

## Loaded dependency reporting

Dependency reports use `app-dependencies-loaded`. Each entry in `dependencies` contains only `name` and `version`, with `hash` added when coordinates or the version are incomplete and a real artifact SHA-256 is available. Only dependencies observed as loaded are reported. Local `application.cdx.json` remains CycloneDX, and `sbom-history.json` retains the inventory history.

Large snapshots share a `sbom_id` and `revision`; `part_index` starts at zero. Consumers must receive all `part_count` parts before replacing their inventory. SBOM rate limiting defers delivery to the next window and increments `sbom.budget_deferred`; queue capacity and shutdown deadlines remain bounded. API emission is not a backend acknowledgement. Consumers must update subscriptions and parsing from the previous component delta and snapshot events.
