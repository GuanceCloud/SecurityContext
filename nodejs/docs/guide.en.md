# SecurityContext Node.js 0.2.5 guide

This guide ships with `securitycontext-0.2.5.tgz` and is intended to be usable without the source repository. Package metadata, the dependency lock, and the actual results for this bundle are recorded in the package metadata and shipped `validation`/`release-validation` files; this guide does not copy historical test counts.

## 1. Version, dependencies, and local installation

The target runtimes are Node.js `>=22.22.3 <23` and `>=24.11.1 <25`. The package and import name is `securitycontext`. Its OTel API peer dependency is `>=1.9.1 <1.10.0`; the locked OTel SDK and instrumentation line is `0.222.0`, with `@opentelemetry/api` at `1.9.1`. The application still supplies its own framework, HTTP instrumentation, and logs provider.

Install the local tarball from the Node package directory in the release bundle so that a same-named registry package is not selected:

```bash
cd nodejs
npm install ./securitycontext-0.2.5.tgz \
  @opentelemetry/api@1.9.1 \
  @opentelemetry/sdk-node@0.222.0 \
  @opentelemetry/instrumentation-http@0.222.0 \
  @opentelemetry/instrumentation-express@0.70.0 \
  @opentelemetry/exporter-trace-otlp-http@0.222.0 \
  @opentelemetry/exporter-logs-otlp-http@0.222.0 \
  express@5.2.1
```

After installation, `securitycontext/register`, the package entry point, `data/securityctl.py`, and `docs/` come from the same tarball. Deployment commands should not depend on a shared documentation path outside the package.

## 2. Minimal runnable example

Create `otel-bootstrap.mjs` so that the host SDK, HTTP/Express instrumentation, and SecurityContext are registered before the application is imported:

```js
import { NodeSDK } from '@opentelemetry/sdk-node';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { ExpressInstrumentation } from '@opentelemetry/instrumentation-express';
import { SecurityInstrumentation } from 'securitycontext';

const sdk = new NodeSDK({
  instrumentations: [
    new HttpInstrumentation(),
    new ExpressInstrumentation(),
    new SecurityInstrumentation(),
  ],
});
sdk.start();
```

Create `app.mjs` with an Express 5 route. It passes `req.query.name` to a file-read boundary so a request source and a real sink are present in the example:

```js
import express from 'express';
import { readFile } from 'node:fs/promises';

const app = express();
app.get('/read', async (req, res) => {
  const requested = String(req.query.name ?? 'README.md');
  try {
    const body = await readFile(requested, 'utf8');
    res.type('text/plain').send(body.slice(0, 256));
  } catch {
    res.status(404).send('not found');
  }
});
const server = app.listen(3000, '127.0.0.1');
process.once('SIGTERM', () => server.close());
```

Start the application with an absolute include root, then send a request from another terminal:

```bash
export SECURITY_NODE_INCLUDE="$PWD"
export SECURITY_OUTPUT="$PWD/security-output"
export SECURITY_EVIDENCE_FILE="$PWD/security-output/evidence.jsonl"
export SECURITY_ENABLED=true
export SECURITY_SBOM_ENABLED=true
export OTEL_SERVICE_NAME=orders

node --import securitycontext/register \
  --import ./otel-bootstrap.mjs ./app.mjs

curl 'http://127.0.0.1:3000/read?name=README.md'
```

`otel-bootstrap.mjs` must run before importing Express, Fastify, `pg`, `mysql2`, or `undici`. `securitycontext/register` installs the package's scoped hooks; it does not take ownership of the host provider. A data-flow event can exist without an HTTP server span, but its trace association is then empty.

### Connect a local Collector and inspect a request

This minimal Collector configuration receives OTLP HTTP on `4318` for traces and logs, applies `memory_limiter` and `batch`, and prints records with the `debug` exporter. Save it as `otel-collector-config.yaml` and start a compatible Collector binary:

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

In another terminal, start the `app.mjs` example with the OTLP environment and then inspect local output:

```bash
export SECURITY_NODE_INCLUDE="$PWD"
export SECURITY_OUTPUT="$PWD/security-output"
export SECURITY_EVIDENCE_FILE="$PWD/security-output/evidence.jsonl"
export SECURITY_ENABLED=true
export SECURITY_SBOM_ENABLED=true
export OTEL_SERVICE_NAME=orders
export OTEL_TRACES_EXPORTER=otlp
export OTEL_LOGS_EXPORTER=otlp
export OTEL_METRICS_EXPORTER=none
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
node --import securitycontext/register \
  --import ./otel-bootstrap.mjs ./app.mjs
```

In a third terminal, run `curl 'http://127.0.0.1:3000/read?name=README.md'`, then inspect the package CLI and evidence:

```bash
python3 node_modules/securitycontext/data/securityctl.py \
  --dir "$PWD/security-output" status
python3 node_modules/securitycontext/data/securityctl.py \
  --dir "$PWD/security-output" query findings
tail -n 5 "$PWD/security-output/evidence.jsonl"
```

The Collector `debug` exporter prints received OTLP records; health, SBOM, and history remain process-level snapshots.

## 3. Configuration

Values are read from the process environment. Restart after changing them and use a new instance output directory.

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `SECURITY_ENABLED` | `true` | Master switch for security data-flow collection |
| `SECURITY_NODE_INCLUDE` | empty | Absolute business-code roots to transform |
| `SECURITY_NODE_EXCLUDE` | empty | Comma-separated excluded roots |
| `SECURITY_SBOM_ENABLED` | `true` | Independent runtime SBOM switch |
| `SECURITY_OUTPUT` | `./security-output/<instance-id>` | Health, findings, runs, control, and SBOM directory |
| `SECURITY_CONTROL_FILE` | `control.json` under output | Local control file |
| `SECURITY_EVIDENCE_FILE` | unset | Security evidence/diagnostic JSONL; SBOM events are not written here |
| `SECURITY_APPLICATION_ID` | OTel service identity fallback | Application identity; set explicitly when possible |
| `SECURITY_CODE_REPOSITORY` | empty | Repository identity for verification runs |
| `SECURITY_CODE_COMMIT` | empty | Commit identity for verification runs |
| `SECURITY_CODE_BUILD_ID` | empty | Build identity for verification runs |
| `SECURITY_RULES_<RULE>_ENABLED` | `true` | SQL, command, SSRF, HTTP input, and path-traversal rules |
| `SECURITY_MAX_ACTIVE_REQUESTS` | `256` | Concurrent-request budget |
| `SECURITY_MAX_NODES` | `8192` | Per-request propagation-node budget |
| `SECURITY_MAX_FINDINGS` | `32` | Per-request finding budget |
| `SECURITY_RUNS_MAX_BYTES` | `8388608` | Estimated retained key/value budget across all run counters; exhaustion increments incomplete and health counters |
| `SECURITY_EVIDENCE_MAX_BYTES` | `65536` | Per-record byte budget |
| `SECURITY_EXPORT_QUEUE_SIZE` / `SECURITY_EXPORT_SBOM_QUEUE_SIZE` | `1024` / `256` | Independent security and SBOM queues |

An empty include, a non-absolute include root, or a runtime outside Node 22/24 does not provide complete collection.

Run snapshots reuse unchanged rows and send only changed rows to the worker. Published counter maps use copy-on-write, and revisions are acknowledged only after a successful write. Source capture reads at most 128 field descriptors without invoking getters; JavaScript key enumeration still scales with input width, so application request-body limits remain relevant. A module with direct eval that can see a business binding named `Symbol` or `globalThis` stays native and reports the `direct_eval_helper_binding` coverage gap.

## 4. Output and schema v2

The main outputs are `health.json`, `findings.json`, `runs.json`, `control.json`, `application.cdx.json`, `sbom-history.json`, and optional `evidence.jsonl`. Owned state snapshots retain top-level `source="security_context"`. Health, SBOM, and SBOM history are process-level snapshots; they are not forced onto an individual request trace. Data-flow evidence is where request trace association is recorded.

Schema v2 events flatten these identity fields:

`application_id`, `instance_id`, `service`, `code`, `runtime`, and `identity_status`.

The OTel envelope `scope.name` is `SecurityContext`; it is not a body field. Native `eventName`, the `event.name` attribute, and body `event_name` must match, and the OTel `source` attribute must match the body `source`. The runtime uses `language=javascript` and `implementation=nodejs`; text ranges use `utf16_code_unit`, and Buffer ranges use `byte`. SBOM logs (`app-dependencies-loaded` and `security.sbom.*`) use `source=security_context_sbom`; other security events use `source=security_context`. The OTLP log `attributes.source` matches the JSON body `source`. Truncation summaries and minimal records preserve the original source. Each `sources[]` entry has `id`, `type`, `name`, `location`, `value_type`, and `value_length`; `sources[].name` is capped at 256 characters. Node sources may be `string`, `number`, `boolean`, `bigint`, or `Buffer`.

Sink roles are the canonical `sql_template`, `shell_script`, `argument`, `executable`, `destination_address`, `destination_unknown`, `path_or_query`, and `file_path`. File `operation` is retained as read/write/copy/rename/delete/unknown. An uncertain path parameter is `unknown`; it is never invented. Fingerprint v2 includes the language, per-segment UTF-8 length prefixes, and an ordered UTF-16 signature. A request emits only one finding for each v2 `finding_id`.

SBOM events use a separate channel. CycloneDX keeps its standard top-level structure; the source marker is the standard `properties[]` entry, with property namespace `securitycontext:` and component references `urn:securitycontext:component:`. Security JSONL contains only the evidence/diagnostic allowlist and never `security.sbom.*` events.

## 5. Trace, truncation, and delivery

For request data-flow, `trace_id` and `server_span_id` come from the HTTP server span, while `current_span_id` is captured from the current span at the sink. The event freezes these values and `trace_flags` when it is generated; the exporter does not rewrite them from a later current span. Without a valid server span, the IDs are empty and flags are `0`; a trace ID alone does not prove backend trace delivery. Process-level health, SBOM, and history use their own observation time and identity and are not forced to carry a request span. An OTel API `emit` is not an SDK, Collector, or backend acknowledgement.

When a record exceeds `SECURITY_EVIDENCE_MAX_BYTES`, optional `propagation`, `ranges`, and `sources` are removed before a `security.export.truncated` summary is written. Summary and minimal records do not require common identity or `observed_at`: a summary retains `original_event`, `evidence_id`, `sbom_id` (or `null`), and `truncated=true`; minimal has only `source`, `schema_version`, `event_name`, and `truncated`. If even those fields do not fit, the exporter records `record_too_small_for_envelope` and increments the channel's `.failed` count instead of directly increasing dropped. `security_dropped` and `sbom_dropped` remain separate, and only security-channel loss/failure/truncation contributes to security-ledger `delivery_loss`.

## 6. CLI and verification runs

The package CLI is the Python standard-library script shipped in the tarball:

```bash
CLI=node_modules/securitycontext/data/securityctl.py
OUT="$PWD/security-output"
python3 "$CLI" --dir "$OUT" status
python3 "$CLI" --dir "$OUT" query findings
python3 "$CLI" --dir "$OUT" query runs
python3 "$CLI" --dir "$OUT" query sbom
python3 "$CLI" --dir "$OUT" pause
python3 "$CLI" --dir "$OUT" resume
```

A run covers all HTTP requests in the process window, so isolate its traffic:

```bash
python3 "$CLI" --dir "$OUT" run-start \
  --case sql-dynamic --rule sql_injection --suite node-sample \
  --fixture express5-node24 --expected-requests 1 --ttl 300
python3 "$CLI" --dir "$OUT" run-stop --output "$OUT/candidate.json"
python3 "$CLI" verify --baseline "$OUT/baseline.json" \
  --candidate "$OUT/candidate.json" --output "$OUT/verification.json"
```

`observed`, `not_observed`, and `inconclusive` describe observations under the named conditions; they are not vulnerability confirmation, fix proof, or complete coverage. CLI control/report output carries source but may retain its own schema v1.

## 7. Upgrade, disable, and uninstall

There is no automatic compatibility shim for an old package/import/JAR/namespace. Update dependencies and imports manually to `securitycontext`; readers of historical events must handle v1 themselves. Keep fingerprint v1 and v2 aggregates separate; v2 must not be silently recomputed as a v1 ID.

At runtime, `instrumentation.disable()` stops new collection. For a complete stop, set `SECURITY_ENABLED=false`, stop the process, and restart it. Drain the package before the host SDK shuts down:

```js
await shutdown({ timeoutMillis: 2000 });
await sdk.shutdown();
```

Stop the Node process before removing the `securitycontext` dependency and output files. Hooks already established in a process are not hot-unloaded.

## 8. Troubleshooting and boundaries

- No events: check that `SECURITY_NODE_INCLUDE` is an absolute business-code path, registration/bootstrap runs before application imports, and the host logs provider is configured.
- Snapshots without trace: start HTTP instrumentation and the provider before requests; an empty association without a server span is expected.
- No JSONL: check permissions on the evidence file's parent; SBOM events do not use this file.
- `incomplete` or `truncated`: inspect `coverage_gaps`, object/node/finding/byte budgets, and dropped/failed counts for both channels.
- Adapter gaps: verify Express 4/5, Fastify 5, `pg` 8, `mysql2` 3, or `undici` 8 and avoid private loaders, dynamic modules, and early imports.
- Unresolved SBOM components: make package-lock, archives, and runtime-load metadata readable; preserve a reason for unknown version/hash/dependency edges.

The default output omits raw request bodies, complete SQL, command text, complete URLs, and command argument values. Arbitrary JavaScript syntax, private dynamic modules, cross-service taint, post-response background work, arbitrary binary bodies, reflection/native data flow, forced-kill/host recovery, trace replay, Collector/backend acknowledgement, performance, and SLA are outside the default guarantee. Events describe observations at modeled call boundaries.

See the package-contained [compatibility](compatibility.md), [verification record](verification.md), and [Chinese guide](guide.zh-CN.md) for related material.
