# SecurityContext Java 0.3.4 user guide

This guide is shipped with the `securitycontext-0.3.4` Java package and is usable without the source checkout. `validation.json`, `manifest.json`, and `SHA256SUMS` are package files. An unpacked release may also place an optional `release-validation.json` beside the archive in the bundle's `java/` directory; it is an external receipt/release report and is deliberately not included in the JAR/tar.gz/zip. This guide does not duplicate test numbers or turn historical results into a current gate claim.

## 1. Package layout and dependencies

```text
securitycontext-0.3.4/
├── lib/
│   ├── securitycontext.jar
│   └── opentelemetry-javaagent-2.31.1.jar
├── bin/
│   ├── run-demo.sh
│   └── securityctl.py
├── examples/apps/
├── examples/observed/
├── collector/
├── docs/guide.zh-CN.md
├── docs/guide.en.md
├── validation.json
├── manifest.json
├── SHA256SUMS
└── licenses/
```

The Java extension is `securitycontext.jar` and its library namespace is `io.securitycontext.*`. The extension is compiled for Java 8 bytecode and targets Java 8, 11, 17, and 21. The paired OTel Java Agent is `2.31.1`; the extension API target is `2.31.1-alpha`. If an application already has an Agent, use the Agent and extension versions covered by the same package inventory.

Verify the package before use:

```bash
shasum -a 256 -c SHA256SUMS       # macOS
sha256sum -c SHA256SUMS           # Linux
```

Then read the matching results in the package's `validation.json`. If the bundle's `java/` directory provides an external `release-validation.json` beside the archive, use it to review unpacking and receipt results. A directory without its inventory, checksums, or `validation.json` is not a reviewable release package.

## 2. Minimal startup

The extension must be loaded together with the OTel Java Agent. If an Agent is already present, append the extension instead of starting a second Agent:

```bash
java \
  -javaagent:/absolute/path/to/lib/opentelemetry-javaagent-2.31.1.jar \
  -Dotel.javaagent.extensions=/absolute/path/to/lib/securitycontext.jar \
  -Dotel.service.name=orders \
  -Dsecurity.enabled=true \
  -Dsecurity.sbom.enabled=true \
  -Dsecurity.application.id=orders \
  -Dsecurity.output="$PWD/security-output" \
  -Dsecurity.evidence.file="$PWD/security-output/evidence.jsonl" \
  -jar application.jar
```

The load order is: the JVM starts the OTel Agent, the Agent loads the SecurityContext extension, HTTP Server instrumentation creates request context, and the application handles the request. Without HTTP Server instrumentation, some events may still be produced, but request lifecycle, `server_span_id`, and request state are not guaranteed.

The package demos use the same order:

```bash
./bin/run-demo.sh boot2
./bin/run-demo.sh boot3
```

The demos are package fixtures. The supported combinations and the current results are recorded in the shipped validation file. The script creates an isolated output directory by default; `SECURITY_OUTPUT_DIR`, `DEMO_PORT`, and `JAVA_BIN` can override it.

### Connect a local Collector and inspect one request

The package's `collector/otel-collector-config.yaml` receives OTLP gRPC on `4317` and OTLP HTTP on `4318`, applies `memory_limiter` and `batch`, exports traces/logs with `debug`, and exposes a health check on `13133`. Start a Collector binary that supports this configuration:

```bash
otelcol --config collector/otel-collector-config.yaml
```

In another terminal, send traces and logs to the OTLP HTTP receiver and use a fixed output directory. The code identity below is for the demo; replace it with the actual repository, commit, and build ID before a verification run:

```bash
OUT="$PWD/output/otlp-demo"
java \
  -javaagent:"$PWD/lib/opentelemetry-javaagent-2.31.1.jar" \
  -Dotel.javaagent.extensions="$PWD/lib/securitycontext.jar" \
  -Dotel.service.name=security-demo \
  -Dotel.traces.exporter=otlp \
  -Dotel.logs.exporter=otlp \
  -Dotel.metrics.exporter=none \
  -Dotel.exporter.otlp.protocol=http/protobuf \
  -Dotel.exporter.otlp.endpoint=http://127.0.0.1:4318 \
  -Dsecurity.enabled=true \
  -Dsecurity.sbom.enabled=true \
  -Dsecurity.application.id=security-demo \
  -Dsecurity.code.repository=https://example.invalid/securitycontext \
  -Dsecurity.code.commit=local-commit \
  -Dsecurity.code.build-id=local-build \
  -Dsecurity.output="$OUT" \
  -Dsecurity.evidence.file="$OUT/evidence.jsonl" \
  -Dserver.address=127.0.0.1 \
  -Dserver.port=18080 \
  -jar examples/apps/security-validation-boot2.jar
```

Send one real request and inspect the local ledger/evidence; the Collector `debug` exporter prints the received OTLP records too:

```bash
OUT="$PWD/output/otlp-demo"
curl 'http://127.0.0.1:18080/api/sql?value=demo'
python3 bin/securityctl.py --dir "$OUT" status
python3 bin/securityctl.py --dir "$OUT" query findings
tail -n 5 "$OUT/evidence.jsonl"
```

This demonstrates the specified request's transport and local record path. Process-level health and SBOM keep their own observation time and identity.

## 3. Configuration

| JVM property | Default | Purpose |
| --- | --- | --- |
| `security.enabled` | `true` | Global security data-flow collection switch |
| `security.sbom.enabled` | `true` | Independent runtime SBOM switch |
| `security.output` | `./security-output/<instance-id>` | Default directory for health, findings, runs, control, and SBOM |
| `security.evidence.file` | unset | Security evidence/diagnostic JSONL path |
| `security.application.id` | derived from OTel service identity | Application identity for findings, SBOM, and runs; set it explicitly |
| `security.code.repository` | empty | Real repository identity required by verification runs |
| `security.code.commit` | empty | Real commit identity |
| `security.code.build-id` | empty | Real build identity |
| `security.rules.<rule>.enabled` | `true` | `sql_injection`, `command_execution`, `command_injection`, `ssrf`, `http_request_input`, `path_traversal` |
| `security.max.active.requests` | `256` | Concurrent request limit |
| `security.max.nodes` | `8192` | Per-request propagation-node limit |
| `security.max.findings` | `32` | Per-request finding limit |
| `security.evidence.max.bytes` | `65536` | Per-record OTel/JSONL byte limit |
| `security.export.queue.size` | `1024` | Security queue entries |
| `security.export.sbom.queue.size` | `256` | SBOM queue entries |

Environment variables use the uppercase underscore form of a system property, such as `SECURITY_ENABLED`, `SECURITY_SBOM_ENABLED`, and `SECURITY_APPLICATION_ID`. JVM properties are read by the running process; restart with a new output directory after changing them.

## 4. Output and schema v2

Typical output includes `health.json`, `findings.json`, `runs.json`, `control.json`, `application.cdx.json`, `sbom-history.json`, and optional `evidence.jsonl`. Events and owned snapshots carry this top-level envelope:

```json
{
  "source": "security_context",
  "schema_version": 2,
  "event_name": "security.dataflow.observed",
  "observed_at": "2026-09-08T00:00:00.123Z"
}
```

Normal schema v2 events also flatten six identity fields: `application_id`, `instance_id`, `service`, `code`, `runtime`, and `identity_status`; unknown identity fields retain the empty string or `null` allowed by their field contract rather than being invented. `runtime` always has `language`, `implementation`, `version`, `os`, `architecture`, and `details`; Java puts `vendor` and `vm_name` in `details`. The OTel envelope `scope.name` is `SecurityContext`, not a body field. Native `eventName`, the OTel `event.name` attribute, and body `event_name` must match, and the OTel `source` attribute must match the body `source`.

SBOM logs (`app-dependencies-loaded` and `security.sbom.*`) use `source=security_context_sbom`; other security events use `source=security_context`. The OTLP log `attributes.source` matches the JSON body `source`. Truncation summaries and minimal records preserve the original source. Each `sources[]` entry uses the six fields `id/type/name/location/value_type/value_length` with `src-` IDs and a 256-character name cap. Sinks use the complete `function/role/location/operation/path_role/input_part` shape. Canonical roles include `sql_template`, `shell_script`, `argument`, `executable`, `destination_address`, `destination_unknown`, `path_or_query`, and `file_path`. File operations remain `read/write/copy/rename/delete/unknown`; use `unknown` when a path cannot be classified as source or target.

`security.sbom.snapshot` is an OTel event with flat identity fields. The owned files `health.json`, `findings.json`, `runs.json`, and `sbom-history.json` keep their own state contracts. Health, SBOM, and history are process-level snapshots rather than request-trace records; request data-flow evidence carries request association. CycloneDX keeps its standard top level: the source marker is in `properties[]`, component refs use `urn:securitycontext:component:`, and properties use the `securitycontext:` namespace. SBOM events are excluded from security JSONL; JSONL receives only the security evidence and diagnostic allowlist.

## 5. Trace and delivery

For request data-flow, `trace_id` and `server_span_id` come from the HTTP Server span, while `current_span_id` is captured from the current span at the sink. The event freezes these values and `trace_flags` when it is generated. Without a valid server span, IDs are empty and flags are `0`; a trace ID alone is not proof that a backend trace exists. Process-level health, SBOM, and history use their own observation time and identity rather than being forced onto a request span. The exporter does not rewrite request fields from the sending thread or current span.

An OTel API `emit` means that the SDK API was called; it does not prove Collector receipt, backend persistence, or acknowledgement. Security and SBOM use independent queues. `security_dropped` and `sbom_dropped` stay separate, and only security-channel loss, failure, and truncation enter the security ledger's `delivery_loss`.

When a record exceeds the byte budget, propagation, ranges, and sources are removed before a `security.export.truncated` summary is emitted. The summary keeps `original_event`, `evidence_id`, `sbom_id` (using `null` when absent), and `truncated=true`, but like minimal it does not require identity or `observed_at`. The minimal envelope has exactly `source`, `schema_version`, `event_name`, and `truncated`. If those four fields do not fit, record `record_too_small_for_envelope` and increment the channel `.failed` counter without directly incrementing dropped.

## 6. CLI and verification runs

All commands operate on one process output directory:

```bash
OUT=/absolute/path/to/security-output
python3 bin/securityctl.py --dir "$OUT" status
python3 bin/securityctl.py --dir "$OUT" query findings
python3 bin/securityctl.py --dir "$OUT" query runs
python3 bin/securityctl.py --dir "$OUT" query sbom
python3 bin/securityctl.py --dir "$OUT" pause
python3 bin/securityctl.py --dir "$OUT" resume
```

A verification run covers every HTTP request in its process window. Isolate test traffic and provide real code identity fields:

```bash
python3 bin/securityctl.py --dir "$OUT" run-start \
  --case sql-dynamic --rule sql_injection --suite java-sample \
  --fixture boot2-java17 --expected-requests 1 --ttl 300
python3 bin/securityctl.py --dir "$OUT" run-stop \
  --output "$OUT/candidate.json"
python3 bin/securityctl.py verify \
  --baseline "$OUT/baseline.json" \
  --candidate "$OUT/candidate.json" \
  --output "$OUT/verification.json"
```

`observed` means data flow was observed under the specified conditions, `not_observed` means it was not observed under those conditions, and `inconclusive` means identity, traffic, source/sink, completeness, or delivery evidence was insufficient. None is an exploit confirmation or complete-coverage claim. CLI report/control output carries `source=security_context`; its own state schema may remain v1.

## 7. Upgrade, disable, and uninstall

Older archive package names, JAR filenames, and namespaces have no automatic compatibility shim. Update consumers manually to `securitycontext.jar`, `io.securitycontext.*`, and schema v2; readers of historical events must handle v1 themselves. `fingerprint_version=2` includes a language segment, a 4-byte big-endian UTF-8 length prefix for every segment, and UTF-16 signature ordering. Do not merge v1 finding IDs directly with v2 IDs.

Disable security collection or SBOM with:

```bash
java -Dsecurity.enabled=false -Dsecurity.sbom.enabled=false \
  -javaagent:/path/to/opentelemetry-javaagent-2.31.1.jar \
  -Dotel.javaagent.extensions=/path/to/securitycontext.jar \
  -jar application.jar
```

To uninstall, stop the JVM, remove the extension from `otel.javaagent.extensions`, confirm that no process references the JAR, and then remove `securitycontext.jar` and its output. A running JVM does not hot-unload an extension.

## 8. Troubleshooting and boundaries

- No events: check the Agent and extension paths, `security.enabled`, HTTP Server instrumentation, the target JVM, and the host SDK's log exporter.
- No request trace: register server instrumentation before requests; dataflow can exist without it, but an empty `server_span_id` is expected.
- No JSONL: check that the parent of `security.evidence.file` is writable; SBOM events do not enter that file.
- Stale health or control timeout: use the same instance directory, confirm the process is alive, and do not merge files from multiple workers or JVMs.
- `incomplete` or `truncated`: inspect `coverage_gaps`, `counts`, budgets, and per-channel dropped/failed counters; it does not mean no risk exists.
- Unresolved SBOM: check readable archive and metadata; unknown versions, hashes, dependency edges, and load mappings retain a reason instead of being guessed.

Raw request values, full SQL, command text, complete URLs, and command argument values are not emitted by default. WebFlux, cross-service propagation, work after response completion, arbitrary binary bodies, reflection/native data flow, JDBC batch, XSS, deserialization, online CVE lookup, dynamic attach, crash/host-failure recovery, trace replay, and external backend acknowledgement are outside the default guarantee.
