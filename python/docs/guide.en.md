# SecurityContext Python 0.2.5 guide

This guide ships with the `securitycontext-0.2.5` wheel and sdist and is intended to be readable without the source repository. The package and import name is `securitycontext`; the supported runtimes are CPython 3.11 through 3.14. The installed package keeps its release material under `securitycontext/data/docs/`. The `validation` and `release-validation` files in a release bundle are the authority for the build and runtime results of that bundle; historical verification numbers are not a gate result for this release.

## Version, dependencies, and installation

The core dependencies are `opentelemetry-api==1.44.0`, `opentelemetry-instrumentation==0.65b0`, `opentelemetry-instrumentation-threading==0.65b0`, `wrapt>=1.17,<3`, and `packaging>=24`. Optional framework adapters cover FastAPI, Flask, and Django. The OTLP startup combination is `opentelemetry-distro==0.65b0` with `opentelemetry-exporter-otlp-proto-http==1.44.0`. The application still supplies its own framework, ASGI/WSGI server, database, and HTTP client. PyPy, free-threaded/no-GIL Python, and other non-CPython interpreters are outside this target.

Install a local artifact from the release bundle so that the package name resolves to this release:

```bash
python -m pip install ./securitycontext-0.2.5-py3-none-any.whl
# or
python -m pip install ./securitycontext-0.2.5.tar.gz
python -m pip install \
  opentelemetry-distro==0.65b0 \
  opentelemetry-exporter-otlp-proto-http==1.44.0 \
  opentelemetry-instrumentation-fastapi==0.65b0
```

Install only the `fastapi`, `flask`, `django`, or `otlp` extras that the application needs. Samples, Collector configuration, constraints, the CLI, and documentation are read from `securitycontext/data/` after installation. Samples are not production dependencies and are not installed as top-level application packages.

## OTel startup order and a minimal example

An ordinary ASGI/WSGI process starts through the OTel pre-instrument and instrumentor entry points. Load the security entry points before importing application modules or database/HTTP clients:

```bash
export SECURITY_ENABLED=true
export SECURITY_PYTHON_INCLUDE=myapp,mycompany.service
export SECURITY_PYTHON_EXCLUDE=myapp.migrations
export SECURITY_OUTPUT="$PWD/security-output"
export SECURITY_EVIDENCE_FILE="$PWD/security-output/evidence.jsonl"
export SECURITY_SBOM_ENABLED=true
export OTEL_SERVICE_NAME=orders
export OTEL_LOGS_EXPORTER=otlp

opentelemetry-instrument uvicorn myapp.main:app \
  --host 127.0.0.1 --port 8000
```

`SECURITY_PYTHON_INCLUDE` must contain at least one application module prefix; an empty value does not install the Python AST loader. `SECURITY_PYTHON_EXCLUDE` wins over include. A module imported before instrumentation is not transformed retroactively, so `opentelemetry-instrument` should be the outermost startup command.

You can run the packaged FastAPI sample directly. The wheel places it at `securitycontext/data/samples/security_sample`; these commands locate that installed directory, start a real application, and send a request:

```bash
python -m pip install fastapi uvicorn requests opentelemetry-instrumentation-fastapi==0.65b0
SAMPLES_DIR="$(python - <<'PY'
from importlib.resources import files
print(files("securitycontext").joinpath("data", "samples"))
PY
)"
SECURITY_ENABLED=true \
SECURITY_PYTHON_INCLUDE=security_sample \
SECURITY_OUTPUT="$PWD/security-output" \
SECURITY_EVIDENCE_FILE="$PWD/security-output/evidence.jsonl" \
OTEL_SERVICE_NAME=security-sample \
PYTHONPATH="$SAMPLES_DIR" \
  opentelemetry-instrument python -m uvicorn \
  security_sample.fastapi_app:app --host 127.0.0.1 --port 8000

# In another terminal, POST /probe reads query/path/header/body and reaches modeled sinks.
curl -X POST -H 'content-type: application/json' \
  --data '{"query":"sample","filename":"safe.txt"}' \
  'http://127.0.0.1:8000/probe/demo?q=sample'
```

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

In another terminal, add the OTLP environment to the packaged-sample command above and start it; from a third terminal, send a request and inspect output:

```bash
export OTEL_TRACES_EXPORTER=otlp
export OTEL_LOGS_EXPORTER=otlp
export OTEL_METRICS_EXPORTER=none
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
# Repeat the SAMPLES_DIR/PYTHONPATH and opentelemetry-instrument command above.
```

```bash
curl -X POST -H 'content-type: application/json' \
  --data '{"query":"sample","filename":"safe.txt"}' \
  'http://127.0.0.1:8000/probe/demo?q=sample'
securityctl --dir "$PWD/security-output" status
securityctl --dir "$PWD/security-output" query findings
tail -n 5 "$PWD/security-output/evidence.jsonl"
```

The Collector `debug` exporter prints received OTLP records; health, SBOM, and history remain process-level snapshots.

Gunicorn must initialize OTel inside each worker:

```bash
gunicorn -c python:securitycontext.gunicorn \
  --bind 127.0.0.1:8000 myapp.wsgi:application
```

The package configuration isolates each worker's output in `post_fork` and then calls OTel `initialize()`. `preload_app=True` is rejected. Do not use `opentelemetry-instrument gunicorn`, which initializes the SDK before the master/fork boundary.

## Configuration

Configuration is read from environment variables; restart the process after changing it. Only case-insensitive `true` enables a Boolean value, and numeric budgets are clamped to at least 1.

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `SECURITY_ENABLED` | `true` | Master switch for security data-flow collection |
| `SECURITY_PYTHON_INCLUDE` | empty | Comma-separated application module prefixes; must be explicit |
| `SECURITY_PYTHON_EXCLUDE` | empty | Module prefixes excluded with priority |
| `SECURITY_OUTPUT` | `./security-output/<instance_id>` | Health, findings, runs, control, and SBOM output directory |
| `SECURITY_EVIDENCE_FILE` | unset | Security evidence/diagnostic JSONL; SBOM events are not written here |
| `SECURITY_CONTROL_FILE` | `control.json` under output | Pause, resume, run, and exception control file |
| `SECURITY_SBOM_ENABLED` | `true` | Independent runtime SBOM switch |
| `SECURITY_SBOM_OUTPUT` | `application.cdx.json` under output | SBOM snapshot path |
| `SECURITY_RULES_SQL_INJECTION_ENABLED` | `true` | SQL-template concatenation flow; bound parameters are not promoted to SQL-injection evidence |
| `SECURITY_RULES_COMMAND_EXECUTION_ENABLED` | `true` | Executable and argument observations |
| `SECURITY_RULES_COMMAND_INJECTION_ENABLED` | `true` | Shell-script observations |
| `SECURITY_RULES_SSRF_ENABLED` | `true` | Actual HTTP destination observations |
| `SECURITY_RULES_HTTP_REQUEST_INPUT_ENABLED` | `true` | Outbound URL path/query carriers |
| `SECURITY_RULES_PATH_TRAVERSAL_ENABLED` | `true` | File path boundary observations |
| `SECURITY_MAX_TRACKED_BYTES` / `SECURITY_MAX_PROCESS_TRACKED_BYTES` | 1 MiB / 64 MiB | Per-request and per-process propagation budgets |
| `SECURITY_MAX_ACTIVE_REQUESTS` / `SECURITY_REQUESTS_PER_SECOND` | 256 / 1000 | Concurrent request and rate budgets |
| `SECURITY_MAX_NODES` / `SECURITY_MAX_FINDINGS` | 8192 / 32 | Per-request graph-node and finding budgets |
| `SECURITY_EVIDENCE_MAX_BYTES` | 65536 | Per-record evidence byte budget |
| `SECURITY_EXPORT_QUEUE_SIZE` / `SECURITY_EXPORT_SBOM_QUEUE_SIZE` | 1024 / 256 | Independent security and SBOM queues |
| `SECURITY_APPLICATION_ID`, `OTEL_SERVICE_NAME` | fallback | Application and service identity; set explicitly when possible |

Set `OTEL_PYTHON_DISABLED_INSTRUMENTATIONS=securitycontext` or `*` to disable the OTel entry point from outside the package. An installed import finder is not unloaded at runtime; stop and restart the process after disabling it.

## Output, schema v2, and source

The main outputs are `health.json`, `findings.json`, `runs.json`, `control.json`, `application.cdx.json`, and `sbom-history.json`. The owned `health`, `findings`, and `runs` snapshots carry top-level `source="security_context"`; `sbom-history` uses application/release history identity fields. Control and report files may retain their own schema v1 and still carry the same source. Security events go to the configured evidence JSONL, while SBOM events use a separate channel and are not written to the security JSONL.

The common schema v2 event envelope contains:

- `schema_version=2`, `event_name`, UTC millisecond `observed_at`, and `source` (`security_context_sbom` for SBOM logs, `security_context` for other events);
- flat `application_id`, `instance_id`, `service`, `code`, `runtime`, and `identity_status`; a caller that supplies incomplete identity may produce `identity_status=incomplete`, and unknown identity fields remain the empty string or `null` allowed by their field contract;
- `runtime={language,implementation,version,os,architecture,details}`, with Python GIL/build information in `details`;
- envelope `scope.name="SecurityContext"`; it is not a body field. Native `eventName`, the `event.name` attribute, and body `event_name` must match, and the OTel `source` attribute must match the body `source`.

SBOM logs (`app-dependencies-loaded` and `security.sbom.*`) use `source=security_context_sbom`; other security events use `source=security_context`. The OTLP log `attributes.source` matches the JSON body `source`. Truncation summaries and minimal records preserve the original source. Each entry in `sources[]` has six fields: `id`, `type`, `name`, `location`, `value_type`, and `value_length`; `sources[].name` is capped at 256 characters. Python sources may be `str`, `bytes`, or `bytearray`; string lengths use `unicode_code_point`, while bytes and bytearray use `byte`. `sink.role` uses only the canonical roles `sql_template`, `shell_script`, `argument`, `executable`, `destination_address`, `destination_unknown`, `path_or_query`, and `file_path`. File `operation` is retained; an unknown path parameter `source` or `target` is written as `unknown` rather than guessed.

SBOM snapshots retain the standard CycloneDX shape. The source marker is the standard `properties[]` entry `{name:"source",value:"security_context"}`; the property namespace is `securitycontext:` and component references use `urn:securitycontext:component:`. SBOM `quality.loaded_components` counts components observed as loaded. Component references in evidence use `status` and `reason` to describe resolution; unknown versions and dependency relationships are not inferred.

## Trace, truncation, and delivery

For request data-flow, `trace_id` and `server_span_id` come from the HTTP server span, while `current_span_id` is captured from the current span at the sink. The event freezes these values and `trace_flags` when it is generated. Without a valid server span the IDs are empty and flags are `0`. Process-level health, SBOM, and history use their own observation time and identity rather than being forced onto a request span. An OTel API `emit` is not an SDK, Collector, or backend acknowledgement. Events and the ledger can exist without a span, but an empty trace ID is not correlation evidence.

When a record exceeds its byte budget, optional evidence is removed before writing a `security.export.truncated` summary. Both summary and minimal records may omit the common identity and `observed_at`: a summary retains `original_event`, `evidence_id`, `sbom_id` (or `null`), and `truncated=true`; minimal is limited to `schema_version`, `source`, `event_name`, and `truncated`. If even that envelope does not fit, the exporter records `record_too_small_for_envelope` and increments the channel's `.failed` count instead of directly increasing dropped. `security_dropped` and `sbom_dropped` remain separate; only security-channel loss/failure/truncation contributes to security-ledger `delivery_loss`.

## CLI and verification runs

The installed command and editable checkout use the same canonical CLI:

```bash
OUT="$PWD/security-output"
securityctl --dir "$OUT" status
securityctl --dir "$OUT" query findings --offset 0 --limit 100
securityctl --dir "$OUT" query runs --case my-case
securityctl --dir "$OUT" query sbom --offset 0 --limit 100
securityctl --dir "$OUT" pause
securityctl --dir "$OUT" resume
```

The module form is available as `python -m securitycontext.cli --dir "$OUT" status`. A verification run must isolate its request traffic and use real identity fields:

```bash
securityctl --dir "$OUT" run-start \
  --case sql-dynamic --rule sql_injection --suite python-sample \
  --fixture fastapi-cpython312 --expected-requests 1 --ttl 300
securityctl --dir "$OUT" run-stop --output "$OUT/candidate.json"
securityctl verify --baseline "$OUT/baseline.json" \
  --candidate "$OUT/candidate.json" --output "$OUT/verification.json"
```

`observed`, `not_observed`, and `inconclusive` describe runtime observations under the specified conditions; they do not prove a vulnerability, a fix, or complete coverage. Status, control, and report files may use v1; events remain schema v2.

## Upgrade, disable, and uninstall

There is no automatic compatibility shim for an old package/import/JAR/namespace. Update the dependency and imports manually to `securitycontext`; readers of historical events must handle v1 themselves. Keep fingerprint v1 and v2 in separate aggregates. v2 uses the language, per-segment UTF-8 length prefixes, and the ordered UTF-16 signature, so it must not be silently recomputed as a v1 ID.

To disable the instrumentation:

```bash
export SECURITY_ENABLED=false
export OTEL_PYTHON_DISABLED_INSTRUMENTATIONS=securitycontext
# Stop existing workers and restart with the new environment
python -m pip uninstall securitycontext
```

Stop all workers before uninstalling and decide whether to retain or remove output, evidence, and SBOM files. Uninstalling does not delete an existing ledger.

## Troubleshooting and capability boundaries

- No events: check `SECURITY_ENABLED=true`, a real module prefix in include, the `opentelemetry-instrument` startup path, and whether the target module was imported too early.
- Snapshots without trace: start the OTel provider, HTTP server instrumentation, and log exporter before handling requests; empty IDs without a server span are expected.
- Gunicorn workers overwrite each other: use `python:securitycontext.gunicorn`, avoid `preload_app=True`, and run the CLI against each worker's output directory.
- `incomplete` or `truncated`: inspect include/exclude, object/node/finding/byte budgets, queue dropped/failed counts, and `coverage_gaps`.
- Incomplete SBOM: make package metadata, loaded components, and runtime dependencies readable; retain a reason for unknown version/hash/dependency edges instead of guessing.
- Empty JSONL: check permissions on the evidence file's parent directory; SBOM events are not written to security JSONL.

The default output omits raw request bodies, complete SQL, command text, complete URLs, and command argument values. Arbitrary Python syntax, source-less `.pyc`/native modules, dynamically generated modules, cross-service taint, arbitrary binary bodies, forced-kill/host recovery, trace replay, Collector/backend acknowledgement, performance, and SLA are outside the default guarantee. Events describe observations at modeled call boundaries.

See the package-contained [configuration](configuration.md), [compatibility](compatibility.md), [architecture](architecture.md), and [verification record](verification.md) for more detail.
