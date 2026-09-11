# SecurityContext Python 0.2.5

`securitycontext` is the SecurityContext Python 0.2.5 package. It uses the OpenTelemetry startup entry points and a pure-Python import hook to transform only explicitly included application modules. It records bounded data-flow evidence in request context and sends records to the process's existing OTel Logs provider. It does not scan for vulnerabilities and does not change application return values.

This README is included in the wheel and sdist. For the complete package-contained operating guide, see [the English guide](docs/guide.en.md) or [中文指南](docs/guide.zh-CN.md). The package's `data/docs/` directory contains the other release material; validation and release-validation files shipped with a bundle are the authority for that bundle's actual results.

## Install and start

The distribution and import name is `securitycontext`, version `0.2.5`. Install the local artifact from a release bundle:

```bash
python -m pip install ./securitycontext-0.2.5-py3-none-any.whl
# or
python -m pip install ./securitycontext-0.2.5.tar.gz
```

The target runtime is CPython 3.11–3.14 with the standard GIL build. Install the optional adapter and OTLP dependencies required by the application:

```bash
python -m pip install \
  opentelemetry-distro==0.65b0 \
  opentelemetry-exporter-otlp-proto-http==1.44.0 \
  opentelemetry-instrumentation-fastapi==0.65b0
```

The core package uses `opentelemetry-api==1.44.0`, `opentelemetry-instrumentation==0.65b0`, and `opentelemetry-instrumentation-threading==0.65b0`. The application supplies its own framework, ASGI/WSGI server, database, and HTTP client.

Start through OTel so the pre-instrument and instrumentor entry points run before application imports:

```bash
SECURITY_ENABLED=true \
SECURITY_PYTHON_INCLUDE=myapp,mycompany.service \
SECURITY_PYTHON_EXCLUDE=myapp.migrations \
SECURITY_OUTPUT="$PWD/security-output" \
SECURITY_EVIDENCE_FILE="$PWD/security-output/evidence.jsonl" \
SECURITY_SBOM_ENABLED=true \
OTEL_SERVICE_NAME=orders \
OTEL_LOGS_EXPORTER=otlp \
opentelemetry-instrument uvicorn myapp.main:app \
  --host 127.0.0.1 --port 8000
```

`SECURITY_PYTHON_INCLUDE` must contain an application module prefix. An empty include does not install the AST loader, and `SECURITY_PYTHON_EXCLUDE` takes priority. Modules imported before instrumentation are not transformed retroactively.

For Gunicorn, initialize OTel in each worker with the package configuration:

```bash
gunicorn -c python:securitycontext.gunicorn \
  --bind 127.0.0.1:8000 myapp.wsgi:application
```

Do not use `opentelemetry-instrument gunicorn`; the package configuration isolates worker output and initializes OTel after `post_fork`, while `preload_app=True` is rejected.

## Installed resources and CLI

Samples, constraints, Collector configuration, documentation, and the canonical CLI are under `securitycontext/data/`. Locate them without relying on a checkout path:

```bash
python - <<'PY'
from importlib.resources import files
print(files("securitycontext").joinpath("data", "docs"))
print(files("securitycontext").joinpath("data", "samples"))
PY
```

Use the installed CLI against a process-local output directory:

```bash
OUT="$PWD/security-output"
securityctl --dir "$OUT" status
securityctl --dir "$OUT" query findings --offset 0 --limit 100
securityctl --dir "$OUT" query runs --case my-case
securityctl --dir "$OUT" query sbom --offset 0 --limit 100
securityctl --dir "$OUT" pause
securityctl --dir "$OUT" resume
```

The module form is `python -m securitycontext.cli --dir "$OUT" status`. A verification run must isolate its request traffic:

```bash
securityctl --dir "$OUT" run-start \
  --case sql-dynamic --rule sql_injection --suite python-sample \
  --fixture fastapi-cpython312 --expected-requests 1 --ttl 300
securityctl --dir "$OUT" run-stop --output "$OUT/candidate.json"
securityctl verify --baseline "$OUT/baseline.json" \
  --candidate "$OUT/candidate.json" --output "$OUT/verification.json"
```

`observed`, `not_observed`, and `inconclusive` are observations under the named conditions; they are not vulnerability confirmation, fix proof, or complete coverage.

## Output contract

The process writes `health.json`, `findings.json`, `runs.json`, `control.json`, `application.cdx.json`, `sbom-history.json`, and, when configured, security evidence/diagnostic JSONL. Owned snapshots and CLI control/report output carry `source="security_context"`; control/report files may keep their own schema v1. Security events use schema v2 and the security JSONL channel. SBOM events use a separate channel and are not written to that JSONL file.

Every schema v2 event carries `schema_version=2`, `event_name`, millisecond UTC `observed_at`, the flat identity fields `application_id`, `instance_id`, `service`, `code`, `runtime`, and `identity_status`, plus root `source` (`security_context_sbom` for SBOM logs, `security_context` for other events). The OTLP `source` attribute matches the body `source`, including after truncation. The OTel envelope scope.name is `SecurityContext`; native `eventName`, the `event.name` attribute, and body `event_name` must agree. Python runtime details include the GIL/build state. Each `sources[]` entry has `id`, `type`, `name`, `location`, `value_type`, and `value_length`; Python sources include `str`, `bytes`, and `bytearray`, using `unicode_code_point` for strings and `byte` for byte sequences. The package guide documents canonical sink roles, SBOM properties, trace association, truncation, and delivery counters.

SBOM output keeps standard CycloneDX structure. Its source marker is in standard `properties[]`; it does not add a nonstandard top-level field. Unknown component status, version, hashes, or dependency edges remain unknown or incomplete instead of being invented.

## Boundaries and lifecycle

Data-flow evidence, the ledger, and security JSONL do not require a span. For request data-flow, `trace_id` and `server_span_id` come from the server span, `current_span_id` is captured at the sink, and the event freezes the values and `trace_flags` when generated. A usable association exists only with a provider/server instrumentation and valid server span. Process-level SBOM and health snapshots are independent of a request trace. An OTel API emit is not an SDK, Collector, or backend acknowledgement, and a local JSONL flush is not `fsync`.

The package models explicit Python source and sink boundaries, including SQL, command, HTTP, and file paths. It does not promise complete coverage for arbitrary Python syntax, source-less or native modules, dynamic modules, cross-service taint, arbitrary binary bodies, forced-kill/host recovery, trace replay, every third-party adapter, performance, or SLA.

## Disable, upgrade, and uninstall

Disable before restarting with:

```bash
export SECURITY_ENABLED=false
export OTEL_PYTHON_DISABLED_INSTRUMENTATIONS=securitycontext
```

There is no automatic compatibility shim for an old package/import/JAR/namespace. Update dependencies and imports manually to `securitycontext`; readers of historical events must handle v1. Keep fingerprint v1 and v2 aggregates separate. Stop all workers before uninstalling:

```bash
python -m pip uninstall securitycontext
```

Uninstalling does not delete existing output, evidence, or SBOM files. See [configuration](docs/configuration.md), [compatibility](docs/compatibility.md), and the [complete guide](docs/guide.en.md) for package-contained details.

## Loaded dependency reporting

Dependency reports use `app-dependencies-loaded`. Each entry in `dependencies` contains only `name` and `version`, with `hash` added when coordinates or the version are incomplete and a real artifact SHA-256 is available. Only dependencies observed as loaded are reported. Local `application.cdx.json` remains CycloneDX, and `sbom-history.json` retains the inventory history.

Large snapshots share a `sbom_id` and `revision`; `part_index` starts at zero. Consumers must receive all `part_count` parts before replacing their inventory. SBOM rate limiting defers delivery to the next window and increments `sbom.budget_deferred`; queue capacity and shutdown deadlines remain bounded. API emission is not a backend acknowledgement. Consumers must update subscriptions and parsing from the previous component delta and snapshot events.
