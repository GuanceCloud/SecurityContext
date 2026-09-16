# SecurityContext Java 0.3.4

SecurityContext `0.3.4` is an OpenTelemetry Java Agent extension for bounded security data-flow observation and a runtime SBOM. Applications do not need source changes. The package carries `validation.json`, `manifest.json`, and `SHA256SUMS`; an unpacked release may provide `release-validation.json` beside the archive in the bundle's `java/` directory as an external receipt/release record, not as package content. Use these records for the package's actual artifact and validation results instead of copying historical numbers into a current report.

## Package contents

- `lib/securitycontext.jar`: Java 8 bytecode extension in the `io.securitycontext.*` namespace;
- `lib/opentelemetry-javaagent-2.31.1.jar`: paired OTel Java Agent;
- `examples/apps/`: Boot 2 and Boot 3 black-box fixtures;
- `examples/observed/`: observations produced by this package when present;
- `collector/`: package Collector configurations;
- `bin/securityctl.py` and `bin/run-demo.sh`: local query, control, verification, and demo startup;
- `docs/`: complete Chinese and English guides;
- `validation.json`, `manifest.json`, `SHA256SUMS`: package artifact and validation records;
- `release-validation.json` beside the archive in the bundle's `java/` directory, when provided: external unpacking/receipt validation, not package content;
- `licenses/`: the SecurityContext Apache-2.0 license, third-party licenses, and the source index.

The Java targets are 8/11/17/21, the Agent target is `2.31.1`, and the extension API target is `2.31.1-alpha`. After extraction, run:

```bash
shasum -a 256 -c SHA256SUMS       # macOS
sha256sum -c SHA256SUMS           # Linux
```

## Quick start

```bash
./bin/run-demo.sh boot2
./bin/run-demo.sh boot3
```

To attach to an application:

```bash
java \
  -javaagent:/path/to/lib/opentelemetry-javaagent-2.31.1.jar \
  -Dotel.javaagent.extensions=/path/to/lib/securitycontext.jar \
  -Dsecurity.enabled=true \
  -Dsecurity.sbom.enabled=true \
  -Dsecurity.application.id=my-application \
  -Dsecurity.output=./security-output \
  -Dsecurity.evidence.file=./security-output/evidence.jsonl \
  -jar application.jar
```

When an OTel Agent is already present, append the extension instead of starting a second Agent. Make HTTP Server instrumentation available before application requests; otherwise request and server-span state is not guaranteed.

## Output contract

Owned state snapshots such as `health.json`, `findings.json`, `runs.json`, and `sbom-history.json` carry top-level `source=security_context`. SBOM logs (`app-dependencies-loaded` and `security.sbom.*`) use `source=security_context_sbom`; other security events use `source=security_context`. The OTLP log `attributes.source` matches the JSON body `source`. Truncation summaries and minimal records preserve the original source. Health, SBOM, and history are process-level snapshots rather than request-trace records. Schema v2 events flatten the six identity fields `application_id`, `instance_id`, `service`, `code`, `runtime`, and `identity_status`; the scope is `SecurityContext`, and native `eventName`, the `event.name` attribute, and body `event_name` agree. The package [English guide](docs/guide.en.md) and [中文指南](docs/guide.zh-CN.md) contain the source, sink, range, component, fingerprint v2, trace, and truncation rules.

CycloneDX keeps its standard top level, puts the source marker in `properties[]`, and uses `urn:securitycontext:component:` component refs. SBOM events use an independent channel and do not enter security JSONL. CLI report/control output also carries source while its own state schema may remain v1.

## CLI, disable, and troubleshooting

```bash
OUT=/absolute/path/to/security-output
python3 bin/securityctl.py --dir "$OUT" status
python3 bin/securityctl.py --dir "$OUT" query findings
python3 bin/securityctl.py --dir "$OUT" query sbom
python3 bin/securityctl.py --dir "$OUT" pause
python3 bin/securityctl.py --dir "$OUT" resume
```

Interpret validation through the package's `validation.json`, the optional `release-validation.json` beside the archive in the bundle's `java/` directory, and run outputs. Disable with `-Dsecurity.enabled=false -Dsecurity.sbom.enabled=false` and restart. To uninstall, stop the JVM, remove the JAR from `otel.javaagent.extensions`, and then delete the files. A running JVM does not hot-unload an extension.

Raw request values, full SQL, command text, complete URLs, and command argument values are not emitted by default. Unmodeled dynamic code, cross-service propagation, arbitrary binary bodies, crash/host-failure recovery, trace replay, Collector/backend acknowledgement, performance, and SLA are outside the default guarantee.

See the [English user guide](docs/guide.en.md) for full configuration, verification runs, breaking rename and fingerprint v2 migration, SBOM, trace, and troubleshooting details.
