# SecurityContext multi-language release bundle (2026-09-08)

The release bundle root is `securitycontext-releases-20260908/`; the links below are relative to that root and use the fixed artifact names.

## Artifacts

| Language | Version | Package and included documentation |
| --- | --- | --- |
| Java | `0.3.0` | [`securitycontext-0.3.0/`](java/securitycontext-0.3.0/), [tar.gz](java/securitycontext-0.3.0.tar.gz), [zip](java/securitycontext-0.3.0.zip), [standalone JAR](java/securitycontext-0.3.0.jar), [package JAR](java/securitycontext-0.3.0/lib/securitycontext.jar), [中文指南](java/securitycontext-0.3.0/docs/guide.zh-CN.md), [English guide](java/securitycontext-0.3.0/docs/guide.en.md) |
| Node.js | `0.2.0` | [tarball](nodejs/securitycontext-0.2.0.tgz), [中文指南](nodejs/docs/guide.zh-CN.md), [English guide](nodejs/docs/guide.en.md) |
| Python | `0.2.0` | [sdist](python/securitycontext-0.2.0.tar.gz), [wheel](python/securitycontext-0.2.0-py3-none-any.whl), [中文指南](python/docs/guide.zh-CN.md), [English guide](python/docs/guide.en.md) |

The external release reports record actual validation for [Java](java/release-validation.json), [Node.js](nodejs/release-validation.json), and [Python](python/release-validation.json). See [`release-manifest.json`](release-manifest.json) for versions, artifacts, and scope. The root [`SHA256SUMS`](SHA256SUMS) covers the delivered files; the Java archive also includes its own inventory and checksums. Verify before installation:

```bash
sha256sum -c SHA256SUMS       # Linux
shasum -a 256 -c SHA256SUMS   # macOS
```

## Local installation and startup

Install Node.js from the local tarball:

```bash
cd nodejs
npm install ./securitycontext-0.2.0.tgz
```

Install Python from the local wheel or sdist:

```bash
cd python
python -m pip install ./securitycontext-0.2.0-py3-none-any.whl
# or python -m pip install ./securitycontext-0.2.0.tar.gz
```

For Java, use the matching OTel Java Agent and JAR from the package. Read [`java/securitycontext-0.3.0/README.en.md`](java/securitycontext-0.3.0/README.en.md), then run the package's `bin/run-demo.sh boot2|boot3` or the corresponding `-javaagent` command. Initialize host OTel and SecurityContext before handling application requests; each language guide defines the order of preloading, provider setup, and application imports.

## Shared contract

All three packages use the `SecurityContext` scope, `source=security_context`, and schema v2 events: the six flat identity fields, runtime, source/sink/component shapes, trace association, SBOM channel, and truncation/delivery counters are described in each package's included guide. Both event source and the OTel `source` attribute are `security_context`; security JSONL accepts only the evidence/diagnostic allowlist, and SBOM events do not use that channel. Health, SBOM, and history are process-level snapshots rather than request traces; data-flow evidence carries `trace_id`, `server_span_id`, `current_span_id`, and frozen `trace_flags`.

Read each package's fingerprint2 and breaking rename notes before upgrading. There is no automatic shim for an old package/import/JAR/namespace; consumers must update manually, and historical event readers must handle the older schema themselves. Stop the application before disabling or uninstalling and handle output, evidence, and SBOM retention according to the deployment policy.

## Validation boundary

Runtime validation ran on OrbStack Linux/arm64. Each language's `release-validation.json` and the root `release-manifest.json` record the actual scope and results. x86_64 and Windows paths remain unverified. Performance measurements from the shared environment are not an SLA; drops were observed under the default Node.js output budgets. Raw runtime logs remain in the source workspace: `build/validation/` paths in the reports are workspace evidence references and are not all copied into this bundle. See each language guide for dependency targets, minimal examples, CLI/run flows, troubleshooting, capability limits, and disable/uninstall steps. These are local release artifacts; no Git commit or remote publication was performed.
