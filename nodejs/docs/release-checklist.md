# Node.js release checklist

Run these checks after the last source, adapter, exporter, and SBOM changes are
on disk. Keep each result directory with the release candidate.

1. Confirm `package.json` and `package-lock.json` pin the agreed OTel
   (`@opentelemetry/api` 1.9.1, SDK/instrumentation 0.222.0, HTTP
   instrumentation 0.222.0), IITM 3.4.0, Babel 8, Express 4/5, Fastify 5,
   `pg` 8, `mysql2` 3, and `undici` 8 dependencies. Run
   `node scripts/prepare-package.mjs`; require
   `data/dependency-lock.json` to be byte-for-byte synchronized with the root
   lock before packing.
2. Run the OrbStack Node 22 and Node 24 framework matrix in disposable
   `--cpus=1 --memory=512m` containers. Retain exact runtime versions and
   distinguish `pass`, `fail`, and `blocked`. Include the exact minimum
   `22.22.3` and `24.11.1` preload requests.
3. Run `tests/check-api-contract.mjs` in both module loading modes available to
   the package. Verify ESM and CommonJS exports, repeated register imports,
   singleton construction, SDK ownership, and plugin shutdown without closing
   the host SDK.
4. Run the semantic, taint, ledger, SBOM, and adapter checks. Keep static
   CycloneDX/schema checks separate from runtime behavior. The current
   CycloneDX loader contract is `specVersion` 1.7. Do not call a static fixture
   or schema check complete feature acceptance.
5. Run the real OTLP logs collector check and the focused PostgreSQL/MySQL
   integration. Require a plugin-emitted `security.dataflow.observed` event
   with source, sink, and trace fields; a hand-written logger event does not
   satisfy this gate. Require SQL template and bind controls to remain
   distinguishable.
6. Run the CLI against a live output directory and exercise `status`, `pause`,
   `resume`, `run-start`, `run-stop`, `verify`, and the documented
   inconclusive exit code. Keep the canonical root `scripts/securityctl.py`
   synchronized byte-for-byte into `data/securityctl.py`; verify its
   standard-library-only imports and POSIX `fcntl` requirement (Python 3 on
   Linux/macOS; Windows is unverified), and carry that file in the package. The Node
   22/24 controls are evidence for the lifecycle, while the final installed
   package still needs its own CLI smoke.
7. Run `tests/performance/run.mjs` in `only-otel`, `security`, `sbom`, and
   `full` modes with fixed request count/concurrency. Record startup,
   throughput, P95, event-loop delay, RSS, drop counts, and bounded shutdown.
   These values compare this build and do not establish a production SLA.
8. Run `tests/performance/reclaim-soak.mjs` for at least 120 seconds at 20–50
   requests/second. Every request must exercise a real HTTP query source,
   string slice/concat, and temporary-file `readFileSync` sink. Use a counting
   span exporter, retain initial/middle/final idle samples for
   `trackingBytes()`, active requests, queues, RSS, heap, and drops, and require
   the final idle sample to return tracking bytes, active requests, and queues
   to zero. Keep the HTTP probe's own in-flight state separate from idle
   samples.
9. Only after all gates pass, pack to `nodejs/dist`, inspect the tarball file
   list, record its SHA-256, install it into a clean temporary directory, and
   run one real `--import securitycontext/register` request. The
   final install must verify the public API, singleton behavior, host SDK
   ownership, transformed business file, dependency lock record, and CLI
   payload. Only the final tarball named by the external release manifest is a
   release artifact.
