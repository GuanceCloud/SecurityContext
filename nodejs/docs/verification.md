# Node.js verification record

The matrix, performance and release records below describe the historical
0.1.0 package. They do not certify 0.2.0 or schema v2. Current 0.2.0 checks
are recorded in `data/current-verification.json`; their scope is limited to
the checks explicitly listed there.

The executable checks run in disposable OrbStack containers with `docker context
show` equal to `orbstack`, `--cpus=1`, `--memory=512m`, no published ports,
and no operation on existing containers. The normal Node TLS trust chain was
used. A CA or package-cache failure remains a setup failure.

## Runtime and API evidence

The current twelve framework/module-system cases are split across the retained
result directories below. They are all `status: pass`:

- Node 22.23.2 (`node:22-bookworm`):
  `build/verification/node22-framework-retest/summary.json` — Express 4/5 and
  Fastify 5, ESM and CommonJS, 6/6.
- Node 24.19.0 (`node:24-bookworm`):
  `build/verification/matrix-node24-latest/express4-cjs.json`,
  `express4-esm.json`, `express5-cjs.json`, and `express5-esm.json` supply the
  four Express cases, and `build/verification/fastify-node24/summary.json`
  supplies the two Fastify cases.
- Minimum Node 22.22.3: `build/verification/min-node22.22.3/summary.json`
  — real Express 5 ESM preload and HTTP request.
- Minimum Node 24.11.1: `build/verification/min-node24.11.1-node-sbom/summary.json`
  — real Express 5 ESM preload and HTTP request.

Older `matrix-node22/` and the first `min-node24.11.1/` directories contain
pre-fix failures and are retained for diagnosis; they are not the current
verdict. Each per-case JSON records the exact runtime, framework version,
loader result, response checks, exported spans, security evidence, and negative
control.

The public API contract was run in Node 24.19.0 and exact Node 24.11.1:

- `build/verification/api-contract-node24-20260908/result.json`
- `build/verification/api-contract-node24.11.1-20260908/result.json`

Both pass ESM import, CommonJS `require`, repeated register import, repeated
`SecurityInstrumentation` construction returning one instance, SDK acceptance,
and plugin shutdown preserving a host SDK span.

## Semantic, collector, and database evidence

The core stateful semantics result is `build/verification/core-semantics.md`:
one test passed on Node 22.23.2 and Node 24.19.0, covering request-local
recursive/closure marks, same-text constants, assignment clearing,
destructuring/default values, getter/setter behavior, Promise branches,
single execution after a throw, local-name shadowing, and sloppy `arguments`
alias clearing. The focused loader contract also passed on the exact minimum
lines in `build/verification/loader-contract-node22.json` and
`build/verification/loader-contract-node24.json`; each file records 5/5 and
covers ESM cycle/live binding, source-map-to-SBOM mapping, source-limit
throw-once behavior, legacy asynchronous IITM loader disablement, and natural
process exit with SBOM toggle handling. The framework boundary and ownership
checks are recorded in `build/verification/framework-boundaries.md` (Node 22
and Node 24 pass); they also cover repeated shutdown, host SDK ownership after
plugin shutdown, and Fastify query/body validation/coercion behavior.

The exact minimum adapter/SBOM suite is
`build/verification/sbom-adapters-20260908.json`: Node 22.22.3 and Node
24.11.1 each passed 17/17 tests.

The semantic taint result is `/tmp/securitycontext-taint-results-20260907.json`
and the current semantic suite is represented by the matrix case files. The
real OTLP logs check used the Node OTLP logs SDK/exporter and a disposable
collector. Its normalized evidence is
`build/verification/collector-real-20260908.json`; the source collector output
was `/tmp/securitycontext-collector-real-20260908f/node-qa-logs.jsonl`. It
contains a real `security.dataflow.observed` record whose `query.path` source,
`fs.readFile` sink, and trace ID match the collector log record. No hand-written
logger event was used.

The focused real-driver result is
`build/verification/database-adapters-20260908.json`. It is a separate
PostgreSQL/MySQL check owned by the database integration worker and is listed
here as evidence, not as a substitute for the framework matrix.

Runtime-control and CLI checks passed six tests on each line:
`build/verification/controls-node22.md` (Node 22.22.3, 6/6) and
`build/verification/controls-node24.md` (Node 24.19.0, 6/6). They cover queue
overflow, output failure, I/O worker termination, pause/resume, run lifecycle,
`query runs`, and `verify`; the observed run had one source request, one sink
request, one observation, and zero delivery loss. The packaged copy
`data/securityctl.py` is byte-identical to the canonical root
`scripts/securityctl.py`, as checked by `prepare-package`.
The intentionally incomplete-ledger path is recorded in
`build/verification/controls-inconclusive.md`: the real CLI returned exit 3
for an inconclusive verification result, while the control suite itself
passed.

## Performance comparison

`build/verification/perf-node24-latest/summary.json` and its four mode files
record 100 requests at concurrency 4 on Node 24.19.0. The observed comparison
is:

| mode | startup ms | requests/s | P95 ms | event-loop P95 ms | RSS bytes | drops total/security/SBOM |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| only OTel | 295.09 | 4031.01 | 1.710 | 19.890 | 80,306,176 | unavailable |
| security | 481.36 | 689.63 | 9.521 | 44.958 | 117,919,744 | 6 / 6 / 0 |
| SBOM | 440.39 | 1166.86 | 2.871 | 66.486 | 127,819,776 | 174 / 0 / 174 |
| full | 563.00 | 427.49 | 57.988 | 79.167 | 144,363,520 | 180 / 6 / 174 |

All four processes returned exit code 0 and observed bounded shutdown. The
security/full drops are real exporter budget drops in this short sample; the
SBOM-only mode's 174 drops are entirely on the SBOM channel. The only-OTel
mode has no plugin drop metric. The SBOM health in the SBOM/full files remains
`completeness: incomplete` with reasons `package_json_unreadable`,
`runtime_dependency_graph_incomplete`, and `unresolved_declared_dependency`.
These are build comparisons, not a production SLA.

The bounded reclamation check is
`build/verification/reclaim-node24-soak-20260908b/summary.json`. On Node
24.19.0 with `SECURITY_SBOM_ENABLED=false` (security-only), it ran 120.505
seconds at 25 requests/second, with 3,000 real HTTP
requests. Each request used a query path, `slice().concat()`, and the
instrumented `readFileSync` sink. All responses were 200; 3,004 requests
(including warmup and probes) started and completed, with zero incomplete
requests and zero security/SBOM delivery drops. The initial, middle, and final
idle samples recorded `trackingBytes=0`, `active_requests=0`, and zero queue
depth; RSS and heap are retained in every sample. A counting span exporter
reported 6,006 exported spans without an unbounded in-memory span store. The
HTTP probe's own in-flight state is retained under each sample's `current`
field so it is not confused with idle reclamation. This is bounded
security-only reclamation evidence, not a full-mode or long-term production
capacity result.

## Packaging and release evidence

The final package is built after `node scripts/prepare-package.mjs` and the
npm pack manifest pass. It carries the pinned `data/dependency-lock.json`, the
byte-identical canonical `data/securityctl.py`, the source entry points, and
the current compact evidence record `data/current-verification.json`. The
prepare result is retained under
`build/verification/prepare-package-final-20260908/`; the external release
records are `dist/SHA256SUMS` and `dist/release-manifest.json`, so the tarball
does not contain a self-referential hash.

The final install record under
`build/verification/clean-install-final-20260908/` comes from a fresh
temporary npm directory and includes a real HTTP request started with the
packaged `register` preload, ESM and CommonJS public API checks, and the
packaged POSIX CLI status check. The exact tarball SHA-256 and install result
are in `dist/release-manifest.json`. Historical diagnostic runs remain in the
workspace; the final manifest identifies the one release artifact.
