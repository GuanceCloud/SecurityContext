# SecurityContext 2026-09-11 release notes

New in the `20260911` release: SBOM snapshots (`app-dependencies-loaded`) and `security.sbom.*` diagnostics use `source=security_context_sbom`; other security events keep `source=security_context`. OTLP attributes and the JSON body agree, including summary/minimal truncation. Local CycloneDX and history file formats and source markers remain unchanged. Upgrade and restart the application to apply the change.

Local complete distribution `securitycontext-releases-20260911`: Java 0.3.4 and Node.js/Python 0.2.5. Rebuilt from the current workspace with all four CPU/memory optimization rounds and the SC-20260909-1/2/3 fixes. Install the new version and restart the application.

## Incremental changes

- Python SBOM reuses install-root and module matching work within each refresh, then rechecks deployments and symlinks on the next refresh.
- Python/Node copy detailed evidence according to representative sampling while retaining occurrence, latest request and verification-run counts.
- Python skips propagation-model allocation for unmarked calls; standard Path.read_text/read_bytes consume the path without marking file contents or reporting an unknown return. File sink observation remains active.
- Java cached component copies reuse immutable identity fields and independently copy mutable collections.

In the controlled Python service at sustained 100 QPS, process CPU time decreased about 4.2% while peak RSS increased about 1.09 MiB. Whole-process memory and tail-latency improvements were not demonstrated. See the complete bundle resource-overhead record.

## Changes

- Java reuses request-tracking lookup keys, deduplicates CodeSource scans, and avoids per-byte formatting and temporary allocations in component SHA-256 encoding.
- Node.js caches stable configuration, indexes loaded package roots, reduces encoding copies, reuses component records during SBOM publication, and retains only digests for historical comparisons.
- Python reuses immutable marks, caches distribution-name/environment-path indexes, retains only required license metadata, and uses digests for SBOM history comparisons while skipping history copies for unchanged snapshots.
- Retains shared Promise result deduplication, the Node numeric-binding work queue and budget, and Python alias work queues and transform limits. Exhausted instrumentation budgets execute native business code and record observation gaps; propagation coverage is omitted for that fallback.
- SBOM uploads remain `app-dependencies-loaded` with `name`, `version`, and an optional real artifact `hash`. Local CycloneDX 1.7 and component history remain available. Reassemble every part of the same snapshot before replacing inventory.

CPU and memory benefits depend on dependency count and workload; hotspot benchmarks do not establish whole-process or production gains. The complete bundle includes the four measurement rounds and their limits in `docs/resource-overhead.md`. This release does not reduce default observation capabilities to obtain the resource improvements; existing budget-exhaustion semantics remain unchanged.

## Installation and validation

Java pairs with OTel Java Agent 2.31.1, uses Java 8 bytecode, and targets Java 8/11/17/21. Node targets >=22.22.3 <23 or >=24.11.1 <25; Python targets CPython 3.11–3.14. Node/Python dependencies require a registry or cache; this is not an offline dependency mirror. Complete English/Chinese guides, CLI, Collector configuration and samples are included.

Use the complete bundle's `release-validation.json`, Java's internal `validation.json`, and the external independent-extraction receipt for checks actually executed and remaining limits. Historical performance measurements do not certify current artifacts. OTel emit does not imply Collector/backend receipt. Sustained load, full database/process matrices, Collector receipt and non-root Java permission cases are outside this release's completed validation scope.

Local artifacts only; no Maven, npm, PyPI or remote Git publication. Historical archives remain unchanged. Resolving the three previously reported P1 issues does not establish that no other P0/P1 issues exist.
