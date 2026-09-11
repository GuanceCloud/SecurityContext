# Lifecycle and shutdown verification

The framework lifecycle wrapper keeps the application's result and exception
unchanged.  For Uvicorn `>=0.52,<0.53`, the installed adapter wraps
`Server.shutdown` with a `finally` hook that calls the existing runtime's
asynchronous bounded flush (`runtime.aflush`). It does not replace signal handlers,
close the shared OpenTelemetry provider, or stop the plugin runtime. One shared
1.5-second deadline covers snapshot-lock waits, snapshots, queue drain, and the
existing provider's `force_flush`. A single in-flight daemon thread performs
these operations; concurrent flush requests reuse it. The thread starts during
exporter initialization so Python 3.12+ can flush during atexit without creating
a new thread. The event loop only awaits
completion. `runtime.flush(timeout)` uses the same operation for synchronous callers.
`Runtime.close(timeout)` also shares its deadline with inventory and exporter cleanup.

A stalled filesystem or SDK call can outlive that deadline in the daemon thread;
it cannot force the caller or process to wait indefinitely. Timeout records
incomplete delivery without waiting for the ledger lock. A subsequent successful
snapshot persists that uncertainty. If storage remains stuck, on-disk snapshots
cannot be refreshed and must not be treated as current verification evidence.

The focused contract test is
`tests/test_framework_lifecycle_contract.py::test_uvicorn_shutdown_flushes_without_changing_result_or_exception`.
It verifies both a normal shutdown return and the original exception identity;
each path awaits `runtime.aflush` once. Blocked monitor writes, writer close and
shared-provider calls also have focused timeout and event-loop regressions. Natural
process exit is tested with both a responsive and a permanently blocked provider.  The same file also covers WSGI close,
ASGI trailers, cancellation, stopped wrappers, and aggregate framework field
depth/cycle/node budgets.

The no-barrier installed-wheel shutdown gate ran against CPython 3.12.14,
Uvicorn 0.52.4, and the final wheel selected under
`build/validation/python-v01/package-final-20260907-final3/dist/`.  The
external release manifest records the final wheel and sdist hashes; no
artifact hash is embedded in this packaged document.

- `build/validation/python-v01/shutdown-hook-final3-20260907/shutdown-summary.json`
- `build/validation/python-v01/shutdown-hook-final3-20260907/health.json`
- `build/validation/python-v01/shutdown-hook-final3-20260907/findings.json`
- `build/validation/python-v01/shutdown-hook-final3-20260907/evidence.jsonl`

The runner performed one readiness request and one query-bearing HTTP request,
sent `SIGTERM` without a pre-shutdown health drain barrier, and then inspected
the resulting files.  The gate passed: HTTP 200, `active_requests=0`,
`requests_completed=3`, nine findings, and 19 JSONL records (9 observed
dataflow events, 9 finding summaries, and 1 collection-incomplete diagnostic).
The health, findings, and dataflow evidence `instance_id` values matched.  The process returned
`-15`, which is recorded as Uvicorn's signal re-raise and is not treated as
proof of a generic `atexit` flush.  This targeted case's health status was
`incomplete` because the sample recorded one request-completion gap; that is
reported rather than converted into a valid negative result.

The ordinary framework runner and benchmark now use a separate bounded drain
barrier before sending `SIGTERM`: they require the health snapshot's
`requests_completed` delta to reach the expected request count and
`active_requests` to be zero.  That barrier prevents stale initial snapshots,
but it is not substituted for the no-barrier shutdown-hook gate above.
