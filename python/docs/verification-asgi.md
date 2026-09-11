# Django ASGI verification

Actual run: 2026-09-07, in the existing OrbStack container `securitycontext-py-312` (`aarch64`).

- Runtime: CPython 3.12.14, Django 5.2.17, Uvicorn 0.52.4. The container also has `opentelemetry-api` 1.44.0 and `opentelemetry-instrumentation` 0.65b0.
- Entry point: `security_sample.django_asgi:application`, with `DJANGO_SETTINGS_MODULE=security_sample.django_settings`. The application was imported by Uvicorn; it was not executed as `__main__`.
- Launch command (the runner chose port `48841`):

  ```text
  opentelemetry-instrument /usr/local/bin/python -m uvicorn security_sample.django_asgi:application --host 127.0.0.1 --port 48841
  ```

## Result

The existing `run_framework_case.run("django", ...)` assertions passed: **29/29 passed, 0 failed**. All six exercised HTTP responses were `200`: source-only, probe, body probe, form, text, and stream. The run observed 12 dataflow evidence events across SQL, command, HTTP, path, form, and text paths; raw input was absent from evidence, parameterized SQL remained negative, evidence IDs were unique, and the instrumented process exited after the runner sent `SIGTERM`. Evidence remains `modeled_calls_only` coverage with diagnostic gaps `call_container_depth`, `http.url.normalize`, and `unmodeled_call_result`; this is not full dataflow coverage.

Artifacts:

- Summary: `build/validation/python-v01/django-asgi-312/summary.json`
- Evidence: `build/validation/python-v01/django-asgi-312/evidence.jsonl` (14 lines: 12 observed dataflow events plus 2 collection-incomplete events)
- Server log: `build/validation/python-v01/django-asgi-312/server.log`
- Runtime health/findings/runs: `health.json`, `findings.json`, and `runs.json` in the same directory; findings are empty and health is configured/effective with collection enabled.

This historical run preceded the Uvicorn shutdown-hook fix. Its health/findings files retained the initial snapshot despite the emitted dataflow events, so this run does **not** establish final ledger flushing. The subsequent fix and separate installed-wheel, no-barrier SIGTERM verification are documented in [Lifecycle and shutdown verification](verification-lifecycle.md).

The server log contains non-failing lifecycle warnings: Uvicorn reports that the sample does not implement ASGI lifespan, and Django warns that the synchronous streaming iterator is consumed asynchronously. The existing stream assertion verified a complete response containing `chunk-` and ending in a newline. This run did not cover client cancellation/disconnect, backpressure, concurrent streams, or async-iterator behavior.

QA is quiet: no `uvicorn`, `opentelemetry-instrument`, or `django_asgi` process remains in `securitycontext-py-312`. The first QA-only container command had a Python one-line `def` syntax error before starting a server; it was corrected with the requested lambda and did not affect the validation result. No client or database cases were rerun.
