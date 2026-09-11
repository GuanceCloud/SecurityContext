# Python validation samples

`security_sample` contains ordinary FastAPI, Flask, and Django applications
which share the same SQL, command, HTTP, file, formatting, streaming, and
parameterized-negative scenarios. The applications do not import
`securitycontext`; the validation scripts load the instrumentor through
`opentelemetry-instrument`.

The samples use only an in-memory SQLite database, `/usr/bin/printf`, a
configurable local HTTP target, and a temporary fixture directory. They do
not contact external services or modify a repository.

The framework matrix is run by `python/scripts/run_python_matrix.py`. Set
`SECURITY_SAMPLE_TEMP` to an isolated temporary directory when running a
sample manually. The Flask acceptance path uses the Flask CLI with
`--app ... run`; do not use `python -m security_sample.flask_app` as an
acceptance result because `runpy` executes that `__main__` path outside the
planned source-loader import boundary.
